# Security Audit Consolidated Report

## Apache STeVe (Voting Tool) — ASVS L3 Assessment

---


> **Note:** 9 Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list.


## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L3 (Maximum) |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 06, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 345 |
| **Total Findings** | 310 | ---

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|------:|----------:|
| **Critical** | 9 | 2.9% |
| **High** | 70 | 22.6% |
| **Medium** | 155 | 50.0% |
| **Low** | 76 | 24.5% |
| **Informational** | 0 | 0.0% |
| **Total** | **310** | **100%** | ### ASVS Level Coverage

Findings were identified across all three ASVS verification levels within the audit scope:

| Level | Findings Applicable | Description |
|-------|-------------------:|-------------|
| **L1** | 98 | Opportunistic — baseline controls expected of all applications |
| **L2** | 213 | Standard — appropriate for applications handling sensitive data |
| **L3** | 134 | Advanced — required for high-value applications (elections, critical infrastructure) | > **Note:** Many findings apply to multiple levels simultaneously (e.g., a Critical finding at L1, L2, L3 is counted in each row above). The application is assessed against L3 requirements given its function as an election/voting system for the Apache Software Foundation.

### Directories Assessed

23 security domains were evaluated spanning the full application stack:

`api_endpoints` · `tls_configuration` · `deployment_and_configuration_hardening` · `secrets_and_configuration_management` · `tallying_and_admin_operations` · `web_page_rendering_and_output_encoding` · `session_management` · `password_and_credential_security` · `token_and_assertion_validation` · `dependency_and_component_security` · `http_security_headers_and_browser_protection` · `data_privacy_and_anonymity` · `asf_oauth_ldap_authentication` · `vote_encryption_and_storage` · `database_security_and_integrity` · `csrf_and_state_changing_operations` · `file_upload_and_handling` · `rate_limiting_and_resource_protection` · `general_security` · `logging_and_monitoring` · `input_validation_and_business_logic` · `injection_prevention` · `election_authorization_and_access_control`

### Top 5 Risks

The following findings represent the most severe threats to the application's integrity, confidentiality, and availability — particularly concerning given its role as an election system:

| # | Finding | Severity | Risk Summary |
|---|---------|----------|--------------|
| 1 | ****: Election Management Authorization Controls Defined But Never Enforced | **Critical** | Authorization logic exists in code but is never invoked, meaning any authenticated ASF member can create, modify, open, close, or delete any election regardless of ownership. This fundamentally undermines the integrity of the voting system. |
| 2 | ****: CSRF Token is a Hardcoded Placeholder — No Server-Side Validation Exists | **Critical** | The CSRF token is a static string with no server-side verification. Combined with  (state-changing GET endpoints), an attacker can forge requests that create elections, cast votes, or alter election state via simple link injection. |
| 3 | ****: Election State Enforcement Uses Python `assert` Statements That Can Be Disabled | **Critical** | Critical election lifecycle guards (e.g., preventing voting on closed elections, preventing deletion of open elections) use Python `assert` statements, which are stripped entirely when Python runs with optimization flags (`-O` or `PYTHONOPTIMIZE=1`). |
| 4 | ****: Stored XSS in JavaScript Context — STV Candidates Object | **Critical** | Candidate names from the database are injected directly into a JavaScript object literal without encoding, enabling stored cross-site scripting that executes in every voter's browser session when viewing STV ballots. |
| 5 | ****: Vote String Has No Validation Against Vote Type Rules | **Critical** | Vote submissions are accepted and encrypted without any validation that the vote content conforms to the election's declared vote type (YNA, STV, etc.), allowing storage of arbitrary data that could corrupt tallying or exploit downstream processing. | **Systemic Observation:** The Critical findings cluster around two architectural gaps: (1) authorization controls that are defined but never called, and (2) input/state validation that relies on mechanisms inappropriate for production (hardcoded tokens, `assert` statements, missing server-side checks). These are not complex exploitation scenarios — they represent fundamental control absences exploitable by any authenticated user or via basic CSRF attacks.

### Positive Security Controls

Despite the significant findings above, the audit identified meaningful security controls that demonstrate intentional security design in the cryptographic and data-access layers:

| Domain | Control | Evidence |
|--------|---------|----------|
| **Vote Encryption** | Well-designed multi-level key derivation chain | `election_data → BLAKE2b → Argon2 → opened_key → (+ pid + iid + salt) → Argon2 → vote_token → HKDF → vote_key → Fernet(vote)` provides strong key separation between elections, issues, and voters |
| **Vote Privacy** | Voter–vote unlinkability architecture | Vote tokens are derived (not stored), votes are encrypted immediately upon submission, and decrypted votes are cryptographically shuffled before output during tallying |
| **Cryptographic Foundations** | Industry-validated libraries with CSPRNG | Uses `cryptography` (Fernet), `argon2-cffi`, `hashlib.blake2b`, and `secrets` module — no deprecated algorithms (MD5/SHA-1 absent), no ECB mode, fresh IV per encryption |
| **SQL Injection Prevention** | Complete parameterization with no dynamic SQL | All 30+ queries defined in `queries.yaml` with `?` placeholders; no string concatenation, f-strings, or format strings used to construct SQL anywhere in the codebase |
| **Data Minimization** | Explicit sensitive field filtering | `get_metadata()` and `get_issue()` use allowlists to strip cryptographic material; `q_open_to_me` query explicitly excludes `SALT` and `OPENED_KEY`; logging never includes key material |
| **Integrity Verification** | Election tamper detection via `opened_key` | Argon2 hash of all election structural data enables detection of unauthorized modifications to election configuration |
| **Key Hygiene** | No hardcoded secrets; deferred key generation | Configuration contains no secret material; cryptographic keys are generated only when an election transitions to the "open" state, minimizing exposure window | **Assessment:** The cryptographic layer and database access patterns reflect strong security engineering. However, the application's web layer, authorization enforcement, session management, and operational security controls (logging, headers, rate limiting) have not received equivalent attention. The resulting posture is one where vote *content* is well-protected cryptographically, but the *processes* surrounding elections (who can create/modify/tally them, and under what conditions) lack enforceable controls.

---

## 3. Findings

## 3.2 High

#### FINDING-010: No Crypto Agility - Algorithms Hardcoded Without Abstraction or Versioning

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 11.2.2 |
| Files | v3/steve/crypto.py (entire file), v3/schema.sql |
| Source Reports | 11.2.2.md |
| Related | - | **Description:**

The application has no crypto-agility design. Specific issues: 1. No algorithm abstraction layer: All crypto operations directly call specific implementations with hardcoded parameters. There's no configuration, registry, or strategy pattern that would allow swapping algorithms. 2. No algorithm versioning in stored data: The vote table stores ciphertext without any algorithm identifier. When transitioning from Fernet to XChaCha20-Poly1305, there will be no way to determine which algorithm was used for existing ciphertext without external tracking. 3. No key versioning: If keys need to be rotated or algorithms changed, there's no version field to indicate which key/algorithm generated a given ciphertext. 4. No re-encryption mechanism: No tooling exists to decrypt existing votes with the old algorithm and re-encrypt with a new one. 5. Fixed key lengths in schema: Database CHECK constraints enforce exact lengths (length(vote_token) = 32, length(opened_key) = 32, length(salt) = 16), preventing algorithm changes that require different sizes without schema migration.

**Remediation:**

1. Add algorithm version to stored ciphertext: CREATE TABLE vote (vid INTEGER PRIMARY KEY AUTOINCREMENT, vote_token BLOB NOT NULL, crypto_version INTEGER NOT NULL DEFAULT 1, ciphertext BLOB NOT NULL) STRICT; 2. Implement a crypto abstraction layer with CRYPTO_VERSIONS dictionary mapping version numbers to algorithm configurations, and update create_vote() and decrypt_votestring() functions to accept and use version parameters. 3. Provide a re-encryption utility for migration.

---

#### FINDING-011: Non-constant-time comparison in tamper check allows timing oracle

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 11.2.4 |
| Files | v3/steve/election.py (331) |
| Source Reports | 11.2.4.md |
| Related | - | **Description:**

Python's `!=` operator on `bytes` objects performs a short-circuit comparison that returns `False` as soon as the first differing byte is found. An attacker who can observe response timing could potentially determine how many leading bytes of the `opened_key` match, gradually reconstructing the stored key. The `opened_key` is derived from election data and serves as the anti-tamper seal; leaking it could allow an attacker to forge tamper checks.

**Remediation:**

Replace the `!=` comparison with `hmac.compare_digest()` to ensure constant-time comparison. Change `return opened_key != md.opened_key` to `return not hmac.compare_digest(opened_key, md.opened_key)` after importing `hmac`.

---

#### FINDING-012: No Secrets Management Solution (Key Vault) Integration

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS sections | 13.3.1, 13.3.3 |
| Files | v3/steve/crypto.py (entire module), v3/steve/election.py (75-85), v3/schema.sql (election table) |
| Source Reports | 13.3.1.md, 13.3.3.md |
| Related | - | **Description:**

All cryptographic operations (key derivation, encryption, decryption, hashing) are performed directly in the application process. Key material is derived in application memory, exists as Python bytes objects on the heap, and is accessible to any code running in the same process (or an attacker who achieves memory read access). There is no isolation boundary — no HSM, no separate vault process, no TEE, and no software enclave protecting key material during use. For an L3 application, this is particularly concerning as ASVS 13.3.3 requires an isolated security module to prevent key exposure. Data flow: vote_token + salt → _b64_vote_key() → derived key in Python heap → Fernet object → encryption/decryption in same process.

**Remediation:**

Integrate a secrets management solution such as HashiCorp Vault, AWS KMS, or Azure Key Vault to store election salts and opened_keys outside the application database. Example implementation provided using HashiCorp Vault with KV secrets engine and AppRole authentication. At minimum, use Vault's KV secrets engine for secret storage with ACL policies per election. Add key lifecycle metadata with key_created_at and key_version columns to enable future rotation and audit capabilities. Implement secret destruction for closed elections by adding an archive_election() method that zeros out cryptographic material after a defined retention period. For L3 ASVS compliance, integrate a hardware security module (PKCS#11 interface or cloud HSM) for key generation and cryptographic operations.

---

#### FINDING-013: Single Database File Provides Unrestricted Access to All Secrets

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 13.3.2 |
| Files | v3/steve/election.py (40), v3/schema.sql |
| Source Reports | 13.3.2.md |
| Related | - | **Description:**

The SQLite architecture stores all cryptographic secrets (election salts, opened_keys, per-voter salts) in the same database file as non-sensitive metadata (titles, person names, emails). Any process or user with read access to the database file can extract all secrets. There is no row-level or column-level access control, and no separation between the secret store and the application data store. Any code path with db_fname can obtain full read/write access to election.salt, election.opened_key, mayvote.salt, and vote.ciphertext. The tally_issue method demonstrates that any caller who reaches it can decrypt ALL votes for an issue without additional per-secret access control.

**Remediation:**

1. Separate secret material into a distinct storage mechanism with independent access controls. 2. Implement application-level access control that verifies the caller's authorization before exposing per-voter salts. 3. Consider encrypting the salt columns with a master key managed by a vault. Implement a SecretAccessLayer class that mediates access to cryptographic secrets with least privilege, restricting access to election keys to admin/tally roles only and voter salts to the specific voter or tally role.

---

#### FINDING-014: No Expiration or Rotation Mechanism for Cryptographic Secrets

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 13.3.4 |
| Files | v3/schema.sql (election and mayvote tables), v3/steve/election.py (75-140) |
| Source Reports | 13.3.4.md |
| Related | - | **Description:**

Once generated, cryptographic secrets (election salts, opened_keys, per-voter salts) persist indefinitely in the database with no expiration timestamp or TTL, key versioning mechanism, rotation procedure, or scheduled re-keying. For long-running elections or elections that remain in storage after closure, cryptographic material ages without replacement. If a key is compromised, there is no rotation mechanism to limit exposure.

**Remediation:**

Add expiration and versioning to schema by extending the election table with key_version, key_created_at, and key_expires_at columns. Implement a rotate_encryption_keys() method that rotates election keys if expired and re-encrypts all votes with new key material, updating key metadata including version, created_at, and expires_at timestamps.

---

#### FINDING-015: No data retention mechanism — opened/closed elections cannot be deleted

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 14.2.7 |
| Files | v3/steve/election.py (60-77) |
| Source Reports | 14.2.7.md |
| Related | - | **Description:**

Once an election is opened, it can NEVER be deleted through the application. The `assert self.is_editable()` check prevents deletion of opened or closed elections. This means: All voter eligibility data (mayvote table with PIDs) persists indefinitely, All encrypted votes persist indefinitely, All person records (emails, names) persist indefinitely. There is no automated cleanup, TTL, or scheduled purge mechanism. For elections containing sensitive data (voter identities, participation records), indefinite retention without a defined schedule violates data minimization principles and potentially GDPR/privacy regulations requiring time-bounded retention. After an election is closed and tallied, calling `Election(db, eid).delete()` raises `AssertionError` — the data is permanently locked in the database.

**Remediation:**

Implement a purge method that allows deletion of closed elections after a retention period. The method should check that the election is closed, verify the retention period has expired, and then delete votes, mayvote records, issues, and the election record in a transaction. Example implementation: `def purge(self, retention_days=None)` that asserts the election is closed, checks the retention period against close_at timestamp, and performs cascading deletes of all related data.

---

#### FINDING-016: Missing Strong Client Authentication for OAuth Token Endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS sections | 10.4.10, 10.4.16 |
| Files | v3/server/main.py (39-42) |
| Source Reports | 10.4.10.md, 10.4.16.md |
| Related | - | **Description:**

The token endpoint callback URL format 'https://oauth.apache.org/token?code=%s' only passes the authorization code via query parameter. There is no evidence of: client_assertion parameter (required for private_key_jwt), client_assertion_type parameter, Mutual TLS configuration for client certificate authentication (tls_client_auth or self_signed_tls_client_auth), or any client_id or client_secret being injected into the token request. The create_app() function initializes the application but does not configure any strong client authentication mechanism. While the asfquart framework may inject credentials internally, the URL format token?code=%s with a single format specifier suggests only the code is passed. Without strong client authentication (mutual TLS or private_key_jwt), the client cannot be verified as confidential. This weakens the security of the authorization code exchange, potentially allowing code injection or replay by unauthorized parties.

**Remediation:**

Configure client authentication using private_key_jwt or mTLS. For private_key_jwt: Create a client assertion function that generates a JWT signed with the client's private key, including claims for iss, sub, aud, iat, exp, and jti. For mTLS: Configure the HTTP client with client certificate using ssl_context.load_cert_chain(certfile='client.pem', keyfile='client_key.pem'). Ensure the asfquart framework sends client credentials with token requests. Example using client_secret_post: Set OAUTH_URL_CALLBACK to 'https://oauth.apache.org/token' and include in the token request body: code=&lt;code&gt;&client_id=&lt;id&gt;&client_secret=&lt;secret&gt;&grant_type=authorization_code. Preferably, use private_key_jwt or mTLS for client authentication.

---

#### FINDING-017: Missing ID Token Audience (aud) Claim Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-345 |
| ASVS sections | 10.5.4, 9.2.4 |
| Files | v3/server/main.py (35-49) |
| Source Reports | 10.5.4.md, 9.2.4.md |
| Related | - | **Description:**

The code explicitly overrides the asfquart framework's default OAuth/OIDC configuration (which presumably includes proper OIDC flows with audience validation). The comment 'Avoid OIDC' and the uncertain 'is this really needed right now?' suggest this was done as a quick workaround rather than a deliberate security decision. OIDC provides built-in audience restriction via: ID Token aud claim (MUST contain client_id per spec), token endpoint client authentication, and standardized token validation procedures. By bypassing OIDC, the application loses these protections that directly satisfy ASVS 9.2.4, creating a false sense of security since the asfquart.auth.require decorator appears to work but doesn't validate audience claims.

**Remediation:**

Configure client_id for audience validation and ensure token validation checks audience. Example implementation: def create_app(): import asfquart.generics; CLIENT_ID = 'steve-voting-app'; asfquart.generics.OAUTH_URL_INIT = (f'https://oauth.apache.org/auth?client_id={CLIENT_ID}&state=%s&redirect_uri=%s'); asfquart.generics.OAUTH_URL_CALLBACK = 'https://oauth.apache.org/token?code=%s'; app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None); app.config['OAUTH_CLIENT_ID'] = CLIENT_ID; # In token validation callback: assert id_token['aud'] == CLIENT_ID

---

#### FINDING-018: Inconsistent Authentication Strength Between Election Creation and Management

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-863 |
| ASVS sections | 6.3.4 |
| Files | v3/server/pages.py |
| Source Reports | 6.3.4.md |
| Related | - | **Description:**

The application enforces a higher privilege level (R.pmc_member) for creating elections than for managing them (R.committer). This inconsistency means a lower-privileged user (committer, not PMC member) can perform more impactful operations such as opening/closing elections and modifying issues, which is a gap in authentication pathway consistency where different pathways to affect election state have different strength requirements.

**Remediation:**

Ensure management operations require at least the same privilege level as creation, or implement proper owner-based authorization checking. Management operations should either require R.pmc_member status or implement the owner/authz checks to ensure consistent security controls.

---

#### FINDING-019: State-Changing Operations Use GET Method, Bypassing CSRF and Browser Security Mechanisms

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-352 |
| ASVS sections | 6.3.4 |
| Files | v3/server/pages.py |
| Source Reports | 6.3.4.md |
| Related | FINDING-138 | **Description:**

The do-open and do-close endpoints use GET methods for state-changing operations. This allows these operations to be triggered by any cross-origin reference such as img tags, link prefetch, or other browser mechanisms. Combined with the lack of authorization checks, this creates an undocumented pathway where elections can be manipulated without the user even visiting the application, simply by loading a malicious image or link.

**Remediation:**

Change state-modifying operations to POST methods and implement proper CSRF protection. Example: @APP.post('/do-open/&lt;eid&gt;') @asfquart.auth.require({R.committer}) @load_election async def do_open_endpoint(election): await verify_csrf_token(); await check_election_authz(election, (await basic_info()).uid); election.open(pdb); ...

---

#### FINDING-020: Vote Submission Lacks Explicit Voter Eligibility Check

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-285 |
| ASVS sections | 8.2.2, 8.3.1, 2.2.3 |
| Files | v3/server/pages.py (407-430), v3/steve/election.py (254-268) |
| Source Reports | 8.2.2.md, 8.3.1.md, 2.2.3.md |
| Related | - | **Description:**

The do_vote_endpoint function lacks an explicit voter eligibility check before processing votes. Authorization relies on an implicit side-effect where add_vote() throws an AttributeError when accessing mayvote.salt if mayvote is None (when q_get_mayvote.first_row() returns no result). This is a Type C gap where the control (mayvote lookup) is called but its result isn't explicitly validated before use. The pattern is fragile and could be silently broken by code refactoring (e.g., adding a default value to mayvote.salt). While the generic error message prevents information leakage, the lack of explicit authorization checking violates secure coding principles.

**Remediation:**

In the add_vote() method in election.py, add explicit eligibility check immediately after q_get_mayvote.first_row(pid, iid): if mayvote is None: raise NotEligibleToVote(f'User {pid} not eligible to vote on issue {iid}'). Define custom NotEligibleToVote exception class. This makes the authorization check explicit and intentional rather than relying on implicit AttributeError. Update do_vote_endpoint to catch NotEligibleToVote and return appropriate 403 response with clear error message.

---

#### FINDING-021: Management Endpoints Expose Sensitive Election Metadata Without Authorization

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-639 |
| ASVS sections | 8.2.3, 8.4.2 |
| Files | v3/server/pages.py (343-363), v3/server/pages.py (193) |
| Source Reports | 8.2.3.md, 8.4.2.md |
| Related | FINDING-022, FINDING-109, FINDING-110 | **Description:**

The manage_page endpoint exposes sensitive election metadata fields (owner_pid, authz LDAP group, issue kv data including STV candidate lists and seat counts) to any authenticated committer without verifying ownership or authorization. Any authenticated committer can view election configuration for any election by knowing or guessing the 10-character hex EID. This results in unauthorized field-level data exposure including: authz LDAP group name (reveals organizational structure), owner_pid (reveals election administrator identity), issue kv data (reveals STV candidate lists, seat counts before election opens), and full issue titles and descriptions (potentially confidential ballot topics). This violates field-level access control requirements (BOPLA).

**Remediation:**

Add await check_election_authz(election, result.uid) to manage_page and manage_stv_page immediately after basic_info() call and before displaying any election data. Implement is_authorized_manager() function that validates user's uid against md.owner_pid and md.authz LDAP group membership. Return 403 Forbidden if not authorized. This ensures backend authorization enforcement matches UI-level filtering and prevents information disclosure through direct URL navigation.

---

#### FINDING-022: Shared Database Without Tenant-Level Data Isolation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-639 |
| ASVS sections | 8.4.1 |
| Files | v3/schema.sql, v3/steve/election.py (list_closed_election_ids) |
| Source Reports | 8.4.1.md |
| Related | FINDING-021, FINDING-109, FINDING-110 | **Description:**

All elections for all organizational groups (tenants) share a single SQLite database (steve.db) with no row-level security. The authz field provides logical tenancy, but query methods like list_closed_election_ids() return ALL elections without tenant filtering. The method has no tenant parameter, meaning any code calling it gets cross-tenant data. While CLI access to all elections is documented as intentional for administrative purposes, the lack of tenant filtering in query methods means administrative functions have access to ALL elections across all tenant boundaries without explicit authorization checks or audit trails.

**Remediation:**

Add tenant filtering to list_closed_election_ids() method by adding an authz_filter parameter. When authz_filter is provided, use a query that filters by the authz group (e.g., q_closed_election_ids_by_authz = 'SELECT eid FROM election WHERE state = ? AND authz = ? ORDER BY close_at DESC'). Only allow unfiltered access for admin CLI operations with explicit authorization and audit logging. Apply similar tenant filtering to any other cross-election queries used by the web interface. Document which functions are intentionally cross-tenant for administrative purposes.

---

#### FINDING-023: No Absolute Maximum Session Lifetime Enforced

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.3.2 |
| Files | v3/server/pages.py (entire file) |
| Source Reports | 7.3.2.md |
| Related | - | **Description:**

The application code contains no absolute session lifetime limit, no session creation timestamp stored in session data, no validation of session age before granting access, and no documented security decision regarding maximum session lifetime. User authenticates, session is created with no creation timestamp, session is used over days/weeks/months, no absolute expiration is enforced, and session remains valid permanently as long as it exists. For an election system where elections have defined open/close periods, a session that outlives an election's lifecycle could allow unintended access patterns. A compromised session token could be used indefinitely by an attacker. Even if a user changes their password or credentials are rotated, the existing session may remain valid. This is particularly concerning for election management operations where election states are time-sensitive.

**Remediation:**

Implement absolute session lifetime enforcement: 1) Add SESSION_MAX_LIFETIME configuration (e.g., 8 hours), 2) Store session creation timestamp in session data (session['created_at'] = time.time()), 3) Validate session age in basic_info() or middleware before granting access, 4) Destroy session and return 401 if session exceeds maximum lifetime, 5) Document security decision regarding chosen lifetime value based on risk analysis.

---

#### FINDING-024: No logout endpoint exists - users cannot terminate sessions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L3 |
| CWE | - |
| ASVS sections | 7.4.1, 6.5.6 |
| Files | v3/server/pages.py (entire routes list) |
| Source Reports | 7.4.1.md, 6.5.6.md |
| Related | - | **Description:**

The application defines 21 routes across GET and POST methods, but NONE of them implement session termination functionality. There is no /logout endpoint, no session destruction call (asfquart.session.destroy() or equivalent), and no mechanism to invalidate sessions on expiration. Users cannot actively terminate their sessions. If a user accesses the system from a shared computer, the next user can access election management features. Combined with the absence of timeouts (7.3.1, 7.3.2), sessions effectively persist indefinitely. This is a Type A gap — the entry point (logout) does not exist at all.

**Remediation:**

Implement a logout endpoint that destroys the session on the backend and clears the session cookie:

```python
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
```

---

#### FINDING-025: No session termination when user account is deleted or disabled

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 7.4.2 |
| Files | v3/queries.yaml (c_delete_person query definition), election.py (no session termination on person operations), pages.py (no endpoint or logic to terminate sessions on account disable/delete) |
| Source Reports | 7.4.2.md |
| Related | - | **Description:**

The system has a c_delete_person SQL query defined in queries.yaml but no application-level code that terminates sessions when a person is deleted. There is no session store indexed by person ID (PID) for bulk invalidation, no mechanism to link active sessions to person records, and no disabled flag in the person table schema for soft-disabling accounts. When a person's account is deleted (e.g., they leave the organization), their active sessions continue to work, allowing them to continue to vote, manage elections, or access sensitive election data until their session naturally expires.

**Remediation:**

Implement delete_person function that first terminates all active sessions for the user (via terminate_all_sessions_for_user) before deleting the person record. Add session-to-user mapping in session store to enable bulk invalidation by user ID. For server-side sessions, use DELETE FROM sessions WHERE user_id = ?. For JWTs, add PID to revocation list or update per-user invalidation timestamp. Log all person deletions and session terminations.

---

#### FINDING-026: No administrative capability to terminate active sessions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.4.5 |
| Files | v3/server/pages.py (279) |
| Source Reports | 7.4.5.md |
| Related | - | **Description:**

There is no administrative capability to terminate active sessions for individual users or all users. The `/admin` page (line 279) only shows election management functionality. No session management endpoints exist anywhere in the application code. If a user account is compromised or a user leaves the organization, administrators cannot force session invalidation. Active compromised sessions persist until natural expiration, extending the window for unauthorized access to election data and voting.

**Remediation:**

Implement an admin session management interface with endpoints for viewing active sessions, terminating sessions for individual users, and terminating all sessions. Add proper admin role definition and implement session store with termination API. Example implementation includes: `/admin/sessions` GET endpoint to list all active sessions, `/admin/sessions/terminate/<uid>` POST endpoint to terminate sessions for a specific user, and `/admin/sessions/terminate-all` POST endpoint to invalidate all active sessions. All endpoints should require proper admin role authorization and log administrative actions.

---

#### FINDING-027: Missing User Session Viewing and Termination Functionality

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.5.2 |
| Files | v3/server/pages.py (entire file scope) |
| Source Reports | 7.5.2.md |
| Related | - | **Description:**

There is no functionality for users to view their currently active sessions or terminate specific sessions. The /profile and /settings pages do not include any session management capabilities. No endpoints exist for listing or invalidating user sessions. Users cannot detect if their account is being used from unauthorized locations/devices. If a session is compromised, the legitimate user has no mechanism to revoke it other than the single "Sign Out" link (which only terminates their current session). This is especially critical for a voting system where unauthorized session use could result in fraudulent votes.

**Remediation:**

Implement three new endpoints: (1) GET /sessions - Display all active sessions for the authenticated user with metadata (device, time, location), marking the current session. (2) POST /sessions/terminate/&lt;session_id&gt; - Allow termination of a specific session after re-authentication with at least one factor. (3) POST /sessions/terminate-all - Terminate all sessions except the current one, also requiring re-authentication. All termination operations must verify user identity through re-authentication before execution. Add session listing data to the profile template and create a new sessions.ezt template for the session management interface.

---

#### FINDING-028: Voting operation lacks step-up authentication or secondary verification

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 7.5.3 |
| Files | v3/server/pages.py (372-407) |
| Source Reports | 7.5.3.md |
| Related | - | **Description:**

Voting — a highly sensitive operation in an election system — does not require step-up authentication or secondary verification. Once a user has an active session, they can cast votes with no additional verification. An attacker with a hijacked session (via XSS exploitation facilitated by the placeholder CSRF token) can cast votes on behalf of the victim without any additional authentication challenge. In a voting system, casting votes is the most sensitive operation. Without step-up authentication, a compromised session directly leads to election manipulation. Combined with the non-functional CSRF protection (line 83: basic.csrf_token = 'placeholder'), this creates a critical attack surface for vote manipulation via session hijacking or CSRF.

**Remediation:**

Implement step-up authentication that requires recent re-authentication for sensitive operations. Example implementation: Create a require_step_up_auth function that checks if the last step-up authentication occurred within a validity window (e.g., 5 minutes). If not, redirect to a step-up authentication page before allowing the vote operation to proceed. Store the last_step_up_auth timestamp in the session and validate it before processing votes.

---

#### FINDING-029: State-Changing GET Endpoints Enable Session Creation + Action Without User Interaction

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.6.2 |
| Files | v3/server/pages.py (539-556), v3/server/pages.py (559-574) |
| Source Reports | 7.6.2.md |
| Related | - | **Description:**

State-changing operations (opening/closing elections) are exposed as GET endpoints with authentication decorators. This creates a compound violation where silent session creation can be immediately followed by sensitive state changes without explicit user interaction. When a user has an expired RP session but active IdP session, an attacker can craft a link that triggers OAuth flow, creates a new session at the RP, and immediately executes a state-changing operation (election opened/closed). The data flow: User has expired RP session but active IdP session → Attacker crafts link to /do-open/abc1234567 → User clicks link → Auth decorator triggers OAuth flow with silent re-auth at IdP → New session created at RP → State-changing operation executes. An attacker who can induce a user to click a link or load an image can trigger election state changes without the user's knowledge or explicit consent.

**Remediation:**

Convert state-changing operations from GET to POST and require CSRF token validation. Change @APP.get to @APP.post for do_open_endpoint and do_close_endpoint functions. Implement and validate CSRF tokens (not placeholder) in these endpoints before executing state changes. This prevents link-triggered session creation combined with immediate state changes.

---

#### FINDING-030: Stored XSS in HTML Context - Election and Issue Metadata

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L3 |
| CWE | CWE-79 |
| ASVS sections | 1.2.1, 3.2.3 |
| Files | v3/server/templates/vote-on.ezt (80), v3/server/templates/vote-on.ezt (82), v3/server/templates/vote-on.ezt (83), v3/server/templates/vote-on.ezt (111) |
| Source Reports | 1.2.1.md, 3.2.3.md |
| Related | FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127, FINDING-128 | **Description:**

Admin sets issue description containing malicious HTML such as `<form id="voteForm" action="https://evil.com/steal">` which is stored in DB and rendered as raw HTML in voting page. When JavaScript calls `document.getElementById('voteForm')`, it resolves to attacker's element instead of the legitimate form. The `submitFormWithLoading('voteForm', ...)` function then submits votes to attacker's server. The vulnerability exists because `rewrite_description()` outputs raw HTML (`<pre>{desc}</pre>` where desc is unescaped user content) and vote-on.ezt renders descriptions as HTML without escaping.

**Remediation:**

1. HTML-escape descriptions before rendering (prevents injection entirely). 2. Use explicit variable references instead of `getElementById` for critical elements: Store direct references at initialization (e.g., `const voteFormRef = document.querySelector('form#voteForm[method="POST"]');`). 3. Verify element type before use: `if (!(voteFormRef instanceof HTMLFormElement)) throw new Error('Form element compromised');`

---

#### FINDING-031: Stored XSS in HTML Context - Issue Descriptions in Management Template

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS sections | 1.2.1 |
| Files | v3/server/templates/manage.ezt (248) |
| Source Reports | 1.2.1.md |
| Related | FINDING-030, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127, FINDING-128 | **Description:**

Issue descriptions are output without HTML encoding in the management template. Unlike vote-on.ezt where rewrite_description is called, manage.ezt outputs descriptions directly. A description containing script tags would execute. Issue descriptions from the database are output raw into HTML div elements.

**Remediation:**

Apply HTML encoding to issue descriptions: &lt;div id="description-[issues.iid]" class="description mt-2"&gt;[format "html"][issues.description][end]&lt;/div&gt;

---

#### FINDING-032: Output encoding performed too early in rewrite_description function

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-79 |
| ASVS sections | 1.1.2 |
| Files | v3/server/pages.py (50-59) |
| Source Reports | 1.1.2.md |
| Related | FINDING-030, FINDING-031, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127, FINDING-128 | **Description:**

The rewrite_description function constructs HTML markup and stores it on the object property before rendering. Output encoding/escaping is being performed too early (or rather, not at all). The function constructs HTML markup by embedding raw user-controlled content (issue.description) directly into HTML tags without encoding. This pre-baked HTML is then output in the template. Since EZT doesn't HTML-encode by default, the description content is never encoded. The encoding should happen at template render time, but the function makes this impossible by mixing raw user content with HTML structure prematurely.

**Remediation:**

Apply html.escape() to the description text before constructing HTML markup, and use urllib.parse.quote() for filenames in constructed URLs. Example: import html; desc = html.escape(issue.description); def repl(match): filename = html.escape(match.group(1)); url_filename = urllib.parse.quote(match.group(1)); return f'&lt;a href="/docs/{issue.iid}/{url_filename}"&gt;{filename}&lt;/a&gt;'; desc = re.sub(r'doc:([^\s]+)', repl, desc); issue.description = f'&lt;pre&gt;{desc}&lt;/pre&gt;'

---

#### FINDING-033: Issue descriptions rendered as raw HTML enabling stored XSS

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-79 |
| ASVS sections | 3.2.2, 1.3.1, 1.3.3, 1.3.5 |
| Files | v3/server/pages.py (47), v3/server/templates/vote-on.ezt, v3/server/templates/manage.ezt |
| Source Reports | 3.2.2.md, 1.3.1.md, 1.3.3.md, 1.3.5.md |
| Related | FINDING-030, FINDING-031, FINDING-032, FINDING-034, FINDING-035, FINDING-126, FINDING-127, FINDING-128 | **Description:**

User-submitted issue descriptions are stored without sanitization and then wrapped in HTML tags (&lt;pre&gt;, &lt;a&gt;) by the rewrite_description() function. Since the content must be rendered unescaped for the formatting to work, malicious HTML/JavaScript in the description executes in the context of all voters viewing the election. Data flow: User submits description via POST → stored in SQLite → retrieved by list_issues() → transformed by rewrite_description() (adds HTML tags) → rendered unescaped in template. No HTML sanitization (bleach.clean(), html.escape()) is applied at any point. This allows authenticated committers who can create/edit issues to inject arbitrary JavaScript that executes in the browsers of all voters, enabling session hijacking, vote manipulation via CSRF, and data exfiltration.

**Remediation:**

Apply html.escape() to issue.description BEFORE constructing HTML in rewrite_description(). Example: desc = html.escape(issue.description) as the first step in the function. This neutralizes any HTML tags in the user input while preserving the ability to add safe formatting tags afterward. For enhanced security, implement a strict allowlist-based HTML sanitizer using bleach or similar library: bleach.clean(issue.description, tags=['b', 'i', 'em', 'strong', 'br'], attributes={}, strip=True)

---

#### FINDING-034: Reflected XSS via election/issue/person IDs in error templates

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS sections | 3.2.2 |
| Files | v3/server/templates/e_bad_eid.ezt, v3/server/templates/e_bad_iid.ezt, v3/server/templates/e_bad_pid.ezt |
| Source Reports | 3.2.2.md |
| Related | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-035, FINDING-126, FINDING-127, FINDING-128 | **Description:**

Election IDs, issue IDs, and person IDs from URL parameters are reflected in error page templates (e_bad_eid.ezt, e_bad_iid.ezt, e_bad_pid.ezt) without HTML encoding. An attacker can craft a URL with a malicious ID containing HTML/JavaScript (e.g., /manage/&lt;img src=x onerror=alert(document.cookie)&gt;). When the load_election decorator catches ElectionNotFound, it sets result.eid to the raw URL parameter and renders the error template with [eid] output unescaped, resulting in reflected XSS.

**Remediation:**

Apply [format "html"] encoding in all error templates: The Election ID ([format "html"][eid][end]) does not exist, The Issue ID ([format "html"][iid][end]) does not exist, The Person ID ([format "html"][pid][end]) does not exist.

---

#### FINDING-035: User-uploaded documents served without Content-Disposition or Content-Type restrictions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS sections | 3.2.1 |
| Files | v3/server/pages.py (506-523) |
| Source Reports | 3.2.1.md |
| Related | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-126, FINDING-127, FINDING-128 | **Description:**

User-uploaded documents are served via send_from_directory without Content-Disposition or Content-Type restrictions. Admin uploads document (e.g., exploit.html) which is stored in DOCSDIR/&lt;iid&gt;/ and served with browser-guessed MIME type. Browser renders as HTML in application origin, allowing execution of malicious scripts. Proof of concept: Admin creates election issue with description containing doc:exploit.html, places exploit.html containing script to steal cookies in the docs directory, voter with valid mayvote entry visits /docs/&lt;iid&gt;/exploit.html, and browser renders the document as HTML in the application's origin, executing the script.

**Remediation:**

Validate docname to prevent path traversal by checking for '..' or '/' or '\' characters and aborting with 400 if present. Force download disposition and restrict content type by using as_attachment=True parameter in send_from_directory which sets Content-Disposition: attachment. Add X-Content-Type-Options: nosniff header and Content-Security-Policy: default-src 'none' header to the response.

---

#### FINDING-036: Authenticated Document Endpoint Serves Resources Without Cross-Origin-Resource-Policy or Sec-Fetch-* Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS sections | 3.5.8 |
| Files | v3/server/pages.py (651-666) |
| Source Reports | 3.5.8.md |
| Related | - | **Description:**

The serve_doc endpoint serves authenticated election documents without Cross-Origin-Resource-Policy headers or Sec-Fetch-* validation. Authenticated election documents (images, diagrams, PDFs) can be loaded on attacker pages via cross-origin img/video/object/embed tags, leaking confidential election materials. This creates a timing/existence oracle where attackers can determine whether a user has mayvote access to specific elections by checking load success/failure. With permissive CORS or browser bugs, pixel-level data extraction from images is possible.

**Remediation:**

1. Validate Sec-Fetch-Site and Sec-Fetch-Dest headers, only allowing 'same-origin', 'none' (direct navigation), or empty string. Reject all other values with 403. 2. Add 'Cross-Origin-Resource-Policy: same-origin' response header to all document responses to prevent cross-origin embedding at the browser level.

---

#### FINDING-037: Missing Comprehensive Session Cookie Security Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-614 |
| ASVS sections | 3.3.1, 3.3.2, 3.3.3, 3.3.4 |
| Files | v3/server/main.py (44), v3/server/pages.py (Application-wide) |
| Source Reports | 3.3.1.md, 3.3.2.md, 3.3.3.md, 3.3.4.md |
| Related | - | **Description:**

The application does not explicitly configure critical security attributes for session cookies including: Secure attribute, __Host-/__Secure- prefix, HttpOnly attribute, and SameSite attribute. While the asfquart framework may provide some defaults internally, no explicit cookie security configuration exists in the application code. This creates dependency on undocumented framework behavior and leaves session cookies vulnerable to: (1) interception via network sniffing if transmitted over unencrypted connections, (2) cross-site request forgery attacks due to missing SameSite protection, (3) JavaScript access via XSS due to unverified HttpOnly enforcement, and (4) subdomain cookie injection attacks due to missing __Host- prefix. The session cookie is created by the framework without explicit security hardening in v3/server/main.py.

**Remediation:**

Explicitly configure all session cookie security attributes in the create_app() function:

```python
app.config.update(
    SESSION_COOKIE_NAME='__Host-steve_session',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
    SESSION_COOKIE_PATH='/',
)
```

This ensures: (1) Secure attribute prevents transmission over HTTP, (2) __Host- prefix binds cookie to exact host and enforces Secure/Path requirements, (3) HttpOnly prevents JavaScript access, (4) SameSite=Strict prevents cross-site request inclusion.

---

#### FINDING-038: No Content-Security-Policy Header Defined in Any HTTP Response

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-1021 |
| ASVS sections | 3.4.3, 3.4.7 |
| Files | v3/server/main.py (Application-wide), v3/server/pages.py (Application-wide) |
| Source Reports | 3.4.3.md, 3.4.7.md |
| Related | FINDING-039, FINDING-040 | **Description:**

The application does not set a Content-Security-Policy header on any HTTP response. Without CSP, the application has no defense-in-depth against cross-site scripting (XSS) attacks, data exfiltration via injected &lt;object&gt;, &lt;embed&gt;, or &lt;base&gt; tags, and clickjacking via embedded frames. The ASVS requirement mandates at minimum: object-src 'none', base-uri 'none', plus either an allowlist or nonces/hashes for script sources. Client requests flow through route handlers to template rendering and HTTP responses without any CSP header being set. An XSS payload would execute without CSP restrictions. Additionally, no CSP violation reporting endpoint is configured (report-uri/report-to directives), meaning XSS exploitation attempts and policy misconfigurations go undetected.

**Remediation:**

Implement a global after_request handler in main.py that sets CSP headers on every response:

```python
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
```

Add CSP violation reporting endpoint:

```python
@APP.post('/csp-report')
async def csp_report():
    report = await quart.request.get_json(force=True)
    _LOGGER.warning(f'CSP Violation: {report}')
    return '', 204
```

Deploy Content-Security-Policy-Report-Only initially to identify policy violations before enforcement.

---

#### FINDING-039: No frame-ancestors CSP Directive Prevents Clickjacking

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-1021 |
| ASVS sections | 3.4.6 |
| Files | v3/server/main.py (Application-wide), v3/server/pages.py (Application-wide) |
| Source Reports | 3.4.6.md |
| Related | FINDING-038, FINDING-040 | **Description:**

The web application does not set the frame-ancestors directive in the Content-Security-Policy header for any HTTP response. This allows the application to be embedded in iframes on malicious sites, enabling clickjacking attacks. All page handlers return responses without framing protection. The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints use GET methods and perform state-changing operations, making them particularly vulnerable to clickjacking combined with the lack of framing protection. An attacker can create a malicious page with an iframe embedding the application and trick authenticated users into performing unintended actions.

**Remediation:**

Implement a global after_request handler that sets the frame-ancestors directive in the Content-Security-Policy header for every response:

```python
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
```

Additionally, convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods to reduce clickjacking and CSRF attack surface.

#### FINDING-040: Missing Cross-Origin-Opener-Policy Header on HTML Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-1021 |
| **ASVS Sections** | 3.4.8 |
| **Files** | v3/server/pages.py (Application-wide), v3/server/main.py (Application-wide) |
| **Source Reports** | 3.4.8.md |
| **Related Findings** | FINDING-038, FINDING-039 | **Description:**

The application does not set the `Cross-Origin-Opener-Policy` (COOP) header on any HTTP responses that render HTML documents. There is no `after_request` handler, middleware, or framework configuration that adds this header. All template-rendered endpoints (using `@APP.use_template()`) return HTML responses without COOP protection. Without COOP, cross-origin pages that open or are opened by the application can retain references to the `Window` object. This enables tabnabbing attacks (where a malicious page opened via `target=_blank` replaces the opener with a phishing page) and frame-counting side-channel attacks.

**Remediation:**

Implement an `after_request` handler to set the COOP header on all HTML responses:

```python
@APP.after_request
async def set_security_headers(response):
    content_type = response.content_type or ''
    if 'text/html' in content_type:
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    return response
```

---

#### FINDING-041: No TLS Protocol Version Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 12.1.1 |
| **Files** | v3/server/main.py:75-78 |
| **Source Reports** | 12.1.1.md |
| **Related Findings** | None | **Description:**

The application starts with whatever TLS versions the underlying framework (Quart/Hypercorn) defaults to. Without explicit configuration, older TLS versions (TLS 1.0, TLS 1.1) may be negotiable depending on the runtime environment and library versions. Config values for certfile and keyfile are passed directly to app.run() without any TLS protocol version constraints. An attacker can attempt handshake with deprecated TLS versions using openssl s_client -connect localhost:58383 -tls1_1.

**Remediation:**

Explicitly configure minimum TLS protocol version and prefer TLS 1.3. For Hypercorn (the ASGI server used in run_asgi()), configure via hypercorn.toml or programmatically: create an SSL context with ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2; ctx.maximum_version = ssl.TLSVersion.TLSv1_3; ctx.load_cert_chain(certfile, keyfile). For config.yaml, add server.min_tls_version: '1.2'.

---

#### FINDING-042: No Cipher Suite Configuration - Weak Ciphers May Be Negotiated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 12.1.2 |
| **Files** | v3/server/main.py:75-82 |
| **Source Reports** | 12.1.2.md |
| **Related Findings** | None | **Description:**

The application has no control over which cipher suites are enabled. Without explicit cipher suite configuration, weak ciphers may be negotiated. Depending on the Python/OpenSSL version, this could allow: Non-forward-secrecy ciphers (e.g., RSA key exchange), Weak encryption algorithms (e.g., 3DES, RC4), Weak hash algorithms in cipher suites (e.g., SHA-1 based MACs). For L3 compliance, the application MUST only support cipher suites providing forward secrecy (ECDHE/DHE key exchange).

**Remediation:**

Create an SSL context with explicit cipher suite configuration. Use ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) with minimum_version = ssl.TLSVersion.TLSv1_2. Set ciphers to only allow strong cipher suites with forward secrecy: 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES'. Load certificate chain using ctx.load_cert_chain(certfile, keyfile).

---

#### FINDING-043: TLS Configuration is Optional - Application Allows Plain HTTP

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Sections** | 12.2.1, 12.3.1, 12.2.2 |
| **Files** | v3/server/config.yaml.example:6-12, v3/server/main.py:72-82 |
| **Source Reports** | 12.2.1.md, 12.3.1.md, 12.2.2.md |
| **Related Findings** | None | **Description:**

The configuration explicitly documents that TLS can be disabled by leaving certfile and keyfile fields blank. When running without TLS, session cookies are transmitted in cleartext (session hijacking), OAuth tokens and credentials are exposed, vote data is transmitted unencrypted, no mechanism exists to redirect HTTP to HTTPS, and no HSTS header enforcement is visible in the code. This is a voting application handling sensitive election data—running without TLS completely undermines confidentiality and integrity.

**Remediation:**

Enforce TLS at startup by modifying main.py to require TLS configuration and fail with a clear error if certificates are missing or invalid. Example code:

```python
if not app.cfg.server.certfile or not app.cfg.server.keyfile:
    _LOGGER.critical('TLS certificates MUST be configured. Set server.certfile and server.keyfile in config.yaml')
    sys.exit(1)

kwargs['certfile'] = CERTS_DIR / app.cfg.server.certfile
kwargs['keyfile'] = CERTS_DIR / app.cfg.server.keyfile
```

---

#### FINDING-044: Election Title and Issue Title/Description Have No Server-Side Length or Content Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 2.2.1 |
| **Files** | v3/server/pages.py:410-425, v3/server/pages.py:469-490, v3/server/pages.py:493-515 |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None | **Description:**

User-supplied text fields (election title, issue title, issue description) are passed directly to the database without any validation in `do_create_endpoint()`, `do_add_issue_endpoint()`, and `do_edit_issue_endpoint()`. Extremely long titles could cause display issues, memory exhaustion, or denial of service. Empty titles violate logical expectations (NOT NULL ≠ non-empty). No character set validation allows control characters or other problematic content. Affects the `gather_election_data()` anti-tamper hash — maliciously crafted titles could cause issues.

**Remediation:**

Add server-side validation for title and description fields: strip whitespace, check for non-empty values, enforce maximum length limits (title: 200 characters, description: 10,000 characters). Return error messages via flash_danger and redirect on validation failure. Consider adding database CHECK constraints for length limits as defense-in-depth.

---

#### FINDING-045: Document Filename (docname) Relies Solely on Framework Protection Without Explicit Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 2.2.1 |
| **Files** | v3/server/pages.py:560-574 |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None | **Description:**

The `serve_doc()` endpoint serves files based on user-supplied `iid` and `docname` parameters. While `send_from_directory` provides framework-level path traversal protection, the code explicitly acknowledges missing validation with a TODO comment. The `docname` parameter could contain special characters, encoded sequences, or reference symlinks. The `iid` parameter constructs a directory path without validating that it's a valid 10-char hex string. Depending on framework version and edge cases, this could lead to unauthorized file access outside the intended document directory.

**Remediation:**

Implement explicit validation for `docname`: use a regex pattern to allow only alphanumeric characters, hyphens, underscores, and dots (e.g., `^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]{0,254}$`). Reject filenames starting with dots or containing `..` sequences. Return HTTP 400 for invalid filenames before calling `send_from_directory`.

---

#### FINDING-046: Multi-Vote Submission Not Wrapped in Transaction — Partial Failure Leaves Inconsistent State

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 2.3.3, 16.5.3 |
| **Files** | v3/server/pages.py:372 |
| **Source Reports** | 2.3.3.md, 16.5.3.md |
| **Related Findings** | None | **Description:**

User submits ballot with 10 issues → Loop processes votes one by one → Vote #5 fails → Votes #1-4 already committed → User told "error" but partial votes persist. Atomic ballot submission is not guaranteed. A voter's intent is a complete ballot, but partial submission creates an inconsistent state where some issues have new votes and others retain old votes. This violates the principle that business operations should succeed entirely or roll back.

**Remediation:**

Wrap all votes in a transaction:

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

---

#### FINDING-047: Election Open Operation Not Fully Atomic — Salt Addition and State Change in Separate Transactions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 2.3.3, 15.4.2 |
| **Files** | v3/steve/election.py:70 |
| **Source Reports** | 2.3.3.md, 15.4.2.md |
| **Related Findings** | None | **Description:**

The open() method performs a non-atomic sequence where it checks if the election is editable (is_editable()), then writes salts (add_salts()), and finally changes the election state (c_open.perform()). No transaction wraps this sequence. If two administrators call open() concurrently, both can pass the is_editable() check before either changes the state. This leads to: T1: Admin A calls open(), passes is_editable() check; T2: Admin B calls open(), also passes is_editable() check; T3: Admin A's add_salts() runs, writes salts; T4: Admin B's add_salts() runs, OVERWRITES salts with different values; T5: Admin A's c_open.perform() runs with opened_key based on original salts; T6: Admin B's c_open.perform() runs, overwrites opened_key. The result is that opened_key and salts are inconsistent, breaking tamper detection and preventing proper tallying.

**Remediation:**

Wrap the entire open() operation in a BEGIN IMMEDIATE transaction. Re-check the election state within the transaction using _all_metadata() to ensure the state hasn't changed. If the state is not editable, rollback and raise ElectionBadState. Integrate add_salts() operations into the same transaction (remove its internal transaction). Include proper exception handling with ROLLBACK on error and COMMIT on success.

---

#### FINDING-048: No Validation That close_at Is After open_at When Setting Dates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 2.2.3 |
| **Files** | v3/server/pages.py:88-110, v3/steve/election.py |
| **Source Reports** | 2.2.3.md |
| **Related Findings** | None | **Description:**

When setting open_at or close_at dates, the application does not validate the logical relationship between them. A user can set close_at to Jan 1, 2024 and then set open_at to Feb 1, 2024, resulting in close_at < open_at which is logically inconsistent. This is a Type A gap where no cross-field consistency validation exists.

**Remediation:**

Add validation in _set_election_date() to check cross-field consistency. When setting open_at, verify it is before any existing close_at. When setting close_at, verify it is after any existing open_at. Return a 400 error with descriptive message if the validation fails.

---

#### FINDING-049: No file size validation or upload limits enforced

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 5.2.1 |
| **Files** | v3/server/pages.py (entire application scope) |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | None | **Description:**

The application serves documents via `/docs/<iid>/<docname>` but has no visible file upload endpoint with size validation. The mechanism by which documents are placed into `DOCSDIR` is not shown in the provided code, meaning there are no observable file size checks that would prevent a denial of service via excessively large files. If files are uploaded through an undocumented mechanism, no size limits are enforced by the shown code. Additionally, the Quart application does not set `MAX_CONTENT_LENGTH` (or equivalent) to limit request body size globally, which would affect any file upload functionality added in the future.

**Remediation:**

1. Configure `APP.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024` (10 MB max upload) in application configuration. 2. In any file upload handler, implement file size validation by seeking to end of file, checking size against MAX_FILE_SIZE constant, and rejecting files exceeding the limit with HTTP 413 status. 3. Reset file pointer after size check before processing.

---

#### FINDING-050: Missing file extension and content validation in document serving endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 5.2.2, 5.3.1 |
| **Files** | v3/server/pages.py:560-574 |
| **Source Reports** | 5.2.2.md, 5.3.1.md |
| **Related Findings** | None | **Description:**

The `serve_doc` endpoint serves files from the filesystem without any validation of file extension or content type. The `docname` parameter is passed directly to `send_from_directory` with no check that: 1. The file extension matches an allowlist of permitted types 2. The file content (magic bytes) matches the extension 3. The file is safe for the end-user to download. The comment `### verify the propriety of DOCNAME.` explicitly acknowledges this gap. Without extension allowlisting and content validation, the application could serve polyglot files, HTML/SVG with embedded scripts (leading to stored XSS), or files masquerading as safe types (e.g., `.pdf` containing HTML).

**Remediation:**

Implement file extension allowlisting against a whitelist of permitted extensions (e.g., .pdf, .txt, .png, .jpg, .jpeg). Validate file content using magic bytes verification (python-magic library) to ensure the detected MIME type matches the expected MIME type for the file extension. Add security headers: X-Content-Type-Options: nosniff and Content-Disposition: attachment. Verify that the file is not a symlink before serving.

---

#### FINDING-051: No logging inventory or documentation exists for the application stack

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.1.1 |
| **Files** | v3/server/bin/tally.py:165, v3/server/pages.py:37, v3/steve/election.py:27 |
| **Source Reports** | 16.1.1.md |
| **Related Findings** | None | **Description:**

The application uses Python's standard logging module across three layers (web pages, election library, CLI tools) but no logging inventory document exists defining: What events are logged at each layer, the log format specification, where logs are stored (file, syslog, SIEM), how log access is controlled, log retention periods, and how logs are consumed for monitoring/alerting. The logging.basicConfig(level=logging.INFO) in tally.py sends to stderr by default. The web layer (pages.py) relies on whatever the application framework configures, which is undocumented. The election.py library logs to a logger with no explicit handler configuration.

**Remediation:**

Create a LOGGING_INVENTORY.md or equivalent documentation covering: Layers, Components, Logger Names, Events Logged, Format, Destination, Retention, and Access Control. Example table provided showing Web layer (pages.py), Library layer (election.py), and CLI layer (tally.py) with JSON structured format, destinations to /var/log/steve/ and SIEM, retention of 90 days to 1 year, and access control root:adm 640.

---

#### FINDING-052: Election library logging omits WHO (actor) metadata from security events

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.2.1 |
| **Files** | v3/steve/election.py:207, v3/steve/election.py:219, v3/steve/election.py:231, v3/steve/election.py:430 |
| **Source Reports** | 16.2.1.md |
| **Related Findings** | None | **Description:**

The election.py library logs creation, update, and state-change events without recording WHO performed the action. While pages.py adds user context at the handler level, the library-level logs are missing the actor (PID/UID). If the library is invoked through a different path (e.g., tally.py, future APIs, or direct imports), the WHO metadata is entirely absent. During incident investigation, it becomes impossible to correlate library-level events with the user who triggered them. This creates blind spots in the audit trail, especially for operations that bypass the web layer (CLI tools, scripts, direct database manipulation).

**Remediation:**

Option 1: Pass actor context to library methods (e.g., def add_issue(self, title, description, vtype, kv, actor_pid=None) and log with Actor[U:{actor_pid}]). Option 2: Use logging context via LoggerAdapter or contextvars to propagate actor identity from web handlers into election.py log messages.

---

#### FINDING-053: Tally script performs security-critical operations without audit logging

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.2.1, 16.4.3 |
| **Files** | v3/server/bin/tally.py:138-165 |
| **Source Reports** | 16.2.1.md, 16.4.3.md |
| **Related Findings** | None | **Description:**

The tally script decrypts all votes for an election—one of the most sensitive operations in the system—without logging WHO (which administrator ran the tally), WHEN (timestamp of tally execution), WHERE (from which machine/terminal), or WHAT (which election was tallied, whether --spy-on-open-elections was used). The --spy-on-open-elections flag is especially concerning as it enables viewing votes before an election closes, and its use is not logged at all. An administrator could spy on open election results without any audit trail. Tamper detection events are output via print() rather than formal security logging, meaning they may not reach monitoring systems.

**Remediation:**

Add audit logging for tally operations before outputting results. Example:

```python
_LOGGER.info(f'User tallied election[E:{election.eid}], {len(results)} issues, {len(all_voters)} voters participated')
```

Log who performed the tally, when it was performed, and what election was tallied to create an audit trail for sensitive tally operations.

---

#### FINDING-054: Debug print statements dump complete form data which may contain sensitive election configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.2.5 |
| **Files** | v3/server/pages.py:427, v3/server/pages.py:449 |
| **Source Reports** | 16.2.5.md |
| **Related Findings** | None | **Description:**

Complete form data is dumped to stdout without any filtering or redaction. While current form fields are `title` and `description`, the EasyDict wrapper captures ALL submitted form fields. If future forms include sensitive data (candidate names for confidential elections, authorization groups, etc.), this would log them without protection. The `print()` call is a Type B gap—the `_LOGGER` system exists but is not used here, creating false confidence that logging is controlled. Any data submitted in these forms is broadcast to stdout without classification-based filtering. In containerized deployments, stdout is captured by orchestrators and may be accessible to operators without appropriate clearance.

**Remediation:**

Remove print statements entirely, or log only safe metadata:

```python
_LOGGER.debug(f'Issue form received: fields={list(form.keys())}')
```

Never log form values for election management operations.

---

#### FINDING-055: No Authentication Event Logging in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.3.1 |
| **Files** | v3/server/pages.py (entire file) |
| **Source Reports** | 16.3.1.md |
| **Related Findings** | None | **Description:**

The application relies on `asfquart.auth.require` decorators for authentication enforcement, but no logging occurs at the authentication boundary within this application code. There is no evidence of authentication success or failure being logged. Authentication successes and failures are invisible to security monitoring. Brute force attempts, credential stuffing, or unauthorized access patterns cannot be detected through application logs.

**Remediation:**

Add authentication event logging middleware or hook using @APP.before_request to log all authentication attempts with metadata including uid, method=oauth, ip address, and path for both successful and failed authentication attempts.

---

#### FINDING-056: Document Access Authorization Failure Not Logged

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 16.3.2 |
| **Files** | v3/server/pages.py:596-602 |
| **Source Reports** | 16.3.2.md |
| **Related Findings** | None | **Description:**

Authorization is checked for document access but failures are not logged. The serve_doc function checks mayvote authorization before serving election documents, but when the check fails, it returns a 404 without logging the unauthorized access attempt. Unauthorized attempts to access election documents (potentially sensitive nomination documents) are invisible to security monitoring.

**Remediation:**

Add logging when document authorization check fails before returning 404. Log the user ID, document name, issue ID, and IP address to create an audit trail of unauthorized document access attempts.

---

#### FINDING-057: Missing Authorization Logging in State-Changing Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 16.3.2 |
| **Files** | v3/server/pages.py:449-470, v3/server/pages.py:472-489 |
| **Source Reports** | 16.3.2.md |
| **Related Findings** | None | **Description:**

Multiple state-changing operations (do_open_endpoint, do_close_endpoint, do_set_open_at_endpoint, do_set_close_at_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint) have comments indicating authorization checks are not implemented. Any authenticated committer can open/close any election. Beyond missing authorization, there's no logging of whether the user performing the action is actually the election owner. These unauthorized modifications are logged as successful actions without flagging the lack of ownership.

**Remediation:**

Implement ownership-based authorization checks for all state-changing operations. Log both successful authorization (when user is owner) and failed authorization attempts (when user is not owner but attempts modification). Include user ID, election ID, action attempted, and IP address in logs.

---

#### FINDING-058: Tampering Detection Does Not Use Logger

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.3.3, 16.3.4 |
| **Files** | v3/server/bin/tally.py:153-156 |
| **Source Reports** | 16.3.3.md, 16.3.4.md |
| **Related Findings** | None | **Description:**

The tamper detection check uses print() instead of the logging framework when tampering is detected—a critical security event. Tampering detected → print() to stdout → potentially lost if stdout is not captured → NO structured security log. Critical tampering events may not reach centralized logging systems. A print() to stdout may be lost if the process output is not captured, and it lacks structured metadata (timestamp format, severity, correlation IDs).

**Remediation:**

Replace print() with structured logging using _LOGGER.error with exc_info=True to capture full exception context. Example:

```python
_LOGGER.error('TALLY_ERROR: election=%s, issue=%s, error_type=%s, error=%s', election.eid, issue.iid, type(e).__name__, str(e), exc_info=True)
```

---

#### FINDING-059: Input Validation Failures Not Logged

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.3.3 |
| **Files** | v3/server/pages.py:95-102, v3/server/pages.py:385, v3/server/pages.py:393 |
| **Source Reports** | 16.3.3.md |
| **Related Findings** | None | **Description:**

Input validation failures (potential bypass attempts) are not logged. Malformed input → validation failure → 400 response → NO LOG. Additional instances: do_vote_endpoint (line 385): Missing form data check with no logging; do_vote_endpoint (line 393): Invalid issue ID check with no logging. Injection attempts would be caught by validation but leave no audit trail.

**Remediation:**

Add logging before validation failures:

```python
_LOGGER.warning('INPUT_VALIDATION_FAILURE: uid=%s, endpoint=%s, reason=%s, election=%s', result.uid, endpoint, reason, election.eid)
```

before aborting with 400.

---

#### FINDING-060: User-Controlled Input in Log Messages Without Encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Sections** | 16.4.1, 1.3.10 |
| **Files** | v3/server/pages.py:440-443 |
| **Source Reports** | 16.4.1.md, 1.3.10.md |
| **Related Findings** | FINDING-187 | **Description:**

Python f-strings are evaluated at the call site before being passed to the logging framework, so they are NOT vulnerable to traditional format string attacks (where attacker controls the format specifier). The form.title value is interpolated as a plain string value, not as a format directive. However, form.title could contain log injection characters (newlines, ANSI escape sequences) that could forge log entries or obscure audit trails. An attacker could inject newlines to create fake log entries.

**Remediation:**

Add a utility function to sanitize user-provided values before logging:

```python
import re

def sanitize_for_log(value: str) -> str:
    """Remove control characters that could enable log injection."""
    return re.sub(r'[\x00-\x1f\x7f]', '', value)

_LOGGER.info(
    f'User[U:{result.uid}] created election[E:{election.eid}];'
    f' title: "{sanitize_for_log(form.title)}"'
)
```

---

#### FINDING-061: No log transmission to a logically separate system

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.4.3 |
| **Files** | v3/server/pages.py:35, v3/steve/election.py:7, v3/server/bin/tally.py:34, v3/server/bin/tally.py:166 |
| **Source Reports** | 16.4.3.md |
| **Related Findings** | None | **Description:**

The entire application uses Python's standard logging module with no configuration for transmitting logs to a logically separate system. The tally.py CLI configures logging.basicConfig(level=logging.INFO) which outputs to stderr only. The web application (pages.py) relies on Quart's default logging configuration, which similarly only writes locally. There is no evidence of syslog forwarding configuration (e.g., SysLogHandler), integration with centralized log management (ELK, Splunk, CloudWatch), log shipping agents or sidecars configured, remote logging handlers (SocketHandler, HTTPHandler), or any log output to files that could be shipped. If the application server is compromised, all security-relevant logs (authentication events, vote casting, election lifecycle changes, authorization failures) reside on the same system and can be modified or deleted by an attacker, destroying forensic evidence.

**Remediation:**

Configure remote log transmission using Python's logging handlers. Example: import logging.handlers and configure SysLogHandler to send logs to a remote syslog/log aggregator at address ('logserver.internal.example.org', 514) with facility LOG_AUTH. Set appropriate formatter with timestamp, name, level, and message. Integrate with centralized log management system (ELK, Splunk, CloudWatch) or configure log shipping agents/sidecars.

---

#### FINDING-062: No graceful degradation for database connectivity failures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.5.2 |
| **Files** | v3/server/pages.py (all route handlers), v3/steve/election.py:38 |
| **Source Reports** | 16.5.2.md |
| **Related Findings** | None | **Description:**

The load_election and load_election_issue decorators only catch ElectionNotFound exceptions. If the SQLite database file is locked, corrupted, or unavailable (disk full, permissions changed, etc.), an unhandled exception propagates to the framework's default error handler. There is no circuit breaker, retry logic, or graceful degradation pattern. This affects ALL routes that use load_election or load_election_issue. Database lock contention, disk failures, or resource exhaustion causes unhandled exceptions across all endpoints, potentially exposing error details and causing service unavailability without informative user messaging.

**Remediation:**

Wrap the Election initialization in the load_election decorator with try/except to catch sqlite3.OperationalError and OSError, logging the error and returning HTTP 503 Service Unavailable.

---

#### FINDING-063: Implicit authorization failure via None dereference instead of explicit check in add_vote

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.5.3 |
| **Files** | v3/steve/election.py:210-211 |
| **Source Reports** | 16.5.3.md |
| **Related Findings** | None | **Description:**

When a person is not authorized to vote on a specific issue (no mayvote entry exists), the query returns None. The code immediately accesses mayvote.salt without checking for None. This results in an AttributeError rather than a proper authorization denial. While the vote IS blocked (fail-closed), the error response is a generic 500 rather than a proper 403 Forbidden, and the exception may expose details. This represents a fragile security boundary that depends on an accidental crash rather than intentional enforcement.

**Remediation:**

Add explicit None check:

```python
mayvote = self.q_get_mayvote.first_row(pid, iid)
if mayvote is None:
    raise VoterNotAuthorized(f'Person {pid} is not authorized to vote on issue {iid}')
vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
```

---

#### FINDING-064: No global exception handler defined for the web application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 16.5.4 |
| **Files** | v3/server/pages.py (entire file) |
| **Source Reports** | 16.5.4.md |
| **Related Findings** | None | **Description:**

The application defines no "last resort" error handler. There is no @APP.errorhandler(Exception), @APP.errorhandler(500), or equivalent catch-all that would: 1. Log the full exception details for debugging 2. Return a generic error page to the user 3. Prevent the application process from crashing on unexpected exceptions. Only ElectionNotFound, IssueNotFound, and PersonNotFound are caught in specific locations. Any other exception type (e.g., sqlite3.OperationalError, TypeError, KeyError, json.JSONDecodeError) propagates to the framework default handler. Quart's default behavior in production mode returns a 500 page, but there's no guarantee DEBUG mode isn't enabled, error details are not guaranteed to be logged by a custom handler, no alerting or escalation is triggered, and no consistent error response format is provided.

**Remediation:**

Implement global exception handlers: @APP.errorhandler(Exception) for catch-all, @APP.errorhandler(500) for internal errors, and @APP.errorhandler(503) for service unavailability. Each should log the error appropriately and return generic error pages.

---

#### FINDING-065: Unconditional DEBUG logging level in all execution modes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.2, 15.2.3 |
| **Files** | v3/server/main.py:62-67, v3/server/main.py:101-106 |
| **Source Reports** | 13.4.2.md, 15.2.3.md |
| **Related Findings** | None | **Description:**

Both execution modes unconditionally set the root logging level to DEBUG with no environment-based differentiation. There is no configuration option to control this in config.yaml.example. DEBUG-level logging can capture sensitive data (session tokens, database queries, request payloads) that could be exposed through log aggregation systems, error handlers, or if logs are inadvertently exposed.

**Remediation:**

Add environment-aware logging and an explicit debug flag. Add debug: false and log_level: WARNING to config.yaml.example as production-safe defaults. Modify main.py to respect configuration:

```python
log_level = getattr(logging, app.cfg.server.get('log_level', 'WARNING').upper())
```

and add warning if debug mode is enabled.

---

#### FINDING-066: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.1 |
| **Files** | Project-wide (no documentation file found), v3/steve/crypto.py, v3/steve/election.py, v3/server/main.py |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | None | **Description:**

The provided codebase contains multiple third-party dependencies (cryptography, argon2-cffi, asfpy, easydict, Quart/asfquart, ezt) but no documentation defining risk-based remediation timeframes for addressing vulnerabilities or specifying update cadence for these libraries. No SECURITY.md, DEPENDENCY_POLICY.md, or equivalent documentation is present that defines: Critical vulnerability remediation timeframe (e.g., 24-48 hours), High vulnerability remediation timeframe (e.g., 7 days), Medium/Low vulnerability remediation timeframe (e.g., 30-90 days), or Routine update schedule for non-vulnerable components.

**Remediation:**

Create a docs/DEPENDENCY_POLICY.md with explicit timeframes defining: Critical (CVSS ≥ 9.0) remediation within 48 hours, High (CVSS 7.0-8.9) within 7 days, Medium (CVSS 4.0-6.9) within 30 days, Low (CVSS < 4.0) within 90 days. Include routine update schedules: Security-critical libraries (cryptography, argon2-cffi) monthly review, Framework libraries (Quart/asfquart) quarterly review, Utility libraries (easydict, asfpy) semi-annual review. Implement automated CVE monitoring via GitHub Dependabot/Safety/pip-audit and manual review of security advisories for cryptography library.

---

#### FINDING-067: No Software Bill of Materials (SBOM) or dependency manifest with pinned versions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.2, 15.2.4 |
| **Files** | Project-wide, All provided files |
| **Source Reports** | 15.1.2.md, 15.2.4.md |
| **Related Findings** | None | **Description:**

The provided codebase does not include a visible requirements.txt, pyproject.toml with pinned dependencies, Pipfile.lock, uv.lock, or any SBOM document (e.g., CycloneDX or SPDX format). While main.py uses a uv run --script shebang suggesting uv as the package manager, no lock file or dependency specification with version pins is provided. Identified dependencies from code analysis include: cryptography (Fernet, HKDF, hashes) from crypto.py, argon2-cffi (low_level) from crypto.py, asfpy (db, generics) from election.py and main.py, easydict from election.py, asfquart (Quart wrapper) from main.py, and ezt (templating) from domain context. All versions are unknown. Without a versioned inventory: transitive dependencies are untracked (e.g., cryptography pulls in cffi, pycparser), reproducible builds are not guaranteed, vulnerability scanning tools cannot accurately assess the dependency tree, and there is no verification that dependencies come from trusted repositories.

**Remediation:**

1. Create a pyproject.toml with pinned dependencies including cryptography>=43.0.0, argon2-cffi>=23.1.0, asfpy>=0.45, easydict>=1.13, quart>=0.19.0, ezt>=1.2. 2. Generate and maintain a lock file using uv lock with hash verification (uv lock --generate-hashes). 3. Generate SBOM in CycloneDX format using cyclonedx-py environment -o sbom.json. 4. Configure automated SBOM generation in CI/CD pipeline.

---

#### FINDING-068: Undocumented resource-intensive Argon2 operations with potential denial-of-service impact

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.3 |
| **Files** | v3/steve/crypto.py:91-101, v3/steve/election.py:265-324 |
| **Source Reports** | 15.1.3.md |
| **Related Findings** | None | **Description:**

The application contains several resource-intensive operations that are not documented, including Argon2 key derivation that allocates 64MB per call, tally operations that iterate over all voters, and vote submission operations. For an election with 1000 voters and 10 issues, tally_issue() requires 1000 Argon2 calls with potential 64GB aggregate memory demand. Concurrent vote submissions during peak periods could exhaust server memory. There is no documentation of these resource demands, no documented rate limiting or queuing strategy, no consumer timeout guidance, and no documentation of maximum supported election size.

**Remediation:**

Create docs/RESOURCE_ANALYSIS.md documenting: (1) Argon2 key derivation operations consuming 64MB memory and ~50ms CPU per operation at vote submission, tally computation, and election opening; (2) Tally computation complexity of O(voters × issues) Argon2 operations, mitigated by performing offline via admin CLI; (3) Vote submission complexity of 1 Argon2 operation per vote with max concurrent operations limited by server memory; (4) Election opening complexity of O(voters × issues) salt generations plus 1 Argon2 operation; (5) Defense mechanisms including CLI-based tally operations, authenticated vote submission, and single-instance architecture limiting parallelism.

---

#### FINDING-069: Cannot verify component versions are within remediation timeframes due to missing version specifications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.1 |
| **Files** | v3/steve/crypto.py, Project-wide |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | None | **Description:**

Since no dependency manifest with pinned versions exists (as identified in ASVS-15.1.2), and no remediation policy exists (as identified in ASVS-15.1.1), it is impossible to verify that all components are within their documented update and remediation timeframes. Specific concerns include: 1) cryptography library has frequent security advisories without a pinned version, 2) Argon2 Type.D usage in production vs Type.ID in benchmark (OWASP recommends Type.ID for password hashing), 3) asfpy ASF-internal library with unknown release cadence and vulnerability tracking, 4) HKDF info parameter mismatch (info=b'xchacha20_key') suggesting code in transitional state. Without verifiable version information: known CVEs in dependencies may be present but undetected, the application may be running outdated versions of security-critical libraries, auditors cannot confirm compliance with any remediation SLA, and the cryptography library specifically has had multiple high-severity CVEs in recent years.

**Remediation:**

1. Pin all dependency versions in pyproject.toml or equivalent. 2. Implement automated vulnerability scanning using pip-audit --require-hashes --desc or uv pip audit in CI/CD pipeline. 3. Create a dependency update log documenting Date, Component, From Version, To Version, and Reason for each update.

#### FINDING-070: Unbounded Argon2 Computation in Tally Operation Without Resource Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 15.2.2 |
| **Files** | v3/steve/election.py:245-305 |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | - | **Description:**

The tally_issue() function performs unbounded Argon2 computations (64MB per call) for each eligible voter without resource controls. An election with 1000 eligible voters would trigger 1000 sequential Argon2 computations, consuming approximately 64GB of peak memory throughput and taking minutes to complete. An attacker with admin access or exploiting a state manipulation bug could trigger this repeatedly, causing denial of service through memory and CPU exhaustion. The has_voted_upon() function performs similar unbounded Argon2 iteration for authenticated voters, proportional to the number of issues in an election.

**Remediation:**

Implement concurrent operation limits using semaphores and process votes in batches to limit memory pressure. Example: Use asyncio.Semaphore to limit concurrent Argon2 operations to 4, and process eligible voters in batches of 50 using ThreadPoolExecutor with max_workers=4.

---

#### FINDING-071: Internal ASF Packages (asfquart, asfpy) Potentially Vulnerable to Dependency Confusion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.2.4 |
| **Files** | v3/server/main.py:30-31, v3/steve/election.py:24 |
| **Source Reports** | 15.2.4.md |
| **Related Findings** | - | **Description:**

Both asfquart and asfpy appear to be ASF-internal packages. Without visible evidence of: A pyproject.toml or requirements.txt with explicit index URLs, A pip.conf or uv configuration pointing to an internal package index, Version pinning with hash verification, A .python-version or lock file. An attacker could register asfquart or asfpy on public PyPI (if not already registered) with a higher version number, causing dependency confusion during installation. Note: If these packages ARE published on PyPI by ASF (asfpy is indeed on PyPI), this reduces but does not eliminate the risk — version pinning and hash verification are still necessary. Data Flow: Package manager resolution → asfquart / asfpy → if not properly configured to resolve from ASF internal repository first → could resolve from public PyPI → malicious package execution.

**Remediation:**

Configure explicit index URLs and pin versions with hashes in pyproject.toml or uv.lock: [tool.uv] index-url = "https://pypi.org/simple/" [tool.uv.sources] asfpy = { version = "==X.Y.Z", hash = "sha256:..." } asfquart = { version = "==X.Y.Z", hash = "sha256:..." }

---

#### FINDING-072: No Trusted Proxy Configuration for IP Address Handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 15.3.4 |
| **Files** | v3/server/pages.py:entire file |
| **Source Reports** | 15.3.4.md |
| **Related Findings** | - | **Description:**

The application has no proxy trust configuration (no ProxyFix middleware, no Quart proxy settings), no IP address extraction from requests for logging, no X-Forwarded-For header processing, no rate limiting based on IP address, and no configuration for trusted proxy headers. Without proper proxy configuration, if rate limiting is added later it could be trivially bypassed by spoofing X-Forwarded-For headers. Security logs lack client IP context, making forensic analysis difficult. An attacker who compromises a session could not be distinguished by IP. If deployed behind a reverse proxy, the application cannot distinguish the original client IP.

**Remediation:**

Configure trusted proxy count in application initialization using app.config['PROXY_FIX_X_FOR'] = 1 and app.config['PROXY_FIX_X_PROTO'] = 1, or use werkzeug.middleware.proxy_fix.ProxyFix middleware with x_for=1 and x_proto=1 parameters. Add IP address logging to security events using quart.request.remote_addr in all _LOGGER.info() calls for security-relevant actions.

---

#### FINDING-073: Vote Insertion Uses Non-Thread-Safe Multi-Step Database Access Without Synchronization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.4.1 |
| **Files** | v3/steve/election.py:242-251 |
| **Source Reports** | 15.4.1.md |
| **Related Findings** | - | **Description:**

The add_vote() method performs multiple unsynchronized database operations (read metadata, query mayvote, insert vote) without transaction or lock protection. Concurrent HTTP requests create separate Election instances with separate DB connections, leading to potential interleaved database state. Under concurrent voting, the autoincrement IDs in the vote table reveal insertion order, which combined with authentication logs could correlate voters to votes. The multi-step read-compute-write pattern is not atomic, even though SQLite serializes the actual writes.

**Remediation:**

Wrap the add_vote() method with an asyncio.Lock to ensure atomic execution of the multi-step operation. Add random delay to decorrelate insertion order from request timing. Convert method to async and use: async with _vote_lock: [perform all operations] followed by await asyncio.sleep(random.uniform(0, 0.1)) before insertion.

---

#### FINDING-074: Non-Atomic Check-Then-Use in Vote Recording Allows Voting on Closed Elections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3, L2 |
| **CWE** | CWE-367 |
| **ASVS Section(s)** | 15.4.2, 2.3.4 |
| **Files** | v3/steve/election.py:242-251 |
| **Source Reports** | 15.4.2.md, 2.3.4.md |
| **Related Findings** | FINDING-219, FINDING-220 | **Description:**

The add_vote() method performs a non-atomic check-then-use operation where it first checks if the election is open (_all_metadata(self.S_OPEN)) and then later inserts the vote (c_add_vote.perform()). Between these two operations, a concurrent close() call can change the election state, allowing votes to be inserted into a closed election. The data flow is: _all_metadata(self.S_OPEN) [CHECK: election is open] → computation → c_add_vote.perform() [USE: insert vote]. Timeline: T1: Voter A calls add_vote(), passes state check (election is OPEN); T2: Admin calls close(), election state changes to CLOSED; T3: Voter A's c_add_vote.perform() executes, inserting vote into CLOSED election. This violates election integrity as votes can be recorded after an election is closed.

**Remediation:**

Use a single transaction with an immediate lock. Use BEGIN IMMEDIATE at the start of the open() method. Re-check state inside the transaction (with lock held) by calling _all_metadata() and _compute_state(). If state is not S_EDITABLE, rollback and raise ElectionBadState. Perform all operations atomically within the transaction: _add_salts_no_transaction(), gather_election_data(), gen_salt(), gen_opened_key(), and c_open.perform(). Wrap in try/except to ensure ROLLBACK on error and COMMIT on success.

---

#### FINDING-075: Inconsistent Transaction Usage — Some Multi-Step Operations Are Transactional, Others Are Not

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.4.3 |
| **Files** | v3/steve/election.py:multiple methods |
| **Source Reports** | 15.4.3.md |
| **Related Findings** | - | **Description:**

The inconsistency means that code reviewers and maintainers may incorrectly assume all multi-step operations are safe. The delete and add_salts methods demonstrate that the developers understand the need for transactions, but the same pattern is not applied to add_vote and open which are equally (or more) critical for election integrity. This creates a Type B gap: the control EXISTS (transaction mechanism) but is NOT CONSISTENTLY CALLED.

**Remediation:**

Wrap add_vote in BEGIN IMMEDIATE transaction with proper try/except/ROLLBACK error handling. Use BEGIN IMMEDIATE to acquire a write lock upfront, preventing concurrent modifications between state check and vote insertion. Apply the same pattern to open() method and all other multi-step operations.

---

#### FINDING-076: No Rate Limiting on Vote Submission or Election Creation Enables Resource Exhaustion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3, L2, L1 |
| **CWE** | - |
| **ASVS Section(s)** | 15.4.4, 2.4.1, 2.4.2, 6.3.1 |
| **Files** | v3/server/pages.py:385-425, v3/steve/election.py: |
| **Source Reports** | 15.4.4.md, 2.4.1.md, 2.4.2.md, 6.3.1.md |
| **Related Findings** | - | **Description:**

The vote submission endpoint has no rate limiting or timing validation whatsoever. An authenticated user can submit votes as rapidly as their network connection allows, with no enforcement of realistic human timing. While the system's re-voting design means only the last vote per voter/issue counts, rapid automated submission creates race conditions in determining which vote is "last" and violates the principle that voting systems should enforce realistic human interaction timing. The vote submission endpoint `/do-vote/<eid>` has no rate limiting controls. Authenticated users can submit unlimited POST requests, with each request adding a new row to the vote table. With 100,000 iterations, the table grows by 100,000 rows per issue. Since only the latest vote counts, all but the last are dead weight consuming storage and slowing tally operations.

**Remediation:**

Implement per-user rate limiting (1 vote per 10 seconds) using quart-rate-limiter. Example: `@rate_limit(10, timedelta(minutes=1))` to limit to 10 votes per minute per user on the `do_vote_endpoint()` function. Add minimum time interval checks since last vote by the user. Track last_vote_timestamp and enforce MINIMUM_VOTE_INTERVAL before processing new votes.

---

#### FINDING-077: OAuth Configuration Lacks Audience/Client Identification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 9.2.4 |
| **Files** | v3/server/main.py:31-35 |
| **Source Reports** | 9.2.4.md |
| **Related Findings** | - | **Description:**

The OAuth authorization URL (OAUTH_URL_INIT) does not include a client_id parameter. In standard OAuth 2.0 (RFC 6749 §4.1.1), the client_id is REQUIRED in the authorization request and is the mechanism by which the authorization server can scope the issued token to a specific audience. Similarly, the token exchange URL (OAUTH_URL_CALLBACK) only passes the authorization code without client credentials. Without client_id: (1) The OAuth server cannot issue audience-restricted tokens, (2) If the same OAuth provider's private key signs tokens for multiple relying parties, any token is valid everywhere, (3) A token obtained by visiting another ASF application (sharing the same OAuth server) could be replayed against STeVe.

**Remediation:**

Include client_id in OAuth requests. Add CLIENT_ID from configuration and update OAUTH_URL_INIT to include client_id parameter: 'https://oauth.apache.org/auth?client_id=%s&state=%s&redirect_uri=%s'. Update OAUTH_URL_CALLBACK to include client_id and client_secret: 'https://oauth.apache.org/token?code=%s&client_id=%s&client_secret=%s'.

---

#### FINDING-078: No Token Audience Validation After OAuth Exchange

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 9.2.4 |
| **Files** | v3/server/pages.py:75-106 |
| **Source Reports** | 9.2.4.md |
| **Related Findings** | - | **Description:**

The session data (uid, fullname, email) is consumed directly from asfquart.session.read() without any validation that the underlying token was issued specifically for the STeVe application. No aud claim is checked. No iss claim is verified against an expected value. By explicitly avoiding OIDC (as noted in main.py line 29), the application loses the standardized aud claim validation that OIDC ID tokens provide. OIDC requires that the ID token's aud claim contains the client_id of the relying party, which is exactly what ASVS 9.2.4 requires. If the OAuth provider issues tokens that can be consumed by multiple services, the application has no defense against cross-service token confusion attacks.

**Remediation:**

Add audience and issuer validation in basic_info() function. Validate that token audience claim matches expected_audience (e.g., APP.cfg.oauth.client_id). Check if token_audience exists and matches expected value, handling both single string and list formats. Validate issuer claim matches 'https://oauth.apache.org'. Reject sessions that fail validation by setting uid, name, email to None and logging warnings.

---

#### FINDING-079: No Anti-caching Headers Set for Sensitive Election Data Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 14.3.2 |
| **Files** | v3/steve/election.py:all data-returning methods |
| **Source Reports** | 14.3.2.md |
| **Related Findings** | - | **Description:**

The election module returns highly sensitive data through multiple methods that would ultimately be served as HTTP responses, but no cache-control mechanism is defined anywhere in the provided codebase. Given the domain context explicitly states 'Anti-caching headers should prevent browsers from storing sensitive pages' and the core requirement is ballot secrecy, this is a significant gap. The following methods return data requiring Cache-Control: no-store: get_metadata() (returns owner_pid, authz groups), has_voted_upon() (returns per-voter voting status), tally_issue() (returns decrypted vote tallies), list_issues() (returns election issues), get_voters_for_email() (returns voter PII - pid, name, email), open_to_pid() (returns elections available to specific voter). Data Flow: Database → election.py methods → web framework response → browser cache (uncontrolled). Browser caching of sensitive pages could expose: (1) Ballot secrecy violation - has_voted_upon() results cached in browser history reveal which issues a specific voter participated in, (2) Voter PII exposure - get_voters_for_email() returns names and email addresses that could persist in browser cache, (3) Election integrity - Cached tally results from tally_issue() could be examined on shared computers, (4) Voter-vote correlation risk - If both voter identity pages and voting status pages are cached, they can be correlated.

**Remediation:**

At the Quart web framework layer, apply anti-caching headers globally for all authenticated endpoints using @app.after_request decorator to set Cache-Control: no-store, no-cache, must-revalidate, max-age=0, Pragma: no-cache, and Expires: 0. Alternatively, apply headers more granularly for specific sensitive endpoints. Example: @app.after_request async def set_security_headers(response): response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'; response.headers['Pragma'] = 'no-cache'; response.headers['Expires'] = '0'; return response

### 3.3 Medium

#### FINDING-080: No Documented Cryptographic Key Management Policy or Key Lifecycle

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.1 |
| **Files** | v3/steve/crypto.py, v3/docs/schema.md |
| **Source Reports** | 11.1.1.md |
| **Related Findings** | None | **Description:**

The codebase contains multiple cryptographic keys and secrets (election salt, opened_key, vote_token, vote encryption keys) but there is no documented key management policy conforming to NIST SP 800-57 or an equivalent standard. While schema.md provides some documentation of what keys exist, it does not constitute a key lifecycle policy addressing: Key generation procedures and responsibilities, Key storage and protection requirements, Key distribution controls, Key usage periods / expiration, Key revocation and destruction procedures, Key recovery mechanisms. Without a documented key lifecycle, keys may persist beyond their intended use period, accumulate risk, and lack clear procedures for compromise response. The opened_key persists in the database indefinitely after an election closes, with no documented destruction schedule.

**Remediation:**

Create a formal cryptographic key management policy document covering: 1. Key types, purposes, and authorized users 2. Key generation procedures (already using secrets module) 3. Maximum key lifetime per key type 4. Key storage protection requirements 5. Key destruction procedures (e.g., zeroing opened_key after tally completion) 6. Incident response for key compromise

---

#### FINDING-081: Incomplete Cryptographic Inventory - Missing Algorithm and Key Usage Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.2 |
| **Files** | crypto.py:49, crypto.py:61-66, schema.md |
| **Source Reports** | 11.1.2.md |
| **Related Findings** | None | **Description:**

While `schema.md` documents some cryptographic assets, it does not constitute a complete cryptographic inventory. The following are not formally inventoried: 1) Algorithms not documented: BLAKE2b (64-byte digest, used as pre-hash for Argon2), HKDF-SHA256 (used for key stretching vote_token → vote_key), The specific Fernet composition (AES-128-CBC + HMAC-SHA256). 2) Key usage boundaries not documented: Where each key type CAN be used vs. CANNOT be used, What data types each key protects, Which components have access to which keys. 3) No centralized inventory document: Crypto information is scattered across `schema.md`, `crypto.py` comments, and `schema.sql` comments. Without a complete inventory, it's impossible to systematically assess cryptographic risk, plan migrations, or ensure all cryptographic assets are properly managed.

**Remediation:**

Create a dedicated `CRYPTO_INVENTORY.md` document containing a comprehensive table with columns: Asset, Algorithm, Key Length, Purpose, Protected Data, Access Scope, Location. The inventory should include: Election salt (N/A random, 128 bits, Argon2 input, Server-only, election.salt), Opened key (Argon2d(BLAKE2b(edata)), 256 bits, Tamper detection + vote token derivation, Server-only, election.opened_key), Mayvote salt (N/A random, 128 bits, Per-voter differentiation, Server-only, mayvote.salt), Vote token (Argon2d(opened_key‖pid‖iid, salt), 256 bits, Voter identification + key derivation, Server-only, vote.vote_token), Vote key (HKDF-SHA256(vote_token, salt), 256 bits, Vote encryption, Ephemeral, Derived in memory), Ciphertext (Fernet (AES-128-CBC + HMAC-SHA256), N/A, Vote confidentiality, Stored, vote.ciphertext).

---

#### FINDING-082: No Cryptographic Discovery Mechanisms Employed

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.3 |
| **Files** | pyproject.toml, pages.py:269 |
| **Source Reports** | 11.1.3.md |
| **Related Findings** | None | **Description:**

There is no evidence of automated cryptographic discovery mechanisms being employed to identify all instances of cryptography in the system. No tooling, CI/CD pipeline steps, or scanning configurations are present to: discover all cryptographic library usage, identify encryption, hashing, and signing operations, detect introduction of new cryptographic operations, or flag deprecated or weak algorithm usage. The pyproject.toml defines development dependencies but includes no cryptographic scanning tools. No tools like cryptosense, crypto-detector, semgrep with crypto rules, or custom SAST rules for cryptographic operations are configured.

**Remediation:**

1. Add a cryptographic linting step to CI/CD using tools like: semgrep with crypto-specific rules, custom ruff or pylint rules flagging hashlib, cryptography, hmac imports, or SAST tools configured to flag crypto operations. 2. Maintain a list of approved crypto imports/modules. 3. Run periodic scans to detect drift from the inventory.

---

#### FINDING-083: No Documented Post-Quantum Cryptography Migration Plan

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.1.4 |
| **Files** | v3/steve/crypto.py:63, v3/docs/schema.md |
| **Source Reports** | 11.1.4.md |
| **Related Findings** | None | **Description:**

While the code acknowledges a planned transition from Fernet to XChaCha20-Poly1305, there is no documented migration plan addressing post-quantum cryptography threats. The current cryptographic primitives (AES-128, SHA-256, BLAKE2b) have varying levels of quantum resistance, and no formal assessment or migration roadmap exists. Without a migration plan, the project cannot react efficiently to quantum computing advances. The planned Fernet → XChaCha20-Poly1305 migration doesn't address quantum threats (both are symmetric and similarly affected by Grover's algorithm). AES-128 specifically should be upgraded to AES-256 for quantum resistance.

**Remediation:**

Create a `PQC_MIGRATION_PLAN.md` documenting: 1. Current algorithm inventory with quantum risk assessment 2. Timeline for migrating AES-128 (Fernet) to AES-256 or authenticated encryption with 256-bit keys 3. Assessment of when PQC-resistant key exchange might be needed (if TLS/network crypto is added) 4. Crypto-agility requirements (see 11.2.2) to enable seamless future upgrades 5. Data re-encryption strategy for stored ciphertext

---

#### FINDING-084: Argon2d (Type.D) Used Instead of Recommended Argon2id (Type.ID)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3, L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.1, 11.2.4, 11.4.2, 11.4.4, 11.6.1, 15.2.1 |
| **Files** | v3/steve/crypto.py:89, v3/steve/crypto.py:87 |
| **Source Reports** | 11.2.1.md, 11.2.4.md, 11.4.2.md, 11.4.4.md, 11.6.1.md, 15.2.1.md |
| **Related Findings** | None | **Description:**

The production code uses argon2.low_level.Type.D (Argon2d), while the OWASP Password Storage Cheat Sheet and NIST SP 800-63B recommend Argon2id as the preferred variant. Argon2d is vulnerable to side-channel attacks (timing attacks based on memory access patterns). The benchmark function at line 116 correctly uses Type.ID (Argon2id), indicating the developer is aware of the preferred variant but used the wrong one in production. An attacker with physical/VM co-location access could observe memory access patterns during vote token generation to recover secret data, since Argon2d's memory accesses are data-dependent. This affects key derivation used for both password storage (11.4.2) and key stretching (11.4.4), and represents a suboptimal algorithm choice (11.6.1).

**Remediation:**

Change the type parameter in the _hash() function from argon2.low_level.Type.D to argon2.low_level.Type.ID as recommended by RFC 9106. Note: this will change all derived values, so must be coordinated with any existing deployed databases. Add a crypto_version column to the vote table to enable future algorithm transitions without data loss.

---

#### FINDING-085: ID generation uses insufficient entropy (40 bits vs required 128 bits)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.3, 11.5.1, 7.2.3 |
| **Files** | v3/steve/crypto.py:100 |
| **Source Reports** | 11.2.3.md, 11.5.1.md, 7.2.3.md |
| **Related Findings** | None | **Description:**

The `create_id()` function generates only 5 bytes (40 bits) of entropy for election/issue IDs. However, these are not session tokens — they are resource identifiers. The schema documentation explicitly states: 'We do not use AUTOINCREMENT, so that URLs for Elections cannot be deduced.' The 40-bit space (~1 trillion possible values) provides unpredictability for URL-based resource identifiers, though it wouldn't meet session token requirements. The actual session tokens are managed by `asfquart.session`, which is an external dependency not included in the provided source. We cannot verify whether session reference tokens meet the 128-bit entropy requirement. The `crypto.py` module demonstrates use of `secrets.token_bytes(16)` (128 bits) for salts, indicating awareness of appropriate entropy levels for cryptographic operations.

**Remediation:**

1. Verify that `asfquart.session` generates session tokens with at least 128 bits of entropy using a CSPRNG. 2. Document the session token generation mechanism: python\n# Session Token Specification:\n# - Generated by asfquart.session using [specific mechanism]\n# - Token length: [N] bytes ([M] bits of entropy)\n# - Source: [e.g., os.urandom / secrets module]\n# - Verified to meet ASVS 7.2.3 (128+ bits, CSPRNG)\n

---

#### FINDING-086: Unhandled cryptographic decryption exceptions in vote tallying

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.2.5 |
| **Files** | v3/steve/election.py:283-290, v3/steve/crypto.py |
| **Source Reports** | 11.2.5.md |
| **Related Findings** | None | **Description:**

The tally_issue() function in election.py does not handle exceptions from crypto.decrypt_votestring(). If any single vote's ciphertext is corrupted (database corruption, malicious tampering with the SQLite file), the entire tally_issue() operation will fail with an unhandled cryptography.fernet.InvalidToken exception. This is a denial-of-service vector against the tallying function. While Fernet's encrypt-then-MAC construction prevents Padding Oracle attacks specifically (HMAC is verified before decryption), the lack of error handling means: (1) A single corrupted vote prevents ALL votes from being tallied, (2) The exception type/message could potentially differentiate between HMAC failure and other issues in some library versions.

**Remediation:**

Wrap the decrypt_votestring() call in a try/except block to catch exceptions generically. Log failures without exposing details that could differentiate between HMAC failure vs decryption failure. Skip the corrupted vote and continue processing remaining votes. Example: try: votestring = crypto.decrypt_votestring(vote_token, mayvote.salt, row.ciphertext); votes.append(votestring) except Exception: _LOGGER.error(f'Failed to decrypt vote for issue {iid} - vote skipped'); continue

---

#### FINDING-087: Use of Fernet (AES-128-CBC) instead of approved AEAD cipher

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.3.2 |
| **Files** | v3/steve/crypto.py:72-82 |
| **Source Reports** | 11.3.2.md |
| **Related Findings** | None | **Description:**

The code explicitly acknowledges it should be using XChaCha20-Poly1305 (an AEAD cipher) but is currently using Fernet (AES-128-CBC + HMAC-SHA256). While Fernet is a secure authenticated encryption construction, it is not a native AEAD mode. Modern ASVS standards prefer purpose-built AEAD ciphers (AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) which provide authenticated encryption in a single primitive with formal security proofs. Key concerns: AES-CBC is a legacy mode that requires careful composition with MAC; Fernet's AES-128 provides only 128 bits of security vs the 256-bit key being derived (waste of key material); The HKDF info parameter says 'xchacha20_key' but the key is used for Fernet indicating incomplete migration; The 32-byte HKDF output is base64-encoded and fed to Fernet, which internally splits it into 16 bytes signing + 16 bytes encryption (AES-128), not using the full 256 bits.

**Remediation:**

Replace Fernet with ChaCha20-Poly1305 AEAD cipher. Derive a 32-byte key using HKDF with appropriate info parameter ('chacha20_poly1305_key'). Generate a 96-bit nonce using os.urandom(12) for each encryption. Use ChaCha20Poly1305 class from cryptography.hazmat.primitives.ciphers.aead. Prepend the nonce to ciphertext for storage/transmission. Update decrypt_votestring to extract nonce from first 12 bytes and decrypt remainder.

---

#### FINDING-088: TLS Private Key Path Stored in Configuration File

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 13.3.1 |
| **Files** | v3/server/config.yaml.example:30-31 |
| **Source Reports** | 13.3.1.md |
| **Related Findings** | None | **Description:**

While this is an example file, the configuration pattern stores TLS private key filesystem paths in a YAML file that may be committed to source control or included in build artifacts. The actual private key material resides on the filesystem accessible to the application process without vault-based access control. Configuration shows: certfile: localhost.apache.org+3.pem and keyfile: localhost.apache.org+3-key.pem

**Remediation:**

Reference TLS material via a secrets manager or environment variable pointing to a managed certificate store. Example: certfile: ${VAULT_TLS_CERT_PATH} and keyfile: ${VAULT_TLS_KEY_PATH}. Store TLS private keys in a vault solution with access control rather than on the filesystem.

---

#### FINDING-089: Argon2 Key Derivation Exposes Intermediate Key Material

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 13.3.3 |
| **Files** | v3/steve/crypto.py:39-55 |
| **Source Reports** | 13.3.3.md |
| **Related Findings** | None | **Description:**

The opened_key (election master secret) is passed as a parameter to gen_vote_token() and concatenated with voter identifiers in application memory. In an isolated security module architecture, the master key would never leave the secure boundary — only derived tokens would be exported. The gen_opened_key function creates a 64-byte digest in memory and returns a 32-byte key to the caller, exposing intermediate key material throughout the process.

**Remediation:**

Restructure so that the opened_key is a reference to a key stored within the security module, and derivation happens inside the module boundary. The master key should never be passed as a parameter or concatenated in application memory. Implement key derivation operations within the isolated security module (vault/HSM) so that only derived tokens are exported to the application.

---

#### FINDING-090: Closed Elections Retain Cryptographic Material Indefinitely

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 13.3.4 |
| **Files** | v3/steve/election.py:116-121, v3/schema.sql |
| **Source Reports** | 13.3.4.md |
| **Related Findings** | None | **Description:**

After an election is closed and results tallied, the cryptographic key material (salt, opened_key, per-voter salt values) remains in the database indefinitely. There is no procedure to destroy secrets after they are no longer needed (post-tally verification period). This violates the principle that secrets should have defined lifetimes.

**Remediation:**

Implement an archive_election() method that after a retention period (e.g., 90 days) has passed, verifies the retention period has elapsed, then zeros out cryptographic material by setting salt and opened_key to NULL for election records, setting salt to NULL for all mayvote records, and deleting encrypted votes.

---

#### FINDING-091: Lack of Full Memory Encryption for Sensitive Data In-Use

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 11.7.1 |
| **Files** | v3/steve/crypto.py, v3/steve/election.py |
| **Source Reports** | 11.7.1.md |
| **Related Findings** | None | **Description:**

Sensitive data including opened_key, vote_token, decrypted vote strings, and PIDs exist unprotected in process memory. The data flow shows: Encrypted ciphertext → decrypted votestrings → accumulated in votes list → passed to tally → returned from function, all without memory encryption. An attacker with memory access (via memory dump, cold boot attack, swap file analysis, or process inspection) could recover individual votes, compromising ballot secrecy.

**Remediation:**

Implement hardware-backed memory encryption using technologies such as: Intel TME (Total Memory Encryption) / MKTME, AMD SEV (Secure Encrypted Virtualization), or ARM CCA (Confidential Compute Architecture). At the application level, consider using memory-safe containers or encrypted memory regions via libraries like sodium with sodium_mlock() / sodium_munlock(). Long-term recommendations include: using mlock() for memory pages containing decrypted votes during tally operations, implementing explicit memory clearing patterns, and implementing incremental hashing in gather_election_data() to use streaming hash computation instead of accumulating all voter data in memory.

---

#### FINDING-092: Incomplete Formal Data Classification into Protection Levels

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 14.1.1, 14.1.2 |
| **Files** | v3/docs/schema.md |
| **Source Reports** | 14.1.1.md, 14.1.2.md |
| **Related Findings** | None | **Description:**

The documentation describes cryptographic mechanisms used but does not define a comprehensive set of protection requirements for each data sensitivity level. Missing documentation includes: formal encryption standards (Fernet mentioned, XChaCha20 planned but no formal requirement), integrity verification requirements (Argon2 opened_key described but no formal requirement), data retention policy (older votes retained for auditing but no retention period/purge schedule defined), logging requirements (no documented policy on what can/cannot be logged), formal access controls documentation (owner_pid and authz mentioned but no formal RBAC documentation), database-level encryption (no mention of SQLite encryption at rest), privacy requirements (vote anonymity implied but not formally specified), and key management (no documentation on key rotation, backup, or destruction). Without documented protection requirements: data retention may grow indefinitely, key management procedures are undefined, logging of sensitive data has no enforceable policy, and database file encryption status is undocumented.

**Remediation:**

Add a 'Data Protection Requirements' section to schema.md that includes: Encryption requirements (all vote ciphertext MUST use authenticated encryption, database file MUST be readable only by application user with chmod 600, cryptographic salts MUST be generated using secrets.token_bytes()); Integrity requirements (election tampering MUST be detectable via opened_key verification using Argon2, foreign key constraints MUST be enforced at runtime); Retention requirements (closed election data MUST be retained for [X] months for audit purposes, vote re-voting history MUST be purged after tallying is complete, person records MUST be reviewed annually for GDPR/privacy compliance); Logging requirements (encrypted vote content/ciphertext MUST NEVER appear in logs, salt values MUST NEVER appear in logs, opened_key MUST NEVER appear in logs, election IDs and issue IDs MAY be logged for operational purposes); Access Control requirements (only election owner and authz group may modify elections, administrative decryption requires CLI access with encryption keys, database file access restricted to application service account).

---

#### FINDING-093: Integrity verification (opened_key) does not cover authorization-critical fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 14.2.4 |
| **Files** | v3/steve/election.py:90-110 |
| **Source Reports** | 14.2.4.md |
| **Related Findings** | None | **Description:**

The gather_election_data() function only includes eid and title in the integrity hash, omitting owner_pid and authz fields. If owner_pid or authz fields are modified after an election is opened (e.g., via direct database manipulation or a future admin endpoint), the tamper detection via is_tampered() will NOT detect the change. An attacker with database write access could reassign election ownership without triggering integrity alerts.

**Remediation:**

Include all integrity-critical fields in gather_election_data(): mdata = md.eid + md.title + md.owner_pid + (md.authz or '')

---

#### FINDING-094: Tamper detection not automatically invoked during critical operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 14.2.4 |
| **Files** | v3/steve/election.py:260-273 |
| **Source Reports** | 14.2.4.md |
| **Related Findings** | None | **Description:**

The is_tampered() method exists but is not automatically called in critical operations like add_vote() or tally_issue(). If the election data is tampered with after opening, votes can still be cast and tallied against a corrupted election without the integrity check being triggered. The method must be called externally by the web layer—there is no enforcement that it has been called before add_vote() proceeds.

**Remediation:**

Add integrity verification before accepting votes: if pdb and self.is_tampered(pdb): raise ElectionTampered(self.eid). Either call is_tampered() within add_vote() automatically, or add a decorator that ensures the web layer has performed the check before the method executes.

---

#### FINDING-095: Superseded votes retained indefinitely without purge mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 14.2.7 |
| **Files** | v3/docs/schema.md, v3/schema.sql |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | None | **Description:**

When a voter re-votes, all previous encrypted votes remain in the database. While only the latest vote (MAX(vid)) is used for tallying, the old ciphertexts represent: (1) Historical sensitive data with no defined retention period, (2) Potential attack surface if encryption keys are later compromised, (3) Storage of data that serves no ongoing operational purpose after tallying. There is no query in `queries.yaml` to delete superseded votes, no scheduled cleanup, and no retention policy documentation.

**Remediation:**

Add queries to queries.yaml for purging old votes: `c_purge_old_votes` to delete superseded votes for a given vote_token (keeping only MAX(vid)), and `c_purge_election_votes` to delete all votes for a specific closed election. Implement a cleanup mechanism that runs after tallying or on a scheduled basis to remove superseded votes that are no longer needed for operational purposes.

---

#### FINDING-096: Person records have no lifecycle management or cleanup

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 14.2.7 |
| **Files** | v3/queries.yaml, v3/schema.sql |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | None | **Description:**

Person records (containing PID, name, and email) accumulate indefinitely. While `c_delete_person` exists, `ON DELETE RESTRICT` constraints on `mayvote` and `election.owner_pid` prevent deletion as long as any election references the person. Since opened elections cannot be deleted, person records for anyone who has ever participated in an election become effectively permanent. This results in indefinite retention of PII without a defined retention schedule or cleanup mechanism.

**Remediation:**

Implement a data anonymization mechanism for persons in completed elections: `def anonymize_person_in_closed_elections(self, pid)` that replaces PII (name and email) with anonymized values after the retention period expires, while preserving referential integrity. This allows person records to remain for database consistency while removing sensitive personal information.

---

#### FINDING-097: Missing PKCE (Proof Key for Code Exchange) in OAuth Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | N/A |
| **ASVS Sections** | 10.1.2, 10.2.1, 10.4.6, 10.4.4 |
| **Files** | v3/server/main.py:39-42 |
| **Source Reports** | 10.1.2.md, 10.2.1.md, 10.4.6.md, 10.4.4.md |
| **Related Findings** | None | **Description:**

The OAuth authorization URL template includes a `state` parameter (`state=%s`), which indicates the `asfquart` framework generates and substitutes state values. However, there is no PKCE (Proof Key for Code Exchange) visible in the authorization request URL. The URL template lacks `code_challenge` and `code_challenge_method` parameters, and no `code_verifier` generation or binding logic is present in the provided code. While the `state` parameter provides some CSRF protection, PKCE provides additional protection against authorization code interception attacks (especially relevant for deployments where the callback URI could be intercepted). The absence of PKCE means the flow relies solely on `state` and the confidentiality of the `code`. This affects multiple ASVS requirements related to PKCE enforcement and code interception protection.

**Remediation:**

Modify OAuth URL template to include PKCE parameters: `asfquart.generics.OAUTH_URL_INIT = ('https://oauth.apache.org/auth?state=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256')`. Framework must generate code_verifier (43-128 chars, cryptographically random), compute code_challenge = BASE64URL(SHA256(code_verifier)), store code_verifier in session, and send it with the token exchange request. Example: code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode(); code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).rstrip(b'=').decode().

---

#### FINDING-098: Missing Fine-Grained Authorization Based on Election Ownership and LDAP Group Claims

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.2 |
| **Files** | v3/server/pages.py:488, v3/server/pages.py:509, v3/server/pages.py:527, v3/server/pages.py:553, v3/server/pages.py:577, v3/server/pages.py:421, v3/server/pages.py:99, v3/server/pages.py:195, v3/server/pages.py:224 |
| **Source Reports** | 10.3.2.md |
| **Related Findings** | None | **Description:**

While the application verifies that users have a 'committer' role from their OAuth session using @asfquart.auth.require({R.committer}), it does not enforce finer-grained authorization based on election ownership (owner_pid) or LDAP group membership (authz field). The application has systematic '### check authz' comments at 9+ locations indicating the authorization control was conceptualized but never implemented (Type B gap). This means ANY authenticated committer can open/close any election, add/edit/delete issues in any election, and set dates on any election, regardless of whether they own the election or are members of the authorized LDAP group. The domain model includes owner_pid and authz fields, but these are never checked before allowing management operations.

**Remediation:**

Implement election ownership authorization checks in the load_election and load_election_issue decorators before any management operation executes. The remediation should: 1) Retrieve the election metadata including owner_pid and authz fields, 2) Compare the authenticated user's uid (from session claims) with the owner_pid, 3) If not the owner, check if the user is a member of the LDAP group specified in the authz field using PersonDB.is_member_of_group(), 4) Return 403 Forbidden if neither condition is met. Example implementation: Check if result.uid != metadata.owner_pid, then if metadata.authz exists, verify pdb.is_member_of_group(result.uid, metadata.authz), otherwise abort with 403. Apply this check in the load_election decorator so all endpoints using it inherit the protection.

---

#### FINDING-099: User identification does not verify iss+sub combination from token claims

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.3 |
| **Files** | v3/server/pages.py:82-89 |
| **Source Reports** | 10.3.3.md |
| **Related Findings** | None | **Description:**

The application identifies users solely by `uid` extracted from the session, which is populated by the `asfquart` framework's OAuth callback. There is no visible validation that the user identity is derived from a combination of `iss` (issuer) and `sub` (subject) claims that cannot be reassigned. The code relies entirely on the `asfquart` framework to properly map OAuth token claims to `uid`, with no explicit verification of the issuer claim. While the application uses a single OAuth provider (`oauth.apache.org`), the `uid` is consumed without any verification that: 1. The token was issued by the expected issuer (`iss` claim validation) 2. The `sub` claim maps uniquely to this user across all possible issuers. If the `asfquart` framework has a misconfiguration or if a second OAuth provider is ever added, user identity could be confused. An attacker at a different IdP could potentially obtain a token with the same `uid`/`sub` that maps to a different user.

**Remediation:**

Verify the session was established from the expected issuer and use iss+sub combination as the canonical user identifier. Example: async def basic_info(): s = await asfquart.session.read(); if s: expected_issuer = 'https://oauth.apache.org'; if s.get('iss') != expected_issuer: _LOGGER.warning(f'Unexpected issuer in session: {s.get("iss")}'); return basic; canonical_id = f"{s['iss']}:{s['sub']}"; basic.update(uid=s['uid'], canonical_user_id=canonical_id, name=s['fullname'], email=s['email'])

---

#### FINDING-100: No verification of authentication strength, methods, or recentness for sensitive operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.4, 6.8.4, 8.4.2 |
| **Files** | v3/server/pages.py:484 |
| **Source Reports** | 10.3.4.md, 6.8.4.md, 8.4.2.md |
| **Related Findings** | None | **Description:**

The application uses different authorization levels for different functions (R.committer for most operations, R.pmc_member for creating elections) representing different privilege levels, yet the application never verifies the authentication strength or method used by the IdP. No OIDC claims like acr (Authentication Context Class Reference), amr (Authentication Methods References), or auth_time are inspected anywhere in the visible code. The application has sensitive operations (opening/closing elections, casting votes) that could benefit from step-up authentication verification, but no mechanism exists to differentiate between a user who authenticated with a password vs. MFA. If the ASF OAuth provider supports multiple authentication methods (password-only, MFA, hardware keys), the application cannot distinguish between them. A user authenticated with a weak method (e.g., compromised password without MFA) would have the same access as one authenticated with strong authentication.

**Remediation:**

Implement authentication strength verification before sensitive operations. Add a verify_auth_strength function that checks: 1) Authentication recentness using auth_time claim with a maximum age (e.g., 5 minutes for sensitive operations), redirecting to re-authentication if exceeded. 2) Authentication context class (acr) to ensure minimum authentication assurance level. 3) Authentication methods (amr) to verify required authentication methods were used. Apply this verification to all sensitive endpoints including do-vote, do-open, do-close, do-create-election, and do-delete-issue. Store auth_time in the session during initial OAuth authentication and validate it before each sensitive operation.

---

#### FINDING-101: No Sender-Constrained Access Token Mechanism (mTLS or DPoP)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.3.5, 10.4.14 |
| **Files** | v3/server/main.py:39-42, v3/server/main.py:76-79, v3/server/pages.py:82-88 |
| **Source Reports** | 10.3.5.md, 10.4.14.md |
| **Related Findings** | None | **Description:**

The application uses standard OAuth 2.0 bearer tokens without any sender-constraining mechanism. There is no implementation of Mutual TLS (mTLS) for OAuth 2 (RFC 8705) with client certificate binding to tokens, nor DPoP (Demonstration of Proof-of-Possession) (RFC 9449) with proof-of-possession headers. The TLS configuration in main.py (lines 76-79) is server-side TLS only. This is a Level 3 requirement. The absence of sender-constrained tokens means that if an access token (or session cookie) is stolen, it can be used from any network location by any party. This affects both the resource server validation requirements (10.3.5) and authorization server issuance requirements (10.4.14).

**Remediation:**

Implement one of the following sender-constraining mechanisms: Option 1: Implement DPoP - Configure DPoP requirement in create_app() by setting app.config['REQUIRE_DPOP'] = True. Generate a DPoP key pair per-session, create DPoP proof JWTs with appropriate headers (typ: dpop+jwt, alg: ES256, jwk), and payload containing htm (HTTP method), htu (HTTP URI), iat, jti, and optionally ath (hash of access token). Include the DPoP proof in token requests via the DPoP header. Option 2: Implement session binding with client fingerprinting - Bind session to TLS connection attributes. Option 3: Implement mTLS approach - Configure client certificate verification in the application and bind tokens to the certificate thumbprint (cnf.x5t#S256).

---

#### FINDING-102: Authorization Code Grant Not Used with Pushed Authorization Requests (PAR)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 10.4.13, 10.4.15 |
| **Files** | v3/server/main.py:39-42 |
| **Source Reports** | 10.4.13.md, 10.4.15.md |
| **Related Findings** | None | **Description:**

The application uses the authorization code grant type without Pushed Authorization Requests (PAR). The authorization request is constructed as a direct redirect to the authorization endpoint with parameters in the URL (state=%s, redirect_uri=%s). Without PAR: 1) Authorization request parameters are exposed in the browser's address bar and potentially in referrer headers, 2) The redirect_uri and state parameters can be manipulated by the user before the request reaches the authorization server, 3) The authorization request is not authenticated (any party can construct one). At ASVS Level 3, the authorization code flow should always be used with PAR, which authenticates the authorization request, prevents parameter manipulation in the browser, and returns a request_uri that the client sends to the authorization endpoint instead of raw parameters. This also relates to protecting authorization_details parameters from tampering (10.4.15).

**Remediation:**

Implement PAR: push authorization request to AS first, then redirect with request_uri. Step 1: Push Authorization Request (authenticated) using httpx.post to 'https://oauth.apache.org/par' with client_id, client_secret, redirect_uri, state, response_type, scope, and any authorization_details. Step 2: Redirect user with only client_id and request_uri to the authorization endpoint. With PAR, authorization_details would be pushed server-to-server, ensuring parameters originate from the authenticated client backend and are tamper-proof.

---

#### FINDING-103: No replay detection mechanism in session claim consumption

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-294 |
| **ASVS Sections** | 10.5.1 |
| **Files** | v3/server/pages.py:82-91 |
| **Source Reports** | 10.5.1.md |
| **Related Findings** | None | **Description:**

The session is read and user identity values (uid, fullname, email) are consumed directly without any mechanism to detect if the underlying token has been replayed. There is no timestamp comparison, no nonce validation, and no binding to the current session. If session data originates from a replayed token, the application will trust it unconditionally.

**Remediation:**

Implement token replay detection mechanisms including nonce validation as described in OAUTH-LDAP-002. Additionally, consider adding timestamp-based validation to ensure tokens are not reused beyond their intended lifetime, and bind session data to specific authentication requests.

---

#### FINDING-104: No MFA Enforcement or Verification at Application Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-308 |
| **ASVS Sections** | 6.3.3 |
| **Files** | v3/server/main.py:38-42, v3/server/pages.py (all @asfquart.auth.require decorators) |
| **Source Reports** | 6.3.3.md |
| **Related Findings** | None | **Description:**

The application accepts any valid OAuth token from oauth.apache.org without verifying that the authentication included a second factor. If ASF OAuth allows single-factor authentication for some users, the application would grant access without MFA. User → ASF OAuth (unknown MFA policy) → OAuth token → Application session → Access granted without MFA verification. If the external OAuth provider does not universally enforce MFA, or if its MFA policy changes, users could authenticate to this application with only a single factor (password). For an election/voting application, this represents significant risk of account takeover leading to vote manipulation.

**Remediation:**

The application should either: 1. Verify MFA claims in the OAuth token/response (e.g., acr or amr claims in OIDC) 2. Implement a second authentication factor within the application 3. Document that ASF OAuth universally enforces MFA and that this is a dependency. Example: Check authentication method references in OAuth response: async def verify_mfa_in_session(session): """Verify that the OAuth authentication included MFA.""" amr = session.get('amr', []); if len(amr) < 2 or 'mfa' not in amr: quart.abort(403, 'Multi-factor authentication required')

---

#### FINDING-105: JWT/Token Signature Validation Not Visible at Application Layer

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-347 |
| **ASVS Sections** | 6.8.2 |
| **Files** | v3/server/main.py:40-43 |
| **Source Reports** | 6.8.2.md |
| **Related Findings** | None | **Description:**

The application configures OAuth URL endpoints but the actual token validation logic is encapsulated within the asfquart library, which is not provided for review. There is no visible code in the application layer that validates JWT signatures on ID tokens or access tokens, verifies token issuer (iss) claims, checks token audience (aud) claims, or validates token expiration (exp). The callback URL pattern suggests a simple token exchange without explicit signature verification at the application layer. If the asfquart library does not properly validate token signatures, an attacker could forge authentication assertions. The trust is entirely placed in the library implementation.

**Remediation:**

1. Verify that the asfquart library validates JWT/token signatures 2. Document the signature validation approach 3. Consider adding application-level assertion validation using a library like python-jose to explicitly validate ID token signatures and claims, including checking for unsigned tokens (alg: none), verifying issuer and audience claims, and only allowing expected algorithms like RS256.

---

#### FINDING-106: No User Notification When LDAP Profile Data Is Updated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-778 |
| **ASVS Sections** | 6.3.7 |
| **Files** | v3/server/bin/asf-load-ldap.py:45-62 |
| **Source Reports** | 6.3.7.md |
| **Related Findings** | FINDING-107 | **Description:**

When the LDAP synchronization script updates a user's profile information (display name or email address), the user is not notified. While the application doesn't manage authentication credentials directly (those are in ASF's IdP), changes to associated identity information (email, display name) that could indicate account compromise are not communicated to users. If an attacker compromises an ASF account and changes the associated email address in LDAP, the synchronized data would change silently in the voting system. The legitimate user would not receive any notification that their profile was modified, potentially missing a signal of account takeover.

**Remediation:**

Implement change detection and notification in the LDAP sync: for r in results: entry = edict(r[1]); uid = entry.uid[0].decode('utf-8'); visname = entry.cn[0].decode('utf-8'); email = entry['asf-committer-email'][0].decode('utf-8'); # Detect changes before overwriting; try: existing = pdb.get_person(uid); if existing[1] != email: notify_user_profile_change(uid, 'email', existing[1], email); if existing[0] != visname: notify_user_profile_change(uid, 'name', existing[0], visname); except steve.persondb.PersonNotFound: pass; pdb.add_person(uid, visname, email)

---

#### FINDING-107: No Suspicious Authentication Notification System

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-778 |
| **ASVS Sections** | 6.3.5 |
| **Files** | All files in scope |
| **Source Reports** | 6.3.5.md |
| **Related Findings** | FINDING-106 | **Description:**

The application does not implement any mechanism to detect or notify users about suspicious authentication attempts. Specifically: 1. No unusual location detection: No IP geolocation tracking or comparison with previous logins. 2. No unusual client detection: No user-agent or device fingerprinting. 3. No failed attempt tracking: No counter for failed authentication attempts per user. 4. No inactivity-based alerts: No detection of authentication after long dormancy periods. 5. No successful-after-failed notification: No mechanism to alert when login succeeds after multiple failures. The application delegates authentication entirely to ASF OAuth, but does not receive or process any signals about authentication anomalies from the OAuth provider.

**Remediation:**

Implement authentication event monitoring and notification: async def check_suspicious_auth(session, request): uid = session['uid']; current_ip = request.remote_addr; current_ua = request.headers.get('User-Agent', ''); last_auth = await get_last_auth_record(uid); suspicious = False; if last_auth: if last_auth.ip != current_ip: suspicious = True; if last_auth.user_agent != current_ua: suspicious = True; if (datetime.now() - last_auth.timestamp).days > 90: suspicious = True; if suspicious: await send_notification(uid, 'Suspicious login detected', details); await record_auth_event(uid, current_ip, current_ua)

---

#### FINDING-108: Inconsistent Privilege Requirements Create Privilege Escalation Path

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 8.2.1 |
| **Files** | v3/server/pages.py:435 |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | None | **Description:**

Election creation requires R.pmc_member (PMC member privilege) while all other election operations only require R.committer (committer privilege). This creates a privilege escalation path where a committer cannot create elections but can fully manage (including opening, closing, deleting issues from) elections created by PMC members. The higher-privilege requirement for creation provides no security benefit when any lower-privileged committer can fully manage all existing elections. This inconsistency undermines the privilege model and creates confusion about intended access controls.

**Remediation:**

Apply consistent authorization at all management endpoints by implementing the ownership and authz group checks described in EAAC-001. This ensures that only authorized users (owners or authz group members) can manage elections, regardless of whether they are PMC members or committers. The R.pmc_member requirement for creation can remain as a separate organizational policy control, but all subsequent management must verify election-specific authorization.

---

#### FINDING-109: Missing Authorization Check in Election Date Modification Helper

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2 |
| **Files** | v3/server/pages.py:75-95 |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | FINDING-021, FINDING-022, FINDING-110 | **Description:**

The _set_election_date helper function contains a '# check authz' comment but performs NO authorization check. Any committer can set open_at or close_at dates on any election. This is a specific instance of the BOLA vulnerability (EAAC-001) applied to the date modification helper function. The function proceeds to modify election dates without verifying the authenticated user has permission to manage that election. While the dates are marked as 'purely advisory' in SQL comments, unauthorized modification still represents a security control failure.

**Remediation:**

Implement authorization check in _set_election_date function to verify the authenticated user is the election owner (md.owner_pid == uid) or member of the authz LDAP group before allowing date modifications. This check should follow the same pattern as the check_election_authz() function recommended in EAAC-001. Return 403 Forbidden if authorization fails.

#### FINDING-110: Issue KV Data Exposed Without Role-Based Field Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.3 |
| **Files** | v3/steve/election.py:235-250 |
| **Source Reports** | 8.2.3.md |
| **Related** | FINDING-021, FINDING-022, FINDING-109 | **Description:**

The list_issues() method returns all KV data including operational configuration fields without filtering based on the caller's role or context. There is no distinction between what fields a voter should see (ballot data like candidates and labelmap) versus what a manager should see (full configuration including internal settings). The kv field contains operational data that may be appropriate for voters, but the method has no field filtering mechanism based on the consumer's role. Any caller (management page OR voting page) receives the full kv field without differentiation, potentially exposing management-specific configuration data to voters.

**Remediation:**

Add an include_management_fields parameter (default False) to the list_issues() method to enable field filtering based on access level. When include_management_fields is False, filter the kv dictionary to only include voter-visible fields such as candidates, labelmap, and seats. When True (for management interfaces), return full kv data. Implement role-based field filtering so that management-specific configuration data is only exposed to authorized managers. Update callers to specify appropriate filtering level based on context.

---

#### FINDING-111: No Session Invalidation Mechanism for Authorization Revocations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.3.2 |
| **Files** | v3/server/pages.py:67-93 |
| **Source Reports** | 8.3.2.md |
| **Related** | - | **Description:**

If a voter's eligibility is revoked (e.g., removed from mayvote during the editable phase, or LDAP group membership changes), there is no mechanism to: (1) immediately invalidate their active session, (2) alert when they perform actions they're no longer authorized for, or (3) revert changes made after authorization was revoked. Given that the authz LDAP group check is not implemented (EAAC-001), this is a compounding issue—even if authz were checked at login, there's no re-check during the session. Authorization changes are only effective on the next database query, but cached session data may allow continued access.

**Remediation:**

Implement authorization re-validation on each request for sensitive operations. Add validate_user_still_active(uid) function that checks if user is still active in LDAP and has required group memberships. In basic_info() or a middleware layer, verify authorization freshness: if s: uid = s['uid']; if not await validate_user_still_active(uid): await asfquart.session.invalidate(); quart.abort(401, 'Session invalidated - user no longer authorized'). Consider adding session metadata tracking (last_authz_check timestamp) to avoid checking on every request while ensuring reasonable freshness.

---

#### FINDING-112: No Device Security Posture Assessment or Contextual Risk Analysis

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 8.4.2 |
| **Files** | v3/server/pages.py:450-486 |
| **Source Reports** | 8.4.2.md |
| **Related** | - | **Description:**

ASVS 8.4.2 explicitly requires 'device security posture assessment' and 'contextual risk analysis' for administrative interfaces. The system has no implementation of: device fingerprinting, behavioral analysis (rapid successive operations, unusual access patterns), geographic/IP risk scoring, session binding to device characteristics, or anomaly detection for administrative operations. Compromised credentials from any network location grant full administrative access with no contextual awareness. No adaptive controls based on IP address changes, time-of-day patterns, concurrent sessions, or device changes.

**Remediation:**

Implement assess_admin_risk(uid, operation) function that calculates risk score based on: (1) IP address consistency with session (session['last_ip'] vs request.remote_addr), (2) rapid successive admin operations (time since last_admin_timestamp), (3) User-Agent consistency (session['user_agent'] vs request headers), (4) time-of-day patterns (operations outside business hours). Store session context in session data. If risk_score >= 50, require step-up authentication. Log all risk assessments with structured format. Implement session binding to device characteristics and detect session hijacking through context changes.

---

#### FINDING-113: No Adaptive Security Controls Based on Environmental/Contextual Attributes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.2.4 |
| **Files** | v3/server/pages.py:67-93 |
| **Source Reports** | 8.2.4.md |
| **Related** | - | **Description:**

The application does not implement any adaptive security controls based on environmental or contextual attributes such as: IP address changes during session, geolocation anomalies, device fingerprint changes, time-of-day restrictions, concurrent session detection, or unusual access patterns (e.g., managing elections outside business hours). This means a compromised session token can be used from any location, device, or context without triggering additional verification. While the application uses server-side session validation, there is no contextual risk assessment or adaptive response.

**Remediation:**

Implement session context validation including: (1) IP-based session binding - store request_ip in session at creation and validate on subsequent requests, (2) device fingerprinting - track User-Agent and basic device characteristics, (3) time-of-day restrictions - require additional authentication for sensitive operations outside business hours (6 AM - 10 PM), (4) geolocation validation - flag sessions from unexpected geographic locations, (5) concurrent session detection - track active sessions per user and alert on anomalies, (6) step-up authentication - require re-authentication for sensitive operations when context changes significantly. Example: async def validate_session_context(session): request_ip = quart.request.remote_addr; stored_ip = session.get('bound_ip'); if stored_ip and request_ip != stored_ip: raise ContextViolation('IP address changed').

---

#### FINDING-114: Incomplete Function-Level Authorization Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 8.1.1, 8.1.2 |
| **Files** | v3/docs/schema.md:entire file |
| **Source Reports** | 8.1.1.md, 8.1.2.md |
| **Related** | - | **Description:**

The authorization documentation partially defines access rules but lacks comprehensive function-level access control specification. While the documentation mentions ownership (owner_pid) and LDAP group authorization (authz), it does not provide a complete mapping of which functions/operations each role can perform. Missing documentation includes: no explicit listing of all protected functions (open, close, add-issue, edit-issue, delete-issue, set-dates, vote, tally); no matrix mapping consumer permissions (owner, authz group member, eligible voter, committer, PMC member) to allowed operations; the authz field format is explicitly marked 'TBD' indicating incomplete design; no documentation of the R.committer vs R.pmc_member distinction for election creation vs management; no documentation of what 'committer' status grants vs 'owner' status.

**Remediation:**

Create comprehensive field-level access control documentation specifying read/write permissions for each consumer type (Owner, Voter) and field, including state dependencies. Document which fields are system-only (salt, opened_key, vote_token) and never exposed to consumers. Include a table mapping fields to permissions with state dependency information: Field | Owner (Read) | Owner (Write) | Voter (Read) | Voter (Write) | State Dependency. Example entries: eid (Yes|Never|Yes|Never|-), title (Yes|EDITABLE only|Yes|Never|-), owner_pid (Yes|Never|No|Never|-), salt (Never|Never|Never|Never|System-only), opened_key (Never|Never|Never|Never|System-only).

---

#### FINDING-115: Missing Documentation of Environmental and Contextual Security Attributes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.1.3 |
| **Files** | v3/docs/schema.md:entire file, v3/server/pages.py:entire file |
| **Source Reports** | 8.1.3.md |
| **Related** | - | **Description:**

The application's documentation does not define any environmental or contextual attributes used in security decisions. There is no documentation of whether time of day, user location, IP address, device type, or other contextual factors influence authentication or authorization decisions. The open_at and close_at fields exist in the schema, but the SQL comment explicitly states: 'These are purely advisory, for humans, and have no effect upon the actual Election operation.' No IP-based restrictions, geographic restrictions, or device/browser-based security decisions are documented. The @asfquart.auth.require decorator handles authentication but no documentation defines what contextual factors the authentication system evaluates.

**Remediation:**

Document all environmental/contextual attributes (or explicitly state none are used). Create documentation section covering: Attributes NOT Used (with intentional design decisions for time-of-day, IP address, device type, geographic location) and Attributes Used (authentication session via OAuth/asfquart with session timeout, LDAP group membership evaluated at request time, election state machine that is time-independent). Example: 'Environmental and Contextual Attributes: Time-of-day restrictions: NOT USED (intentional - ASF is a global organization with contributors in all time zones). IP address restrictions: NOT USED (intentional - contributors work from various locations). Device type restrictions: NOT USED (intentional - support for diverse platforms). Geographic location: NOT USED (intentional - global contributor base). Attributes that ARE used: Authentication session (OAuth via ASF IdP, session timeout per ASF IdP configuration), LDAP group membership (evaluated at request time), Election state (managed through explicit state transitions, not time-based).'

---

#### FINDING-116: Missing Documentation of Environmental Factors in Authorization Decision-Making

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 8.1.4 |
| **Files** | All documentation files |
| **Source Reports** | 8.1.4.md |
| **Related** | - | **Description:**

There is no documentation defining how environmental and contextual factors are used in authentication and authorization decision-making, including thresholds, risk levels, and actions taken. Since no environmental/contextual attributes are documented (EAAC-017), there is no documentation of decision logic, evaluated attributes, risk thresholds, or resulting actions (allow/challenge/deny/step-up). Missing documentation includes: no risk scoring model, no step-up authentication triggers, no adaptive authentication rules, no documentation of when 'deny' vs 'challenge' applies, no documentation of how the ASF IdP session interacts with the application's authorization layer, and no documentation of what happens when LDAP group membership changes mid-session.

**Remediation:**

Create comprehensive decision-making framework documentation that includes: Authentication Decision Flow table (Context | Evaluation | Threshold | Action) covering valid session, expired session, and no session scenarios. Authorization Decision Flow table covering election management, vote casting, and election creation with evaluation criteria, thresholds, and actions (Allow or Deny with HTTP status). Factors NOT Evaluated section documenting design decisions: IP address changes during session (not evaluated due to global user base), concurrent sessions (not restricted), rate limiting (delegated to reverse proxy layer). Example format provided in 8.1.4.md report.

---

#### FINDING-117: No session inactivity timeout or absolute session lifetime documentation or configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.1.1, 7.3.1 |
| **Files** | v3/server/pages.py:58-84 |
| **Source Reports** | 7.1.1.md, 7.3.1.md |
| **Related** | - | **Description:**

No session inactivity timeout is configured anywhere in the provided codebase. No absolute maximum session lifetime is defined. The asfquart.session.read() function is called without any visible timeout parameters. No documentation (in code comments, configuration, or schema.md) addresses session timeout decisions or deviations from NIST SP 800-63B. NIST SP 800-63B §7.2 recommends re-authentication after 30 minutes of inactivity at AAL1 or 15 minutes at AAL2. No such controls are evident. The election system handles sensitive voting operations, which would typically require documented justification for session lifetime decisions. Without documented session timeouts, sessions could persist indefinitely, increasing the risk of session hijacking on shared/public workstations. Lack of documentation means no security review can verify that timeouts are appropriate for the risk level.

**Remediation:**

Implement session inactivity timeout mechanism: 1. Add SESSION_INACTIVITY_TIMEOUT configuration (e.g., 30 minutes), 2. Store last_activity timestamp in session data, 3. Implement middleware or modify basic_info() to check elapsed time since last activity, 4. Update last_activity timestamp on each request, 5. Destroy session and return 401 if timeout exceeded. Example code: SESSION_INACTIVITY_TIMEOUT = 30 * 60  # 30 minutes; async def basic_info(): s = await asfquart.session.read(); if s: last_activity = s.get('last_activity', 0); now = time.time(); if now - last_activity > SESSION_INACTIVITY_TIMEOUT: await asfquart.session.destroy(); quart.abort(401, 'Session expired due to inactivity'); s['last_activity'] = now; await asfquart.session.save(s)

---

#### FINDING-118: No concurrent session policy documentation or enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.1.2 |
| **Files** | v3/server/pages.py:entire file, notably authentication patterns |
| **Source Reports** | 7.1.2.md |
| **Related** | - | **Description:**

No documentation defines how many concurrent sessions are permitted per account. No session counting or session listing mechanism exists in the codebase. No behavior is defined for when a maximum number of sessions is reached (e.g., deny new login, terminate oldest session, or alert user). The election system allows voting operations—if an attacker establishes a parallel session after stealing credentials, there is no detection or limitation mechanism. The basic_info() function simply reads whatever session is present without cross-referencing against other active sessions for the same user.

**Remediation:**

Document concurrent session policy and implement controls: Create documentation (session-management-policy.md) specifying: Maximum concurrent sessions per account: 3; When maximum reached: oldest session is invalidated; Justification: Allows legitimate use across desktop/mobile while detecting credential sharing or compromise; Users are notified on login if other active sessions exist. Implementation example: async def enforce_session_limits(uid): active_sessions = await session_store.get_active_sessions(uid); MAX_CONCURRENT = 3; if len(active_sessions) >= MAX_CONCURRENT: oldest = min(active_sessions, key=lambda s: s.created_at); await session_store.invalidate(oldest.session_id); _LOGGER.warning(f'User[U:{uid}] exceeded max sessions; terminated oldest')

---

#### FINDING-119: Federated identity system (ASF SSO) interaction undocumented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.1.3 |
| **Files** | v3/server/pages.py:1-36 |
| **Source Reports** | 7.1.3.md |
| **Related** | - | **Description:**

The application uses asfquart.auth and asfquart.session, which integrate with Apache Software Foundation's identity management ecosystem (likely involving LDAP and OAuth/SSO). The code comments explicitly acknowledge this is ASF-committer-specific authentication. There is no documentation detailing: How the ASF SSO session coordinates with the application session, what happens when the SSO session expires but the local session persists, how session termination propagates between systems, conditions that require re-authentication (e.g., sensitive operations like opening/closing elections), and session lifetime coordination between the Identity Provider and this application. The schema.md documentation covers database schema but not authentication/session architecture. Multiple comments indicate incomplete authorization design. Without documented federated session management, there is a risk of: orphaned local sessions after SSO logout, inconsistent session lifetimes between the IdP and this application, missing re-authentication for high-privilege operations (opening elections, tallying votes), and no coordinated session termination in incident response scenarios.

**Remediation:**

Create federated session management documentation covering: Systems in Ecosystem (ASF OAuth/SSO Identity Provider, STeVe Application, LDAP Directory), Session Coordination (local session must not exceed IdP session lifetime, application checks IdP token validity on sensitive operations, logout from IdP triggers backchannel logout notification), Re-authentication Requirements (opening an election, closing an election, tallying votes all require re-verification of IdP session), and Session Termination (user-initiated logout invalidates both local and IdP sessions, IdP-initiated revocation must invalidate local session within 5 minutes, administrative session revocation propagates immediately).

---

#### FINDING-120: No visible session token regeneration on authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.2.4 |
| **Files** | v3/server/pages.py:58-85 |
| **Source Reports** | 7.2.4.md |
| **Related** | - | **Description:**

The application code does not contain any explicit login endpoint or authentication handler where session token regeneration could occur. Authentication is entirely delegated to the asfquart.auth framework via decorators (@asfquart.auth.require). There is no evidence in the codebase that: (1) A new session token is generated upon successful authentication, (2) The old session token is invalidated upon re-authentication, (3) Any session fixation protections are implemented at the application level. The asfquart.session.read() call only reads existing session data — it does not create or rotate sessions. If the underlying asfquart framework does not regenerate session tokens on authentication, the application is vulnerable to session fixation attacks. An attacker who sets or knows a user's session ID before login could hijack the session after the user authenticates.

**Remediation:**

After successful authentication, the framework or application should: (1) Invalidate old session using await asfquart.session.destroy(), (2) Create new session with fresh token using await asfquart.session.create(), (3) Populate new session with user data (uid, fullname, email), (4) Save the new session using await asfquart.session.save(new_session). This may be handled by the asfquart framework outside the visible code scope. Verification with the framework documentation is required.

---

#### FINDING-121: No option to terminate other sessions after authentication factor change

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.4.3 |
| **Files** | v3/server/pages.py:535-549 |
| **Source Reports** | 7.4.3.md |
| **Related** | - | **Description:**

The application provides a /profile page and a /settings page but both are stubs that only render templates with basic info. There is no password change endpoint, no MFA configuration endpoint, no 'terminate all other sessions' feature, no mechanism to list active sessions, and no per-user session invalidation trigger. Even if authentication factor changes are handled by an external identity provider (implied by the ASF/LDAP integration), the application provides no option to terminate other sessions after such a change. If a user's credentials are compromised and they change their password through an external system, all existing sessions (including those of the attacker) remain valid. The user has no way to force re-authentication on other active sessions.

**Remediation:**

Implement a session termination endpoint that allows users to invalidate all sessions except the current one. Example implementation: Add a POST endpoint '/do-terminate-other-sessions' that retrieves the current session ID, invalidates all other sessions for the user via session_store.invalidate_all_except(result.uid, current_session_id), logs the action, and redirects to settings. Additionally, implement session-to-user mapping to enable finding all sessions for a given PID, add active session listing functionality, and integrate session termination options into the /settings page.

---

#### FINDING-122: No re-authentication enforced before sensitive account modifications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.5.1 |
| **Files** | v3/server/pages.py:535-548, v3/server/pages.py:83 |
| **Source Reports** | 7.5.1.md |
| **Related** | - | **Description:**

The `/profile` and `/settings` pages exist with authentication requirements, but there is no evidence of re-authentication being enforced before modifying sensitive account attributes. While no POST handlers for profile/settings changes are currently visible in this file, the pages are defined and presumably have (or will have) modification capabilities. User has active session → navigates to `/profile` or `/settings` → only requires existing valid session → no re-authentication challenge for modifications. If an attacker gains access to an active session (XSS, session fixation, physical access to unlocked device), they could modify sensitive account attributes (email for recovery, etc.) without being challenged for credentials. This is particularly concerning given the CSRF token is a placeholder (`basic.csrf_token = 'placeholder'` at line 83).

**Remediation:**

Implement re-authentication middleware for sensitive operations: async def require_reauthentication(): """Check if user has recently re-authenticated (within last 5 minutes).""" s = await asfquart.session.read(); reauth_time = s.get('last_reauth'); if not reauth_time or (time.time() - reauth_time) > 300: return quart.redirect(f'/auth/reauth?return_to={quart.request.path}'); return None; @APP.post('/do-update-profile'); @asfquart.auth.require; async def do_update_profile(): redirect = await require_reauthentication(); if redirect: return redirect; # ... proceed with attribute changes

---

#### FINDING-123: Creating elections lacks step-up authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 7.5.3 |
| **Files** | v3/server/pages.py:410-427 |
| **Source Reports** | 7.5.3.md |
| **Related** | - | **Description:**

Creating an election — while less destructive — is a privileged operation that only requires R.pmc_member session authentication with no additional verification. The do_create_endpoint function processes election creation requests without requiring recent re-authentication or secondary verification.

**Remediation:**

Implement step-up authentication using the require_step_up_auth function before allowing election creation. Require recent authentication (within 5 minutes) before processing the election creation request.

---

#### FINDING-124: No validation of session freshness or maximum time between IdP authentication events

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.6.1 |
| **Files** | v3/server/pages.py:68-84 |
| **Source Reports** | 7.6.1.md |
| **Related** | - | **Description:**

The application reads session data from the SSO provider but does not validate session freshness or enforce maximum time between IdP authentication events. There is no check of when the user last authenticated at the IdP level. If the IdP session expires or is revoked, the application's local session may continue to be valid, creating a disconnect between the IdP's authentication state and the RP's session state. This is particularly relevant for this voting system since a user removed from a PMC/committer group at the IdP level may retain voting access, and the application cannot enforce re-authentication when IdP policies change.

**Remediation:**

Implement IdP authentication freshness checking by validating auth_time claims from the IdP and forcing re-authentication when the maximum authentication age is exceeded. Example: Check if idp_auth_time exists in session and compare (time.time() - idp_auth_time) against MAX_IDP_AUTH_AGE (e.g., 3600 seconds). If exceeded, redirect to /auth?login= to force re-authentication at IdP.

---

#### FINDING-125: Silent Session Creation via Federated Re-authentication Without User Consent

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.6.2 |
| **Files** | v3/server/main.py:36-40 |
| **Source Reports** | 7.6.2.md |
| **Related** | - | **Description:**

The OAuth initialization URL does not include a prompt parameter (such as prompt=login or prompt=consent). Per NIST SP 800-63C, the RP should ensure that re-authentication involves explicit user action to prevent session creation without user awareness. When a user has an active IdP session but no RP session, accessing any protected page triggers silent re-authentication and session creation. The data flow: User's RP session expires → User visits any protected page → @asfquart.auth.require decorator detects no session and redirects to OAuth → OAuth URL has no prompt parameter → If user has active IdP session at oauth.apache.org, IdP silently redirects back with auth code → RP callback creates new session without any user interaction at the RP or IdP. An attacker who can inject content into a page viewed by the victim could trigger silent session creation at the RP by embedding hidden requests to protected pages.

**Remediation:**

Add prompt=consent or prompt=login parameter to the OAuth initialization URL in main.py. Change OAUTH_URL_INIT to include &prompt=consent to force user interaction. Alternatively, implement a login interstitial page with an explicit 'Continue to login' button that serves as the sole OAuth entry point, ensuring users are aware of and consent to session creation before the OAuth flow begins.

---

#### FINDING-126: Flash messages embed user-controlled input without encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.1.2 |
| **Files** | v3/server/pages.py:430, v3/server/pages.py:491, v3/server/pages.py:513, v3/server/pages.py:531 |
| **Source Reports** | 1.1.2.md |
| **Related** | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-127, FINDING-128 | **Description:**

User-controlled input (form.title) is embedded in flash messages without HTML encoding at the point of message creation. The encoding responsibility is deferred to the template. This violates the principle of encoding as the final step before the interpreter because the control is split across two locations with no guarantee the template applies it. If the flashes.ezt template outputs these without HTML encoding, this creates a reflected XSS vulnerability.

**Remediation:**

Either HTML-encode at flash message creation using html.escape(), or ensure the flashes template uses [format "html"]. Example: import html; await flash_success(f'Created election: {html.escape(form.title)}')

---

#### FINDING-127: Election titles and user names output without HTML encoding across multiple templates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.2 |
| **Files** | v3/server/templates/header.ezt, v3/server/templates/admin.ezt, v3/server/templates/voter.ezt, v3/server/templates/manage.ezt, v3/server/templates/vote-on.ezt |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-128 | **Description:**

User-controlled data including election titles and person names are output in multiple templates (header.ezt, admin.ezt, voter.ezt, manage.ezt, vote-on.ezt) without [format "html"] encoding. Election titles are set by PMC members during creation, and names come from PersonDB/LDAP. An attacker with PMC member or LDAP write access could inject HTML/JavaScript that renders for all users viewing the affected elections. Examples include page titles, navbar user names, card titles, and election owner names.

**Remediation:**

Apply [format "html"] to ALL user-controlled template variables: &lt;title&gt;Apache STeVe: [format "html"][title][end]&lt;/title&gt;, &lt;h5 class="card-title"&gt;[format "html"][owned.title][end]&lt;/h5&gt;, &lt;strong&gt;[format "html"][issues.title][end]&lt;/strong&gt;, etc.

---

#### FINDING-128: Missing JavaScript Encoding in HTML Attributes with Template Variables

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.2.3 |
| **Files** | v3/server/templates/vote-on.ezt:throughout the &lt;script&gt; block |
| **Source Reports** | 1.2.3.md |
| **Related** | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127 | **Description:**

Template variables (issues.iid) are embedded in onclick attribute strings and DOM element IDs without [format "js,html"] applied. While IIDs are cryptographically generated and thus practically safe, the pattern of embedding template variables in JavaScript strings within HTML attributes without encoding is architecturally wrong. If the ID generation ever changes or a different data source is used, this becomes exploitable. This represents a defense-in-depth gap.

**Remediation:**

Apply [format "js,html"] to all template variables embedded in HTML attributes that contain JavaScript, for example: &lt;span onclick="toggleDescription('[format "js,html"][issues.iid][end]')"&gt;. This ensures defense-in-depth even for controlled values.

---

#### FINDING-129: voter.ezt tab activation script embeds server value without JS encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.2 |
| **Files** | v3/server/templates/voter.ezt |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127 | **Description:**

The voter.ezt template embeds the active_tab value into JavaScript without [format "js"] encoding: var active = "[active_tab]";. Currently, active_tab is set to fixed string values ('open', 'upcoming', 'past') in server code, so the impact is low in practice. However, the pattern is unsafe and could become exploitable if the logic changes to accept user input or if the code is refactored.

**Remediation:**

Apply [format "js"] encoding: var active = "[format "js"][active_tab][end]";

---

#### FINDING-130: Missing URL encoding and HTML escaping in document link construction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.2.2, 1.3.1, 1.3.3 |
| **Files** | v3/server/pages.py:54-56 |
| **Source Reports** | 1.2.2.md, 1.3.1.md, 1.3.3.md |
| **Related** | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127 | **Description:**

The rewrite_description() function extracts filenames from 'doc:' patterns using regex and directly injects them into href attributes and tag bodies without proper escaping. The regex ([^\s]+) captures everything after 'doc:' until whitespace, allowing an attacker to inject attribute values. For example, 'doc:"onmouseover="alert(1)"x="' results in &lt;a href="/docs/iid/"onmouseover="alert(1)"x=""&gt;...&lt;/a&gt;, creating an XSS vector via event handler injection. User-supplied description containing doc:payload pattern flows to unsanitized filename value inserted into HTML href attribute and element content.

**Remediation:**

Apply URL encoding to the href value using urllib.parse.quote() and HTML escaping to the display text using html.escape(). Example: safe_href = quote(filename, safe=''); safe_display = html.escape(filename); return f'&lt;a href="/docs/{issue.iid}/{safe_href}"&gt;{safe_display}&lt;/a&gt;'

---

#### FINDING-131: Missing explicit canonicalization validation in document serving endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 1.1.1 |
| **Files** | v3/server/pages.py:559-576 |
| **Source Reports** | 1.1.1.md |
| **Related** | - | **Description:**

While Quart performs URL decoding once (correct), there is no verification that `docname` or `iid` don't contain encoded sequences that could bypass controls after the single decode. The comment `### verify the propriety of DOCNAME.` explicitly acknowledges missing canonicalization validation. Although `send_from_directory` provides path traversal protection, the `iid` is used to construct the directory path (`DOCSDIR / iid`) before being passed to `send_from_directory`, and is only implicitly validated via database lookup rather than explicit canonicalization. Data Flow: URL path (`/docs/<iid>/<docname>`) → URL-decoded once by Quart router → used directly in path construction without canonicalization verification → passed to `send_from_directory`. A request to `/docs/valid_iid/..%252f..%252fetc%252fpasswd` — if Quart's routing or send_from_directory performed additional decoding, this could bypass controls. In practice, `send_from_directory` handles this, but the architectural pattern is incorrect.

**Remediation:**

Validate docname is a simple filename (canonical form check): if '/' in docname or '\\' in docname or docname.startswith('.'): quart.abort(400). Ensure IID matches expected format (alphanumeric crypto ID): if not iid.isalnum(): quart.abort(400). This should be done before the database lookup and before constructing the path to send_from_directory.

---

#### FINDING-132: No Content-Security-Policy headers on HTML responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.2.1 |
| **Files** | v3/server/templates/header.ezt |
| **Source Reports** | 3.2.1.md |
| **Related** | - | **Description:**

Server generates HTML responses without CSP header or meta tag to restrict resource loading. If XSS occurs, attacker has full browser capability. Without CSP, any successful XSS injection has unrestricted access to inline scripts, eval(), and cross-origin resource loading. CSP would serve as a defense-in-depth layer against content rendering in unintended contexts.

**Remediation:**

Add CSP via middleware or response headers using after_request decorator. For HTML responses, set Content-Security-Policy header with: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' https://www.apache.org; frame-ancestors 'none'. Also add X-Content-Type-Options: nosniff header.

---

#### FINDING-133: No Sec-Fetch-* header validation on API endpoints serving sensitive data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.2.1 |
| **Files** | v3/server/pages.py |
| **Source Reports** | 3.2.1.md |
| **Related** | - | **Description:**

API endpoints do_set_open_at_endpoint, do_set_close_at_endpoint, and serve_doc do not validate Sec-Fetch-* headers. Without Sec-Fetch-* validation, the application cannot distinguish between same-origin navigation requests and cross-origin or embed attempts, reducing defense-in-depth against CSRF and resource misuse attacks.

**Remediation:**

Create a validate_sec_fetch decorator that checks the Sec-Fetch-Site header and only allows 'same-origin' or 'none' values. Abort with 403 'Cross-origin request rejected' for other values. Apply this decorator to sensitive endpoints.

---

#### FINDING-134: Form-Based POST Endpoints Accept CORS-Safelisted Content Types Without Origin Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.5.2 |
| **Files** | v3/server/pages.py |
| **Source Reports** | 3.5.2.md |
| **Related** | - | **Description:**

Requests with Content-Type: application/x-www-form-urlencoded are CORS-safelisted and do NOT trigger a preflight OPTIONS request. Since there is no CSRF token validation, no Origin header validation, and no requirement for non-safelisted headers, these endpoints cannot rely on the CORS preflight mechanism for protection. Cross-origin form submissions can reach sensitive functionality without triggering a CORS preflight.

**Remediation:**

Implement Origin header validation using a decorator function that validates the Origin header matches expected values. If Origin is present (cross-origin request) and not in allowed_origins list, reject with 403. Additionally, implement CSRF token validation and enforce Content-Type validation on form endpoints.

---

#### FINDING-135: Authenticated Document Endpoint Serves Files Without XSSI Protections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.7 |
| **Files** | v3/server/pages.py:651-666 |
| **Source Reports** | 3.5.7.md |
| **Related** | - | **Description:**

The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serves files to authenticated users after performing fine-grained authorization checks, but does not implement browser-level origin separation controls. If JavaScript files are stored as election documents (e.g., configuration scripts, candidate data in JS format), an attacker can embed them cross-origin via &lt;script src&gt; tags and extract authorized data. The attack requires the victim to visit the attacker's page while authenticated and having mayvote access to the target issue. The server's authorization model can be circumvented because the browser sends cookies with the cross-origin request, the server authorizes it, but the response is delivered to the attacker's origin context where it can be parsed as JavaScript.

**Remediation:**

Add X-Content-Type-Options: nosniff and Cross-Origin-Resource-Policy: same-origin headers to the response from the serve_doc endpoint. Example implementation: @APP.get('/docs/&lt;iid&gt;/&lt;docname&gt;'); @asfquart.auth.require; async def serve_doc(iid, docname): result = await basic_info(); db = steve.election.Election.open_database(DB_FNAME); row = db.q_get_mayvote.first_row(result.uid, iid); if not row: quart.abort(404); response = await quart.send_from_directory(DOCSDIR / iid, docname); response.headers['X-Content-Type-Options'] = 'nosniff'; response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'; return response

---

#### FINDING-136: No Cross-Origin-Resource-Policy Header on Any Authenticated Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.8 |
| **Files** | v3/server/pages.py |
| **Source Reports** | 3.5.8.md |
| **Related** | - | **Description:**

No Cross-Origin-Resource-Policy response header is set anywhere in the application. There is no after-request middleware adding this header. Without CORP headers, browsers rely solely on other mechanisms (SameSite cookies, CORS) to prevent cross-origin resource loading. This removes a critical defense-in-depth layer. Authenticated pages and resources can potentially be loaded in cross-origin contexts depending on cookie settings and browser behavior.

**Remediation:**

Implement an after_request handler that adds Cross-Origin-Resource-Policy headers to all responses: 'cross-origin' for public resources (static files, favicon), 'same-site' for landing/about pages, and 'same-origin' for all authenticated resources.

---

#### FINDING-137: Template Triggers State-Changing GET Requests via JavaScript Navigation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.8 |
| **Files** | v3/server/templates/manage.ezt |
| **Source Reports** | 3.5.8.md |
| **Related** | - | **Description:**

The manage.ezt template uses window.location.href in JavaScript to trigger state changes (open/close election) via GET requests. This confirms the architectural decision to use GET requests for state-changing operations, which is inherently vulnerable to cross-origin exploitation via links, redirects, and top-level navigations. The client-side code reinforces the server-side vulnerability by using navigational JavaScript rather than POST form submissions.

**Remediation:**

Replace window.location.href navigations with POST form submissions that include CSRF tokens. Create forms dynamically in JavaScript, add CSRF token as hidden input, append to document body, and submit programmatically.

---

#### FINDING-138: State-Changing Operations Using GET Method Without SameSite Protection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.3.2 |
| **Files** | v3/server/pages.py:468, v3/server/pages.py:490 |
| **Source Reports** | 3.3.2.md |
| **Related** | FINDING-019 | **Description:**

State-changing operations (open/close election) use GET method at endpoints /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt;. Without SameSite cookie protection, these are trivially exploitable via &lt;img&gt; tags or link preloading. Even with SameSite=Lax, GET-based state-changing operations would be vulnerable since Lax allows top-level navigation. Only SameSite=Strict would fully protect these endpoints, but they should use POST methods regardless.

**Remediation:**

Change these endpoints to POST methods and implement proper CSRF protection: @APP.post('/do-open/&lt;eid&gt;'); @asfquart.auth.require({R.committer}); @load_election; async def do_open_endpoint(election): # Validate CSRF token; ...; @APP.post('/do-close/&lt;eid&gt;'); @asfquart.auth.require({R.committer}); @load_election; async def do_close_endpoint(election): # Validate CSRF token; ...

---

#### FINDING-139: No CORS Configuration Visible in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-942 |
| **ASVS Sections** | 3.4.2 |
| **Files** | v3/server/main.py:32-45, v3/server/pages.py:Application-wide |
| **Source Reports** | 3.4.2.md |
| **Related** | - | **Description:**

The provided application code contains no visible CORS configuration — no Access-Control-Allow-Origin header is set on any response, no CORS middleware is registered, and no @app.after_request handler manages CORS headers. The api module is imported but not provided for review, meaning CORS handling for API endpoints cannot be verified. If the underlying asfquart framework does not provide CORS protection by default, the application may either not serve cross-origin requests at all (failing to serve legitimate API consumers), or if a CORS library is added later without proper configuration, it could expose sensitive election data to unauthorized origins.

**Remediation:**

Implement CORS header configuration in create_app() or via a dedicated middleware using an @app.after_request handler. Use a fixed allowlist of trusted origins (e.g., ALLOWED_ORIGINS = {'https://whimsy.apache.org', 'https://www.apache.org'}). Validate the Origin HTTP request header against this allowlist and only set Access-Control-Allow-Origin to the validated origin value. Include Vary: Origin header when dynamically setting CORS headers.

#### FINDING-140: No X-Content-Type-Options: nosniff Header Set on HTTP Responses

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-430 |
| ASVS Sections | 3.4.4 |
| Files | v3/server/main.py (Application-wide), v3/server/pages.py (Application-wide) |
| Source Reports | 3.4.4.md |
| Related Findings | | **Description:**

All HTTP responses lack the 'X-Content-Type-Options: nosniff' header field. Client requests to endpoints such as `/static/<path:filename>` and `/docs/<iid>/<docname>` return content without this header. If a document with ambiguous content type is served (e.g., an uploaded file mistyped as `text/plain` but containing HTML/JavaScript), the browser's MIME sniffing could interpret it as executable content. This can lead to XSS via uploaded documents and weakens Cross-Origin Read Blocking (CORB) protection. This is particularly relevant for the `/docs/<iid>/<docname>` endpoint which serves user-referenced documents.

**Remediation:**

Implement a global after_request handler that sets the X-Content-Type-Options header on all responses:

```python
@app.after_request
async def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response
```

---

#### FINDING-141: No Referrer-Policy Header Set on HTTP Responses

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-200 |
| ASVS Sections | 3.4.5 |
| Files | v3/server/main.py (Application-wide), v3/server/pages.py (Application-wide) |
| Source Reports | 3.4.5.md |
| Related Findings | | **Description:**

The application does not set a Referrer-Policy HTTP response header on any responses. When users navigate from pages containing election IDs (e.g., /vote-on/&lt;eid&gt;) to external links, the browser sends the full URL including sensitive election IDs in the Referer header to third-party services. This leads to leakage of election IDs (10-char hex), internal URL structure (paths like /manage/&lt;eid&gt;, /vote-on/&lt;eid&gt;), and potentially sensitive hostname information for internal deployments.

**Remediation:**

Implement a global after_request handler that sets the Referrer-Policy header on all responses. Use 'strict-origin-when-cross-origin' or 'no-referrer' for maximum protection:

```python
@app.after_request
async def set_security_headers(response):
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response
```

---

#### FINDING-142: Missing Redirect Allowlist and Validation Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-601 |
| ASVS Sections | 3.7.2 |
| Files | v3/server/pages.py (353), v3/server/pages.py (420), v3/server/pages.py (437), v3/server/main.py (37) |
| Source Reports | 3.7.2.md |
| Related Findings | FINDING-143 | **Description:**

While all current redirects in the application are to internal paths, there is no defensive mechanism (allowlist, redirect validator, or middleware) that would prevent future code changes from introducing open redirects. The application lacks a centralized redirect validation control. Additionally, the OAuth flow in main.py hardcodes external redirects to oauth.apache.org, which is acceptable, but the pattern shows that external redirects are architecturally possible without validation. No user-controllable input flows into redirect targets in the current code. However, there is no safe_redirect() utility or allowlist that would catch regressions. The domain context explicitly mentions that 'any redirects to external domains show user warnings' — this control is absent.

**Remediation:**

Implement a safe_redirect() utility with an allowlist of external domains:

```python
ALLOWED_EXTERNAL_DOMAINS = {'oauth.apache.org'}

def safe_redirect(url, code=303):
    """Only allow redirects to internal paths or allowlisted domains."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        # External URL - check allowlist
        if parsed.netloc not in ALLOWED_EXTERNAL_DOMAINS:
            raise ValueError(f"Redirect to unauthorized domain: {parsed.netloc}")
    return quart.redirect(url, code=code)
```

Replace all quart.redirect() calls with safe_redirect().

---

#### FINDING-143: No User Notification When Redirecting to External OAuth Domain

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-601 |
| ASVS Sections | 3.7.3 |
| Files | v3/server/main.py (37), v3/server/pages.py (Application-wide) |
| Source Reports | 3.7.3.md |
| Related Findings | FINDING-142 | **Description:**

The application does not implement any user notification or interstitial page when redirecting to external domains. While current application redirects are all internal, the OAuth flow redirects users to `oauth.apache.org` without displaying a notification that they are leaving the application. The domain context explicitly requires: 'any redirects to external domains show user warnings.' The OAuth authentication flow (managed by `asfquart.generics`) redirects users to `https://oauth.apache.org/auth?state=%s&redirect_uri=%s` without an interstitial page.

**Remediation:**

Implement an interstitial page that warns users before external redirects. Create a `/leaving` endpoint with template `leaving.ezt` that validates the target URL against an allowlist of external domains (e.g., oauth.apache.org), displays the target domain to the user, and provides options to proceed or cancel. Example implementation: create a `@APP.get('/leaving')` route that accepts a `target` parameter, validates it against `ALLOWED_EXTERNAL_DOMAINS`, and renders a template showing the destination domain with proceed/cancel options.

---

#### FINDING-144: No Browser Security Feature Detection or Warning Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-1104 |
| ASVS Sections | 3.7.5 |
| Files | v3/server/pages.py (Application-wide) |
| Source Reports | 3.7.5.md |
| Related Findings | | **Description:**

The application does not implement any mechanism to detect whether the user's browser supports expected security features (such as CSP, COOP, CORS, SameSite cookies, etc.) and does not warn the user or block access if these features are unavailable. There is no client-side JavaScript feature detection, no User-Agent analysis, and no server-side checks that would identify outdated browsers lacking critical security support. Users accessing the application with outdated browsers (e.g., IE11, older mobile browsers) that lack support for modern security features (CSP Level 3, SameSite cookies, COOP) would not be warned that their session may be vulnerable to attacks that the application's security architecture assumes are mitigated by browser enforcement.

**Remediation:**

Implement client-side JavaScript feature detection to check for required browser security capabilities (crypto.subtle, crossOriginIsolated, etc.) and display warnings to users with unsupported browsers. Add server-side User-Agent analysis using a before_request hook to block known-insecure browsers (MSIE, Trident/, Edge/12, Edge/13). Include browser compatibility check script in base template and utilize existing flash message infrastructure to display warnings. Example implementation: Create static/js/browser-check.js with feature detection logic checking for window.crypto, window.crypto.subtle, and other required features. Add @APP.before_request handler to check User-Agent header and return 400 response for insecure browser patterns.

---

#### FINDING-145: No TLS Version Configuration in Config Template

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Sections | 12.1.1 |
| Files | v3/server/config.yaml.example (6-12) |
| Source Reports | 12.1.1.md |
| Related Findings | | **Description:**

The configuration template provides no guidance or fields for specifying TLS protocol versions. Administrators deploying this application have no documented mechanism to enforce TLS 1.2+ or prefer TLS 1.3. The config.yaml.example only includes certfile and keyfile fields without any TLS protocol version settings.

**Remediation:**

Add TLS version configuration to the example config: server.certfile, server.keyfile, and server.min_tls_version: '1.2' with a comment indicating 'Minimum TLS version (1.2 or 1.3)'.

---

#### FINDING-146: OCSP Stapling Not Configured for TLS Server

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Sections | 12.1.4 |
| Files | v3/server/main.py (75-82), v3/server/config.yaml.example |
| Source Reports | 12.1.4.md |
| Related Findings | | **Description:**

No OCSP stapling is configured for the TLS server. If a server certificate is compromised and revoked, clients will not be efficiently informed of the revocation status. Without OCSP stapling: Clients must perform their own OCSP lookups (slower, privacy-leaking), many clients soft-fail OCSP checks meaning revoked certificates may still be accepted, and the development configuration uses self-signed certificates (where OCSP is not applicable), but production deployments need this.

**Remediation:**

For production deployment with Hypercorn, configure OCSP stapling in the SSL context using ssl.SSLContext with set_ocsp_client_callback. For Hypercorn-based deployment, add ssl configuration to hypercorn.toml with certfile and keyfile, and configure a reverse proxy (nginx/Apache) with OCSP stapling enabled. Implement periodic refresh of the OCSP response.

---

#### FINDING-147: Self-Signed Certificates Used with No Pathway to Publicly Trusted Certificates for External-Facing Services

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Sections | 12.2.2 |
| Files | v3/server/config.yaml.example (25-31), v3/docs/quickstart.md (49-53) |
| Source Reports | 12.2.2.md |
| Related Findings | | **Description:**

The example configuration and documentation exclusively reference self-signed certificates. While the architecture document mentions 'Typical usage is that a proxy sits in front of this server,' there is: 1. No production configuration example with publicly trusted certificates 2. No documentation on deploying with publicly trusted TLS certs 3. No validation that configured certificates are publicly trusted 4. The `certs/` directory structure implies certificate storage alongside code. External-facing clients (voters, administrators) connecting directly to this service would encounter certificate warnings or be vulnerable to MITM attacks if self-signed certificates are used in production.

**Remediation:**

Provide a production configuration example using Let's Encrypt or other CA-signed certificates. Add deployment documentation requiring publicly trusted certificates for production. Consider integrating ACME (Let's Encrypt) certificate provisioning. Example production configuration:
```yaml
server:
    port: 443
    certfile: /etc/letsencrypt/live/voting.example.org/fullchain.pem
    keyfile: /etc/letsencrypt/live/voting.example.org/privkey.pem
```

---

#### FINDING-148: No Visible TLS Certificate Validation for Outbound OAuth Connections

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 12.3.2 |
| Files | v3/server/main.py (44-49) |
| Source Reports | 12.3.2.md |
| Related Findings | | **Description:**

The application makes outbound HTTPS connections to oauth.apache.org for authentication. The actual HTTP client implementation is within asfquart (not provided), and there is no visible code confirming: 1) TLS certificate validation is enabled (not verify=False), 2) Certificate chain is validated against system trust store, 3) Hostname verification is performed. While Python's urllib/requests/httpx default to validating certificates, custom HTTP clients or misconfiguration could disable this.

**Remediation:**

Verify that the asfquart library's HTTP client has certificate validation enabled. Add explicit configuration to enforce certificate verification:
```python
import httpx
async with httpx.AsyncClient(verify=True) as client:
    response = await client.get(oauth_url)
```

---

#### FINDING-149: Self-Signed Certificates for Internal/Development Use with No Trust Management

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 12.3.4 |
| Files | v3/docs/quickstart.md (49-53), v3/server/config.yaml.example (25-31) |
| Source Reports | 12.3.4.md |
| Related Findings | | **Description:**

The system uses self-signed certificates but there is no: 1. Internal CA configuration or documentation 2. Trust store management for consuming services 3. Certificate pinning for internal connections 4. Guidance on which specific self-signed certificates should be trusted by clients/proxies. If the reverse proxy connects to this backend, it would need to trust the self-signed certificate. Without a specific internal CA or pinning configuration, this creates a risk that any self-signed certificate could be accepted. A consuming service (reverse proxy) configured to trust "any" self-signed certificate or to skip validation when connecting to this backend would be vulnerable to MITM attacks on the internal network.

**Remediation:**

Establish an internal CA and document certificate provisioning. Configure the reverse proxy to pin the specific backend certificate or trust only the internal CA. Example nginx proxy configuration:
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

---

#### FINDING-150: Incomplete Documentation of Input Validation Rules for User-Supplied Text Fields

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Sections | 2.1.1 |
| Files | v3/docs/schema.md, v3/server/pages.py |
| Source Reports | 2.1.1.md |
| Related Findings | | **Description:**

The documentation (schema.md) defines structural rules for internal identifiers (eid, iid as 10-char hex, salt as 16 bytes, etc.) but fails to document validation rules for user-supplied input data including: Election title (max length, allowed characters, format), Issue title (max length, allowed characters), Issue description (max length, allowed characters, format), Vote string (votestring) format per vote type (yna: expected values, stv: ranking format), Person email format validation rules (RFC 5322 compliance), Person name (max length, allowed characters), Date inputs (expected format, range constraints), and Authorization group (authz) allowed values/format. Data flow: User form input → server endpoint → database storage → no documented validation specification. Developers implementing or maintaining the application have no reference for what constitutes valid input. This leads to inconsistent validation (some fields validated, others not), making it difficult to verify correctness or identify gaps.

**Remediation:**

Create an input-validation.md document specifying validation rules for all user input fields. Example entries: Election Title - Type: String, Required: Yes, Max length: 200 characters, Allowed: Unicode printable characters no control characters, Validation: Non-empty after trimming whitespace. Vote String (YNA) - Type: String, Required: Yes, Allowed values: yes/no/abstain, Case-insensitive. Vote String (STV) - Type: String, Required: Yes, Format: Comma-separated candidate labels from issue's labelmap, Validation: Each label must exist in issue.kv.labelmap, no duplicates.

---

#### FINDING-151: No Documentation of Temporal Consistency Rules for Election Dates

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 2.1.2 |
| Files | v3/docs/schema.md, v3/server/pages.py |
| Source Reports | 2.1.2.md |
| Related Findings | | **Description:**

While the code enforces state-based restrictions (e.g., can only add issues when editable, can only vote when open), these rules are not documented in the business logic documentation. Missing documentation includes: Adding voters is only valid when election.salt IS NULL (editable state); Adding issues is only valid when election.salt IS NULL; Voting is only valid when election.salt IS NOT NULL AND closed != 1; Tallying is only valid when closed = 1; Issue IID must belong to the election's EID when voting; Voter PID must have a mayvote entry for the issue IID

**Remediation:**

Document the expected temporal relationships: close_at must be after open_at if both are set; open_at should be in the future when the election is editable; neither date can be modified once the election is closed (enforced by trigger)

---

#### FINDING-152: No Documentation of Per-User or Global Business Logic Limits

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 2.1.3 |
| Files | schema.md, TODO.md, create-election.py (67), election.py (169) |
| Source Reports | 2.1.3.md |
| Related Findings | | **Description:**

The application documentation does not define any limits on per-user operations (maximum elections a user can create, maximum issues per election, maximum voters per election/issue, rate limiting on vote submissions, rate limiting on election creation) or global operations (maximum concurrent open elections, maximum total elections in the system, maximum title/description field lengths, maximum number of STV candidates, maximum number of STV seats, timeout for election open/close operations). The create-election.py validates STV seats as positive integer but no upper bound, and election.py has no limits on issue count. Without documented limits, the application is vulnerable to resource exhaustion (creating thousands of issues/elections) and there's no reference for implementing rate limiting or quotas.

**Remediation:**

Create a business limits document specifying: Per-User limits (Max elections created: 50 configurable, Max concurrent open elections owned: 10), Per-Election limits (Max issues: 500, Max eligible voters: 10,000, Max STV candidates per issue: 50, Max STV seats: candidates - 1), Global limits (Election title max length: 200 characters, Issue title max length: 200 characters, Issue description max length: 10,000 characters)

---

#### FINDING-153: Date Validation Checks Format But Not Logical Business Constraints

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1, L2 |
| CWE | |
| ASVS Sections | 2.2.1, 2.3.2 |
| Files | v3/server/pages.py (88-110), v3/server/pages.py (88) |
| Source Reports | 2.2.1.md, 2.3.2.md |
| Related Findings | | **Description:**

The `_set_election_date()` function validates ISO date format parsing but does not enforce business logic constraints. Elections can be set with nonsensical dates including past dates, close dates before open dates, or dates in the far future. This confuses administrators and potentially breaks UI display logic. The validation only checks `datetime.fromisoformat()` success without verifying the date makes logical sense for an election. Data flow: JSON body `{"date": "2020-01-01"}` → `_set_election_date()` → `election.set_close_at(past_date)` — no logical validation. Impact: Confusing/misleading date information displayed to voters. Could be used to manipulate voter behavior (e.g., showing a close date has passed to discourage voting while election is still open).

**Remediation:**

Add business logic validation after format checking: reject dates in the past (compare against `datetime.date.today()`), ensure close_at is after open_at when both are set, and consider adding reasonable range limits (e.g., not more than 5 years in the future). Return HTTP 400 with descriptive error messages for violations. Add logical date validation: Ensure close_at > open_at, validate dates are not in unreasonable past, and check that dates are within reasonable future bounds.

---

#### FINDING-154: Client-Side Required Field Validation Not Replicated Server-Side

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Sections | 2.2.2 |
| Files | v3/server/pages.py, v3/server/templates/manage.ezt (92) |
| Source Reports | 2.2.2.md |
| Related Findings | | **Description:**

The HTML form uses client-side 'required' attribute and JavaScript validation, but the server-side handler does NOT verify the field is non-empty. The server-side handler in do_add_issue_endpoint does not check if form.title is empty or contains only whitespace. This allows bypassing client-side validation by sending a direct HTTP request with empty title and description fields, creating issues with empty titles and violating data quality expectations.

**Remediation:**

Add server-side validation to verify required fields are non-empty. Example:
```python
async def do_add_issue_endpoint(election):
    form = edict(await quart.request.form)
    title = form.get('title', '').strip()
    if not title:
        await flash_danger('Issue title is required.')
        return quart.redirect(f'/manage/{election.eid}', code=303)
```

---

#### FINDING-155: No Validation That STV Vote Rankings Reference Valid Candidates from Issue's Labelmap

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 2.2.3 |
| Files | v3/steve/election.py (231-244) |
| Source Reports | 2.2.3.md |
| Related Findings | | **Description:**

For STV issues, the votestring should contain a ranking of candidates whose labels exist in the issue's kv.labelmap. This combined data consistency (vote references valid candidates from the issue's metadata) is not validated. The add_vote() method stores the votestring without checking that candidate labels match the issue's labelmap, that ranking count is valid, or that there are no duplicate candidates.

**Remediation:**

Validate that each ranked candidate label exists in the issue's kv.labelmap and there are no duplicates. Check that the ranking count does not exceed the number of candidates in the labelmap. Reject votes that reference non-existent candidates or contain duplicates.

---

#### FINDING-156: No Prerequisite Validation Before Election Opening

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Sections | 2.3.1 |
| Files | v3/steve/election.py (70), v3/server/pages.py (431) |
| Source Reports | 2.3.1.md |
| Related Findings | | **Description:**

An election can be opened without any issues or eligible voters by calling `/do-open/<eid>` immediately after creation. The `open()` method does not verify that the election has been properly configured with issues and voters before allowing the state transition. This represents a skipped step in the business flow (configure → validate → open). The election opens successfully but is useless and irreversible, which is logically invalid.

**Remediation:**

Add prerequisite validation in the `open()` method before allowing the state transition. Verify that the election has at least one issue and at least one eligible voter:
```python
issues = self.list_issues()
if not issues:
    raise ValueError('Cannot open election with no issues')
```
and
```python
self.q_voting_persons.perform(self.eid)
voters = self.q_voting_persons.fetchall()
if not voters:
    raise ValueError('Cannot open election with no eligible voters')
```

---

#### FINDING-157: Election Creation Script Has Transaction Code Commented Out

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 2.3.3 |
| Files | v3/server/bin/create-election.py (83-87), v3/server/bin/create-election.py (109-112) |
| Source Reports | 2.3.3.md |
| Related Findings | | **Description:**

The create-election.py script has transaction wrapping code (BEGIN TRANSACTION, COMMIT, ROLLBACK) commented out with a TODO note. If voter addition fails partway through (e.g., PID not found), the election is left with some but not all eligible voters. No rollback occurs, leaving the election in an inconsistent state.

**Remediation:**

Re-enable the transaction wrapping code by uncommenting the BEGIN TRANSACTION at the start of the try block and the COMMIT/ROLLBACK statements in the success and exception paths respectively.

---

#### FINDING-158: Vote Table Allows Unlimited Re-Votes Without Locking or Rate Control

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 2.3.4 |
| Files | v3/steve/election.py (231), v3/queries.yaml (44) |
| Source Reports | 2.3.4.md |
| Related Findings | | **Description:**

Each call to add_vote() performs a pure INSERT into the vote table. There's no UPDATE or UPSERT — every submission creates a new row. No limit on how many rows a single vote_token can accumulate. Each call to add_vote() performs a pure INSERT. Repeatedly POSTing to /do-vote/&lt;eid&gt; with the same ballot adds a new row for each issue. After 1000 submissions, there are 1000 rows per vote_token, consuming storage and making tally queries slower. While re-voting is an intended feature (only the latest vote counts), there's no limit on how many times a voter can re-vote, potentially exhausting storage or degrading tally performance.

**Remediation:**

Consider either an UPDATE pattern (replacing the existing vote) or limiting re-votes per voter per issue. Add rate limiting on the /do-vote/&lt;eid&gt; endpoint. Consider implementing vote garbage collection to periodically remove superseded vote rows to prevent unbounded table growth.

---

#### FINDING-159: Irreversible Election State Changes Require Only Single-User Action

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Sections | 2.3.5 |
| Files | v3/server/pages.py (431), v3/server/pages.py (451) |
| Source Reports | 2.3.5.md |
| Related Findings | | **Description:**

Opening an election triggers irreversible cryptographic operations (salt generation, opened_key computation). Closing an election permanently ends voting. Both actions have significant organizational impact — voters may be disenfranchised by premature closure, or an improperly configured election may be opened without review. A single user (or compromised account) can irreversibly alter election state without oversight. For an organization like the ASF where elections determine governance, this represents a high-value operation that should require multi-party approval.

**Remediation:**

Add approval workflow with separate request and approval endpoints. Example: Add /do-request-open/&lt;eid&gt; to record the request and notify approvers, and /do-approve-open/&lt;eid&gt; to verify approver is different from requester, verify approver has authority, and execute the state change. Ensure the approver is different from the requester and has proper authority.

---

#### FINDING-160: No Rate Limiting on Authentication-Gated Page Views

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 2.4.1 |
| Files | v3/server/pages.py (133), v3/server/pages.py (279), v3/server/pages.py (221) |
| Source Reports | 2.4.1.md |
| Related Findings | | **Description:**

Authentication-gated page views including `/voter`, `/admin`, and vote pages have no rate limiting. Each page view triggers multiple database queries with JOINs across mayvote, issue, election, and person tables. High-frequency requests from an authenticated user could cause denial of service via query overload on the SQLite database. Data flow: Authenticated user → unlimited GET requests → repeated database queries → resource exhaustion.

**Remediation:**

Apply general rate limiting at the application or reverse-proxy level for all authenticated page views.

---

#### FINDING-161: No Minimum Time Enforcement in add_vote() Business Logic

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Sections | 2.4.2 |
| Files | v3/steve/election.py (180-194) |
| Source Reports | 2.4.2.md |
| Related Findings | | **Description:**

The business logic layer's add_vote() function has no concept of vote timing. There is no tracking of when a voter last submitted a vote, no minimum interval enforcement between re-votes, and the vote table lacks a timestamp column that could enable retroactive timing analysis. Combined with the handler-level lack of rate limiting, there is zero defense-in-depth against automated vote submission.

**Remediation:**

Implement vote timing tracking in the add_vote() business logic by checking time since last vote by the same vote_token and raising a VoteTooRapid exception if the vote is submitted within MINIMUM_REVOTE_INTERVAL seconds.

---

#### FINDING-162: Flash messages include unsanitized issue ID from form field names

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-79 |
| ASVS Sections | 1.3.3 |
| Files | v3/server/pages.py (443) |
| Source Reports | 1.3.3.md |
| Related Findings | FINDING-030, FINDING-031, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-126, FINDING-127 | **Description:**

The do_vote_endpoint() function extracts issue ID from form field names using key.split('-', 1)[1] and includes it in flash messages without HTML escaping. Form field names in POST body (attacker-controlled) are processed by splitting on '-' and extracting everything after 'vote-', then passed to flash_danger() message which may be rendered in template as raw HTML. This creates reflected XSS if the flash template renders message content without escaping. Example payload: vote-&lt;img src=x onerror=alert(1)&gt;=yes.

**Remediation:**

Apply html.escape() to all user-controlled data included in flash messages:
```python
import html
await flash_danger(f'Invalid issue ID: {html.escape(iid)}')
```
Consider creating a wrapper function for safe flash messages.

---

#### FINDING-163: Email Infrastructure Exists Without Visible Sanitization

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-93 |
| ASVS Sections | 1.3.11 |
| Files | v3/steve/election.py (335-342) |
| Source Reports | 1.3.11.md |
| Related Findings | | **Description:**

The method `get_voters_for_email()` retrieves voter data (name and email) from the database for email purposes. The `name` field originates from LDAP `cn` attribute and could theoretically contain SMTP header injection characters (`\r\n`) if LDAP data is malformed. When used in email headers (To, From, Subject), these could inject additional headers (BCC, CC) or alter message content. The email-sending code itself is not in the provided files, so sanitization at the send boundary cannot be verified. Data flow: LDAP `cn` field → `pdb.add_person(uid, visname, email)` → database → `get_voters_for_email()` → email system.

**Remediation:**

Implement sanitization at the boundary where email is sent. Add a utility function to remove SMTP header injection characters:

```python
def sanitize_email_header(value: str) -> str:
    """Remove characters that could enable SMTP header injection."""
    return value.replace('\r', '').replace('\n', '').replace('\x00', '')

# When constructing email:
recipient_name = sanitize_email_header(voter.name)
recipient_email = sanitize_email_header(voter.email)
```

---

#### FINDING-164: LDAP Operations Lack Defensive Coding for Future Extension

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 1.3.8 |
| Files | v3/server/bin/asf-load-ldap.py (48) |
| Source Reports | 1.3.8.md |
| Related Findings | | **Description:**

The current LDAP search filter is hardcoded and safe. However, the application stores an 'authz' field in elections (LDAP group names per the domain context), and the code contains multiple '### check authz' placeholders throughout pages.py. When authorization checks are implemented, they will likely need to query LDAP with the authz value. No sanitization framework exists for future LDAP filter construction. Data flow: form.authz → Election.create() → stored in DB → (future) LDAP query → potential injection. Impact: Low currently (hardcoded filter), but when '### check authz' is implemented, LDAP special characters (*, (, ), \, NUL) in group names could enable LDAP injection if not escaped.

**Remediation:**

Implement LDAP filter escaping using ldap.filter.escape_filter_chars() before constructing LDAP filters with user-controlled values. Example:

```python
import ldap.filter

def safe_ldap_filter(group_name):
    """Escape LDAP special characters for filter construction."""
    escaped = ldap.filter.escape_filter_chars(group_name)
    return f'(cn={escaped})'
```

Integrate this as a mandatory step before implementing the '### check authz' functionality.

---

#### FINDING-165: Missing File Handling Documentation for Issue Documents

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 5.1.1 |
| Files | v3/server/pages.py (560-574), v3/docs/schema.md (N/A) |
| Source Reports | 5.1.1.md |
| Related Findings | | **Description:**

The application serves documents from `DOCSDIR/<iid>/` via the `/docs/<iid>/<docname>` endpoint, and issue descriptions can reference documents via `doc:filename` syntax (processed by `rewrite_description`). However, there is no documentation anywhere in the provided codebase that defines: permitted file types for documents associated with issues, expected file extensions, maximum file size (or maximum unpacked size), or how the application handles malicious files detected during download/processing. Without documented policies on accepted file types, extensions, and sizes, developers cannot implement consistent file validation. End users downloading served documents have no assurance that files have been vetted for malware or unsafe content (e.g., polyglot files, malicious macros).

**Remediation:**

Create explicit documentation specifying: permitted file types for issue documents (e.g., PDF (.pdf) - application/pdf, Plain text (.txt) - text/plain, PNG images (.png) - image/png), maximum file size (e.g., individual file: 10 MB, per-issue total: 50 MB), and malicious file handling procedures (e.g., files are scanned with ClamAV on upload, files failing validation are rejected with HTTP 415 and logged, served files include `Content-Disposition: attachment` header, X-Content-Type-Options: nosniff is set on all responses).

---

#### FINDING-166: No compressed file validation against uncompressed size and file count limits

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Sections | 5.2.3 |
| Files | v3/server/pages.py (entire application scope) |
| Source Reports | 5.2.3.md |
| Related Findings | | **Description:**

The application has a document serving mechanism (`/docs/<iid>/<docname>`) but no visible handling or validation of compressed files (zip, gz, docx, odt, etc.). There is no code that: 1. Detects if a served or uploaded file is a compressed archive 2. Checks the maximum uncompressed size before extraction 3. Limits the maximum number of files within an archive 4. Prevents zip bomb attacks. Since the upload mechanism is not shown in the provided code, it is impossible to verify that compressed file protections exist upstream. If compressed files (e.g., zip bombs) are placed in `DOCSDIR` through any mechanism, they could be served to users or potentially processed server-side without decompression limits, leading to denial of service.

**Remediation:**

Implement compressed file validation that checks: 1) if file is a compressed archive using zipfile.is_zipfile() or similar, 2) total number of files in archive against MAX_FILES_IN_ARCHIVE (e.g., 100), 3) total uncompressed size against MAX_UNCOMPRESSED_SIZE (e.g., 100 MB), 4) compression ratio to detect zip bombs (e.g., reject if ratio > 100). Reject files failing any check with appropriate error messages.

---

#### FINDING-167: No per-user file quota or maximum file count enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Sections | 5.2.4 |
| Files | v3/server/pages.py (entire application scope), v3/schema.sql (database schema) |
| Source Reports | 5.2.4.md |
| Related Findings | | **Description:**

There is no per-user file quota or maximum file count enforcement anywhere in the provided code or database schema. The database schema (v3/schema.sql) contains tables for elections, issues, persons, mayvotes, and votes — but nothing tracking file storage per user. Documents are served from DOCSDIR/&lt;iid&gt;/ but there is no: 1. Database table or column tracking per-user storage consumption 2. Check limiting the total number of files a user can upload 3. Check limiting total storage bytes per user 4. Any quota enforcement mechanism. A single user (or compromised account) could fill available storage by uploading an unlimited number of files or excessively large files, causing denial of service for all users.

**Remediation:**

Add file tracking table to database schema with columns for file_id, pid, iid, filename, file_size, and uploaded_at. Implement quota checking function that validates against MAX_FILES_PER_USER (e.g., 50) and MAX_STORAGE_PER_USER (e.g., 500 MB) before accepting file uploads. Query user's current file count and total storage, rejecting uploads that would exceed limits.

---

#### FINDING-168: No symlink detection or prevention in compressed file handling

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Sections | 5.2.5 |
| Files | v3/server/pages.py (entire application scope) |
| Source Reports | 5.2.5.md |
| Related Findings | | **Description:**

There is no handling of compressed files visible in the provided code, and consequently no symlink detection or prevention. If documents placed in DOCSDIR originated from extracted archives, symbolic links within those archives could allow access to sensitive files outside the intended directory. While send_from_directory provides some protection against traversal, symlinks resolved at the filesystem level could bypass this. If an attacker can place a compressed file containing symlinks (e.g., pointing to /etc/passwd or the database file) and it gets extracted into DOCSDIR, the serve_doc endpoint could serve sensitive system files to authorized users.

**Remediation:**

Implement validation functions to detect and reject symlinks in archives before extraction. Use validate_no_symlinks() to check archive contents for symlink attributes. Implement safe_extract() to prevent both symlinks and path traversal during extraction. Add symlink check in serve_doc endpoint using filepath.is_symlink() and abort with 403 if detected. Consider mounting DOCSDIR filesystem with nosymfollow option to prevent symlink resolution at OS level.

---

#### FINDING-169: Missing application-level validation for user-supplied docname parameter in serve_doc()

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS Sections | 5.3.2 |
| Files | v3/server/pages.py (560-574) |
| Source Reports | 5.3.2.md |
| Related Findings | FINDING-279 | **Description:**

The serve_doc() function uses the user-supplied docname URL parameter directly in send_from_directory() without application-level validation. The developer explicitly acknowledged this gap with the comment '### verify the propriety of DOCNAME.' While Quart's send_from_directory() internally uses safe_join() to prevent path traversal, there is no defense-in-depth validation at the application layer. Relying solely on framework internals without application-level validation creates risk if: 1) The framework is upgraded and safe_join behavior changes, 2) A bypass is discovered in safe_join, 3) The code is refactored to use a different file-serving mechanism.

**Remediation:**

Add an explicit allowlist regex (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) to validate docname and reject requests with invalid filenames including path traversal sequences. Validate before passing to send_from_directory() and abort with 400 for invalid filenames.

#### FINDING-170: Missing filename validation and Content-Disposition header in document download endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 5.4.1, 5.4.2 |
| **Files** | v3/server/pages.py:560-574 |
| **Source Reports** | 5.4.1.md, 5.4.2.md |
| **Related** | - | **Description:**

The serve_doc() endpoint accepts a user-submitted filename via the docname URL parameter and uses it directly to serve files. There is no validation or sanitization of this filename, and no explicit Content-Disposition header is set in the response to override the user-controlled filename. Without explicit filename validation: 1. The Content-Type of the response is derived from the user-controlled filename extension, which could cause browser behavior differences. 2. If the response includes a Content-Disposition header, the user-controlled filename could contain injection characters. 3. The lack of explicit Content-Disposition means the browser uses the URL's filename segment for Save As operations.

**Remediation:**

Implement filename validation using an allowlist regex (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) and reject requests with invalid filenames. Sanitize the filename using secure_filename() from werkzeug.utils. Serve files with explicit Content-Disposition header using as_attachment=True in send_from_directory(). Add X-Content-Type-Options: nosniff header for defense-in-depth. Implement file extension allowlist to only serve known-safe extensions (.pdf, .txt, .md, etc.).

---

#### FINDING-171: No Antivirus Scanning for Documents Served to Users

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 5.4.3 |
| **Files** | v3/server/pages.py:598-614, v3/server/pages.py:50-57 |
| **Source Reports** | 5.4.3.md |
| **Related** | - | **Description:**

The application serves per-issue documents directly to authenticated users without any antivirus or malware scanning. Files are served from the DOCSDIR/{iid}/ directory structure and referenced in issue descriptions using the doc:filename syntax, which is converted into clickable download links. Files placed in the docs directory (whether by admin CLI scripts, manual upload, or an upload mechanism not shown in these files) are served directly to authenticated users without malware scanning. A malicious document (e.g., a PDF with embedded exploit, a malware-laden Office document, or an HTML file with scripts) placed in the docs directory would be served to all voters authorized for that issue.

**Remediation:**

Implement antivirus scanning using ClamAV at serving time or at ingestion time. For serving time, integrate clamdscan to scan files before delivery with fail-closed behavior if scanner is unavailable. Add file extension whitelisting to restrict allowed document types (e.g., .pdf, .txt, .md, .html). Implement periodic background scanning of the docs directory to catch files that may have been clean at upload but later identified as malicious. Add a quarantine mechanism for suspicious files and log all scan results for security monitoring.

---

#### FINDING-172: No evidence of header trust boundary enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 4.1.3 |
| **Files** | v3/server/api.py:1-21 |
| **Source Reports** | 4.1.3.md |
| **Related** | - | **Description:**

The file imports and exposes `APP` from `asfquart` without any visible configuration to strip or reject user-supplied intermediary headers (e.g., `X-Forwarded-For`, `X-Real-IP`, `X-User-ID`). While the `asfquart` framework may handle this internally, there is no visible control in the auditable codebase to confirm that end-users cannot inject headers that would be trusted as if set by intermediaries. Data flow: External HTTP request → `X-Forwarded-For` header → `APP` request handling → potential trust of user-supplied value as intermediary-set value. If `asfquart` or downstream handlers trust these headers without validation, an attacker could spoof their IP address or identity for access control bypass or audit log pollution.

**Remediation:**

Configure the application or its framework to explicitly define trusted proxy sources and strip/ignore intermediary headers from untrusted origins. Example: Configure trusted proxies using APP.config['FORWARDED_ALLOW_IPS'] = '127.0.0.1,10.0.0.0/8' or use middleware to strip untrusted headers. This finding is classified as MEDIUM rather than CRITICAL because the control may exist in `asfquart` but cannot be verified from the provided source.

---

#### FINDING-173: No visible HTTP message boundary validation or Transfer-Encoding/Content-Length conflict handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 4.2.1 |
| **Files** | v3/server/api.py:1-21 |
| **Source Reports** | 4.2.1.md |
| **Related** | - | **Description:**

The file provides no configuration related to HTTP/1.1 request smuggling prevention. There is no visible rejection of requests with both Transfer-Encoding and Content-Length headers, HTTP/2 DATA frame length validation against Content-Length, or configuration ensuring the application server and reverse proxy agree on message boundaries. If the reverse proxy and Quart/Hypercorn disagree on how to parse the request boundary (e.g., one uses Content-Length while the other uses Transfer-Encoding), an attacker could smuggle a second request that bypasses authentication or access controls.

**Remediation:**

1. Configure the reverse proxy to normalize requests (reject ambiguous requests with both TE and CL). 2. Configure the ASGI server (Hypercorn) to reject malformed requests. 3. Add application-level validation using @APP.before_request to reject requests with both Transfer-Encoding and Content-Length headers by aborting with 400 status and 'Ambiguous message framing' message.

---

#### FINDING-174: Mixed logging mechanisms (print vs logger) create undocumented output channels

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.1.1, 16.2.3 |
| **Files** | v3/server/pages.py:427, v3/server/pages.py:449, v3/server/bin/tally.py:127, v3/server/bin/tally.py:152, v3/server/bin/tally.py:157 |
| **Source Reports** | 16.1.1.md, 16.2.3.md |
| **Related** | - | **Description:**

Multiple code paths use print() statements alongside the formal _LOGGER system. These bypass any logging framework configuration (formatters, handlers, filters, destinations) and output to stdout directly, creating undocumented log channels that cannot be inventoried. Security-relevant information (form submissions, tamper detection alerts) exits through channels not covered by any logging policy, potentially being lost or logged without proper access controls.

**Remediation:**

Replace print statements with proper logging. For form data, use _LOGGER.debug() with structured identifiers. For security events like tamper detection, use _LOGGER.critical() with clear event descriptions. Example: _LOGGER.critical(f'TAMPER DETECTED: Election[E:{election_id}] integrity check failed')

---

#### FINDING-175: Authorization failure events lack structured metadata

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.1 |
| **Files** | v3/server/pages.py:199-201 |
| **Source Reports** | 16.2.1.md |
| **Related** | - | **Description:**

When a user attempts to access an election they are not authorized to vote in, the application returns a 404 but does not log this authorization failure. This is a security event (potential enumeration or unauthorized access attempt) that should include WHO tried, WHAT they tried to access, WHEN, and the outcome. Authorization failures are invisible to security monitoring. Repeated attempts to access unauthorized elections cannot be detected or alerted upon.

**Remediation:**

Add _LOGGER.warning() call when authorization check fails in vote_on_page, capturing user=U:{result.uid}, resource=election[E:{election.eid}], action=vote_access, and reason=not_in_mayvote before returning 404.

---

#### FINDING-176: Election state change operations in election.py lack logging

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.1 |
| **Files** | v3/steve/election.py:110-115, v3/steve/election.py:117-137 |
| **Source Reports** | 16.2.1.md |
| **Related** | - | **Description:**

Critical election lifecycle operations (close(), add_salts(), delete()) do not emit log entries at the library level. While pages.py logs the close event when invoked via the web interface, direct library usage (e.g., from tally.py or future integration paths) leaves no trace. If the library is used outside the web context, security-critical state changes occur without audit trails.

**Remediation:**

Add _LOGGER.info() calls to close(), add_salts(), and delete() methods in election.py to log state changes at the library level, including Election[E:{self.eid}] identifier and the action performed.

---

#### FINDING-177: No logging format configuration enforces UTC timestamps

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.2 |
| **Files** | v3/server/bin/tally.py:165, v3/server/pages.py:entire file |
| **Source Reports** | 16.2.2.md |
| **Related** | - | **Description:**

The application does not configure a logging format that ensures: 1. Timestamps are present in every log entry 2. Timestamps use UTC (or include explicit timezone offset) 3. Time sources are synchronized across components. The logging.basicConfig(level=logging.INFO) in tally.py uses the default format which does NOT include a timestamp at all (default format is %(levelname)s:%(name)s:%(message)s). The web server's logging configuration is not shown but relies on framework defaults which typically use local time without timezone. Additionally, pages.py uses datetime.datetime.now() (line 571) and datetime.datetime.fromtimestamp() (line 86) without timezone awareness, suggesting a general lack of UTC discipline.

**Remediation:**

Configure UTC timestamps globally using logging.basicConfig with format='%(asctime)s %(levelname)s %(name)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S.%fZ', and set logging.Formatter.converter = time.gmtime to force UTC. Alternatively, use a JSON formatter for structured logging with ISO 8601 timestamps that include timezone information.

---

#### FINDING-178: No structured logging format enables machine parsing and correlation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.4 |
| **Files** | v3/server/pages.py:all logging calls, v3/steve/election.py:all logging calls |
| **Source Reports** | 16.2.4.md |
| **Related** | - | **Description:**

The application uses unstructured f-string log messages that vary in format between modules. While the `[U:xxx]`, `[E:xxx]`, `[I:xxx]` convention is helpful, the overall format is not machine-parseable without custom regex patterns. Issues include: 1. No common structured format (JSON, CEF, CLF) is used, 2. Inconsistent field ordering: Some messages start with "User[U:]", others with "Created", 3. No correlation ID: No request ID or trace ID to correlate multiple log entries from the same request, 4. Mixed separators: Uses semicolons, commas, and natural language inconsistently, 5. No event type field: Cannot filter by event category without text matching. Log processors (ELK, Splunk, CloudWatch) would require custom parsing rules for each message variant. Automated alerting on patterns like "3 failed access attempts in 5 minutes" becomes difficult without structured fields.

**Remediation:**

Implement structured logging using structlog or similar library. Example: import structlog; logger = structlog.get_logger(); logger.info("election.vote_cast", actor_uid=result.uid, election_id=election.eid, issue_id=iid, event_type="security", action="vote_cast"). Output should be JSON format with consistent fields.

---

#### FINDING-179: Tally output includes full voter identity list without classification controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.5 |
| **Files** | v3/server/bin/tally.py:129-132 |
| **Source Reports** | 16.2.5.md |
| **Related** | - | **Description:**

The JSON output format includes a complete sorted list of voter PIDs (`voters=sorted(all_voters)`). This reveals which specific individuals voted on each issue, which could be considered sensitive in some election contexts (e.g., someone's participation/non-participation in a controversial vote). The voter list is output without any masking or classification-based control. Voter participation metadata is output in cleartext. While knowing WHO voted doesn't reveal HOW they voted (votes are shuffled), participation patterns could be sensitive. The sorted output also enables easy diff-ing between multiple tallies to identify new voters.

**Remediation:**

Option 1: Hash voter identities in output using hashlib.sha256(v.encode()).hexdigest()[:12]. Option 2: Only include voter count, not identities, with voters list available only with --verbose flag.

---

#### FINDING-180: Exception details potentially leak sensitive information into error logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.5 |
| **Files** | v3/server/pages.py:356 |
| **Source Reports** | 16.2.5.md |
| **Related** | - | **Description:**

The catch-all `Exception` handler logs the full exception message (`{e}`). Depending on the failure mode, this could include: cryptographic operation details (key derivation failures, Fernet errors), database state information (SQLite error messages with table/column names), internal path information, or partial sensitive data that caused the error. The error message is not sanitized before logging. Exception messages could leak internal implementation details into logs. If logs are accessible to a broader audience than the application code, this creates an information disclosure risk.

**Remediation:**

Log only exception type name in standard logs: _LOGGER.error(f'Vote submission failed for user[U:{result.uid}] on issue[I:{iid}] in election[E:{election.eid}]: {type(e).__name__}', exc_info=True). Full traceback only at configured log level.

---

#### FINDING-181: No Authentication Metadata Captured in Existing Logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.3.1 |
| **Files** | v3/server/pages.py:106-108, v3/server/pages.py:404-407, v3/server/pages.py:440-443 |
| **Source Reports** | 16.3.1.md |
| **Related** | - | **Description:**

The existing log messages record user actions but do not include authentication metadata (authentication type, factors used, session age, IP address). Even where actions are logged, there's insufficient metadata to correlate events with authentication context (OAuth provider, MFA status, source IP).

**Remediation:**

Include authentication metadata in log messages: auth_method=oauth, ip address, session_id hash, and other relevant authentication context for all user actions.

---

#### FINDING-182: No Authorization Logging in Vote Submission

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 16.3.2 |
| **Files** | v3/server/pages.py:380-422 |
| **Source Reports** | 16.3.2.md |
| **Related** | - | **Description:**

The vote endpoint has a comment indicating incomplete authorization implementation and does not log authorization decisions. While add_vote in election.py checks mayvote internally, no explicit authorization decision is logged, preventing audit trail of who attempted to vote and whether they were authorized.

**Remediation:**

Implement explicit authorization check for vote submission and log both successful and failed authorization attempts. Include user ID, election ID, timestamp, and IP address in authorization logs.

---

#### FINDING-183: Election State Assertion Failures Not Logged

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.3.3 |
| **Files** | v3/steve/election.py:multiple |
| **Source Reports** | 16.3.3.md |
| **Related** | - | **Description:**

State validation uses Python assert statements which raise AssertionError without logging. Attempts to bypass election state controls (e.g., voting in a closed election, modifying an open election) produce no audit trail. These are business logic bypass attempts that should be logged per ASVS 16.3.3. Assertions are also disabled when Python runs with optimization (-O flag), making this a potential security bypass.

**Remediation:**

Replace assertions with explicit checks and logging: if not self.is_open(): _LOGGER.warning('BUSINESS_LOGIC_BYPASS: attempt to vote on non-open election, election=%s, state=%s, pid=%s, iid=%s', self.eid, self.get_state(), pid, iid); raise ElectionBadState(...)

---

#### FINDING-184: No Logging of Anti-Automation or Rate Limiting Events

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.3.3 |
| **Files** | v3/server/pages.py:entire file |
| **Source Reports** | 16.3.3.md |
| **Related** | - | **Description:**

There is no evidence of rate limiting, anti-automation controls, or logging of potential automated abuse: No request rate tracking, No logging of rapid successive requests, No CAPTCHA or similar controls, No detection of automated voting attempts. Automated attacks against authentication, voting, or election management endpoints cannot be detected through application logs.

**Remediation:**

Implement rate-limit event logging—Implement request rate tracking and log anomalous patterns. Add anti-automation detection and logging mechanisms for authentication, voting, and election management endpoints.

---

#### FINDING-185: Assertion Errors Not Caught or Logged at Application Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.3.4 |
| **Files** | v3/steve/election.py:48, v3/steve/election.py:69, v3/steve/election.py:115, v3/steve/election.py:178, v3/steve/election.py:197, v3/steve/election.py:211, v3/steve/election.py:238 |
| **Source Reports** | 16.3.4.md |
| **Related** | - | **Description:**

Multiple critical operations use assert for state validation. If assertions fail (indicating an unexpected state or security control failure), no structured logging occurs. Security control failures (election in wrong state) produce unstructured stack traces rather than structured security event logs. When running with -O (optimized mode), these checks are completely disabled.

**Remediation:**

Replace assert statements with proper conditional checks that log security events before raising exceptions. Use explicit if statements with structured logging to capture state validation failures as security events.

---

#### FINDING-186: Database Connectivity Failures Not Explicitly Logged

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.3.4 |
| **Files** | v3/steve/election.py:28 |
| **Source Reports** | 16.3.4.md |
| **Related** | - | **Description:**

Database connection failures would produce SQLite exceptions without application-level logging. Backend infrastructure failures (database unavailability, file system issues) would not be captured as structured security events.

**Remediation:**

Wrap database connection attempts in try-except blocks with explicit logging of connection failures, including database path and error details, before re-raising or handling the exception.

---

#### FINDING-187: Debug Print Statements with Unsanitized User Input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Sections** | 16.4.1 |
| **Files** | v3/server/pages.py:500, v3/server/pages.py:523 |
| **Source Reports** | 16.4.1.md |
| **Related** | FINDING-060 | **Description:**

Debug `print()` statements output raw form data including user-controlled input. If stdout is captured to log files (common in containerized deployments), unsanitized user input flows into logs, enabling log injection attacks through the stdout capture mechanism.

**Remediation:**

Replace debug print() statements with proper logging using _LOGGER. Apply sanitization to any user-controlled data before logging. If debug output is necessary, use _LOGGER.debug() with sanitized values instead of print() statements.

---

#### FINDING-188: No Log Protection Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.4.2 |
| **Files** | v3/server/bin/tally.py:163 |
| **Source Reports** | 16.4.2.md |
| **Related** | - | **Description:**

The logging configuration uses `basicConfig` with no file protection, access control, or integrity measures. Logs are written to stdout/stderr with no write-once/append-only guarantees, file permissions configuration, log rotation with integrity verification, transmission to a protected centralized system, or digital signatures or checksums on log entries.

**Remediation:**

Configure structured logging with proper handlers for centralized log collection. Implement log integrity protection using append-only log files or use a log shipping agent with integrity verification. Configure appropriate file permissions for log files and ensure logs are transmitted to a protected centralized system.

---

#### FINDING-189: No Centralized Logging Configuration in Web Application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.4.2 |
| **Files** | v3/server/pages.py: |
| **Source Reports** | 16.4.2.md |
| **Related** | - | **Description:**

The web application uses Python's `logging` module but there is no evidence of log forwarding to a centralized system, log file protection configuration, separate log storage from application server, or log integrity verification. While the infrastructure may provide these protections (e.g., container logging drivers, syslog forwarding), the application code shows no explicit configuration ensuring log protection.

**Remediation:**

Configure centralized logging with log forwarding to a protected system. Implement log file protection configuration including appropriate file permissions, separate log storage from the application server, and log integrity verification mechanisms.

---

#### FINDING-190: HTTP 400 responses expose specific validation failure reasons

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.5.1 |
| **Files** | v3/server/pages.py:103-110 |
| **Source Reports** | 16.5.1.md |
| **Related** | - | **Description:**

The `quart.abort()` calls include descriptive messages ('Missing date', 'Invalid date format', 'Invalid field') that are passed to the default Quart error handler, which may render them in the HTTP response body. While these specific messages are not highly sensitive, the pattern establishes a practice that could lead to information disclosure if applied to more sensitive contexts.

**Remediation:**

Return generic validation error: `quart.abort(400)` and let global error handler provide generic message

---

#### FINDING-191: PersonDB failures not handled in admin endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.5.2 |
| **Files** | v3/server/pages.py:286-287 |
| **Source Reports** | 16.5.2.md |
| **Related** | - | **Description:**

While PersonNotFound is handled gracefully, the PersonDB.open() call itself has no error handling for database connectivity failures. If the database is unavailable, the error propagates unhandled. The admin page becomes completely unavailable if database has connectivity issues, with no graceful degradation or retry.

**Remediation:**

Wrap PersonDB.open() and subsequent operations in a try/except block to handle sqlite3.OperationalError and OSError. Log the error, flash a user-friendly message, and redirect to a safe page.

---

#### FINDING-192: CLI tally script has no top-level exception handler

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 16.5.4 |
| **Files** | v3/server/bin/tally.py:166-180 |
| **Source Reports** | 16.5.4.md |
| **Related** | - | **Description:**

The main() function and entry point have no top-level try/except block. While the function handles is_tampered() and calls sys.exit(1), unexpected exceptions (database corruption, permission denied, memory errors) will print full stack traces to stderr and exit ungracefully. Within tally_election, the raise after catching an exception intentionally fails hard but doesn't ensure the error is logged through the logging system (only print()). Full stack traces with file paths and variable values printed to stderr; error details may be lost if not captured by a process manager; no structured error logging for operational monitoring.

**Remediation:**

Add top-level exception handler to CLI entry point wrapping main() call with try/except to catch KeyboardInterrupt and Exception, logging critical errors before exiting with appropriate exit codes.

---

#### FINDING-193: Incomplete documentation of application communication needs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.1 |
| **Files** | v3/ARCHITECTURE.md:, v3/docs/schema.md:, v3/server/config.yaml.example:, v3/server/main.py:36-40, v3/server/bin/mail-voters.py:67-73, v3/steve/election.py:37, v3/server/pages.py:560-574 |
| **Source Reports** | 13.1.1.md |
| **Related** | - | **Description:**

The application communicates with multiple external services, but there is no comprehensive communication inventory document. The following communication channels were identified through code analysis but are not formally documented in a single reference: 1) ASF OAuth Service (external authentication), 2) SMTP/Email Service (voter notification), 3) SQLite Database (local persistence), 4) LDAP Service (authorization, referenced but not implemented), 5) End-user-provided document filenames (potential SSRF vector). Without comprehensive communication documentation, security teams cannot perform complete threat modeling, firewall rule validation, or network segmentation reviews. Undocumented external dependencies may introduce unmonitored attack surfaces.

**Remediation:**

Create a dedicated COMMUNICATIONS.md or equivalent document that inventories: All external service endpoints (OAuth, SMTP, LDAP), Protocol, port, and authentication method for each, Direction of communication (inbound/outbound), User-controllable endpoints or file references, Network security requirements (TLS versions, cipher suites)

---

#### FINDING-194: No documentation of concurrent connection limits or fallback mechanisms for any service

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.2 |
| **Files** | v3/ARCHITECTURE.md:, v3/steve/election.py:35-37, v3/steve/election.py:39-44, v3/server/pages.py:165-186, v3/server/pages.py:297 |
| **Source Reports** | 13.1.2.md |
| **Related** | - | **Description:**

The application interacts with multiple services (SQLite, OAuth, SMTP) but there is no documentation defining maximum concurrent connections, connection pool limits, or behavior when those limits are reached. Database connections are opened per-operation without pooling. Each Election() instantiation opens a new database connection. Web handlers create new Election/PersonDB instances per request without connection management. ARCHITECTURE.md mentions connections without limits. No documentation exists for maximum concurrent SQLite connections, OAuth service connection timeouts/limits, SMTP connection pooling or rate limits, or fallback behavior if any service becomes unavailable. Under high load or during service outages, the application may exhaust file descriptors, memory, or other resources. Without defined limits and fallback mechanisms, a denial-of-service condition could result from legitimate traffic spikes or upstream service degradation.

**Remediation:**

Document for each service: connection pool size or maximum concurrent connections, queue/backpressure behavior when limits are reached, circuit breaker or fallback patterns. Example configuration: database: max_connections: 10, connection_timeout_ms: 5000, behavior_at_limit: queue; oauth: max_concurrent_requests: 5, timeout_ms: 10000, fallback: deny_login; smtp: max_concurrent_sends: 3, retry_on_failure: false

---

#### FINDING-195: No documented resource-management strategies, timeout settings, or retry logic for external services

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.3 |
| **Files** | v3/ARCHITECTURE.md:, v3/steve/election.py:, v3/server/main.py:37-40, v3/server/bin/mail-voters.py:67-73, v3/server/pages.py:165-186 |
| **Source Reports** | 13.1.3.md |
| **Related** | - | **Description:**

The application documentation does not define resource-management strategies for any external system. Code analysis reveals the following gaps: 1. No timeout settings for database operations - SQLite's default timeout for busy/locked databases is 5 seconds, but this is never explicitly configured or documented. 2. No resource-release procedures documented - Database connections are released in some cases but not others. Normal request-serving paths (via load_election decorator) never explicitly close connections. 3. Email sending has no retry or timeout configuration - asfpy.messaging.mail has no timeout, no retry configuration, no error handling per recipient. 4. OAuth callback has no documented timeout - No timeout or failure handling documented for OAuth callback URL. 5. No retry limits, delays, or back-off algorithms documented anywhere. Without defined resource management strategies: database locks could cause indefinite hangs under concurrent access, failed email sends could silently drop voter notifications, OAuth service outages could leave requests hanging, and resource leaks from unclosed connections could degrade availability over time.

**Remediation:**

Create a resource management section in documentation covering: SQLite Database - Timeout: 30 seconds (sqlite3 timeout parameter), Release: Connections closed after each request via context manager, Failure handling: Return 503 if database is locked beyond timeout, Retry: No retries for synchronous operations. OAuth (ASF OAuth) - Timeout: 10 seconds for token exchange, Retry: None (redirect user to retry login), Failure handling: Display error page with retry option. SMTP (Email) - Timeout: 30 seconds per message, Retry: Up to 2 retries with 5-second delay, Back-off: Not applicable (batch script), Failure handling: Log error, continue to next recipient.

---

#### FINDING-196: No secrets rotation schedule or lifecycle management documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.4 |
| **Files** | v3/docs/schema.md:, v3/steve/crypto.py:27-29, 32-41, v3/server/config.yaml.example:, v3/server/pages.py:83 |
| **Source Reports** | 13.1.4.md |
| **Related** | - | **Description:**

While the application documents what secrets exist and how they are generated, there is no documentation defining a rotation schedule or lifecycle management for any secret. Secrets identified include: (1) Election salts (16 bytes) generated once at election opening, never rotated; (2) Mayvote salts (16 bytes) generated once at election opening, never rotated; (3) Opened keys (32 bytes) derived once for tamper detection; (4) TLS certificate private keys with path documented but no rotation; (5) Session secrets managed by asfquart, not documented; (6) OAuth client credentials referenced but not documented; (7) CSRF tokens currently placeholder ('placeholder'), not a real secret. Documentation exists in schema.md for salt purposes, generation method, key derivation (Argon2), and encryption algorithm (Fernet, planned migration to XChaCha20-Poly1305), but missing rotation schedules for TLS certificates, rotation procedures if election salts are compromised, session secret rotation policy, OAuth credential rotation, impact assessment if secrets are compromised, and classification of secrets by criticality. Without a defined rotation schedule, compromised secrets may remain in use indefinitely. The placeholder CSRF token represents a complete absence of this security control, which could allow cross-site request forgery attacks.

**Remediation:**

Create a secrets management document with the following structure: Secrets Inventory and Rotation Schedule table containing columns for Secret, Criticality, Rotation Schedule, and Rotation Procedure. Include entries for: TLS private key (Critical, Annual or on compromise, Re-issue certificate/deploy/restart); Session signing key (High, Monthly, Update config/restart server); OAuth client secret (High, Annual, Coordinate with ASF OAuth team); Election salts (Medium, N/A single-use per election lifecycle, Cannot rotate once election opened); CSRF tokens (High, Per-session, Automatically generated per session). Add Compromise Response section detailing: If TLS key compromised - Revoke certificate immediately and re-issue; If session key compromised - Rotate key and invalidate all sessions; If election salt compromised - Election integrity may be violated, re-run if possible.

---

#### FINDING-197: All application components use identical full-privilege database access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.2.2 |
| **Files** | v3/steve/election.py:35-37, v3/steve/persondb.py:25-26, v3/server/bin/create-election.py:31, v3/server/bin/mail-voters.py:28, v3/server/pages.py:40 |
| **Source Reports** | 13.2.2.md |
| **Related** | - | **Description:**

All application modules — web handlers, business logic, command-line tools — access the SQLite database with the same full read/write permissions. There is no privilege separation. Web request handlers, election model, PersonDB, and CLI tools all have full access. Specific concerns: (1) The mail-voters.py script only needs READ access to election metadata and voter emails, but has full write access to the database. (2) The voter-facing endpoints (e.g., /vote-on/&lt;eid&gt;) can technically invoke any database operation (create elections, delete data) since the same Election class is used. (3) No OS-level service account separation between the web server and CLI tools. If any component is compromised (e.g., through a web vulnerability), the attacker gains full database access including ability to modify election results, delete elections, or alter voter records. The mail-voters.py script could be leveraged to modify data if compromised.

**Remediation:**

1. For SQLite: Implement application-level privilege separation by using different database wrapper classes with restricted query sets (e.g., VoterDB with read-only access and ALLOWED_QUERIES). 2. For CLI tools, use read-only database connections where write access is not needed (e.g., mail-voters.py should use sqlite3.connect with mode=ro). 3. Document the principle of least privilege for each component and its required access level.

---

#### FINDING-198: No allowlist of permitted external resources defined in application configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.2.4 |
| **Files** | v3/server/config.yaml.example:entire file scope |
| **Source Reports** | 13.2.4.md |
| **Related** | - | **Description:**

The configuration schema defines server listening parameters and database location but contains no allowlist section defining permitted OAuth/authentication endpoints (ASF OAuth server), permitted LDAP server addresses, permitted external API endpoints, or blocked internal network ranges (SSRF prevention). The domain context confirms the application communicates with external services (ASF OAuth for authentication, LDAP for authorization), but no configuration mechanism restricts which external systems the application may contact. Without an application-layer allowlist, if any code path allows user-influenced URLs (e.g., OAuth redirect handling, webhook callbacks), there is no defense-in-depth against SSRF or unauthorized outbound communication.

**Remediation:**

Add an explicit allowlist section to the configuration: yaml # Permitted external communication targets allowed_backends: oauth: url: "https://oauth.apache.org" # Only this specific endpoint is permitted ldap: host: "ldaps://ldap.apache.org" port: 636 # No other outbound connections permitted # Network-level restrictions denied_networks: - "169.254.0.0/16" # Link-local - "10.0.0.0/8" # Private - "172.16.0.0/12" # Private - "192.168.0.0/16" # Private - "127.0.0.0/8" # Loopback

---

#### FINDING-199: Web server configuration lacks allowlist for permitted outbound request targets

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.2.5 |
| **Files** | v3/server/config.yaml.example:entire file scope |
| **Source Reports** | 13.2.5.md |
| **Related** | - | **Description:**

The server configuration (config.yaml.example) only specifies listening parameters (port, TLS certificates) and database location. There is no configuration for allowed outbound request destinations at the web server level, file access restrictions beyond the database path, permitted data load sources, or egress filtering rules. The comment 'Typical usage is that a proxy sits in front of this server' suggests a reverse proxy architecture, but the proxy configuration for egress filtering is not documented or enforced at the application level. The application server itself has no configured restrictions on what resources it may fetch or what systems it may contact.

**Remediation:**

Add server-level egress configuration: yaml server: port: 58383 certfile: localhost.apache.org+3.pem keyfile: localhost.apache.org+3-key.pem # Permitted outbound destinations (egress allowlist) allowed_outbound: - host: "oauth.apache.org" port: 443 protocol: "https" - host: "ldap.apache.org" port: 636 protocol: "ldaps" # File access restrictions allowed_file_paths: - "/opt/steve/data/" - "/opt/steve/certs/" Additionally, document the expected proxy/firewall-level egress controls in a deployment guide.

---

#### FINDING-200: Auto-reload capability enabled in standalone mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.2 |
| **Files** | v3/server/main.py:84-91 |
| **Source Reports** | 13.4.2.md |
| **Related Findings** | None | **Description:**

The standalone mode uses extra_files for auto-reload capability, which is typically a development/debug feature. While the hot-reload behavior depends on the asfquart.runx() implementation, passing extra_files implies file-watching and automatic restart on changes. Auto-reload in production can cause service disruptions and may expose timing information about server state.

**Remediation:**

Conditionally enable extra_files only when debug mode is explicitly enabled. Remove or disable file-watching capabilities in production deployments.

---

#### FINDING-201: Missing debug configuration in example config file

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.2 |
| **Files** | v3/server/config.yaml.example |
| **Source Reports** | 13.4.2.md |
| **Related Findings** | None | **Description:**

The example configuration file lacks a debug setting with a production-safe default (i.e., debug: false). Without this, operators may not realize debug mode controls are needed.

**Remediation:**

Add production-safe defaults to config.yaml.example including debug: false and log_level: WARNING with comments indicating these MUST be false/WARNING in production.

---

#### FINDING-202: HTTP TRACE method not explicitly disabled

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.4 |
| **Files** | v3/server/main.py:entire file, v3/server/config.yaml.example |
| **Source Reports** | 13.4.4.md |
| **Related Findings** | None | **Description:**

There is no explicit configuration or middleware to disable the HTTP TRACE method. Neither the application code nor the configuration file addresses TRACE method handling. While Quart/Hypercorn may not support TRACE by default (as it typically only routes methods explicitly defined in decorators), there is no explicit rejection mechanism documented or configured. The reliance on framework defaults without verification creates a gap. If TRACE is supported, an attacker could use it in conjunction with XSS (Cross-Site Tracing) to extract HTTP-only cookies or authentication headers.

**Remediation:**

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

---

#### FINDING-203: Server version headers exposed in HTTP responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.6 |
| **Files** | v3/server/main.py:entire file |
| **Source Reports** | 13.4.6.md |
| **Related Findings** | None | **Description:**

There is no configuration to suppress server version headers. Hypercorn (the ASGI server) by default includes a `server: hypercorn-h11` or similar header in responses, and Quart may expose its version in error pages. No middleware or configuration is present to strip these headers. Detailed version information of the ASGI server allows attackers to identify specific vulnerabilities in that version, reducing the effort needed for targeted attacks.

**Remediation:**

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

---

#### FINDING-204: No Application-Level File Extension Allowlist as Defense-in-Depth

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.7 |
| **Files** | v3/server/main.py:48 |
| **Source Reports** | 13.4.7.md |
| **Related Findings** | None | **Description:**

While static_folder=None disables the default static file serving, there is no application-level middleware or response filter that would enforce a file extension allowlist if any route (in the unseen pages or api modules) serves files dynamically. This means there is no secondary control to prevent serving of .py, .yaml, .db, .pem, .git, or other sensitive extensions if a file-serving endpoint is introduced.

**Remediation:**

Add a response middleware that validates served content types, or add an after_request hook that enforces allowed extensions. Example: Create an after_request handler that checks file extensions against an allowlist (e.g., .html, .css, .js, .png, .jpg, .svg, .ico, .woff2) and returns 404 for unexpected extensions.

---

#### FINDING-205: No Reverse Proxy Hardening Configuration for File Extension Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 13.4.7 |
| **Files** | v3/server/config.yaml.example |
| **Source Reports** | 13.4.7.md |
| **Related Findings** | None | **Description:**

The domain context confirms deployment behind reverse proxies (Apache/nginx). However, no example reverse proxy configuration is provided that restricts which file extensions may be served. ASVS 13.4.7 specifically targets web tier configuration, which in a proxy-fronted architecture means the reverse proxy must enforce extension restrictions. Without proxy-level restrictions, requests for .git/, .env, config.yaml, *.db, *.pem, and source files could potentially reach the application layer if any misconfiguration occurs.

**Remediation:**

Provide example reverse proxy configurations that deny access to sensitive file extensions. For nginx: Add location blocks that deny .py, .yaml, .yml, .db, .pem, .key, .sqlite, .git, .env, .cfg, .ini, .log extensions and block access to hidden files/directories. For Apache: Use FilesMatch and DirectoryMatch directives to deny access to these extensions and hidden files.

---

#### FINDING-206: Comment indicates known pending migration without documented timeline

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.1 |
| **Files** | v3/steve/crypto.py:63-64 |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | None | **Description:**

The code contains a TODO-style comment indicating a planned migration from Fernet (AES-128-CBC) to XChaCha20-Poly1305, with HKDF parameters already configured for the target algorithm. However, there is no documented timeline for this migration, nor is there a documented assessment of whether the current Fernet implementation has any specific vulnerability requiring urgent migration. Without a documented timeline, this technical debt may persist indefinitely, and stakeholders cannot assess whether the current cryptographic approach meets the application's risk profile.

**Remediation:**

Document the migration plan with a target date and risk assessment of the current implementation. Either migrate to XChaCha20-Poly1305 or update the HKDF info parameter to accurately reflect current Fernet usage.

---

#### FINDING-207: No documentation highlighting risky third-party components despite known risks

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.4 |
| **Files** | Project-wide, election.py |
| **Source Reports** | 15.1.4.md |
| **Related Findings** | None | **Description:**

The domain context explicitly notes that 'ezt' is not widely used, which may be a risk factor, yet no formal documentation exists that classifies this or other components according to their risk profile. Based on the ASVS definition of 'risky components' (poorly maintained, unsupported, end-of-life, or history of significant vulnerabilities), the following components warrant documented risk assessment: 'ezt' (not widely used, small maintainer base, niche templating engine), 'easydict' (simple utility, low activity repository), 'asfpy' (ASF-internal library, limited community review), and 'argon2-cffi' (well-maintained but wraps C library via cffi). Without documented risk assessment, teams cannot make informed decisions about whether additional sandboxing is needed for risky components, whether alternatives should be evaluated, what additional testing is required for these components, and appropriate monitoring for vulnerability disclosures.

**Remediation:**

Create 'docs/RISKY_COMPONENTS.md' documenting risk assessment for each component. For 'ezt': Risk Level Medium, risk factors include limited community adoption and small maintainer pool, mitigation is to restrict to rendering pre-validated data only, quarterly review frequency, alternative considered is Jinja2. For 'easydict': Risk Level Low, risk factors include infrequent updates, mitigation is frozen version that could be replaced with dataclasses, annual review frequency. For 'asfpy': Risk Level Low-Medium, risk factors include limited external security review, mitigation is that ASF infrastructure team maintains with organizational trust boundary, review frequency tied to ASF infrastructure releases.

---

#### FINDING-208: No documentation highlighting dangerous functionality used in the application

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.5 |
| **Files** | v3/steve/election.py:410, v3/steve/crypto.py:91-101, v3/steve/crypto.py:75-88, v3/server/main.py:40-41, v3/steve/crypto.py:63-70 |
| **Source Reports** | 15.1.5.md |
| **Related Findings** | None | **Description:**

The application contains several instances of "dangerous functionality" as defined by ASVS (deserialization, dynamic code execution, raw data parsing, direct memory manipulation) that are not documented with their risks and mitigations: (1) Deserialization of data (json.loads) in json2kv function - While JSON is safer than pickle/yaml, it still processes structured data from database storage. (2) Low-level cryptographic operations (argon2.low_level) - Direct use of low_level API bypasses safety checks of the high-level argon2 API. (3) Symmetric encryption/decryption with key material handling - create_vote and decrypt_votestring functions handle sensitive key material. (4) Dynamic module imports - pages and api modules are imported dynamically. (5) HKDF key derivation with hardcoded info parameter - The info parameter references XChaCha20 but the derived key is used for Fernet, which could confuse auditors or lead to incorrect cryptographic assumptions. Without documentation, developers and auditors cannot quickly identify: where the most security-sensitive code resides, what additional review/testing these areas require, what the acceptable input constraints are for dangerous operations, and what the blast radius is if a vulnerability is found in these areas.

**Remediation:**

Create docs/DANGEROUS_FUNCTIONALITY.md documenting: ## Cryptographic Key Derivation (crypto.py) - Type: Direct memory manipulation (Argon2 low-level), key material handling - Location: v3/steve/crypto.py:_hash(), _b64_vote_key(), gen_opened_key() - Risk: Incorrect parameters could weaken vote encryption - Mitigation: Parameters benchmarked, unit tested, review required for changes - Input Trust: All inputs are system-generated (salts, tokens) — not user-controlled. ## Vote Encryption/Decryption (crypto.py) - Type: Symmetric encryption with derived keys - Location: v3/steve/crypto.py:create_vote(), decrypt_votestring() - Risk: Key leakage exposes all votes for an election - Mitigation: Keys derived per-voter-per-issue, never stored in plaintext. ## Data Deserialization (election.py) - Type: JSON deserialization - Location: v3/steve/election.py:json2kv() - Risk: Low (JSON parser, data sourced from database) - Mitigation: Data written by application's own kv2json(); no untrusted input. ## Dynamic Module Loading (main.py) - Type: Dynamic imports at startup - Location: v3/server/main.py:create_app() - Risk: Module injection if filesystem compromised - Mitigation: Imports are hardcoded module names, not user-controlled strings.

---

#### FINDING-209: Repeated Argon2 Calls in has_voted_upon() Without Throttling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.2 |
| **Files** | v3/steve/election.py:307-333 |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | None | **Description:**

The has_voted_upon() function is callable by any authenticated voter and triggers Argon2 computation for each issue in an election without throttling. An election with many issues (e.g., 50+ candidates as individual issues) would require 50+ Argon2 computations per page load, consuming ~3.2GB+ of memory throughput per request. This creates a resource consumption vector proportional to election size that can be triggered by any authenticated user.

**Remediation:**

Implement per-user rate limiting and cap the number of concurrent Argon2 operations system-wide to prevent resource exhaustion from repeated calls to this endpoint.

---

#### FINDING-210: No Visible Rate Limiting or Request Timeout Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.2 |
| **Files** | v3/server/main.py |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | None | **Description:**

The application has no visible rate limiting at the application layer and no evidence of middleware or framework-level controls for request throttling or timeouts. Without these controls, unlimited HTTP requests can trigger resource-intensive operations (Argon2, database) with no backpressure mechanism. The application relies entirely on external infrastructure (reverse proxy) for DoS protection, which is undocumented and may not be implemented in all deployment environments.

**Remediation:**

Implement application-level rate limiting using quart_rate_limiter with default limits (e.g., 50 requests per minute). Add request timeout configuration and document deployment requirements for external DoS protection infrastructure.

---

#### FINDING-211: Benchmarking Function Included in Production Crypto Module

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.3 |
| **Files** | v3/steve/crypto.py:125-158 |
| **Source Reports** | 15.2.3.md |
| **Related Findings** | None | **Description:**

While not directly exploitable via HTTP (requires __main__ execution or explicit import), this function: 1. Exists in the production deployment, increasing attack surface 2. Uses a hardcoded salt (b'16_byte_salt_123') which could mislead developers 3. Imports time module solely for this function 4. Uses Argon2.Type.ID while production uses Type.D, potentially confusing security audits 5. Contains informational output via print() rather than logging

**Remediation:**

Move benchmark_argon2() to a separate development/testing module not included in production deployments: Move to: v3/tools/benchmark_argon2.py (excluded from production)

---

#### FINDING-212: easydict Package Used Without Verification — Low-Maintenance Dependency

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.4 |
| **Files** | v3/steve/election.py:25 |
| **Source Reports** | 15.2.4.md |
| **Related Findings** | None | **Description:**

easydict is a convenience package with minimal maintenance activity. It's used throughout election.py for dictionary attribute access. Being a low-download, simple utility package, it's a higher-risk target for supply chain attacks (typosquatting, maintainer account takeover). The domain context notes that ezt is "not widely used" as a risk factor — the same applies to easydict.

**Remediation:**

Consider replacing with Python's built-in types.SimpleNamespace or dataclasses, eliminating the third-party dependency entirely: from types import SimpleNamespace # Replace edict(...) with SimpleNamespace(...)

---

#### FINDING-213: No Architectural Isolation Between Administrative and User-Facing Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.5 |
| **Files** | v3/server/main.py, v3/steve/election.py |
| **Source Reports** | 15.2.5.md |
| **Related Findings** | None | **Description:**

Administrative operations (election deletion, tallying with decryption, opening/closing elections) execute in the same process space as user-facing operations. A vulnerability in a user-facing endpoint could be leveraged to access administrative functionality. There is no evidence of: Separate admin service/process, Network-level isolation between admin and voter paths, Container boundaries between operations, Privilege separation at the OS level.

**Remediation:**

Option 1: Separate admin into its own service (admin_service/main.py - runs on different port/network). Option 2: Containerization with network policies using docker-compose.yml with voter-app on frontend network and admin-app on backend network not accessible from internet.

---

#### FINDING-214: Cryptographic Operations Execute Without Sandboxing or Memory Isolation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.5 |
| **Files** | v3/steve/crypto.py:88-99 |
| **Source Reports** | 15.2.5.md |
| **Related Findings** | None | **Description:**

The argon2.low_level API directly calls into a C library (argon2-cffi-bindings wrapping the reference C implementation). This: 1. Allocates 64MB of memory per call within the application process, 2. Executes native code that could be exploited if the argon2-cffi-bindings library has a memory corruption vulnerability, 3. Shares the same memory space as all application data (encryption keys, vote content). A memory corruption vulnerability in the native Argon2 library could expose the opened_key or vote tokens stored in the same process memory.

**Remediation:**

Run crypto operations in a sandboxed subprocess using subprocess.run with resource limits via ulimit or seccomp. Alternatively, deploy with container-level memory limits and seccomp profiles to contain potential native code exploitation.

---

#### FINDING-215: Raw Database Rows Returned Without Python-Level Field Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.3.1 |
| **Files** | v3/steve/election.py:374, v3/steve/election.py:399 |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | None | **Description:**

The methods `open_to_pid()` and `upcoming_to_pid()` in `election.py` return raw database rows without explicit Python-level field filtering. If the underlying SQL queries select from the metadata table without column restrictions, sensitive fields (`salt`, `opened_key`) could leak to templates and eventually to client-side HTML. This is inconsistent with the control pattern used in `owned_elections()`, which explicitly excludes sensitive columns with a comment acknowledging the need to prevent exposure of `salt` and `opened_key`. The severity is mitigated if the queries in `queries.yaml` select only specific columns, but this cannot be verified from the provided code.

**Remediation:**

Apply explicit Python-level field filtering to `open_to_pid()` and `upcoming_to_pid()` methods, matching the pattern used in `get_metadata()` and `owned_elections()`. Return only safe fields by constructing explicit `edict` objects with allowed fields (eid, title, owner_pid, closed, open_at, close_at, issue_count) rather than passing through raw database rows.

---

#### FINDING-216: Election Creation Accepts Unrestricted Form Data Pattern

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 15.3.3 |
| **Files** | v3/server/pages.py:439 |
| **Source Reports** | 15.3.3.md |
| **Related Findings** | None | **Description:**

The do_create_endpoint() function loads ALL form data into an edict without a whitelist, creating risk of future mass assignment. While currently only form.title is passed to Election.create(), the pattern lacks an explicit allowlist meaning code review is the only protection. The create() method accepts additional parameters (authz, open_at, close_at) that could be exploited if a developer later extracts them from the form. If authz were controllable, an attacker could modify LDAP group authorization for elections they create. If open_at/close_at were controllable, dates could be manipulated.

**Remediation:**

Replace the edict pattern with explicit field extraction using form.get('title', '').strip(). Add validation to ensure title is not empty. Only accept whitelisted fields and perform type checking before passing to Election.create().

---

#### FINDING-217: Incomplete Exception Handling for Type Errors in Date Parsing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 15.3.5 |
| **Files** | v3/server/pages.py:91 |
| **Source Reports** | 15.3.5.md |
| **Related Findings** | None | **Description:**

The `data.get('date')` could return any JSON type (array, object, number, boolean). The `if not date_str` check would pass for non-empty arrays/objects (truthy values). When passed to `datetime.datetime.fromisoformat()`, a non-string type raises `TypeError`, not `ValueError`. Only `ValueError` is caught. This results in unhandled 500 error instead of a clean 400 response, potentially causing information leakage via stack traces if debug mode is enabled.

**Remediation:**

Add explicit type validation using `isinstance(date_str, str)` before the truthy check. Catch both `ValueError` and `TypeError` in the exception handler. Example:
```python
async def _set_election_date(election, field):
    data = await quart.request.get_json()
    date_str = data.get('date')
    if not isinstance(date_str, str) or not date_str:
        quart.abort(400, 'Missing or invalid date')

    try:
        dt = datetime.datetime.fromisoformat(date_str).date()
    except (ValueError, TypeError):
        quart.abort(400, 'Invalid date format')
```

---

#### FINDING-218: Database Connections Created Per-Instance Without Connection Lifecycle Management or Pool Safety

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.4.1 |
| **Files** | v3/steve/election.py |
| **Source Reports** | 15.4.1.md |
| **Related Findings** | None | **Description:**

Each concurrent request creates a new Election instance which opens a new asfpy.db.DB connection to the same SQLite file through Election.__init__() and open_database(). There is no connection pooling, no maximum connection limit, and no timeout configuration. Under high concurrency (e.g., many voters submitting simultaneously during election close), this could exhaust file descriptors or cause SQLite SQLITE_BUSY errors without proper retry logic.

**Remediation:**

Implement connection pooling with bounded concurrency using an asyncio.Semaphore to limit simultaneous database connections (e.g., max 10 concurrent connections). Create a managed ElectionDB class with a class-level semaphore that controls access to database connections, providing fair queuing and preventing file descriptor exhaustion.

---

#### FINDING-219: Non-Atomic State Check and Close Operation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-367 |
| **ASVS Sections** | 15.4.2 |
| **Files** | v3/steve/election.py:111-116 |
| **Source Reports** | 15.4.2.md |
| **Related Findings** | FINDING-074, FINDING-220 | **Description:**

The close() method performs a non-atomic check-then-use operation where it first checks if the election is open (is_open()) and then closes it (c_close.perform()). Between these operations, a concurrent close could execute. While double-close is less severe than double-open since closing is idempotent at the database level (setting closed=1 twice has the same effect), it still represents a TOCTOU pattern that could produce misleading log entries or confusing user feedback.

**Remediation:**

Wrap the close() operation in a BEGIN IMMEDIATE transaction with state re-verification. Re-check the election state within the transaction to ensure it is still open before performing the close operation. Include proper exception handling with ROLLBACK on error and COMMIT on success.

---

#### FINDING-220: TOCTOU Between Authorization Check and File Serving

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-367 |
| **ASVS Sections** | 15.4.2 |
| **Files** | v3/server/pages.py:585-599 |
| **Source Reports** | 15.4.2.md |
| **Related Findings** | FINDING-074, FINDING-219 | **Description:**

The serve_doc() endpoint performs a non-atomic authorization check followed by file serving. It first checks if the user has permission by querying q_get_mayvote.first_row(result.uid, iid), then serves the file using send_from_directory(). Between the check and use, the mayvote entry could be deleted (e.g., if the election is reset), allowing a file to be served to a user whose permission was just revoked. While the window is small and the consequence is limited, this is a textbook TOCTOU pattern.

**Remediation:**

Perform the authorization check and file serving within a transaction, or re-verify the authorization immediately before serving the file. Consider caching the authorization decision with a short TTL, or restructuring the code to minimize the time window between check and use.

---

#### FINDING-221: Transaction Blocks Lack Error Handling — No ROLLBACK on Failure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.4.3 |
| **Files** | v3/steve/election.py:56-67, v3/steve/election.py:118-135 |
| **Source Reports** | 15.4.3.md |
| **Related Findings** | None | **Description:**

If any operation within the transaction raises an exception, the transaction remains open (not committed, not rolled back). The SQLite connection would hold a write lock until the connection is garbage-collected or explicitly closed. In a concurrent environment, this could deadlock other database operations waiting for the write lock.

**Remediation:**

Add try/except/ROLLBACK blocks to all transaction code. Wrap transaction operations in try blocks, catch exceptions, execute ROLLBACK, and re-raise the exception to ensure locks are properly released on failure.

---

#### FINDING-222: No SQLite Busy Timeout Configuration — Concurrent Requests Can Fail Immediately

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.4.4 |
| **Files** | v3/steve/election.py:40 |
| **Source Reports** | 15.4.4.md |
| **Related Findings** | None | **Description:**

Concurrent requests → multiple open_database() calls → multiple SQLite connections → no busy_timeout set → SQLITE_BUSY error returned immediately to lower-priority threads. When multiple concurrent requests contend for the SQLite write lock, requests that cannot immediately acquire the lock receive an SQLITE_BUSY error without retrying. This effectively starves lower-priority requests (those that arrive slightly later) by failing them immediately rather than allowing them to wait a reasonable time. SQLite's default busy timeout is 0 (fail immediately), which causes thread starvation under any write contention.

**Remediation:**

Configure SQLite busy timeout in open_database(): db.conn.execute('PRAGMA busy_timeout = 5000') to allow waiting up to 5 seconds for locks to clear.

---

#### FINDING-223: Unbounded Iteration Over User-Supplied Form Keys Without Limiting Candidate Count

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Sections** | 15.4.4 |
| **Files** | v3/server/pages.py:399-420 |
| **Source Reports** | 15.4.4.md |
| **Related Findings** | None | **Description:**

User-controlled form data (potentially thousands of vote-xxx keys) → iteration → add_vote() call per key → database query + crypto operations per iteration → CPU/IO exhaustion. A single authenticated request with many fabricated vote- parameters forces the server to iterate through all of them. While invalid IIDs are caught early, the iteration itself and the issue_dict lookups consume resources proportional to attacker input size.

**Remediation:**

Implement a maximum vote count per request (e.g., MAX_VOTES_PER_REQUEST = 100). Check len(votes) during iteration and return an error if the limit is exceeded before processing further.

---

#### FINDING-224: No documented rate limiting, anti-automation, or adaptive response controls for authentication endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 6.1.1 |
| **Files** | v3/server/main.py:34-39, v3/server/pages.py |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | None | **Description:**

The application delegates authentication to ASF OAuth (oauth.apache.org). However, there is no documentation anywhere in the provided code (comments, docstrings, or configuration) that describes: 1. How rate limiting is configured for the OAuth callback endpoint 2. Whether the upstream ASF OAuth provider implements anti-automation controls 3. What adaptive response mechanisms exist (e.g., progressive delays, CAPTCHA escalation) 4. How the system prevents malicious account lockout at the ASF OAuth layer 5. Whether the application itself implements any secondary rate limiting on session-protected endpoints. The asfquart.auth.require decorator is used extensively across endpoints (with {R.committer}, {R.pmc_member}, or bare), but no per-endpoint rate limiting is applied. Without documented rate limiting controls, there is no assurance that brute force or credential stuffing attacks against the OAuth flow are mitigated. Operational staff cannot verify correct configuration without documentation.

**Remediation:**

Create authentication security documentation that specifies: 1. Rate Limiting - OAuth callback endpoint: Delegated to ASF OAuth (oauth.apache.org) with specific controls described, Application-level max attempts per IP per minute via reverse proxy. 2. Anti-Automation - CAPTCHA integration and bot detection mechanisms. 3. Adaptive Response - Behavior after N failed attempts, account lockout prevention with unlock mechanism for ASF accounts. 4. Reverse Proxy Configuration - Apache/nginx rate limit rules with reference to config files.

---

#### FINDING-225: Multiple authentication pathways exist but are not documented together with security controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 6.1.3 |
| **Files** | v3/server/pages.py:multiple locations |
| **Source Reports** | 6.1.3.md |
| **Related Findings** | None | **Description:**

The application implements at least three distinct authentication/authorization pathways: 1) Bare session (@asfquart.auth.require) for endpoints like /profile, /settings, /docs/&lt;iid&gt;/&lt;docname&gt;; 2) Committer level (@asfquart.auth.require({R.committer})) for /voter, /admin, /manage/&lt;eid&gt;, and all voting and issue management endpoints; 3) PMC member level (@asfquart.auth.require({R.pmc_member})) for /do-create-election. Additionally, the '### need general solution' comments throughout indicate that the authorization model is incomplete and evolving. There is no documentation that defines what security controls apply at each level, describes the authentication strength at each level (all use the same OAuth flow), explains why certain endpoints use one level vs another, or documents the planned 'general solution' mentioned in comments. The repeated '### check authz' comments indicate that fine-grained authorization checks are acknowledged as needed but not implemented.

**Remediation:**

Create comprehensive authentication pathways documentation that includes: 1) OAuth Flow documentation covering provider (ASF OAuth), authentication strength (single-factor ASF credentials), session management, and security controls; 2) Authorization Levels documentation for Level 0 (Public/No Authentication), Level 1 (Authenticated User with valid session), Level 2 (ASF Committer with committer status), and Level 3 (PMC Member); 3) Consistency Enforcement documentation explaining that all pathways use the same ASF OAuth provider with identical authentication strength, with authorization differing by LDAP group membership. Document the current state including acknowledged gaps (fine-grained authorization checks) and planned remediation. Store this documentation in a central location such as docs/AUTHENTICATION.md.

---

#### FINDING-226: No Visible Token Signature Validation in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 9.1.1 |
| **Files** | v3/server/pages.py:75-106, v3/server/main.py:27-42 |
| **Source Reports** | 9.1.1.md |
| **Related Findings** | None | **Description:**

Token/session validation is entirely delegated to the `asfquart` framework. The application code contains zero explicit signature validation, and no configuration parameters for signature verification keys are provided. If `asfquart` fails to validate, the application has no defense-in-depth. The application's trust model assumes `asfquart.session.read()` returns fully validated, trustworthy data. Every endpoint reads session data and uses `uid` directly for authorization decisions (database queries, ownership checks, logging) without any additional verification layer.

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
1. Audit `asfquart` framework for compliance with ASVS 9.x requirements
2. Configure audience validation with explicit audience ('steve')
3. Reconsider OIDC avoidance to gain standardized ID token validation
4. Document and configure algorithm allowlist (RS256, ES256)
5. Add issuer validation for expected token issuer (https://oauth.apache.org)
6. Implement defense-in-depth with application-level validation of critical session properties
7. Implement or verify JWKS endpoint caching and rotation handling
8. Implement explicit token type checking to prevent cross-purpose token reuse

---

#### FINDING-227: No Algorithm Restriction Configuration Visible

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 9.1.2 |
| **Files** | v3/server/main.py:27-42 |
| **Source Reports** | 9.1.2.md |
| **Related Findings** | None | **Description:**

No algorithm allowlist is configured anywhere in the provided application code. If the asfquart framework or any JWT library processes self-contained tokens, there is no explicit restriction to approved algorithms (e.g., RS256, ES256) and no explicit prohibition of the 'None' algorithm. If the underlying framework uses a JWT library that accepts the alg: none header or allows algorithm confusion attacks (e.g., treating an RSA public key as an HMAC secret with HS256), an attacker could forge valid-looking tokens. The audit context specifies only approved algorithms (RS256, ES256) are allowed (not HS256 with shared secrets) — no such restriction is implemented or configured in the visible code.

**Remediation:**

In create_app() or configuration, explicitly set allowed algorithms. Configure algorithm allowlist for token validation: app.config['TOKEN_ALGORITHMS'] = ['RS256', 'ES256'] (No 'none', no HS256), app.config['TOKEN_REJECT_NONE_ALG'] = True. If using PyJWT directly: ALLOWED_ALGORITHMS = ['RS256', 'ES256'] and jwt.decode(token, key, algorithms=ALLOWED_ALGORITHMS) with never passing algorithms=None.

---

#### FINDING-228: No Key Material Source Validation Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 9.1.3 |
| **Files** | v3/server/main.py:27-42 |
| **Source Reports** | 9.1.3.md |
| **Related Findings** | None | **Description:**

No configuration of trusted key sources, no JKU/x5u/JWK header allowlists, and no pinned public keys for the OAuth issuer (oauth.apache.org) are visible in the application code. If self-contained tokens (JWTs) are used with headers like jku (JSON Web Key URL), an attacker could potentially craft a token pointing to their own key server, causing the application to validate the forged token against attacker-controlled keys. Data flow: OAuth provider issues tokens → Token may contain jku/x5u/jwk headers → Application/framework processes token → No visible restriction on key source headers.

**Remediation:**

Configure trusted key sources (TRUSTED_JWKS_URLS = ['https://oauth.apache.org/.well-known/jwks.json'], TRUSTED_ISSUERS = ['https://oauth.apache.org']). In token validation, reject tokens with jku/x5u/jwk headers unless they match the allowlist. Implement validation function to check token headers against allowlist and reject untrusted sources or embedded keys.

---

#### FINDING-229: No Token Expiry Verification in Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 9.2.1 |
| **Files** | v3/server/pages.py:75-106 |
| **Source Reports** | 9.2.1.md |
| **Related Findings** | None | **Description:**

The application reads session data and checks only for presence (if s:), not for temporal validity. No exp, nbf, or iat claim verification is visible. If asfquart.session.read() does not internally verify token expiration, expired sessions would be accepted indefinitely. The application's trust model assumes asfquart.session.read() returns fully validated, trustworthy data. Every endpoint reads session data and uses uid directly for authorization decisions without any additional verification layer. Data flow: asfquart.session.read() returns session dict, application checks only if s: (truthy), accepts claims without time validation.

**Remediation:**

Verify session hasn't expired at the application layer even if framework handles this. Check exp claim: if time.time() > s['exp'], treat as unauthenticated. Check nbf claim: if time.time() < s['nbf'], treat as unauthenticated. Add defense-in-depth validation of critical session properties (expiry, audience, type) even if the framework also validates them.

---

#### FINDING-230: No Token Type Differentiation or Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 9.2.2 |
| **Files** | v3/server/pages.py:75-106, v3/server/main.py:27-42 |
| **Source Reports** | 9.2.2.md |
| **Related** | - | **Description:**

The application explicitly avoids OIDC (which provides standard ID tokens with typ claims and clear access/identity token separation). The plain OAuth flow used does not distinguish between token types. No typ or token_use claim is checked before accepting token contents for authentication decisions. Without token type verification, there is a risk of token misuse. For example, if different token types are issued for different purposes (API access vs. user identity), the absence of type checking could allow an access token to be used where an ID token is expected, potentially granting unintended access. Data flow: OAuth response → framework creates session → application uses session for both identity (display name/email) and authorization (uid for access decisions) → no verification that the token was intended for identity vs. authorization.

**Remediation:**

If using OIDC (recommended over plain OAuth), the framework should validate that ID tokens are used for authentication and access tokens for API calls. At the application level, implement token type checking: verify that session tokens have appropriate token_type or typ claims (e.g., 'id_token' or 'session') before accepting them for identity-related decisions. Reject tokens that do not match the expected type for the intended purpose.

---

#### FINDING-231: No Audience Claim Validation Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 9.2.3 |
| **Files** | v3/server/main.py:27-42, v3/server/pages.py:75-106 |
| **Source Reports** | 9.2.3.md |
| **Related** | - | **Description:**

No audience (aud) claim validation is configured or performed anywhere in the visible application code. The application identifier 'steve' is used for app construction but not configured as an expected audience for token validation. If oauth.apache.org issues tokens for multiple applications (which is likely given it's a shared OAuth provider for all ASF services), a token intended for another ASF application could potentially be replayed against this STeVe application. Without audience validation, cross-application token reuse is possible. Data flow: OAuth token → session → asfquart.session.read() → no aud claim check → application accepts any valid token regardless of intended audience.

**Remediation:**

Configure expected audience in create_app(): app.config['TOKEN_AUDIENCE'] = 'steve' and app.config['TOKEN_ISSUER'] = 'https://oauth.apache.org'. Implement token validation function that checks if 'aud' claim matches EXPECTED_AUDIENCE (handling both string and list formats) and validates 'iss' claim matches EXPECTED_ISSUER. Raise ValueError if validation fails.

---

#### FINDING-232: No Clear-Site-Data Header or Client-side Storage Cleanup Mechanism Present

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 14.3.1 |
| **Files** | v3/steve/election.py, v3/schema.sql, v3/docs/schema.md |
| **Source Reports** | 14.3.1.md |
| **Related** | - | **Description:**

The provided code constitutes the data access layer of an election system that handles highly sensitive data (voter eligibility, encrypted votes, election metadata). The election.py module exposes methods that return authenticated/sensitive data to callers. Without a Clear-Site-Data header sent on session termination/logout, sensitive election data (voter identity associations, voting status per issue, election ownership information) may persist in browser caches, cookies, and storage after the user's session ends. Given the core security requirement of ballot secrecy, residual data showing which issues a voter has voted upon (has_voted_upon results) could persist on shared or compromised devices. Type A gap: No control exists in provided codebase. The web framework layer (Quart) is not included in the audit scope, but no evidence of a logout handler sending Clear-Site-Data header is present.

**Remediation:**

In the Quart web layer (not provided), implement a logout endpoint that invalidates server-side session and sends Clear-Site-Data header with values 'cache', 'cookies', 'storage'. Additionally, implement client-side cleanup for cases where server connection is unavailable using JavaScript beforeunload event listener to clear localStorage and sessionStorage when session expires.

---

#### FINDING-233: Data Access Layer Returns Sensitive Data Without Browser Storage Restrictions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 14.3.3 |
| **Files** | v3/steve/election.py:has_voted_upon method, v3/steve/election.py:get_voters_for_email method |
| **Source Reports** | 14.3.3.md |
| **Related** | - | **Description:**

The election module's API surface returns data that must not be persisted in client-side browser storage (localStorage, sessionStorage, IndexedDB). While the provided code contains no client-side JavaScript, the data structures returned are rich in sensitive information that could violate ballot secrecy if stored. The has_voted_upon method creates a voter-to-issue-participation mapping. The get_voters_for_email method returns PII: person IDs, names, and email addresses. If any client-side JavaScript stores has_voted_upon results, it directly links voter identity (PID) to voting participation per issue, violating ballot secrecy. If get_voters_for_email results are stored, it exposes voter PII. The domain context explicitly states that client-side storage should not contain vote data or voter-vote associations. No client-side storage restriction mechanism is visible in the provided code. No Content-Security-Policy or JavaScript controls preventing storage are present.

**Remediation:**

1. At the web framework layer, implement CSP headers that restrict JavaScript capabilities: response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'". 2. In any client-side JavaScript, explicitly avoid storing sensitive API responses. Keep sensitive data only in memory (JavaScript variables) that are garbage-collected on page navigation. 3. Add a security comment/contract to the data access layer methods documenting that results contain voter-specific data that MUST NOT be persisted in client-side storage.

---

#### FINDING-234: No HTTP Security Headers Configuration or Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.1.1 |
| **Files** | v3/server/pages.py:entire file |
| **Source Reports** | 3.1.1.md |
| **Related** | - | **Description:**

The application does not configure or document any browser security features. There is no evidence of: HTTP Strict Transport Security (HSTS) headers, Content Security Policy (CSP) headers, X-Content-Type-Options headers, X-Frame-Options or frame-ancestors CSP directive, Referrer-Policy headers, or Permissions-Policy headers. Furthermore, there is no documentation (in code comments, configuration files, or docstrings) specifying what browser security features are expected or how the application should behave when they are unavailable. Without documented browser security requirements and enforced headers: (1) No HSTS means connections may be downgraded to HTTP (especially relevant since domain context acknowledges TLS termination at reverse proxy), (2) No CSP means the application is more vulnerable to XSS exploitation, (3) No documentation means deployment teams cannot verify correct security configuration, (4) Browsers with insufficient security features will access the application without warning.

**Remediation:**

Add security headers middleware: @APP.after_request async def set_security_headers(response): response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'; response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'"; response.headers['X-Content-Type-Options'] = 'nosniff'; response.headers['X-Frame-Options'] = 'DENY'; response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'; return response. Additionally, create a SECURITY.md or equivalent documentation specifying: Required browser features (TLS 1.2+, JavaScript enabled, secure cookie support), Expected headers from reverse proxy (HSTS, etc.), Behavior when security features are unavailable (graceful degradation vs. blocking).

### 3.4 Low

#### FINDING-235: Key Sharing Scope Not Formally Documented

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 11.1.1 |
| Files | v3/steve/crypto.py, v3/steve/election.py |
| Source Reports | 11.1.1.md |
| Related | None | **Description:**

The opened_key in each election effectively acts as a shared secret used by the system to derive per-voter vote tokens. While the key is only accessible to the application server (single entity), the sharing boundaries are not formally documented. The key derivation chain (opened_key → vote_token → vote_key) means compromise of the opened_key enables decryption of all votes in that election. Without formal documentation of key sharing boundaries, there's risk of architectural changes inadvertently exposing keys to additional entities.

**Remediation:**

Formally document key sharing boundaries and access control policies for all cryptographic keys, particularly the opened_key. Document the key derivation chain and the security implications of opened_key compromise.

---

#### FINDING-236: Misleading HKDF Info Parameter Suggests Incomplete Migration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | N/A |
| ASVS sections | 11.2.2, 11.3.4 |
| Files | v3/steve/crypto.py:63-67 |
| Source Reports | 11.2.2.md, 11.3.4.md |
| Related | None | **Description:**

The HKDF `info` parameter is set to `b'xchacha20_key'` while the system currently uses Fernet for encryption. When the system migrates to XChaCha20-Poly1305, this `info` value will remain the same, meaning keys derived for Fernet would be identical to keys derived for XChaCha20-Poly1305. If old ciphertexts coexist with new ciphertexts during migration, this violates the principle that a single key should not be used across different algorithm/data-element pairs.

**Remediation:**

Use `info=b'fernet_vote_key'` now, and switch to `info=b'xchacha20_vote_key'` during migration to ensure domain separation. Example: `info=b'fernet_vote_key',  # Change to b'xchacha20_vote_key' when algorithm changes`

---

#### FINDING-237: BLAKE2b usage may not meet strict NIST compliance requirements

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | N/A |
| ASVS sections | 11.4.1 |
| Files | v3/steve/crypto.py:45 |
| Source Reports | 11.4.1.md |
| Related | None | **Description:**

BLAKE2b is a modern, secure hash function (RFC 7693) with a 512-bit output, providing strong collision resistance. However, it is not listed in NIST FIPS 180-4 (SHA-2) or FIPS 202 (SHA-3) as an "approved" hash function. Depending on organizational compliance requirements, this could be a concern. In practice, BLAKE2b is used within Argon2 itself (which is NIST-recognized via SP 800-63B), making this a very low-risk finding.

**Remediation:**

If strict NIST compliance is required, replace with SHA-512: `digest = hashlib.sha512(edata).digest()  # 64 bytes, NIST-approved`

---

#### FINDING-238: HKDF usage documentation needed to clarify key stretching architecture

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 11.4.4 |
| Files | v3/steve/crypto.py:60-67 |
| Source Reports | 11.4.4.md |
| Related | None | **Description:**

HKDF is not a key-stretching function and provides no computational cost against brute-force. However, since the input (vote_token) is already the 32-byte output of Argon2 (which provides the key stretching), HKDF is being used appropriately as a key derivation function to transform already-stretched material into an encryption key. This is acceptable architecture but worth documenting that the stretching occurs upstream.

**Remediation:**

Add a comment clarifying the security model: 'Note: Key stretching is provided by Argon2 in gen_vote_token(). HKDF here only transforms the already-stretched token into a key suitable for the encryption algorithm.'

---

#### FINDING-239: All votes decrypted and held simultaneously in memory during tally

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 11.7.2 |
| Files | v3/steve/election.py:248-294 |
| Source Reports | 11.7.2.md |
| Related | None | **Description:**

The entire set of decrypted votes exists in cleartext memory simultaneously. For elections with many voters, this creates a larger window where all vote data is exposed. There is no explicit clearing of sensitive variables after use. Data flow: All votes for an issue are decrypted simultaneously → stored in `votes` list → remain in memory until garbage collected.

**Remediation:**

Process votes through streaming tally where possible. For STV (requires all votes), minimize exposure window by explicitly clearing sensitive data in a finally block. Use pattern: clear each vote string to None, then clear the list. Note: Python doesn't guarantee memory zeroing, but this reduces exposure window.

---

#### FINDING-240: Voter identity data accumulated in cleartext memory during election data gathering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 11.7.2 |
| Files | v3/steve/election.py:82-107 |
| Source Reports | 11.7.2.md |
| Related | None | **Description:**

Voter identity data (PIDs and email addresses) exists in unencrypted memory longer than necessary. The assembled string is only needed for hashing but persists until garbage collected. Data flow: All voter PIDs and emails assembled in cleartext string → encoded to bytes → passed to hash function → original strings remain in memory.

**Remediation:**

Use incremental hashing to avoid accumulating all data in a single string. Create a hash object (e.g., hashlib.blake2b()) and update it incrementally for each metadata element, issue, and voter record. Return the final digest without accumulating sensitive data in memory.

---

#### FINDING-241: No Evidence of Cache-Control Mechanisms for Sensitive Data Responses

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 14.2.2 |
| Files | v3/steve/election.py |
| Source Reports | 14.2.2.md |
| Related | None | **Description:**

The data access layer returns sensitive data objects but no cache prevention controls are visible in the provided code. The data access layer in election.py returns sensitive data objects including voter PII (email, name) and election metadata (salt, opened_key) without visible HTTP cache-control headers or cache purging mechanisms. Without explicit cache controls at the HTTP layer, voter email addresses could be cached in reverse proxies, election metadata with sensitive fields could persist in application-level caches, and browser caches could store sensitive responses. The web layer (Quart framework) is not in scope for this audit.

**Remediation:**

In the Quart web handlers (not provided), add appropriate headers for endpoints returning sensitive data. Implement an after_request handler to add Cache-Control: no-store, no-cache, must-revalidate, private headers, along with Pragma: no-cache and Expires: 0 headers for paths like /election/ and /vote/. Example code provided in the report shows implementing this as a Quart after_request decorator.

---

#### FINDING-242: No programmatic enforcement of database file permissions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 14.2.4 |
| Files | v3/steve/election.py:38 |
| Source Reports | 14.2.4.md |
| Related | None | **Description:**

The domain context states 'database file permissions restrict access to the application user only' but there is no verification of file permissions when the database is opened. If the database file is created with overly permissive modes (e.g., 0644 instead of 0600), sensitive data including encrypted votes and cryptographic salts would be accessible to other system users.

**Remediation:**

Check and enforce database file permissions in open_database(): verify that existing database files do not have group or world read permissions, and set mode 0600 on newly created database files.

---

#### FINDING-243: tally_issue returns full set of voter PIDs alongside tally results

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 14.2.6 |
| Files | v3/steve/election.py:280-320 |
| Source Reports | 14.2.6.md |
| Related | None | **Description:**

The method returns the full set of voter PIDs (identities of who voted) alongside tally results. While knowing *who* voted (not *how*) may be legitimate for participation tracking, returning a full identity set to the caller provides more data than may be needed for simply displaying results. If the web layer exposes this to unauthorized users, it reveals voting participation patterns. This may be intentional for audit purposes (showing voter turnout). The severity is LOW because the votes themselves remain anonymous (shuffled and unlinkable to specific PIDs).

**Remediation:**

Return voter count instead of full PID set for display purposes and provide separate method for authorized audit access. Implement two methods: tally_issue() returning m.tally(votes, self.json2kv(issue.kv)), len(voters) for display, and tally_issue_with_voters() returning the full voters set for authorized audit only.

---

#### FINDING-244: Token Handling Cannot Be Fully Verified Without asfquart Library Inspection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 10.1.1 |
| Files | v3/server/main.py:40-43 |
| Source Reports | 10.1.1.md |
| Related | None | **Description:**

The OAuth authorization code flow is configured with server-side token exchange, which is the correct pattern for keeping tokens away from the browser. The OAUTH_URL_CALLBACK URL format suggests the authorization code is exchanged server-side. However, without visibility into: 1) The asfquart library's token handling, 2) Whether access/refresh tokens are ever sent to the browser via cookies or response bodies, 3) Whether the session cookie contains tokens or only a session identifier, full compliance cannot be confirmed. The architectural pattern appears correct based on available code.

**Remediation:**

Verify token confinement in asfquart (ASVS 10.1.1): Confirm that the session cookie contains only a session identifier (not embedded tokens) and that access/refresh tokens are stored server-side only.

---

#### FINDING-245: Missing nonce Parameter for OpenID Connect

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 10.1.2, 10.5.1 |
| Files | v3/server/main.py:39-42 |
| Source Reports | 10.1.2.md, 10.5.1.md |
| Related | None | **Description:**

The authentication request URL template includes state and redirect_uri parameters but does NOT include a nonce parameter. Per OIDC Core Section 3.1.2.1, the nonce parameter should be included in authentication requests and then validated in the returned ID token to mitigate replay attacks. Additionally, the comment in create_app() explicitly states '# Avoid OIDC', indicating the application is intentionally bypassing OIDC in favor of a custom OAuth flow. This means OIDC-standard protections like nonce validation are not implemented. An attacker who captures an ID token (e.g., from browser history, logs, or XSS) could replay it against the application. Without nonce binding, the attacker could obtain a victim's ID token from a previous session, present the captured token to the application, and the application would accept it as valid since there is no nonce to tie the token to a specific authentication request.

**Remediation:**

Generate a cryptographically random nonce for each authentication request using secrets.token_urlsafe(32), store it in the session, include it in the authorization request URL, and validate it in the returned ID token. Example: nonce = secrets.token_urlsafe(32); session['oauth_nonce'] = nonce; OAUTH_URL_INIT = 'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&nonce=%s'. In the token validation callback, verify that id_token_claims.get('nonce') matches session.get('oauth_nonce'), raise a SecurityError if mismatched, and delete the session nonce after single use.

---

#### FINDING-246: OAuth authorization URL does not include explicit scope parameter

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3, L2 |
| CWE | N/A |
| ASVS sections | 10.2.3, 10.4.11 |
| Files | v3/server/main.py:40 |
| Source Reports | 10.2.3.md, 10.4.11.md |
| Related | None | **Description:**

The OAuth authorization URL template does not include a `scope` parameter. This means either: 1. The authorization server applies default scopes (potentially broader than needed), or 2. The `asfquart` framework appends scope parameters elsewhere (not visible), or 3. The ASF OAuth system doesn't use scopes and grants a fixed set of claims. Based on the application's session usage (`basic_info()` reads `uid`, `fullname`, `email`), the application only needs identity information. If the authorization server grants additional permissions by default (e.g., write access to ASF services), this would violate the principle of least privilege. If the authorization server grants broader permissions than necessary by default, any token theft would grant the attacker more access than the application actually requires.

**Remediation:**

Add an explicit scope parameter to the OAuth authorization URL template: `asfquart.generics.OAUTH_URL_INIT = ('https://oauth.apache.org/auth?state=%s&redirect_uri=%s&scope=openid+profile+email')`. Or if ASF OAuth uses custom scopes, request only what's needed for the application's functionality. Document and enforce explicit mapping between OAuth scopes and application-level permissions.

---

#### FINDING-247: OAuth scope to application permission mapping not explicit

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 10.4.11 |
| Files | v3/server/pages.py |
| Source Reports | 10.4.11.md |
| Related | None | **Description:**

The application uses role-based access control (R.committer, R.pmc_member) but these roles appear to be derived from the session/token data, not from OAuth scopes. The mapping between OAuth scopes and application-level permissions is not explicit in the provided code. If the authorization server grants overly broad scopes, the application's internal RBAC may be the only control preventing scope abuse. The application has its own authorization layer, but the principle of defense-in-depth suggests scopes should also be constrained at the OAuth level.

**Remediation:**

Document and enforce explicit mapping between OAuth scopes and application-level permissions. Ensure OAuth scopes are also constrained at the authorization server level to support defense-in-depth.

---

#### FINDING-248: Token Audience Validation Not Verifiable in OAuth Callback

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 10.3.1 |
| Files | v3/server/pages.py |
| Source Reports | 10.3.1.md |
| Related | None | **Description:**

The application does not appear to function as a traditional OAuth resource server that accepts bearer tokens. Instead, it uses session-based authentication established through an OAuth login flow. All protected endpoints use @asfquart.auth.require decorators which check session validity, not access token audience claims. However, the initial token received from the authorization server during the OAuth callback should ideally have its audience validated by the asfquart framework before establishing the session. This validation occurs in framework code not provided for audit. If the asfquart framework does not validate the audience of tokens received during the OAuth callback, a token intended for a different ASF application could potentially be used to establish a session in this application (token confusion attack).

**Remediation:**

Verify that the asfquart framework validates the aud claim (or equivalent) in any tokens received from the authorization server before establishing a local session.

---

#### FINDING-249: Cannot verify redirect URI validation with exact string comparison on external authorization server

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | N/A |
| ASVS sections | 10.4.1 |
| Files | v3/server/main.py:39-42 |
| Source Reports | 10.4.1.md |
| Related | None | **Description:**

This requirement applies to the authorization server (OAuth AS), not to the OAuth client. The application delegates authorization to oauth.apache.org, which is the entity responsible for validating redirect URIs against a client-specific allowlist using exact string comparison. From the client perspective, the redirect_uri is passed as %s in the template URL. The actual value is determined by the asfquart framework. We cannot verify from this codebase: 1) Whether the authorization server (oauth.apache.org) validates redirect URIs with exact string matching, 2) What redirect URI value the asfquart framework substitutes, 3) Whether the client's registered redirect URIs are restricted to specific paths. If the authorization server does not perform exact string comparison on redirect URIs, an attacker could potentially redirect the authorization response (containing the code) to a malicious endpoint. Additionally, if the asfquart framework dynamically constructs the redirect_uri from the request Host header, there could be an open redirect vulnerability on the client side.

**Remediation:**

In create_app(), explicitly set the redirect_uri to a fixed value rather than relying on dynamic construction: FIXED_REDIRECT_URI = 'https://steve.apache.org/oauth/callback' and asfquart.generics.OAUTH_URL_INIT = (f'https://oauth.apache.org/auth?state=%s&redirect_uri={FIXED_REDIRECT_URI}'). Additionally, verify with ASF OAuth team that: 1) Redirect URIs are validated with exact string comparison, 2) No wildcard or pattern matching is used, 3) The client registration includes only the specific callback URL.

---

#### FINDING-250: response_mode parameter not explicitly specified in authorization request

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 10.4.12 |
| Files | v3/server/main.py:39 |
| Source Reports | 10.4.12.md |
| Related | None | **Description:**

The authorization request does not specify a response_mode parameter. The default response_mode for the authorization code flow is query (code returned as a query parameter in the redirect URI). For this application acting as a server-side confidential client using the authorization code flow, response_mode=query is acceptable. However, the authorization server should be configured to reject requests with response_mode=fragment or other modes that this client doesn't need. Since this application is not the authorization server, this requirement primarily applies to the ASF OAuth server configuration, which is outside the scope of the provided code. If the authorization server allows the client to use response_mode=fragment, an attacker could potentially craft authorization requests that deliver the code via the fragment, which would not be sent to the server and could be intercepted by client-side scripts.

**Remediation:**

This is a server-side configuration item for oauth.apache.org. From the client perspective, explicitly specify response_mode to make the intent clear: asfquart.generics.OAUTH_URL_INIT = ('https://oauth.apache.org/auth?state=%s&redirect_uri=%s&response_mode=query')

---

#### FINDING-251: Authorization Code Lifetime and One-Time Use Cannot Be Verified from Client Code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | N/A |
| ASVS sections | 10.4.2, 10.4.3 |
| Files | v3/server/main.py:42 |
| Source Reports | 10.4.2.md, 10.4.3.md |
| Related | None | **Description:**

These requirements apply to the authorization server (oauth.apache.org), which must ensure authorization codes: 1) Can only be used once (10.4.2), 2) Have a maximum lifetime of 10 minutes (L1/L2) or 1 minute (L3) (10.4.3). From the client perspective, the application receives the authorization code in the callback and immediately exchanges it via the token endpoint. There is no client-side code that stores or delays the use of authorization codes. The asfquart framework processes the callback and exchanges the code in the same request flow. The code lifetime and one-time use enforcement is entirely controlled by the external authorization server. The client-side behavior (immediate exchange) is appropriate and does not contribute to code lifetime or replay issues. If the authorization server allows codes to be valid for too long or permits code reuse, the window for code interception and replay attacks increases.

**Remediation:**

Verify with the ASF OAuth team that oauth.apache.org: 1) Enforces single-use authorization codes and revokes any tokens issued if the code is reused, 2) Authorization codes expire within 10 minutes (or 1 minute for L3). Ensure the asfquart framework does not cache or retry code exchanges. Consider implementing PKCE (RFC 7636) on the client side to mitigate code interception attacks. The client-side code is appropriate — no changes needed on the client.

---

#### FINDING-252: No user-facing interface for revoking OAuth tokens or active sessions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-613 |
| ASVS sections | 10.4.9 |
| Files | v3/server/pages.py |
| Source Reports | 10.4.9.md |
| Related | None | **Description:**

The application provides no user-facing interface for revoking OAuth tokens or active sessions. While the application has /profile and /settings pages, neither appears to offer session/token revocation capabilities. If a user's session or tokens are compromised (e.g., stolen OAuth tokens from malicious clients), the user has no way to revoke those tokens through the application's interface. They would need to go directly to oauth.apache.org to revoke tokens. Since this application is an OAuth client rather than an authorization server, the primary responsibility for token revocation UI lies with the authorization server (ASF OAuth). However, a well-designed relying party should provide a 'sign out of all sessions' or 'revoke access' capability, or at minimum link to the IdP's token management interface.

**Remediation:**

Add a session management page or a 'revoke all sessions' action that: 1. Invalidates local sessions, 2. Optionally calls the ASF OAuth revocation endpoint (if available), 3. Provides users visibility into active sessions

---

#### FINDING-253: User identification may not explicitly map to OIDC sub claim

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-287 |
| ASVS sections | 10.5.2 |
| Files | v3/server/pages.py:82-91 |
| Source Reports | 10.5.2.md |
| Related | FINDING-255 | **Description:**

The application identifies users via 's['uid']' from the session, which is used consistently across the codebase for all authorization decisions. This 'uid' field is the ASF username (Apache ID) which maps to the LDAP 'uid' attribute. While the code does use a stable identifier, it's not clear whether this maps to the OIDC 'sub' claim specifically. The comment 'Avoid OIDC' in main.py suggests the application may be receiving a custom user identifier from ASF's OAuth, which may or may not have the same non-reassignment guarantees as an OIDC 'sub' claim. However, given that the ASF OAuth system uses Apache IDs which are non-reassignable by ASF policy, this is a low-severity observation rather than a vulnerability. If ASF ever changes their OAuth to return reassignable identifiers, the application would not detect the difference.

**Remediation:**

Explicitly document the user identification strategy and add issuer scoping. Example: s = await asfquart.session.read(); if s: # User identified by ASF UID (equivalent to OIDC 'sub' claim); # ASF UIDs are non-reassignable per ASF policy; basic.update(uid=s['uid'], issuer='https://oauth.apache.org', name=s['fullname'], email=s['email'])

---

#### FINDING-254: No Documented Fallback for Missing Authentication Strength Information

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-1008 |
| ASVS sections | 6.8.4 |
| Files | v3/server/pages.py |
| Source Reports | 6.8.4.md |
| Related | None | **Description:**

No documented fallback approach exists for when the IdP doesn't provide authentication strength information. Per ASVS 6.8.4, if the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used. The codebase has no documentation or code indicating awareness of this requirement. The '### need general solution' comments on auth decorators suggest this is a known gap. Without a documented fallback, there's no clear security posture regarding authentication strength assumptions.

**Remediation:**

Create explicit documentation stating that the application assumes minimum authentication strength (single-factor) since ASF OAuth doesn't provide acr/amr claims. If ASF OAuth does provide these claims, implement validation. Document the fallback policy clearly in security documentation and code comments.

---

#### FINDING-255: Potential Multi-IdP Identity Spoofing Risk if Additional IdPs Added

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-287 |
| ASVS sections | 6.8.1 |
| Files | v3/server/pages.py:86-95, main.py:40-43 |
| Source Reports | 6.8.1.md |
| Related | FINDING-253 | **Description:**

The application uses a single IdP (ASF OAuth at https://oauth.apache.org/), so the multi-IdP identity spoofing scenario doesn't directly apply. The uid from the session is used consistently as the user identifier across all operations (election creation, voting, document access). Since there's only one IdP configured in main.py, the risk of cross-IdP spoofing is effectively eliminated by architecture. However, if additional IdPs were added in the future without namespacing user IDs (e.g., prefixing with IdP identifier), this would become a critical vulnerability.

**Remediation:**

The requirement is effectively satisfied by design through single-IdP architecture. If additional IdPs are added in the future, implement namespaced user identifiers (e.g., asf-oauth:username) to prevent cross-IdP spoofing.

---

#### FINDING-256: Self-disclosure of PersonDB synchronization status

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-203 |
| ASVS sections | 6.3.8 |
| Files | v3/server/pages.py:406-416 |
| Source Reports | 6.3.8.md |
| Related | None | **Description:**

The admin_page() function reveals whether an authenticated user's OAuth identity has been synchronized into the local PersonDB through a distinct error response ('Unknown Person'). While this only affects the currently authenticated user viewing their own status, it creates a distinguishable response pattern. The application delegates authentication entirely to ASF OAuth, so traditional login/registration/forgot-password enumeration vectors are not present. This finding is informational rather than exploitable for user enumeration since it only shows the user their own synchronization status.

**Remediation:**

No immediate action required. The distinct error only reveals the user's own synchronization status to themselves. This is a self-disclosure pattern with minimal security impact.

---

#### FINDING-257: Incomplete Data-Specific Access Rules Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | N/A |
| ASVS sections | 8.1.1 |
| Files | v3/docs/schema.md |
| Source Reports | 8.1.1.md |
| Related | None | **Description:**

Data-specific access rules for election isolation are partially documented. The documentation explains that elections use unique EIDs and that mayvote restricts voting access, but does not explicitly document that access to one election's data must not grant access to another election's data, nor does it specify the complete set of data-specific restrictions. Missing is an explicit statement that election management operations are restricted to the specific election's owner_pid or authz group members, and that data from different elections is isolated.

**Remediation:**

Add explicit data-level access documentation stating isolation requirements per election. Document that: (1) election management operations are restricted to the specific election's owner_pid or authz group members, (2) data from different elections is isolated (queries are scoped by EID), (3) access to one election's data does not grant access to another election's data, (4) the mayvote table enforces voter eligibility on a per-election, per-issue basis. Include this in a dedicated 'Data Isolation' section in schema.md.

---

#### FINDING-258: No Real-Time Notification for Election State Changes

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 8.3.2 |
| Files | v3/steve/election.py |
| Source Reports | 8.3.2.md |
| Related | None | **Description:**

When an election is closed, any voter with the voting page already loaded can still submit their form, which will fail with a state error. The authorization change (election closed = no more voting) IS applied immediately in the database (add_vote checks self.S_OPEN), but there's no mitigating control to alert voters mid-session that the election state has changed. This is partially mitigated by _all_metadata(self.S_OPEN) in add_vote which validates state on every vote submission, ensuring closed elections immediately reject votes. However, the user experience is poor as voters may spend time filling out ballots only to have submission fail.

**Remediation:**

Implement a real-time notification mechanism to alert active voters when election state changes occur. Options include: (1) WebSocket connection to push state change notifications to active voting pages, (2) periodic AJAX polling to check election state and display warning banner if state changed, (3) optimistic UI validation before form submission to check current state and warn user before they invest time in ballot completion. This improves user experience and prevents wasted effort on ballots that will be rejected due to state changes.

---

#### FINDING-259: Session Identity Correctly Used - No Intermediary Permission Escalation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 8.3.3 |
| Files | v3/server/pages.py, v3/steve/election.py |
| Source Reports | 8.3.3.md |
| Related | None | **Description:**

The application is a monolithic server with direct database access. There are no service-to-service calls, no intermediary services, and no token forwarding patterns. All operations use result.uid (from the authenticated session) directly. The application correctly uses the originating subject's identity for all permission decisions. No findings detected for this requirement in the current architecture. This is documented as a positive finding to confirm compliance with ASVS 8.3.3.

**Remediation:**

No remediation required. The application correctly uses the originating subject's identity for all permission decisions. Continue to maintain direct identity propagation from session to data layer. If the architecture evolves to include service-to-service calls or intermediary services, ensure that the originating subject's identity is propagated and used for all authorization decisions rather than the intermediary's permissions.

---

#### FINDING-260: Logout functionality nested in dropdown menu reduces visibility

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 7.4.4 |
| Files | v3/server/templates/header.ezt:31-39 |
| Source Reports | 7.4.4.md |
| Related | None | **Description:**

The logout functionality exists but is nested within a dropdown menu that requires two clicks to access (click username dropdown, then click "Sign Out"). While this is a common UI pattern, it reduces visibility. The requirement states "easy and visible access" — a nested dropdown partially meets this but may fail strict interpretation. Users under session-hijacking attack may not quickly find the logout option.

**Remediation:**

While the current implementation follows common web patterns (similar to GitHub, GitLab), consider adding a visible logout icon/button directly in the navbar for higher visibility. Add a dedicated logout link with an icon directly in the navbar navigation items for immediate visibility without requiring dropdown interaction.

---

#### FINDING-261: No documentation of expected session lifetime behavior between RP and IdP

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 7.6.1 |
| Files | v3/server/pages.py, v3/server/templates/header.ezt |
| Source Reports | 7.6.1.md |
| Related | None | **Description:**

There is no documentation of the expected session lifetime behavior between this application (RP) and the ASF SSO provider (IdP). The login (/auth?login=/) and logout (/auth?logout=/) endpoints delegate to asfquart but session lifetime policies are not explicitly configured or documented in the application code. Without documented session behavior, it's impossible to verify correct implementation. Operations teams cannot validate that session termination at the IdP properly propagates to this application, and vice versa.

**Remediation:**

Document and configure session behavior explicitly in application configuration. Define SESSION_LIFETIME (max session duration), IDP_REAUTH_INTERVAL (re-verify with IdP interval), IDLE_TIMEOUT, and document that logout at /auth?logout=/ terminates both RP session and IdP session (single logout). Example: APP.config.update(SESSION_LIFETIME=3600, IDP_REAUTH_INTERVAL=1800, IDLE_TIMEOUT=900).

---

#### FINDING-262: No Session Creation Notification to User

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS sections | 7.6.2 |
| Files | v3/server/pages.py:69-100 |
| Source Reports | 7.6.2.md |
| Related | None | **Description:**

After OAuth callback creates a new session, there is no mechanism to notify users or provide visibility into session creation events. Per ASVS 7.6.2's intent (derived from NIST 800-63C), users should be aware when sessions are created on their behalf. The data flow: OAuth callback completes successfully → New session created in asfquart framework → User redirected to protected page → No indication that new session was created → User may be unaware of active session state. Users lack awareness of when sessions are created, making it difficult to detect unauthorized session creation. This reduces user ability to identify potential security issues and does not align with the principle of informed consent for session establishment.

**Remediation:**

Implement session creation notifications in the OAuth callback handler. After successful session creation, display a flash message indicating 'New session created. If you did not initiate login, please contact support.' Store session creation timestamp in session data. Add a session management page at /account/sessions that displays active sessions and creation timestamps, allowing users to view and manage their sessions.

---

#### FINDING-263: Missing URL encoding in JavaScript form action construction

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | N/A |
| ASVS sections | 1.2.2 |
| Files | v3/server/templates/manage.ezt:339, v3/server/templates/manage.ezt:348, v3/server/templates/manage.ezt:357 |
| Source Reports | 1.2.2.md |
| Related | None | **Description:**

The issueId JavaScript variable (passed from server-rendered onclick attributes) is concatenated directly into a URL path without encoding in manage.ezt template. While IIDs are cryptographically generated and thus safe in practice, the pattern doesn't apply URL encoding to untrusted data used in URL construction. Impact is low because IIDs are server-generated alphanumeric values with no user control over their format.

**Remediation:**

Apply encodeURIComponent to all URL path parameters: form.action = `/do-edit-issue/[eid]/${encodeURIComponent(issueId)}`;

---

#### FINDING-264: Global window function assignments could be overridden via DOM clobbering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS sections | 3.2.3 |
| Files | v3/server/templates/vote-on.ezt |
| Source Reports | 3.2.3.md |
| Related | None | **Description:**

Multiple functions are assigned to the window object (openSTVModal, saveSTVRanking, clearSTVRanking, bulkVote, clearYNAVotes, toggleDescription, toggleAllDescriptions, submitVotes). If unescaped HTML content contains named elements like `<a id="submitVotes" href="https://evil.com">`, and JavaScript code later accesses `window.submitVotes` without type checking, the element reference could shadow the function. Impact is Low because modern browsers resolve `window.X` to function assignments over named elements when both exist. However, if the function assignment fails (e.g., due to a syntax error caused by XSS in `STV_CANDIDATES`), the named element would be accessible via `window.X`.

**Remediation:**

Add type checking before invocation: `const submitFn = window.submitVotes; if (typeof submitFn !== 'function') { console.error('submitVotes has been overridden'); return; }`

---

#### FINDING-265: JSON Endpoints Use Content-Type That Triggers Preflight But Lack Explicit CORS Policy

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 3.5.2 |
| Affected File(s) | v3/server/pages.py:360-366 |
| Source Report(s) | 3.5.2.md |
| Related Finding(s) | - | **Description:**

The client sends Content-Type: application/json (from manage.ezt line 251), which is non-safelisted and would trigger a CORS preflight. However, without explicit CORS configuration visible in the code, it is unclear whether the server properly rejects unauthorized origins during the OPTIONS preflight. If a permissive CORS policy were added in the future (e.g., Access-Control-Allow-Origin: *), these endpoints would become vulnerable. Protection is implicit rather than explicit.

**Remediation:**

Add explicit CORS policy configuration that restricts allowed origins, and validate Content-Type server-side. Explicitly verify Content-Type is application/json and reject with 415 if not. Example: if quart.request.content_type != 'application/json': quart.abort(415, 'Content-Type must be application/json')

---

#### FINDING-266: Unable to Verify Hostname Separation — Single Application Serves All Functionality

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 3.5.4 |
| Affected File(s) | v3/server/pages.py:entire file |
| Source Report(s) | 3.5.4.md |
| Related Finding(s) | - | **Description:**

The application serves administrative functions (/admin, /manage), voter functions (/voter, /vote-on), static files (/static), and document files (/docs) all from the same application instance. There is no evidence of: separate hostnames for admin vs. voter functionality, separate origins for static content, or domain-based cookie scoping. The code uses a single APP instance with all routes registered in one file, suggesting a single-origin deployment. If a vulnerability (e.g., XSS) exists in one area of the application, it can access cookies and data from all other areas since they share the same origin. Administrative session cookies are accessible from voter-facing pages and vice versa.

**Remediation:**

Consider separating administrative and voter functionality onto different subdomains: admin.steve.example.com — Election management, vote.steve.example.com — Voter interface, static.steve.example.com — Static assets (with restrictive CSP).

---

#### FINDING-267: No Global X-Content-Type-Options: nosniff Header to Prevent Content-Type Sniffing

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 3.5.7 |
| Affected File(s) | v3/server/pages.py:all endpoints |
| Source Report(s) | 3.5.7.md |
| Related Finding(s) | - | **Description:**

The application does not set the X-Content-Type-Options: nosniff header on any response. No after-request handler or middleware adds this header globally. Without this header, browsers may MIME-sniff responses and interpret non-JavaScript content as executable scripts, creating potential XSSI exploitation vectors for non-script responses. This is primarily a defense-in-depth gap since authenticated HTML pages won't parse as valid JavaScript, but it represents a missing security control that could prevent certain attack variants.

**Remediation:**

Add a global after-request handler to set the X-Content-Type-Options: nosniff header on all responses:

@APP.after_request
async def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

---

#### FINDING-268: No Cookie Size Validation Before Writing Cookies

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 3.3.5 |
| Affected File(s) | v3/server/pages.py:Application-wide |
| Source Report(s) | 3.3.5.md |
| Related Finding(s) | - | **Description:**

The application does not explicitly validate that cookie name and value length combined do not exceed 4096 bytes before writing cookies. While unlikely in normal operation (flash messages are consumed on next page load and session data is minimal), a rapid sequence of operations or very long election titles in flash messages could theoretically push the cookie size near the limit. If cookie exceeds 4096 bytes, the browser silently drops the cookie and the user loses their session.

**Remediation:**

Add middleware to check cookie size before sending:

@app.after_request
async def check_cookie_size(response):
    for header_name, header_value in response.headers:
        if header_name.lower() == 'set-cookie':
            cookie_content = header_value.split(';')[0]
            if len(cookie_content.encode('utf-8')) > 4096:
                _LOGGER.warning(f'Cookie exceeds 4096 bytes: {len(cookie_content)} bytes')
                # Handle gracefully - truncate flash messages or use server-side sessions
    return response

---

#### FINDING-269: Encrypted Client Hello (ECH) Not Configured

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 12.1.5 |
| Affected File(s) | v3/server/main.py, v3/server/config.yaml.example |
| Source Report(s) | 12.1.5.md |
| Related Finding(s) | - | **Description:**

No ECH (Encrypted Client Hello) configuration exists anywhere in the codebase. Without ECH, the Server Name Indication (SNI) field in the TLS ClientHello is transmitted in plaintext. This allows network observers (ISPs, network administrators, or attackers performing passive surveillance) to determine which hostname the client is connecting to, even though the payload is encrypted. This is a metadata privacy issue. ECH is a TLS 1.3 extension (RFC 9578, formerly ESNI) that is still relatively new and requires DNS infrastructure support (HTTPS/SVCB DNS records with ECH configuration), server-side TLS library support (OpenSSL 3.x+ with ECH patches, or BoringSSL). Python's ssl module does not natively support ECH configuration as of Python 3.12.

**Remediation:**

This is a Level 3 requirement. Implementation requires: 1. Deploy behind a reverse proxy that supports ECH (e.g., Cloudflare, nginx with ECH patches) 2. Publish ECH keys via DNS HTTPS records 3. Document ECH configuration in deployment guides. Example DNS record for ECH support: _443._https.steve.apache.org. IN HTTPS 1 . ech="&lt;base64-encoded ECH config&gt;"

---

#### FINDING-270: LDAP Connection Security Not Verified in Architecture

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 12.3.1 |
| Affected File(s) | v3/docs/quickstart.md:38-44, v3/ARCHITECTURE.md |
| Source Report(s) | 12.3.1.md |
| Related Finding(s) | - | **Description:**

The system connects to an LDAP server for user data loading via the asf-load-ldap.py script. There is no documentation indicating whether: 1) LDAPS (LDAP over TLS) or StartTLS is used, 2) Certificate validation is performed, 3) Credentials in bind.txt are transmitted securely. If LDAP connections use plaintext LDAP (port 389) without StartTLS, credentials and user data are transmitted unencrypted.

**Remediation:**

Ensure the LDAP loading script uses LDAPS (port 636) or StartTLS with certificate validation, and document this requirement. Verify OAuth Client TLS by auditing the asfquart library to confirm certificate validation is enabled and cannot be accidentally disabled. Add certificate validation for LDAP in asf-load-ldap.py.

---

#### FINDING-271: No Documented Enforcement of TLS Between Application and Reverse Proxy

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 12.3.3 |
| Affected File(s) | v3/ARCHITECTURE.md, v3/server/config.yaml.example:22 |
| Source Report(s) | 12.3.3.md |
| Related Finding(s) | - | **Description:**

The architecture states a proxy sits in front of the application server. The communication between the proxy and the application backend is not explicitly configured to use TLS. If the TLS configuration is left blank (as the config allows), the proxy-to-application link would be unencrypted. In a typical deployment: External client → Proxy (TLS terminated) → Application server (plain HTTP on port 58383). This internal hop may be unencrypted if the application's certfile/keyfile are not set. If the proxy and application are on different hosts or cross a network boundary, internal traffic between them could be intercepted. This is a lower severity concern if both are on the same host/container.

**Remediation:**

Document that TLS must be configured on the application even when behind a proxy (unless on the same localhost). Or enforce TLS between proxy and backend by requiring certfile and keyfile in production configuration: server: port: 58383, certfile: internal-service.pem (Required even behind proxy), keyfile: internal-service-key.pem

---

#### FINDING-272: No Mutual TLS (mTLS) or Strong Service Authentication for Internal Communications

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 12.3.5 |
| Affected File(s) | v3/ARCHITECTURE.md, v3/server/main.py |
| Source Report(s) | 12.3.5.md |
| Related Finding(s) | - | **Description:**

The architecture is primarily a monolithic application (Quart web server + SQLite file database) with minimal service-to-service communication. However, there are identifiable communication paths: 1. Reverse proxy → Application server: No mutual TLS; the proxy authenticates to the backend only via network connectivity (no client certificate) 2. Application → OAuth provider (oauth.apache.org): Standard TLS, no client certificate authentication 3. Application → LDAP server: Authentication via bind credentials in bind.txt, no evidence of mTLS. The system does not implement: TLS client certificate authentication, Service mesh, API keys or tokens for service-to-service authentication, or Replay attack prevention for internal calls. At Level 3, the absence of mutual TLS means internal services cannot cryptographically verify each other's identity. An attacker with network access could potentially impersonate internal services. However, given the monolithic architecture with SQLite (no network database), the attack surface is limited.

**Remediation:**

For a Level 3 deployment, add mTLS support in main.py by creating an SSL context with client certificate authentication enabled. Load server certificate chain and internal CA certificate, set verify_mode to ssl.CERT_REQUIRED to require client certificates, and apply this context when running the app. Alternatively, consider implementing a service mesh (e.g., Istio, Linkerd) if the architecture evolves to microservices.

---

#### FINDING-273: Vote Type Enumeration Not Documented Outside of Code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 2.1.1 |
| Affected File(s) | v3/docs/schema.md |
| Source Report(s) | 2.1.1.md |
| Related Finding(s) | - | **Description:**

The schema documentation mentions yna and stv as vote types but does not document the complete set of valid values, how they are validated, or their expected input/output formats. The schema.md states: type (TEXT, NOT NULL): The voting mechanism. Currently supports: yna: Yes/No/Abstain voting, stv: Single Transferable Vote. Additional types may be added in the future. The enumeration exists partially in documentation and is enforced in code (vtypes.TYPES), but the validation rules for each type's vote data are not documented.

**Remediation:**

Document the expected vote input format for each type and the validation rules that apply.

---

#### FINDING-274: Election Creation Has No Secondary Approval

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 2.3.5 |
| Affected File(s) | v3/server/pages.py:410 |
| Source Report(s) | 2.3.5.md |
| Related Finding(s) | - | **Description:**

While creation itself is not destructive, it's the entry point for the entire election lifecycle. A PMC member could create elections without organizational awareness. This is lower severity as elections must still be opened and closed, and the R.pmc_member requirement provides some gatekeeping.

**Remediation:**

Consider implementing a secondary approval workflow for election creation to ensure organizational awareness and oversight, particularly for high-impact elections.

---

#### FINDING-275: Vote Table Schema Lacks Timestamp for Timing Analysis

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 2.4.2 |
| Affected File(s) | v3/schema.sql:148-168 |
| Source Report(s) | 2.4.2.md |
| Related Finding(s) | - | **Description:**

The vote table schema lacks a created_at timestamp column, preventing timing-based analysis or enforcement at the database level. This means the application cannot retroactively detect automated voting patterns, cannot implement minimum interval checks at the database level, and audit capabilities are limited.

**Remediation:**

Add a created_at INTEGER column with DEFAULT (strftime('%s', 'now')) to the vote table and implement a database trigger prevent_rapid_revote to enforce minimum time intervals between votes at the database level.

---

#### FINDING-276: Regex Applied to User-Controlled Content Without Input Length Limit

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 1.3.12 |
| Affected File(s) | v3/server/pages.py:56-62 |
| Source Report(s) | 1.3.12.md |
| Related Finding(s) | - | **Description:**

The rewrite_description() function applies a regex pattern r'doc:([^\s]+)' to issue.description content without a documented length limit on the description field. While the regex itself is not vulnerable to ReDoS (it uses a simple non-overlapping character class with linear O(n) complexity and no nested quantifiers or ambiguous matching), an extremely long description (megabytes) could cause momentary CPU usage during the linear scan. This is a standard DoS concern rather than exponential backtracking. The description field is admin-provided content (election managers create issues via do_add_issue_endpoint() and do_edit_issue_endpoint()), not arbitrary external users.

**Remediation:**

Implement maximum length constraints on description and title fields in do_add_issue_endpoint() and do_edit_issue_endpoint() to prevent resource exhaustion. As the application grows, consider integrating a static analysis tool (e.g., regexploit) into CI/CD to catch ReDoS-vulnerable patterns in new code.

---

#### FINDING-277: Election title used in flash messages and logs without length restriction

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 1.3.3 |
| Affected File(s) | v3/server/pages.py:476-479 |
| Source Report(s) | 1.3.3.md |
| Related Finding(s) | - | **Description:**

The election creation endpoint accepts form.title without length validation and uses it in logs and flash messages. No length validation on form.title allows arbitrarily long strings to be stored and rendered. While not directly exploitable for code injection (SQL is parameterized), extremely long values could cause display issues or log flooding.

**Remediation:**

Add input length validation with a reasonable maximum (e.g., 200 characters): MAX_TITLE_LENGTH = 200; if not form.title or len(form.title) > MAX_TITLE_LENGTH: await flash_danger('Title is required and must be under 200 characters.'); return quart.redirect('/admin', code=303).

---

#### FINDING-278: User-controlled data passed to EZT template variables without explicit escaping (mitigated by EZT design)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 1.3.7 |
| Affected File(s) | v3/server/pages.py:243, v3/server/pages.py:666 |
| Source Report(s) | 1.3.7.md |
| Related Finding(s) | - | **Description:**

User-controlled data like eid from URL parameters is passed to EZT template variables without explicit escaping. EZT (EaZyTemplate) is a restricted template engine that substitutes variable values as literal strings without re-interpreting template syntax. Unlike Jinja2 or Mako, EZT's [varname] directives do not evaluate expressions—they output the string value directly. Therefore, even if eid contained [include /etc/passwd], EZT would output it as literal text. Template injection is not achievable via EZT variable substitution. However, the lack of explicit HTML escaping means this is an XSS concern rather than a template injection concern.

**Remediation:**

While template injection is mitigated by EZT's design, documenting this architectural decision and ensuring templates are never loaded from user-controlled paths provides defense-in-depth. Ensure all templates are loaded from the TEMPLATES directory only and never construct template content from user input: assert template_path.resolve().is_relative_to(TEMPLATES)

---

#### FINDING-279: Unsanitized filenames extracted from issue descriptions in rewrite_description()

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS Section(s) | 5.3.2 |
| Affected File(s) | v3/server/pages.py:49-56 |
| Source Report(s) | 5.3.2.md |
| Related Finding(s) | FINDING-169 | **Description:**

The rewrite_description() function extracts filenames from issue descriptions using a regex pattern 'doc:([^\s]+)' and constructs URL paths without sanitization. While filenames originate from authorized users (committers storing issue descriptions), a malicious committer could craft a description containing path traversal sequences in the doc: pattern. A committer could store an issue description containing 'doc:../../sensitive-file' which generates a link to '/docs/&lt;iid&gt;/../../sensitive-file'. When a voter clicks this link, it would be handled by serve_doc() where framework-level safe_join would prevent traversal, but the link itself could confuse users or be used in social engineering.

**Remediation:**

Validate extracted filenames against a safe pattern (e.g., ^[a-zA-Z0-9][a-zA-Z0-9._-]*$) and HTML-encode output. Replace invalid references with placeholder text like '[invalid doc reference]'. Use markupsafe.escape() for safe HTML rendering.

---

#### FINDING-280: Unencoded filenames in HTML output breaking document structure

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 5.4.2 |
| Affected File(s) | v3/server/pages.py:49-56 |
| Source Report(s) | 5.4.2.md |
| Related Finding(s) | - | **Description:**

The `rewrite_description()` function constructs HTML `<a>` tags with filenames extracted from issue descriptions without HTML encoding. If a filename contains HTML special characters (`"`, `<`, `>`, `&`), it could break the document structure of the rendered page. If an issue description (set by a committer) contains `doc:file"onmouseover="alert(1)`, the resulting HTML would inject event handlers, breaking the HTML attribute context. Exploitation requires a malicious committer.

**Remediation:**

Use `markupsafe.escape()` for display text and `urllib.parse.quote()` for href attributes. Example: `safe_display = escape(filename)` and `safe_href = urllib.parse.quote(filename, safe='')` then construct link as `f'<a href="/docs/{issue.iid}/{safe_href}">{safe_display}</a>'`

---

#### FINDING-281: No File Content-Type Validation on Document Serving

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 5.4.3 |
| Affected File(s) | v3/server/pages.py:614 |
| Source Report(s) | 5.4.3.md |
| Related Finding(s) | - | **Description:**

The send_from_directory function infers MIME type from the file extension without restricting allowed file types. This allows any file type to be served, including HTML files (which could contain JavaScript for XSS) or executable content that could be rendered inline by browsers. Without content type restrictions, a file named exploit.html containing JavaScript could be served with text/html content type, enabling stored XSS attacks against voters who view the document in their browser. Browsers may execute JavaScript or other active content in files served with permissive content types. SVG files could contain embedded JavaScript that executes in the browser context.

**Remediation:**

Force safe content disposition by adding as_attachment=True parameter to send_from_directory to force download rather than inline rendering. Add security headers including X-Content-Type-Options: nosniff to prevent MIME-type sniffing and Content-Security-Policy: default-src 'none' to restrict content execution. Implement a whitelist of allowed file extensions (.pdf, .txt, .md). Consider serving documents from a separate domain to isolate them from the main application context.

---

#### FINDING-282: No explicit HTTP method restrictions visible

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.1.4 |
| Affected File(s) | v3/server/api.py:1-21 |
| Source Report(s) | 4.1.4.md |
| Related Finding(s) | - | **Description:**

The file defines no routes and contains no method restriction configuration. While the `asfquart` framework likely provides method-specific routing (e.g., `@app.route('/path', methods=['GET', 'POST'])`), there is no visible global rejection of unexpected methods (e.g., TRACE, TRACK, DELETE on endpoints that shouldn't support them) nor a catch-all handler to return 405 for undefined methods. If the framework's default behavior allows arbitrary HTTP methods on endpoints (e.g., TRACE for XST attacks, or unexpected method handling), unused methods may be accessible.

**Remediation:**

Add global method restriction or verify Quart/asfquart defaults reject unsupported methods with 405. Example implementation: Add a @APP.before_request handler that checks if request.method is in an allowed set of methods (GET, POST, OPTIONS, HEAD) and returns 405 for others. Ensure TRACE and TRACK methods are blocked at the server level.

---

#### FINDING-283: No per-message digital signature mechanism observed

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.1.5 |
| Affected File(s) | v3/server/api.py:1-21 |
| Source Report(s) | 4.1.5.md |
| Related Finding(s) | - | **Description:**

For a voting application handling highly sensitive transactions (vote casting, election management), there is no visible implementation of per-message digital signatures (e.g., HTTP Message Signatures RFC 9421, JWS, or HMAC-based request signing) that would provide integrity assurance beyond transport-layer TLS. Without per-message signatures, if TLS is terminated at a proxy and internal traffic is unencrypted, or if there are intermediary systems, message integrity cannot be independently verified. For a voting system, this means vote submissions could theoretically be tampered with in transit between internal components.

**Remediation:**

For highly sensitive operations (vote submission, election state changes), implement request signing using HMAC or digital signatures. Example implementation: Add a before_request handler that verifies X-Signature header using HMAC with SHA256, comparing against the request body. Ensure hmac.compare_digest is used for timing-safe comparison. Consider implementing HTTP Message Signatures RFC 9421, JWS, or HMAC-based request signing for vote submissions and election state changes.

---

#### FINDING-284: Date/time operations use naive datetimes without timezone awareness

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.2.2 |
| Affected File(s) | v3/server/pages.py:86, v3/server/pages.py:571, v3/server/bin/tally.py:86, v3/server/pages.py:97 |
| Source Report(s) | 16.2.2.md |
| Related Finding(s) | - | **Description:**

All datetime operations use naive (timezone-unaware) datetime objects. While not directly a logging issue, this indicates that the application lacks UTC discipline, making it likely that log timestamps (when configured) would also use local time. Affected operations include datetime.datetime.now().timestamp() at line 571, datetime.datetime.fromtimestamp(election.close_at) at line 86, and datetime.datetime.fromisoformat(date_str) at line 97 in pages.py.

**Remediation:**

Use timezone-aware datetime objects throughout the application. Import from datetime import datetime, timezone and use datetime.now(timezone.utc) and datetime.fromtimestamp(ts, tz=timezone.utc) for all datetime operations.

---

#### FINDING-285: Tally script outputs decrypted vote results to stdout without log governance

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.2.3, 16.4.2 |
| Affected File(s) | v3/server/bin/tally.py:129-135 |
| Source Report(s) | 16.2.3.md, 16.4.2.md |
| Related Finding(s) | - | **Description:**

The tally script outputs decrypted election results (including voter identities and vote tallies) directly to stdout. While this is the intended functionality of a CLI tool, it represents sensitive data being output to an undocumented channel. There is no logging of WHERE this output goes or who captures it. Without documentation of how tally outputs should be secured, results could be inadvertently captured in shell history, piped to insecure files, or logged by terminal multiplexers.

**Remediation:**

Add audit logging when results are output: `_LOGGER.info(f'TALLY_OUTPUT election_id={election.eid} format={output_format} issues={len(results)} voters={len(all_voters)}')`. Document in logging inventory that tally output is to stdout and must be handled per data classification policy.

---

#### FINDING-286: No request/correlation ID for tracing multi-step operations

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.2.4 |
| Affected File(s) | v3/server/pages.py:all endpoint handlers |
| Source Report(s) | 16.2.4.md |
| Related Finding(s) | - | **Description:**

When a user submits votes for multiple issues in a single request, each vote generates a separate log entry with no shared correlation ID. A log processor cannot determine that these entries belong to the same HTTP request without temporal proximity heuristics. This could complicate forensic investigation of specific voting sessions.

**Remediation:**

Generate request-scoped correlation ID using uuid. Example: import uuid; request_id = str(uuid.uuid4())[:8]; for iid, votestring in votes.items(): _LOGGER.info(f'request_id={request_id} User[U:{result.uid}] voted on issue[I:{iid}] in election[E:{election.eid}]')

---

#### FINDING-287: PersonDB Lookup Failure Handling

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.3.4 |
| Affected File(s) | v3/server/pages.py:303-313 |
| Source Report(s) | 16.3.4.md |
| Related Finding(s) | - | **Description:**

When a PersonNotFound exception occurs, the handler returns a 404 but doesn't log this unexpected condition. An authenticated user not found in PersonDB is an anomalous condition that could indicate a configuration issue or data integrity problem.

**Remediation:**

Add structured logging when PersonNotFound exception occurs for an authenticated user. Log the authenticated UID, context, and timestamp as this represents an anomalous security-relevant condition.

---

#### FINDING-288: Debug print statements expose form data to process output

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 16.5.1 |
| Affected File(s) | v3/server/pages.py:499, v3/server/pages.py:524 |
| Source Report(s) | 16.5.1.md |
| Related Finding(s) | - | **Description:**

Debug `print()` statements output raw form data (which could include issue titles, descriptions, and other user-supplied content) to stdout. While not directly returned to other users, if stdout is captured by a process manager or accessible logging system, it could expose data to unauthorized parties. This is stdout output, not response body. However, it indicates development debugging left in production code.

**Remediation:**

Remove debug print statements or replace with appropriate log level: `_LOGGER.debug(f'Form data received for issue creation: keys={list(form.keys())}')`

---

#### FINDING-289: SQLite database access lacks authentication mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 13.2.1 |
| Affected File(s) | v3/steve/election.py:35-37, v3/steve/persondb.py:25-26 |
| Source Report(s) | 13.2.1.md |
| Related Finding(s) | - | **Description:**

Communications between application components and the SQLite database do not use any authentication mechanism. The database is accessed via file path with no credentials. SQLite is a file-based database and does not natively support user authentication. Access control depends entirely on file system permissions. This is classified as LOW because SQLite's embedded nature means it runs in-process and is not a network service. However, the requirement applies to "data layers" which includes databases. The application relies solely on OS file permissions rather than cryptographic authentication. Data Flow: Application process → file system → steve.db → no authentication layer

**Remediation:**

For SQLite specifically: Document that file system permissions serve as the authentication mechanism; Ensure the database file has restrictive permissions (e.g., 0600, owned by the application service account); Consider SQLite encryption extensions (e.g., SQLCipher) for data-at-rest protection; If migrating to a networked database, implement service account authentication with short-term credentials

---

#### FINDING-290: Email service communication lacks documented authentication configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 13.2.1 |
| Affected File(s) | v3/server/bin/mail-voters.py:67-73 |
| Source Report(s) | 13.2.1.md |
| Related Finding(s) | - | **Description:**

The email sending function does not show explicit SMTP authentication. The comment '# Add other parameters as needed (e.g., auth, headers)' suggests authentication is not yet configured. The asfpy.messaging library may handle this internally, but it is not documented or visible in this codebase. If SMTP authentication is not configured, the application may be relying on network-level trust (e.g., sending from within the same network as the mail relay) which could be spoofed or abused.

**Remediation:**

Document SMTP authentication method and ensure it uses short-term tokens or certificate-based authentication rather than static passwords.

---

#### FINDING-291: CLI scripts run without documented privilege requirements

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Section(s) | 13.2.2 |
| Affected File(s) | v3/server/bin/create-election.py, v3/server/bin/mail-voters.py |
| Source Report(s) | 13.2.2.md |
| Related Finding(s) | - | **Description:**

Command-line utilities that directly modify the database or send emails have no documented OS-level privilege requirements or access controls. Scripts create-election.py (can create elections, add voters) and mail-voters.py (can read voter emails and send messages) have the same database privileges as the web server but no authentication or authorization layer. Anyone with shell access to the server can create elections, modify voter rolls, or send emails to voters without audit trail beyond system-level logging.

**Remediation:**

Document required OS permissions and consider adding authentication checks or restricted execution contexts for CLI tools.

---

#### FINDING-292: No connection management parameters (timeouts, retries, max connections) defined in configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.2.6 |
| Affected File(s) | v3/server/config.yaml.example:entire file scope |
| Source Report(s) | 13.2.6.md |
| Related Finding(s) | - | **Description:**

The configuration schema does not define connection management parameters for any backend service. For the SQLite database (steve.db), connection parameters like busy timeout and journal mode should be configured. For external services (OAuth, LDAP), timeout and retry parameters prevent cascading failures. Without explicit connection configuration: slow external services (OAuth, LDAP) could cause request handler timeouts, connection leaks could exhaust file descriptors, no circuit-breaker behavior when backends are unavailable, and default retry strategies may cause thundering herd problems.

**Remediation:**

Extend config.yaml schema to include connection configuration for backend services:

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
    max_parallel: 10
    
  ldap:
    host: "ldaps://ldap.apache.org"
    connect_timeout_s: 5
    search_timeout_s: 10
    max_retries: 2
    pool_size: 5
    pool_lifetime_s: 300
    behavior_on_exhaustion: "block"

Implement these parameters in the HTTP client and LDAP connection code. Add application-layer URL validation for outbound requests against a configured allowlist. Implement health checks for backend connectivity.

---

#### FINDING-293: No explicit exclusion of source control metadata in deployment configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 13.4.1 |
| Affected File(s) | main.py:49 |
| Source Report(s) | 13.4.1.md |
| Related Finding(s) | - | **Description:**

No deployment manifest, Dockerfile, or `.dockerignore` is present in the audited code to explicitly exclude `.git`, `.svn`, or other source control metadata directories from production deployments. The application does set `static_folder=None` in `main.py:create_app()`, which prevents Quart from serving arbitrary files from a static directory. However, there is no explicit deployment configuration ensuring source control metadata is excluded. If a deployment pipeline does not strip `.git` directories and the reverse proxy (mentioned in config.yaml.example comments) does not block access to these paths, source code history, credentials in commits, and internal structure could be exposed.

**Remediation:**

Add explicit deployment artifacts (`.dockerignore`, deployment script, or reverse proxy rules) that exclude `.git` and `.svn` from production:

yaml
# In a .dockerignore or deployment exclusion list:
.git
.svn
.hg
*.pyc
__pycache__


Or add reverse proxy rules:
apache
# Apache
&lt;DirectoryMatch "^\.(git|svn|hg)"&gt;
    Require all denied
&lt;/DirectoryMatch&gt;

---

#### FINDING-294: Documentation and monitoring endpoints cannot be verified due to missing module visibility

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 13.4.5 |
| Affected File(s) | v3/server/main.py:52-53 |
| Source Report(s) | 13.4.5.md |
| Related Finding(s) | - | **Description:**

The `pages` and `api` modules are imported but their contents are not available for audit. Without visibility into these modules, we cannot verify whether documentation endpoints (e.g., Swagger/OpenAPI), health check endpoints, or monitoring endpoints are exposed without access control. If the `api` module exposes auto-generated documentation (common in frameworks using decorators) or if monitoring/health endpoints exist without authentication, internal API structure and system health information could be disclosed to unauthorized users.

**Remediation:**

Ensure that any documentation or monitoring endpoints in the `pages` and `api` modules are: (1) Protected by authentication/authorization, (2) Disabled in production via configuration, (3) Or only bound to internal network interfaces. Example: conditional endpoint registration using `if not app.cfg.server.get('production', True): import api_docs` to only load docs in non-production.

#### FINDING-295: 🔵 Example configuration reveals development tooling information

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.4.6 |
| Files | v3/server/config.yaml.example |
| Source Reports | 13.4.6.md |
| Related Findings | - | **Description:**

The example configuration uses specific certificate filenames (`localhost.apache.org+3.pem`) that reveal the use of `mkcert` tool (which generates certificates in this naming format). While this is an example file, if used as a template, it could leak tooling information. Impact is minimal — reveals development tooling choice but no exploitable information.

**Remediation:**

Use generic certificate filenames in example configuration files (e.g., `server.pem`, `server-key.pem`) to avoid revealing development tooling choices.

---

#### FINDING-296: 🔵 Sensitive Files Co-Located in Application Directory

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 13.4.7 |
| Files | v3/server/config.yaml.example, v3/server/main.py:27-28, v3/server/main.py:48 |
| Source Reports | 13.4.7.md |
| Related Findings | - | **Description:**

The application directory (THIS_DIR) contains or is configured to contain config.yaml (database credentials, server configuration), steve.db (database file), certs/*.pem and certs/*-key.pem (TLS private keys), and *.py (application source code). While static_folder=None prevents serving these via the framework's default handler, the co-location means a single misconfiguration (e.g., accidentally setting static_folder='.') could expose all sensitive files. This is a defense-in-depth violation where a single-point failure in static file configuration could expose credentials, keys, and source code.

**Remediation:**

Store sensitive files outside the application directory. Move database to /var/lib/steve/steve.db and certificates to /etc/ssl/private/steve. Update path resolution in main.py to use separate directories for sensitive data. Add .dockerignore or deployment script that excludes sensitive files from the web-accessible directory.

---

#### FINDING-297: 🔵 Database Operations Not Isolated From Web-Serving Process

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 15.2.5 |
| Files | v3/steve/election.py:43 |
| Source Reports | 15.2.5.md |
| Related Findings | - | **Description:**

SQLite database access occurs directly in the web-serving process. The database file (containing encrypted votes, salts, and opened_keys) is accessible to the same process that handles untrusted HTTP input. A path traversal or file inclusion vulnerability elsewhere could compromise the database directly.

**Remediation:**

Consider using a dedicated database access layer (microservice or separate process) that mediates all database operations, limiting the web process to API calls rather than direct file access.

---

#### FINDING-298: 🔵 Election Owner PID Exposed to Non-Owner Voters

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.3.1 |
| Files | v3/server/pages.py:235 |
| Source Reports | 15.3.1.md |
| Related Findings | - | **Description:**

In the `vote_on_page()` function in `pages.py`, the `result.election` object passed to the template includes `owner_pid`, `authz`, and other administrative fields that voters do not need. While `get_metadata()` already excludes `salt` and `opened_key`, fields like `authz` (LDAP group) are still exposed. This is low severity as the template likely only renders specific fields, but it violates the principle of returning only the required subset of fields to users.

**Remediation:**

Create a voter-specific view of election metadata that excludes administrative fields like `owner_pid` and `authz`. Implement field-level access control so different users (owner vs voter vs admin) receive different field subsets from the same data objects.

---

#### FINDING-299: 🔵 Vote Endpoint Accepts Arbitrary Form Keys with vote- Prefix

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.3.3 |
| Files | v3/server/pages.py:390 |
| Source Reports | 15.3.3.md |
| Related Findings | - | **Description:**

The do_vote_endpoint() function extracts any form key prefixed with 'vote-' and uses the suffix as an issue ID. An attacker could submit arbitrary issue IDs for issues they shouldn't vote on (if issues exist in other elections). However, this is mitigated by downstream validation in add_vote() which calls self.q_get_mayvote.first_row(pid, iid) to check authorization. The risk is limited to triggering errors for non-existent issues within the election.

**Remediation:**

Add validation to ensure extracted issue IDs exist in the current election's issue_dict before processing. Consider adding explicit allowlisting of issue IDs based on the election context to fail fast rather than relying solely on downstream authorization checks.

---

#### FINDING-300: 🔵 No Type Validation on Form Fields Before Use

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.3.5 |
| Files | v3/server/pages.py |
| Source Reports | 15.3.5.md |
| Related Findings | - | **Description:**

Functions `do_add_issue_endpoint()`, `do_edit_issue_endpoint()`, and `do_create_endpoint()` use `edict(await quart.request.form)` pattern without explicit type validation. While Quart's form parser naturally returns strings for standard form-encoded data, the conversion to `edict` and direct attribute access without type checking creates potential for unexpected behavior if Content-Type headers are manipulated. Mitigating factor: Quart's request.form parser specifically handles application/x-www-form-urlencoded and multipart/form-data, always returning string values.

**Remediation:**

Replace `edict(await quart.request.form)` pattern with explicit field extraction using `form_data.get('fieldname')` with type checking. Example:
```python
form = await quart.request.form
title = form.get('title', '')
if not isinstance(title, str) or not title:
    quart.abort(400, 'Invalid title')
```

---

#### FINDING-301: 🔵 EasyDict Usage with User-Controlled Input May Allow Attribute Injection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.3.6 |
| Files | v3/server/pages.py:401, v3/server/pages.py:447, v3/server/pages.py:518 |
| Source Reports | 15.3.6.md |
| Related Findings | - | **Description:**

EasyDict converts dictionary keys to object attributes. If user input contains keys like `__class__`, `__init__`, `__dict__`, `items`, `keys`, or other Python dunder/method names, it could shadow built-in methods. In Python, this is significantly less dangerous than JavaScript prototype pollution. The worst case is denial of service via TypeError if internal method names are shadowed. No actual prototype chain modification occurs. However, if a form field named `items` is submitted, EasyDict's __getattr__ resolves to the stored value, potentially causing TypeError when code later calls form.items().

**Remediation:**

Instead of edict for user input, use explicit field extraction: form_data = await quart.request.form; title = form_data.get('title', '').strip(); description = form_data.get('description', '').strip(). Replace `edict(await quart.request.form)` pattern throughout the application with explicit field extraction with type checking instead of converting entire form data to attribute-accessible objects.

---

#### FINDING-302: 🔵 Implicit Parameter Deduplication Without Explicit HPP Defense

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 15.3.7 |
| Files | v3/server/pages.py:397 |
| Source Reports | 15.3.7.md |
| Related Findings | - | **Description:**

HTTP form body (MultiDict with potential duplicate keys) is converted to edict() constructor which silently drops duplicates by keeping first value per key. When edict(await quart.request.form) is called, the MultiDict is converted to a regular dict, silently dropping duplicate parameters. The behavior depends on Werkzeug's MultiDict-to-dict conversion (typically keeps first value), but this is undocumented and implicit rather than explicit. While the framework naturally separates parameter sources (request.form vs request.args), there is no explicit defense against duplicate parameters within the same source. The implicit deduplication behavior is framework-version-dependent, making it fragile. However, the subsequent validation (if iid not in issue_dict) and the vote re-submission model (latest vote wins) significantly reduce impact.

**Remediation:**

Implement explicit duplicate key detection: Check for duplicate vote keys using raw_form.getlist(key) and reject requests with duplicate parameters. Example: raw_form = await quart.request.form; for each key starting with 'vote-', extract iid and values = raw_form.getlist(key); if len(values) > 1, flash error message 'Duplicate vote parameter detected for issue {iid}' and redirect. This makes the deduplication behavior explicit and prevents framework-version-dependent behavior.

---

#### FINDING-303: 🔵 State-changing GET endpoints increase attack surface without documented protection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.1.1 |
| Files | v3/server/pages.py:498-537 |
| Source Reports | 6.1.1.md |
| Related Findings | - | **Description:**

State-changing operations using GET requests are trivially exploitable via link injection/prefetching. While not directly a rate-limiting issue, these endpoints compound the risk because automated tools (crawlers, prefetch mechanisms) can trigger state changes without the user's intent, and there's no documentation of how such automated abuse is prevented. Automated tools or cross-origin requests can trigger election state changes without rate limiting documentation.

**Remediation:**

Document that these endpoints are planned for migration to POST with CSRF protection, and implement reverse-proxy rate limiting in the interim.

---

#### FINDING-304: 🔵 No documented context-specific password deny list for the delegated authentication system

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 6.1.2 |
| Files | v3/server/main.py:entire file, v3/server/pages.py:entire file |
| Source Reports | 6.1.2.md |
| Related Findings | - | **Description:**

The application delegates password management entirely to ASF OAuth. However, ASVS 6.1.2 requires that a list of context-specific words be documented to prevent their use in passwords. For this application, such a list would include: Organization: "apache", "asf", "foundation"; Product: "steve", "voter", "election", "ballot"; System identifiers: Any election IDs, database names; Project codenames: "steve3", "STeVe"; Roles: "committer", "pmc", "member", "admin". Even though password enforcement is delegated, the documentation requirement still applies. The application should document either: 1. That ASF OAuth maintains such a deny list (with reference), OR 2. The recommended deny list for the ASF OAuth system to implement. Low severity because authentication is fully delegated to ASF OAuth, which likely has its own password policies. However, without documentation, there's no verification that context-specific words are prevented.

**Remediation:**

Create documentation for context-specific password deny list:

# Context-Specific Password Deny List

## Delegation Notice
Password policies are enforced by ASF OAuth (oauth.apache.org).
The following context-specific words SHOULD be blocked by ASF's 
password system:

### Organization Names
- apache, asf, foundation, software

### Product/System Names  
- steve, voter, voting, election, ballot

### Role Names
- committer, pmc, member, admin, owner

### Project Identifiers
- steve3, STeVe, apache-steve

## Verification
[Link to ASF password policy documentation]
[Date last verified: YYYY-MM-DD]

---

#### FINDING-305: 🔵 State-changing operations exposed via GET method (session replay risk)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.3.1 |
| Files | v3/server/pages.py:do_open_endpoint, v3/server/pages.py:do_close_endpoint |
| Source Reports | 6.3.1.md |
| Related Findings | - | **Description:**

State-changing endpoints /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; use HTTP GET method instead of POST. GET requests for state-changing operations can be cached/logged by proxies and browsers, triggered via &lt;img&gt; tags or link prefetching, and replayed from browser history. While primarily a CSRF concern, it also reduces the effectiveness of brute force protection since GET requests are easier to automate and may bypass POST-specific protections in WAFs.

**Remediation:**

Change state-changing endpoints from GET to POST method. Example: @APP.post('/do-open/&lt;eid&gt;') instead of @APP.get('/do-open/&lt;eid&gt;'). This aligns with HTTP semantics and reduces accidental/automated triggering risks.

---

#### FINDING-306: 🔵 OAuth state parameter binding not verifiable in reviewed code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 6.6.2 |
| Files | v3/server/main.py:33-37 |
| Source Reports | 6.6.2.md |
| Related Findings | - | **Description:**

The state parameter in the OAuth flow serves to bind the authentication callback to the original request (analogous to OOB binding). However, the state generation and validation logic resides within the asfquart framework (not provided for review). The %s format string suggests the state is injected but we cannot verify: 1. Whether the state contains sufficient entropy, 2. Whether it's bound to the user's session, 3. Whether it's validated on callback. If the asfquart framework does not properly validate the OAuth state parameter, authentication responses could be replayed or misbound. However, this is a framework-level concern rather than application-level.

**Remediation:**

Document reliance on asfquart framework for OAuth state binding. Verify during integration testing that: 1. State is generated with CSPRNG (≥128 bits), 2. State is stored in server-side session before redirect, 3. State is verified on callback and consumed (single-use)

---

#### FINDING-307: 🔵 TLS certificate storage lacks explicit integrity protection mechanisms

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 6.7.1 |
| Files | v3/server/main.py:6, v3/server/main.py:71-73 |
| Source Reports | 6.7.1.md |
| Related Findings | - | **Description:**

While this requirement specifically targets certificates used for cryptographic authentication assertions (FIDO/smart cards) rather than TLS server certificates, the TLS certificates are stored on the filesystem at a path relative to the application directory. There is no evidence of: 1. File permission enforcement 2. Integrity verification (checksums/signatures) before loading 3. Read-only filesystem mounting. If an attacker gains filesystem write access to the certs/ directory, they could replace the TLS certificate/key pair, enabling MITM attacks. However, this requires prior server compromise and is noted as an observation rather than a critical finding. This is primarily an infrastructure/deployment concern. The ASVS requirement is about cryptographic authentication assertion certificates, which are not implemented in this application.

**Remediation:**

For defense-in-depth:

import os
import stat

# Verify certificate file permissions before loading
cert_path = CERTS_DIR / app.cfg.server.certfile
cert_stat = os.stat(cert_path)
if cert_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
    raise RuntimeError(f"Certificate file {cert_path} has unsafe permissions")

---

#### FINDING-308: 🔵 Session Token Storage Mechanism Not Defined

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 14.3.3 |
| Files | Entire provided codebase |
| Source Reports | 14.3.3.md |
| Related Findings | - | **Description:**

Per ASVS 14.3.3, session tokens are the only exception allowed for browser storage. However, no session management mechanism is visible in the provided code. The domain context mentions the application uses Quart (async Flask-like framework), which typically uses signed cookies for sessions. Without seeing the session configuration, it's unclear whether session cookies are marked HttpOnly, Secure, and SameSite, or whether session data beyond the token ID is stored client-side. Session management not visible in provided code. This is likely handled by the Quart framework's session management, but cannot be verified from the provided files.

**Remediation:**

Ensure Quart session configuration includes: app.config['SESSION_COOKIE_HTTPONLY'] = True, app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'.

---

#### FINDING-309: 🔵 Deserialized JSON `kv` data lacks schema validation before use in vote tallying

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 1.5.2 |
| Files | v3/steve/election.py:292, v3/steve/election.py:368 |
| Source Reports | 1.5.2.md |
| Related Findings | - | **Description:**

Database `issue.kv` column (TEXT) is deserialized via `json.loads()` and passed directly to `vtypes` module `tally()` function without structural validation. While `json.loads()` is inherently safe from code execution (only produces basic Python types: dict, list, str, int, float, bool, None), the deserialized structure is passed to vote-type-specific modules without validation against an expected schema. If the `kv` data were corrupted or maliciously set (e.g., via an authorization bypass — the code inventory notes multiple `### check authz` placeholders are unimplemented), unexpected data structures could cause logic errors in tallying. Mitigating factors include: data originates from authorized election administrators (write path is `add_issue`/`edit_issue` which assert `is_editable()`), `json.loads()` cannot instantiate arbitrary objects, `issue.type` is validated against `vtypes.TYPES` at creation time, and risk is LOW because exploitation requires bypassing multiple controls.

**Remediation:**

Implement schema validation in the `json2kv()` method to ensure the parsed result is a dict (expected schema) and raise ValueError if not. Additionally, each `vtypes` module should validate the `kv` structure it receives in its `tally()` function. Example code:
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

#### FINDING-310: 🔵 Cannot Verify SRI Compliance - Templates Not Available for Audit

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 3.6.1 |
| Files | v3/server/pages.py:40-41 |
| Source Reports | 3.6.1.md |
| Related Findings | - | **Description:**

The application serves static assets locally via `STATICDIR = THIS_DIR / 'static'` and the `serve_static()` handler. However, the HTML templates (.ezt files in TEMPLATES directory) are not provided for audit. These templates may reference external CDN resources (JavaScript libraries, CSS frameworks like Bootstrap which is referenced in flash message categories, or web fonts) without Subresource Integrity (SRI) attributes. If external resources are loaded without SRI in templates, a CDN compromise could inject malicious JavaScript into the voting application, potentially stealing votes, session tokens, or manipulating election results.

**Remediation:**

1. Audit all .ezt template files for &lt;script src=, <link href=, and @import references to external domains. 2. For any external resources found, add integrity and crossorigin attributes (e.g., <script src="https://cdn.example.com/lib.min.js" integrity="sha384-{hash}" crossorigin="anonymous"&gt;&lt;/script&gt;). 3. Preferably, host all assets locally (which the serve_static handler supports). 4. Document any external resource dependencies and their SRI hashes.

---

# 4. Positive Security Controls

| Control | Evidence | Files | Domain |
|---------|----------|-------|--------|
| **Cryptographically secure salt generation** | `crypto.py:gen_salt()` uses `secrets.token_bytes()` (CSPRNG) | `v3/steve/crypto.py:37` | Vote Encryption and Storage |
| **Centralized cryptographic operations** | All cryptographic operations are centralized in `v3/steve/crypto.py`, making manual discovery straightforward and audit feasible | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **Industry-validated cryptographic libraries** | Uses `cryptography` library for symmetric encryption, `argon2-cffi` for password hashing, `hashlib.blake2b` for general hashing, `secrets` module for random generation | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **Fernet's encrypt-then-MAC design prevents Padding Oracle attacks** | Fernet verifies HMAC-SHA256 before attempting AES-CBC decryption, completely preventing Padding Oracle attacks | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **No insecure block modes (ECB) used** | Fernet uses AES-128-CBC with HMAC authentication, not ECB | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **Random IV generation per encrypt** | Fernet library guarantees a fresh 128-bit random IV for every encryption call, preventing nonce reuse | `cryptography.fernet.Fernet.encrypt()` | Vote Encryption and Storage |
| **Well-designed multi-level key derivation chain** | `election_data → BLAKE2b → Argon2 → opened_key → (+ pid + iid + salt) → Argon2 → vote_token → HKDF → vote_key → Fernet(vote)` provides good key separation | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **Adequate key lengths for most operations** | HKDF derives 32-byte (256-bit) keys, Argon2 produces 32-byte outputs, BLAKE2b uses full 64-byte digest, salts are 16 bytes (128 bits) | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **Election data integrity via opened_key mechanism** | The `opened_key` mechanism (Argon2 hash of all election data) detects any unauthorized modification of the election structure | `v3/steve/election.py:is_tampered()` | Vote Encryption and Storage |
| **Pinned crypto library versions** | `pyproject.toml` pins crypto library versions with upper bounds: `cryptography>=46.0.5,<47`, `argon2-cffi>=25.1.0,<26` | `pyproject.toml` | Vote Encryption and Storage |
| **No disallowed hash functions (MD5, SHA-1 absent)** | MD5 and SHA-1 are completely absent from the codebase | — | Vote Encryption and Storage |
| **SHA-256 in HKDF for key derivation** | The key derivation function uses NIST-approved SHA-256 | `v3/steve/crypto.py:62` | Vote Encryption and Storage |
| **Argon2 memory-hard KDF usage** | The system uses a memory-hard KDF (Argon2) rather than PBKDF2 or bcrypt, which is current best practice | `v3/steve/crypto.py:85` | Vote Encryption and Storage |
| **Adequate memory cost parameter (64 MB)** | `memory_cost=65536` provides meaningful GPU resistance | `v3/steve/crypto.py:91` | Vote Encryption and Storage |
| **Benchmark utility for parameter tuning** | A utility exists (`benchmark_argon2()`) to help administrators tune parameters for their hardware | `v3/steve/crypto.py:108` | Vote Encryption and Storage |
| **BLAKE2b for election data integrity (512-bit output)** | `crypto.py:gen_opened_key()` uses BLAKE2b with full 512-bit output exceeding 256-bit minimum for collision resistance | `v3/steve/crypto.py:45` | Vote Encryption and Storage |
| **HMAC-SHA256 in Fernet for authenticated encryption** | Fernet provides both confidentiality (AES-128-CBC) and integrity (HMAC-SHA256) | — | Vote Encryption and Storage |
| **Anti-tamper mechanism using `is_tampered()`** | `election.py` recomputes the `opened_key` from current election data and compares against stored value, providing 256-bit collision-resistant integrity verification | `v3/steve/election.py` | Vote Encryption and Storage |
| **Salt generation uses proper CSPRNG with 128 bits of entropy** | `gen_salt()` correctly uses `secrets.token_bytes(16)` | `v3/steve/crypto.py:36` | Vote Encryption and Storage |
| **Cryptographic shuffle implementation using CSPRNG** | `shuffle()` function implements Fisher-Yates using `secrets.randbelow()` for cryptographically secure randomization of vote order during tally | `v3/steve/crypto.py:93` | Vote Encryption and Storage |
| **Python secrets module with OS-level CSPRNG** | All cryptographic random generation uses the `secrets` module, backed by `os.urandom()`. On modern Linux, uses kernel's CSPRNG (ChaCha20-based getrandom) which is non-blocking and designed to work securely under heavy demand | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **No blocking entropy sources** | The code does not use `/dev/random` or any blocking entropy sources that could be depleted under load | — | Vote Encryption and Storage |
| **HKDF with appropriate parameters** | The `_b64_vote_key()` function uses HKDF-SHA256 with a proper salt and context info (`b'xchacha20_key'`), deriving a 32-byte key — approved per NIST SP 800-56C | `v3/steve/crypto.py:63` | Vote Encryption and Storage |
| **Vote shuffling before return** | `crypto.shuffle(votes)` ensures that even if memory is inspected, the order of decrypted votes does not correlate to database insertion order (voter identity) | `v3/steve/election.py:tally_issue()` | Vote Encryption and Storage |
| **Vote tokens are derived, not stored in plaintext** | Vote tokens are recomputed on each access rather than stored as plaintext lookup keys with PID associations | `v3/steve/election.py:tally_issue()` | Vote Encryption and Storage |
| **Immediate vote encryption upon submission** | Votes encrypted immediately upon submission | `v3/steve/election.py:231` | Vote Encryption and Storage |
| **Data minimization in queries - SALT and OPENED_KEY excluded** | SALT and OPENED_KEY excluded from public queries | `queries.yaml:q_open_to_me` | Vote Encryption and Storage |
| **Explicit exclusion of secrets in public APIs** | Both `get_metadata()` and `get_issue()` deliberately exclude cryptographic material from returned data with comments documenting the intention | `v3/steve/election.py:get_metadata()`, `v3/steve/election.py:get_issue()` | Vote Encryption and Storage |
| **No hardcoded secrets in source code** | The `config.yaml.example` file contains no passwords, API keys, or secret material — only structural configuration | `v3/server/config.yaml.example` | Vote Encryption and Storage |
| **Environment variable injection pattern** | The application uses asfpy for external secret injection in containerized deployments, separating config from deployment | — | Vote Encryption and Storage |
| **State machine enforcement for election lifecycle** | Assert statements prevent unauthorized state transitions (e.g., cannot delete opened elections, cannot vote on closed elections) | `v3/steve/election.py` | Vote Encryption and Storage |
| **Per-issue voter authorization** | The `mayvote` table constrains which persons can vote on which issues, preventing unauthorized vote submission | `v3/schema.sql` | Vote Encryption and Storage |
| **Centralized cryptographic module** | All cryptographic operations are consolidated in `crypto.py`, creating a clear architectural boundary that could be replaced with a vault/HSM integration point | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **No key material in logs** | The code uses `_LOGGER` but never logs salt, key, or token values (commented-out print statements are present but disabled) | `v3/steve/crypto.py` | Vote Encryption and Storage |
| **Deferred key generation** | Cryptographic material only generated when election opens | `v3/steve/election.py:open()` | Vote Encryption and Storage |
| **Immutability after closure** | `prevent_open_close_update` trigger and state assertions provide foundation for retention policies | `v3/schema.sql` | Vote Encryption and Storage |
| **Parameterized queries in queries.yaml** | All 30+ queries use `?` placeholders | `v3/queries.yaml` | Database Security and Integrity |
| **asfpy.db wrapper `.perform()` method** | All database interactions route through parameterized interface | `v3/steve/election.py` | Database Security and Integrity |
| **Schema constraints (CHECK, GLOB)** | Type enforcement at database level | `v3/schema.sql` | Database Security and Integrity |
| **Centralized Query Definition** | All SQL is defined in `queries.yaml` with `?` placeholders, separated from application logic | `v3/queries.yaml` | Database Security and Integrity |
| **No Dynamic SQL Construction** | No string concatenation, f-strings, or format strings are used to build SQL | `v3/steve/election.py` | Database Security and Integrity |
| **Implicit Separation of Internal vs External Data Access** | `_all_metadata()` marked INTERNAL ONLY vs. `get_metadata()` which strips sensitive fields | `v3/steve/election.py` | Database Security and Integrity |
| **Query-Level Awareness of Sensitive Data** | `q_open_to_me` query explicitly comments 'SALT and OPENED_KEY are never returned for security' | `v3/queries.yaml` | Database Security and Integrity |
| **Cryptographic Field Documentation** | Schema.md documents which fields use cryptographic operations and their byte sizes | `v3/docs/schema.md` | Database Security and Integrity |
| **Logging Hygiene** | Logging only includes operation types and non-sensitive identifiers (EID, IID). No sensitive data (votes, salts, keys, PII) in log statements | `v3/steve/election.py` | Database Security and Integrity |
| **Vote Privacy Architecture** | Separation of voter identity from vote content through vote_token derivation using Argon2 with per-voter salts, combined with encrypted vote storage and shuffling during tallying | `v3/steve/election.py` | Database Security and Integrity |
| **Vote encryption using Fernet** | Applied in `add_vote()` via `crypto.create_vote()` | `v3/steve/election.py` | Database Security and Integrity |
| **Tamper detection mechanism (opened_key)** | `is_tampered()` method exists (though not auto-called) | `v3/steve/election.py` | Database Security and Integrity |
| **Salt generation using secrets module** | Applied in `add_salts()` via `crypto.gen_salt()` | `v3/steve/election.py` | Database Security and Integrity |
| **Sensitive field filtering** | `get_metadata()` uses explicit allowlist, constructing new edict with only permitted fields | `v3/steve/election.py` | Database Security and Integrity |
| **Transaction isolation** | Applied in multi-step operations | `v3/steve/election.py` | Database Security and Integrity |
| **Vote shuffling before tally** | `crypto.shuffle(votes)` prevents database insertion order from leaking through tally results | `v3/steve/election.py` | Database Security and Integrity |
| **No external API calls** | `v3/steve/election.py` (entire module) - no outbound HTTP requests | `v3/steve/election.py` | Database Security and Integrity |
| **No tracking/analytics integration** | All provided files - no third-party SDK imports | — | Database Security and Integrity |
| **Connection Cleanup** | The `delete()` and `_disappeared()` methods explicitly close database connections, preventing stale data in connection pools | `v3/steve/election.py` | Database Security and Integrity |
| **Structured data model avoids file upload metadata leakage** | The application's data model uses structured fields (TEXT for titles/descriptions, BLOB for cryptographic data) rather than accepting arbitrary file uploads, which inherently avoids metadata leakage concerns in this layer | — | Database Security and Integrity |
| **Server-side token exchange pattern** | `OAUTH_URL_CALLBACK` configuration shows authorization code is exchanged server-side, keeping tokens out of the browser | `v3/server/main.py:40-43` | ASF OAuth/LDAP Authentication |
| **Session-based authentication architecture** | Application uses server-side sessions (`asfquart.session.read()`) rather than passing tokens to the client, eliminating traditional resource server attack surface | `v3/server/pages.py:82-88` | ASF OAuth/LDAP Authentication |
| **Server-rendered templates with minimal data exposure** | EZT templates are server-rendered, and `basic_info()` function only passes display data (uid, name, email) to templates - never tokens | `v3/server/pages.py` | ASF OAuth/LDAP Authentication |
| **Single authorization server hardcoded** | The application hardcodes a single authorization server (oauth.apache.org), eliminating the attack surface for OAuth mix-up attacks entirely | `v3/server/main.py:40-42` | ASF OAuth/LDAP Authentication |
| **Role-based access control using `@asfquart.auth.require` decorator** | Applied consistently to all management endpoints to verify committer role from OAuth session, with elevated `R.pmc_member` role for election creation | `v3/server/pages.py:multiple endpoints` | ASF OAuth/LDAP Authentication |
| **Voter eligibility verification** | `vote_on_page` handler correctly checks mayvote entries before allowing users to see voting options | `v3/server/pages.py:261-266` | ASF OAuth/LDAP Authentication |
| **Authorization-aware domain model** | Election data model includes `owner_pid` and `authz` fields indicating correct authorization architecture design (though not yet enforced) | `v3/server/pages.py:domain model` | ASF OAuth/LDAP Authentication |
| **Authorization code grant flow usage** | The application exclusively uses the authorization code flow (code parameter in callback URL), which is the recommended OAuth grant type. No evidence of implicit flow or password grant usage. | `v3/server/main.py:39-42` | ASF OAuth/LDAP Authentication |
| **HTTPS for all OAuth endpoints** | All OAuth communication uses HTTPS protocol, protecting against passive network eavesdropping | `v3/server/main.py:39-42` | ASF OAuth/LDAP Authentication |
| **State parameter for CSRF protection** | The OAuth URL template explicitly includes `state=%s`, showing the framework architecture was designed with CSRF protection in mind | `v3/server/main.py:40` | ASF OAuth/LDAP Authentication |
| **Hardcoded OAuth URLs to prevent manipulation** | OAuth URLs are statically defined rather than dynamically discovered or user-configurable at runtime | `v3/server/main.py:39-42` | ASF OAuth/LDAP Authentication |
| **No local refresh token storage visible** | The application does not appear to store or directly manage refresh tokens, reducing the attack surface for replay attacks at the application layer | — | ASF OAuth/LDAP Authentication |
| **No dynamic client registration surface** | The application does not expose any dynamic client registration endpoints, eliminating this attack vector entirely | — | ASF OAuth/LDAP Authentication |
| **Static client configuration** | OAuth configuration is hardcoded/configured statically with predefined OAuth endpoints, reducing the risk of malicious client registration | `main.py` | ASF OAuth/LDAP Authentication |
| **Delegation to identity provider for token lifecycle** | Token lifecycle management is delegated to ASF's OAuth infrastructure (oauth.apache.org), which is appropriate for a relying party application | — | ASF OAuth/LDAP Authentication |
| **Server-side sessions with server-side state** | Session invalidation can be performed server-side without needing client cooperation using asfquart.session | — | ASF OAuth/LDAP Authentication |
| **State parameter included in OAuth authorization request for CSRF protection** | The state parameter is present in the authorization request URL template | `v3/server/main.py:39` | ASF OAuth/LDAP Authentication |
| **Session-based identity storage rather than passing tokens to browser** | Application uses server-side sessions to store OAuth-derived identity, limiting some token replay vectors by not exposing tokens to client-side scripts | `v3/server/pages.py:82-91` | ASF OAuth/LDAP Authentication |
| **Stable user identifier (uid field)** | The 'uid' field is used consistently as the sole user identifier across all endpoints | `pages.py:84` | ASF OAuth/LDAP Authentication |
| **LDAP synchronization for authoritative identity** | LDAP synchronization script uses the LDAP 'uid' attribute which is stable and authoritative | `asf-load-ldap.py:53` | ASF OAuth/LDAP Authentication |
| **Hardcoded OAuth URLs eliminate metadata spoofing** | By directly configuring `OAUTH_URL_INIT` and `OAUTH_URL_CALLBACK` to specific ASF endpoints, the application cannot be redirected to a malicious authorization server through metadata manipulation | `main.py:39-42` | ASF OAuth/LDAP Authentication |
| **No back-channel logout attack surface** | Back-channel logout is not implemented, eliminating forced-logout denial of service and cross-JWT confusion in logout flow | — | ASF OAuth/LDAP Authentication |
| **OAuth client configuration uses authorization code flow** | Application correctly uses code flow when acting as OAuth client | `main.py:39-42` | ASF OAuth/LDAP Authentication |
| **LDAP-sourced user population** | Users come exclusively from organizational LDAP | `asf-load-ldap.py:main()` | ASF OAuth/LDAP Authentication |
| **OAuth-based authentication with no local password database** | No local password database or default credentials | `main.py:create_app()` | ASF OAuth/LDAP Authentication |
| **Single OAuth authentication pathway** | All user authentication flows through ASF OAuth with no alternate login mechanisms, API keys, or backdoor authentication paths | `main.py:create_app()` | ASF OAuth/LDAP Authentication |
| **Consistent decorator pattern for authentication** | The `@asfquart.auth.require` decorator is consistently applied to all protected endpoints, establishing a clear authentication boundary | `v3/server/pages.py` | ASF OAuth/LDAP Authentication |
| **OAuth-only authentication with no email-based authentication** | Authentication is performed exclusively via ASF OAuth tokens | `main.py:create_app()` | ASF OAuth/LDAP Authentication |
| **Email used for display only** | `s['email']` read from session but not used for auth | `pages.py:basic_info()` | ASF OAuth/LDAP Authentication |
| **OAuth delegation eliminates local login/register/forgot-password** | Authentication fully delegated to ASF OAuth — no local login/register/forgot-password | `main.py:40-43` | ASF OAuth/LDAP Authentication |
| **Consistent error templates for elections** | The `load_election` decorator uses `T_BAD_EID` for both nonexistent elections and unauthorized access, preventing election enumeration | `pages.py:load_election` | ASF OAuth/LDAP Authentication |
| **Single IdP configuration** | Only ASF OAuth is configured as the identity provider | `main.py:40-43` | ASF OAuth/LDAP Authentication |
| **Server-side token exchange** | The `OAUTH_URL_CALLBACK` pattern indicates server-side code exchange, meaning tokens don't traverse the browser | `v3/server/main.py:40-43` | ASF OAuth/LDAP Authentication |
| **HTTPS for IdP communication** | Both OAuth URLs use https://, preventing MITM attacks on the token exchange | `v3/server/main.py:40-43` | ASF OAuth/LDAP Authentication |
| **OAuth 2.0 / OIDC used instead of SAML** | OAuth authorization and token endpoints configured | `main.py:40-43` | ASF OAuth/LDAP Authentication |
| **Authentication requirements via decorators** | All endpoints have authentication requirements via `@asfquart.auth.require` decorators—no unauthenticated access to election operations | `v3/server/pages.py` | Election Authorization and Access Control |
| **Voting eligibility validation on voting page** | `vote_on_page()` properly checks `q_find_issues` to verify the authenticated user has mayvote entries before showing the voting interface | `v3/server/pages.py:vote_on_page()` | Election Authorization and Access Control |
| **Document access authorization check** | `serve_doc()` properly checks mayvote before serving election documents, ensuring only eligible voters can access materials | `v3/server/pages.py:serve_doc()` | Election Authorization and Access Control |
| **Election state machine enforcement** | `is_editable()`, `is_open()`, `is_closed()` prevent out-of-order operations regardless of authorization gaps; state transitions enforced via assertions | `v3/steve/election.py` | Election Authorization and Access Control |
| **Cryptographic field exclusion in `get_metadata()`** | `get_metadata()` explicitly constructs a safe subset of fields, excluding salt and opened_key with explicit comments ('# NEVER return salt/opened_key') | `v3/steve/election.py:163-177` | Election Authorization and Access Control |
| **Issue salt filtering in `get_issue()`** | `get_issue()` returns only (title, description, type, kv), never the per-issue salt field | `v3/steve/election.py:179-187` | Election Authorization and Access Control |
| **Vote anonymization design** | `vote_token` is a one-way hash that prevents reverse-engineering the voter's identity from the vote table | `v3/steve/election.py` | Election Authorization and Access Control |
| **Implicit mayvote enforcement in add_vote** | `add_vote()` won't succeed without a corresponding mayvote entry (though mechanism is implicit rather than explicit) | `v3/steve/election.py:add_vote()` | Election Authorization and Access Control |
| **Per-request vote state validation** | Every call to `add_vote()` validates `self.S_OPEN` via `_all_metadata(self.S_OPEN)`, ensuring closed elections immediately reject votes | `v3/steve/election.py:265` | Election Authorization and Access Control | ---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status |
|---------|-------|--------|
| **1.1.1** | Encoding and Sanitization Architecture - Canonical Decoding | Partial |
| **1.1.2** | Encoding and Sanitization Architecture - Output Encoding as Final Step | Fail |
| **1.2.1** | Injection Prevention - Context-Appropriate Output Encoding | Fail |
| **1.2.2** | Injection Prevention - URL Encoding and Safe Protocols | Fail |
| **1.2.3** | Injection Prevention - JavaScript/JSON Encoding | Fail |
| **1.2.4** | Injection Prevention | Pass |
| **1.2.5** | OS Command Injection Prevention | Pass |
| **1.2.6** | LDAP Injection Prevention | Pass |
| **1.2.7** | XPath Injection Prevention | Pass |
| **1.2.8** | LaTeX Injection Prevention | Pass |
| **1.2.9** | Regular Expression Injection Prevention | Pass |
| **1.2.10** | Injection Prevention - CSV and Formula Injection | Pass |
| **1.3.1** | HTML Sanitization of Untrusted Input | Fail |
| **1.3.2** | Dynamic Code Execution | Pass |
| **1.3.3** | Sanitization Before Dangerous Contexts | Fail |
| **1.3.4** | SVG Sanitization | Pass |
| **1.3.5** | Scriptable/Expression Template Language Content | Fail |
| **1.3.6** | SSRF Protection | Pass |
| **1.3.7** | Template Injection Protection | Pass |
| **1.3.8** | JNDI Injection Prevention | Partial |
| **1.3.9** | Memcache Injection Prevention | N/A |
| **1.3.10** | Format String Sanitization | Partial |
| **1.3.11** | SMTP/IMAP Injection Prevention | Partial |
| **1.3.12** | ReDoS Prevention | Pass |
| **1.4.1** | Memory-Safe String and Pointer Operations | Pass |
| **1.4.2** | Integer Overflow Prevention | Pass |
| **1.4.3** | Memory and Resource Release | Pass |
| **1.5.1** | XML Parser Restrictive Configuration | Pass |
| **1.5.2** | Safe Deserialization | Partial |
| **1.5.3** | Parser Consistency | Pass |
| **2.1.1** | Validation and Business Logic Documentation - Input Validation Rules | Partial |
| **2.1.2** | Validation and Business Logic Documentation - Contextual Consistency | Fail |
| **2.1.3** | Validation and Business Logic Documentation - Business Logic Limits | Fail |
| **2.2.1** | Input Validation | Fail |
| **2.2.2** | Input Validation at Trusted Service Layer | Fail |
| **2.2.3** | Combinations of Related Data Items | Fail |
| **2.3.1** | Business Logic Sequential Step Order | Fail |
| **2.3.2** | Business Logic Limits | Fail |
| **2.3.3** | Transaction Usage at Business Logic Level | Fail |
| **2.3.4** | Business Logic Locking (Double-Booking Prevention) | Fail |
| **2.3.5** | Multi-User Approval for High-Value Operations | Fail |
| **2.4.1** | Anti-Automation Controls | Fail |
| **2.4.2** | Anti-Automation: Realistic Human Timing Controls | Fail |
| **3.1.1** | Web Frontend Security Documentation | Fail |
| **3.2.1** | Unintended Content Interpretation | Fail |
| **3.2.2** | Safe Rendering (Text vs HTML) | Fail |
| **3.2.3** | DOM Clobbering Prevention | Fail |
| **3.3.1** | Cookie Secure Attribute and Prefix | Fail |
| **3.3.2** | Cookie SameSite Attribute | Fail |
| **3.3.3** | Cookie __Host- Prefix | Fail |
| **3.3.4** | Cookie HttpOnly Attribute | Fail |
| **3.3.5** | Cookie Size Limit (4096 bytes) | Partial |
| **3.4.1** | Strict-Transport-Security (HSTS) Header | Fail |
| **3.4.2** | CORS Access-Control-Allow-Origin | Fail |
| **3.4.3** | Content-Security-Policy Header | Fail |
| **3.4.4** | X-Content-Type-Options Header | Fail |
| **3.4.5** | Referrer-Policy Header | Fail |
| **3.4.6** | frame-ancestors Directive | Fail |
| **3.4.7** | CSP Report-URI/Report-To | Fail |
| **3.4.8** | Cross-Origin-Opener-Policy Header | Fail |
| **3.5.1** | Browser Origin Separation - Anti-Forgery Tokens | Fail |
| **3.5.2** | Browser Origin Separation - CORS Preflight Mechanism | Fail |
| **3.5.3** | Browser Origin Separation - HTTP Methods | Fail |
| **3.5.4** | Browser Origin Separation - Separate Hostnames | Fail |
| **3.5.5** | Browser Origin Separation - postMessage Validation | N/A |
| **3.5.6** | Browser Origin Separation - JSONP | Pass |
| **3.5.7** | Browser Origin Separation - XSSI Prevention | Partial |
| **3.5.8** | Browser Origin Separation - Authenticated Resource Loading | Fail |
| **3.6.1** | External Resource Integrity | Partial |
| **3.7.1** | Supported and Secure Client-Side Technologies | Pass |
| **3.7.2** | Redirect Allowlist for External Domains | Partial |
| **3.7.3** | Redirect Notification for External URLs | Fail |
| **3.7.4** | HSTS Preload List | Fail |
| **3.7.5** | Browser Security Feature Detection | Fail |
| **4.1.1** | Content-Type Header Verification | N/A |
| **4.1.2** | HTTP to HTTPS Redirect Behavior | Pass |
| **4.1.3** | Intermediary Header Override Protection | Partial |
| **4.1.4** | HTTP Method Restriction | Partial |
| **4.1.5** | Per-Message Digital Signatures | Fail |
| **4.2.1** | HTTP Request Smuggling Prevention | Partial |
| **4.2.2** | Content-Length Header Validation | N/A |
| **4.2.3** | HTTP/2 and HTTP/3 Connection-Specific Header Fields | Pass |
| **4.2.4** | CR/LF/CRLF Injection in HTTP/2 and HTTP/3 Headers | N/A |
| **4.2.5** | URI and Header Field Length Validation | N/A |
| **4.3.1** | GraphQL DoS Prevention | N/A |
| **4.3.2** | GraphQL Introspection Disabled in Production | N/A |
| **4.4.1** | WebSocket over TLS (WSS) | N/A |
| **4.4.2** | Origin Header Validation on WebSocket Handshake | N/A |
| **4.4.3** | Dedicated WebSocket Session Tokens | N/A |
| **4.4.4** | WebSocket Token Validation via Authenticated HTTPS | N/A |
| **5.1.1** | File Handling Documentation | Fail |
| **5.2.1** | File Size Limits | Fail |
| **5.2.2** | File Extension and Content Validation | Fail |
| **5.2.3** | Compressed File Checks | Fail |
| **5.2.4** | File Size Quota and Maximum File Count Per User | Fail |
| **5.2.5** | Symlink Prevention in Compressed Files | Fail |
| **5.2.6** | Pixel Flood Attack Prevention | N/A |
| **5.3.1** | Uploaded Files Not Executed as Server-Side Code | Partial |
| **5.3.2** | Path Traversal Protection | Partial |
| **5.3.3** | Zip Slip Protection | Pass |
| **5.4.1** | Filename Validation in Downloads | Fail |
| **5.4.2** | Filename Encoding/Sanitization in Responses | Fail |
| **5.4.3** | Antivirus Scanning of Untrusted Files | Fail |
| **6.1.1** | Authentication Documentation - Rate Limiting and Anti-Automation | Fail |
| **6.1.2** | Authentication Documentation - Context-Specific Password Deny List | Fail |
| **6.1.3** | Authentication Documentation - Multiple Authentication Pathways | Fail |
| **6.2.1** | Password Security - Minimum Length | Pass |
| **6.2.2** | Password Security - Password Change Capability | N/A |
| **6.2.3** | Password Security - Password Change Requires Current Password | N/A |
| **6.2.4** | Password Blocklist Check | N/A |
| **6.2.5** | No Password Composition Rules | Pass |
| **6.2.6** | Password Field Masking (type=password) | N/A |
| **6.2.7** | Paste and Password Manager Support | Pass |
| **6.2.8** | No Password Modification Before Verification | Pass |
| **6.2.9** | Support Passwords of 64+ Characters | N/A |
| **6.2.10** | Password Validity Until Compromise | Pass |
| **6.2.11** | Context-Specific Word Blocklist | N/A |
| **6.2.12** | Breached Password Check | N/A |
| **6.3.1** | Credential Stuffing and Brute Force Prevention | Partial |
| **6.3.2** | Default User Accounts | Pass |
| **6.3.3** | Multi-Factor Authentication | Fail |
| **6.3.4** | Authentication Pathway Consistency | Fail |
| **6.3.5** | Suspicious Authentication Notification | Fail |
| **6.3.6** | Email Not Used for Authentication | Pass |
| **6.3.7** | User Notification on Authentication Detail Changes | Fail |
| **6.3.8** | User Enumeration Protection | Pass |
| **6.4.1** | System Generated Initial Passwords/Activation Codes | N/A |
| **6.4.2** | No Password Hints or Knowledge-Based Authentication | Pass |
| **6.4.3** | Secure Password Reset Process | N/A |
| **6.4.4** | MFA Factor Loss Requires Identity Proofing | N/A |
| **6.4.5** | Renewal Instructions for Expiring Authentication Mechanisms | N/A |
| **6.4.6** | Administrative Password Reset Without Knowing User Password | N/A |
| **6.5.1** | One-Time Use of Lookup Secrets, OOB Codes, and TOTPs | N/A |
| **6.5.2** | Lookup Secret Storage with Proper Hashing | N/A |
| **6.5.3** | CSPRNG for Lookup Secrets, OOB Codes, and TOTP Seeds | Pass |
| **6.5.4** | Minimum 20 Bits of Entropy for Lookup Secrets and OOB Codes | N/A |
| **6.5.5** | Defined Lifetime for OOB Requests/Codes and TOTPs | Pass |
| **6.5.6** | Revocability of Authentication Factors | Partial |
| **6.5.7** | Biometric Authentication as Secondary Factor Only | Pass |
| **6.5.8** | TOTP Time Source from Trusted Service | Pass |
| **6.6.1** | PSTN/SMS OTP Restrictions | Pass |
| **6.6.2** | Out-of-Band Authentication Binding | Partial |
| **6.6.3** | Brute Force Protection for Code-based OOB | N/A |
| **6.6.4** | Push Notification Rate Limiting | N/A |
| **6.7.1** | Certificate Storage Protection for Cryptographic Authentication | N/A |
| **6.7.2** | Challenge Nonce Requirements | N/A |
| **6.8.1** | IdP Identity Spoofing Prevention | Pass |
| **6.8.2** | Digital Signature Validation on Authentication Assertions | Partial |
| **6.8.3** | SAML Assertion Replay Prevention | N/A |
| **6.8.4** | Authentication Strength Verification from IdP | Fail |
| **7.1.1** | Session Inactivity Timeout and Maximum Session Lifetime Documentation | Fail |
| **7.1.2** | Concurrent Session Documentation | Fail |
| **7.1.3** | Federated Identity Management Documentation | Fail |
| **7.2.1** | Backend Session Token Verification | Pass |
| **7.2.2** | Dynamic Session Tokens (Not Static API Keys) | Pass |
| **7.2.3** | Reference Tokens - CSPRNG with 128+ Bits Entropy | Partial |
| **7.2.4** | Fundamental Session Management Security | Fail |
| **7.3.1** | Session Timeout | Fail |
| **7.3.2** | Session Timeout | Fail |
| **7.4.1** | Session Termination | Fail |
| **7.4.2** | Session Termination | Fail |
| **7.4.3** | Session Termination | Fail |
| **7.4.4** | Session Termination - Logout Visibility | Partial |
| **7.4.5** | Admin Session Termination | Fail |
| **7.5.1** | Re-authentication Before Sensitive Account Changes | Fail |
| **7.5.2** | User Session Viewing and Termination | Fail |
| **7.5.3** | Step-up Authentication for Sensitive Operations | Fail |
| **7.6.1** | Federated Re-authentication | Fail |
| **7.6.2** | Federated Re-authentication | Fail |
| **8.1.1** | Authorization Documentation - Function-level and Data-specific Access | Partial |
| **8.1.2** | Authorization Documentation - Field-level Access Restrictions | Fail |
| **8.1.3** | Authorization Documentation - Environmental and Contextual Attributes | Fail |
| **8.1.4** | Authorization Documentation - Environmental Factors in Decision-Making | Fail |
| **8.2.1** | General Authorization Design - Function-level Access | Fail |
| **8.2.2** | General Authorization Design - Data-specific Access (IDOR/BOLA) | Fail |
| **8.2.3** | General Authorization Design - Field-level Access (BOPLA) | Fail |
| **8.2.4** | General Authorization Design - Adaptive Security Controls | Fail |
| **8.3.1** | Operation Level Authorization - Server-Side Enforcement | Fail |
| **8.3.2** | Operation Level Authorization - Immediate Authorization Change Application | Fail |
| **8.3.3** | Operation Level Authorization - Subject-Based Permissions | Pass |
| **8.4.1** | Other Authorization Considerations - Multi-Tenant Cross-Tenant Controls | Fail |
| **8.4.2** | Other Authorization Considerations - Administrative Interface Multi-Layer Security | Fail |
| **9.1.1** | Token Signature Validation | Partial |
| **9.1.2** | Algorithm Allowlist for Token Verification | Fail |
| **9.1.3** | Key Material from Trusted Pre-configured Sources | Fail |
| **9.2.1** | Token Validity Time Span Verification | Partial |
| **9.2.2** | Token Type Verification | Fail |
| **9.2.3** | Token Audience Validation | Fail |
| **9.2.4** | Token Audience Restriction | Fail |
| **10.1.1** | Token Exposure Limitation | Partial |
| **10.1.2** | Client-Generated Secrets for OAuth Flow Security | Partial |
| **10.2.1** | OAuth Client CSRF Protection for Code Flow | Partial |
| **10.2.2** | Mix-Up Attack Defense | Pass |
| **10.2.3** | Minimal Scope Requests | Fail |
| **10.3.1** | Resource Server Audience Validation | Partial |
| **10.3.2** | Authorization Decisions Based on Token Claims | Fail |
| **10.3.3** | User Identification from Access Token Claims | Partial |
| **10.3.4** | Authentication Strength Verification | Fail |
| **10.3.5** | Sender-Constrained Access Tokens | Fail |
| **10.4.1** | Redirect URI Validation | Partial |
| **10.4.2** | Authorization Code One-Time Use | Partial |
| **10.4.3** | Authorization Code Short Lifetime | Partial |
| **10.4.4** | OAuth Grant Type Restriction | Partial |
| **10.4.5** | Refresh Token Replay Mitigation | N/A |
| **10.4.6** | PKCE Enforcement for Code Grant | Fail |
| **10.4.7** | Dynamic Client Registration Security | N/A |
| **10.4.8** | Refresh Token Absolute Expiration | N/A |
| **10.4.9** | Token Revocation by Authorized User | Partial |
| **10.4.10** | Confidential Client Authentication for Backchannel Requests | Partial |
| **10.4.11** | Authorization Server Only Assigns Required Scopes | Partial |
| **10.4.12** | Only Allow Needed response_mode per Client | Partial |
| **10.4.13** | Grant Type 'code' Always Used with PAR | Fail |
| **10.4.14** | Sender-Constrained (Proof-of-Possession) Access Tokens | Fail |
| **10.4.15** | Authorization Details Parameter Integrity for Server-Side Clients | Partial |
| **10.4.16** | Strong Client Authentication Methods | Fail |
| **10.5.1** | ID Token Replay Attack Mitigation (Nonce Validation) | Fail |
| **10.5.2** | User Identification from ID Token Claims (sub claim) | Partial |
| **10.5.3** | Authorization Server Metadata Issuer Validation | Pass |
| **10.5.4** | ID Token Audience (aud) Claim Validation | Fail |
| **10.5.5** | OIDC Back-Channel Logout Security | N/A |
| **10.6.1** | OpenID Provider Response Mode Restrictions | N/A |
| **10.6.2** | OpenID Provider Forced Logout DoS Mitigation | N/A |
| **10.7.1** | User Consent for Authorization Requests | N/A |
| **10.7.2** | Clear Consent Information Presentation | N/A |
| **10.7.3** | User Review/Modify/Revoke Consents | N/A |
| **11.1.1** | Cryptographic Key Management Policy | Fail |
| **11.1.2** | Cryptographic Inventory | Fail |
| **11.1.3** | Cryptographic Discovery Mechanisms | Fail |
| **11.1.4** | Cryptographic Inventory with PQC Migration Plan | Fail |
| **11.2.1** | Industry-Validated Cryptographic Implementations | Partial |
| **11.2.2** | Crypto Agility | Fail |
| **11.2.3** | Minimum 128-bits of Security | Partial |
| **11.2.4** | Constant-Time Operations | Fail |
| **11.2.5** | Secure Cryptographic Failure | Partial |
| **11.3.1** | No Insecure Block Modes or Weak Padding | Pass |
| **11.3.2** | Approved Ciphers and Modes | Partial |
| **11.3.3** | Protection Against Unauthorized Modification | Pass |
| **11.3.4** | Nonces, IVs, and Single-Use Numbers | Pass |
| **11.3.5** | Encrypt-then-MAC Mode | Pass |
| **11.4.1** | Approved Hash Functions | Partial |
| **11.4.2** | Password Storage with Approved KDF | Partial |
| **11.4.3** | Hash Functions for Digital Signatures / Data Integrity | Pass |
| **11.4.4** | Approved KDF with Key Stretching for Key Derivation from Passwords | Partial |
| **11.5.1** | Random Values - CSPRNG with 128-bit Entropy | Fail |
| **11.5.2** | Random Number Generation Under Heavy Demand | Pass |
| **11.6.1** | Approved Cryptographic Algorithms and Modes | Partial |
| **11.6.2** | Approved Key Exchange Algorithms with Secure Parameters | N/A |
| **11.7.1** | Full Memory Encryption for Sensitive Data In-Use | Fail |
| **11.7.2** | Data Minimization and Immediate Encryption | Partial |
| **12.1.1** | General TLS Security Guidance - TLS Protocol Versions | Fail |
| **12.1.2** | General TLS Security Guidance - Cipher Suites | Fail |
| **12.1.3** | General TLS Security Guidance - mTLS Client Certificate Validation | N/A |
| **12.1.4** | General TLS Security Guidance - Certificate Revocation (OCSP Stapling) | Fail |
| **12.1.5** | General TLS Security Guidance - Encrypted Client Hello (ECH) | Fail |
| **12.2.1** | HTTPS Communication with External Facing Services | Fail |
| **12.2.2** | HTTPS Communication with External Facing Services | Fail |
| **12.3.1** | General Service to Service Communication Security | Fail |
| **12.3.2** | TLS Certificate Validation by Clients | Partial |
| **12.3.3** | TLS for Internal HTTP-based Services | Fail |
| **12.3.4** | Trusted Certificates for Internal Service TLS | Fail |
| **12.3.5** | Strong Authentication for Intra-Service Communications | Fail |
| **13.1.1** | Communication Needs Documentation | Fail |
| **13.1.2** | Connection Pool Limits and Fallback | Fail |
| **13.1.3** | Resource Management Strategies | Fail |
| **13.1.4** | Secrets Documentation and Rotation | Partial |
| **13.2.1** | Backend Communication Authentication | Partial |
| **13.2.2** | Least Privilege for Backend Communications | Fail |
| **13.2.3** | No Default Credentials for Service Authentication | Pass |
| **13.2.4** | Allowlist for External Resource Communication | Fail |
| **13.2.5** | Server Allowlist for Outbound Requests/Data Loads | Fail |
| **13.2.6** | Documented Connection Configuration | Fail |
| **13.3.1** | Secret Management Solution | Fail |
| **13.3.2** | Least Privilege Access to Secrets | Fail |
| **13.3.3** | Isolated Security Module for Cryptographic Operations | Fail |
| **13.3.4** | Secret Expiration and Rotation | Fail |
| **13.4.1** | Source Control Metadata | Partial |
| **13.4.2** | Debug Modes Disabled in Production | Fail |
| **13.4.3** | Directory Listings Disabled | Pass |
| **13.4.4** | HTTP TRACE Method Disabled | Fail |
| **13.4.5** | Documentation and Monitoring Endpoints | Partial |
| **13.4.6** | Backend Version Information | Fail |
| **13.4.7** | Unintended Information Leakage - Web Tier File Extension Filtering | Partial |
| **14.1.1** | Data Classification | Partial |
| **14.1.2** | Documented Protection Requirements | Fail |
| **14.2.1** | Sensitive Data Not in URL/Query String | Pass |
| **14.2.2** | Prevent Sensitive Data Caching | Partial |
| **14.2.3** | Sensitive Data Not Sent to Untrusted Parties | Pass |
| **14.2.4** | General Data Protection - Encryption, Integrity, Retention, Logging Controls | Partial |
| **14.2.5** | Caching Mechanisms and Web Cache Deception Prevention | N/A |
| **14.2.6** | Minimum Required Sensitive Data / Data Masking | Partial |
| **14.2.7** | Data Retention Classification and Automatic Deletion | Fail |
| **14.2.8** | Metadata Removal from User-Submitted Files | N/A |
| **14.3.1** | Clear-Site-Data on Session Termination | Fail |
| **14.3.2** | Anti-caching HTTP Response Headers | Fail |
| **14.3.3** | No Sensitive Data in Browser Storage | Partial |
| **15.1.1** | Risk-Based Remediation Timeframes | Fail |
| **15.1.2** | SBOM and Inventory Catalog | Fail |
| **15.1.3** | Documentation of Resource-Demanding Functionality | Fail |
| **15.1.4** | Documentation of Risky Components | Fail |
| **15.1.5** | Documentation of Dangerous Functionality | Fail |
| **15.2.1** | Components Within Remediation Timeframes | Fail |
| **15.2.2** | Defenses Against Loss of Availability Due to Resource-Demanding Functionality | Fail |
| **15.2.3** | Production Environment Only Includes Required Functionality | Partial |
| **15.2.4** | Third-Party Components From Expected Repositories Without Dependency Confusion Risk | Fail |
| **15.2.5** | Additional Protections Around Dangerous Functionality and Risky Components | Fail |
| **15.3.1** | Data Object Field Subsetting | Partial |
| **15.3.2** | Backend URL Following Redirects | Pass |
| **15.3.3** | Mass Assignment Protection | Partial |
| **15.3.4** | IP Address Handling by Proxies and Middleware | Fail |
| **15.3.5** | Type Safety and Strict Comparisons | Partial |
| **15.3.6** | Prototype Pollution Prevention | Partial |
| **15.3.7** | HTTP Parameter Pollution Defenses | Partial |
| **15.4.1** | Safe Concurrency — Thread-Safe Shared Objects | Fail |
| **15.4.2** | Safe Concurrency — TOCTOU Race Conditions | Fail |
| **15.4.3** | Safe Concurrency — Consistent Lock Usage | Fail |
| **15.4.4** | Safe Concurrency — Resource Allocation and Thread Starvation | Fail |
| **16.1.1** | Security Logging Documentation | Fail |
| **16.2.1** | General Logging - Metadata Requirements | Fail |
| **16.2.2** | Time Synchronization and UTC Timestamps | Fail |
| **16.2.3** | Logs Only to Documented Destinations | Fail |
| **16.2.4** | Logs Readable and Correlatable by Log Processor | Partial |
| **16.2.5** | Sensitive Data Protection in Logs | Fail |
| **16.3.1** | Authentication Operations Logging | Fail |
| **16.3.2** | Authorization Failure Logging | Fail |
| **16.3.3** | Security Events and Bypass Attempts Logging | Fail |
| **16.3.4** | Unexpected Errors and Security Control Failures Logging | Fail |
| **16.4.1** | Log Injection Prevention | Fail |
| **16.4.2** | Log Protection from Unauthorized Access and Modification | Fail |
| **16.4.3** | Log Protection - Secure Transmission | Fail |
| **16.5.1** | Error Handling - Generic Messages | Partial |
| **16.5.2** | Error Handling - External Resource Failure | Fail |
| **16.5.3** | Error Handling - Fail Gracefully and Securely | Fail |
| **16.5.4** | Error Handling - Last Resort Error Handler | Fail |
| **17.1.1** | TURN Server IP Address Filtering | N/A |
| **17.1.2** | TURN Server Resource Exhaustion | N/A |
| **17.2.1** | DTLS Certificate Key Management | N/A |
| **17.2.2** | DTLS Cipher Suites and SRTP Protection Profile | N/A |
| **17.2.3** | SRTP Authentication Verification | N/A |
| **17.2.4** | Resilience to Malformed SRTP Packets | N/A |
| **17.2.5** | Resilience to SRTP Packet Floods | N/A |
| **17.2.6** | DTLS ClientHello Race Condition | N/A |
| **17.2.7** | Recording Mechanism Resilience During Floods | N/A |
| **17.2.8** | DTLS Certificate Verification Against SDP Fingerprint | N/A |
| **17.3.1** | Signaling Server Rate Limiting Against Flood Attacks | N/A |
| **17.3.2** | Signaling Server Resilience Against Malformed Messages | N/A | ---

# 6. Cross-Reference Matrix

## Finding → ASVS Mapping

| Finding ID | ASVS Requirements |
|------------|-------------------|
| | 8.2.1, 8.2.2, 8.3.1, 8.4.1, 8.4.2, 6.3.4, 2.3.2 |
| | 8.2.1, 8.3.1, 8.4.2, 2.2.2, 2.3.1, 3.5.1, 3.5.3, 3.5.8 |
| | 1.2.1, 1.2.3 |
| | 3.2.2, 1.3.1, 1.3.3 |
| | 3.5.1, 2.4.1, 8.4.2 |
| | 3.4.1, 3.7.4, 12.2.1 |
| | 2.2.1, 2.3.2, 1.3.3, 16.5.3, 15.2.3 |
| | 2.3.1, 8.3.1, 16.5.3, 15.4.3 |
| | 16.3.2 |
| FINDING-010 | 11.2.2 |
| FINDING-011 | 11.2.4 |
| FINDING-012 | 13.3.1, 13.3.3 |
| FINDING-013 | 13.3.2 |
| FINDING-014 | 13.3.4 |
| FINDING-015 | 14.2.7 |
| FINDING-016 | 10.4.10, 10.4.16 |
| FINDING-017 | 10.5.4, 9.2.4 |
| FINDING-018 | 6.3.4 |
| FINDING-019 | 6.3.4 |
| FINDING-020 | 8.2.2, 8.3.1, 2.2.3 |
| FINDING-021 | 8.2.3, 8.4.2 |
| FINDING-022 | 8.4.1 |
| FINDING-023 | 7.3.2 |
| FINDING-024 | 7.4.1, 6.5.6 |
| FINDING-025 | 7.4.2 |
| FINDING-026 | 7.4.5 |
| FINDING-027 | 7.5.2 |
| FINDING-028 | 7.5.3 |
| FINDING-029 | 7.6.2 |
| FINDING-030 | 1.2.1, 3.2.3 |
| FINDING-031 | 1.2.1 |
| FINDING-032 | 1.1.2 |
| FINDING-033 | 3.2.2, 1.3.1, 1.3.3, 1.3.5 |
| FINDING-034 | 3.2.2 |
| FINDING-035 | 3.2.1 |
| FINDING-036 | 3.5.8 |
| FINDING-037 | 3.3.1, 3.3.2, 3.3.3, 3.3.4 |
| FINDING-038 | 3.4.3, 3.4.7 |
| FINDING-039 | 3.4.6 |
| FINDING-040 | 3.4.8 |
| FINDING-041 | 12.1.1 |
| FINDING-042 | 12.1.2 |
| FINDING-043 | 12.2.1, 12.3.1, 12.2.2 |
| FINDING-044 | 2.2.1 |
| FINDING-045 | 2.2.1 |
| FINDING-046 | 2.3.3, 16.5.3 |
| FINDING-047 | 2.3.3, 15.4.2 |
| FINDING-048 | 2.2.3 |
| FINDING-049 | 5.2.1 |
| FINDING-050 | 5.2.2, 5.3.1 |
| FINDING-051 | 16.1.1 |
| FINDING-052 | 16.2.1 |
| FINDING-053 | 16.2.1, 16.4.3 |
| FINDING-054 | 16.2.5 |
| FINDING-055 | 16.3.1 |
| FINDING-056 | 16.3.2 |
| FINDING-057 | 16.3.2 |
| FINDING-058 | 16.3.3, 16.3.4 |
| FINDING-059 | 16.3.3 |
| FINDING-060 | 16.4.1, 1.3.10 |
| FINDING-061 | 16.4.3 |
| FINDING-062 | 16.5.2 |
| FINDING-063 | 16.5.3 |
| FINDING-064 | 16.5.4 |
| FINDING-065 | 13.4.2, 15.2.3 |
| FINDING-066 | 15.1.1 |
| FINDING-067 | 15.1.2, 15.2.4 |
| FINDING-068 | 15.1.3 |
| FINDING-069 | 15.2.1 |
| FINDING-070 | 15.2.2 |
| FINDING-071 | 15.2.4 |
| FINDING-072 | 15.3.4 |
| FINDING-073 | 15.4.1 |
| FINDING-074 | 15.4.2, 2.3.4 |
| FINDING-075 | 15.4.3 |
| FINDING-076 | 15.4.4, 2.4.1, 2.4.2, 6.3.1 |
| FINDING-077 | 9.2.4 |
| FINDING-078 | 9.2.4 |
| FINDING-079 | 14.3.2 |
| FINDING-080 | 11.1.1 |
| FINDING-081 | 11.1.2 |
| FINDING-082 | 11.1.3 |
| FINDING-083 | 11.1.4 |
| FINDING-084 | 11.2.1, 11.2.4, 11.4.2, 11.4.4, 11.6.1, 15.2.1 |
| FINDING-085 | 11.2.3, 11.5.1, 7.2.3 |
| FINDING-086 | 11.2.5 |
| FINDING-087 | 11.3.2 |
| FINDING-088 | 13.3.1 |
| FINDING-089 | 13.3.3 |
| FINDING-090 | 13.3.4 |
| FINDING-091 | 11.7.1 |
| FINDING-092 | 14.1.1, 14.1.2 |
| FINDING-093 | 14.2.4 |
| FINDING-094 | 14.2.4 |
| FINDING-095 | 14.2.7 |
| FINDING-096 | 14.2.7 |
| FINDING-097 | 10.1.2, 10.2.1, 10.4.6, 10.4.4 |
| FINDING-098 | 10.3.2 |
| FINDING-099 | 10.3.3 |
| FINDING-100 | 10.3.4, 6.8.4, 8.4.2 |
| FINDING-101 | 10.3.5, 10.4.14 |
| FINDING-102 | 10.4.13, 10.4.15 |
| FINDING-103 | 10.5.1 |
| FINDING-104 | 6.3.3 |
| FINDING-105 | 6.8.2 |
| FINDING-106 | 6.3.7 |
| FINDING-107 | 6.3.5 |
| FINDING-108 | 8.2.1 |
| FINDING-109 | 8.2.2 |
| FINDING-110 | 8.2.3 |
| FINDING-111 | 8.3.2 |
| FINDING-112 | 8.4.2 |
| FINDING-113 | 8.2.4 |
| FINDING-114 | 8.1.1, 8.1.2 |
| FINDING-115 | 8.1.3 |
| FINDING-116 | 8.1.4 |
| FINDING-117 | 7.1.1, 7.3.1 |
| FINDING-118 | 7.1.2 |
| FINDING-119 | 7.1.3 |
| FINDING-120 | 7.2.4 |
| FINDING-121 | 7.4.3 |
| FINDING-122 | 7.5.1 |
| FINDING-123 | 7.5.3 |
| FINDING-124 | 7.6.1 |
| FINDING-125 | 7.6.2 |
| FINDING-126 | 1.1.2 |
| FINDING-127 | 3.2.2 |
| FINDING-128 | 1.2.3 |
| FINDING-129 | 3.2.2 |
| FINDING-130 | 1.2.2, 1.3.1, 1.3.3 |
| FINDING-131 | 1.1.1 |
| FINDING-132 | 3.2.1 |
| FINDING-133 | 3.2.1 |
| FINDING-134 | 3.5.2 |
| FINDING-135 | 3.5.7 |
| FINDING-136 | 3.5.8 |
| FINDING-137 | 3.5.8 |
| FINDING-138 | 3.3.2 |
| FINDING-139 | 3.4.2 |
| FINDING-140 | 3.4.4 |
| FINDING-141 | 3.4.5 |
| FINDING-142 | 3.7.2 |
| FINDING-143 | 3.7.3 |
| FINDING-144 | 3.7.5 |
| FINDING-145 | 12.1.1 |
| FINDING-146 | 12.1.4 |
| FINDING-147 | 12.2.2 |
| FINDING-148 | 12.3.2 |
| FINDING-149 | 12.3.4 |
| FINDING-150 | 2.1.1 |
| FINDING-151 | 2.1.2 |
| FINDING-152 | 2.1.3 |
| FINDING-153 | 2.2.1, 2.3.2 |
| FINDING-154 | 2.2.2 |
| FINDING-155 | 2.2.3 |
| FINDING-156 | 2.3.1 |
| FINDING-157 | 2.3.3 |
| FINDING-158 | 2.3.4 |
| FINDING-159 | 2.3.5 |
| FINDING-160 | 2.4.1 |
| FINDING-161 | 2.4.2 |
| FINDING-162 | 1.3.3 |
| FINDING-163 | 1.3.11 |
| FINDING-164 | 1.3.8 |
| FINDING-165 | 5.1.1 |
| FINDING-166 | 5.2.3 |
| FINDING-167 | 5.2.4 |
| FINDING-168 | 5.2.5 |
| FINDING-169 | 5.3.2 |
| FINDING-170 | 5.4.1, 5.4.2 |
| FINDING-171 | 5.4.3 |
| FINDING-172 | 4.1.3 |
| FINDING-173 | 4.2.1 |
| FINDING-174 | 16.1.1, 16.2.3 |
| FINDING-175 | 16.2.1 |
| FINDING-176 | 16.2.1 |
| FINDING-177 | 16.2.2 |
| FINDING-178 | 16.2.4 |
| FINDING-179 | 16.2.5 |
| FINDING-180 | 16.2.5 |
| FINDING-181 | 16.3.1 |
| FINDING-182 | 16.3.2 |
| FINDING-183 | 16.3.3 |
| FINDING-184 | 16.3.3 |
| FINDING-185 | 16.3.4 |
| FINDING-186 | 16.3.4 |
| FINDING-187 | 16.4.1 |
| FINDING-188 | 16.4.2 |
| FINDING-189 | 16.4.2 |
| FINDING-190 | 16.5.1 |
| FINDING-191 | 16.5.2 |
| FINDING-192 | 16.5.4 |
| FINDING-193 | 13.1.1 |
| FINDING-194 | 13.1.2 |
| FINDING-195 | 13.1.3 |
| FINDING-196 | 13.1.4 |
| FINDING-197 | 13.2.2 |
| FINDING-198 | 13.2.4 |
| FINDING-199 | 13.2.5 |
| FINDING-200 | 13.4.2 |
| FINDING-201 | 13.4.2 |
| FINDING-202 | 13.4.4 |
| FINDING-203 | 13.4.6 |
| FINDING-204 | 13.4.7 |
| FINDING-205 | 13.4.7 |
| FINDING-206 | 15.1.1 |
| FINDING-207 | 15.1.4 |
| FINDING-208 | 15.1.5 |
| FINDING-209 | 15.2.2 |
| FINDING-210 | 15.2.2 |
| FINDING-211 | 15.2.3 |
| FINDING-212 | 15.2.4 |
| FINDING-213 | 15.2.5 |
| FINDING-214 | 15.2.5 |
| FINDING-215 | 15.3.1 |
| FINDING-216 | 15.3.3 |
| FINDING-217 | 15.3.5 |
| FINDING-218 | 15.4.1 |
| FINDING-219 | 15.4.2 |
| FINDING-220 | 15.4.2 |
| FINDING-221 | 15.4.3 |
| FINDING-222 | 15.4.4 |
| FINDING-223 | 15.4.4 |
| FINDING-224 | 6.1.1 |
| FINDING-225 | 6.1.3 |
| FINDING-226 | 9.1.1 |
| FINDING-227 | 9.1.2 |
| FINDING-228 | 9.1.3 |
| FINDING-229 | 9.2.1 |
| FINDING-230 | 9.2.2 |
| FINDING-231 | 9.2.3 |
| FINDING-232 | 14.3.1 |
| FINDING-233 | 14.3.3 |
| FINDING-234 | 3.1.1 |
| FINDING-235 | 11.1.1 |
| FINDING-236 | 11.2.2, 11.3.4 |
| FINDING-237 | 11.4.1 |
| FINDING-238 | 11.4.4 |
| FINDING-239 | 11.7.2 |
| FINDING-240 | 11.7.2 |
| FINDING-241 | 14.2.2 |
| FINDING-242 | 14.2.4 |
| FINDING-243 | 14.2.6 |
| FINDING-244 | 10.1.1 |
| FINDING-245 | 10.1.2, 10.5.1 |
| FINDING-246 | 10.2.3, 10.4.11 |
| FINDING-247 | 10.4.11 |
| FINDING-248 | 10.3.1 |
| FINDING-249 | 10.4.1 |
| FINDING-250 | 10.4.12 |
| FINDING-251 | 10.4.2, 10.4.3 |
| FINDING-252 | 10.4.9 |
| FINDING-253 | 10.5.2 |
| FINDING-254 | 6.8.4 |
| FINDING-255 | 6.8.1 |
| FINDING-256 | 6.3.8 |
| FINDING-257 | 8.1.1 |
| FINDING-258 | 8.3.2 |
| FINDING-259 | 8.3.3 |
| FINDING-260 | 7.4.4 |
| FINDING-261 | 7.6.1 |
| FINDING-262 | 7.6.2 |
| FINDING-263 | 1.2.2 |
| FINDING-264 | 3.2.3 |
| FINDING-265 | 3.5.2 |
| FINDING-266 | 3.5.4 |
| FINDING-267 | 3.5.7 |
| FINDING-268 | 3.3.5 |
| FINDING-269 | 12.1.5 |
| FINDING-270 | 12.3.1 |
| FINDING-271 | 12.3.3 |
| FINDING-272 | 12.3.5 |
| FINDING-273 | 2.1.1 |
| FINDING-274 | 2.3.5 |
| FINDING-275 | 2.4.2 |
| FINDING-276 | 1.3.12 |
| FINDING-277 | 1.3.3 |
| FINDING-278 | 1.3.7 |
| FINDING-279 | 5.3.2 |
| FINDING-280 | 5.4.2 |
| FINDING-281 | 5.4.3 |
| FINDING-282 | 4.1.4 |
| FINDING-283 | 4.1.5 |
| FINDING-284 | 16.2.2 |
| FINDING-285 | 16.2.3, 16.4.2 |
| FINDING-286 | 16.2.4 |
| FINDING-287 | 16.3.4 |
| FINDING-288 | 16.5.1 |
| FINDING-289 | 13.2.1 |
| FINDING-290 | 13.2.1 |
| FINDING-291 | 13.2.2 |
| FINDING-292 | 13.2.6 |
| FINDING-293 | 13.4.1 |
| FINDING-294 | 13.4.5 |
| FINDING-295 | 13.4.6 |
| FINDING-296 | 13.4.7 |
| FINDING-297 | 15.2.5 |
| FINDING-298 | 15.3.1 |
| FINDING-299 | 15.3.3 |
| FINDING-300 | 15.3.5 |
| FINDING-301 | 15.3.6 |
| FINDING-302 | 15.3.7 |
| FINDING-303 | 6.1.1 |
| FINDING-304 | 6.1.2 |
| FINDING-305 | 6.3.1 |
| FINDING-306 | 6.6.2 |
| FINDING-307 | 6.7.1 |
| FINDING-308 | 14.3.3 |
| FINDING-309 | 1.5.2 |
| FINDING-310 | 3.6.1 | ## ASVS → Finding Mapping

| ASVS ID | Related Findings |
|---------|------------------|
| **1.1.1** | FINDING-131 |
| **1.1.2** | FINDING-032, FINDING-126 |
| **1.2.1** | FINDING-030, FINDING-031 |
| **1.2.2** | FINDING-130, FINDING-263 |
| **1.2.3** | FINDING-128 |
| **1.3.1** | FINDING-033, FINDING-130 |
| **1.3.3** | FINDING-033, FINDING-130, FINDING-162, FINDING-277 |
| **1.3.5** | FINDING-033 |
| **1.3.7** | FINDING-278 |
| **1.3.8** | FINDING-164 |
| **1.3.10** | FINDING-060 |
| **1.3.11** | FINDING-163 |
| **1.3.12** | FINDING-276 |
| **1.5.2** | FINDING-309 |
| **2.1.1** | FINDING-150, FINDING-273 |
| **2.1.2** | FINDING-151 |
| **2.1.3** | FINDING-152 |
| **2.2.1** | FINDING-044, FINDING-045, FINDING-153 |
| **2.2.2** | FINDING-154 |
| **2.2.3** | FINDING-020, FINDING-048, FINDING-155 |
| **2.3.1** | FINDING-156 |
| **2.3.2** | FINDING-153 |
| **2.3.3** | FINDING-046, FINDING-047, FINDING-157 |
| **2.3.4** | FINDING-074, FINDING-158 |
| **2.3.5** | FINDING-159, FINDING-274 |
| **2.4.1** | FINDING-076, FINDING-160 |
| **2.4.2** | FINDING-076, FINDING-161, FINDING-275 |
| **3.1.1** | FINDING-234 |
| **3.2.1** | FINDING-035, FINDING-132, FINDING-133 |
| **3.2.2** | FINDING-033, FINDING-034, FINDING-127, FINDING-129 |
| **3.2.3** | FINDING-030, FINDING-264 |
| **3.3.1** | FINDING-037 |
| **3.3.2** | FINDING-037, FINDING-138 |
| **3.3.3** | FINDING-037 |
| **3.3.4** | FINDING-037 |
| **3.3.5** | FINDING-268 |
| **3.4.1** | |
| **3.4.2** | FINDING-139 |
| **3.4.3** | FINDING-038 |
| **3.4.4** | FINDING-140 |
| **3.4.5** | FINDING-141 |
| **3.4.6** | FINDING-039 |
| **3.4.7** | FINDING-038 |
| **3.4.8** | FINDING-040 |
| **3.5.1** | |
| **3.5.2** | FINDING-134, FINDING-265 |
| **3.5.3** | |
| **3.5.4** | FINDING-266 |
| **3.5.7** | FINDING-135, FINDING-267 |
| **3.5.8** | FINDING-036, FINDING-136, FINDING-137 |
| **3.6.1** | FINDING-310 |
| **3.7.2** | FINDING-142 |
| **3.7.3** | FINDING-143 |
| **3.7.4** | |
| **3.7.5** | FINDING-144 |
| **4.1.3** | FINDING-172 |
| **4.1.4** | FINDING-282 |
| **4.1.5** | FINDING-283 |
| **4.2.1** | FINDING-173 |
| **5.1.1** | FINDING-165 |
| **5.2.1** | FINDING-049 |
| **5.2.2** | FINDING-050 |
| **5.2.3** | FINDING-166 |
| **5.2.4** | FINDING-167 |
| **5.2.5** | FINDING-168 |
| **5.3.1** | FINDING-050 |
| **5.3.2** | FINDING-169, FINDING-279 |
| **5.4.1** | FINDING-170 |
| **5.4.2** | FINDING-170, FINDING-280 |
| **5.4.3** | FINDING-171, FINDING-281 |
| **6.1.1** | FINDING-224, FINDING-303 |
| **6.1.2** | FINDING-304 |
| **6.1.3** | FINDING-225 |
| **6.3.1** | FINDING-076, FINDING-305 |
| **6.3.3** | FINDING-104 |
| **6.3.4** | FINDING-018, FINDING-019 |
| **6.3.5** | FINDING-107 |
| **6.3.7** | FINDING-106 |
| **6.3.8** | FINDING-256 |
| **6.5.6** | FINDING-024 |
| **6.6.2** | FINDING-306 |
| **6.7.1** | FINDING-307 |
| **6.8.1** | FINDING-255 |
| **6.8.2** | FINDING-105 |
| **6.8.4** | FINDING-100, FINDING-254 |
| **7.1.1** | FINDING-117 |
| **7.1.2** | FINDING-118 |
| **7.1.3** | FINDING-119 |
| **7.2.3** | FINDING-085 |
| **7.2.4** | FINDING-120 |
| **7.3.1** | FINDING-117 |
| **7.3.2** | FINDING-023 |
| **7.4.1** | FINDING-024 |
| **7.4.2** | FINDING-025 |
| **7.4.3** | FINDING-121 |
| **7.4.4** | FINDING-260 |
| **7.4.5** | FINDING-026 |
| **7.5.1** | FINDING-122 |
| **7.5.2** | FINDING-027 |
| **7.5.3** | FINDING-028, FINDING-123 |
| **7.6.1** | FINDING-124, FINDING-261 |
| **7.6.2** | FINDING-029, FINDING-125, FINDING-262 |
| **8.1.1** | FINDING-114, FINDING-257 |
| **8.1.2** | FINDING-114 |
| **8.1.3** | FINDING-115 |
| **8.1.4** | FINDING-116 |
| **8.2.1** | FINDING-108 |
| **8.2.2** | FINDING-020, FINDING-109 |
| **8.2.3** | FINDING-021, FINDING-110 |
| **8.2.4** | FINDING-113 |
| **8.3.1** | FINDING-020 |
| **8.3.2** | FINDING-111, FINDING-258 |
| **8.3.3** | FINDING-259 |
| **8.4.1** | FINDING-022 |
| **8.4.2** | FINDING-021, FINDING-100, FINDING-112 |
| **9.1.1** | FINDING-226 |
| **9.1.2** | FINDING-227 |
| **9.1.3** | FINDING-228 |
| **9.2.1** | FINDING-229 |
| **9.2.2** | FINDING-230 |
| **9.2.3** | FINDING-231 |
| **9.2.4** | FINDING-017, FINDING-077, FINDING-078 |
| **10.1.1** | FINDING-244 |
| **10.1.2** | FINDING-097, FINDING-245 |
| **10.2.1** | FINDING-097 |
| **10.2.3** | FINDING-246 |
| **10.3.1** | FINDING-248 |
| **10.3.2** | FINDING-098 |
| **10.3.3** | FINDING-099 |
| **10.3.4** | FINDING-100 |
| **10.3.5** | FINDING-101 |
| **10.4.1** | FINDING-249 |
| **10.4.2** | FINDING-251 |
| **10.4.3** | FINDING-251 |
| **10.4.4** | FINDING-097 |
| **10.4.6** | FINDING-097 |
| **10.4.9** | FINDING-252 |
| **10.4.10** | FINDING-016 |
| **10.4.11** | FINDING-246, FINDING-247 |
| **10.4.12** | FINDING-250 |
| **10.4.13** | FINDING-102 |
| **10.4.14** | FINDING-101 |
| **10.4.15** | FINDING-102 |
| **10.4.16** | FINDING-016 |
| **10.5.1** | FINDING-103, FINDING-245 |
| **10.5.2** | FINDING-253 |
| **10.5.4** | FINDING-017 |
| **11.1.1** | FINDING-080, FINDING-235 |
| **11.1.2** | FINDING-081 |
| **11.1.3** | FINDING-082 |
| **11.1.4** | FINDING-083 |
| **11.2.1** | FINDING-084 |
| **11.2.2** | FINDING-010, FINDING-236 |
| **11.2.3** | FINDING-085 |
| **11.2.4** | FINDING-011, FINDING-084 |
| **11.2.5** | FINDING-086 |
| **11.3.2** | FINDING-087 |
| **11.3.4** | FINDING-236 |
| **11.4.1** | FINDING-237 |
| **11.4.2** | FINDING-084 |
| **11.4.4** | FINDING-084, FINDING-238 |
| **11.5.1** | FINDING-085 |
| **11.6.1** | FINDING-084 |
| **11.7.1** | FINDING-091 |
| **11.7.2** | FINDING-239, FINDING-240 |
| **12.1.1** | FINDING-041, FINDING-145 |
| **12.1.2** | FINDING-042 |
| **12.1.4** | FINDING-146 |
| **12.1.5** | FINDING-269 |
| **12.2.1** | FINDING-043 |
| **12.2.2** | FINDING-043, FINDING-147 |
| **12.3.1** | FINDING-043, FINDING-270 |
| **12.3.2** | FINDING-148 |
| **12.3.3** | FINDING-271 |
| **12.3.4** | FINDING-149 |
| **12.3.5** | FINDING-272 |
| **13.1.1** | FINDING-193 |
| **13.1.2** | FINDING-194 |
| **13.1.3** | FINDING-195 |
| **13.1.4** | FINDING-196 |
| **13.2.1** | FINDING-289, FINDING-290 |
| **13.2.2** | FINDING-197, FINDING-291 |
| **13.2.4** | FINDING-198 |
| **13.2.5** | FINDING-199 |
| **13.2.6** | FINDING-292 |
| **13.3.1** | FINDING-012, FINDING-088 |
| **13.3.2** | FINDING-013 |
| **13.3.3** | FINDING-012, FINDING-089 |
| **13.3.4** | FINDING-014, FINDING-090 |
| **13.4.1** | FINDING-293 |
| **13.4.2** | FINDING-065, FINDING-200, FINDING-201 |
| **13.4.4** | FINDING-202 |
| **13.4.5** | FINDING-294 |
| **13.4.6** | FINDING-203, FINDING-295 |
| **13.4.7** | FINDING-204, FINDING-205, FINDING-296 |
| **14.1.1** | FINDING-092 |
| **14.1.2** | FINDING-092 |
| **14.2.2** | FINDING-241 |
| **14.2.4** | FINDING-093, FINDING-094, FINDING-242 |
| **14.2.6** | FINDING-243 |
| **14.2.7** | FINDING-015, FINDING-095, FINDING-096 |
| **14.3.1** | FINDING-232 |
| **14.3.2** | FINDING-079 |
| **14.3.3** | FINDING-233, FINDING-308 |
| **15.1.1** | FINDING-066, FINDING-206 |
| **15.1.2** | FINDING-067 |
| **15.1.3** | FINDING-068 |
| **15.1.4** | FINDING-207 |
| **15.1.5** | FINDING-208 |
| **15.2.1** | FINDING-069, FINDING-084 |
| **15.2.2** | FINDING-070, FINDING-209, FINDING-210 |
| **15.2.3** | FINDING-065, FINDING-211 |
| **15.2.4** | FINDING-067, FINDING-071, FINDING-212 |
| **15.2.5** | FINDING-213, FINDING-214, FINDING-297 |
| **15.3.1** | FINDING-215, FINDING-298 |
| **15.3.3** | FINDING-216, FINDING-299 |
| **15.3.4** | FINDING-072 |
| **15.3.5** | FINDING-217, FINDING-300 |
| **15.3.6** | FINDING-301 |
| **15.3.7** | FINDING-302 |
| **15.4.1** | FINDING-073, FINDING-218 |
| **15.4.2** | FINDING-047, FINDING-074, FINDING-219, FINDING-220 |
| **15.4.3** | FINDING-075, FINDING-221 |
| **15.4.4** | FINDING-076, FINDING-222, FINDING-223 |
| **16.1.1** | FINDING-051, FINDING-174 |
| **16.2.1** | FINDING-052, FINDING-053, FINDING-175, FINDING-176 |
| **16.2.2** | FINDING-177, FINDING-284 |
| **16.2.3** | FINDING-174, FINDING-285 |
| **16.2.4** | FINDING-178, FINDING-286 |
| **16.2.5** | FINDING-054, FINDING-179, FINDING-180 |
| **16.3.1** | FINDING-055, FINDING-181 |
| **16.3.2** | FINDING-056, FINDING-057, FINDING-182 |
| **16.3.3** | FINDING-058, FINDING-059, FINDING-183, FINDING-184 |
| **16.3.4** | FINDING-058, FINDING-185, FINDING-186, FINDING-287 |
| **16.4.1** | FINDING-060, FINDING-187 |
| **16.4.2** | FINDING-188, FINDING-189, FINDING-285 |
| **16.4.3** | FINDING-053, FINDING-061 |
| **16.5.1** | FINDING-190, FINDING-288 |
| **16.5.2** | FINDING-062, FINDING-191 |
| **16.5.3** | FINDING-046, FINDING-063 |
| **16.5.4** | FINDING-064, FINDING-192 | ## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 69 |
| L2 | 183 | 180 |
| L3 | 92 | 112 | **Total consolidated findings: 310**

*End of Consolidated Security Audit Report*