# Security Issues

## Issue: FINDING-001 - AES-128-CBC (Fernet) Used Instead of Approved AEAD Cipher; Incomplete Migration to XChaCha20-Poly1305
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application uses Fernet (AES-128-CBC + HMAC-SHA256) for vote encryption, which violates ASVS 11.3.2's requirement for approved AEAD cipher modes such as AES-GCM or ChaCha20-Poly1305. Evidence of an incomplete cryptographic migration exists: the key derivation function is explicitly configured for XChaCha20-Poly1305 (HKDF with info=b'xchacha20_key', 32-byte key length), but the actual encryption operations still use Fernet.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 11.3.2
- **ASVS Levels:** L1
- **Affected Files:**
  - `v3/steve/crypto.py` (lines 63-75, 77-80, 84-88)
  - `v3/steve/election.py` (lines 236, 271)

This represents a Type B gap where the control exists but is not applied, creating false confidence that an approved cipher is in use. Fernet uses AES-128-CBC (not an approved AEAD mode), splits the 32-byte key into 16 bytes for HMAC-SHA256 and 16 bytes for AES-128 encryption, and while the encrypt-then-MAC construction mitigates classic padding oracle attacks, CBC mode remains vulnerable to implementation-level side channels. All vote ciphertext stored in the vote table uses this unapproved cipher mode, and the effective encryption strength is AES-128 (not AES-256), below modern recommendations for high-sensitivity data in a voting system protecting ballot secrecy.

### Remediation
Complete the migration indicated by the code comments. Replace Fernet with XChaCha20-Poly1305 (as the HKDF is already configured for) using the nacl.secret.SecretBox implementation, or alternatively use AES-256-GCM from the cryptography library. For XChaCha20-Poly1305: derive a 32-byte key using the existing HKDF setup, create a nacl.secret.SecretBox with the key, and use box.encrypt() for encryption (nonce auto-generated) and box.decrypt() for decryption. For AES-256-GCM: update HKDF info parameter to 'aesgcm_vote_key', use AESGCM(key) with a 96-bit nonce (12 bytes from os.urandom), prepend the nonce to ciphertext for storage, and split on decryption. Note: Migration requires a re-encryption strategy for existing vote data or a version-aware decryption path to handle both old Fernet-encrypted votes and new AEAD-encrypted votes during the transition period.

### Acceptance Criteria
- [ ] Replace Fernet with XChaCha20-Poly1305 or AES-256-GCM
- [ ] Implement version-aware decryption for migration
- [ ] Add tests verifying AEAD cipher usage
- [ ] Document migration strategy for existing data

### References
- Source Reports: 11.3.2.md
- Related Findings: None

### Priority
Critical - Cryptographic control gap affecting vote confidentiality

---

## Issue: FINDING-002 - Vote Submission Endpoint Lacks Voter Eligibility Authorization Check
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The codebase contains 14+ instances of '### check authz' comments indicating developer awareness of the need for authorization checks, but these checks were never implemented. Any authenticated ASF committer can manage, open, close, or modify any election regardless of ownership. The authz field exists in the election schema but is never validated against the current user.

### Details
- **Severity:** Critical
- **CWE:** CWE-862
- **ASVS Sections:** 10.3.2, 2.1.2, 2.1.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `v3/server/pages.py` (lines 424-467, 426)

The combined data item (requesting user's PID + election.owner_pid) is never validated for consistency. Any authenticated ASF committer can perform irreversible operations (open, close) on elections they don't own, and modify election content (add/edit/delete issues) arbitrarily.

### Remediation
Add voter eligibility verification in the POST handler before recording votes: election.q_find_issues.perform(result.uid, election.eid); if not election.q_find_issues.fetchall(): await flash_danger('You are not authorized to vote in this election.'); return quart.redirect('/voter', code=303). Deploy immediately to prevent unauthorized vote manipulation.

### Acceptance Criteria
- [ ] Implement voter eligibility check before vote submission
- [ ] Test with authorized and unauthorized users
- [ ] Add audit logging for authorization failures
- [ ] Verify election ownership is enforced

### References
- Source Reports: 10.3.2.md, 2.1.2.md, 2.1.3.md
- Related Findings: FINDING-003, FINDING-024, FINDING-073, FINDING-088, FINDING-103, FINDING-104, FINDING-105

### Priority
Critical - Missing authorization allows unauthorized vote manipulation

---

## Issue: FINDING-003 - Election Management Endpoints Missing Ownership Authorization
**Labels:** bug, security, priority:critical
**Description:**
### Summary
All election management endpoints fail to verify that the authenticated user (identified by the 'sub' claim from the OAuth token, stored as 'uid' in the session) owns the election being modified. The Election.owned_elections(DB_FNAME, result.uid) query exists and is used in admin_page for display purposes, but is never used as an enforcement gate for state-changing operations.

### Details
- **Severity:** Critical
- **CWE:** CWE-862
- **ASVS Sections:** 10.3.2, 10.4.11
- **ASVS Levels:** L2
- **Affected Files:**
  - `v3/server/pages.py` (lines 493, 498, 515, 520, 410, 98, 417, 534, 539, 559, 564, 583, 588, 355, 195)

Any authenticated committer can tamper with elections they don't own — opening elections prematurely, closing them early to suppress votes, deleting issues, or modifying election content.

### Remediation
Implement ownership verification in the load_election decorator to protect all management endpoints: verify that metadata.owner_pid matches the authenticated user's uid from the session; abort with 403 if not matched.

### Acceptance Criteria
- [ ] Add ownership verification to load_election decorator
- [ ] Test that non-owners receive 403 errors
- [ ] Test that owners can perform operations
- [ ] Add audit logging for ownership violations

### References
- Source Reports: 10.3.2.md, 10.4.11.md
- Related Findings: FINDING-002, FINDING-024, FINDING-073, FINDING-088, FINDING-103, FINDING-104, FINDING-105

### Priority
Critical - Any authenticated user can manipulate any election

---

## Issue: FINDING-004 - Election Lifecycle State Enforcement Uses Bypassable `assert` Statements
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Security-critical state enforcement throughout the election lifecycle relies on Python assert statements, which are removed when Python is run with optimization flags (-O or -OO). This is a common production optimization that would completely bypass all election state validation.

### Details
- **Severity:** Critical
- **CWE:** CWE-670
- **ASVS Sections:** 2.3.1, 2.3.2, 2.3.4, 2.1.2, 2.1.3, 13.2.2, 15.3.5, 15.4.1, 15.4.3, 16.5.3, 16.3.3, 15.1.5, 8.1.2, 8.1.3, 8.1.4
- **ASVS Levels:** L1, L2, L3
- **Affected Files:**
  - `v3/steve/election.py` (lines 50, 52, 70, 73, 110, 116, 123, 127, 176, 190, 193, 205, 208, 220, 227, 228, 241, 248, 273, 349)
  - `v3/server/pages.py` (lines 447, 466, 483, 510, 534)

With assertions disabled, ALL election state enforcement is bypassed: issues can be added/edited/deleted on open or closed elections, voters can be added to open elections, elections can be opened multiple times or closed when editable, and vote types are not validated. When Python runs with optimization flags, all assert statements are removed from the bytecode, completely disabling state machine enforcement.

### Remediation
Replace all security-relevant assert statements with explicit conditional checks that raise appropriate exceptions and include logging. For example: if not self.is_editable(): _LOGGER.warning('STATE_VIOLATION: election[E:%s] operation=%s current_state=%s required_state=%s', self.eid, operation, self.get_state(), self.S_EDITABLE); raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE). Implement a _require_state() method that validates election state and logs violations before raising ElectionBadState exception. Additionally, wrap calls in pages.py with try/except blocks to return user-friendly errors instead of 500 errors. Apply this pattern consistently to all state-changing methods.

### Acceptance Criteria
- [ ] Replace all assert statements with explicit checks
- [ ] Implement _require_state() method with logging
- [ ] Add ElectionBadState exception class
- [ ] Test state enforcement with Python -O flag
- [ ] Add unit tests for all state transitions

### References
- Source Reports: 2.3.1.md, 2.3.2.md, 2.3.4.md, 2.1.2.md, 2.1.3.md, 13.2.2.md, 15.3.5.md, 15.4.1.md, 15.4.3.md, 16.5.3.md, 16.5.4.md, 16.3.3.md, 15.1.5.md, 8.1.2.md, 8.1.3.md, 8.1.4.md
- Related Findings: None

### Priority
Critical - State enforcement completely bypassed in production optimization mode

---

## Issue: FINDING-005 - Vote Content Validation Step Entirely Absent in Vote Submission Flow
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The add_vote() method accepts arbitrary vote content from users and encrypts it without any validation against the issue's vote type. The expected business logic step (validate vote against issue type) is explicitly marked as missing via a TODO comment ('### validate VOTESTRING for ISSUE.TYPE voting') but was never implemented.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 2.3.1, 2.3.2, 1.3.8, 1.3.9, 2.1.2, 2.2.1, 2.2.2, 2.2.3, 14.2.4, 15.3.5, 15.2.2, 16.5.3
- **ASVS Levels:** L1, L2
- **Affected Files:**
  - `v3/steve/election.py` (lines 282-298, 288, 238)
  - `v3/server/pages.py` (lines 383-424, 397-415, 336)

The votestring travels directly from user input to encrypted storage, skipping step 4 of the required sequential flow: 1) Authenticate user ✓, 2) Verify election is open ✓, 3) Verify voter eligibility ✓, 4) Validate vote content ✗, 5) Encrypt and store vote ✓. Invalid votes (e.g., 'INVALID_VALUE' for a Yes/No/Abstain issue, or malformed rankings for STV) are accepted, encrypted, and stored. The corruption is only discovered during tally_issue() when decrypted votestrings are passed to vote-type-specific tally functions, potentially causing miscounts, crashes, or incorrect results.

### Remediation
Implement the missing validation step using the existing `vtypes` module infrastructure. In election.py add_vote(), fetch the issue record, get its type, load the appropriate vtypes module, and call its validate() method before encryption: issue = self.q_get_issue.first_row(iid); if not issue: raise IssueNotFound(iid); vtype_mod = vtypes.vtype_module(issue.type); if not vtype_mod.validate(votestring, self.json2kv(issue.kv)): raise InvalidVoteString(iid, issue.type, votestring). Implement validate() functions in each vtype module (e.g., vtypes/yna.py: VALID_VOTES = {'yes', 'no', 'abstain'}; def validate(votestring, kv): return votestring.lower().strip() in VALID_VOTES). Add vote validation unit tests verifying that each vote type properly rejects invalid vote strings.

### Acceptance Criteria
- [ ] Implement validate() in all vtype modules
- [ ] Add validation call in add_vote() before encryption
- [ ] Test rejection of invalid vote strings for each type
- [ ] Add InvalidVoteString exception class
- [ ] Document validation rules per vote type

### References
- Source Reports: 2.3.1.md, 2.3.2.md, 1.3.8.md, 1.3.9.md, 2.1.2.md, 2.2.1.md, 2.2.2.md, 2.2.3.md, 14.2.4.md, 15.3.5.md, 15.2.2.md, 16.5.3.md
- Related Findings: None

### Priority
Critical - Invalid votes can corrupt election results

---

## Issue: FINDING-006 - Stored XSS via Missing HTML Output Encoding in EZT Templates
**Labels:** bug, security, priority:critical
**Description:**
### Summary
User-controlled data (election titles, issue titles, issue descriptions, owner names, authorization strings) is rendered in EZT templates without HTML encoding. The EZT templating engine provides the [format "html"] directive for HTML encoding, which is correctly used in a few JavaScript onclick handlers, but is systematically omitted in HTML body contexts across all templates.

### Details
- **Severity:** Critical
- **CWE:** CWE-79
- **ASVS Sections:** 1.1.1, 1.1.2, 1.2.1, 1.3.1, 1.3.5, 1.3.4
- **ASVS Levels:** L1, L2
- **Affected Files:**
  - `v3/server/templates/manage.ezt` (lines 176, 180, 241, 283)
  - `v3/server/templates/manage-stv.ezt` (lines 134, 175, 196)
  - `v3/server/templates/admin.ezt` (line 19)
  - `v3/server/templates/voter.ezt` (lines 35, 49, 88, 96)
  - `v3/server/templates/vote-on.ezt` (lines 88, 108-109, 131, 163)
  - `v3/server/templates/flashes.ezt` (line 3)
  - `v3/server/pages.py` (lines 240, 504, 535, 598)

This enables both reflected XSS via URL parameters and stored XSS via admin-created content. Any authenticated committer who creates an election or adds/edits an issue can inject persistent JavaScript that executes in the browsers of all other authenticated users viewing those elections.

### Remediation
Apply [format "html"] to all user-controlled template variables in HTML body contexts. For example: &lt;strong&gt;[format "html"][issues.title][end]&lt;/strong&gt;, &lt;div&gt;[format "html"][issues.description][end]&lt;/div&gt;, &lt;h5&gt;[format "html"][owned.title][end]&lt;/h5&gt;. Alternative (Recommended): Migrate to a template engine with auto-escaping by default (e.g., Jinja2 with autoescape=True) to eliminate this entire class of vulnerabilities architecturally.

### Acceptance Criteria
- [ ] Apply [format "html"] to all user-controlled variables in templates
- [ ] Test XSS payloads are properly escaped
- [ ] Consider migration to Jinja2 with auto-escaping
- [ ] Add automated XSS testing to CI/CD

### References
- Source Reports: 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.3.1.md, 1.3.5.md, 1.3.4.md
- Related Findings: FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-193, FINDING-194

### Priority
Critical - Stored XSS affecting all authenticated users

---

## Issue: FINDING-007 - No TLS Protocol Version Enforcement — Server May Accept Deprecated TLS 1.0/1.1 Connections
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application constructs TLS parameters by passing only certfile and keyfile as keyword arguments to app.runx(). At no point in the codebase is an ssl.SSLContext explicitly created or configured. This means no minimum TLS version is enforced, no protocol flags disable deprecated versions, and no TLS 1.3 preference is configured.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 12.1.1, 12.3.1
- **ASVS Levels:** L1, L2
- **Affected Files:**
  - `v3/server/main.py` (lines 83-91, 99-118, 77-82)
  - `v3/server/config.yaml.example`

Python's ssl.SSLContext defaults minimum_version to TLSVersion.MINIMUM_SUPPORTED, which is typically TLS 1.0 on most systems. Both deployment modes affected — run_standalone() passes raw paths; run_asgi() creates no SSL configuration at all, deferring entirely to Hypercorn's own defaults. An attacker can force a protocol downgrade to exploit known TLS 1.0/1.1 weaknesses (BEAST, POODLE, Lucky Thirteen) to decrypt authentication tokens or encrypted vote payloads in transit.

### Remediation
Create an explicit ssl.SSLContext with enforced minimum version and pass it to the server framework. The context should: (1) Set ctx.minimum_version = ssl.TLSVersion.TLSv1_2, (2) Set ctx.maximum_version = ssl.TLSVersion.TLSv1_3, (3) Enable ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE, (4) Restrict cipher suites to 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES'. For ASGI/Hypercorn deployment, provide a hypercorn.toml configuration that enforces TLS 1.2+ with modern ciphers. Add minimum_tls_version and ciphers fields to the config schema. Add a startup warning/abort when certfile is empty and the server is not binding to localhost.

### Acceptance Criteria
- [ ] Create explicit ssl.SSLContext with TLS 1.2 minimum
- [ ] Configure strong cipher suites
- [ ] Add Hypercorn TLS configuration
- [ ] Test that TLS 1.0/1.1 connections are rejected
- [ ] Add startup validation for TLS configuration

### References
- Source Reports: 12.1.1.md, 12.3.1.md, 12.3.5.md
- Related Findings: None

### Priority
Critical - Weak TLS versions allow decryption of authentication tokens

---

## Issue: FINDING-008 - Application Falls Back to Plain HTTP When TLS Not Configured
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The TLS control exists but is implemented as an optional, bypassable configuration toggle. When the certfile config value is empty, blank, or absent, the server launches over plain HTTP with zero warnings, zero errors, and zero compensating controls. The configuration comments actively document this as intended behavior.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 12.2.1, 12.3.1, 12.3.3, 12.3.4, 12.3.5, 4.1.2
- **ASVS Levels:** L1, L2, L3
- **Affected Files:**
  - `v3/server/main.py` (lines 84-90, 98-117, 77-80, 83-86)
  - `v3/server/config.yaml.example` (lines 27-31, 28-31, 30-32)

Three specific issues compound into a single critical vulnerability: (1) Explicit plain HTTP fallback by design, (2) No enforcement at any layer - no startup validation, HTTP redirect, HSTS header, or warning log, (3) ASGI mode has no TLS configuration at all. For this voting system, plain HTTP operation exposes authentication tokens (ASF OAuth tokens and session cookies transmitted in cleartext), vote contents (transmitted from client to server in HTTP request body before encryption), and election management operations.

### Remediation
Make TLS mandatory by enforcing certificate validation at startup - fail with critical error if certfile/keyfile are missing or invalid. Create explicit `ssl.SSLContext` with `minimum_version=TLSv1_2` and restricted cipher suites ('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES') instead of passing raw file paths. Remove config documentation suggesting plain HTTP is acceptable. Add HSTS response header ('Strict-Transport-Security: max-age=31536000; includeSubDomains') to all responses. For ASGI mode, document mandatory Hypercorn TLS configuration and add startup validation of X-Forwarded-Proto or equivalent. Consider adding an HTTP listener that returns 301 redirects to HTTPS to handle accidental plaintext connections.

### Acceptance Criteria
- [ ] Add startup validation requiring TLS configuration
- [ ] Create explicit ssl.SSLContext with strong settings
- [ ] Add HSTS header to all responses
- [ ] Document ASGI TLS requirements
- [ ] Test that server fails to start without TLS config

### References
- Source Reports: 12.2.1.md, 12.2.2.md, 12.3.1.md, 12.3.3.md, 12.3.4.md, 12.3.5.md, 4.1.2.md
- Related Findings: None

### Priority
Critical - Authentication tokens transmitted in plaintext

---

## Issue: FINDING-009 - Complete Absence of Authenticated Data Clearing from Client Storage
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application completely lacks mechanisms to clear authenticated data from client storage after session termination. No `Clear-Site-Data` HTTP header is sent on any response, no logout endpoint exists to trigger session termination and cleanup, no `Cache-Control` headers prevent browser caching of authenticated pages, and no client-side JavaScript clears DOM/storage when session ends.

### Details
- **Severity:** Critical
- **CWE:** CWE-524
- **ASVS Sections:** 14.3.1
- **ASVS Levels:** L1
- **Affected Files:**
  - `v3/server/pages.py` (lines 85-95, 148, 186, 528)

All 12+ authenticated routes inject voter identity (uid, name, email) and election data into HTML responses via the `basic_info()` function. Without cache-control headers, browsers cache these pages containing sensitive voter information. In the context of a voting system, this enables voter privacy violations through browser cache on shared computers, exposing who voted and in which elections, violating ballot secrecy principles.

### Remediation
1. Add logout endpoint with `Clear-Site-Data` header that destroys server-side session and sends `Clear-Site-Data: "cache", "cookies", "storage"` header. 2. Add `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` headers to all authenticated responses via `after_request` middleware. 3. Add client-side cleanup JavaScript as fallback that clears sessionStorage on beforeunload and periodically checks session validity, clearing DOM and storage if session expired or server unreachable. 4. Mark sensitive DOM elements in templates with `data-sensitive` attribute for targeted cleanup.

### Acceptance Criteria
- [ ] Implement logout endpoint with Clear-Site-Data header
- [ ] Add Cache-Control headers to authenticated responses
- [ ] Add client-side cleanup JavaScript
- [ ] Test that cached data is cleared on logout
- [ ] Verify no voter information persists in browser cache

### References
- Source Reports: 14.3.1.md
- Related Findings: None

### Priority
Critical - Voter privacy violations through cached data on shared computers

---

## Issue: FINDING-010 - No Documented Risk-Based Remediation Timeframes and No SBOM for Security-Critical Dependencies
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application has no Software Bill of Materials (SBOM), no dependency manifest, no version pinning, and no documented risk-based remediation timeframes for third-party components. The application's entire security model depends on cryptographic libraries (cryptography for Fernet encryption, argon2-cffi for key derivation) used extensively in crypto.py and election.py.

### Details
- **Severity:** Critical
- **CWE:** CWE-1395
- **ASVS Sections:** 15.1.1, 15.1.2, 15.2.1
- **ASVS Levels:** L1, L2
- **Affected Files:**
  - `v3/steve/crypto.py` (lines 21-24, 58-94)
  - `v3/steve/election.py` (lines 283-287, 320-333)
  - `v3/server/main.py` (lines 1, 29, 37-38)

Without documented remediation timeframes, a published CVE in these libraries could remain unpatched indefinitely with no organizational accountability. The uv run --script invocation without a lock file resolves dependencies at install time, creating inconsistent environments and exposing the system to supply chain attacks. This renders vulnerability scanning impossible, eliminates build reproducibility, and creates compliance failures.

### Remediation
1. Create a Dependency Security Policy document (DEPENDENCY-POLICY.md) that includes: (a) Software Bill of Materials (SBOM) in CycloneDX or SPDX format, (b) Component Risk Classification, (c) Vulnerability Remediation Timeframes with severity-based response times, (d) General Update Cadence, (e) Monitoring Process. 2. Create pyproject.toml with pinned dependencies. 3. Generate and commit lock file using 'uv lock' or 'pip-compile --generate-hashes'. 4. Generate and maintain SBOM. 5. Integrate automated vulnerability scanning via pip-audit in CI/CD pipeline. 6. Enable GitHub Dependabot or Renovate for automated dependency updates.

### Acceptance Criteria
- [ ] Create DEPENDENCY-POLICY.md with SBOM and remediation timeframes
- [ ] Create pyproject.toml with pinned dependencies
- [ ] Generate and commit lock file
- [ ] Integrate pip-audit into CI/CD
- [ ] Enable automated dependency updates

### References
- Source Reports: 15.1.1.md, 15.1.2.md, 15.2.1.md
- Related Findings: None

### Priority
Critical - No visibility into dependency vulnerabilities or remediation plan

---

## Issue: FINDING-011 - Inconsistent Field Filtering — Election List Methods Return Raw Database Rows
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The codebase demonstrates awareness of the need to exclude sensitive cryptographic fields through an explicit filtering control in `get_metadata()`, but this control is not applied to three parallel code paths that also return election data to user-facing page templates. The methods `open_to_pid()`, `upcoming_to_pid()`, and `owned_elections()` return raw database rows without Python-level field filtering.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 15.3.1
- **ASVS Levels:** L1
- **Affected Files:**
  - `v3/steve/election.py` (lines 407-412, 420-436, 438-446)
  - `v3/server/pages.py` (lines 155-162, 320-324, 477-519)

If the SQL queries include `salt` or `opened_key` columns, these cryptographic materials flow into the template rendering context for every authenticated user viewing the voter or admin pages. With `opened_key` and `mayvote.salt`, an attacker can compute `vote_token` values for any eligible voter, decrypt existing votes, and submit forged votes. The absence of Python-level filtering creates a single-layer defense that violates defense-in-depth principles.

### Remediation
Apply the same explicit field construction pattern used in `get_metadata()` to all class methods that return election data. Implement a `_safe_election_summary()` static method that constructs a safe election summary excluding cryptographic fields (salt, opened_key), and apply it in `open_to_pid()`, `upcoming_to_pid()`, and `owned_elections()`. Add a defense-in-depth guard in `postprocess_election()` that explicitly deletes sensitive fields if they exist. Audit `queries.yaml` to confirm that queries do NOT select `salt` or `opened_key` columns. Establish a coding standard that ALL methods returning data objects to callers outside the `Election` class MUST use explicit field construction (allowlist pattern), never raw query passthrough.

### Acceptance Criteria
- [ ] Implement _safe_election_summary() method
- [ ] Apply field filtering to all election list methods
- [ ] Add defense-in-depth guard in postprocess_election()
- [ ] Audit queries.yaml for sensitive field selection
- [ ] Test that cryptographic fields never reach templates

### References
- Source Reports: 15.3.1.md
- Related Findings: None

### Priority
Critical - Cryptographic material exposure enables vote forgery

---

## Issue: FINDING-012 - Tally CLI Operations Lack Security Audit Trail
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The tally script performs the most sensitive operation in the system—decrypting all encrypted votes to compute election results. Despite this, the entire tally execution path contains zero audit logging for data access. This represents a Type A gap—no logging control exists at all for this critical operation.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 16.1.1, 16.2.1, 16.3.1, 16.3.2
- **ASVS Levels:** L2, L3
- **Affected Files:**
  - `v3/server/bin/tally.py` (lines 136-160, 102-133, 145-171, 88-142, 76-113, 138-165, 98-135, 120-150, 85-115)

An administrator runs tally.py and all votes in an election are decrypted and displayed. No log record exists of who accessed this data, when, or which election was tallied. The tallying operation is the single most sensitive operation in the system—it decrypts all encrypted votes, revealing vote content. Without audit logging: there is no record of who initiated tallying, when votes were decrypted, whether --spy-on-open-elections was used to tally an election that hasn't closed yet, and the voter list is also extracted without logging.

### Remediation
Add comprehensive audit logging to tally operations including: operator identity (via os.environ.get('USER')), election ID, issue ID, spy_on_open flag status, start/completion timestamps. Log tally initiation with _LOGGER.info() at start of main(). Log tampering detection with _LOGGER.critical() if detected. Log per-issue tallying with _LOGGER.info() including issue IID. Log tally completion with operator and election ID. Example: _LOGGER.info(f'Tally initiated by system user "{invoking_user}" for election[E:{election_id}] spy_on_open={spy_on_open}')

### Acceptance Criteria
- [ ] Add audit logging to tally script entry point
- [ ] Log operator identity, election ID, timestamps
- [ ] Log tampering detection events
- [ ] Log per-issue tally operations
- [ ] Test log output includes all required fields

### References
- Source Reports: 16.1.1.md, 16.2.1.md, 16.3.1.md, 16.3.3.md, 16.3.2.md
- Related Findings: None

### Priority
Critical - No audit trail for vote decryption operations

---

## Issue: FINDING-013 - Tampering Detection Event Bypasses Structured Logging Framework
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The most critical security event in the entire voting system—detection of election tampering—bypasses the configured structured logging framework and outputs only to stdout via print(). The logging control (_LOGGER) is imported, configured, and used elsewhere in the same file for less critical events, but is NOT invoked for the highest-severity security event.

### Details
- **Severity:** Critical
- **CWE:** None specified
- **ASVS Sections:** 16.1.1, 16.2.1, 16.2.3, 16.2.4, 16.3.2, 16.3.3
- **ASVS Levels:** L2
- **Affected Files:**
  - `v3/server/bin/tally.py` (lines 124, 152, 153-155, 119, 151, 129, 140-141, 145-147, 133-136)

Election tampering detection uses print() instead of structured logging means: (1) Alert Loss Risk - stdout may not be captured by log aggregation systems, (2) No Forensic Timeline - without timestamp and operator identity, investigators cannot reconstruct when tampering was detected, (3) False Security Confidence - security team believes logging covers all events when the most critical one is excluded, (4) No SIEM Correlation - cannot correlate tampering detection with other security events.

### Remediation
Replace print() statements with structured logging using _LOGGER.critical() for tampering detection. Add complete ASVS 16.2.1 metadata including timestamp, operator identity, system context, and structured event type. Example: _LOGGER.critical(f'TAMPERING_DETECTED: election[E:{election_id}] has been tampered with. Tally aborted. db_path={db_fname} spy_on_open={spy_on_open}'). Maintain print() for CLI user feedback but ensure security events are logged to structured logging framework. Add unit tests to verify critical events are logged with caplog assertions.

### Acceptance Criteria
- [ ] Replace print() with _LOGGER.critical() for tampering detection
- [ ] Add complete metadata to log messages
- [ ] Maintain print() for user feedback
- [ ] Add unit tests verifying logging with caplog
- [ ] Test SIEM integration receives tampering alerts

### References
- Source Reports: 16.1.1.md, 16.2.1.md, 16.2.3.md, 16.2.4.md, 16.3.2.md, 16.3.3.md
- Related Findings: None

### Priority
Critical - Tampering detection bypasses audit logging

---

## Issue: FINDING-014 - Error Handling Pattern Exists but Not Applied to State-Changing Endpoints
**Labels:** bug, security, priority:critical
**Description:**
### Summary
A secure error handling pattern exists in do_vote_endpoint that catches exceptions, logs details server-side, and returns generic error messages to users. However, this pattern is not applied to five other state-changing endpoints that perform security-critical operations. These unprotected endpoints call business logic methods that use assert statements for state validation, which will raise unhandled AssertionError exceptions when violated.

### Details
- **Severity:** Critical
- **CWE:** CWE-209
- **ASVS Sections:** 16.5.1, 16.5.2
- **ASVS Levels:** L2
- **Affected Files:**
  - `v3/server/pages.py` (lines 498, 520, 538, 563, 586)
  - `v3/steve/election.py` (lines 75-89, 122-128, 190-207, 209-220, 222-233)

Stack traces could expose cryptographic parameters (opened_key, salt values), database file paths, query structures, and internal election state machine design. In debug mode, full source code context and all local variables in each stack frame are exposed.

### Remediation
Option A: Apply try-except pattern to each endpoint (consistent with do_vote_endpoint). Wrap all business logic calls in try-except blocks that catch Exception, log full details server-side with _LOGGER.error(), and return generic flash messages to users. Option B (preferred): Replace assert statements with proper validation that returns user-friendly errors. Change assert statements to if checks that raise typed exceptions (e.g., ElectionBadState) which can be caught and handled appropriately in web endpoints.

### Acceptance Criteria
- [ ] Apply try-except pattern to all state-changing endpoints
- [ ] Replace assert statements with explicit checks
- [ ] Log errors server-side with full details
- [ ] Return generic error messages to users
- [ ] Test error handling in debug and production modes

### References
- Source Reports: 16.5.1.md, 16.5.2.md
- Related Findings: FINDING-059

### Priority
Critical - Information disclosure through stack traces

---

## Issue: FINDING-015 - Cross-Election Issue Data Access via Unscoped Queries
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Issue-level queries (q_get_issue, c_edit_issue, c_delete_issue) filter only by iid without constraining to the parent election's eid. Combined with the load_election_issue decorator not validating issue-election affiliation, operations on Election A can read/modify/delete issues belonging to Election B.

### Details
- **Severity:** Critical
- **CWE:** CWE-639
- **ASVS Sections:** 8.2.2, 8.3.3, 8.4.1
- **ASVS Levels:** L1, L2, L3
- **Affected Files:**
  - `v3/queries.yaml` (q_get_issue, c_edit_issue, c_delete_issue)
  - `v3/steve/election.py` (lines 145, 160, 170)
  - `v3/server/pages.py` (line 175)

This allows an attacker to bypass election state restrictions by routing operations through an editable election. An attacker can read issue titles, descriptions, and vote configurations from other elections, edit issues in open/closed elections by routing through an editable election (bypasses state machine), and delete issues from other elections, destroying voting data and election integrity. This is a cross-tenant data access vulnerability where the tenant boundary (election) is not enforced at the query level.

### Remediation
Add election scoping to all issue queries by adding 'AND eid = ?' to q_get_issue, c_edit_issue, and c_delete_issue queries in queries.yaml. Modify get_issue(), edit_issue(), and delete_issue() methods in election.py to pass self.eid as an additional parameter. Add rowcount checks after UPDATE/DELETE operations to detect cross-election attempts and raise IssueNotFound exception when no rows are affected. This ensures issues can only be accessed within the context of their parent election.

### Acceptance Criteria
- [ ] Add eid constraint to all issue queries
- [ ] Pass self.eid to all issue operations
- [ ] Add rowcount checks after UPDATE/DELETE
- [ ] Test cross-election access is blocked
- [ ] Verify IssueNotFound is raised appropriately

### References
- Source Reports: 8.2.2.md, 8.3.3.md, 8.4.1.md
- Related Findings: FINDING-028, FINDING-251

### Priority
Critical - Cross-election data access and manipulation

---

*[Continuing with remaining 60 findings in same format...]*

Due to length constraints, I've provided the first 15 critical findings. Would you like me to continue with the remaining findings (16-75), or would you prefer a specific subset (e.g., all High severity, specific domains, etc.)?

## Issue: FINDING-076 - Complete Absence of Authentication Event Tracking and Storage
**Labels:** bug, security, priority:high
**Description:**
### Summary
The database schema defines five tables (election, issue, person, mayvote, vote) but none track authentication events. No table stores login attempts, timestamps, source IPs, user agents, geolocation data, or authentication outcomes. Without persistent storage of authentication events, it is structurally impossible to detect suspicious patterns or notify users.

### Details
The person table stores only pid, name, and email — no last_login, last_login_ip, failed_login_count, or similar fields. There is no auth_event or audit table for tracking authentication activity. This violates CWE-778 and ASVS 6.3.5 (L3) requirements for authentication event logging.

**Affected files:**
- v3/schema.sql (entire file)
- v3/docs/schema.md

### Remediation
Add an authentication audit table and last-login tracking:

```sql
CREATE TABLE auth_event (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    pid        TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('login_success', 'login_failure', 'mfa_partial', 'logout')),
    ip_address TEXT,
    user_agent TEXT,
    geo_hint   TEXT,
    created_at INTEGER NOT NULL,
    notified   INTEGER DEFAULT 0 CHECK (notified IN (0, 1)),
    FOREIGN KEY (pid) REFERENCES person(pid) ON DELETE RESTRICT
) STRICT;

CREATE INDEX idx_auth_event_pid ON auth_event(pid);
CREATE INDEX idx_auth_event_created ON auth_event(created_at);

ALTER TABLE person ADD COLUMN last_login_at INTEGER;
ALTER TABLE person ADD COLUMN last_login_ip TEXT;
```

### Acceptance Criteria
- [ ] auth_event table created with proper schema
- [ ] Indexes added for performance
- [ ] person table extended with last_login fields
- [ ] Authentication events logged on login/logout
- [ ] Test added for authentication event storage
- [ ] Test added for suspicious pattern detection

### References
- CWE-778: Insufficient Logging
- ASVS 6.3.5
- Source: 6.3.5.md

### Priority
High

---

## Issue: FINDING-077 - No Suspicious Authentication Detection Logic in Session Handling
**Labels:** bug, security, priority:high
**Description:**
### Summary
The basic_info() function reads session data but performs no analysis of authentication context. It does not capture or evaluate client IP, user agent, geolocation, time since last authentication, or prior failed attempts. An attacker who compromises credentials can authenticate from different locations/devices without detection.

### Details
Authentication is delegated to asfquart.auth.require decorators, but no post-authentication hook exists to evaluate the authentication event. Every authenticated endpoint calls basic_info() which reads uid, fullname, email from session without any contextual validation.

**Affected files:**
- v3/server/pages.py:57-86, 136-169, 171-264, 391-398, 570-576

### Remediation
Implement a post-authentication hook that:
1. Checks for unusual IP/location by comparing current IP against last authentication event
2. Checks for login after long inactivity by comparing timestamps
3. Checks for success after recent failures
4. Records all authentication events with IP, user agent, and timestamp
5. Notifies users via email or in-app alert when suspicious patterns detected

### Acceptance Criteria
- [ ] Post-authentication hook implemented
- [ ] IP/location comparison logic added
- [ ] Inactivity detection implemented
- [ ] Failed attempt tracking added
- [ ] User notification mechanism created
- [ ] Tests added for suspicious pattern detection

### References
- CWE-223: Omission of Security-relevant Information
- ASVS 6.3.5
- Source: 6.3.5.md

### Priority
High

---

## Issue: FINDING-078 - Voter access cannot be revoked during open elections due to cryptographic locking
**Labels:** bug, security, priority:high
**Description:**
### Summary
When an election is opened, the voter roster is cryptographically bound into the opened_key via tamper detection. Any modification causes is_tampered() to return True. The Election class has no remove_voter(), suspend_voter(), or revoke_voter_access() method. If a voter's authentication is compromised during an active election, administrators can only do nothing or close the entire election.

### Details
gather_election_data() includes ALL voter PIDs and emails in the hash. Tamper detection verifies this hash hasn't changed. This creates an impossible choice during security incidents: allow compromised accounts to vote or invalidate the entire election.

**Affected files:**
- v3/steve/election.py:85-117, 210, 292-303

### Remediation
Implement voter suspension mechanism that works with tamper detection by creating a separate suspension table checked during vote submission but NOT part of the tamper-detection hash:

1. Add suspend_voter() method to record suspensions
2. Modify add_vote() to check _is_voter_suspended() before accepting votes
3. Create suspended_voters SQL table
4. Add admin endpoint POST /admin/suspend-voter/&lt;eid&gt;
5. Add audit logging for suspension actions

### Acceptance Criteria
- [ ] suspended_voters table created
- [ ] suspend_voter() method implemented
- [ ] add_vote() checks suspension status
- [ ] Admin endpoint for suspension added
- [ ] Suspension does not trigger tamper detection
- [ ] Tests added for voter suspension
- [ ] Audit logging implemented

### References
- ASVS 6.5.6
- Source: 6.5.6.md

### Priority
High

---

## Issue: FINDING-079 - No Verification of IdP Authentication Strength or Method
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses Apache OAuth but never requests, receives, or validates authentication strength metadata (equivalent to OIDC 'acr', 'amr', 'auth_time') from the IdP. This applies to all endpoints, including highly sensitive voting and election lifecycle operations. The application cannot distinguish between MFA and password-only authentication.

### Details
Since Apache OAuth (not OIDC) is used, no ID Token with standard claims is available. ASVS 6.8.4 specifically requires documented fallback approach assuming minimum strength authentication. No such documentation or compensating control exists.

**Affected files:**
- v3/server/main.py:40-44
- v3/server/pages.py:56-83, 367-407, 409-429, 433-452, 454-472

### Remediation
**Option A** (if IdP can provide metadata):
Extract authentication metadata (acr, amr, auth_time) from IdP response. Implement require_strong_auth() to enforce minimum authentication strength for sensitive operations.

**Option B** (documented fallback per ASVS 6.8.4):
Add to ARCHITECTURE.md that Apache OAuth doesn't provide acr/amr/auth_time and application assumes MINIMUM strength authentication. Implement compensating controls:
- Session lifetime limited to 30 minutes for voting
- Re-authentication required before casting votes
- Election management restricted to verified PMC members

### Acceptance Criteria
- [ ] Authentication strength verification implemented OR
- [ ] Documented fallback with compensating controls
- [ ] Session age checks implemented
- [ ] Re-authentication for sensitive operations
- [ ] Tests added for authentication strength validation

### References
- ASVS 6.8.4
- Source: 6.8.4.md

### Priority
High

---

## Issue: FINDING-080 - No Session Inactivity Timeout or Absolute Maximum Session Lifetime
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application reads sessions from federated SSO but implements no controls to coordinate session lifetimes. basic_info() performs binary session existence check with no validation of session age, expiry, or freshness. If SSO provider issues long-lived tokens, the voting application honors them indefinitely.

### Details
No idle timeout means abandoned sessions remain valid. No evidence exists that application-layer session is invalidated when SSO provider terminates the IdP session. ASVS 7.1.3 explicitly requires documentation of 'controls to coordinate session lifetimes' — none exists.

**Affected files:**
- v3/server/pages.py:44-71, 62-88, 45-68
- v3/server/main.py:33-46

### Remediation
Implement session timeouts at application layer:
- SESSION_INACTIVITY_TIMEOUT = 900 seconds (15 minutes per NIST AAL2)
- SESSION_ABSOLUTE_LIFETIME = 43200 seconds (12 hours)

Modify basic_info() to:
1. Check absolute session lifetime against created_at
2. Check inactivity timeout against last_active
3. Destroy expired sessions with asfquart.session.destroy()
4. Update last_active on valid sessions

Configure session cookie with appropriate settings.

### Acceptance Criteria
- [ ] Session timeout constants configured
- [ ] basic_info() checks session age
- [ ] Expired sessions destroyed automatically
- [ ] last_active timestamp updated on requests
- [ ] Session cookie settings configured
- [ ] Tests added for timeout behavior

### References
- ASVS 7.1.1, 7.3.1, 7.3.2, 7.1.3, 7.6.1
- CWE-613
- Source: 7.1.1.md, 7.3.1.md, 7.3.2.md, 7.1.3.md, 7.6.1.md

### Priority
High

---

## Issue: FINDING-081 - No Session Termination (Logout) Endpoint Exists
**Labels:** bug, security, priority:high
**Description:**
### Summary
No logout endpoint exists anywhere in the codebase. There is no POST /logout, GET /logout, POST /revoke-session, POST /revoke-factor, or POST /suspend-user endpoint. If credentials are compromised through theft, phishing, or device loss, there is no way to revoke the compromised authentication factor or force-invalidate active sessions.

### Details
The /settings and /profile pages are empty stubs with zero authentication factor management. A comprehensive search confirms no revocation endpoint exists. User/account management is limited to PersonDB.get_person() (read-only).

**Affected files:**
- v3/server/pages.py (entire file, lines 1-679, 1-508)

### Remediation
Implement logout endpoint:

```python
@APP.get('/logout')
@APP.post('/logout')
@asfquart.auth.require
async def logout():
    await asfquart.session.destroy()
    quart.flash('You have been logged out', 'info')
    return quart.redirect('/', 303)
```

For SSO integration, redirect to IdP's logout endpoint for federated logout. Add logout links to all authenticated page templates.

### Acceptance Criteria
- [ ] Logout endpoint implemented (GET and POST)
- [ ] Session properly destroyed on logout
- [ ] SSO federated logout implemented
- [ ] Logout links added to templates
- [ ] Audit logging for logout events
- [ ] Tests added for logout functionality

### References
- ASVS 7.2.4, 7.3.1, 7.4.1, 6.5.6
- CWE-613
- Source: 7.2.4.md, 7.3.1.md, 7.4.1.md, 6.5.6.md
- Related: FINDING-086, FINDING-099, FINDING-106, FINDING-107

### Priority
High

---

## Issue: FINDING-082 - No Session Regeneration on Authentication
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has no session regeneration logic anywhere. Authentication is handled through OAuth but the application never explicitly regenerates or rotates session tokens upon successful authentication. Session is only ever READ, never regenerated. This creates a session fixation vulnerability.

### Details
A search for session.write, session.create, session.regenerate, session.new, session.rotate, session.clear, or session.destroy yields zero results. An attacker could set a victim's session ID before authentication, then hijack the authenticated session after the victim logs in.

**Affected files:**
- v3/server/pages.py:78-90
- v3/server/main.py:38-42

### Remediation
Add explicit session regeneration in authentication callback:

```python
async def on_authentication_success(user_data):
    old_session = await asfquart.session.read()
    if old_session:
        await asfquart.session.destroy()
    await asfquart.session.create({
        'uid': user_data['uid'],
        'fullname': user_data['fullname'],
        'email': user_data['email'],
        'auth_time': time.time()
    })
```

If asfquart doesn't expose session regeneration APIs, raise as framework requirement.

### Acceptance Criteria
- [ ] Session regeneration on authentication implemented
- [ ] Old session destroyed before creating new one
- [ ] auth_time recorded in new session
- [ ] Tests added for session fixation prevention

### References
- ASVS 7.2.4
- CWE-384: Session Fixation
- Source: 7.2.4.md

### Priority
High

---

## Issue: FINDING-083 - No Re-authentication Before Critical Operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
The most sensitive operations (casting votes, opening elections, closing elections) do not require re-authentication. A stale or compromised session can perform all critical operations without proving the user is still present. Vote submission, election opening, and closing operations require no re-authentication or secondary verification.

### Details
If an attacker gains access to a valid session token, they can immediately perform all critical operations without any additional authentication challenge. This violates NIST SP 800-63C requirements for federation session synchronization.

**Affected files:**
- v3/server/pages.py:466-468, 539-541, 559-561, 372-413, 436-452, 455-470, 393, 460, 480

### Remediation
Implement re-authentication gate for critical operations:

```python
def require_recent_auth(max_age_seconds):
    async def decorator(f):
        async def wrapper(*args, **kwargs):
            s = await asfquart.session.read()
            auth_time = s.get('auth_time', 0)
            if time.time() - auth_time > max_age_seconds:
                await asfquart.session.destroy()
                # Redirect to IdP with prompt=login
                return quart.redirect(idp_reauth_url)
            return await f(*args, **kwargs)
        return wrapper
    return decorator
```

Apply to:
- POST /do-vote/&lt;eid&gt; (max_age=300)
- GET /do-open/&lt;eid&gt; (max_age=300)
- GET /do-close/&lt;eid&gt; (max_age=300)
- POST /do-create-election (max_age=900)
- POST /do-delete-issue/&lt;eid&gt;/&lt;iid&gt; (max_age=900)

Change /do-open and /do-close to POST method with CSRF protection.

### Acceptance Criteria
- [ ] require_recent_auth() decorator implemented
- [ ] Applied to vote submission endpoint
- [ ] Applied to election open/close endpoints
- [ ] Applied to election creation endpoint
- [ ] /do-open and /do-close changed to POST
- [ ] CSRF token validation added
- [ ] Tests added for re-authentication enforcement

### References
- ASVS 7.2.4, 7.5.3, 7.6.1
- CWE-306
- Source: 7.2.4.md, 7.5.3.md, 7.6.1.md
- Related: FINDING-027, FINDING-108

### Priority
High

---

## Issue: FINDING-084 - Session-Verified Identity Not Used for Election Ownership Authorization
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application defines election ownership (owner_pid) and group authorization (authz) fields in the database schema with documentation stating only the owner or authorized group members should edit elections. However, these controls are never enforced in the web layer. The load_election decorator contains only a placeholder comment '### check authz' with no actual logic.

### Details
This allows any authenticated committer to manipulate any election — opening, closing, adding/editing/deleting issues, changing dates — regardless of ownership or group membership. Any of the ~800+ ASF committers can perform administrative operations on any election. This is a Type B gap where the authorization need is explicitly recognized but never implemented.

**Affected files:**
- v3/server/pages.py:448, 468, 486, 513, 537, 369, 375, 319, 164-185

### Remediation
Implement ownership and authorization group verification:

```python
async def verify_election_owner(e: Election):
    s = await asfquart.session.read()
    md = e.get_metadata()
    if s['uid'] != md.owner_pid:
        if md.authz and not await check_group_membership(s['uid'], md.authz):
            quart.abort(403, 'Not authorized to manage this election')
```

Apply this check in load_election decorator or create separate verify_election_owner function. Apply to all management endpoints.

### Acceptance Criteria
- [ ] Ownership verification implemented
- [ ] LDAP group membership check implemented
- [ ] Applied to all management endpoints
- [ ] HTTP 403 returned for unauthorized users
- [ ] Tests added for authorization enforcement
- [ ] Tests verify both owner and group-based access

### References
- ASVS 7.2.1, 4.4.3, 14.1.2, 14.2.4, 14.2.6, 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.1, 8.3.3, 8.4.1, 2.3.2, 2.3.5
- Source: 7.2.1.md, 4.4.3.md, 14.1.2.md, 14.2.4.md, 14.2.6.md, 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.3.1.md, 8.3.3.md, 8.4.1.md, 2.3.2.md, 2.3.5.md

### Priority
High

---

## Issue: FINDING-085 - No Session Termination When User Account Is Deleted or Disabled
**Labels:** bug, security, priority:high
**Description:**
### Summary
When user accounts are deleted via PersonDB.delete_person(), no mechanism exists to terminate active sessions. Deleted users retain full application access until their session naturally expires. basic_info() reads session data without verifying the user still exists or is active. Additionally, there is no disable_person() or is_active field mechanism.

### Details
If a user has participated in any election, their account cannot be deleted due to foreign key constraints, and there is no disable mechanism. The application trusts session data directly without consulting PersonDB to verify current user status.

**Affected files:**
- v3/steve/persondb.py:51-61, 28-73
- v3/server/pages.py:78-92

### Remediation
Implement comprehensive account lifecycle management:

1. Add is_active field to person schema:
```sql
ALTER TABLE person ADD COLUMN is_active INTEGER DEFAULT 1;
```

2. Implement disable_person(pid) method that sets is_active=0 and terminates sessions

3. Modify delete_person() to accept session_manager and call session_manager.revoke_all_sessions_for_user(pid)

4. Modify basic_info() to verify user exists and is active:
```python
pdb = PersonDB()
try:
    person = pdb.get_person(s['uid'])
    if not person.get('is_active', 1):
        await asfquart.session.destroy()
        return {'uid': None}
except PersonNotFound:
    await asfquart.session.destroy()
    return {'uid': None}
```

5. Consider caching user-existence check with short TTL (60 seconds)

### Acceptance Criteria
- [ ] is_active field added to person table
- [ ] disable_person() method implemented
- [ ] delete_person() terminates sessions
- [ ] basic_info() validates user status
- [ ] Session destroyed for deleted/disabled users
- [ ] Tests added for account lifecycle
- [ ] Performance optimization via caching

### References
- ASVS 7.4.2
- Source: 7.4.2.md

### Priority
High

---

## Issue: FINDING-086 - No Administrator Capability to Terminate User Sessions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application provides no mechanism for administrators to terminate active sessions, either for an individual user or for all users. Session management is entirely delegated to the external asfquart framework with no application-level override capability. Administrators cannot respond to account compromises by terminating sessions.

### Details
There is no emergency 'terminate all sessions' capability during a security incident. In a voting system, fraudulent votes can continue to be cast during an active compromise. Exhaustive review of all route handlers, backend classes, database schema, and CLI tools confirms no session management capability exists.

**Affected files:**
- v3/server/pages.py (all routes)
- v3/schema.sql (all tables)
- v3/queries.yaml (all queries)

### Remediation
Implement comprehensive session management:

1. Add session storage table to v3/schema.sql:
```sql
CREATE TABLE session (
    session_id TEXT PRIMARY KEY,
    pid TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_activity INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    is_active INTEGER DEFAULT 1,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (pid) REFERENCES person(pid)
) STRICT;
```

2. Add session management queries to v3/queries.yaml

3. Add admin endpoints:
- GET /admin/sessions
- POST /admin/sessions/terminate/&lt;pid&gt;
- POST /admin/sessions/terminate-all
- POST /admin/sessions/terminate-session/&lt;session_id&gt;

4. Implement session validation middleware using @APP.before_request

5. Create admin template showing active sessions with termination controls

6. Add comprehensive audit logging for all session termination actions

7. Define dedicated admin role (R.admin) for session management

### Acceptance Criteria
- [ ] Session storage table created
- [ ] Session management queries added
- [ ] Admin endpoints implemented
- [ ] Session validation middleware added
- [ ] Admin UI for session management
- [ ] Audit logging implemented
- [ ] Admin role defined and enforced
- [ ] Tests added for session management

### References
- ASVS 7.4.5
- CWE-613
- Source: 7.4.5.md
- Related: FINDING-081, FINDING-099, FINDING-106, FINDING-107

### Priority
High

---

## Issue: FINDING-087 - Complete Absence of Active Session Viewing and Termination for Users
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application defines /profile and /settings pages but neither provides ability to view active sessions or terminate them. Users cannot see their currently active sessions, including device information, IPs, last activity times, or creation timestamps. Full text search reveals no endpoint for terminating sessions.

### Details
If a user's session token is stolen, the user has no mechanism to discover the compromised session exists, revoke it, or revoke all sessions as defensive measure. ASVS 7.5.2 explicitly requires users re-authenticate before terminating sessions, but no re-authentication mechanism exists.

**Affected files:**
- v3/server/pages.py:537-549, 68-78

### Remediation
Implement comprehensive user-facing session management:

1. Add session listing endpoint (/sessions or integrate into /settings) displaying:
- Session ID
- Creation time
- Last activity
- IP address
- User agent
- Current session indicator

2. Implement session termination endpoints with re-authentication:
- POST /sessions/terminate/&lt;session_id&gt;
- POST /sessions/terminate-all (except current)

3. Implement re-authentication flow:
```python
async def verify_reauthentication():
    # Verify password or check recent authentication (< 5 minutes)
    pass

def require_recent_auth():
    # Decorator to enforce re-authentication
    pass
```

4. Add audit logging for all termination operations

### Acceptance Criteria
- [ ] Session listing UI implemented
- [ ] Session termination endpoints added
- [ ] Re-authentication flow implemented
- [ ] require_recent_auth() decorator created
- [ ] Audit logging for session operations
- [ ] Tests added for session management
- [ ] Tests verify re-authentication requirement

### References
- ASVS 7.5.2
- Source: 7.5.2.md

### Priority
High

---

## Issue: FINDING-088 - Missing Explicit Voter Eligibility Check on Vote Submission
**Labels:** bug, security, priority:high
**Description:**
### Summary
The vote viewing page (vote_on_page) correctly checks voter eligibility using q_find_issues before rendering the ballot. However, the vote submission endpoint (do_vote_endpoint) does not perform this check. Instead, it relies on an implicit exception when add_vote() attempts to access .salt on a None mayvote record.

### Details
While the vote ultimately fails, the failure mode is an unhandled exception rather than proper authorization denial. The generic error handler could mask real errors, and an attacker can probe which issues exist by observing error vs. success responses. This violates defense-in-depth as the GET endpoint has explicit authorization while POST relies on implicit failure.

**Affected files:**
- v3/server/pages.py:285-307, 222-228
- v3/steve/election.py:201-207

### Remediation
Add explicit voter eligibility verification in do_vote_endpoint:

```python
@APP.post('/do-vote/<eid>')
@asfquart.auth.require
async def do_vote_endpoint(eid):
    result = await basic_info()
    election = Election(eid)
    
    # Explicit eligibility check
    eligible_issues = set(
        row['iid'] for row in election.q_find_issues.perform(result.uid)
    )
    if not eligible_issues:
        quart.abort(403, 'Not eligible to vote in this election')
    
    form = await quart.request.form
    for iid, votestring in form.items():
        if iid not in eligible_issues:
            _LOGGER.warning(f'User {result.uid} attempted unauthorized vote on issue {iid}')
            quart.abort(403, 'Not eligible to vote on this issue')
        
        election.add_vote(result.uid, iid, votestring, pdb)
```

Create VoterNotEligible exception class and add explicit None check in add_vote() method.

### Acceptance Criteria
- [ ] Explicit eligibility check in do_vote_endpoint
- [ ] 403 returned for ineligible voters
- [ ] Per-issue eligibility verified
- [ ] VoterNotEligible exception created
- [ ] Security logging for unauthorized attempts
- [ ] Tests added for eligibility enforcement
- [ ] Tests verify proper error responses

### References
- ASVS 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.2, 8.3.3, 8.4.1, 8.2.3
- CWE-862
- Source: 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.3.2.md, 8.3.3.md, 8.4.1.md, 8.2.3.md
- Related: FINDING-002, FINDING-003, FINDING-024, FINDING-073, FINDING-103, FINDING-104, FINDING-105

### Priority
High

---

## Issue: FINDING-089 - Argon2d Used Instead of RFC 9106-Recommended Argon2id
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The production _hash() function uses Argon2d (Type.D) while the benchmark function uses Argon2id (Type.ID). Argon2d uses data-dependent memory access patterns, making it vulnerable to side-channel attacks (cache-timing, memory bus snooping). RFC 9106 Section 4 explicitly recommends Argon2id for general-purpose use.

### Details
This affects both the election master key (opened_key) and per-voter tokens (vote_token), potentially compromising ballot encryption and vote anonymity. In shared hosting or cloud environments, an attacker with co-tenant access could use cache timing attacks to extract data-dependent memory access patterns.

**Affected files:**
- v3/steve/crypto.py:80-92, 116-146

### Remediation
Change _hash() to use argon2.low_level.Type.ID:

```python
def _hash(...):
    return argon2.low_level.hash_secret_raw(
        ...,
        type=argon2.low_level.Type.ID,  # Changed from Type.D
        ...
    )
```

**Note:** Changing the Argon2 type will change all derived key values. This must be treated as a key rotation event and cannot be applied to elections that have already been opened. Implement with version flag for new elections only or coordinate migration during maintenance window when no elections are open.

### Acceptance Criteria
- [ ] Argon2 type changed to Type.ID
- [ ] Migration strategy documented
- [ ] Version flag for new elections
- [ ] Existing elections continue to work
- [ ] Tests added for Argon2id usage
- [ ] Performance benchmarks updated

### References
- ASVS 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.2.3, 11.2.4, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.6.1, 11.6.2, 11.7.1, 11.7.2, 6.5.2
- CWE-327
- Source: 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 11.2.3.md, 11.2.4.md, 11.3.3.md, 11.4.2.md, 11.4.3.md, 11.4.4.md, 11.6.1.md, 11.6.2.md, 11.7.1.md, 11.7.2.md, 6.5.2.md
- Related: FINDING-153

### Priority
Medium

---

## Issue: FINDING-090 - Non-Constant-Time Comparison of Cryptographic Key Material
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The is_tampered() function uses Python's standard != operator to compare cryptographic keys (opened_key), which performs byte-by-byte comparison that short-circuits on the first differing byte. This leaks information about the stored key through timing differences.

### Details
An attacker who can trigger tamper checks with controlled election data modifications and observe response timing could gradually reconstruct the opened_key value. The opened_key is the root of trust for the entire key derivation chain — knowledge of it combined with per-voter salts would allow computing vote_token values and decrypting individual votes, breaking voter anonymity.

**Affected files:**
- v3/steve/election.py:335-349

### Remediation
Replace the != operator with hmac.compare_digest() for constant-time comparison:

```python
import hmac

def is_tampered(self, pdb):
    opened_key = self._open_election(pdb)
    md = self._all_metadata()
    return not hmac.compare_digest(opened_key, md.opened_key)
```

This prevents timing oracle attacks that could leak key material.

### Acceptance Criteria
- [ ] hmac.compare_digest() used for key comparison
- [ ] hmac module imported
- [ ] Tests added for constant-time behavior
- [ ] Performance impact assessed

### References
- ASVS 11.1.1, 11.1.2, 11.2.1, 11.2.3, 11.2.4, 11.2.5, 11.3.3, 11.4.2, 11.6.1, 11.7.1
- CWE-208
- Source: 11.1.1.md, 11.1.2.md, 11.2.1.md, 11.2.3.md, 11.2.4.md, 11.2.5.md, 11.3.3.md, 11.4.2.md, 11.6.1.md, 11.7.1.md

### Priority
Medium

---

## Issue: FINDING-091 - HKDF Domain Separation Label Misidentifies Encryption Algorithm
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The HKDF info parameter in _b64_vote_key() uses info=b'xchacha20_key' while the actual encryption uses Fernet (AES-128-CBC + HMAC-SHA256). This violates the principle of accurate domain separation in key derivation and creates a latent key reuse vulnerability.

### Details
The HKDF info parameter provides cryptographic domain separation per NIST SP 800-56C / RFC 5869. If XChaCha20-Poly1305 is later added alongside Fernet, both would derive keys with info=b'xchacha20_key', meaning the same key material feeds two different algorithms — a key reuse violation per NIST SP 800-57 §5.2.

**Affected files:**
- v3/steve/crypto.py:51-62, 64-69

### Remediation
Change the HKDF info parameter to accurately reflect the actual algorithm:

```python
def _b64_vote_key(vote_token):
    return hkdf.derive(
        vote_token.encode('utf-8'),
        info=b'fernet_vote_key_v1',  # Changed from xchacha20_key
        ...
    )
```

Document algorithm migration strategy before switching from Fernet to XChaCha20-Poly1305, including versioning scheme and backwards compatibility plan. When migrating to XChaCha20-Poly1305, use a distinct info value like b'xchacha20_vote_key_v2'.

**Note:** Changing the info parameter changes all derived keys and requires coordinated migration similar to Argon2 variant change.

### Acceptance Criteria
- [ ] HKDF info parameter corrected
- [ ] Algorithm migration strategy documented
- [ ] Version flag for new elections
- [ ] Tests added for correct domain separation
- [ ] Migration plan for existing elections

### References
- ASVS 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.3.3, 11.3.4, 11.3.5, 11.6.1, 11.6.2
- CWE-320
- Source: 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 11.3.3.md, 11.3.4.md, 11.3.5.md, 11.6.1.md, 11.6.2.md

### Priority
Medium

---

## Issue: FINDING-092 - Cryptographic Decryption Errors Propagate Without Secure Handling
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Cryptographic operations in crypto.py and their callers in election.py lack exception handling. Raw exceptions from the cryptography library propagate directly to the transport layer (CLI stdout or web response). This can lead to information disclosure (stack traces reveal encryption library and algorithm choices) and availability issues (single corrupted ciphertext prevents tallying of entire election).

### Details
While Fernet's encrypt-then-MAC design prevents padding oracle attacks specifically, the broader fail-secure principle is violated. Stack traces could reveal internal architecture and implementation details.

**Affected files:**
- v3/steve/crypto.py:75
- v3/steve/election.py:290, 250

### Remediation
1. Add dedicated CryptoError exception class in crypto.py

2. Wrap all cryptographic operations in try/except blocks:
```python
class CryptoError(Exception):
    """Sanitized crypto operation error"""
    pass

def decrypt_votestring(vote_key, ciphertext):
    try:
        return fernet.Fernet(vote_key).decrypt(ciphertext.encode('utf-8')).decode('utf-8')
    except Exception as e:
        _LOGGER.debug(f'Decryption failed: {type(e).__name__}')
        raise CryptoError('Vote decryption failed')
```

3. Handle CryptoError gracefully in election.py callers:
```python
def tally_issue(self, iid):
    for row in self.q_recent_vote.perform(iid):
        try:
            plaintext = decrypt_votestring(vote_key, row['vote'])
            # Process vote
        except CryptoError:
            _LOGGER.warning(f'Failed to decrypt vote {hash(row["vote_token"])}')
            continue  # Continue processing other votes
```

4. Add internal debug-level logging of actual exception types for troubleshooting

### Acceptance Criteria
- [ ] CryptoError exception class created
- [ ] All crypto operations wrapped with exception handling
- [ ] Sanitized error messages returned to callers
- [ ] tally_issue continues on decryption failures
- [ ] Debug logging for operational troubleshooting
- [ ] Tests added for error handling

### References
- ASVS 11.2.5
- Source: 11.2.5.md

### Priority
Medium

---

## Issue: FINDING-093 - Election and Issue IDs Generated with Insufficient Entropy
**Labels:** bug, security, priority:medium
**Description:**
### Summary
create_id() generates reference tokens (election IDs eid, issue IDs iid) with only 40 bits of entropy (5 bytes × 8 = 40 bits). ASVS 7.2.3 mandates a minimum of 128 bits for reference tokens. The insufficient entropy becomes a security issue due to three compounding factors: authorization is systematically incomplete, IDs are exposed in URLs, and brute-force is feasible (40 bits = ~1.1 trillion possible values).

### Details
Without authorization checks, discovering a valid eid grants full access. An authenticated attacker can enumerate valid election IDs systematically. Every state-changing endpoint contains '### check authz' comments with no actual authorization enforcement.

**Affected files:**
- v3/steve/crypto.py:118
- v3/schema.sql:61, 104
- v3/steve/election.py:370, 195

### Remediation
Increase ID entropy to at least 128 bits (16 bytes → 32 hex characters):

```python
def create_id():
    return secrets.token_hex(16)  # 16 bytes = 128 bits → 32 hex characters
```

Update schema.sql CHECK constraints for both eid and iid:
```sql
CHECK (length(eid) = 32 AND eid GLOB '[0-9a-f]*')
CHECK (length(iid) = 32 AND iid GLOB '[0-9a-f]*')
```

Create database migration script for existing installations. Add rate limiting on election/issue lookup endpoints as defense-in-depth. Implement monitoring for ID enumeration attempts. Document entropy requirements in developer guidelines.

### Acceptance Criteria
- [ ] create_id() generates 128-bit IDs
- [ ] Schema CHECK constraints updated
- [ ] Database migration script created
- [ ] Rate limiting added to lookup endpoints
- [ ] Monitoring for enumeration attempts
- [ ] Documentation updated
- [ ] Tests added for ID entropy

### References
- ASVS 11.5.1, 6.6.3, 7.2.3
- Source: 11.5.1.md, 6.6.3.md, 7.2.3.md

### Priority
Medium

---

## Issue: FINDING-094 - Argon2 Parameters Adopted Without Application-Specific Tuning
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application uses Argon2 key derivation with significant resource requirements (64MB memory, ~200-500ms CPU time per invocation) in multiple web request paths including vote submission, ballot status checking, and tallying. There is no documentation identifying these operations as resource-intensive, no documented defenses against availability loss, and no documented strategies to avoid response times exceeding consumer timeouts.

### Details
With 10 concurrent vote submissions: 10 × 64MB = 640MB peak memory + 10 × 500ms of CPU blocking. With has_voted_upon() for a voter eligible on 20 issues: 20 sequential Argon2 calls = ~10 seconds response time. For tally_issue() with 100 eligible voters: ~50 seconds; 1,000 voters: ~500 seconds. Without documentation, operators cannot size infrastructure appropriately.

**Affected files:**
- v3/steve/crypto.py:78

### Remediation
Create an operations/architecture document that:

1. Identifies each resource-intensive operation with its CPU/memory profile:
- Vote Submission (add_vote): 1× Argon2 derivation (64MB RAM, ~500ms CPU)
- Ballot Status (has_voted_upon): N × Argon2 where N = number of issues (64MB × N RAM, ~500ms × N CPU)
- Tally Operation: O(N) Argon2 derivations where N = eligible voters per issue (~0.5 seconds × N voters per issue)

2. Documents maximum concurrent requests the server can handle based on Argon2 memory:
- Max concurrent vote submissions = available_memory / 64MB

3. Specifies recommended reverse proxy timeout settings and deployment configuration (worker count, memory limits)

4. Describes recommended defenses:
- Configure reverse proxy to limit concurrent connections
- Set worker count = (available_memory - base_usage) / 64MB
- Limit elections to ≤ 20 issues for has_voted_upon or implement caching
- Schedule tallying during low-usage windows for elections > 200 voters
- Consider batched processing with progress output for elections > 1000 voters

5. Provides timeout guidance:
- Client timeout should be ≥ 2 seconds for vote submission
- For N issues, expect N × 0.5s response time for has_voted_upon
- Tally is CLI-only, NOT exposed via web API

### Acceptance Criteria
- [ ] Operations document created
- [ ] Resource profiles documented
- [ ] Deployment sizing guidance provided
- [ ] Timeout recommendations documented
- [ ] Defense strategies documented
- [ ] Capacity planning guidance added

### References
- ASVS 11.4.4, 15.1.3
- CWE-916
- Source: 11.4.4.md, 15.1.3.md

### Priority
Medium

---

## Issue: FINDING-095 - Missing OIDC Audience Restriction Control
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application explicitly overrides the framework's default OIDC configuration to use a plain OAuth flow against oauth.apache.org. By disabling OIDC, the application loses the standardized ID Token 'aud' (audience) claim verification that ensures tokens issued by the authorization server are intended exclusively for this specific client.

### Details
Without audience-restricted tokens, there is no verifiable mechanism at the application layer to confirm that the access token obtained was issued specifically for the STeVe application.

**Affected files:**
- v3/server/main.py:36-43, 36-41

### Remediation
**Option A (recommended):** Re-enable OIDC and validate the ID Token's 'aud' claim. Remove the OAUTH_URL_INIT and OAUTH_URL_CALLBACK overrides to use OIDC defaults. Configure OIDC_CLIENT_ID for audience validation and set OIDC_VALIDATE_AUDIENCE to True in the app configuration.

**Option B:** Add explicit audience validation through RFC 8707 resource parameter or JWT validation middleware.

### Acceptance Criteria
- [ ] OIDC re-enabled OR
- [ ] Explicit audience validation implemented
- [ ] OIDC_CLIENT_ID configured
- [ ] OIDC_VALIDATE_AUDIENCE set to True
- [ ] Tests added for audience validation

### References
- ASVS 10.1.1, 10.3.1
- CWE-346
- Source: 10.1.1.md, 10.3.1.md
- Related: FINDING-101

### Priority
Medium

---

## Issue: FINDING-096 - Unverified Session Transport May Expose Tokens to Browser
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application reads session data via asfquart.session.read() in every authenticated handler. Quart's default session implementation stores all session data in a client-side signed cookie (itsdangerous-signed, base64-encoded). If the asfquart.session follows Quart's default and the framework stores the OAuth access token or refresh token in the session, these tokens would be serialized into the session cookie sent to the browser with every HTTP response.

### Details
There is no visible configuration in the application ensuring server-side session storage, session cookie attributes (HttpOnly, Secure, SameSite=Lax), or token exclusion from the session cookie payload.

**Affected files:**
- v3/server/pages.py:65-95

### Remediation
Configure server-side session storage and secure cookie attributes:

```python
app.config.update(
    SESSION_TYPE='filesystem',  # or 'redis'
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_NAME='__Host-steve_session'
)
```

Audit the asfquart framework to confirm tokens are stored server-side only and session cookies contain only a session identifier.

### Acceptance Criteria
- [ ] Server-side session storage configured
- [ ] Session cookie attributes set securely
- [ ] asfquart framework audited for token storage
- [ ] Verification that tokens not in cookies
- [ ] Tests added for secure cookie configuration

### References
- ASVS 10.1.1
- CWE-522
- Source: 10.1.1.md

### Priority
Medium

---

## Issue: FINDING-097 - OAuth State Parameter Security Properties Unverifiable
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 10.1.2 requires that the state parameter is: (1) Not guessable, (2) Specific to the transaction, (3) Securely bound to the client and user agent session. The state=%s placeholder confirms the framework is expected to populate this value. However, the OAuth callback handler is not present in any of the provided source files and is entirely within the asfquart framework.

### Details
The state generation logic, validation logic, and session binding mechanism are opaque and cannot be assessed. The basic.csrf_token = 'placeholder' pattern raises concern about whether the analogous OAuth state parameter handling in the framework is robust.

**Affected files:**
- v3/server/main.py:35-38
- v3/server/pages.py:89

### Remediation
1. Obtain and audit the asfquart framework source code
2. Verify that state is generated using secrets.token_urlsafe(32) or equivalent
3. Verify that state is stored in a server-side session before the redirect
4. Verify that the callback handler rejects requests where the returned state does not match the session-stored value
5. Document the framework's OAuth security properties as part of the application's security architecture

### Acceptance Criteria
- [ ] asfquart framework source code audited
- [ ] State generation verified as cryptographically secure
- [ ] State validation verified in callback handler
- [ ] Session binding verified
- [ ] Security properties documented

### References
- ASVS 10.1.2
- CWE-352
- Source: 10.1.2.md
- Related: FINDING-021, FINDING-022, FINDING-023, FINDING-192, FINDING-222

### Priority
Medium

---

## Issue: FINDING-098 - User Identity Derived from Opaque 'uid' Without Verifiable Origin
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application derives user identity from a session field 'uid' without verifiable proof that this identifier originates from non-reassignable OAuth token claims ('iss' + 'sub'). All authorization decisions throughout the application depend on this single 'uid' field, which is populated by the opaque asfquart framework during OAuth token exchange.

### Details
If the asfquart framework populates 'uid' from a reassignable claim (such as 'preferred_username', 'email', or a custom attribute) rather than the immutable 'sub' claim combined with 'iss' validation, a user who inherits a recycled identifier could gain access to another user's election permissions.

**Affected files:**
- v3/server/pages.py:89-98, 77-88

### Remediation
Implement explicit checks in the basic_info() function to extract and validate 'iss' and 'sub' claims from the session:

```python
async def basic_info():
    s = await asfquart.session.read()
    if not s:
        return edict({'uid': None})
    
    # Validate issuer
    iss = s.get('iss')
    if iss != 'https://oauth.apache.org':
        _LOGGER.warning(f'Invalid issuer: {iss}')
        await asfquart.session.destroy()
        return edict({'uid': None})
    
    # Use iss + sub as canonical identity
    sub = s.get('sub')
    if not sub:
        _LOGGER.warning('Missing sub claim')
        await asfquart.session.destroy()
        return edict({'uid': None})
    
    return edict({
        'uid': sub,  # Use immutable sub claim
        'fullname': s.get('fullname', ''),
        'email': s.get('email', '')
    })
```

If the asfquart framework cannot be modified to expose 'iss' and 'sub' in the session, audit the framework's token-to-session mapping to confirm that 'uid' is derived from the 'sub' claim.

### Acceptance Criteria
- [ ] 'iss' and 'sub' claims extracted from session
- [ ] Issuer validation implemented
- [ ] 'sub' used as canonical identity
- [ ] Framework token mapping audited
- [ ] Tests added for identity validation
- [ ] Tests verify issuer validation

### References
- ASVS 10.3.3, 10.5.2
- CWE-287
- Source: 10.3.3.md, 10.5.2.md
- Related: FINDING-026, FINDING-100, FINDING-229, FINDING-235

### Priority
Medium

---

## Issue: FINDING-099 - Missing Authentication Recentness Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application explicitly disables OIDC and uses plain OAuth, thereby removing the standard mechanism (auth_time claim) for verifying authentication recentness. The session object contains only uid, fullname, and email — no authentication timestamp is stored or checked. Sensitive operations (voting, opening/closing elections) proceed without verifying when the user last authenticated.

### Details
In a voting system, stale sessions can be exploited to cast votes on behalf of another user without requiring recent authentication.

**Affected files:**
- v3/server/main.py:37-43
- v3/server/pages.py:85-95, 443-482, 507-525

### Remediation
1. Store auth_time in session during OAuth callback by recording int(time.time()) when session is established

2. Implement a require_recent_auth() helper function:
```python
def require_recent_auth(max_age_seconds=3600):
    async def decorator(f):
        async def wrapper(*args, **kwargs):
            s = await asfquart.session.read()
            auth_time = s.get('auth_time', 0)
            if (time.time() - auth_time) > max_age_seconds:
                # Redirect to re-authentication
                return quart.redirect(idp_reauth_url)
            return await f(*args, **kwargs)
        return wrapper
    return decorator
```

3. Apply this check before sensitive operations like voting, opening/closing elections

4. Redirect to re-authentication if auth_time check fails

### Acceptance Criteria
- [ ] auth_time stored in session
- [ ] require_recent_auth() function implemented
- [ ] Applied to sensitive operations
- [ ] Re-authentication flow implemented
- [ ] Tests added for recentness verification

### References
- ASVS 10.3.4
- CWE-613
- Source: 10.3.4.md
- Related: FINDING-081, FINDING-086, FINDING-106, FINDING-107

### Priority
Medium

---

## Issue: FINDING-100 - Missing Authentication Method and Strength Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has operations of varying sensitivity (viewing elections, voting, managing elections, creating elections) but performs no verification of authentication method or strength. The framework distinguishes R.committer from R.pmc_member roles but these are authorization checks on group membership — not authentication quality.

### Details
There is no verification that the user authenticated with an appropriate method (e.g., MFA for administrative operations). Administrative operations on elections (open, close, create, delete issues) can be performed with any authentication method, including potentially weak ones.

**Affected files:**
- v3/server/pages.py:443-482, 507-525

### Remediation
1. If using OIDC (recommended), capture and verify acr/amr claims from the identity provider

2. Implement a require_auth_strength() function:
```python
def require_auth_strength(required_acr=None, required_amr=None):
    async def decorator(f):
        async def wrapper(*args, **kwargs):
            s = await asfquart.session.read()
            actual_acr = s.get('acr')
            actual_amr = s.get('amr', [])
            
            if required_acr and actual_acr != required_acr:
                quart.abort(403, 'Insufficient authentication strength')
            
            if required_amr and not any(m in actual_amr for m in required_amr):
                quart.abort(403, 'MFA required for this operation')
            
            return await f(*args, **kwargs)
        return wrapper
    return decorator
```

3. For election management operations requiring MFA, check that actual_amr includes values like 'mfa', 'otp', or 'hwk'

4. Return 403 error if authentication strength is insufficient

### Acceptance Criteria
- [ ] acr/amr claims captured from IdP
- [ ] require_auth_strength() function implemented
- [ ] Applied to administrative operations
- [ ] MFA verification for sensitive operations
- [ ] Tests added for auth strength verification

### References
- ASVS 10.3.4
- CWE-287
- Source: 10.3.4.md
- Related: FINDING-026, FINDING-098, FINDING-229, FINDING-235

### Priority
Medium

---

[Continuing with remaining 25 findings in next response due to length...]

## Issue: FINDING-151 - Sensitive Voter Identity Data Stored in Session (Likely Cookie-Backed)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application stores sensitive voter identity data (PII) directly in the session object, which in Quart's default configuration is implemented as a client-side signed cookie. The session contains uid (voter identifier), fullname (voter full name), and email (voter email address). Additionally, flash messages stored in the session may contain election-specific data such as issue IDs and election titles, potentially revealing voter-to-issue mappings. The session cookie is base64-encoded and signed but not encrypted, making it readable by anyone with access to browser DevTools, file system, or via XSS if HttpOnly flag is not set. ASVS 14.3.3 allows session tokens in cookies but not sensitive data - a session token should be an opaque identifier, not a container for user PII.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 62-80, 107-113)

**CWE:** None specified
**ASVS:** 14.3.3 (L2)

### Remediation
Option 1 (Recommended): Configure a server-side session backend (Redis, filesystem, SQLAlchemy, memcached) so only an opaque session ID is stored in the browser cookie. Set SESSION_TYPE to appropriate backend, configure SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, and SESSION_COOKIE_SAMESITE='Lax'. Option 2: Minimize cookie-based session data by storing only the session identifier (uid) in the cookie and looking up user details server-side on each request from persondb. Option 3: If cookie-based sessions must be used with full data, encrypt the cookie contents using an encrypted serializer with URLSafeTimedSerializer. Additionally, verify session backend configuration is documented and add security flags HttpOnly=True, Secure=True, SameSite=Lax to session cookies.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 14.3.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-152 - easydict Library Used Without Documented Risk Assessment
**Labels:** bug, security, priority:medium
**Description:**
### Summary
easydict is used pervasively throughout the Election class to wrap database results and return data structures. This library is a small utility package with a narrow contributor base, has no documented security review process, converts dict keys to object attributes which could mask key collisions or unexpected attribute access patterns, and is used to wrap security-sensitive data (election metadata including owner_pid, authz, salt, opened_key). Per ASVS 15.1.4 definition, a library that is poorly maintained or lacks security controls around its development processes qualifies as a risky component that must be highlighted in documentation.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 24, 146-156, 216, 259, 310)

**CWE:** None specified
**ASVS:** 15.1.4 (L3)

### Remediation
1. Document easydict as a risky component per ASVS 15.1.4. 2. Consider replacing with Python standard library alternatives such as dataclasses (Python 3.7+) or typing.NamedTuple to eliminate dependency on minimally-maintained third-party library. Example: Use @dataclass decorator to create ElectionMetadata, IssueData, and VoteData classes with explicit type annotations for all fields including eid, title, owner_pid, authz, state, created, salt, opened_key, owner_name, and owner_email.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.1.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-153 - Low-Level Argon2 API with Argon2d Variant Not Documented as Risky Decision
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The code is in a transitional state between Fernet (AES-128-CBC + HMAC-SHA256) and XChaCha20-Poly1305 encryption. The HKDF parameters are already configured for the future algorithm (info=b'xchacha20_key', length=32 for XChaCha20), but the actual encryption still uses Fernet. This creates a mismatch between the key derivation context (info parameter) and actual usage. The TODO comment indicates planned changes to a cryptographic dependency, but no documentation captures this planned migration, its timeline, or associated risks. The info parameter in HKDF provides domain separation — using xchacha20_key as the info while actually using the key for Fernet means the cryptographic binding is technically incorrect. This represents undocumented technical debt in dangerous functionality.

### Details
**Affected Files:**
- `v3/steve/crypto.py` (lines 23, 87-101, 125-145)

**CWE:** CWE-327
**ASVS:** 15.1.4, 15.1.5, 15.2.5 (L3)

### Remediation
1. Document the cryptographic migration plan in SECURITY.md or architecture documentation including timeline and risk assessment. 2. Fix the HKDF info parameter to match current usage by changing info=b'xchacha20_key' to info=b'fernet_vote_key_v1' to correctly reflect current Fernet usage. 3. Document the future XChaCha20-Poly1305 library dependency in the component risk assessment before adoption. 4. Document migration requirements including: current state (Fernet with correct info parameter), target state (XChaCha20-Poly1305 with new info parameter like b'xchacha20_vote_key_v1'), migration requirements (re-encryption of active election votes), and requirement that HKDF info MUST change to ensure domain separation. When migrating to XChaCha20-Poly1305, update the info parameter with appropriate documentation of the cryptographic library change and security review of the new dependency.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.1.4.md, 15.1.5.md, 15.2.5.md
- Related Findings: FINDING-089

### Priority
Medium

---

## Issue: FINDING-154 - cryptography.hazmat and argon2.low_level API Usage Not Documented as Dangerous Functionality
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The codebase uses two explicitly dangerous low-level cryptographic APIs without formal documentation: cryptography.hazmat module (explicitly named 'hazardous materials' by maintainers) and argon2.low_level module (bypasses high-level safety features). The cryptography library's hazmat module documentation states: 'This is a Hazardous Materials module. You should ONLY use it if you're 100% absolutely sure that you know what you're doing.' The code contains only brief inline comments but no formal documentation that inventories all hazmat/low-level crypto usage, explains why high-level APIs were insufficient, documents the security review status, or identifies the specific risks of each operation.

### Details
**Affected Files:**
- `v3/steve/crypto.py` (lines 25, 26, 23, 62, 92)

**CWE:** None specified
**ASVS:** 15.1.5 (L3)

### Remediation
Create a SECURITY.md or architecture document section that inventories dangerous functionality. Document each hazmat/low-level crypto usage including: what operation is performed, why low-level API was required instead of high-level alternatives, specific risks associated with the operation, and parameter choices. Example sections: (1) HKDF-SHA256 in _b64_vote_key: Operation: Key derivation using HKDF with SHA256; Why low-level: Need raw key bytes for Fernet, not password hashing; Risks: Incorrect salt/info usage could compromise key separation; Parameters: 32-byte output for Fernet, domain-specific info parameter. (2) Argon2 hashing in _hash: Operation: Memory-hard key derivation; Why low-level: Need raw hash output, not password verification format; Risks: Parameter misconfiguration could weaken security, Type.D vulnerable to side-channels; Parameters: time_cost=2, memory_cost=65536 (64MiB), parallelism=4.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.1.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-155 - Repeated Vote Submissions Trigger Unbounded Argon2 Computation Without Throttling
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The add_vote() method allows authenticated eligible voters to submit votes without any rate limiting or throttling mechanism. Each vote submission triggers an expensive Argon2 computation (64 MiB memory, 4 CPU threads, ~100ms) before validation or deduplication checks. The code includes a TODO comment acknowledging missing votestring validation, and there is no mechanism to prevent rapid repeated submissions. An authenticated eligible voter could script rapid repeated POST requests to the vote submission endpoint, forcing 1× Argon2 computation (64 MiB memory allocation, 4 CPU threads, ~100ms), 1× HKDF + Fernet encryption, and 1× database INSERT per request. At 10 concurrent requests/second, this consumes ~640 MiB peak memory and saturates 40 CPU threads, degrading service for all other users.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 266-280)

**CWE:** None specified
**ASVS:** 15.2.2 (L2)

### Remediation
1. Validate votestring before expensive operations by checking issue existence and voter eligibility first. 2. Consider short-circuit check if identical vote already exists before computing expensive token. 3. Implement rate limiting at the web layer using quart_rate_limiter with conservative limits (e.g., 5 votes per minute per user). Example: @rate_limit(5, timedelta(minutes=1)) decorator on the vote submission endpoint.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-156 - has_voted_upon() Performs O(N) Argon2 Operations Per Request Without Caching or Bounds
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The has_voted_upon() method iterates over all issues a voter is eligible for and computes an Argon2 hash for each one to generate vote tokens. This operation scales linearly with the number of issues (O(N)) and is likely called on every page load when voters view their election dashboard. There is no caching of computed vote tokens between requests and no upper bound on the iteration count. Each page load for a voter viewing their status triggers this entire computation. With 10 issues, this takes ~1.0s CPU time; with 50 issues, ~5.0s. With concurrent users refreshing the page, server CPU is rapidly saturated.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 350-375)

**CWE:** None specified
**ASVS:** 15.2.2 (L2)

### Remediation
1. Bound the number of issues processed per request (e.g., MAX_ISSUES_PER_CHECK = 100) and raise TooManyIssues exception if exceeded. 2. Consider implementing a time-limited cache for vote status at the web layer to avoid re-computation on page refreshes. 3. Implement session-level caching of vote tokens to avoid repeated Argon2 computations within the same user session.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-157 - tally_issue() Computes Argon2 for Every Eligible Voter Without Resource Bounds or Timeout
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The tally_issue() method queries all eligible voters for an issue and computes an Argon2 hash for each one to derive their vote token, regardless of whether they actually voted. This scales linearly with the number of eligible voters (O(N)) and can result in extremely long-running operations for large elections. While tallying is documented as a privileged CLI operation, the method itself has no enforcement of this restriction and would monopolize server resources if called during normal operations. With 100 eligible voters, this takes ~10s CPU time; with 1,000 voters, ~100s. On shared infrastructure, this degrades web application availability during tallying.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 282-348)

**CWE:** None specified
**ASVS:** 15.2.2 (L2)

### Remediation
1. Log expected resource consumption before starting tally operations to provide visibility into resource impact. 2. Optionally yield control periodically during processing (e.g., every 50 voters) if using async operations. 3. Consider running tally operations in a separate process or with CPU affinity to isolate resource impact from the web server. 4. Implement progress callbacks to monitor long-running tally operations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-158 - Development benchmark function present in production crypto module
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The crypto.py module contains a benchmark_argon2() function (lines 129-158) that is development/test code exposed in the production module. This function executes 8 CPU/memory-intensive Argon2 operations with up to 128MB memory each, creating a potential denial-of-service vector if reachable through any server-side codepath. The function uses hardcoded test salts and print() statements that write to stdout/logs, potentially exposing Argon2 tuning parameters and timing information. Additionally, the benchmark uses argon2.Type.ID while production uses argon2.Type.D, indicating it is purely development tooling that does not represent production behavior.

### Details
**Affected Files:**
- `v3/steve/crypto.py` (lines 129-158, 160-162)

**CWE:** None specified
**ASVS:** 15.2.3 (L2)

### Remediation
Move the benchmark to a separate development-only script (e.g., tools/benchmark_argon2.py) excluded from the production deployment package. Remove benchmark_argon2() function (lines 129-158), the if __name__ == '__main__' block (lines 160-162), and import time (line 26, if unused elsewhere) from crypto.py. Create separate file tools/benchmark_argon2.py with the benchmark code marked as NOT for production deployment.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-159 - DEBUG logging level configured in production ASGI deployment path
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The run_asgi() function in main.py (lines 85-96) is the production code path triggered when the module is imported by Hypercorn. It unconditionally sets logging.DEBUG level on both the root logger and the application logger (_LOGGER.setLevel(logging.DEBUG) on line 96). This causes all application-level debug messages including cryptographic operations, database queries, and election state transitions to be written to production logs. While current debug messages in election.py are relatively benign, the DEBUG level setting means any future debug logging added anywhere in the application will automatically be exposed in production, creating a latent information disclosure risk characteristic of development configuration that was not hardened for production.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 85-96)

**CWE:** None specified
**ASVS:** 15.2.3 (L2)

### Remediation
Change run_asgi() to use logging.INFO as the production-appropriate level. Implement environment variable override for log level configuration: use os.environ.get('STEVE_LOG_LEVEL', 'INFO').upper() to allow operational flexibility while defaulting to secure INFO level. Update both logging.basicConfig(level=logging.INFO) and _LOGGER.setLevel() to use the environment-driven configuration.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-160 - Dependency confusion risk for ASF-namespaced internal package asfquart
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The asfquart package is an ASF-internal web framework wrapper that provides critical security infrastructure including OAuth integration, authentication, and application construction. This package presents an elevated dependency confusion risk. If asfquart is distributed via an internal ASF package repository and the name is not defensively registered on PyPI, an attacker could register asfquart on PyPI with a higher version number. If pip or uv is configured with --extra-index-url (adding internal repo alongside PyPI), the public malicious package could be preferred due to version precedence. The malicious package would execute during import, with full access to the OAuth configuration, authentication flow, and application construction. No configuration restricting the package index source was provided for audit.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 32-38)

**CWE:** None specified
**ASVS:** 15.2.4 (L3)

### Remediation
1. Configure uv or pip to use exclusive index source for ASF packages using tool.uv.sources in pyproject.toml with explicit = true flag. 2. Defensively register the asfquart package name on PyPI (even as an empty placeholder) to prevent name squatting. 3. Configure uv or pip to use --index-url exclusively for ASF packages, preventing fallback to public PyPI. 4. Document the expected repository source for all internal packages.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-161 - No SBOM documenting transitive dependency tree
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's direct dependencies pull in significant transitive dependency chains including cryptography (cffi, pycparser, OS-level OpenSSL bindings), argon2-cffi (argon2-cffi-bindings, cffi, pycparser), asfquart (quart, hypercorn, h11, h2, wsproto, priority, hpack, and more), asfpy (PyYAML, requests, ldap3, and others), and easydict. None of these transitive dependencies are documented in the provided audit materials. Without an SBOM, vulnerabilities in transitive dependencies cannot be tracked, the full attack surface of the application is unknown, and compliance with ASVS 15.2.4's requirement to verify 'all of their transitive dependencies' cannot be satisfied. A compromised or vulnerable transitive dependency would go undetected.

### Details
**Affected Files:**
- Project root (expected location) (N/A)

**CWE:** None specified
**ASVS:** 15.2.4 (L3)

### Remediation
1. Generate and maintain an SBOM using CycloneDX (cyclonedx-py environment -o sbom.json --format json) or syft. 2. Integrate SBOM generation into CI/CD pipeline. 3. Store SBOM artifacts with each release. 4. Implement automated vulnerability scanning against the SBOM. 5. Review transitive dependency changes during dependency updates. 6. Establish policy for regular SBOM review and transitive dependency audits.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-162 - __getattr__ Proxy Undermines Encapsulation of Dangerous Database Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Election class defines explicit public methods with state-machine assertions to guard dangerous operations (e.g., delete() asserts is_editable()). However, the __getattr__ proxy exposes all database cursors defined in queries.yaml to any code holding an Election instance, completely bypassing the state-machine protections. This means a programming error in any API handler that creates an Election instance could inadvertently invoke destructive or state-bypassing database operations without the intended safety checks. For example, election.c_delete_election.perform(eid) can delete an election regardless of state, bypassing the assertion in the delete() method. This undermines protections around dangerous functionality.

### Details
**Affected Files:**
- `v3/steve/election.py` (line 56)

**CWE:** None specified
**ASVS:** 15.2.5 (L3)

### Remediation
Replace the open proxy with explicit, controlled delegation. Remove __getattr__ proxy entirely and define explicit private properties for needed cursors. Alternatively, use __getattr__ with an allowlist: define _ALLOWED_ATTRS as a frozenset explicitly listing each allowed cursor, and raise AttributeError if name is not in the allowlist.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-163 - No Explicit Field Whitelist Enforcement on Form-Handling Endpoints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
All form-handling POST endpoints capture the complete form submission into an EasyDict object without validating or restricting the set of allowed fields. While individual handlers currently extract only specific fields (e.g., form.title, form.description), unexpected fields are silently accepted rather than rejected. The EasyDict class makes any form field accessible as an attribute, meaning any code that accesses form.attacker_field will succeed if the attacker included it in the submission. This creates a structural risk where any future code accessing form.&lt;field&gt; immediately trusts attacker input with no systematic defense preventing mass assignment when handlers evolve.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 493, 549, 572, 453)

**CWE:** None specified
**ASVS:** 15.3.3 (L2)

### Remediation
Implement explicit field whitelisting per action using a helper function. Create an ALLOWED_FIELDS dictionary mapping each action to its permitted fields. Implement an extract_allowed_fields() function that validates form data against the whitelist, logs unexpected fields, and returns HTTP 400 if unexpected fields are present. Example: ALLOWED_FIELDS = {'create_election': {'title'}, 'add_issue': {'title', 'description'}, 'edit_issue': {'title', 'description'}, 'vote': set()}. Apply this helper to all form-handling endpoints before processing the data.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-164 - Vote Submission Handler Does Not Restrict Writable Issue IDs to Voter's Eligible Subset
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote handler accepts vote-* form fields where the issue ID portion is entirely user-controlled from the form key name. The handler validates the issue ID against ALL issues in the election (issue_dict), not the subset the voter is eligible for. The actual eligibility check is in the model's add_vote() method, but it manifests as an AttributeError when accessing .salt on a None mayvote result—not as an explicit authorization decision. This creates two problems: (1) The mayvote check exists but isn't called explicitly—eligibility enforcement happens as a side effect of None attribute access, and (2) Partial batch processing where the loop processes votes sequentially with early return on error, meaning legitimate votes submitted before a failure are committed while later votes are not, leaving the voter in a partial state. The controller layer does not limit which issue IDs (fields) are valid per the specific voter's authorization, violating the ASVS 15.3.3 principle of limiting allowed fields per action.

### Details
**Affected Files:**
- `v3/server/pages.py` (line 453)
- `v3/steve/election.py` (line 216)

**CWE:** None specified
**ASVS:** 15.3.3 (L2)

### Remediation
Pre-filter eligible issue IDs at the controller level before processing any votes. In do_vote_endpoint(), query the voter's eligible issues using election.q_find_issues.perform(result.uid, election.eid) and create a set of eligible_iids. When processing vote-* form fields, validate each extracted iid against eligible_iids before accepting it. If an ineligible iid is submitted, log the attempt and return an error before processing any votes. Additionally, add an explicit eligibility check in add_vote() that raises a custom VoterNotEligible exception if mayvote is None, rather than relying on AttributeError. Consider wrapping the vote processing loop in a database transaction to ensure atomicity.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-165 - Complete Absence of Client IP Address in Security Audit Logs
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 16.2.1 requires 'where' metadata for detailed investigation. For web applications, the source IP address is essential context that is completely absent from all security log entries. Every state-changing operation logs user identity and action details, but never records the IP address from which the request originated. Without source IP addresses, security teams cannot: (1) Detect Compromised Accounts - cannot identify votes/actions from unexpected geolocations, (2) Correlate Multi-Account Attacks - cannot identify single attacker using multiple compromised accounts, (3) Investigate Incidents - cannot determine which requests were malicious during incident response, (4) Enforce Rate Limiting - cannot implement IP-based rate limiting or abuse prevention, (5) Meet Compliance Requirements - many election security standards require IP address logging for audit trails.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 115, 405, 412, 434, 446, 459, 475, 492, 510, 524)

**CWE:** None specified
**ASVS:** 15.3.4, 16.2.1, 16.3.1 (L2)

### Remediation
Create a helper to extract the client IP from the trusted proxy header and include it in all security log entries:

```python
def get_client_ip():
    """Extract client IP from trusted proxy header or fall back to remote_addr."""
    # Only trust X-Forwarded-For from configured trusted proxies
    if quart.request.access_route:
        # access_route[0] is the leftmost (client) IP; only trust if
        # the immediate upstream (remote_addr) is a known proxy
        trusted_proxies = APP.cfg.get('trusted_proxies', set())
        if quart.request.remote_addr in trusted_proxies:
            return quart.request.access_route[0]
    return quart.request.remote_addr

# Usage in handlers:
client_ip = get_client_ip()
_LOGGER.info(
    f'User[U:{result.uid}] IP[{client_ip}] voted on'
    f' issue[I:{iid}] in election[E:{election.eid}]'
)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.4.md, 16.2.1.md, 16.3.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-166 - No Trusted Proxy Configuration for IP Forwarding
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no configuration for trusted proxy headers. When deployed behind a reverse proxy (standard for production web applications), `request.remote_addr` returns the proxy's IP rather than the client's. The Quart framework supports `ProxyFix`-style middleware or explicit `X-Forwarded-For` parsing, but neither is configured. This means even if the application were to start reading IP addresses, it would obtain the wrong value. Without trusted proxy configuration, an attacker can spoof their IP by injecting headers directly. If the application naively reads `X-Forwarded-For` without validating the sender is a trusted proxy, any client can claim any IP address. This impacts any future IP-based security controls (rate limiting, geo-blocking) which would operate on incorrect data, audit logs would record proxy IPs instead of real client IPs, and spoofable headers could be used to bypass IP-based restrictions.

### Details
**Affected Files:**
- `v3/server/api.py` (None)
- `v3/server/pages.py` (None)

**CWE:** None specified
**ASVS:** 15.3.4 (L2)

### Remediation
Configure trusted proxy middleware at application startup:

```python
# In api.py or app initialization
from quart import Quart

APP = asfquart.APP

# Configure trusted proxies (use actual proxy IPs)
APP.config['TRUSTED_PROXIES'] = {'10.0.0.1', '10.0.0.2'}

# Or use Quart's built-in proxy handling
@APP.before_serving
async def configure_proxy():
    # Quart supports proxy_fix via its config
    APP.config['FORWARDED_ALLOW_IPS'] = '10.0.0.1,10.0.0.2'
```

For Quart specifically, use the `ProxyFixMiddleware` or configure `forwarded_allow_ips`:

```python
from quart_proxy_fix import ProxyFix  # or equivalent

app = ProxyFix(APP, x_for=1, x_proto=1, x_host=1)
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-167 - Missing Type Validation on JSON Request Body
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The _set_election_date function accepts JSON request bodies without validating that the parsed data is the expected type (dict) or that nested fields have the expected types (string for date). The code makes type assumptions that can lead to unhandled exceptions. quart.request.get_json() can return None if body isn't valid JSON, causing AttributeError. The date field could be int, bool, list, dict, or null, and fromisoformat() will raise TypeError for non-string inputs, which is not caught by the except ValueError block. This results in 500 errors with potential stack trace exposure and violates ASVS 15.3.5 by making type assumptions without verification.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 93-113)

**CWE:** None specified
**ASVS:** 15.3.5 (L2)

### Remediation
Add explicit type validation after JSON parsing. Check that data is a dict using isinstance(data, dict), validate that date_str is a string using isinstance(date_str, str), and catch both ValueError and TypeError exceptions from fromisoformat(). Example: if not isinstance(data, dict): quart.abort(400, 'Invalid request body'); date_str = data.get('date'); if not isinstance(date_str, str) or not date_str: quart.abort(400, 'Missing or invalid date field'); try: dt = datetime.datetime.fromisoformat(date_str).date(); except (ValueError, TypeError): quart.abort(400, 'Invalid date format')

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-168 - Deserialized KV Data Used Without Type Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The json2kv method deserializes JSON strings from the database without validating that the result is the expected type (dict). Consumers of this data throughout the application assume it's a dict and call .get() methods on it, which will fail if the deserialized value is a different JSON type (array, string, number, etc.). The method returns ANY JSON type (dict, list, str, int, bool, None) and consumers in pages.py and election.py assume dict type without verification. This causes runtime errors during election display or tallying. If KV data contains unexpected types for nested values (e.g., seats as a string instead of integer), tallying could silently produce incorrect results.

### Details
**Affected Files:**
- `v3/steve/election.py` (line 365)
- `v3/server/pages.py` (lines 278-281)
- `v3/steve/election.py` (line 299)

**CWE:** None specified
**ASVS:** 15.3.5 (L2)

### Remediation
Add type validation to json2kv to ensure the deserialized value is a dict, and add field-level type checks for known KV fields. Example: if not j: return None; parsed = json.loads(j); if parsed is not None and not isinstance(parsed, dict): raise ValueError(f'KV data must be a JSON object, got {type(parsed).__name__}'); return parsed. Additionally implement _validate_kv function to check specific fields like seats (must be int) and labelmap (must be dict) for each vote type.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-169 - Unsanitized JSON Object Keys in Data Pipeline to Client-Side Templates
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `labelmap` field in STV issue KV data is an arbitrary key-value dictionary where keys represent candidate labels. These keys are: 1) Deserialized from JSON without any key filtering (`json.loads()`), 2) Converted to an `EasyDict` without filtering, 3) Iterated to produce `candidates` list where each key becomes a `label` value, 4) Passed to the template for client-side rendering. If these labels are used to construct JavaScript objects on the client side (e.g., `{[label]: value}` or `Object.assign({}, labelData)`), keys like `__proto__`, `constructor`, or `prototype` could pollute JavaScript prototypes. The data flow is: Database KV column (JSON text) → json2kv() [election.py:448] — raw json.loads(), no key filtering → list_issues() [election.py:256] — returns edict with unfiltered KV → vote_on_page() [pages.py:258] — extracts labelmap as dictionary → issue.candidates list with arbitrary 'label' keys → EZT template rendering → client-side JavaScript. If client-side JavaScript constructs objects using these labels as keys, an attacker with write access to KV data could pollute JavaScript prototypes, potentially leading to XSS, authentication bypass, or denial of service on the client side.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 444-452, 448, 256)
- `v3/server/pages.py` (lines 258-265)

**CWE:** CWE-1321
**ASVS:** 15.3.6 (L2)

### Remediation
Implement server-side key filtering in the data pipeline by adding a safe key filter to json2kv() that recursively removes dangerous keys (__proto__, constructor, prototype) from parsed JSON objects. Additionally, validate labelmap keys when they are set in add_issue() to reject any keys matching the dangerous key list. Example implementation:

```python
# election.py — Add a safe key filter
DANGEROUS_KEYS = frozenset({'__proto__', 'constructor', 'prototype'})

@staticmethod
def json2kv(j):
    if not j:
        return None
    parsed = json.loads(j)
    return Election._sanitize_keys(parsed)

@staticmethod
def _sanitize_keys(obj):
    if isinstance(obj, dict):
        return {
            k: Election._sanitize_keys(v)
            for k, v in obj.items()
            if k not in Election.DANGEROUS_KEYS
        }
    if isinstance(obj, list):
        return [Election._sanitize_keys(item) for item in obj]
    return obj
```

Also add KV schema validation for STV issues with regex-based key validation to ensure labelmap keys are alphanumeric only.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.6.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-170 - No Explicit Defense Against Intra-Source HTTP Parameter Pollution in Form-Processing Endpoints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Quart's `request.form` returns a Werkzeug `MultiDict` that preserves multiple values for the same parameter name. When this `MultiDict` is passed to `EasyDict()` (which inherits from `dict`), the constructor calls `dict.__init__()`, which invokes `MultiDict.__getitem__()` for each unique key — returning only the first submitted value and silently discarding all subsequent duplicates. This means: (1) Duplicate parameters are silently dropped with no validation, logging, or error, (2) The application has no mechanism to detect or reject HTTP parameter pollution attempts, (3) The behavior (first-value-wins) is an implicit framework artifact, not an explicit security decision. The vulnerable pattern occurs at multiple endpoints where `edict(await quart.request.form)` is used, systematically destroying the MultiDict's ability to represent duplicate parameters.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 405, 448, 508, 532)

**CWE:** None specified
**ASVS:** 15.3.7 (L2)

### Remediation
Create a helper function that validates form inputs are single-valued and rejects requests with duplicate parameters:

```python
from quart import request, abort
from easydict import EasyDict as edict

async def get_single_value_form():
    """Parse request.form, rejecting duplicate parameters (HPP defense)."""
    form = await request.form
    
    # Detect duplicate parameters
    seen = set()
    for key in form:
        values = form.getlist(key)
        if len(values) > 1:
            _LOGGER.warning(
                f'HPP attempt detected: parameter "{key}" submitted '
                f'{len(values)} times from {request.remote_addr}'
            )
            abort(400, f'Duplicate parameter: {key}')
        seen.add(key)
    
    return edict(form)
```

Then replace all instances of `edict(await quart.request.form)` with `form = await get_single_value_form()`. Additionally, for the vote endpoint, validate that only expected parameter names are present using whitelist pattern matching (e.g., `^vote-[a-f0-9]+$`).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.3.7.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-171 - Batch Vote Submission Without Transactional Integrity
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote submission endpoint processes multiple votes from a single user ballot submission by iterating through each vote and calling `add_vote()` individually. Each `add_vote()` call performs a single INSERT that auto-commits immediately in autocommit mode. If any vote in the sequence fails (e.g., election closes mid-batch or an error occurs), all previously committed votes remain in the database while subsequent votes are lost, resulting in a partial ballot submission. In a voting system, the user's ballot submission is the most critical business operation. A partial ballot violates voter intent—the user believed they were submitting all votes together. In elections with multiple issues, voters may have a partial set of votes recorded without clear feedback about which votes succeeded. The user receives a generic error message and is redirected, with no indication of partial success.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 397-437, 373-410, 307-353)
- `v3/steve/election.py` (lines 268-285)

**CWE:** CWE-362
**ASVS:** 15.4.1, 15.4.2, 15.4.3, 2.3.3, 2.3.4, 16.5.2, 16.5.3 (L3, L2)

### Remediation
Create a new `add_votes()` batch method in `election.py` that wraps all vote insertions for a single ballot in a single transaction with explicit BEGIN IMMEDIATE/COMMIT/ROLLBACK. Use `BEGIN IMMEDIATE` before processing any votes in the loop, then commit after all votes are successfully processed. Update the `do_vote_endpoint()` to use this batch method instead of iterating through individual `add_vote()` calls. Implement proper rollback on any error and provide clear feedback to the user about success or complete failure. Consider creating an `add_vote_within_transaction()` method variant that doesn't manage its own transaction boundaries.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.4.1.md, 15.4.2.md, 15.4.3.md, 2.3.3.md, 2.3.4.md, 16.5.2.md, 16.5.3.md
- Related Findings: FINDING-030, FINDING-053

### Priority
Medium

---

## Issue: FINDING-172 - Unbounded Synchronous Vote Processing Loop Amplifies Event Loop Starvation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Vote submission loops over all issues synchronously, performing database reads, PBKDF key derivation, encryption, and database writes for each issue without yielding to the event loop. For elections with many issues, this creates extended blocking proportional to the number of issues. With N issues per election, total blocking time = N × (2 queries + PBKDF + Fernet encrypt + 1 insert). For an election with 20 issues, this results in ~100 synchronous blocking operations in a single request. Additionally, _all_metadata(self.S_OPEN) is re-queried on every iteration, performing redundant state checks that add unnecessary blocking time.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 399-432)
- `v3/steve/election.py` (lines 231-244)

**CWE:** None specified
**ASVS:** 15.4.4 (L3)

### Remediation
Offload each blocking vote operation to thread pool using asyncio.to_thread() within the vote processing loop. Alternatively, create a bulk add_votes_bulk() method that performs a single state check and wraps all inserts in one transaction, reducing per-vote overhead and caching the repeated metadata query.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.4.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-173 - Web Server Log Timestamps Use Local Time Without Timezone Offset, Year, or Seconds
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The web server logging configuration uses DATE_FORMAT = '%m/%d %H:%M' which produces timestamps in local time without timezone offset, year, or seconds. This violates multiple ASVS 16.2.2 requirements: no explicit timezone offset as required, no UTC enforcement as recommended, no year for cross-year correlation, and no seconds precision for event ordering. During DST transitions, timestamps become ambiguous and the same wall-clock time can occur twice, making forensic analysis of security events impossible.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 23, 55-59, 85-91, 20, 51-56, 85-90)
- `v3/server/pages.py` (lines 101, 371, 374, 394-395, 415, 428, 451, 472-473, 489-490)

**CWE:** None specified
**ASVS:** 16.2.2, 16.2.4 (L2)

### Remediation
Replace the DATE_FORMAT constant with ISO 8601 UTC format and explicitly set the formatter converter to time.gmtime. Example: DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'; formatter = logging.Formatter(fmt='[{asctime}|{levelname}|{name}] {message}', datefmt=DATE_FORMAT, style='{'); formatter.converter = time.gmtime. Apply the same pattern to both run_standalone() and run_asgi().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.2.2.md, 16.2.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-174 - Unsynchronized Logging Configuration Between Web Server and Tally CLI Components
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The web server (main.py) and tally CLI (tally.py) use completely different logging configurations with incompatible formats. The web server uses '[{asctime}|{levelname}|{name}] {message}' with '%m/%d %H:%M' timestamps in local time, while the tally CLI uses Python's default format '%(levelname)s:%(name)s:%(message)s' with no timestamps at all. This means the same security event from election.py produces fundamentally different log entries depending on the entry point, making SIEM correlation impossible and violating ASVS 16.2.2's requirement that 'time sources for all logging components are synchronized'.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 23, 55-59, 85-91, 51-56)
- `v3/server/bin/tally.py` (lines 145, 148)
- `v3/steve/election.py` (lines 186, 197, 381)

**CWE:** None specified
**ASVS:** 16.2.2, 16.2.4 (L2)

### Remediation
Create a shared logging configuration module (v3/steve/log_config.py) used by all components. Define LOG_FORMAT, LOG_DATEFMT, and LOG_STYLE constants with a configure_logging() function that both entry points can call. Use ISO 8601 UTC format with time.gmtime converter to ensure consistency. Import and use in both main.py and tally.py.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.2.2.md, 16.2.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-175 - Production Web Endpoints Output Form Data to Undocumented stdout Channel via print()
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Debug `print()` statements in `do_add_issue_endpoint` and `do_edit_issue_endpoint` output unfiltered form data to stdout, including issue titles, descriptions, and potentially CSRF tokens when implemented. The do_add_issue_endpoint() and do_edit_issue_endpoint() functions contain print('FORM:', form) statements that dump all form fields to stdout. All form data including issue titles, descriptions (which may contain confidential candidate information or election details), and any future form fields are written to stdout with uncontrolled retention characteristics. Process stdout may be captured by container logs, systemd journal, or process monitoring systems without appropriate access controls. This data flows to container logs, log aggregation systems (Docker, Kubernetes, CloudWatch), and is accessible to operators/administrators who should not see election content.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 508, 537, 493, 516, 510, 531, 482, 499, 489, 513, 447, 467)

**CWE:** CWE-117
**ASVS:** 16.1.1, 16.2.3, 16.2.4, 16.2.5, 16.4.1, 14.1.1, 14.1.2, 14.2.4 (L2)

### Remediation
Remove all debug print statements from do_add_issue_endpoint() and do_edit_issue_endpoint(). If logging is needed for debugging, log only non-sensitive metadata such as election ID and user ID, never form field values in production. Replace with structured logging at DEBUG level if needed: `_LOGGER.debug(f'Issue form received for election[E:{election.eid}]')`. Configure logging to exclude DEBUG level in production environments. Implement structured logging with SensitiveFieldFilter that removes sensitive fields from log records.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.1.1.md, 16.2.3.md, 16.2.4.md, 16.2.5.md, 16.4.1.md, 16.4.2.md, 14.1.1.md, 14.1.2.md, 14.2.4.md
- Related Findings: FINDING-176, FINDING-182

### Priority
Medium

---

## Issue: FINDING-176 - Log Injection via Unsanitized User-Controlled Input
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-controlled input from form submissions is directly interpolated into log messages using f-strings without encoding newlines or other log control characters. An attacker can inject fake log entries by including newline characters in form fields, undermining log integrity for forensic analysis. Attackers can forge log entries to cover tracks or frame other users, log analysis tools may misparse injected entries, incident investigation can be misled by fabricated audit trails, and this undermines trust in the entire logging infrastructure. Specifically affects election title logging and other user-provided form fields.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 455, 101, 517, 542, 429-431, 459)

**CWE:** CWE-117
**ASVS:** 16.1.1, 16.4.1, 16.3.3 (L2)

### Remediation
Implement and use a sanitize_for_log() utility function that removes control characters and truncates long input before logging. Example: def sanitize_for_log(value: str, max_length: int = 200) -> str: if value is None: return '&lt;none&gt;'; sanitized = re.sub(r'[\r\n\t\x00-\x1f]', ' ', str(value)); if len(sanitized) > max_length: sanitized = sanitized[:max_length] + '...[truncated]'; return sanitized. Apply to all user-controlled values in logs including titles, descriptions, usernames, etc.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.1.1.md, 16.4.1.md, 16.3.3.md
- Related Findings: FINDING-175, FINDING-182

### Priority
Medium

---

## Issue: FINDING-177 - Exception Details in Error Logs May Expose Sensitive Data
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Exception objects are directly interpolated into log messages. During vote processing and tally operations, exceptions from cryptographic operations or database layer could expose sensitive internal state including cryptographic parameters, SQL queries, or partial vote data. Cryptographic errors could expose key material, salts, or vote tokens in logs. Database errors could expose SQL queries with parameter values. Vote processing errors could leak partial vote content (violating ballot secrecy). Logs containing sensitive data become a high-value target for attackers.

### Details
**Affected Files:**
- `v3/server/pages.py` (line 419)
- `v3/server/bin/tally.py` (line 124)
- `v3/server/pages.py` (lines 399-403)
- `v3/server/bin/tally.py` (lines 115-118)

**CWE:** None specified
**ASVS:** 16.1.1, 16.2.5 (L2)

### Remediation
Log only exception type names at ERROR level and restrict full exception details to DEBUG level. Example: except Exception as e: _LOGGER.error(f'Vote processing failed for user[U:{result.uid}] on issue[I:{iid}]: {type(e).__name__}'); _LOGGER.debug(f'Vote error details (issue[I:{iid}]): {e}', exc_info=True). Create a centralized safe_log_exception() utility function that returns only exception type.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.1.1.md, 16.2.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-178 - No Documented Log Inventory or Centralized Log Destination Configuration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application lacks a documented log inventory and uses only default logging destinations across all execution modes. No persistent log storage or centralized log destination is configured. Without a log inventory, it is impossible to verify that logs are only going to approved destinations. The three different logging configurations across execution modes (standalone, ASGI, CLI) mean logs may end up in different places depending on how the application is run, with no documentation of which destinations are approved. This makes compliance with ASVS 16.2.3 unverifiable.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 58-63, 92-97)
- `v3/server/bin/tally.py` (line 157)

**CWE:** None specified
**ASVS:** 16.2.3 (L2)

### Remediation
1. Create a formal log inventory document specifying approved log destinations. 2. Centralize logging configuration using logging.config.dictConfig with defined handlers for console and file output. 3. Configure RotatingFileHandler for persistent audit logs with appropriate maxBytes and backupCount. 4. Add linting rules or code review checks to prevent print() in production modules. Example configuration provided in report shows structured logging setup with both console and file handlers.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-179 - add_vote Crashes on Missing Voter Eligibility Record Instead of Failing Securely
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The add_vote method retrieves voter eligibility records from the database but does not check for null results. When a voter attempts to vote on an issue they're not eligible for, the database query returns None, and the subsequent access to mayvote.salt raises an AttributeError instead of a proper authorization failure. This results in insecure failure that pollutes the security audit trail with implementation errors instead of recording authorization failure events, and could mask attacks where users attempt to vote on unauthorized issues.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 207-218)

**CWE:** None specified
**ASVS:** 16.5.2 (L2)

### Remediation
Add explicit null check after q_get_mayvote.first_row() call. If mayvote is None, log a security warning with details (user ID, issue ID) and raise a custom VoterNotEligible exception. This provides proper authorization failure handling with appropriate audit trail and prevents AttributeError from masking security events.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.5.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-180 - CLI Tally Tool Lacks Top-Level Exception Handler
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The CLI tally tool, which processes election results and is likely run as a scheduled job or manual administrative task, lacks any top-level exception handling around the main() function call. Additionally, error handling within tally_election() uses print() instead of the configured logger, bypassing structured logging. When unhandled exceptions occur (e.g., database corruption, crypto errors, permission denied), the process crashes with a traceback on stderr, and the error is NOT captured in log files. The print() call specifically bypasses the configured _LOGGER, meaning tally errors won't reach any log aggregation system. This results in loss of error details critical for audit trails (which election, what went wrong) as they are not recorded in structured log format.

### Details
**Affected Files:**
- `v3/server/bin/tally.py` (lines 172-185, 125-126)

**CWE:** None specified
**ASVS:** 16.5.4 (L3)

### Remediation
Wrap the main() call in the __main__ block with a try/except handler that: 1) Catches specific exceptions like ElectionNotFound with appropriate error codes, 2) Catches all other exceptions with critical-level logging including full traceback, 3) Exits with appropriate non-zero status codes. Replace the print() call in tally_election() with _LOGGER.error() to ensure errors are captured in structured logs with full context including issue IID and exception details.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.5.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-181 - Input Validation and Business Logic Bypass Attempts Not Logged
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 16.3.3 specifically requires logging of attempts to bypass security controls, such as input validation, business logic, and anti-automation. The application performs input validation and business logic checks but does not log when these checks fail. This includes: invalid issue IDs in vote submissions, empty form submissions, invalid date formats, and other validation failures. This makes automated attacks, fuzzing attempts, and manipulation attempts invisible to security monitoring.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 420-422, 413-415, 107-111)

**CWE:** None specified
**ASVS:** 16.3.3 (L2)

### Remediation
Add _LOGGER.warning() calls for all input validation failures with 'INPUT_VALIDATION_FAILED' prefix. Include user ID, resource being accessed, validation rule that failed, and the invalid value (sanitized). Example: _LOGGER.warning('INPUT_VALIDATION_FAILED: User[U:%s] submitted vote with invalid issue[I:%s] in election[E:%s]. valid_issues=%s', result.uid, iid, election.eid, list(issue_dict.keys())). Implement rate limiting on validation failures to prevent fuzzing attacks.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.3.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-182 - Log Injection via URL Path Parameters in Election Constructor
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Election constructor logs the eid parameter before validating it against the database, allowing log injection through 11 different endpoints that use the @load_election decorator. Any authenticated committer (lower privilege than PMC member) can inject arbitrary log entries across 11 endpoints. The injection occurs before the election ID is validated against the database, so completely arbitrary content is logged. Attackers can forge entries that appear to show election openings, closings, or vote submissions by other users. The vulnerability is exploitable because both run_standalone() and run_asgi() set the root logger to logging.DEBUG level.

### Details
**Affected Files:**
- `v3/steve/election.py` (line 40)
- `v3/server/main.py` (line 57)

**CWE:** CWE-117
**ASVS:** 16.4.1 (L2)

### Remediation
Option 1 (Preferred): Move log statement after validation. Log only after validation confirms this is a real election ID. Option 2: Sanitize before logging using safe_eid = re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', str(eid))[:64] before logging. Additionally, reduce production log level from DEBUG to INFO in main.py to prevent debug-level logs from being output in production.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.4.1.md
- Related Findings: FINDING-175, FINDING-176

### Priority
Medium

---

## Issue: FINDING-183 - No Rate Limiting on Election Creation Endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The election creation endpoint lacks rate limiting, quota controls, cooldown periods, and maximum count restrictions. A compromised PMC member account can create unbounded elections at machine speed, causing: (1) database bloat and garbage-data creation, (2) quota exhaustion, (3) CPU resource consumption for cryptographic key derivation (per steve.crypto) for each election, (4) SQLite write contention degrading voter experience, (5) pollution of the election list, and (6) potential disk exhaustion on the server as SQLite has no inherent size limits. An attacker could create thousands of elections in seconds.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 463-490)

**CWE:** None specified
**ASVS:** 2.4.1, 2.4.2 (L2, L3)

### Remediation
Implement two-tier rate limiting and quota controls: (1) Add per-user election creation quota with a configurable MAX_ELECTIONS_PER_USER limit and check the count of owned elections before allowing new creation. (2) Enforce a daily per-user creation limit (e.g., 5 elections per day) by adding an Election.count_created_today() method to query the database. (3) Add a per-user cooldown period (e.g., 30 seconds minimum between creation attempts) tracked in the session using 'last_election_create' timestamp. (4) Check all constraints before allowing creation and return appropriate error messages when quota or cooldown limits are reached.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 2.4.1.md, 2.4.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-184 - No Limits on Election Size (Issues per Election)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The issue creation endpoint has no limits on the number of issues per election and no rate limiting. An election with unbounded issues causes resource exhaustion during: (1) voting page load (election.list_issues() fetches all issues, random.shuffle() runs per STV issue), (2) tallying operations (each issue requires vote decryption and counting), and (3) vote submission (do_vote_endpoint iterates over all submitted votes with database writes per issue, causing extended write locks). A million-issue election would make tallying computationally infeasible and create denial-of-service conditions.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 523-545)

**CWE:** None specified
**ASVS:** 2.4.1 (L2)

### Remediation
Enforce configurable maximum issues per election in do_add_issue_endpoint and maximum candidates per STV issue. Implement MAX_ISSUES_PER_ELECTION constant (e.g., 100) and MAX_CANDIDATES_PER_STV_ISSUE constant. Check current issue count before allowing new issue creation and validate candidate count for STV issues. Return appropriate error messages when limits are reached to prevent resource exhaustion attacks.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 2.4.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-185 - Election State-Change Endpoints Lack Timing Controls and Use GET for Mutations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The election state-change endpoints (open/close) execute immediately upon GET requests with no timing controls, confirmation steps, or cooldowns. An election could be rapidly toggled between open and closed states at machine speed, disrupting active voters. Additionally, the use of GET methods for state-changing operations violates HTTP semantics and RESTful design principles. Combined with the lack of owner-only authorization ('### check authz' is commented out), any authenticated committer can toggle any election's state with no human-paced interaction required for critical election lifecycle operations.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 485-504, 507-523)

**CWE:** None specified
**ASVS:** 2.4.2 (L3)

### Remediation
Implement three security improvements: (1) Change HTTP methods from GET to POST for state-changing operations to comply with HTTP semantics and prevent CSRF attacks. (2) Add per-election state-change cooldown (e.g., 60 seconds) tracked in session using an 'election_state_{eid}' key to prevent rapid state toggling. (3) Implement owner authorization check to verify that metadata.owner_pid matches the acting user's UID before allowing state changes. Provide appropriate error messages (403 for authorization failures, warning flash for cooldown violations) and redirect to the management page.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 2.4.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-186 - No Browser Security Feature Documentation or Degradation Behavior
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 3.1.1 explicitly requires that application documentation states: (1) Expected security features browsers must support (HTTPS, HSTS, CSP, etc.), (2) How the application behaves when features are unavailable (warning, blocking, graceful degradation). Neither the application code nor any referenced configuration contains such documentation. Specifically: No `SECURITY.md`, security section in README, or inline documentation of browser requirements; No runtime checks for browser security feature support; No warning mechanism for users on non-conforming browsers; No `@app.before_request` handler that validates request security properties. Without documented browser security requirements, deployment teams cannot verify that the application is served with appropriate security headers. Operations teams have no guidance on required proxy/CDN security configurations. Users are not warned when their browser lacks required security features.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 32-42)

**CWE:** None specified
**ASVS:** 3.1.1, 3.7.4 (L3)

### Remediation
Create `SECURITY.md` documenting required browser security features (HTTPS with TLS 1.2+, HSTS support, CSP Level 2, SameSite cookies), degradation behavior (HTTP→HTTPS redirect, CSP warning logging, JavaScript requirement warnings, unsupported browser banners), and deployment requirements (reverse proxy HSTS configuration, required security headers). Add runtime enforcement in `create_app()` with an `@app.after_request` handler that applies documented security headers from a REQUIRED_SECURITY_FEATURES dictionary.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.1.1.md, 3.7.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-187 - No X-Frame-Options or frame-ancestors CSP Directive — Clickjacking Unmitigated
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No route handler or application-level middleware sets `X-Frame-Options` or a `Content-Security-Policy` `frame-ancestors` directive. This is a Type A gap. All 18+ HTML-rendering endpoints can be embedded in attacker-controlled iframes. Most critical are state-changing pages that could be clickjacked: `/vote-on/<eid>` (voting form), `/manage/<eid>` (election management), `/do-open/<eid>` (election opening - GET request), `/do-close/<eid>` (election closing - GET request). Since `/do-open/<eid>` and `/do-close/<eid>` are GET requests that perform state changes, a simple iframe load (without even requiring a click on a form button) could open or close an election. An attacker can trick an authenticated election administrator into opening/closing elections or submitting votes by framing the application page and overlaying deceptive UI elements.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 203, 315, 448, 468)

**CWE:** None specified
**ASVS:** 3.1.1, 3.5.8 (L3)

### Remediation
Implement global `@APP.after_request` middleware that sets `Cross-Origin-Resource-Policy: same-origin` on all responses. Add `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` headers. Create a `validate_sec_fetch()` utility function to validate Sec-Fetch-* headers for state-changing and sensitive endpoints, rejecting requests where `Sec-Fetch-Site` is not in ('same-origin', 'same-site', 'none') and where `Sec-Fetch-Mode` is 'no-cors'. Apply this validation as a decorator to sensitive endpoints.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.1.1.md, 3.5.8.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-188 - Missing Upper-Bound Range Validation on STV `seats` Integer Parameter
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The STV (Single Transferable Vote) election type accepts a `seats` parameter that determines how many candidates should be elected. While the CLI import tool validates that `seats` is a positive integer, there is no upper-bound validation anywhere in the codebase. Additionally, the core API function `election.add_issue()` performs no validation on the `kv` dictionary contents at all, creating a defense-in-depth gap. This allows extreme values (e.g., 2147483647) to pass validation and be stored in the database. When `tally()` is called, this unbounded value is passed to `stv_tool.run_stv()`, which could cause resource exhaustion, logically incorrect election results, or potential integer overflow if the underlying STV tool uses C-based numeric processing.

### Details
**Affected Files:**
- `v3/server/bin/create-election.py` (lines 60-61)
- `v3/steve/election.py` (line 174)
- `v3/steve/vtypes/stv.py` (line 65)

**CWE:** None specified
**ASVS:** 1.4.2 (L2)

### Remediation
Add range validation at multiple layers for defense-in-depth:

1. In `election.py:add_issue()` — API layer validation:
```python
def add_issue(self, title, description, vtype, kv):
    assert self.is_editable()
    assert vtype in vtypes.TYPES
    
    # Validate STV-specific integer parameters
    if vtype == 'stv' and kv:
        seats = kv.get('seats')
        if not isinstance(seats, int) or seats <= 0:
            raise ValueError('STV seats must be a positive integer')
        if seats > 100:  # Reasonable upper bound for any election
            raise ValueError('STV seats exceeds maximum allowed (100)')
        labelmap = kv.get('labelmap', {})
        if seats > len(labelmap):
            raise ValueError('STV seats cannot exceed number of candidates')
    ...
```

2. In `stv.py:tally()` — Validate before algorithm execution:
```python
def tally(votestrings, kv):
    seats = kv['seats']
    labelmap = kv['labelmap']
    
    # Range validation at point of use
    if not isinstance(seats, int) or seats <= 0:
        raise ValueError('Invalid seats value')
    if seats > len(labelmap):
        raise ValueError(f'seats ({seats}) exceeds candidate count ({len(labelmap)})')
    ...
```

3. In `create-election.py:validate_issue()` — Add upper bound:
```python
if not isinstance(kv['seats'], int) or kv['seats'] <= 0:
    raise ValueError('STV seats must be a positive integer')
if kv['seats'] > 100:
    raise ValueError('STV seats exceeds maximum allowed value')
labelmap = kv.get('labelmap', {})
if kv['seats'] > len(labelmap):
    raise ValueError('STV seats cannot exceed number of candidates')
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.4.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-189 - Missing Exception-Safe Resource Cleanup in Transactional Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Transactional operations begin transactions but lack exception handling to rollback on failure and ensure resource cleanup. This leaves the database connection in an inconsistent state with open transactions holding locks. If an exception occurs between BEGIN TRANSACTION and COMMIT, the SQLite write lock is held until the connection is garbage collected. In delete(), the connection is never closed and self.db is never set to None, leaving the Election object in an inconsistent state. In add_salts() (called from open()), a stale write lock could block subsequent vote submissions.

### Details
**Affected Files:**
- `v3/steve/election.py` (lines 53-71, 127-141)

**CWE:** None specified
**ASVS:** 1.4.3 (L2)

### Remediation
Wrap transactional operations in try/except/finally blocks. Add ROLLBACK in except block and ensure connection cleanup in finally block. For delete() method: add try/except to catch exceptions, execute ROLLBACK on exception, and ensure conn.close() and self.db = None in finally block. For add_salts() method: add try/except to catch exceptions during iteration and execute ROLLBACK on exception.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.4.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-190 - Election Instance Lacks General Resource Release Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `Election` class opens a new, independent SQLite database connection for every operation via `open_database()`. There is no connection pool, no maximum connection limit, no timeout configuration, and no documented behavior for when the database becomes unavailable or connections are exhausted. Class-level methods each independently open new connections, meaning concurrent API requests create unbounded parallel connections. Under concurrent load, each inbound request opens at least one new SQLite connection. SQLite uses file-level locking; under write contention, connections queue on the lock with no configured timeout. Concurrent read-heavy operations (listing elections) exhaust file descriptors. No fallback or circuit-breaker exists—the application will produce unhandled exceptions (e.g., `sqlite3.OperationalError: unable to open database file` or `database is locked`), leading to cascading failures.

### Details
**Affected Files:**
- `v3/steve/election.py` (line 44)

**CWE:** None specified
**ASVS:** 1.4.3, 13.1.2, 13.2.6 (L2, L3)

### Remediation
1. Add connection pool configuration to `config.yaml.example` with parameters: pool_size (10), pool_timeout (5 seconds), max_overflow (5), and documented behavior when pool exhausted (return HTTP 503 with Retry-After header). 2. Implement a connection pool or singleton pattern in `election.py` using threading.Lock and queue.Queue with maxsize=MAX_CONNECTIONS, raising ServiceUnavailable after POOL_TIMEOUT. 3. Document fallback behavior when limits are reached. 4. Set SQLite busy_timeout PRAGMA on every connection in open_database() using configured timeout value (default 5000ms).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.4.3.md, 13.1.2.md, 13.2.6.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-191 - Missing Global Security Headers Framework
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no after_request handler or middleware to apply security response headers globally. All 21 endpoints in the application serve responses without Content-Security-Policy, X-Content-Type-Options, or other defensive headers. This creates no defense-in-depth layer and allows browsers to MIME-sniff responses. Any response from the application lacks critical security headers, allowing MIME-sniffing attacks and providing no defense-in-depth if any endpoint inadvertently returns user-controlled content.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 30-43)

**CWE:** CWE-693
**ASVS:** 3.2.1 (L1)

### Remediation
Implement an after_request handler in the create_app() function to set security headers globally. Add X-Content-Type-Options: nosniff to all responses and implement a default Content-Security-Policy that restricts content sources. The handler should check if CSP is already set before applying defaults to allow per-endpoint customization.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.1.md
- Related Findings: FINDING-201

### Priority
Medium

---

## Issue: FINDING-192 - API Endpoints Lack Sec-Fetch-* Context Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
API-style endpoints that accept JSON or form data and return non-HTML responses do not validate Sec-Fetch-Dest or Sec-Fetch-Mode headers to confirm the request originates from the expected context (e.g., fetch from JavaScript, not direct browser navigation). While POST mitigates direct navigation, there is no server-side enforcement that these endpoints are called only via the intended AJAX/fetch context. Without Sec-Fetch-* validation, there is no server-side assurance that API endpoints are accessed only from the application's frontend. Combined with the lack of CSRF tokens, this increases the risk that these endpoints could be triggered from external contexts.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 376, 383, 390)

**CWE:** CWE-352
**ASVS:** 3.2.1 (L1)

### Remediation
Implement a require_fetch_context decorator that validates Sec-Fetch-Dest and Sec-Fetch-Mode headers on API endpoints. The decorator should verify that requests originate from fetch/XHR contexts and reject requests with invalid context headers with a 403 Forbidden response. Apply this decorator to all API-style endpoints that return non-HTML responses.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.1.md
- Related Findings: FINDING-021, FINDING-022, FINDING-023, FINDING-097, FINDING-222

### Priority
Medium

---

## Issue: FINDING-193 - JavaScript Injection via STV Candidate Data in Inline Script
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The STV_CANDIDATES JavaScript object literal in vote-on.ezt embeds user-provided issue titles and candidate names directly in JavaScript string literals without proper escaping. While [format "js,html"] exists and is used elsewhere in the codebase, it is NOT applied in this context. An issue title or candidate name containing script-breaking characters can close the existing &lt;script&gt; block and inject arbitrary JavaScript, bypassing the string literal context entirely. The client-side escapeHtml() function is bypassed because the data source is already corrupted at the template level.

### Details
**Affected Files:**
- `v3/server/templates/vote-on.ezt` (STV_CANDIDATES object literal)
- `v3/server/pages.py` (line 254)

**CWE:** CWE-79
**ASVS:** 3.2.2 (L1)

### Remediation
Apply [format "js"] to all values in the STV_CANDIDATES object: title: "[format "js"][issues.title][end]", and for all candidate label and name fields: { label: "[format "js"][issues.candidates.label][end]", name: "[format "js"][issues.candidates.name][end]" }

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.2.md
- Related Findings: FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-194

### Priority
Medium

---

## Issue: FINDING-194 - Reflected XSS via URL Path Parameters in Error Pages
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Error pages e_bad_eid.ezt and e_bad_iid.ezt render URL path parameters (eid and iid) directly in HTML without any output encoding. When Quart URL-decodes malicious path parameters like /vote-on/&lt;script&gt;alert(1)&lt;/script&gt;, the decoded value is assigned to result.eid in the load_election decorator and rendered as raw HTML in the 404 error page. This is a Type A gap with no output encoding control applied.

### Details
**Affected Files:**
- `v3/server/templates/e_bad_eid.ezt` (eid output)
- `v3/server/templates/e_bad_iid.ezt` (iid output)
- `v3/server/pages.py` (line 172)

**CWE:** CWE-79
**ASVS:** 3.2.2 (L1)

### Remediation
Apply HTML escaping to error template outputs: The Election ID ([format "html"][eid][end]) does not exist, and The Issue ID ([format "html"][iid][end]) does not exist

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.2.md
- Related Findings: FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-193

### Priority
Medium

---

## Issue: FINDING-195 - Shared Utility Functions Declared in Global Scope Without Namespace Isolation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The shared utility file `steve.js` declares three functions at global scope without namespace isolation or strict mode enforcement. These functions are accessible as properties of the `window` object, making them vulnerable to DOM clobbering attacks where malicious HTML elements with matching `id` or `name` attributes could shadow these function references. Combined with raw HTML rendering of issue descriptions that enables injection of elements with arbitrary `id` attributes, this creates an exploitable DOM clobbering attack surface. While function declarations typically take precedence, browser inconsistencies and edge cases (especially with `<form name="...">` or `<embed name="...">`) can lead to unexpected behavior.

### Details
**Affected Files:**
- `v3/server/static/js/steve.js` (lines 30-73)

**CWE:** None specified
**ASVS:** 3.2.3 (L3)

### Remediation
Wrap `steve.js` in an IIFE with 'use strict' directive and namespace isolation. Implement type checking on all `getElementById` results. Return a namespace object exposing only necessary functions. Apply the same pattern to all inline scripts.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-196 - Inline Scripts in Management Templates Lack Namespace Isolation and Strict Mode
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Management templates contain inline JavaScript that declares multiple functions and variables at global scope without namespace isolation or strict mode. This creates pollution of the global namespace and makes these functions vulnerable to DOM clobbering attacks. The templates handle sensitive operations and render unsanitized issue descriptions, but do not use the proper isolation pattern that exists in `vote-on.ezt`. Functions like `openEditIssueModal`, `saveIssue`, `openDeleteIssueModal`, and `toggleDescription` are all exposed on the window object, creating opportunities for DOM clobbering when combined with raw HTML rendering of issue descriptions on the same page.

### Details
**Affected Files:**
- `v3/server/templates/manage.ezt` (inline script block)
- `v3/server/templates/manage-stv.ezt` (inline script block)
- `v3/server/templates/admin.ezt` (inline script block)

**CWE:** None specified
**ASVS:** 3.2.3 (L3)

### Remediation
Wrap all template inline scripts in IIFEs with strict mode, matching the pattern already used in `vote-on.ezt`. Only expose to HTML onclick handlers via window if needed. Apply the same pattern to manage-stv.ezt and admin.ezt.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-197 - No Type or Null Checking on document.getElementById() Results Across All Client-Side JavaScript
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Throughout the codebase, `document.getElementById()` is called without subsequent null or type checking. The return value is immediately used with property access (`.value`, `.classList`, `.innerHTML`) without verifying the returned element exists or is of the expected type. This creates vulnerability to DOM clobbering where an injected element of unexpected type could cause silent failures or type errors. Without type checking, DOM clobbered elements can silently substitute for expected elements, leading to silent data corruption (wrong `.value` read/written), function failures (`TypeError` on unexpected types), or bypassed client-side validation. Issue descriptions rendered as raw HTML may contain elements with `id` attributes that collide with IDs used by the application (e.g., `id="csrf-token"`, `id="vote-<iid>"`, `id="issueTitle"`), and `document.getElementById()` returns the first matching element in DOM order without verification.

### Details
**Affected Files:**
- `v3/server/static/js/steve.js` (lines 31, 42, 49)
- `v3/server/templates/manage.ezt` (inline script - csrf-token access)
- `v3/server/templates/vote-on.ezt` (inline script - multiple instances)
- `v3/server/templates/manage-stv.ezt` (inline script - multiple instances)
- `v3/server/templates/admin.ezt` (inline script - multiple instances)

**CWE:** None specified
**ASVS:** 3.2.3 (L3)

### Remediation
Implement a safe element lookup utility with type checking and apply it to all `document.getElementById()` calls across all JavaScript files.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-198 - Session Cookie Name Missing `__Host-` or `__Secure-` Prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 3.3.1 requires that if the `__Host-` prefix is not used for cookie names, the `__Secure-` prefix must be used. The application uses Quart/Flask which defaults the session cookie name to `session` without any security prefix. Neither the `__Host-` nor `__Secure-` prefix is configured in the application code. The `__Secure-` prefix instructs browsers to only send the cookie over HTTPS and requires the `Secure` attribute. The `__Host-` prefix additionally restricts the cookie to the exact host and root path, preventing subdomain attacks. Without these prefixes, the browser does not enforce prefix-based cookie protections. Combined with the missing `Secure` attribute, this means no browser-enforced HTTPS-only transmission, potential for subdomain cookie injection attacks, and cookies could be overwritten by a less-secure subdomain.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 30-44, 36-38)

**CWE:** None specified
**ASVS:** 3.3.1, 3.3.3 (L1, L2)

### Remediation
In the `create_app()` function in `v3/server/main.py`, configure the session cookie name with the `__Host-` prefix: app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session', app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_PATH'] = '/', and do NOT set SESSION_COOKIE_DOMAIN (required for __Host- prefix)

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.3.1.md, 3.3.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-199 - No Explicit HttpOnly Configuration on Session Cookie
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not explicitly configure session cookie security attributes (SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE) anywhere in the auditable codebase. The asfquart.construct() call is the sole application factory, and no cookie attribute configuration follows it. While Quart (based on Flask's API) defaults SESSION_COOKIE_HTTPONLY to True, the asfquart wrapper layer is not available for review and could potentially override this default. ASVS 3.3.4 requires verification that HttpOnly is set — this cannot be verified from the provided code. If HttpOnly is not set, a cross-site scripting vulnerability anywhere in the application could be leveraged to steal session tokens via document.cookie.

### Details
**Affected Files:**
- `v3/server/main.py` (line 42)

**CWE:** None specified
**ASVS:** 3.3.4 (L2)

### Remediation
Explicitly configure session cookie security attributes after app construction in main.py: app.config['SESSION_COOKIE_HTTPONLY'] = True, app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_SAMESITE'] = 'Lax', app.config['SESSION_COOKIE_NAME'] = '__Host-session'

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.3.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-200 - No Cookie Size Validation Control
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no mechanism to validate or enforce the 4096-byte cookie size limit. All session cookie management is delegated to the Quart/asfquart framework with no application-level guard. While the current session payload (uid, fullname, email, flash messages) is likely small enough, there is no defensive control preventing oversized cookies if session data grows (e.g., additional session attributes, accumulated data from framework internals, or future code changes). If the session cookie exceeds 4096 bytes (through future code changes, framework overhead growth, or unforeseen session data accumulation), the browser will silently discard it. The user's session would effectively be invalidated, preventing authentication and use of all protected functionality. This is a denial-of-service condition against individual users.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 63-94, 73-78, 121-128, 356, 519)

**CWE:** None specified
**ASVS:** 3.3.5 (L3)

### Remediation
Implement middleware that validates cookie size before the response is sent using an after_request handler. Log warnings when Set-Cookie headers approach 4096 bytes. Cap flash message content length to prevent edge cases. Document session storage architecture for future developers.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.3.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-201 - Complete Absence of X-Content-Type-Options Header
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not set the 'X-Content-Type-Options: nosniff' header on any HTTP response. No global middleware, after-request handler, or framework configuration was found that would inject this header. All 21+ routes return responses without this protection. This exposes the application to MIME-sniffing attacks where browsers may interpret content differently than the declared Content-Type, potentially executing attacker-controlled content as active scripts. The vulnerability is particularly critical for the /docs/&lt;iid&gt;/&lt;docname&gt; endpoint which serves user-associated documents, and the /static/&lt;path:filename&gt; endpoint which serves CSS/JS files. Without nosniff, Cross-Origin Read Blocking (CORB) protection in browsers is also weakened.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 28-43)
- `v3/server/pages.py` (lines 134, 144, 180, 259, 299, 323, 353, 359, 365, 400, 423, 445, 463, 486, 511, 531, 540, 548, 553-562, 565-566, 570-571, 653-654, 92-112)

**CWE:** CWE-693
**ASVS:** 3.4.4 (L2)

### Remediation
PRIMARY FIX: Add a global after_request hook in the application factory (main.py) that sets the header on every response: response.headers['X-Content-Type-Options'] = 'nosniff'. SECONDARY FIX (Defense-in-Depth): Fix manually constructed 404 response in pages.py to include the header. Consider implementing comprehensive security header policy including X-Frame-Options, Referrer-Policy, and Content-Security-Policy.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.4.md
- Related Findings: FINDING-191

### Priority
Medium

---

## Issue: FINDING-202 - Missing Referrer-Policy Header on All Application Responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not set a `Referrer-Policy` HTTP response header on any responses, nor is there evidence of HTML meta tag configuration in the provided code. This violates ASVS requirement 3.4.5 and exposes sensitive election identifiers, issue IDs, and document names in URL paths to third-party services via the browser's `Referer` header. When users navigate to sensitive pages like `/vote-on/<eid>`, `/manage/<eid>`, `/manage-stv/<eid>/<iid>`, or `/docs/<iid>/<docname>`, and those pages contain links to third-party resources or the user clicks external links, the browser sends the full URL including the path (election ID, issue ID, document name) in the `Referer` header to the third party. This allows third-party services to learn internal election identifiers and navigation patterns.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 31-47)
- `v3/server/pages.py` (lines 125-602)

**CWE:** None specified
**ASVS:** 3.4.5 (L2)

### Remediation
Add a global `after_request` handler that sets `Referrer-Policy` on all responses. For an election system, `strict-origin-when-cross-origin` (minimum) or `no-referrer` (strictest) is recommended. Implementation: response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' or 'no-referrer' for maximum protection.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-203 - Missing Content-Security-Policy Header with Violation Reporting Directive
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not configure a Content-Security-Policy header with a violation reporting directive (report-uri or report-to) anywhere in the codebase. No CSP header is set at the application level, and there is no middleware or after-request hook that would add one with reporting capabilities. Without a CSP header, the browser applies no restrictions on script sources, style sources, frame ancestors, or other content policies, leaving the application exposed to XSS and content injection attacks. Without report-uri or report-to directives, the security team has no visibility into policy violations, cannot detect attack attempts, and cannot identify misconfigured CSP directives that break legitimate functionality.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 29-40)
- `v3/server/pages.py` (lines 135-653, 52)

**CWE:** None specified
**ASVS:** 3.4.7 (L3)

### Remediation
Add an after_request handler in main.py that sets the CSP header with a reporting directive on all responses. For initial rollout, use Content-Security-Policy-Report-Only to collect violations without breaking functionality. Implement a /csp-report endpoint to collect and log violations.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.7.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-204 - Missing Cross-Origin-Opener-Policy Header on All HTML Responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not set the `Cross-Origin-Opener-Policy` (COOP) header on any HTTP response that renders HTML content. This leaves all document-rendering responses vulnerable to cross-origin window handle attacks such as tabnabbing and frame counting. An attacker page opened via a link from the voting application can retain a reference to the opener window, enabling tabnabbing (redirecting the voting page to a phishing page), frame counting (enumerating open windows/tabs to infer voting activity patterns), and window reference leakage (cross-origin state inspection via window.opener property).

### Details
**Affected Files:**
- `v3/server/main.py` (lines 32-47)
- `v3/server/pages.py` (lines 659, ~125, ~133, ~222, ~280, ~320, ~343, ~551, ~559, ~567, ~575)

**CWE:** None specified
**ASVS:** 3.4.8 (L3)

### Remediation
Add a global `after_request` hook in the application factory to set the `Cross-Origin-Opener-Policy` header on all HTML responses: response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'. Also update the `raise_404` function to include the header. Use `same-origin` as the default directive (appropriate given OAuth uses redirects rather than popups).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.8.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-205 - Externally Hosted SVG Image Without SRI or Documented Security Decision
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Apache feather logo is loaded at runtime from an external domain (www.apache.org). This resource is not versioned (the URL has no version identifier, meaning content can change), has no SRI integrity attribute (the integrity attribute is not supported on &lt;img&gt; elements), and has no documented security decision justifying this external dependency. ASVS 3.6.1 requires that when SRI is not possible, there should be a documented security decision to justify this for each resource. While SVG loaded via &lt;img&gt; is sandboxed (no script execution), a compromised resource could still be used for phishing (visual replacement) or tracking. If the external host is compromised or the resource is modified, the application would display attacker-controlled visual content to all users. In a voting application context, this could undermine trust or be used for social engineering.

### Details
**Affected Files:**
- `v3/server/templates/header.ezt` (line 18)

**CWE:** None specified
**ASVS:** 3.6.1 (L3)

### Remediation
Self-host the SVG image alongside other static assets. In fetch-thirdparty.sh, add download command for the feather SVG. In header.ezt, change to use the self-hosted version: &lt;img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top"&gt;

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.6.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-206 - Missing SRI for Self-Hosted Third-Party Library (bootstrap-icons.css)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SRI defense-in-depth pattern is applied to bootstrap.min.css and bootstrap.bundle.min.js but explicitly skipped for bootstrap-icons.css. This third-party CSS file controls @font-face declarations for web fonts. If tampered with after deployment, it could: (1) Redirect font loading to an attacker-controlled origin, (2) Inject CSS-based data exfiltration (e.g., attribute selectors with background URLs), (3) Modify visual rendering to mislead voters. The inconsistency creates a false confidence that third-party resources are integrity-protected when a significant gap exists. An attacker who can modify server-side files or intercept during deployment could alter bootstrap-icons.css without detection, while other Bootstrap files would trigger integrity failures. This creates a targeted attack vector through the weakest link.

### Details
**Affected Files:**
- `v3/server/templates/header.ezt` (line 10)
- `v3/server/bin/fetch-thirdparty.sh` (lines 70-74)

**CWE:** None specified
**ASVS:** 3.6.1 (L3)

### Remediation
Add SRI hash generation and template integration. In fetch-thirdparty.sh, after extracting bootstrap-icons.css, generate hash using openssl dgst. In header.ezt, add integrity attribute: &lt;link href="/static/css/bootstrap-icons.css" rel="stylesheet" integrity="sha384-GENERATED_HASH_HERE"&gt;

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.6.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-207 - Build Script Downloads Third-Party Assets Without Pre-Download Integrity Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The build script generates SRI hashes from the downloaded content rather than verifying downloads against known-good hashes. This means: (1) curl does not use --fail flag (HTTP errors silently produce non-library content), (2) No pre-defined SHA-256/SHA-384 checksums are checked before extraction, (3) No GPG signature verification of release packages, (4) The generated SRI hash will match whatever was downloaded, including compromised content. If a supply chain attack targets the download (e.g., compromised GitHub release, DNS hijacking), the SRI mechanism would be rendered ineffective because the integrity hash would be computed from the malicious payload. A supply chain compromise during the build process would result in malicious JavaScript/CSS being served to all voters, with SRI hashes that appear valid. The existing SRI provides zero protection against this attack vector.

### Details
**Affected Files:**
- `v3/server/bin/fetch-thirdparty.sh` (lines 47, 60-62, 67, 82, 92)

**CWE:** None specified
**ASVS:** 3.6.1 (L3)

### Remediation
Add known-good hash verification before extraction. Define expected hashes from official release notes. Download with: curl -q --fail --location. Verify before extraction using sha256sum and compare against expected hash. Exit with error if verification fails. Only then extract the files.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.6.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-208 - Complete Absence of External URL Navigation Warning
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no mechanism whatsoever to warn users before navigating to URLs outside the application's control. There is no interstitial warning page, no client-side JavaScript intercept for external links, and no server-side redirect proxy. This is a complete absence of the ASVS 3.7.3 control. The rewrite_description() function injects unescaped HTML into the page, allowing arbitrary HTML including external links to be rendered directly to voters without any warning or cancellation option. An election administrator can create an issue with external links in the description, and voters clicking these links will navigate directly to external URLs with no interstitial warning and no option to cancel. This could be used for phishing attacks or social engineering to influence voter behavior in an election context.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 52-59, 349-350)

**CWE:** None specified
**ASVS:** 3.7.3 (L3)

### Remediation
Implement a three-part solution: (1) Server-side redirect proxy route that validates target URL and redirects to interstitial warning page for external domains, (2) Interstitial template showing warning with continue/cancel options, (3) HTML escaping in rewrite_description() and client-side JavaScript to intercept external links and route through warning page.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.7.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-209 - Complete Absence of Browser Security Feature Detection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's common JavaScript utility file contains zero browser security feature detection. The application implicitly depends on modern browser features (Bootstrap 5 Modal API, ES6 template literals, classList API, const declarations) but never checks whether the browser supports the security features the application relies upon. For a voting system, the browser must support Content Security Policy (CSP), Strict-Transport-Security, SameSite cookie attribute, Secure cookie flag enforcement, and SubtleCrypto/Web Crypto API if any client-side cryptographic operations are used. No feature detection, no user warning, and no access-blocking logic exists anywhere in the provided client-side code. Users on browsers lacking security feature support could be targeted with XSS or session hijacking attacks that would succeed due to missing CSP/HSTS enforcement. Voters may unknowingly cast votes on compromised sessions. The application provides false confidence that security is enforced uniformly.

### Details
**Affected Files:**
- `v3/server/static/js/steve.js` (lines 1-76)

**CWE:** None specified
**ASVS:** 3.7.5 (L3)

### Remediation
Add a browser security feature detection module to steve.js that runs on page load. Implement checkBrowserSecurityFeatures() function that checks for: Content Security Policy support (CSP Level 2), Web Cryptography API, Fetch API with credentials support, HTTPS enforcement, and SameSite cookie support. Display warning messages to users when critical security features are missing. Optionally block access by disabling form submission buttons for browsers that lack critical security features. Add &lt;noscript&gt; tag warning, document minimum browser requirements, create automated tests, implement server-side User-Agent analysis, and implement telemetry.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.7.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-210 - HTML Responses Created Without Explicit Charset in Content-Type
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `raise_404` function constructs explicit HTML responses with `mimetype='text/html'` but does not include a charset parameter. In Werkzeug 3.0+ (used by modern Quart), this produces a `Content-Type: text/html` header without `; charset=utf-8`. Without an explicit charset declaration, browsers must guess the character encoding, creating a window for character-encoding-based attacks (e.g., UTF-7 XSS in legacy or misconfigured clients, or multi-byte encoding attacks). The rendered templates contain URL-derived values (`eid`, `iid`) making this a plausible vector.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 764-766, 183, 211, 222, 318, 390)

**CWE:** None specified
**ASVS:** 4.1.1 (L1)

### Remediation
Replace `mimetype='text/html'` with `content_type='text/html; charset=utf-8'` in the `raise_404` function:

```python
def raise_404(template, data):
    content = asfquart.utils.render(template, data)
    quart.abort(quart.Response(
        content,
        status=404,
        content_type='text/html; charset=utf-8'
    ))
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.1.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-211 - No Application-Wide Content-Type Enforcement Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no centralized mechanism to ensure all HTTP responses include a Content-Type header with an appropriate charset parameter. Content-Type correctness is entirely delegated to individual handler implementations and framework defaults from `@APP.use_template`, `send_from_directory`, `quart.redirect`, and `quart.abort`. There is no `@APP.after_request` hook to validate or enforce Content-Type headers with charset across all response types. This creates systemic risk: if framework default behavior changes across versions (as happened with Werkzeug 3.0's charset removal), all responses silently lose charset declarations. New endpoints added by developers may omit Content-Type charset without any safety net. 22+ response-generating endpoints rely entirely on unverifiable framework defaults.

### Details
**Affected Files:**
- `v3/server/pages.py` (None)
- `v3/server/main.py` (None)
- `v3/server/pages.py` (lines 93, 679)

**CWE:** None specified
**ASVS:** 4.1.1 (L1)

### Remediation
Add an `after_request` hook to enforce Content-Type charset on all text-based responses:

```python
# Add to main.py create_app() or pages.py module level:

@APP.after_request
async def set_content_type_charset(response):
    """Ensure all text-based responses include charset=utf-8."""
    content_type = response.content_type or ''
    if content_type:
        # For text/* and *+xml types, ensure charset is present
        mime = content_type.split(';')[0].strip().lower()
        needs_charset = (
            mime.startswith('text/')
            or mime.endswith('+xml')
            or mime == 'application/xml'
            or mime == 'application/json'
        )
        if needs_charset and 'charset' not in content_type.lower():
            response.content_type = f'{mime}; charset=utf-8'
    return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.1.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-212 - State-changing operations use GET method, compounding transport security risk
**Labels:** bug, security, priority:medium
**Description:**
### Summary
State-changing operations for opening and closing elections are exposed as GET endpoints rather than POST endpoints. This architectural choice compounds the transport security risk because GET requests are more likely to be logged, cached, and automatically redirected by intermediaries, increasing the attack surface for plaintext credential leakage. The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints use GET method for state-changing operations. GET requests are especially prone to being logged by proxies, browsers, and intermediaries. Session cookies and election IDs are exposed in the URL and headers. A blanket HTTP→HTTPS proxy redirect for GET requests allows authentication cookies to be sent in plaintext on the initial HTTP request before redirect occurs.

### Details
**Affected Files:**
- `v3/server/pages.py` (None)

**CWE:** None specified
**ASVS:** 4.1.2 (L2)

### Remediation
Convert state-changing operations to POST method. Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from @APP.get to @APP.post decorators. Ensure HTTPS enforcement is handled by before_request middleware for these endpoints. This will reduce surface area for transport security issues and prevent session token leakage in plaintext, preventing election administration hijacking.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.1.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-213 - No Trusted Proxy Configuration or X-Forwarded-* Header Sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application, designed to run behind a reverse proxy via Hypercorn (ASGI), lacks any configuration or middleware to sanitize, validate, or restrict intermediary-set HTTP headers (e.g., X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host). While the application reads user identity from server-side sessions rather than headers, the underlying Quart framework and OAuth redirect flow may implicitly trust these spoofable headers. This creates risks for OAuth redirect manipulation, audit log integrity issues, and scheme confusion. An attacker could inject X-Forwarded-Host: attacker.com to redirect OAuth callbacks to a malicious domain, spoof their IP address in logs, or cause HTTP URLs to be generated for HTTPS-only resources.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 34-53, 78-95, 96-113)

**CWE:** None specified
**ASVS:** 4.1.3 (L2)

### Remediation
Configure trusted proxy handling at the ASGI server level and/or within the application:

Option 1: Configure Hypercorn with --forwarded-allow-ips to only trust forwarded headers from specific proxy IPs (e.g., --forwarded-allow-ips="127.0.0.1,10.0.0.0/8")

Option 2: Add ProxyFixMiddleware in create_app() function:
```python
from quart.middleware import ProxyFixMiddleware
app.asgi_app = ProxyFixMiddleware(
    app.asgi_app,
    mode="modern",
    trusted_hops=1,
)
```

Option 3: Add a @APP.before_request handler to strip untrusted proxy headers:
```python
@APP.before_request
async def strip_untrusted_proxy_headers():
    untrusted_headers = [
        'X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host',
        'X-Real-IP', 'X-User-ID', 'Forwarded'
    ]
    for header in untrusted_headers:
        if header in quart.request.headers:
            _LOGGER.warning(f'Stripped untrusted header: {header}')
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.1.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-214 - No explicit HTTP request body size limits configured, enabling denial-of-service via overly long HTTP messages
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Quart application does not set `max_content_length` or configure Hypercorn body size limits. The ASVS 4.2.1 parent section explicitly includes "denial of service via overly long HTTP messages" as an attack vector. Multiple POST endpoints accept unbounded request bodies. An authenticated attacker (any committer) can submit arbitrarily large HTTP request bodies that are fully buffered by the framework before reaching handler code. This can exhaust server memory and cause denial of service during an active election, potentially disrupting voting.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 31-44)
- `v3/server/pages.py` (lines 403, 96, 440, 504, 531)

**CWE:** None specified
**ASVS:** 4.2.1 (L2)

### Remediation
Set `app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024` (1 MB) in the `create_app()` function in `main.py`. Additionally, configure Hypercorn limits in the ASGI deployment using a configuration file with settings for `h11_max_incomplete_size`, `h2_max_concurrent_streams`, and `h2_max_header_list_size`.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.2.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-215 - State-changing operations as GET requests increase HTTP request smuggling attack surface
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Two state-changing operations (`/do-open/<eid>` and `/do-close/<eid>`) are implemented as GET requests. In the context of ASVS 4.2.1, this is significant because GET requests have simpler message boundary determination (no body parsing) and are therefore the easiest payloads to smuggle through a misconfigured proxy/server chain. A smuggled GET request requires only a request line and minimal headers, making successful exploitation more likely if any infrastructure component mishandles message boundaries. Additionally, authorization check stubs (`### check authz`) exist but are NOT CALLED, compounding the smuggling risk by removing the ownership check that would limit impact. If HTTP request smuggling is achievable at the infrastructure level (reverse proxy ↔ Hypercorn), any authenticated committer's session could be hijacked to open or close elections they don't own.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 453-470, 475-492)

**CWE:** None specified
**ASVS:** 4.2.1 (L2)

### Remediation
Convert state-changing operations to POST with CSRF protection. Change route decorators from `@APP.get()` to `@APP.post()` for both `/do-open/<eid>` and `/do-close/<eid>` endpoints. Implement ownership verification by checking `md.owner_pid != result.uid` and returning 403 if unauthorized. Add CSRF token validation using `validate_csrf_token(form.get('csrf_token'))` after parsing the request form data.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.2.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-216 - No Application-Level HTTP/2 Connection-Specific Header Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application runs on Hypercorn, which supports HTTP/2 by default when TLS is enabled (via ALPN negotiation) and can support HTTP/3. There is no application-level middleware, Quart extension, or Hypercorn configuration to: (1) Reject incoming HTTP/2/HTTP/3 requests containing prohibited connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade, TE except for trailers), (2) Prevent connection-specific headers from being included in outgoing HTTP/2/HTTP/3 responses, (3) Validate header integrity during HTTP version conversion (e.g., if deployed behind a reverse proxy that downgrades/upgrades HTTP versions). In an HTTP/2-to-HTTP/1.1 downgrade proxy scenario, an attacker could craft requests with prohibited headers leading to request smuggling, bypassing authentication/authorization decorators, response splitting, and authorization bypass on state-changing endpoints.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 33-48, 91-110)
- `v3/server/pages.py` (lines 93, 441, 499, 520)

**CWE:** None specified
**ASVS:** 4.2.3 (L3)

### Remediation
1. Add ASGI middleware to validate and strip connection-specific headers for HTTP/2/HTTP/3 requests. Create a HTTP2HeaderValidationMiddleware class that checks the http_version in the ASGI scope and rejects requests with CONNECTION_SPECIFIC_HEADERS (transfer-encoding, connection, keep-alive, proxy-connection, upgrade) by returning a 400 Bad Request response. 2. Register the middleware in create_app() by wrapping app.asgi_app with HTTP2HeaderValidationMiddleware. 3. Add a Quart @after_request handler to strip connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade) from all responses. 4. Configure Hypercorn explicitly for HTTP version handling and document supported versions. 5. Convert state-changing GET endpoints (/do-open/&lt;eid&gt;, /do-close/&lt;eid&gt;) to POST methods. 6. Add integration tests validating that HTTP/2 requests with Transfer-Encoding are rejected.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.2.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-217 - No Application-Level CRLF Validation on HTTP Request Headers
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has zero middleware, decorators, or configuration that validates incoming HTTP request headers for CR (\r), LF (\n), or CRLF (\r\n) sequences. ASVS 4.2.4 specifically requires this validation for HTTP/2 and HTTP/3 requests. The application supports HTTP/2 when deployed via Hypercorn but does not add any application-layer header validation. The application relies entirely on the underlying ASGI server (Hypercorn) and framework (Quart/Werkzeug) for protocol-level protection, with no defense-in-depth. This becomes critical when HTTP version conversion occurs at a reverse proxy layer, where headers containing CRLF that pass HTTP/2 binary framing could become injection vectors after protocol downgrade to HTTP/1.1.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 114-628)
- `v3/server/main.py` (lines 90-107)

**CWE:** None specified
**ASVS:** 4.2.4 (L3)

### Remediation
Add Quart `before_request` middleware to validate all incoming request headers:

```python
import re

CRLF_PATTERN = re.compile(r'[\r\n]')

@APP.before_request
async def validate_headers_no_crlf():
    """Reject requests with CR/LF/CRLF in header names or values (ASVS 4.2.4)."""
    for header_name, header_value in quart.request.headers:
        if CRLF_PATTERN.search(header_name) or CRLF_PATTERN.search(header_value):
            _LOGGER.warning(
                f'Rejected request with CRLF in header: {header_name!r}'
            )
            quart.abort(400, 'Invalid characters in request headers')
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.2.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-218 - Redirect Responses Constructed with URL Path Parameters Without CRLF Sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Multiple POST and GET endpoints construct redirect Location headers using URL path parameters (eid, or values derived from form input). While the load_election decorator provides database validation that would reject most injected values, not all redirect paths go through this validation, and the application places no explicit CRLF check on data flowing into response headers. The framework-level protection is version-dependent and not verified. If a future code change introduces a redirect path without database validation, header injection becomes possible with no defense-in-depth against response splitting.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 303, 363, 413, 416, 434, 455, 477, 496, 521, 547, 567)

**CWE:** None specified
**ASVS:** 4.2.4 (L3)

### Remediation
Create a safe redirect helper that validates the URL:

```python
def safe_redirect(url, code=303):
    """Redirect with CRLF validation to prevent header injection."""
    if CRLF_PATTERN.search(url):
        _LOGGER.warning(f'Blocked redirect with CRLF in URL: {url!r}')
        quart.abort(400, 'Invalid redirect URL')
    return quart.redirect(url, code=code)
```

Additionally, add an `after_request` hook to validate all outgoing headers:

```python
@APP.after_request
async def validate_response_headers(response):
    """Ensure no CRLF injection in response headers."""
    for header_name, header_value in response.headers:
        if CRLF_PATTERN.search(str(header_value)):
            _LOGGER.error(
                f'CRLF detected in response header: {header_name}'
            )
            quart.abort(500)
    return response
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.2.4.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-219 - Unbounded User Input in Flash Messages Creates Potential for Oversized Cookie Header DoS
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Multiple endpoints incorporate unsanitized, unbounded user input into session flash messages via `quart.flash()`. If the session uses cookie-based storage (the default for Quart/Flask frameworks), the resulting `Set-Cookie` response header can exceed the browser's cookie size limit (~4KB) or the server's incoming header size limit (~8-16KB for most ASGI servers). When the browser sends back the oversized cookie on subsequent requests, the server rejects every request before reaching application code, resulting in a persistent DoS for that user's session. The vulnerable code paths include: (1) do_vote_endpoint extracting unbounded 'iid' from form field names (vote-&lt;arbitrary_data&gt;), (2) do_create_endpoint using unbounded form.title, (3) do_add_issue_endpoint using unbounded form.title, and (4) do_edit_issue_endpoint using unbounded form.title. The data flows from HTTP POST form fields through extraction without length checks into quart.flash() which stores data in session storage, ultimately appearing in Set-Cookie response headers. A proof of concept would involve submitting a POST request with a 100KB form field name like 'vote-AAAA...[100KB]...=y', causing the server to store this in the session flash message, creating an oversized cookie that locks out the user's session permanently.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 385-395, 424, 485, 505)

**CWE:** None specified
**ASVS:** 4.2.5 (L3)

### Remediation
Apply length limits at two levels: (1) Truncate user input before including in flash messages by defining MAX_FLASH_INPUT_LEN = 200 and truncating inputs like 'safe_iid = iid[:MAX_FLASH_INPUT_LEN]' before passing to flash_danger/flash_success. (2) Enforce maximum request body size via Quart configuration: APP.config['MAX_CONTENT_LENGTH'] = 64 * 1024 (64KB max request body). (3) Add server-side input length validation for form fields with MAX_TITLE_LEN = 500 and MAX_DESCRIPTION_LEN = 5000, aborting requests with 400 status if exceeded.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.2.5.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-220 - TLS is optional, not enforced for WebSocket connections
**Labels:** bug, security, priority:medium
**Description:**
### Summary
TLS is optional, not enforced. If WebSocket endpoints exist in unprovided files (pages.py, api.py), they would operate over plaintext WS when TLS is not configured. The server explicitly supports running without TLS based on configuration. In run_standalone() mode, TLS certificates are conditionally loaded based on config values that can be blank. In run_asgi() mode (production), TLS is not configured at the application level at all and depends entirely on external Hypercorn or reverse proxy configuration, with no application-level validation that the deployment is actually using TLS.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 79-83, 85, 94-110)
- `v3/server/config.yaml.example` (lines 27-31)

**CWE:** None specified
**ASVS:** 4.4.1 (L1)

### Remediation
Option 1 — Enforce TLS at startup (fail-closed): Add validation in run_standalone() to check if certfile and keyfile are configured, and exit with critical error if not set. Option 2 — If plain HTTP must be supported for development, add WebSocket-specific middleware using @app.before_websocket decorator to enforce WSS scheme and reject non-TLS WebSocket connections with close code 1008. Additionally, add startup validation requiring TLS configuration in non-development modes, or add a --insecure flag that must be explicitly set to run without TLS. Document TLS requirements in deployment documentation specifying that production deployments MUST use TLS either at the application level or via reverse proxy.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.4.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-221 - No WebSocket Origin Header Validation Infrastructure
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application lacks any infrastructure for validating the `Origin` header during WebSocket handshakes. The `create_app()` function, which serves as the sole application configuration entry point, establishes zero WebSocket security controls: (1) No allowed-origins list is defined in application configuration, (2) No `before_websocket` or `before_request` middleware is registered to inspect the `Origin` header, (3) The underlying framework (`asfquart`, built on Quart) does not validate WebSocket Origin headers by default, (4) All WebSocket endpoints defined in `pages` and `api` modules inherit this unprotected configuration. This represents a Type A gap — no control exists at any layer. If WebSocket endpoints exist in `pages` or `api` modules, an attacker can perform Cross-Site WebSocket Hijacking (CSWSH). An authenticated user visiting a malicious page would have their browser establish a WebSocket connection to the voting application using their existing session cookies, allowing the attacker to: submit or modify votes on behalf of the victim, read election state or results in real-time, bypass CSRF protections (WebSocket connections are not subject to SameSite cookie restrictions in all browsers), and compromise the integrity and confidentiality of the voting process.

### Details
**Affected Files:**
- `v3/server/main.py` (lines 36-51)

**CWE:** None specified
**ASVS:** 4.4.2 (L2)

### Remediation
Add a `before_websocket` hook in `create_app()` that validates the `Origin` header against an explicit allow-list:

```python
def create_app():
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)

    # Define allowed WebSocket origins from configuration
    ALLOWED_WS_ORIGINS = set(app.cfg.server.get('allowed_origins', [
        'https://steve.apache.org',
    ]))

    @app.before_websocket
    async def validate_websocket_origin():
        from quart import websocket, abort
        origin = websocket.headers.get('Origin', '')
        if origin not in ALLOWED_WS_ORIGINS:
            abort(403)

    import pages
    import api
    return app
```

Add to application configuration file:

```yaml
server:
  allowed_origins:
    - https://steve.apache.org
    - https://voting.apache.org
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.4.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-222 - State-Changing Operations via GET Requests Bypass Session Security
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints perform critical state-changing operations (opening and closing elections) via HTTP GET requests. When combined with cookie-based session management, GET requests are inherently vulnerable to cross-site request forgery through simple link injection, image tags, or browser prefetching. These endpoints cannot carry request body tokens, making them structurally impossible to protect with CSRF tokens. Election state transitions (EDITABLE → OPEN, OPEN → CLOSED) are irreversible, and browser prefetching or extensions may trigger these URLs automatically.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 323, 340)

**CWE:** CWE-352
**ASVS:** 4.4.3 (L2)

### Remediation
Convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods. Implement CSRF token validation by checking form.get('csrf_token') against a valid token. Replace the placeholder CSRF token implementation in basic_info() with a real token generation and validation mechanism. Ensure all state-changing operations use POST with CSRF protection.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 4.4.3.md
- Related Findings: FINDING-021, FINDING-022, FINDING-023, FINDING-097, FINDING-192

### Priority
Medium

---

## Issue: FINDING-223 - Complete Absence of File Handling Documentation for Document Serving Feature
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has an active document-serving feature with two components: (1) A route GET /docs/&lt;iid&gt;/&lt;docname&gt; that serves files from the DOCSDIR / iid directory, and (2) A rewrite_description() function that converts doc:filename tokens in issue descriptions into clickable download links. Neither the schema.md, ARCHITECTURE.md, nor any other provided documentation defines: permitted file types for documents associated with issues, expected file extensions (e.g., .pdf, .txt, .md), maximum file size (including unpacked size for archives), how files are made safe for end-user download and processing (Content-Disposition, Content-Type validation, anti-virus scanning), or behavior when a malicious file is detected. Without documented file handling requirements, developers have no specification to implement or test against. This has directly led to the missing validation in serve_doc(). An attacker who can place files in the docs directory (or exploit any future upload feature) could serve HTML files with embedded JavaScript (stored XSS via Content-Type sniffing), executable files disguised as documents, or excessively large files causing storage exhaustion.

### Details
**Affected Files:**
- `v3/docs/schema.md` (None)
- `v3/ARCHITECTURE.md` (line 18)
- `v3/server/pages.py` (lines 562-580)

**CWE:** None specified
**ASVS:** 5.1.1 (L2)

### Remediation
Create a file handling specification document and reference it from ARCHITECTURE.md. The specification should define: Permitted file types (PDF, plain text, Markdown), Expected extensions (.pdf, .txt, .md), Maximum file size (10 MB per file, 50 MB per issue), Maximum unpacked size (N/A - archives not accepted), Safety measures (file extension validation against allowlist, explicit Content-Type header based on extension mapping, Content-Disposition: attachment for non-text files, X-Content-Type-Options: nosniff on all responses, rejection of unrecognized extensions with 403), and Malicious file behavior (logging of denied access attempts with user ID and filename, MIME type validation for uploads, HTTP 403 for extension validation failures).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 5.1.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-224 - Issue Description Doc-Link Rewriting Generates Unvalidated File References
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The rewrite_description() function parses issue descriptions and converts doc:filename patterns into HTML anchor tags pointing to /docs/{iid}/{filename}. The filename extracted from the description is not validated against any allowlist of permitted file types or extensions before being embedded in the HTML link. The regex r'doc:([^\s]+)' captures any non-whitespace sequence, meaning filenames like ../../../etc/passwd, evil.html, or payload.exe would be turned into clickable links. While the serve_doc endpoint's send_from_directory provides basic path traversal protection, the absence of documented permitted file types means there is no basis for validation at either the link-generation or file-serving layer. This creates a social engineering vector where attackers with issue-editing privileges can embed links to dangerous file types, and generates links to file types that should not be served.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 52-58)

**CWE:** None specified
**ASVS:** 5.1.1 (L2)

### Remediation
Validate the filename in rewrite_description() against the documented allowlist. Implementation should: (1) Define ALLOWED_DOC_EXTENSIONS constant, (2) Extract file extension using pathlib.Path(filename).suffix.lower(), (3) Check if extension is in allowlist, (4) Check for path traversal characters ('/' or '\\' in filename), (5) If validation fails, replace the link with an error message like '[invalid document reference: {filename}]', (6) Only generate clickable links for valid, safe filenames.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 5.1.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-225 - Files Served to Voters from `/docs/` Endpoint Undergo No Antivirus or Malicious Content Scanning
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The document serving endpoint allows authenticated voters to download files associated with election issues. While the endpoint implements proper authentication and authorization checks, it completely bypasses any antivirus or malicious content scanning. Files are served directly from the filesystem without inspection, creating a potential vector for malware distribution to voters. An election administrator can place a document in DOCSDIR/&lt;iid&gt;/ containing known malware (e.g., weaponized PDF, malicious Office document, or disguised executable). When voters access the election and click the document link, the malicious file is served directly without detection. In an election system context, compromised voter machines could lead to vote manipulation or credential theft. The trust relationship between the voting system and voters amplifies the risk as voters are more likely to open documents from the official voting platform.

### Details
**Affected Files:**
- `v3/server/pages.py` (lines 638-658, 52, 308)

**CWE:** None specified
**ASVS:** 5.4.3 (L2)

### Remediation
Integrate antivirus scanning at the point where files are placed into DOCSDIR (upload time) and optionally at serve time. Implement a scan_file() function using ClamAV (clamdscan for daemon mode) that returns True if clean or raises AVScanError if malicious or scan fails. Modify the serve_doc endpoint to: 1) Validate docname to prevent path traversal by checking that safe_name equals docname and '..' is not in docname, 2) Scan the file before serving using scan_file(filepath), 3) Block serving with 403 error if file fails security scan, 4) Log all blocked attempts. Additionally implement scanning at the point of file ingestion: hook into file upload/placement workflow to scan before writing to DOCSDIR, reject files that fail scanning before they reach the serving directory, and consider periodic background scans of DOCSDIR to catch newly-identified threats. Add file type allowlisting for serve_doc (e.g., only PDF, TXT, specific document types). Long-term: implement a controlled file upload endpoint with scanning rather than relying on out-of-band file placement.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 5.4.3.md
- Related Findings: None

### Priority
Medium

## Issue: FINDING-226 - Complete absence of documentation defining authentication defense controls
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 6.1.1 requires application documentation to explicitly define how rate limiting, anti-automation, and adaptive response controls defend against credential stuffing and password brute force, and how they prevent malicious account lockout. A thorough review of all provided documentation and code reveals no documentation whatsoever addressing these concerns.

### Details
The application delegates authentication to Apache OAuth (oauth.apache.org) but provides no documentation explaining:
- What brute force protections the OAuth provider implements
- Whether there are retry limits on the OAuth callback flow
- How the application would detect or respond to credential stuffing
- How malicious account lockout is prevented at the identity provider level

**CWE:** None specified
**ASVS:** 6.1.1 (L1)

### Remediation
Create an authentication security document (e.g., `v3/docs/authentication-security.md`) that addresses:
1. Authentication flow and OAuth provider's brute force protections
2. Rate limiting policies for login attempts, vote submission, and API endpoints including implementation details
3. Anti-automation measures such as CAPTCHA/challenge requirements and bot detection mechanisms
4. Adaptive response policies describing actions taken after N failed attempts and escalation procedures
5. Account lockout prevention including lockout policy, anti-lockout measures, and election-specific protections against voter lockout during active elections
6. Configuration details including where settings are configured, how to modify thresholds, and monitoring/alerting for attack detection

### Acceptance Criteria
- [ ] Authentication security documentation created
- [ ] OAuth provider protections documented
- [ ] Rate limiting policies defined
- [ ] Anti-automation measures documented
- [ ] Account lockout prevention strategy documented

### References
- Affected files: `v3/TODO.md`, `v3/docs/schema.md`, `v3/server/pages.py`, `v3/server/main.py:33,39-43`
- Source: 6.1.1.md

### Priority
Medium

---

## Issue: FINDING-227 - No rate limiting or throttling on vote submission and state-changing endpoints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote submission and election state-change endpoints have no rate limiting or throttling controls. An authenticated attacker (any committer) could submit rapid automated requests causing database contention in SQLite's single-writer model.

### Details
Affected endpoints with no rate limiting:
- `/do-vote/<eid>` for vote submission
- `/do-create/<eid>` for election creation
- `/do-open/<eid>` for opening elections
- `/do-close/<eid>` for closing elections

These endpoints only perform authentication checks via `@asfquart.auth.require` but have no rate limiting, anti-automation checks, or throttling mechanisms.

**CWE:** None specified
**ASVS:** 6.1.1, 6.3.1 (L1)

### Remediation
1. Implement rate limiting on sensitive endpoints using a library like `quart_rate_limiter` (e.g., `@rate_limit(1, timedelta(seconds=5))` for vote submission to allow 1 vote per 5 seconds)
2. Document the rate limiting configuration in the authentication security document
3. Add similar rate limiting to election state-change endpoints (e.g., `@rate_limit(5, timedelta(minutes=1))` to allow 5 state changes per minute)
4. Convert state-changing GET endpoints to POST with CSRF protection as acknowledged in TODO.md
5. Implement submission cooldown check by tracking last vote timestamp and enforcing minimum 10-second delay between resubmissions

### Acceptance Criteria
- [ ] Rate limiting implemented on vote submission endpoint
- [ ] Rate limiting implemented on state-change endpoints
- [ ] Rate limiting configuration documented
- [ ] Test added for rate limit enforcement

### References
- Affected files: `v3/server/pages.py:367,408,429,448,290-323`, `v3/steve/election.py:265`
- Source: 6.1.1.md, 6.3.1.md

### Priority
Medium

---

## Issue: FINDING-228 - Inconsistent Authentication Level Between Vote Display Page and Vote Submission Endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote display page (`GET /vote-on/<eid>`) includes a voter eligibility check via `election.q_find_issues`, but the corresponding vote submission endpoint (`POST /do-vote/<eid>`) does not perform the same check at the web layer, violating the principle of consistent enforcement.

### Details
While the business logic layer (`election.add_vote`) does check `q_get_mayvote`, the inconsistency in where and how security controls are applied means that if the business-layer check in `add_vote` fails or is modified, the web layer provides no safety net. Additionally, error messages from the business layer are caught generically, potentially revealing different information than the web-layer check would provide.

**CWE:** None specified
**ASVS:** 6.1.3 (L2)

### Remediation
Apply consistent eligibility checking at the web layer for both endpoints. In the `do_vote_endpoint` function, add the same eligibility check used in `vote_on_page`: call `election.q_find_issues.perform(result.uid, election.eid)` and check if results exist using `fetchall()`. If no results (user not eligible), flash a danger message 'You are not eligible to vote in this election.' and redirect to '/voter' with code 303 before processing any votes.

### Acceptance Criteria
- [ ] Eligibility check added to vote submission endpoint
- [ ] Consistent error messaging implemented
- [ ] Test added for unauthorized vote submission

### References
- Affected files: `v3/server/pages.py:231-290,402-440`
- Source: 6.1.3.md

### Priority
Medium

---

## Issue: FINDING-229 - Inconsistent Authentication Strength for Election Document Access
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `/docs/<iid>/<docname>` route serves election-related documents but requires only a bare session (`@asfquart.auth.require`) while all other election data access routes require committer-level authentication (`@asfquart.auth.require({R.committer})`), creating inconsistent authentication strength across the election data access pathway.

### Details
While the `mayvote` check provides partial mitigation by verifying voter eligibility, the authentication tier is weaker than equivalent election routes. Additionally, the unimplemented `### verify the propriety of DOCNAME` comment suggests incomplete security hardening and potential path traversal vulnerability.

**CWE:** CWE-287
**ASVS:** 6.3.4 (L2)

### Remediation
1. Change authentication decorator from bare `@asfquart.auth.require` to `@asfquart.auth.require({R.committer})` to match other election routes
2. Implement docname validation to prevent directory traversal by checking for '..' and path separators
3. Use whitelist approach by verifying resolved file path is relative to allowed directory
4. Log invalid docname access attempts with user ID for security monitoring

### Acceptance Criteria
- [ ] Authentication level increased to committer
- [ ] Path traversal validation implemented
- [ ] Logging added for invalid access attempts
- [ ] Test added for path traversal prevention

### References
- Affected files: `v3/server/pages.py:469-489`
- Related findings: FINDING-026, FINDING-098, FINDING-100, FINDING-235
- Source: 6.3.4.md

### Priority
Medium

---

## Issue: FINDING-230 - No User-Facing Notification Mechanism for Security Events
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Even if authentication events were tracked and analyzed, there is no delivery mechanism to notify users. The application has no email notification system for security events, no in-app security alert display, and no security event display on profile/dashboard pages.

### Details
Missing notification mechanisms:
- No email notification system for security events (the person.email field exists but is only for sending ballot links)
- No in-app security alert display (flash messages are only used for operational feedback)
- No security event display on profile/dashboard pages
- Users cannot review their own authentication history to identify compromise

For a voting system, users should be able to verify that only they have accessed their voting sessions.

**CWE:** CWE-356
**ASVS:** 6.3.5 (L3)

### Remediation
1. Add security notification display to authenticated pages
2. Create a profile page that displays authentication history (recent login times, IPs, user agents) and pending security alerts
3. Implement an async notification function that sends both email notifications and stores in-app alerts for suspicious authentication events
4. Include functionality to mark alerts as read and allow users to review their complete authentication history

### Acceptance Criteria
- [ ] Profile page with authentication history created
- [ ] Email notification system implemented
- [ ] In-app security alerts implemented
- [ ] Test added for notification delivery

### References
- Affected files: `v3/server/pages.py:570-576,136-169`
- Source: 6.3.5.md

### Priority
Medium

---

## Issue: FINDING-231 - No User Notification When Person Details (Email/Name) Are Modified
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `add_person` method performs an upsert operation that can silently modify a user's email address without any notification to either the old or new email address. Email addresses are security-sensitive authentication details used for election-related communications, making silent modifications a security risk.

### Details
- The method doesn't check if values actually changed before updating
- No audit trail exists, preventing administrative oversight
- A silently changed email could redirect election notifications to an attacker
- No notification is sent to the old or new email address when changes occur

**CWE:** None specified
**ASVS:** 6.3.7 (L3)

### Remediation
1. Implement change detection in `add_person()` to compare existing values before updating
2. Add logging to record all person detail changes with before/after values
3. Implement a notification service that sends alerts to BOTH the old and new email addresses when email is changed
4. Create an audit trail for all person detail modifications
5. Example implementation should check for existing person record, detect changes, log modifications, and call `_notify_detail_change()` method to send notifications to both old and new email addresses

### Acceptance Criteria
- [ ] Change detection implemented
- [ ] Notification service created
- [ ] Audit trail added
- [ ] Test added for email change notifications

### References
- Affected files: `v3/steve/persondb.py:46-51`, `v3/steve/election.py:510-516`
- Source: 6.3.7.md

### Priority
Medium

---

## Issue: FINDING-232 - Profile/Settings Pages Exist Without Update Notification Framework
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application provides authenticated `/profile` and `/settings` endpoints, indicating user-facing profile management is an intended feature. However, no notification framework exists anywhere in the codebase to support ASVS 6.3.7 compliance when profile update functionality is implemented.

### Details
- No email module, notification queue, or message templates exist
- When POST handlers are added, no infrastructure guides developers toward notification implementation
- The system stores and uses email addresses for election communications (as shown in `get_voters_for_email()`), but lacks security notification capability

**CWE:** None specified
**ASVS:** 6.3.7 (L3)

### Remediation
Implement a notification service that can be used across the application:
1. Create a `notifications.py` module with `notify_auth_detail_change()` function that sends notifications to affected email addresses about authentication detail changes
2. The service should support different notification types (email_changed, name_changed, profile_updated) and notify all relevant email addresses (typically both old and new)
3. Implement email sending infrastructure including templates that clearly explain what changed, when, and how to report unauthorized changes
4. Integrate this notification service into all profile update handlers before deploying POST functionality for `/profile` and `/settings` routes

### Acceptance Criteria
- [ ] Notification service module created
- [ ] Email templates implemented
- [ ] Integration with profile update handlers completed
- [ ] Test added for notification functionality

### References
- Affected files: `v3/server/pages.py:578-591,82`
- Source: 6.3.7.md

### Priority
Medium

---

## Issue: FINDING-233 - Differential Response in /admin Reveals PersonDB Registration Status
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When an authenticated ASF committer visits /admin, the application checks whether they exist in the PersonDB. Two distinct responses are returned based on PersonDB registration status, creating observable differentiators that violate the principle of consistent error handling.

### Details
Observable differentiators:
1. HTTP response code (200 vs 404)
2. Page content/template (Full admin page vs. 'Unknown Person' error)
3. Timing (successful path executes additional DB queries and template processing)

At ASVS Level 3, this differential response reveals whether an authenticated ASF committer is registered in the STeVe PersonDB, violating the principle of consistent error handling even for self-status information leakage.

**CWE:** None specified
**ASVS:** 6.3.8 (L3)

### Remediation
Return a consistent response regardless of PersonDB status. Either show a 'setup required' page with the same HTTP 200 code, or handle the missing person case gracefully within the normal admin template. Modify the admin_page function to catch PersonNotFound exceptions and set a result.person_registered flag to False, then return HTTP 200 with the admin template showing a 'not yet registered' state rather than a 404 error page. This ensures consistent HTTP status codes, templates, and processing times regardless of PersonDB registration status.

### Acceptance Criteria
- [ ] Consistent HTTP status codes implemented
- [ ] Same template used for all registration states
- [ ] Timing differences eliminated
- [ ] Test added for response consistency

### References
- Affected files: `v3/server/pages.py:297-310`
- Source: 6.3.8.md

### Priority
Medium

---

## Issue: FINDING-234 - No Authentication Factor Lifecycle Management for Voting System
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application delegates all authentication to external ASF OAuth but performs no verification of the authentication strength or MFA status of the authenticated session. The session data contains no information about how the user authenticated or whether MFA was used.

### Details
Critical gaps:
- No MFA factor recovery process exists
- No authentication level tracking exists via amr/acr claims
- No re-authentication is required for sensitive operations like voting, opening elections, or closing elections
- The person table schema contains only pid, name, and email with no mechanism for local identity proofing, secondary factor enrollment, or factor replacement tracking

In a voting system where election integrity is paramount, accepting authentication sessions without verifying that MFA factor recovery was accompanied by enrollment-level identity proofing means an attacker who social-engineers a factor recovery at the IdP level gains full voting access.

**CWE:** None specified
**ASVS:** 6.4.4 (L2)

### Remediation
Implement multi-layered authentication verification:
1. Request amr/acr claims from ASF OAuth and store in session to enable MFA verification at application level
2. Implement require_mfa decorator for sensitive operations including voting and election lifecycle management to prevent access from weakened/recovered sessions
3. Add session freshness checks requiring re-authentication for critical operations to limit exposure window of compromised sessions
4. Coordinate with ASF IdP team to document factor recovery identity proofing procedures ensuring NIST 800-63B §6.1.2.3 compliance at the IdP
5. Add authentication event logging including auth method, time, and factor changes to audit trail for post-incident forensic analysis

### Acceptance Criteria
- [ ] AMR/ACR claims requested and stored
- [ ] MFA requirement decorator implemented
- [ ] Session freshness checks added
- [ ] Authentication event logging implemented
- [ ] Test added for MFA enforcement

### References
- Affected files: `v3/server/pages.py:64-85,133,233,397,431,449,466`, `v3/steve/persondb.py:36-43,46-50`, `v3/schema.sql`
- Source: 6.4.4.md

### Priority
Medium

---

## Issue: FINDING-235 - No Automated Renewal Notification System for Expiring Authentication Factors
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The email infrastructure lacks all critical components required by ASVS 6.4.5 for timely authentication factor renewal notifications. The script operates as a manual, context-agnostic broadcast tool with no awareness of authentication factor expiration timelines.

### Details
Specific gaps include:
1. No expiration filtering - `get_voters_for_email()` retrieves all eligible voters without expiration context
2. No automated scheduling - script must be invoked manually by administrator
3. No configurable reminder thresholds - no reminder configuration, interval, or escalation logic exists
4. No standard renewal content - email body determined entirely by user-supplied template with no enforced renewal instructions
5. No state tracking - no mechanism to record reminders sent, preventing deduplication and escalation

**CWE:** CWE-287
**ASVS:** 6.4.5 (L3)

### Remediation
Implement a comprehensive automated renewal notification system with the following components:
1. Add expiration date tracking to voter/authentication data model with auth_expiry TIMESTAMP and renewal_token fields
2. Implement `get_voters_expiring_before(cutoff_date)` query method in steve.election module
3. Add `--days-before-expiry` CLI parameter to filter voters by approaching expiration
4. Create renewal_reminders tracking table to prevent duplicate notifications
5. Implement `reminder_already_sent()` and `record_reminder_sent()` methods for state management
6. Create standardized renewal email templates with required fields (expiry_date, days_remaining, renewal_url)
7. Integrate with cron/systemd timer for automated daily execution at multiple thresholds (14, 7, 3, 1 day before expiry)
8. Add `--dry-run` flag for testing
9. Implement escalation logic for unactioned renewals

### Acceptance Criteria
- [ ] Expiration tracking added to data model
- [ ] Automated scheduling implemented
- [ ] Reminder state tracking created
- [ ] Standardized templates implemented
- [ ] Test added for renewal notification flow

### References
- Affected files: `v3/server/bin/mail-voters.py:34-73,45,60-71,81-88`
- Related findings: FINDING-026, FINDING-098, FINDING-100, FINDING-229
- Source: 6.4.5.md

### Priority
Medium

---

## Issue: FINDING-236 - Email-based voter notification lacks request-bound authentication token generation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The email notification system provides template data consisting entirely of static, reusable identifiers. There is no mechanism anywhere in the email sending flow to generate a unique, time-limited authentication token per voter per notification, violating ASVS 6.6.2 which requires OOB tokens to be bound to the original authentication request.

### Details
The `get_voters_for_email()` method returns only persistent attributes (pid, name, email). If the operator-provided EZT template constructs any voting link, that link would be:
- Identical across multiple invocations
- Replayable indefinitely for the election's lifetime
- Not bound to any specific authentication request or session

**CWE:** None specified
**ASVS:** 6.6.2 (L2)

### Remediation
Generate a cryptographically random, time-limited, single-use token per voter per email send, store it server-side bound to the authentication context, and validate it on use:
1. Implement `generate_voter_auth_token()` to create tokens using `secrets.token_urlsafe(32)` with expiry timestamps
2. Store tokens in a database table bound to voter_pid, election_id, and usage status
3. Implement `validate_voter_auth_token()` to check token validity, expiry, single-use status, and mark as consumed after validation
4. Add database table for OOB token storage with expiry and single-use enforcement
5. Provide application control over authentication token injection into emails
6. Consider implementing HMAC-signed URLs with server-validated expiry timestamps
7. Long-term: migrate from email-based voter notification to push notifications or TOTP for voter authentication per ASVS section guidance

### Acceptance Criteria
- [ ] Token generation implemented
- [ ] Token storage table created
- [ ] Token validation implemented
- [ ] Single-use enforcement added
- [ ] Test added for token lifecycle

### References
- Affected files: `v3/server/bin/mail-voters.py:45-68`, `v3/steve/election.py:455-460`
- Source: 6.6.2.md

### Priority
Medium

---

## Issue: FINDING-237 - No Rate Limiting on Resource Identifier Endpoints — Brute Force Enumeration Unprotected
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Despite the application requiring authentication for all sensitive endpoints, no brute-force protection mechanism exists anywhere in the codebase. The absence of rate limiting on election/issue lookup endpoints means an authenticated attacker can systematically probe for valid identifiers without restriction.

### Details
The `load_election` and `load_election_issue` decorators do not implement any rate limiting, account lockout, or exponential backoff. Combined with the 40-bit entropy issue (CH06-022), an authenticated attacker can systematically discover valid election IDs. ASVS 6.6.3 explicitly requires rate limiting as a defense against brute force of out-of-band codes.

**CWE:** None specified
**ASVS:** 6.6.3 (L2)

### Remediation
Implement per-user rate limiting on election/issue lookup endpoints using quart_rate_limiter (e.g., `@rate_limit(10, timedelta(minutes=1))` to allow 10 requests/minute per IP). Alternatively, implement custom tracking of failed EID lookups per session with exponential backoff. Track failed lookup attempts per user, implement rate limiting that triggers after threshold is exceeded, and return HTTP 429 when rate limit is reached.

### Acceptance Criteria
- [ ] Rate limiting implemented on lookup endpoints
- [ ] Failed lookup tracking added
- [ ] HTTP 429 responses implemented
- [ ] Test added for rate limit enforcement

### References
- Affected files: `v3/server/pages.py:161,180,217,306,362,418,436,536`
- Source: 6.6.3.md

### Priority
Medium

---

## Issue: FINDING-238 - TLS Certificates Loaded Without Integrity Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The TLS certificate and private key files — which protect the OAuth authentication channel — are loaded directly from the filesystem without any integrity verification. There is no hash comparison, fingerprint validation, or signature check to ensure certificates have not been tampered with.

### Details
An attacker with write access to the `server/certs/` directory could substitute a rogue certificate and key, enabling man-in-the-middle interception of the OAuth authentication flow. The certificates are explicitly added to the `extra_files` watch set (line 88), meaning the server will automatically reload when certificate files change on disk, which amplifies the risk — a certificate swap triggers immediate adoption without manual restart.

**CWE:** None specified
**ASVS:** 6.7.1 (L3)

### Remediation
Implement certificate integrity verification before loading TLS certificates:
1. Validate against known fingerprints stored separately from the certificate files
2. Enforce restrictive file permissions (0o400 for key, 0o444 for cert) at startup
3. Store certificate fingerprints in a separate, integrity-protected configuration
4. Consider removing certificates from extra_files to prevent automatic reload on modification
5. Create a `verify_certificate_integrity()` function that computes SHA-256 hash of certificate file and compares against expected fingerprint from protected config, raising RuntimeError on mismatch

### Acceptance Criteria
- [ ] Certificate fingerprint validation implemented
- [ ] File permissions enforcement added
- [ ] Protected fingerprint configuration created
- [ ] Test added for integrity verification

### References
- Affected files: `v3/server/main.py:37,85-90`
- Source: 6.7.1.md

### Priority
Medium

---

## Issue: FINDING-239 - Certificate File Paths Accept Unvalidated Configuration Input
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Certificate and key file paths are constructed by joining `CERTS_DIR` with values from `config.yaml` without validating that the resulting paths remain within the intended `certs/` directory. The `pathlib.Path` `/` operator does not sanitize path traversal sequences.

### Details
An attacker who can modify `config.yaml` could redirect certificate loading to an arbitrary filesystem path using path traversal sequences (e.g., '../../../tmp/attacker-cert.pem'), causing the server to use an attacker-controlled certificate outside the intended certs directory.

**CWE:** None specified
**ASVS:** 6.7.1 (L3)

### Remediation
Add path containment validation for certificate configuration values to prevent directory traversal. Implement a `safe_cert_path()` function that resolves the certificate path and verifies it stays within the certs directory using `is_relative_to()`, raising ValueError if path escapes the directory. Also verify the file exists before returning the path.

### Acceptance Criteria
- [ ] Path containment validation implemented
- [ ] Directory traversal prevention added
- [ ] File existence check added
- [ ] Test added for path traversal attempts

### References
- Affected files: `v3/server/main.py:85-86`
- Source: 6.7.1.md

### Priority
Medium

---

## Issue: FINDING-240 - User Identity Model Lacks IdP Namespacing Despite Multi-IdP Capable Framework
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's identity model uses bare user identifiers (uid/pid) without IdP namespacing throughout the entire authentication and authorization flow. While currently configured with a single OAuth provider, the underlying asfquart framework explicitly supports OIDC multi-IdP authentication, which has been deliberately disabled.

### Details
This architectural gap means that re-enabling OIDC or adding a second IdP would immediately introduce identity spoofing vulnerabilities with no code-level protection. The entire identity model throughout the application — session handling, PersonDB, election ownership, voter eligibility, and vote recording — uses a bare uid/pid string with no IdP identifier or namespace component. If OIDC is re-enabled or another IdP is added, identity collision becomes possible where an attacker could register at IdP-B with a username matching a legitimate user at IdP-A and gain access to their elections and voting privileges.

**CWE:** None specified
**ASVS:** 6.8.1 (L2)

### Remediation
Implement composite identity keys combining IdP identifier and user ID throughout the application:
1. Store IdP identifier in session (e.g., `idp_id = s.get('idp', 'apache-oauth')`) and create composite UIDs (e.g., `composite_uid = f"{idp_id}:{raw_uid}"`)
2. Update PersonDB schema to include IdP namespace with columns for idp, idp_uid, and a generated composite pid
3. Refactor all pid/uid references in pages.py, election.py, and database operations to use namespaced identifiers
4. Add validation in election.py functions to assert pid includes IdP namespace (`assert ':' in pid`)
5. Implement IdP allowlist validation to ensure only approved IdPs can provide identities
6. Add integration tests for cross-IdP identity isolation to prevent regression when OIDC is re-enabled

### Acceptance Criteria
- [ ] Composite identity keys implemented
- [ ] PersonDB schema updated
- [ ] All pid/uid references refactored
- [ ] IdP allowlist validation added
- [ ] Test added for cross-IdP isolation

### References
- Affected files: `v3/server/main.py:43-47`, `v3/server/pages.py:80-95`, `v3/steve/election.py:184-196,295,308-317,321-330`
- Source: 6.8.1.md

### Priority
Medium

---

## Issue: FINDING-241 - Authentication Assertion Signature Validation Unverifiable — Entirely Delegated to Unaudited External Library
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application delegates 100% of its authentication assertion validation to the `asfquart` framework. No code in the audited codebase validates the presence or integrity of digital signatures on authentication assertions from the ASF Identity Provider.

### Details
There is no JWT parsing, no SAML signature verification, no JWKS endpoint configuration, and no public key or certificate configuration visible anywhere in the audited files. The application trusts session data without any visible signature verification at the application layer. All authorization decisions (voting, election management, ownership) flow from this trusted but unverified session data. If the `asfquart` framework contains any deficiency in assertion validation—such as accepting unsigned JWTs, not validating the `alg` header (algorithm confusion attack), not verifying issuer/audience claims, or misconfiguring JWKS—the entire application's authentication and authorization model would be bypassed.

**CWE:** None specified
**ASVS:** 6.8.2 (L2)

### Remediation
1. Include `asfquart` in audit scope: The `asfquart.auth` and `asfquart.session` modules MUST be audited for ASVS 6.8.2 compliance since they contain the actual assertion validation logic
2. Add defense-in-depth assertion claim validation at the application layer to validate critical session claims, verify assertion freshness, and verify expected issuer
3. Document IdP configuration requirements including JWKS endpoint, expected algorithm, issuer, and audience values so deployments can be verified
4. Implement assertion validation logging to create an audit trail of authentication events and signature verification results
5. Verify `asfquart` rejects unsigned assertions and protects against algorithm confusion attacks (alg: none)
6. Verify `asfquart` validates assertion signatures against IdP public keys with proper JWKS/certificate-based signature verification

### Acceptance Criteria
- [ ] Asfquart library audited for assertion validation
- [ ] Defense-in-depth claim validation added
- [ ] IdP configuration documented
- [ ] Assertion validation logging implemented
- [ ] Test added for unsigned assertion rejection

### References
- Affected files: `v3/server/pages.py:65-80,302-303`, `v3/steve/election.py`
- Source: 6.8.2.md

### Priority
Medium

---

## Issue: FINDING-242 - No Authentication Recentness Check for State-Changing Election Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Critical state-changing operations that alter election lifecycle (open, close, vote, create) perform no verification of when the user last authenticated. A session established hours or days earlier can be used to perform irreversible operations like casting votes or closing elections.

### Details
A stale or long-lived session (potentially from a compromised browser, shared workstation, or session replay) can be used to perform irreversible election operations. For a voting system, this undermines the assurance that the person casting the vote is the legitimate user and was actively present at the time of voting. 

Proof of concept: User authenticates and receives a session, leaves browser open on a shared workstation, hours later another person uses the still-active session to cast votes or manipulate election state without any recentness check preventing this abuse.

**CWE:** None specified
**ASVS:** 6.8.4 (L2)

### Remediation
Add session timestamp at login and verify before sensitive operations:
1. Define `SENSITIVE_OPS_MAX_AGE = 300` (5 minutes)
2. Implement `verify_session_freshness(max_age)` function that reads the session, checks for auth_time or session_created timestamp, and aborts with 401 if session age exceeds max_age, requiring re-authentication
3. Apply this verification to sensitive endpoints like `do_vote_endpoint`, `do_open_endpoint`, and `do_close_endpoint` by calling `await verify_session_freshness()` before proceeding with the operation

### Acceptance Criteria
- [ ] Session timestamp tracking implemented
- [ ] Session freshness verification function created
- [ ] Freshness check applied to sensitive operations
- [ ] Test added for stale session rejection

### References
- Affected files: `v3/server/pages.py:367,433,454,367-407,433-452,454-472,56-83`
- Source: 6.8.4.md

### Priority
Medium

---

## Issue: FINDING-243 - State-Changing Operations via GET Bypass Session CSRF Protections
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Two critical state-changing operations (opening and closing elections) use GET methods. While session tokens are verified on the backend via `@asfquart.auth.require({R.committer})`, GET requests are inherently more vulnerable to cross-site request forgery because they can be triggered by image tags, link prefetching, or redirects without user interaction.

### Details
Combined with the placeholder CSRF token (`basic.csrf_token = 'placeholder'` at line 84), a verified session can be abused through external trigger mechanisms. An attacker can trick an authenticated user into opening or closing an election without their knowledge by embedding malicious GET requests in external web pages. These operations are also exploitable in the context of automatic session creation without user consent (ASVS 7.6.2).

**CWE:** None specified
**ASVS:** 7.2.1, 7.5.3 (L1, L2, L3)

### Remediation
1. Change `/do-open/<eid>` and `/do-close/<eid>` endpoints to POST methods
2. Implement proper CSRF token generation using `secrets.token_urlsafe(32)` instead of the placeholder
3. Validate CSRF tokens on all POST requests by storing the token in the session and comparing it with the submitted form value
4. Example: `async def basic_info(): result = await asfquart.session.read(); basic = BasicInfo(); basic.uid = result.uid; basic.csrf_token = secrets.token_urlsafe(32); await asfquart.session.write({'csrf_token': basic.csrf_token}); return basic`
5. Add CSRF validation function and call it in all POST endpoints before processing state changes

### Acceptance Criteria
- [ ] Endpoints converted to POST
- [ ] CSRF token generation implemented
- [ ] CSRF token validation added
- [ ] Test added for CSRF protection

### References
- Affected files: `v3/server/pages.py:448,468,84`
- Source: 7.2.1.md, 7.5.3.md

### Priority
Medium

---

## Issue: FINDING-244 - Absence of Session Management Risk Analysis and Policy Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 7.1.1 explicitly requires documentation stating session inactivity timeout value, absolute maximum session lifetime, justification for these values in combination with other controls, and justification for any deviations from NIST SP 800-63B. The project's only documentation file (schema.md) covers database schema in detail but contains no mention of session management policies.

### Details
Missing documentation includes:
- Session token storage mechanism
- Session timeout values
- SSO interaction considerations
- NIST SP 800-63B analysis or deviation justification
- Risk analysis for session handling decisions
- Controls to coordinate session lifetimes between federated systems (ASVS 7.1.3)

Without this documentation, the session management implementation cannot be verified as intentional or appropriate for an election system.

**CWE:** None specified
**ASVS:** 7.1.1, 7.1.3 (L2)

### Remediation
Create a `session-management.md` document (or equivalent section in existing docs) containing:
1. Overview describing session management decisions for the Steve voting system per ASVS 7.1.1 requirements
2. Session Timeout Values section documenting inactivity timeout (recommended 15 minutes) with justification, noting NIST SP 800-63B Section 7.2 permits up to 30 minutes for AAL2; and absolute session lifetime (recommended 12 hours) with justification
3. NIST SP 800-63B Compliance section documenting AAL level with justification based on authentication method, re-authentication requirements for vote submission, and any deviations with justification
4. SSO Interaction section documenting how SSO session lifetime interacts with application session lifetime, session revocation on SSO logout, and IdP session coordination
5. Risk Analysis section documenting threats and corresponding mitigations
6. Federated identity management ecosystem documentation including SSO provider identity and integration points, session lifetime policy and rationale, idle timeout configuration, termination coordination between app and SSO provider, and re-authentication conditions

### Acceptance Criteria
- [ ] Session management documentation created
- [ ] Timeout values documented and justified
- [ ] NIST SP 800-63B compliance documented
- [ ] SSO interaction documented
- [ ] Risk analysis completed

### References
- Affected files: `v3/docs/schema.md`, `v3/ARCHITECTURE.md`
- Source: 7.1.1.md, 7.1.3.md

### Priority
Medium

---

## Issue: FINDING-245 - Complete Absence of Concurrent Session Limit Policy and Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no documented policy, configuration, or code to define or enforce how many concurrent (parallel) sessions are permitted for a single user account. For a voting/election management system where session integrity directly impacts the trustworthiness of votes and administrative actions, this is a significant gap.

### Details
Missing controls include:
1. No session count tracking - no database table, in-memory store, or external service tracks how many sessions exist per uid
2. No session limit constant/configuration defined anywhere in the codebase
3. No enforcement action to revoke oldest sessions, deny new login, or notify the user when multiple sessions exist
4. No session listing endpoint for users to view their active sessions
5. No session revocation endpoint for users to terminate other active sessions
6. No documentation defining the intended concurrent session behavior

**CWE:** None specified
**ASVS:** 7.1.2 (L2)

### Remediation
1. Document the policy - Create a session management policy defining: maximum concurrent sessions per account (e.g., 3 for regular users, 1 during active voting), behavior when the limit is reached (e.g., terminate oldest session, or deny new login), and any role-specific limits
2. Implement session tracking using a server-side session registry that tracks active sessions per user with timestamps, implements MAX_CONCURRENT_SESSIONS policy, and provides methods to `register_session()`, `get_active_sessions()`, and `revoke_session()`
3. Integrate into authentication flow - Check session count at login and at `basic_info()`
4. Add session management UI - Populate the existing `/settings` page with session listing and revocation controls
5. Invalidate sessions on credential change - When a user's OAuth token or password changes, revoke existing sessions

### Acceptance Criteria
- [ ] Concurrent session policy documented
- [ ] Session tracking registry implemented
- [ ] Session limit enforcement added
- [ ] Session management UI created
- [ ] Test added for session limit enforcement

### References
- Affected files: `v3/server/pages.py:70-87,547-560`, `v3/server/main.py:39-41`
- Source: 7.1.2.md

### Priority
Medium

---

## Issue: FINDING-246 - No Session Invalidation Mechanism or IdP Session Synchronization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no mechanism to synchronize session state with the IdP beyond the initial authentication. There is no back-channel logout handler to receive notifications when the IdP terminates sessions.

### Details
Complete codebase review reveals:
- No backchannel_logout implementation
- No session timeout configuration visible in application code
- No IdP token introspection/validation
- No max_age/auth_time parameter handling

Sessions cannot be actively terminated by the IdP. Revoked users retain access until some external mechanism clears sessions (server restart, store expiry). There is no documented session termination behavior between RP and IdP as required by ASVS 7.6.1.

**CWE:** None specified
**ASVS:** 7.6.1, 7.4.3 (L2)

### Remediation
Implement IdP session synchronization mechanisms:
1. Add back-channel logout support per OIDC spec with a POST `/backchannel-logout` endpoint that validates logout tokens, extracts sub/sid claims, and invalidates corresponding sessions
2. Add periodic IdP session validation that calls the IdP's token introspection or userinfo endpoint to verify the session is still active, destroying the local session if invalid
3. Ensure the `/logout` endpoint redirects to the IdP's logout endpoint for federated logout
4. Document the expected session lifetime behavior between RP and IdP

### Acceptance Criteria
- [ ] Back-channel logout endpoint implemented
- [ ] Periodic IdP session validation added
- [ ] Federated logout implemented
- [ ] Session termination behavior documented
- [ ] Test added for session invalidation

### References
- Affected files: `v3/server/pages.py` (entire file)
- Source: 7.6.1.md, 7.4.3.md

### Priority
Medium

---

## Issue: FINDING-247 - No Re-authentication Before Election Administration Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Election administration operations (create, add/edit/delete issues, set dates) require no re-authentication beyond the initial session. While these operations are restricted to the editable state (before an election opens), they can corrupt election configuration when combined with the ability to open elections.

### Details
Affected endpoints include:
- `do_create_endpoint` (create election)
- `do_add_issue_endpoint` (add issue)
- `do_edit_issue_endpoint` (modify issue)
- `do_delete_issue_endpoint` (delete issue)
- `do_set_open_at_endpoint` (set election date)
- `do_set_close_at_endpoint` (set election date)

All endpoints contain placeholder `### check authz` comments but no actual authorization implementation. A hijacked committer session can create spurious elections, add/modify/delete issues, and combined with the ability to open elections, an attacker could configure AND open a manipulated election.

**CWE:** None specified
**ASVS:** 7.5.3 (L3)

### Remediation
At minimum, administrative operations should require session freshness validation. Implement `require_fresh_auth()` middleware for administrative operations requiring authentication within the last 15 minutes (900 seconds). Check if the session's auth_time exists and if `time.time() - auth_time > max_age_seconds`. If authentication is stale, store the original request URL in session and redirect to IdP with `prompt=login` or `max_age` parameter for re-authentication. Apply this check to all administrative endpoints before processing the operation. Additionally, implement the `### check authz` placeholders with proper ownership verification.

### Acceptance Criteria
- [ ] Session freshness validation implemented
- [ ] Fresh auth requirement added to admin operations
- [ ] Authorization placeholders implemented
- [ ] Test added for stale session rejection on admin operations

### References
- Affected files: `v3/server/pages.py:416-433,472,497,518-534,360,366`
- Source: 7.5.3.md

### Priority
Medium

---

## Issue: FINDING-248 - Session Creation Without User Consent
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not enforce explicit user consent or action before creating new application sessions. When a user's application session expires but their IdP session remains active, visiting any protected endpoint triggers an automatic redirect chain that silently re-establishes an application session without user interaction.

### Details
The OAuth integration lacks prompt parameters (`prompt=login` or `prompt=consent`) and there is no interstitial login page requiring explicit user action. When `@asfquart.auth.require` detects no session, it auto-redirects to the IdP which silently authenticates if the IdP session is still active, creating a new application session without user awareness. This is particularly dangerous with state-changing GET endpoints like `/do-open/<eid>` and `/do-close/<eid>` where an attacker can craft links that trigger both session creation and state changes in a single redirect chain.

**CWE:** None specified
**ASVS:** 7.6.2 (L2)

### Remediation
1. Add `prompt=login` or `prompt=consent` to the OAuth initiation URL to force explicit user interaction at the IdP: `asfquart.generics.OAUTH_URL_INIT = 'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&prompt=login'`
2. Implement an interstitial login page instead of auto-redirecting to the IdP. When `@asfquart.auth.require` detects no session, render a page with a Sign In button rather than auto-redirecting. Create a `/login` endpoint with a form requiring POST to `/auth/begin`
3. Add `max_age` parameter to limit how recently the user must have authenticated at the IdP (e.g., `max_age=300` for 5 minutes)
4. Convert `/do-open/<eid>` and `/do-close/<eid>` from GET to POST to prevent link-triggered state changes (already covered in CH07-006)

### Acceptance Criteria
- [ ] Prompt parameter added to OAuth flow
- [ ] Interstitial login page implemented
- [ ] Max_age parameter added
- [ ] Test added for explicit consent requirement

### References
- Affected files: `v3/server/main.py:37-40`, `v3/server/pages.py:136-165,437-453,456-472`
- Source: 7.6.2.md

### Priority
Medium

---

## Issue: FINDING-249 - No Formal Authorization Policy Document Defining Access Rules
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application lacks a formal authorization policy document that defines function-level and data-specific access rules. ARCHITECTURE.md contains only a single sentence about authorization. schema.md marks authorization rules as 'TBD' (to be determined). There are 10 unresolved '### check authz' placeholders in pages.py.

### Details
Without documented authorization rules:
- Developers cannot implement consistent access controls
- Testers cannot verify authorization enforcement
- Administrators cannot audit compliance
- Security reviewers cannot assess completeness

The absence of formal documentation has directly led to the implementation gaps identified in the other findings. ASVS 8.1.1, 8.1.2, and 8.1.3 specifically require authorization documentation defining decision-making factors, field-level access rules, and environmental/contextual attributes.

**CWE:** CWE-1059
**ASVS:** 8.1.1, 8.1.2, 8.1.3 (L1, L2, L3)

### Remediation
Create a formal `AUTHORIZATION.md` document that includes:
1. Role definitions with sources and descriptions (Anonymous, Authenticated, Committer, PMC Member, Election Owner, Authz Group Member, Voter)
2. Function-level access rules matrix mapping endpoints to required roles and resource checks
3. Data-specific rules for election management, voting, and tallying
4. Field-level access rules for election metadata, issues, votes, and person records showing read/write permissions by role and state
5. Decision-making factors including user role, resource ownership, group membership, voter eligibility, election state, and tamper status
6. Environmental and contextual attributes (session UID, election state, time-based attributes like open_at/close_at, explicitly excluded attributes like IP/device)
7. State transition rules defining which roles can trigger which state changes
8. Security Decision Matrix mapping each endpoint to the attributes evaluated before granting access

Include this documentation alongside ARCHITECTURE.md and reference it from code comments.

### Acceptance Criteria
- [ ] AUTHORIZATION.md document created
- [ ] Role definitions documented
- [ ] Function-level access rules matrix completed
- [ ] Field-level access rules documented
- [ ] Security decision matrix created

### References
- Affected files: `v3/ARCHITECTURE.md`, `v3/docs/schema.md`, `v3/server/pages.py:101,167,194,290,335,349,363,378,394,413`
- Related findings: FINDING-040, FINDING-130
- Source: 8.1.1.md, 8.1.2.md, 8.1.3.md

### Priority
Medium

---

## Issue: FINDING-250 - Authorization Tier Inconsistency: Lower Privilege Required for Management Than Creation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has an inverted authorization model where creating an election requires higher privileges (R.pmc_member) than performing all subsequent management operations (R.committer). This means users who lack sufficient privileges to create elections can nonetheless fully manage, modify, open, close, and delete issues from any existing election.

### Details
Every management endpoint includes a comment acknowledging this issue: '### need general solution'. The authorization model is inverted: creation of elections (a lower-impact, reversible operation that simply initializes a new election) requires higher privilege than opening/closing elections and modifying issues (higher-impact, irreversible operations that affect election integrity and voter participation). A committer who should only have voter-level access can perform all administrative operations on any election.

**CWE:** CWE-269
**ASVS:** 8.3.1 (L1)

### Remediation
Align management endpoint authorization with creation privilege level. Change all management endpoints (`do_add_issue_endpoint`, `do_edit_issue_endpoint`, `do_delete_issue_endpoint`, `do_open_endpoint`, `do_close_endpoint`, `do_set_open_at_endpoint`, `do_set_close_at_endpoint`, `manage_page`, `manage_stv_page`) from requiring R.committer to requiring R.pmc_member. Add ownership verification using `check_election_authz` (from CH08-001 remediation). Long-term: implement granular RBAC system distinguishing between election creators, election administrators, voters, and system administrators.

### Acceptance Criteria
- [ ] Management endpoints require R.pmc_member
- [ ] Ownership verification added
- [ ] Test added for privilege escalation prevention

### References
- Affected files: `v3/server/pages.py:423,445,465,483,507,530`
- Source: 8.3.1.md

### Priority
Medium

---

## Issue: FINDING-251 - Election Date Modification Without Object-Level Authorization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_set_election_date` helper function modifies election properties (open_at, close_at) without performing object-level authorization checks, relying only on the broken `load_election` decorator that contains an unimplemented '### check authz' placeholder.

### Details
Any committer can modify the advisory open/close dates on any election, causing confusion for eligible voters and election owners. While the `prevent_open_close_update` trigger prevents changes after closing, dates can be freely modified while the election is editable or open. This is a direct modification of object properties without authorization, violating ASVS 8.2.3's requirement for field-level access restrictions.

**CWE:** CWE-639
**ASVS:** 8.2.3 (L2)

### Remediation
This is resolved by the same `load_election` decorator fix described in CH08-001. Additionally, `_set_election_date` should verify the election is in the editable state: `if not election.is_editable(): quart.abort(403, 'Cannot modify dates on a non-editable election')`. Add proper exception-based state checking instead of relying on implicit database trigger enforcement.

### Acceptance Criteria
- [ ] Object-level authorization added to decorator
- [ ] State validation added to _set_election_date
- [ ] Test added for unauthorized date modification

### References
- Affected files: `v3/server/pages.py:99-122`, `v3/steve/election.py:117,119`
- Related findings: FINDING-015, FINDING-028
- Source: 8.2.3.md

### Priority
Medium

---

## Issue: FINDING-252 - Election Time-Based Validity Constraints (open_at/close_at) Are Stored But Never Enforced During Vote Acceptance or State Computation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The election system stores `open_at` and `close_at` timestamp fields in the database and displays them to users in the UI, creating an expectation that voting is only permitted within the specified time window. However, these time constraints are never validated when accepting votes or computing election state.

### Details
The `_compute_state()` method only checks the manual `closed` flag and the presence of cryptographic keys, ignoring the time-based validity fields entirely. This creates a false expectation of enforcement where votes can be accepted after the displayed deadline, undermining election integrity. The gap is classified as Type B - control EXISTS (time fields stored and displayed) but NOT APPLIED (never checked during vote acceptance or state computation).

**CWE:** None specified
**ASVS:** 9.2.1 (L1, L2, L3)

### Remediation
**Option 1:** Enforce time constraints in `_compute_state()` by adding time-based checks that return S_CLOSED if close_at has passed or S_EDITABLE if open_at has not yet arrived.

**Option 2:** Add explicit time checks in `add_vote()` that raise ElectionBadState exceptions if the current time is outside the open_at/close_at window.

Implementation should include:
1. Import time module and get current timestamp
2. Compare current time against md.close_at and md.open_at
3. Return appropriate state or raise exception if outside valid time window
4. Consider automated election close via background task for defense-in-depth

### Acceptance Criteria
- [ ] Time-based validation added to state computation or vote acceptance
- [ ] Votes rejected outside time window
- [ ] Test added for time-based enforcement

### References
- Affected files: `v3/steve/election.py:306,211,367,371`, `v3/server/pages.py:590,402`
- Source: 9.2.1.md

### Priority
Medium