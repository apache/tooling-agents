# Security Audit Consolidated Report — apache/tooling-agents

## Report Metadata

| Field | Value |
|---|---|
| **Repository** | `apache/tooling-agents` |
| **ASVS Level** | L3 |
| **Severity Threshold** | Medium and above |
| **Commit** | `d0aa7e9` |
| **Date** | Apr 22, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 340 |
| **Total Findings** | 252 |

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|---|--:|--:|
| **Critical** | 15 | 6.0% |
| **High** | 73 | 29.0% |
| **Medium** | 164 | 65.1% |
| **Low** | 0 | — *(below threshold)* |
| **Info** | 0 | — *(below threshold)* |
| **Total** | **252** | **100%** |

### ASVS Level Coverage

Findings were identified across all three ASVS verification levels within scope. Many findings are tagged to multiple levels, reflecting controls that are absent at every assurance tier.

| Level | Findings Touching Level | Notes |
|---|--:|---|
| **L1** (Opportunistic) | 68 | Fundamental controls missing at the baseline tier — session management, output encoding, TLS enforcement, and basic authorization checks. |
| **L2** (Standard) | 199 | Broadest surface — OAuth/OIDC hardening, CSRF, logging, secrets management, race conditions, and header security gaps dominate. |
| **L3** (Advanced) | 107 | Key lifecycle, process isolation, memory protection, mTLS, ECH, PAR, data retention, SBOM, and multi-party approval gaps. |

### Top 5 Risk Themes

**1. Broken Authorization and Cross-Tenant Data Access (Critical–High, 20+ findings)**

The most severe systemic risk. The vote submission endpoint does not verify voter eligibility before accepting ballots (FINDING-002). Election management endpoints lack ownership checks, allowing any authenticated user to modify or delete any election (FINDING-003, FINDING-084). Most critically, unscoped database queries enable cross-election read and write access to issues, votes, and voter rosters (FINDING-015). These gaps collectively undermine the core trust model of the application: that only eligible voters can vote, and only election owners can administer elections.

**2. Transport and Channel Security Not Enforced (Critical–High, 12+ findings)**

The application does not enforce a minimum TLS protocol version, leaving the server potentially negotiating deprecated TLS 1.0/1.1 connections (FINDING-007). When TLS is not configured, the application silently falls back to plain HTTP with no warning or guard (FINDING-008). No HSTS header is emitted even when TLS is active (FINDING-063), cipher suite selection is entirely uncontrolled (FINDING-036), and OCSP stapling and ECH are absent (FINDING-037, FINDING-038). Together, these gaps mean vote traffic, session tokens, and administrative actions may traverse the network without confidentiality or integrity guarantees.

**3. Election Integrity Bypass via State Enforcement and Race Conditions (Critical–High, 10+ findings)**

Election lifecycle state guards rely on Python `assert` statements that are stripped in optimized bytecode (`python -O`), rendering all state-transition checks — editable, open, closed — completely ineffective in production if optimization flags are used (FINDING-004). Vote content is never validated against the election's expected ballot structure (FINDING-005). TOCTOU race conditions allow votes to be inserted after an election is closed (FINDING-029), and the election-open operation lacks atomic transaction control, enabling concurrent state corruption (FINDING-030). The close and delete operations suffer from analogous atomicity and race-window defects (FINDING-053, FINDING-054).

**4. Pervasive Cross-Site Scripting (Critical–High, 8+ findings)**

Multiple XSS vectors exist across both stored and reflected attack surfaces. EZT templates render election titles, issue descriptions, and candidate names without HTML encoding (FINDING-006, FINDING-065). The `rewrite_description()` function constructs HTML from unencoded user input (FINDING-032). Server-generated data is injected into inline JavaScript objects without JavaScript-context escaping (FINDING-033). URL path parameters are reflected into error templates without sanitization (FINDING-034). Flash messages containing user input are rendered unencoded (FINDING-035). No Content-Security-Policy header is configured on any response (FINDING-062), eliminating the defense-in-depth layer that would constrain exploitation.

**5. Session Management and Authentication Architecture Gaps (High, 18+ findings)**

No logout endpoint exists anywhere in the application (FINDING-081). Sessions have no inactivity timeout and no absolute maximum lifetime (FINDING-080). Session identifiers are not regenerated upon authentication (FINDING-082). No re-authentication is required before critical operations such as opening, closing, or deleting elections (FINDING-083). CSRF protection is non-functional: a hardcoded placeholder token is used for POST requests (FINDING-022), and state-changing operations are exposed via GET, bypassing CSRF, CORS preflight, and session protections entirely (FINDING-021, FINDING-069). Multi-factor authentication is neither enforced nor available (FINDING-075). The OAuth integration lacks PKCE (FINDING-023), does not request or enforce scopes (FINDING-024), and bypasses OIDC entirely by not handling ID tokens (FINDING-026).

### Positive Controls Observed

Despite the breadth of findings, the audit identified a meaningful set of well-implemented security controls that demonstrate intentional security design in the cryptographic and data-access layers:

| # | Control | Strength |
|---|---|---|
| 1 | **CSPRNG throughout** — All randomness uses Python's `secrets` module (`token_bytes`, `token_hex`, `randbelow`). No use of `random` for cryptographic purposes. | Eliminates predictable randomness as an attack vector for salts, IDs, and vote shuffling. |
| 2 | **100% parameterized SQL** — All queries use `?`-placeholder binding via `asfpy.db` and `queries.yaml`. No string concatenation or f-string interpolation constructs SQL. | Effectively eliminates SQL injection across the entire data layer. |
| 3 | **Multi-layer key derivation** — Chain of `election_data → BLAKE2b → Argon2 → opened_key → Argon2(+pid+iid+salt) → vote_token → HKDF → encryption_key` provides strong cryptographic separation. | Compromising one layer does not directly yield keys for another; per-voter salt prevents cross-voter correlation. |
| 4 | **Per-voter cryptographic salt separation** — Each `(person, issue)` pair receives a unique 16-byte salt, used in vote-token generation and encryption-key derivation. | Prevents vote correlation even with full database access; enforced at schema level with `CHECK` length constraints. |
| 5 | **No OS command execution surface** — No imports or usage of `os.system()`, `subprocess`, `exec()`, `eval()`, or `os.execv*()` anywhere in the codebase. | Eliminates command injection as an attack class entirely. |
| 6 | **Centralized cryptography module** — All cryptographic operations are concentrated in `crypto.py`, using `cryptography`, `argon2-cffi`, and `hashlib` — no hand-rolled crypto. | Single audit surface for all crypto; industry-standard library usage. |
| 7 | **Schema-level defense in depth** — SQLite `STRICT` mode, `CHECK` constraints on BLOB lengths, `FOREIGN KEY … ON DELETE RESTRICT`, and the `prevent_open_close_update` trigger. | Database-level guards persist even if application-level checks are bypassed. |
| 8 | **Tamper detection before tallying** — `is_tampered()` recomputes `opened_key` from current election data and compares against stored value; `tally.py` gates on this check with a hard exit. | Detects post-opening modification of election structure before any decryption occurs. |
| 9 | **Fernet encrypt-then-MAC** — AES-128-CBC + HMAC-SHA256 with HMAC verified before decryption, preventing padding oracle attacks. *(Note: migration to XChaCha20-Poly1305 is in progress per FINDING-001.)* | Authenticated encryption is correctly implemented at the primitive level despite the algorithm-generation gap. |
| 10 | **Vote shuffling before tallying** — `crypto.shuffle()` uses Fisher-Yates with `secrets.randbelow()` to remove database insertion ordering from decrypted votes. | Prevents timing-based vote correlation via database row order. |
| 11 | **Framework-delegated OAuth and server-side token exchange** — Authorization code flow with server-to-server token exchange; single authorization server eliminates mix-up attacks. | Tokens never exposed to the browser; reduced OAuth attack surface. |
| 12 | **Consistent authentication decorator pattern** — All protected routes use `@asfquart.auth.require()` with role differentiation (`R.committer` vs `R.pmc_member`). | Uniform enforcement reduces the risk of accidentally unprotected endpoints. |

These controls — particularly the parameterized query discipline, CSPRNG usage, and multi-layer key derivation — represent a strong cryptographic and data-integrity foundation. The findings in this report primarily concern the *surrounding* infrastructure: transport security, session lifecycle, authorization enforcement, output encoding, operational logging, and configuration hardening — areas where the same rigor has not yet been applied.

---

## 3. Findings

### 3.1 Critical

#### FINDING-001: AES-128-CBC (Fernet) Used Instead of Approved AEAD Cipher; Incomplete Migration to XChaCha20-Poly1305

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 11.3.2 |
| **Files** | `v3/steve/crypto.py:63-75`, `v3/steve/crypto.py:77-80`, `v3/steve/crypto.py:84-88`, `v3/steve/election.py:236`, `v3/steve/election.py:271` |
| **Source Reports** | 11.3.2.md |
| **Related Findings** | None |

**Description:**

The application uses Fernet (AES-128-CBC + HMAC-SHA256) for vote encryption, which violates ASVS 11.3.2's requirement for approved AEAD cipher modes such as AES-GCM or ChaCha20-Poly1305. Evidence of an incomplete cryptographic migration exists: the key derivation function is explicitly configured for XChaCha20-Poly1305 (HKDF with info=b'xchacha20_key', 32-byte key length), but the actual encryption operations still use Fernet. This represents a Type B gap where the control exists but is not applied, creating false confidence that an approved cipher is in use. Fernet uses AES-128-CBC (not an approved AEAD mode), splits the 32-byte key into 16 bytes for HMAC-SHA256 and 16 bytes for AES-128 encryption, and while the encrypt-then-MAC construction mitigates classic padding oracle attacks, CBC mode remains vulnerable to implementation-level side channels. All vote ciphertext stored in the vote table uses this unapproved cipher mode, and the effective encryption strength is AES-128 (not AES-256), below modern recommendations for high-sensitivity data in a voting system protecting ballot secrecy.

**Remediation:**

Complete the migration indicated by the code comments. Replace Fernet with XChaCha20-Poly1305 (as the HKDF is already configured for) using the nacl.secret.SecretBox implementation, or alternatively use AES-256-GCM from the cryptography library. For XChaCha20-Poly1305: derive a 32-byte key using the existing HKDF setup, create a nacl.secret.SecretBox with the key, and use box.encrypt() for encryption (nonce auto-generated) and box.decrypt() for decryption. For AES-256-GCM: update HKDF info parameter to 'aesgcm_vote_key', use AESGCM(key) with a 96-bit nonce (12 bytes from os.urandom), prepend the nonce to ciphertext for storage, and split on decryption. Note: Migration requires a re-encryption strategy for existing vote data or a version-aware decryption path to handle both old Fernet-encrypted votes and new AEAD-encrypted votes during the transition period.

---

#### FINDING-002: Vote Submission Endpoint Lacks Voter Eligibility Authorization Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 10.3.2, 2.1.2, 2.1.3 |
| **Files** | `v3/server/pages.py:424-467`, `v3/server/pages.py:426` |
| **Source Reports** | 10.3.2.md, 2.1.2.md, 2.1.3.md |
| **Related Findings** | FINDING-003, FINDING-024, FINDING-073, FINDING-088, FINDING-103, FINDING-104, FINDING-105 |

**Description:**

The codebase contains 14+ instances of '### check authz' comments indicating developer awareness of the need for authorization checks, but these checks were never implemented. Any authenticated ASF committer can manage, open, close, or modify any election regardless of ownership. The authz field exists in the election schema but is never validated against the current user. The combined data item (requesting user's PID + election.owner_pid) is never validated for consistency. Any authenticated ASF committer can perform irreversible operations (open, close) on elections they don't own, and modify election content (add/edit/delete issues) arbitrarily.

**Remediation:**

Add voter eligibility verification in the POST handler before recording votes: election.q_find_issues.perform(result.uid, election.eid); if not election.q_find_issues.fetchall(): await flash_danger('You are not authorized to vote in this election.'); return quart.redirect('/voter', code=303). Deploy immediately to prevent unauthorized vote manipulation.

---

#### FINDING-003: Election Management Endpoints Missing Ownership Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 10.3.2, 10.4.11 |
| **Files** | `v3/server/pages.py:493`, `v3/server/pages.py:498`, `v3/server/pages.py:515`, `v3/server/pages.py:520`, `v3/server/pages.py:410`, `v3/server/pages.py:98`, `v3/server/pages.py:417`, `v3/server/pages.py:534`, `v3/server/pages.py:539`, `v3/server/pages.py:559`, `v3/server/pages.py:564`, `v3/server/pages.py:583`, `v3/server/pages.py:588`, `v3/server/pages.py:355`, `v3/server/pages.py:195` |
| **Source Reports** | 10.3.2.md, 10.4.11.md |
| **Related Findings** | FINDING-002, FINDING-024, FINDING-073, FINDING-088, FINDING-103, FINDING-104, FINDING-105 |

**Description:**

All election management endpoints fail to verify that the authenticated user (identified by the 'sub' claim from the OAuth token, stored as 'uid' in the session) owns the election being modified. The Election.owned_elections(DB_FNAME, result.uid) query exists and is used in admin_page for display purposes, but is never used as an enforcement gate for state-changing operations. Any authenticated committer can tamper with elections they don't own — opening elections prematurely, closing them early to suppress votes, deleting issues, or modifying election content.

**Remediation:**

Implement ownership verification in the load_election decorator to protect all management endpoints: verify that metadata.owner_pid matches the authenticated user's uid from the session; abort with 403 if not matched.

---

#### FINDING-004: Election Lifecycle State Enforcement Uses Bypassable `assert` Statements

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-670 |
| **ASVS Sections** | 2.3.1, 2.3.2, 2.3.4, 2.1.2, 2.1.3, 13.2.2, 15.3.5, 15.4.1, 15.4.3, 16.5.3, 16.3.3, 15.1.5, 8.1.2, 8.1.3, 8.1.4 |
| **Files** | `v3/steve/election.py:50`, `v3/steve/election.py:52`, `v3/steve/election.py:70`, `v3/steve/election.py:73`, `v3/steve/election.py:110`, `v3/steve/election.py:116`, `v3/steve/election.py:123`, `v3/steve/election.py:127`, `v3/steve/election.py:176`, `v3/steve/election.py:190`, `v3/steve/election.py:193`, `v3/steve/election.py:205`, `v3/steve/election.py:208`, `v3/steve/election.py:220`, `v3/steve/election.py:227`, `v3/steve/election.py:228`, `v3/steve/election.py:241`, `v3/steve/election.py:248`, `v3/steve/election.py:273`, `v3/steve/election.py:349`, `v3/server/pages.py:447`, `v3/server/pages.py:466`, `v3/server/pages.py:483`, `v3/server/pages.py:510`, `v3/server/pages.py:534` |
| **Source Reports** | 2.3.1.md, 2.3.2.md, 2.3.4.md, 2.1.2.md, 2.1.3.md, 13.2.2.md, 15.3.5.md, 15.4.1.md, 15.4.3.md, 16.5.3.md, 16.5.4.md, 16.3.3.md, 15.1.5.md, 8.1.2.md, 8.1.3.md, 8.1.4.md |
| **Related Findings** | None |

**Description:**

Security-critical state enforcement throughout the election lifecycle relies on Python assert statements, which are removed when Python is run with optimization flags (-O or -OO). This is a common production optimization that would completely bypass all election state validation. With assertions disabled, ALL election state enforcement is bypassed: issues can be added/edited/deleted on open or closed elections, voters can be added to open elections, elections can be opened multiple times or closed when editable, and vote types are not validated. When Python runs with optimization flags, all assert statements are removed from the bytecode, completely disabling state machine enforcement. This allows issues to be added to open elections, elections to be opened twice (overwriting salts/keys), elections to be closed when already closed, voters to be added to open elections, and elections to be deleted while active. This violates ASVS 15.4.3's requirement that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently modified.

**Remediation:**

Replace all security-relevant assert statements with explicit conditional checks that raise appropriate exceptions and include logging. For example: if not self.is_editable(): _LOGGER.warning('STATE_VIOLATION: election[E:%s] operation=%s current_state=%s required_state=%s', self.eid, operation, self.get_state(), self.S_EDITABLE); raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE). Implement a _require_state() method that validates election state and logs violations before raising ElectionBadState exception. Additionally, wrap calls in pages.py with try/except blocks to return user-friendly errors instead of 500 errors. Apply this pattern consistently to all state-changing methods.

---

#### FINDING-005: Vote Content Validation Step Entirely Absent in Vote Submission Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Sections** | 2.3.1, 2.3.2, 1.3.8, 1.3.9, 2.1.2, 2.2.1, 2.2.2, 2.2.3, 14.2.4, 15.3.5, 15.2.2, 16.5.3 |
| **Files** | `v3/steve/election.py:282-298`, `v3/steve/election.py:288`, `v3/steve/election.py:238`, `v3/server/pages.py:383-424`, `v3/server/pages.py:397-415`, `v3/server/pages.py:336` |
| **Source Reports** | 2.3.1.md, 2.3.2.md, 1.3.8.md, 1.3.9.md, 2.1.2.md, 2.2.1.md, 2.2.2.md, 2.2.3.md, 14.2.4.md, 15.3.5.md, 15.2.2.md, 16.5.3.md |
| **Related Findings** | None |

**Description:**

The add_vote() method accepts arbitrary vote content from users and encrypts it without any validation against the issue's vote type. The expected business logic step (validate vote against issue type) is explicitly marked as missing via a TODO comment ('### validate VOTESTRING for ISSUE.TYPE voting') but was never implemented. The votestring travels directly from user input to encrypted storage, skipping step 4 of the required sequential flow: 1) Authenticate user ✓, 2) Verify election is open ✓, 3) Verify voter eligibility ✓, 4) Validate vote content ✗, 5) Encrypt and store vote ✓. Invalid votes (e.g., 'INVALID_VALUE' for a Yes/No/Abstain issue, or malformed rankings for STV) are accepted, encrypted, and stored. For YNA issues, any arbitrary string is accepted instead of restricting to y/n/a values. For STV issues, invalid rankings (non-existent candidates, duplicate rankings, out-of-range values) are accepted. The corruption is only discovered during tally_issue() when decrypted votestrings are passed to vote-type-specific tally functions, potentially causing miscounts, crashes, or incorrect results.

**Remediation:**

Implement the missing validation step using the existing `vtypes` module infrastructure. In election.py add_vote(), fetch the issue record, get its type, load the appropriate vtypes module, and call its validate() method before encryption: issue = self.q_get_issue.first_row(iid); if not issue: raise IssueNotFound(iid); vtype_mod = vtypes.vtype_module(issue.type); if not vtype_mod.validate(votestring, self.json2kv(issue.kv)): raise InvalidVoteString(iid, issue.type, votestring). Implement validate() functions in each vtype module (e.g., vtypes/yna.py: VALID_VOTES = {'yes', 'no', 'abstain'}; def validate(votestring, kv): return votestring.lower().strip() in VALID_VOTES). Add vote validation unit tests verifying that each vote type properly rejects invalid vote strings.

---

#### FINDING-006: Stored XSS via Missing HTML Output Encoding in EZT Templates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.1.1, 1.1.2, 1.2.1, 1.3.1, 1.3.5, 1.3.4 |
| **Files** | `v3/server/templates/manage.ezt:176, 180, 241, 283`, `v3/server/templates/manage-stv.ezt:134, 175, 196`, `v3/server/templates/admin.ezt:19`, `v3/server/templates/voter.ezt:35, 49, 88, 96`, `v3/server/templates/vote-on.ezt:88, 108-109, 131, 163`, `v3/server/templates/flashes.ezt:3`, `v3/server/pages.py:240, 504, 535, 598` |
| **Source Reports** | 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.3.1.md, 1.3.5.md, 1.3.4.md |
| **Related Findings** | FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-193, FINDING-194 |

**Description:**

User-controlled data (election titles, issue titles, issue descriptions, owner names, authorization strings) is rendered in EZT templates without HTML encoding. The EZT templating engine provides the [format "html"] directive for HTML encoding, which is correctly used in a few JavaScript onclick handlers, but is systematically omitted in HTML body contexts across all templates. This enables both reflected XSS via URL parameters and stored XSS via admin-created content. Any authenticated committer who creates an election or adds/edits an issue can inject persistent JavaScript that executes in the browsers of all other authenticated users viewing those elections.

**Remediation:**

Apply [format "html"] to all user-controlled template variables in HTML body contexts. For example: &lt;strong&gt;[format "html"][issues.title][end]&lt;/strong&gt;, &lt;div&gt;[format "html"][issues.description][end]&lt;/div&gt;, &lt;h5&gt;[format "html"][owned.title][end]&lt;/h5&gt;. Alternative (Recommended): Migrate to a template engine with auto-escaping by default (e.g., Jinja2 with autoescape=True) to eliminate this entire class of vulnerabilities architecturally.

---

#### FINDING-007: No TLS Protocol Version Enforcement — Server May Accept Deprecated TLS 1.0/1.1 Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | N/A |
| **ASVS Sections** | 12.1.1, 12.3.1 |
| **Files** | `v3/server/main.py:83-91`, `v3/server/main.py:99-118`, `v3/server/main.py:77-82`, `v3/server/config.yaml.example` |
| **Source Reports** | 12.1.1.md, 12.3.1.md, 12.3.5.md |
| **Related Findings** | None |

**Description:**

The application constructs TLS parameters by passing only certfile and keyfile as keyword arguments to app.runx(). At no point in the codebase is an ssl.SSLContext explicitly created or configured. This means: (1) No ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2 — Python's ssl.SSLContext defaults minimum_version to TLSVersion.MINIMUM_SUPPORTED, which is typically TLS 1.0 on most systems. (2) No protocol flags — No use of ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 to disable deprecated versions. (3) No TLS 1.3 preference — No configuration ensures TLS 1.3 is the preferred negotiation outcome. (4) Both deployment modes affected — run_standalone() passes raw paths; run_asgi() creates no SSL configuration at all, deferring entirely to Hypercorn's own defaults. An attacker can force a protocol downgrade to exploit known TLS 1.0/1.1 weaknesses (BEAST, POODLE, Lucky Thirteen) to decrypt authentication tokens or encrypted vote payloads in transit.

**Remediation:**

Create an explicit ssl.SSLContext with enforced minimum version and pass it to the server framework. The context should: (1) Set ctx.minimum_version = ssl.TLSVersion.TLSv1_2, (2) Set ctx.maximum_version = ssl.TLSVersion.TLSv1_3, (3) Enable ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_SINGLE_DH_USE | ssl.OP_SINGLE_ECDH_USE, (4) Restrict cipher suites to 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES'. For ASGI/Hypercorn deployment, provide a hypercorn.toml configuration that enforces TLS 1.2+ with modern ciphers. Add minimum_tls_version and ciphers fields to the config schema. Add a startup warning/abort when certfile is empty and the server is not binding to localhost.

---

#### FINDING-008: Application Falls Back to Plain HTTP When TLS Not Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 12.2.1, 12.3.1, 12.3.3, 12.3.4, 12.3.5, 4.1.2 |
| **Files** | `v3/server/main.py:84-90`, `v3/server/main.py:98-117`, `v3/server/main.py:77-80`, `v3/server/main.py:83-86`, `v3/server/config.yaml.example:27-31`, `v3/server/config.yaml.example:28-31`, `v3/server/config.yaml.example:30-32` |
| **Source Reports** | 12.2.1.md, 12.2.2.md, 12.3.1.md, 12.3.3.md, 12.3.4.md, 12.3.5.md, 4.1.2.md |
| **Related Findings** | None |

**Description:**

The TLS control exists but is implemented as an optional, bypassable configuration toggle. Three specific issues compound into a single critical vulnerability: (1) Explicit plain HTTP fallback by design - The `if app.cfg.server.certfile:` conditional means when the certfile config value is empty, blank, or absent, the server launches over plain HTTP with zero warnings, zero errors, and zero compensating controls. The configuration comments actively document this as intended behavior. (2) No enforcement at any layer - There is no startup validation that rejects a missing TLS configuration, no HTTP listener that redirects to HTTPS, no HSTS header injection, and no warning log message when operating without TLS. The application silently degrades to an insecure transport. (3) ASGI mode has no TLS configuration at all - The `run_asgi()` function creates the application without any TLS parameters, delegating all transport security to the external ASGI server or reverse proxy with no verification that such protection exists. For this voting system, plain HTTP operation exposes authentication tokens (ASF OAuth tokens and session cookies transmitted in cleartext), vote contents (transmitted from client to server in HTTP request body before encryption), and election management operations.

**Remediation:**

Make TLS mandatory by enforcing certificate validation at startup - fail with critical error if certfile/keyfile are missing or invalid. Create explicit `ssl.SSLContext` with `minimum_version=TLSv1_2` and restricted cipher suites ('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES') instead of passing raw file paths. Remove config documentation suggesting plain HTTP is acceptable. Add HSTS response header ('Strict-Transport-Security: max-age=31536000; includeSubDomains') to all responses. For ASGI mode, document mandatory Hypercorn TLS configuration and add startup validation of X-Forwarded-Proto or equivalent. Consider adding an HTTP listener that returns 301 redirects to HTTPS to handle accidental plaintext connections.

---

#### FINDING-009: Complete Absence of Authenticated Data Clearing from Client Storage

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-524 |
| **ASVS Sections** | 14.3.1 |
| **Files** | `v3/server/pages.py:85-95`, `v3/server/pages.py:148`, `v3/server/pages.py:186`, `v3/server/pages.py:528` |
| **Source Reports** | 14.3.1.md |
| **Related Findings** | None |

**Description:**

The application completely lacks mechanisms to clear authenticated data from client storage after session termination. No `Clear-Site-Data` HTTP header is sent on any response, no logout endpoint exists to trigger session termination and cleanup, no `Cache-Control` headers prevent browser caching of authenticated pages, and no client-side JavaScript clears DOM/storage when session ends. All 12+ authenticated routes inject voter identity (uid, name, email) and election data into HTML responses via the `basic_info()` function. Without cache-control headers, browsers cache these pages containing sensitive voter information. In the context of a voting system, this enables voter privacy violations through browser cache on shared computers, exposing who voted and in which elections, violating ballot secrecy principles.

**Remediation:**

1. Add logout endpoint with `Clear-Site-Data` header that destroys server-side session and sends `Clear-Site-Data: "cache", "cookies", "storage"` header. 2. Add `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` headers to all authenticated responses via `after_request` middleware. 3. Add client-side cleanup JavaScript as fallback that clears sessionStorage on beforeunload and periodically checks session validity, clearing DOM and storage if session expired or server unreachable. 4. Mark sensitive DOM elements in templates with `data-sensitive` attribute for targeted cleanup.

---

#### FINDING-010: No Documented Risk-Based Remediation Timeframes and No SBOM for Security-Critical Dependencies

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-1395 |
| **ASVS Sections** | 15.1.1, 15.1.2, 15.2.1 |
| **Files** | `v3/steve/crypto.py:21-24`, `v3/steve/crypto.py:58-94`, `v3/steve/election.py:283-287`, `v3/steve/election.py:320-333`, `v3/server/main.py:1`, `v3/server/main.py:29`, `v3/server/main.py:37-38` |
| **Source Reports** | 15.1.1.md, 15.1.2.md, 15.2.1.md |
| **Related Findings** | None |

**Description:**

The application has no Software Bill of Materials (SBOM), no dependency manifest, no version pinning, and no documented risk-based remediation timeframes for third-party components. The application's entire security model depends on cryptographic libraries (cryptography for Fernet encryption, argon2-cffi for key derivation) used extensively in crypto.py and election.py. Without documented remediation timeframes, a published CVE in these libraries could remain unpatched indefinitely with no organizational accountability. The uv run --script invocation without a lock file resolves dependencies at install time, creating inconsistent environments and exposing the system to supply chain attacks. This renders vulnerability scanning impossible, eliminates build reproducibility, and creates compliance failures. Each deployment may resolve to different dependency versions, including ones with known vulnerabilities (e.g., CVE-2023-49083, CVE-2024-26130 in cryptography).

**Remediation:**

1. Create a Dependency Security Policy document (DEPENDENCY-POLICY.md) that includes: (a) Software Bill of Materials (SBOM) in CycloneDX or SPDX format generated by CI pipeline using cyclonedx-bom or syft, (b) Component Risk Classification identifying 'Dangerous Functionality Components' (cryptography, argon2-cffi) and 'Risky Components', (c) Vulnerability Remediation Timeframes with severity-based response times (Critical: 24-48h, High: 72h-7d, Medium: 14-30d, Low: 30-90d) with faster timelines for dangerous functionality components, (d) General Update Cadence (security-critical libraries: monthly review, update within 7 days of patch; all other dependencies: quarterly review), (e) Monitoring Process including automated dependency scanning in CI/CD, CVE notification subscription for dangerous functionality components, and quarterly manual review. 2. Create pyproject.toml with pinned dependencies: asfquart, asfpy, cryptography>=43.0.0,&lt;44, argon2-cffi&gt;=23.1.0,&lt;24, easydict&gt;=1.13. 3. Generate and commit lock file using 'uv lock' or 'pip-compile --generate-hashes'. 4. Generate and maintain SBOM, committing sbom.json to version control and regenerating on every dependency change. 5. Integrate automated vulnerability scanning via pip-audit in CI/CD pipeline. 6. Enable GitHub Dependabot or Renovate for automated dependency updates with mandatory security review for cryptographic library updates.

---

#### FINDING-011: Inconsistent Field Filtering — Election List Methods Return Raw Database Rows Without Python-Level Sensitive Field Exclusion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.3.1 |
| **Files** | `v3/steve/election.py:407-412`, `v3/steve/election.py:420-436`, `v3/steve/election.py:438-446`, `v3/server/pages.py:155-162`, `v3/server/pages.py:320-324`, `v3/server/pages.py:477-519` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | None |

**Description:**

The codebase demonstrates awareness of the need to exclude sensitive cryptographic fields through an explicit filtering control in `get_metadata()`, but this control is not applied to three parallel code paths that also return election data to user-facing page templates. The methods `open_to_pid()`, `upcoming_to_pid()`, and `owned_elections()` return raw database rows without Python-level field filtering. If the SQL queries include `salt` or `opened_key` columns, these cryptographic materials flow into the template rendering context for every authenticated user viewing the voter or admin pages. With `opened_key` and `mayvote.salt`, an attacker can compute `vote_token` values for any eligible voter, decrypt existing votes, and submit forged votes. The absence of Python-level filtering creates a single-layer defense that violates defense-in-depth principles.

**Remediation:**

Apply the same explicit field construction pattern used in `get_metadata()` to all class methods that return election data. Implement a `_safe_election_summary()` static method that constructs a safe election summary excluding cryptographic fields (salt, opened_key), and apply it in `open_to_pid()`, `upcoming_to_pid()`, and `owned_elections()`. Add a defense-in-depth guard in `postprocess_election()` that explicitly deletes sensitive fields if they exist. Audit `queries.yaml` to confirm that queries do NOT select `salt` or `opened_key` columns. Establish a coding standard that ALL methods returning data objects to callers outside the `Election` class MUST use explicit field construction (allowlist pattern), never raw query passthrough.

---

#### FINDING-012: Tally CLI Operations Lack Security Audit Trail

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | N/A |
| **ASVS Sections** | 16.1.1, 16.2.1, 16.3.1, 16.3.2 |
| **Files** | `v3/server/bin/tally.py:136-160`, `v3/server/bin/tally.py:102-133`, `v3/server/bin/tally.py:145-171`, `v3/server/bin/tally.py:88-142`, `v3/server/bin/tally.py:76-113`, `v3/server/bin/tally.py:138-165`, `v3/server/bin/tally.py:98-135`, `v3/server/bin/tally.py:120-150`, `v3/server/bin/tally.py:85-115` |
| **Source Reports** | 16.1.1.md, 16.2.1.md, 16.3.1.md, 16.3.3.md, 16.3.2.md |
| **Related Findings** | None |

**Description:**

The tally script performs the most sensitive operation in the system—decrypting all encrypted votes to compute election results. Despite this, the entire tally execution path contains zero audit logging for data access. This represents a Type A gap—no logging control exists at all for this critical operation. An administrator runs tally.py and all votes in an election are decrypted and displayed. No log record exists of who accessed this data, when, or which election was tallied. The tallying operation is the single most sensitive operation in the system—it decrypts all encrypted votes, revealing vote content. Without audit logging: there is no record of who initiated tallying, when votes were decrypted, whether --spy-on-open-elections was used to tally an election that hasn't closed yet, and the voter list is also extracted without logging. For L3 compliance, all access to sensitive data must be logged.

**Remediation:**

Add comprehensive audit logging to tally operations including: operator identity (via os.environ.get('USER')), election ID, issue ID, spy_on_open flag status, start/completion timestamps. Log tally initiation with _LOGGER.info() at start of main(). Log tampering detection with _LOGGER.critical() if detected. Log per-issue tallying with _LOGGER.info() including issue IID. Log tally completion with operator and election ID. Example: _LOGGER.info(f'Tally initiated by system user "{invoking_user}" for election[E:{election_id}] spy_on_open={spy_on_open}')

---

#### FINDING-013: Tampering Detection Event Bypasses Structured Logging Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Sections** | 16.1.1, 16.2.1, 16.2.3, 16.2.4, 16.3.2, 16.3.3 |
| **Files** | `v3/server/bin/tally.py:124`, `v3/server/bin/tally.py:152`, `v3/server/bin/tally.py:153-155`, `v3/server/bin/tally.py:119`, `v3/server/bin/tally.py:151`, `v3/server/bin/tally.py:129, 140-141`, `v3/server/bin/tally.py:145-147`, `v3/server/bin/tally.py:133-136` |
| **Source Reports** | 16.1.1.md, 16.2.1.md, 16.2.3.md, 16.2.4.md, 16.3.2.md, 16.3.3.md |
| **Related Findings** | None |

**Description:**

The most critical security event in the entire voting system—detection of election tampering—bypasses the configured structured logging framework and outputs only to stdout via print(). The logging control (_LOGGER) is imported, configured, and used elsewhere in the same file for less critical events, but is NOT invoked for the highest-severity security event. Election tampering detection uses print() instead of structured logging means: (1) Alert Loss Risk - stdout may not be captured by log aggregation systems, especially in daemon/cron/systemd deployments, (2) No Forensic Timeline - without timestamp and operator identity, investigators cannot reconstruct when tampering was detected or who discovered it, (3) False Security Confidence - security team believes logging covers all events when the most critical one is excluded, (4) No SIEM Correlation - cannot correlate tampering detection with other security events.

**Remediation:**

Replace print() statements with structured logging using _LOGGER.critical() for tampering detection. Add complete ASVS 16.2.1 metadata including timestamp, operator identity, system context, and structured event type. Example: _LOGGER.critical(f'TAMPERING_DETECTED: election[E:{election_id}] has been tampered with. Tally aborted. db_path={db_fname} spy_on_open={spy_on_open}'). Maintain print() for CLI user feedback but ensure security events are logged to structured logging framework. Add unit tests to verify critical events are logged with caplog assertions.

---

#### FINDING-014: Error Handling Pattern Exists in do_vote_endpoint but Not Applied to Five Other State-Changing Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-209 |
| **ASVS Sections** | 16.5.1, 16.5.2 |
| **Files** | `v3/server/pages.py:498`, `v3/server/pages.py:520`, `v3/server/pages.py:538`, `v3/server/pages.py:563`, `v3/server/pages.py:586`, `v3/steve/election.py:75-89`, `v3/steve/election.py:122-128`, `v3/steve/election.py:190-207`, `v3/steve/election.py:209-220`, `v3/steve/election.py:222-233` |
| **Source Reports** | 16.5.1.md, 16.5.2.md |
| **Related Findings** | FINDING-059 |

**Description:**

A secure error handling pattern exists in do_vote_endpoint that catches exceptions, logs details server-side, and returns generic error messages to users. However, this pattern is not applied to five other state-changing endpoints that perform security-critical operations (do_open_endpoint, do_close_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint). These unprotected endpoints call business logic methods that use assert statements for state validation, which will raise unhandled AssertionError exceptions when violated. Stack traces could expose cryptographic parameters (opened_key, salt values), database file paths, query structures, and internal election state machine design. In debug mode, full source code context and all local variables in each stack frame are exposed.

**Remediation:**

Option A: Apply try-except pattern to each endpoint (consistent with do_vote_endpoint). Wrap all business logic calls in try-except blocks that catch Exception, log full details server-side with _LOGGER.error(), and return generic flash messages to users. Option B (preferred): Replace assert statements with proper validation that returns user-friendly errors. Change assert statements to if checks that raise typed exceptions (e.g., ElectionBadState) which can be caught and handled appropriately in web endpoints.

---

#### FINDING-015: Cross-Election Issue Data Access and Modification via Unscoped Queries

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2, 8.3.3, 8.4.1 |
| **Files** | `v3/queries.yaml:q_get_issue`, `v3/queries.yaml:c_edit_issue`, `v3/queries.yaml:c_delete_issue`, `v3/steve/election.py:145`, `v3/steve/election.py:160`, `v3/steve/election.py:170`, `v3/server/pages.py:175` |
| **Source Reports** | 8.2.2.md, 8.3.3.md, 8.4.1.md |
| **Related Findings** | FINDING-028, FINDING-251 |

**Description:**

Issue-level queries (q_get_issue, c_edit_issue, c_delete_issue) filter only by iid without constraining to the parent election's eid. Combined with the load_election_issue decorator not validating issue-election affiliation, operations on Election A can read/modify/delete issues belonging to Election B. This allows an attacker to bypass election state restrictions by routing operations through an editable election. An attacker can read issue titles, descriptions, and vote configurations from other elections, edit issues in open/closed elections by routing through an editable election (bypasses state machine), and delete issues from other elections, destroying voting data and election integrity. This is a cross-tenant data access vulnerability where the tenant boundary (election) is not enforced at the query level.

**Remediation:**

Add election scoping to all issue queries by adding 'AND eid = ?' to q_get_issue, c_edit_issue, and c_delete_issue queries in queries.yaml. Modify get_issue(), edit_issue(), and delete_issue() methods in election.py to pass self.eid as an additional parameter. Add rowcount checks after UPDATE/DELETE operations to detect cross-election attempts and raise IssueNotFound exception when no rows are affected. This ensures issues can only be accessed within the context of their parent election.

### 3.2 High

#### FINDING-016: No Cryptographic Key Lifecycle Management Implementation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | N/A |
| ASVS Sections | 11.1.1, 13.1.4, 13.3.4 |
| Files | `v3/steve/crypto.py` (27-29, 32-42, 44-48)&lt;br&gt;`v3/steve/election.py` (71-82, 111-116, 119-135)&lt;br&gt;`v3/schema.sql` (N/A) |
| Source Reports | 11.1.1.md, 13.1.4.md, 13.3.4.md |
| Related Findings | None |

**Description:**

NIST SP 800-57 defines a key lifecycle with states: Pre-Activation → Active → Deactivated → Compromised → Destroyed. The codebase implements only the first two states (Pre-Activation as NULL columns, Active when populated) and has no mechanism for any subsequent state. There is no key rotation, no key expiration, no key destruction after election closure, no key revocation/compromise handling, and no documented policy. Key material (election.salt, opened_key, per-voter salts, vote tokens) persists indefinitely in the database with no destruction mechanism. A compromised database backup from any point in time contains all key material needed to decrypt all votes from all elections.

**Remediation:**

1. Create a documented key management policy (CRYPTO_KEY_MANAGEMENT.md) specifying: complete inventory of all cryptographic keys and their purposes, authorized entities for each key type, maximum key lifetime per election state, key destruction procedures post-tallying, and compromise response procedures. 2. Implement key destruction after tally completion: Add archive_and_destroy_keys() method that sets salt=NULL, opened_key=NULL, and mayvote.salt=NULL after tallying is complete and verified. 3. Add key lifecycle tracking columns to schema: keys_created_at INTEGER, keys_destroyed_at INTEGER. 4. Implement key rotation mechanisms for long-lived elections. 5. Add key access audit logging.

---

#### FINDING-017: Absence of Formal Cryptographic Inventory Document

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-1240 |
| ASVS Sections | 11.1.2, 11.1.3, 11.1.4 |
| Files | `v3/steve/crypto.py` (entire file)&lt;br&gt;`v3/steve/election.py` (entire file)&lt;br&gt;`v3/schema.sql` (entire file) |
| Source Reports | 11.1.2.md, 11.1.3.md, 11.1.4.md |
| Related Findings | None |

**Description:**

ASVS 11.1.2 requires a cryptographic inventory that is 'performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application.' No such document exists in the codebase. Cryptographic usage is spread across crypto.py, election.py, and schema.sql with inline comments that serve as the only documentation—and these are demonstrably inconsistent. No algorithm registry exists - algorithms are discoverable only by reading source code. No key boundary documentation showing where keys can/cannot be used. No data protection mapping specifying what data can/cannot be protected. No key lifecycle documentation covering generation, rotation, and destruction policies. The absence of discovery mechanisms has allowed concrete inconsistencies to develop: Argon2d used in production while Argon2id is used in benchmarks, HKDF info parameter labels XChaCha20 while actual cipher is Fernet/AES-128-CBC, and non-constant-time cryptographic comparison in tamper detection.

**Remediation:**

Create and maintain a CRYPTO_INVENTORY.md document at the project root containing: (1) Complete algorithm registry with variants, parameters, approval status, usage locations, and purposes; (2) Keys and their boundaries table documenting derivation, what data can/cannot be protected, and storage locations; (3) Key lifecycle policies covering generation, storage, access, rotation, and destruction; (4) Post-Quantum Cryptography Migration Plan with risk assessment, migration phases, timeline, breaking change management, and trigger conditions; (5) Parameter Justification documenting Argon2 parameters, HKDF parameters, and Fernet configuration; (6) Compliance Mapping to ASVS 11.1.4, NIST SP 800-175B, FIPS 140-2, RFC 9106; (7) Review History establishing quarterly review cadence. Establish quarterly inventory review process with documented sign-off. Integrate inventory verification into CI/CD pipeline. Create automated tooling to detect cryptographic API usage not documented in inventory.

---

#### FINDING-018: Absence of Cryptographic Abstraction Layer Prevents Algorithm Agility

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS Sections | 11.2.2 |
| Files | `v3/steve/crypto.py` (62, 69, 53, 77, 38) |
| Source Reports | 11.2.2.md |
| Related Findings | None |

**Description:**

All cryptographic algorithms are directly instantiated without any abstraction, configuration, or strategy pattern. The application lacks a cryptographic provider layer that would enable algorithm substitution without code changes. All algorithms including Fernet (AES-128-CBC+HMAC), HKDF-SHA256, Argon2, and BLAKE2b are hardcoded directly in crypto.py functions without any mechanism for configuration, versioning, or swapping. This makes it impossible to swap from Fernet to AES-256-GCM or XChaCha20-Poly1305, upgrade Argon2 parameters, or migrate to post-quantum cryptography (PQC) algorithms without complete rewrite and no backward-compatibility path. ASVS 11.2.2 requires the application be designed with crypto agility such that algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time.

**Remediation:**

Introduce a crypto provider abstraction with configuration-driven algorithm selection. Implement a CryptoProvider class with a registry-based algorithm selection mechanism that supports multiple encryption algorithms (Fernet, AES-256-GCM, XChaCha20-Poly1305, future PQC). Create a CryptoConfig dataclass to load algorithm choices from YAML configuration. Implement versioned encryption/decryption that embeds algorithm version in ciphertext and uses appropriate decryptor based on version. Add encryption algorithm registry (ENCRYPTION_REGISTRY) to map algorithm names to encryptor implementations. This enables algorithm substitution without code changes and provides a clear migration path to post-quantum cryptography.

---

#### FINDING-019: No Algorithm Versioning in Stored Cryptographic Data Prevents Migration

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS Sections | 11.2.2 |
| Files | `v3/schema.sql` (157, 54, 137) |
| Source Reports | 11.2.2.md |
| Related Findings | None |

**Description:**

The database schema contains no algorithm version fields to track which cryptographic algorithms were used to produce stored data. The vote, election, and mayvote tables store cryptographic material (ciphertext, vote_token, opened_key, salt) without any metadata indicating which algorithm version produced them. Additionally, CHECK constraints enforce fixed byte lengths (length(vote_token) = 32, length(opened_key) = 32, length(salt) = 16) which prevent algorithms with different output sizes. This makes phased migration impossible and prevents the application from knowing which algorithm to use when decrypting or verifying existing data. During any algorithm migration, there is no way to determine which algorithm produced a given ciphertext, hash, or key, requiring all-or-nothing migration and directly blocking seamless upgrades to post-quantum cryptography.

**Remediation:**

Add algorithm version fields to all tables storing cryptographic material. Add crypto_version INTEGER NOT NULL DEFAULT 1 column to vote table to track encryption algorithm version. Add crypto_version INTEGER column to election and mayvote tables to track key derivation and hashing algorithm versions. Relax fixed-length CHECK constraints to use >= instead of = to accommodate future algorithms with different output sizes (e.g., CHECK (salt IS NULL OR length(salt) >= 16)). Remove exact length requirements on vote_token and opened_key fields. Update application code to write version metadata when performing cryptographic operations and read version metadata to select appropriate algorithm for decryption/verification. This enables phased migration where new data uses new algorithms while existing data continues to use the algorithm that created it.

---

#### FINDING-020: No Application-Level Memory Protection for Sensitive Cryptographic Material

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS Sections | 11.7.1, 11.7.2, 13.3.3 |
| Files | `v3/steve/crypto.py` (60-71, 74-79, 82-87, 40-50)&lt;br&gt;`v3/steve/election.py` (262-320, 247-260)&lt;br&gt;`v3/server/bin/tally.py` (103-145) |
| Source Reports | 11.7.1.md, 11.7.2.md, 13.3.3.md |
| Related Findings | None |

**Description:**

The application handles highly sensitive cryptographic material (encryption keys, plaintext votes, voter tokens) but implements no memory protection mechanisms. Python's immutable bytes and str objects cannot be overwritten, and no memory locking or zeroing is performed. Specific concerns include: (1) Immutable bytes for keys that persist until garbage collected with no guaranteed zeroing, (2) Immutable str for plaintext votes that cannot be zeroed, (3) No mlock() allowing sensitive memory pages to be swapped to disk, and (4) Bulk accumulation during tally where the entire election's decrypted votes exist in memory simultaneously. A memory dump during vote submission or tallying could recover plaintext votes, cryptographic keys, and voter-to-vote mappings. Cryptographic key material (per-voter encryption keys, election opened_key, derived key material) remains in process memory beyond operational need with no cleanup mechanism.

**Remediation:**

Implement secure memory handling: 1. Use mutable bytearray for key material with secure zeroing using ctypes.memset. 2. Implement streaming/incremental tallying where each vote is decrypted, contributed to the tally accumulator, and discarded immediately rather than accumulating all plaintext votes in memory. Modify vtype modules to support incremental input with an accumulator pattern. 3. Wrap cryptographic operations in try/finally blocks to ensure key material is zeroed after use. 4. Deploy with OS-level memory encryption (Intel TME, AMD SME/SEV). 5. Use mlockall(MCL_CURRENT | MCL_FUTURE) to prevent swapping. 6. Disable core dumps for the application process. Consider using ctypes-based wrappers or compiled-language crypto modules for the most sensitive operations to achieve better memory control.

---

#### FINDING-021: State-Changing Election Operations Exposed via GET Method — Trivially Exploitable CSRF

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2, L3 |
| CWE | CWE-352 |
| ASVS Sections | 10.2.1, 2.3.2, 2.3.5, 2.1.2, 2.1.3, 3.3.2, 3.5.3, 8.1.4, 8.3.1, 8.3.2 |
| Files | `v3/server/pages.py` (510-523, 532-545) |
| Source Reports | 10.2.1.md, 2.3.2.md, 2.3.5.md, 2.1.2.md, 2.1.3.md, 3.3.2.md, 3.5.3.md, 8.1.4.md, 8.3.1.md, 8.3.2.md |
| Related Findings | FINDING-022, FINDING-023, FINDING-097, FINDING-192, FINDING-222 |

**Description:**

The most consequential operations in the system — opening and closing elections — are implemented as GET endpoints. This violates HTTP semantics (GET should be safe/idempotent) and makes these irreversible operations trivially triggerable by link clicks, browser prefetching, crawlers, proxy pre-fetching, browser extensions, or embedded resources. Opening an election generates cryptographic salts for all voter/issue pairs and computes the tamper-detection key - this is completely irreversible. Closing an election prevents all further voting. Using GET for these operations means they can be triggered by browser link prefetching, image tags, crawlers, and will appear in browser history, referer headers, and access logs. Combined with the missing owner authorization (AUTHZ-001), an attacker can embed a URL that will irreversibly open or close any election when visited by any authenticated committer. Even without malicious intent, browser prefetching or link previewing tools could accidentally trigger these operations.

**Remediation:**

Change do_open_endpoint() and do_close_endpoint() from @APP.get() to @APP.post(). Implement CSRF token validation by verifying the submitted token matches the user's session token. Require explicit form submission with confirmation rather than allowing simple link navigation to trigger these operations. Update any UI code that links to these endpoints to use POST forms instead of hyperlinks. This follows the pattern already correctly implemented for do_vote_endpoint(), do_create_endpoint(), do_add_issue_endpoint(), do_edit_issue_endpoint(), and do_delete_issue_endpoint(). This prevents accidental triggering via browser prefetching, link previews, or malicious embedded resources.

---

#### FINDING-022: CSRF Token Is a Hardcoded Placeholder — All POST State-Changing Operations Lack CSRF Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-352 |
| ASVS Sections | 10.2.1, 3.5.1 |
| Files | `v3/server/pages.py` (96, 428, 435, 442, 488, 551, 576, 601) |
| Source Reports | 10.2.1.md, 3.5.1.md |
| Related Findings | FINDING-021, FINDING-023, FINDING-097, FINDING-192, FINDING-222 |

**Description:**

The application generates a hardcoded placeholder CSRF token that is never validated server-side, creating a false sense of security. While templates correctly include CSRF tokens in forms and JavaScript correctly sends them in headers, all POST endpoints completely ignore these tokens during request processing. The csrf_token is set to the literal string 'placeholder' in basic_info() and is never checked in any of the state-changing endpoints including do_vote_endpoint(), do_create_endpoint(), do_add_issue_endpoint(), do_edit_issue_endpoint(), do_delete_issue_endpoint(), and _set_election_date().

**Remediation:**

Implement real CSRF token generation using secrets.token_hex(32) stored in the session, and create a validate_csrf_token() function that checks tokens from either form data or the X-CSRFToken header using secrets.compare_digest(). Apply this validation to all state-changing endpoints: /do-vote/&lt;eid&gt;, /do-create-election, /do-add-issue/&lt;eid&gt;, /do-edit-issue/&lt;eid&gt;/&lt;iid&gt;, /do-delete-issue/&lt;eid&gt;/&lt;iid&gt;, /do-set-open_at/&lt;eid&gt;, and /do-set-close_at/&lt;eid&gt;.

---

#### FINDING-023: OAuth Authorization Code Flow Lacks PKCE; State Parameter Validation Delegated to Unauditable Framework

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-352 |
| ASVS Sections | 10.2.1, 10.4.6, 10.1.2 |
| Files | `v3/server/main.py` (38-42, 37-43) |
| Source Reports | 10.2.1.md, 10.4.6.md, 10.1.2.md |
| Related Findings | FINDING-021, FINDING-022, FINDING-097, FINDING-192, FINDING-222 |

**Description:**

The application uses OAuth Authorization Code grant flow but the authorization request (OAUTH_URL_INIT) lacks code_challenge and code_challenge_method parameters, while the token request (OAUTH_URL_CALLBACK) lacks the code_verifier parameter. ASVS 10.1.2 specifically requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier' are used to cryptographically bind the authorization code to the specific transaction. Without PKCE, an attacker who intercepts an authorization code can exchange it at the token endpoint since no proof of the original requestor is required.

**Remediation:**

Add PKCE parameters to OAuth URL templates: include code_challenge and code_challenge_method=S256 in OAUTH_URL_INIT, and code_verifier in OAUTH_URL_CALLBACK. The framework must also: 1) Generate a cryptographically random code_verifier (>= 43 chars); 2) Derive code_challenge = BASE64URL(SHA256(code_verifier)); 3) Store code_verifier in server-side session before redirect; 4) Send code_verifier with the token exchange request.

---

#### FINDING-024: OAuth Scope Neither Requested Nor Enforced in Authorization Decisions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-862 |
| ASVS Sections | 10.3.2, 10.2.3, 10.4.11 |
| Files | `v3/server/main.py` (37-41, 38-42, 38-43) |
| Source Reports | 10.3.2.md, 10.2.3.md, 10.4.11.md |
| Related Findings | FINDING-002, FINDING-003, FINDING-073, FINDING-088, FINDING-103, FINDING-104, FINDING-105 |

**Description:**

The OAuth authorization URL contains no 'scope' parameter. The application has two distinct privilege levels (voter vs. election manager) that map naturally to OAuth scopes, but all authorization is done through a single flat role check (R.committer). The application does not request scopes in the OAuth authorization URL, does not validate scopes at any endpoint, and has no scope differentiation between voting operations and election management operations.

**Remediation:**

Request appropriate scopes in the OAuth authorization URL (e.g., 'openid profile email steve:vote steve:manage'). Enforce scope-based authorization at endpoints by validating that the token contains required scopes before processing operations. Create a require_scope() function that checks token_scopes from the session and aborts with 403 if required scope is missing.

---

#### FINDING-025: No Sender-Constrained Access Token Implementation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-294 |
| ASVS Sections | 10.3.5, 10.4.14 |
| Files | `v3/server/main.py` (37-41)&lt;br&gt;`v3/server/pages.py` (multiple - all 21 protected endpoints) |
| Source Reports | 10.3.5.md, 10.4.14.md |
| Related Findings | None |

**Description:**

The application implements OAuth 2.0 authentication through Apache's OAuth infrastructure but provides no mechanism to bind access tokens to the presenting client. Neither Mutual TLS (RFC 8705) nor Demonstration of Proof-of-Possession (DPoP, RFC 9449) is implemented. This allows stolen access tokens or session tokens to be replayed from any network location by any attacker who obtains them. An attacker who intercepts or exfiltrates a valid session token can replay it from any client without cryptographic proof of being the legitimate token holder.

**Remediation:**

Implement DPoP (RFC 9449) as the primary sender-constraining mechanism: 1) Coordinate with asfquart framework maintainers to add DPoP support for OAuth token exchange; 2) Implement DPoP proof validation middleware for all resource server endpoints; 3) Configure token introspection to verify 'cnf' claims when validating access tokens; 4) Validate DPoP proof JWT including htm, htu, iat, ath claims; 5) Verify JWK thumbprint matches token's cnf.jkt claim. Alternatively, implement Mutual TLS (RFC 8705) with client certificate validation.

---

#### FINDING-026: No ID Token Handling - Custom OAuth Bypasses OIDC

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-287 |
| ASVS Sections | 10.5.2, 10.5.1, 10.5.4 |
| Files | `v3/server/main.py` (38-43, 36-43, 35-48) |
| Source Reports | 10.5.2.md, 10.5.1.md, 10.5.4.md |
| Related Findings | FINDING-098, FINDING-100, FINDING-229, FINDING-235 |

**Description:**

The application explicitly configures custom OAuth endpoints and comments '# Avoid OIDC'. This means no ID Token is issued or consumed, and the 'sub' claim (which OIDC guarantees to be a locally unique, never-reassigned identifier) is not used. Without OIDC ID Token processing, critical validations are absent: cryptographic signature verification of identity assertions, 'iss' (issuer) validation, 'aud' (audience) validation ensuring the token was intended for this client, 'exp'/'iat' temporal validity checks on the identity assertion, and 'nonce' validation for replay protection.

**Remediation:**

Migrate from the custom OAuth flow to standard OIDC, consuming and validating the ID Token. Configure OIDC with proper ID Token validation using OIDC discovery endpoint for automatic key/endpoint configuration. Use 'sub' claim as the unique, non-reassignable user identifier. Verify issuer matches expected OP and verify audience includes this client. Validate 'nonce' claim to prevent replay attacks.

---

#### FINDING-027: OAuth Client Authentication Lacks Public-Key-Based Methods (mTLS / private_key_jwt)

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-306 |
| ASVS Sections | 10.4.16, 10.4.10 |
| Files | `v3/server/main.py` (38-43, 38-41) |
| Source Reports | 10.4.16.md, 10.4.10.md |
| Related Findings | FINDING-083, FINDING-108 |

**Description:**

ASVS 10.4.16 requires that the OAuth client uses strong, public-key-based client authentication methods (mutual TLS or 'private_key_jwt') that are resistant to replay attacks. The application shows no evidence of configuring or using any public-key-based client authentication method for the token endpoint exchange. The token endpoint URL template only formats the authorization code with no client certificate (mTLS) configuration, no client_assertion/client_assertion_type (private_key_jwt), and no configuration for token_endpoint_auth_method.

**Remediation:**

Configure the OAuth client to use either Mutual TLS (tls_client_auth) with client certificate and key, or Private Key JWT (private_key_jwt) with signed JWT containing iss, sub, aud, iat, exp, and jti claims. Include client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer in token request. Use short-lived tokens with unique JTI to prevent replay attacks.

---

#### FINDING-028: Authorization Code Grant Without Pushed Authorization Requests (PAR)

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-639 |
| ASVS Sections | 10.4.13, 10.4.15 |
| Files | `v3/server/main.py` (37-42, 38-42) |
| Source Reports | 10.4.13.md, 10.4.15.md |
| Related Findings | FINDING-015, FINDING-251 |

**Description:**

The application uses the OAuth authorization code grant type but constructs authorization requests using the traditional approach of passing parameters directly in URL query strings. This violates ASVS 10.4.13 Level 3 requirement that the authorization code grant type must always be used together with Pushed Authorization Requests (PAR). The current implementation bypasses this security mechanism entirely, exposing authorization parameters through browser history, server logs, and referrer headers without server-side pre-validation.

**Remediation:**

Implement PAR flow: 1) Verify AS PAR Support; 2) Update Framework to add OAUTH_PAR_ENDPOINT configuration; 3) POST authorization parameters to PAR endpoint server-to-server, receive request_uri from AS, then redirect user with only client_id and request_uri; 4) Enforce PAR at AS by setting require_pushed_authorization_requests: true; 5) Implement PKCE alongside PAR for defense-in-depth.

---

#### FINDING-029: TOCTOU Race Condition Allows Vote Insertion After Election Closure

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-367 |
| ASVS Sections | 2.3.4, 15.4.1, 15.4.2, 15.4.3 |
| Files | `v3/steve/election.py` (258-269, 113-119)&lt;br&gt;`v3/server/pages.py` (403-446) |
| Source Reports | 2.3.4.md, 15.4.1.md, 15.4.2.md, 15.4.3.md |
| Related Findings | FINDING-054 |

**Description:**

The vote submission process performs eligibility verification and vote insertion as separate database operations without transactional protection. This creates a TOCTOU vulnerability where an election can be closed between the eligibility check and the vote insertion, allowing votes to be recorded after the official closure. The _all_metadata(S_OPEN) check and q_get_mayvote.first_row() eligibility check are separate queries from the c_add_vote.perform() insertion, creating a race window. During tally, post-closure votes with the highest vid will be treated as the voter's most recent vote, overriding legitimate votes cast before closure. In Quart's async model, await quart.request.form in do_vote_endpoint yields control, allowing the close request to be processed before the vote insertion completes.

**Remediation:**

Wrap the entire add_vote() operation in a BEGIN IMMEDIATE transaction. Perform the election state check via _all_metadata(S_OPEN) within the transaction with a read lock, verify voter eligibility via q_get_mayvote.first_row() within the same transaction, then insert the vote via c_add_vote.perform() within the same transaction before COMMIT. Use BEGIN IMMEDIATE to acquire a reserved lock, preventing concurrent writes (like election close) from completing until this transaction finishes. Include proper exception handling with ROLLBACK on failure.

---

#### FINDING-030: Election Opening Operation Lacks Atomic Transaction Control and Enables Concurrent State Corruption

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-362 |
| ASVS Sections | 2.3.3, 2.3.4, 15.4.1, 15.4.2, 15.4.3 |
| Files | `v3/steve/election.py` (74-89, 126-140, 73-84, 121-139) |
| Source Reports | 2.3.3.md, 2.3.4.md, 15.4.1.md, 15.4.2.md, 15.4.3.md |
| Related Findings | FINDING-053, FINDING-171 |

**Description:**

The election opening operation is a critical state transition that involves multiple database modifications across two separate committed transactions. The `open()` method first calls `add_salts()`, which commits its own transaction containing per-voter salt generation, then separately executes cryptographic operations and commits the election state change. This split-transaction approach creates multiple problems: (1) If steps after `add_salts()` fail, the database retains committed salts while the election remains in 'editable' state, creating an inconsistent state. (2) Concurrent `open()` calls can interleave, causing cryptographic material to be overwritten. If the race window is exploited, the election's cryptographic material can be overwritten after voters have already begun casting votes. Votes encrypted with the first set of keys become permanently undecryptable, effectively destroying cast ballots. The `is_tampered()` check would also produce unpredictable results.

**Remediation:**

Wrap the entire open operation in a single BEGIN IMMEDIATE transaction to acquire a reserved lock immediately. Move the state check inside the transaction using _all_metadata(S_EDITABLE), perform all salt generation and key derivation within the transaction, and use an atomic WHERE clause in the UPDATE statement (WHERE eid=? AND salt IS NULL AND opened_key IS NULL) to ensure only one request can transition the state. Verify rowcount == 1 after the UPDATE to confirm the state transition succeeded. Remove the inner transaction from add_salts() and create a private _add_salts_inner() method. Include proper exception handling with ROLLBACK on failure.

---

#### FINDING-031: No Multi-User Approval for Irreversible Election State Transitions

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS Sections | 2.3.5 |
| Files | `v3/server/pages.py` (479-515)&lt;br&gt;`v3/steve/election.py` (70-120) |
| Source Reports | 2.3.5.md |
| Related Findings | None |

**Description:**

Opening and closing elections are the highest-value operations in this system. Opening an election is explicitly irreversible (generates cryptographic salt and opened_key, sets per-voter salts), and closing permanently terminates voting. Neither operation requires approval from a second authorized user. A single user (or an attacker who compromises a single committer account) can unilaterally open an election prematurely, close an election early (disenfranchising voters), or trigger tallying. The state machine prevents invalid transitions but does not address who should be authorized to trigger valid transitions. This violates ASVS 2.3.5's requirement for multi-user approval of high-value business logic flows.

**Remediation:**

Implement a two-phase approval workflow: (1) Add an approval_request table to track pending approval requests with fields for action type, requester, approver, timestamp, and status. (2) Create separate endpoints for requesting operations (do-request-open, do-request-close) and approving them (do-approve-open, do-approve-close). (3) Enforce that the approver must be a different authorized user than the requester. (4) Only execute the irreversible operation (election.open() or election.close()) after a second authorized user has approved the request. Apply this pattern to open, close, and delete operations.

---

#### FINDING-032: HTML Injection via rewrite_description() Constructing HTML from Unencoded User Input

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-79 |
| ASVS Sections | 1.1.1, 1.1.2, 1.2.1, 1.2.2, 1.2.9, 1.3.1, 1.3.5, 1.3.9, 3.2.2 |
| Files | `v3/server/pages.py` (46-54)&lt;br&gt;`v3/server/templates/vote-on.ezt` (108) |
| Source Reports | 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.2.2.md, 1.2.9.md, 1.3.1.md, 1.3.5.md, 1.3.9.md, 3.2.2.md |
| Related Findings | FINDING-006, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-193, FINDING-194 |

**Description:**

The rewrite_description() function in pages.py constructs HTML by wrapping user-controlled issue descriptions in &lt;pre&gt; tags and converting doc:filename patterns into &lt;a&gt; links. The user-controlled description content and the regex-captured filename are inserted into HTML markup without any HTML encoding. This violates the principle that encoding should occur before further processing—here, HTML construction (processing) occurs on raw input without prior encoding of user-controlled parts. The resulting HTML string is then rendered in templates without encoding, creating stored XSS affecting all voters viewing the election ballot page.

**Remediation:**

Encode user content FIRST (before HTML construction): import html; from urllib.parse import quote; def rewrite_description(issue): desc = html.escape(issue.description or ''); def repl(match): filename = match.group(1); return f'&lt;a href="/docs/{html.escape(issue.iid)}/{quote(filename)}"&gt;{html.escape(filename)}&lt;/a&gt;'; desc = re.sub(r'doc:([^\s]+)', repl, desc); issue.description = f'&lt;pre&gt;{desc}&lt;/pre&gt;'

---

#### FINDING-033: JavaScript Injection via Unescaped Server Data in STV_CANDIDATES Object

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-79 |
| ASVS Sections | 1.1.1, 1.1.2, 1.2.1, 1.2.3, 1.3.5, 1.3.7, 1.3.10 |
| Files | `v3/server/templates/vote-on.ezt` (script block - STV_CANDIDATES object definition)&lt;br&gt;`v3/server/pages.py` (~158) |
| Source Reports | 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.2.3.md, 1.3.5.md, 1.3.7.md, 1.3.10.md |
| Related Findings | FINDING-006, FINDING-032, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-193, FINDING-194 |

**Description:**

STV candidate names, labels, and issue titles from the database are embedded directly into JavaScript string literals within a &lt;script&gt; block using bare [issues.title], [issues.candidates.name], and [issues.candidates.label] without [format "js"] or [format "js,html"]. If a candidate name contains a double quote ("), backslash, or &lt;/script&gt;, it will break out of the JavaScript string or script block. The [format "js,html"] control exists and is used in the management templates for identical scenarios (user text in JS strings), but it is not applied in vote-on.ezt.

**Remediation:**

Apply [format "js"] or [format "js,html"] to all candidate data and issue titles embedded in JavaScript: const STV_CANDIDATES = { [for issues][is issues.vtype "stv"] "[format "js"][issues.iid][end]": { seats: [issues.seats], title: "[format "js"][issues.title][end]", candidates: [ [for issues.candidates] { label: "[format "js"][issues.candidates.label][end]", name: "[format "js"][issues.candidates.name][end]" }, [end] ] }, [end][end] };

---

#### FINDING-034: Reflected XSS via URL Path Parameters in Error Templates

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-79 |
| ASVS Sections | 1.1.1, 1.2.1, 1.3.5, 1.3.7, 1.3.10 |
| Files | `v3/server/templates/e_bad_eid.ezt` (8)&lt;br&gt;`v3/server/templates/e_bad_iid.ezt` (8)&lt;br&gt;`v3/server/templates/e_bad_pid.ezt` (8)&lt;br&gt;`v3/server/pages.py` (174-225) |
| Source Reports | 1.1.1.md, 1.2.1.md, 1.3.5.md, 1.3.7.md, 1.3.10.md |
| Related Findings | FINDING-006, FINDING-032, FINDING-033, FINDING-035, FINDING-064, FINDING-065, FINDING-193, FINDING-194 |

**Description:**

Error page templates (e_bad_eid.ezt, e_bad_iid.ezt, e_bad_pid.ezt) render URL path parameters (election ID, issue ID, person ID) directly into HTML without encoding. When an invalid ID is accessed, the application displays an error message that includes the user-supplied ID value without sanitization. An attacker can craft a malicious URL containing JavaScript that executes when the error page is rendered. The load_election(), load_election_issue(), and admin_page() decorators set result.eid, result.iid, and result.pid from URL parameters without encoding.

**Remediation:**

Apply HTML encoding to URL parameters in error templates: The Election ID ([format "html"][eid][end]) does not exist. The Issue ID ([format "html"][iid][end]) does not exist. The Person ID ([format "html"][pid][end]) does not exist. Additionally, implement input validation to enforce alphanumeric-only constraint on these parameters as defense-in-depth.

---

#### FINDING-035: Stored XSS via Flash Messages Containing Unencoded User Input

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-79 |
| ASVS Sections | 1.1.1, 1.1.2, 1.2.1, 1.3.10, 1.3.7, 3.2.2 |
| Files | `v3/server/pages.py` (504, 535, 598)&lt;br&gt;`v3/server/templates/flashes.ezt` (3) |
| Source Reports | 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.3.10.md, 1.3.7.md, 3.2.2.md |
| Related Findings | FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-064, FINDING-065, FINDING-193, FINDING-194 |

**Description:**

Flash messages constructed using f-string interpolation with user-provided input (form.title, iid from form keys) are stored in the session and rendered without HTML escaping. Multiple endpoints create flash messages that directly embed unsanitized user input: do_create_endpoint (line 459), do_add_issue_endpoint (line 521), do_edit_issue_endpoint (line 543), and do_vote_endpoint (lines 427, 435). The iid-based vector is particularly concerning as it comes from user-controllable form key names (vote-&lt;payload&gt;), allowing direct injection into flash messages.

**Remediation:**

Template-side fix: [for flashes] &lt;div class="alert alert-[flashes.category] alert-dismissible fade show" role="alert"&gt; [format "html"][flashes.message][end] &lt;button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"&gt;&lt;/button&gt; &lt;/div&gt; [end]. Python-side defense-in-depth: import html; await flash_danger(f'Invalid issue ID: {html.escape(iid)}'); await flash_success(f'Created election: {html.escape(form.title)}');

---

#### FINDING-036: Complete Absence of Cipher Suite Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | N/A |
| ASVS Sections | 12.1.2 |
| Files | `v3/server/main.py` (79-84) |
| Source Reports | 12.1.2.md |
| Related Findings | None |

**Description:**

The server passes raw certificate/key file paths to the underlying Quart/Hypercorn runtime without creating an ssl.SSLContext. This results in: (1) No cipher suite restriction - all system-default ciphers are enabled, including potentially weak ones (RC4, 3DES, NULL, EXPORT, CBC-mode ciphers vulnerable to BEAST/Lucky13); (2) No cipher preference order - server does not enforce strongest-first ordering (ssl.OP_CIPHER_SERVER_PREFERENCE is not set); (3) No forward secrecy enforcement - non-ECDHE/DHE cipher suites remain available. Weak cipher suites allow passive decryption by an attacker who compromises the server's private key (no forward secrecy). Certain legacy ciphers have known cryptographic weaknesses exploitable by active or passive attackers. Fails ASVS 12.1.2 L2 (recommended ciphers only) and L3 (forward secrecy requirement).

**Remediation:**

Create a properly configured ssl.SSLContext with: (1) ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); (2) ctx.minimum_version = ssl.TLSVersion.TLSv1_2; (3) ctx.maximum_version = ssl.TLSVersion.TLSv1_3; (4) ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'); (5) ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE; (6) ctx.options |= ssl.OP_NO_COMPRESSION; (7) ctx.load_cert_chain(certfile=..., keyfile=...); (8) Pass ctx via kwargs['ssl'] to app.runx().

---

#### FINDING-037: Missing OCSP Stapling Configuration in Server TLS Setup

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS Sections | 12.1.4 |
| Files | `v3/server/main.py` (93-100) |
| Source Reports | 12.1.4.md |
| Related Findings | None |

**Description:**

The TLS setup passes only certfile and keyfile paths directly to app.runx() without creating a custom ssl.SSLContext. This means: (1) No OCSP Stapling callback is registered, so the server cannot provide stapled OCSP responses to connecting clients. Clients must independently query the CA's OCSP responder, which introduces latency and privacy leakage, or many clients will skip revocation checking entirely. (2) No control over revocation behavior — if the application's own certificate is revoked by the CA, clients relying on default behavior may not detect this. (3) No SSL context parameters are set — protocol version minimums, cipher suites, and certificate verification modes all rely on framework defaults which are not auditable from this code.

**Remediation:**

Create an explicit ssl.SSLContext with OCSP Stapling support and pass it to the server. Example implementation: Create _create_ssl_context() function that creates ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), sets minimum_version to TLSv1_2, loads cert chain, sets OCSP server callback, and configures strong ciphers. For production deployments, OCSP Stapling is most effectively handled by a reverse proxy (e.g., Nginx with ssl_stapling on; ssl_stapling_verify on;). This should be documented as a deployment requirement.

---

#### FINDING-038: Encrypted Client Hello (ECH) Not Implemented

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS Sections | 12.1.5 |
| Files | `v3/server/main.py` (82-88)&lt;br&gt;`v3/server/config.yaml.example` (28-31) |
| Source Reports | 12.1.5.md |
| Related Findings | None |

**Description:**

The TLS setup passes raw file paths for certificate and key to app.runx(). There is: 1) No ECH key pair generated or referenced in certs/ directory or configuration, 2) No ech_config or equivalent parameter in TLS settings, 3) No ssl.SSLContext created where ECH could be enabled, 4) No DNS HTTPS record guidance or ECHConfig publication mechanism, 5) No ECH retry configuration for client compatibility. Without ECH, the Server Name Indication (SNI) field is transmitted in plaintext during the TLS ClientHello, allowing network observers to identify which specific server/election the client is connecting to. For a voting system, this metadata leakage can reveal voter participation patterns.

**Remediation:**

ECH requires server-side support in the TLS library and DNS publication. Add ECH configuration to config.yaml (ech_keyfile, ech_config_list). Create SSL context with ECH support in main.py using ssl.SSLContext with TLS 1.3 minimum version and ECH key configuration. Recommended immediate approach: Deploy behind a TLS-terminating reverse proxy (e.g., Cloudflare or nginx compiled with OpenSSL 3.2+) that supports ECH, and publish ECHConfig via DNS HTTPS resource records.

---

#### FINDING-039: No Concurrency Limits on Memory-Intensive Argon2 Operations Enabling Resource Exhaustion

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | N/A |
| ASVS Sections | 13.1.2 |
| Files | `v3/steve/crypto.py` (88-98)&lt;br&gt;`v3/steve/election.py` (230-243, 266) |
| Source Reports | 13.1.2.md |
| Related Findings | None |

**Description:**

Each vote submission (`add_vote`) triggers Argon2 hashing with `memory_cost=65536` (64 MiB) per invocation. There are no documented or implemented limits on concurrent cryptographic operations. An authenticated attacker can submit concurrent vote requests, each consuming 64 MiB of memory with no cap, leading to memory exhaustion and denial of service. With 20 concurrent vote submissions, the application allocates 20 × 64 MiB = 1.28 GiB of memory simultaneously for Argon2 alone. The `tally_issue` method is worse—it calls `gen_vote_token` once per eligible voter in a loop (line 266), meaning tallying an election with 1,000 voters allocates 64 GiB sequentially (or concurrently if multiple tallies run). No documentation defines these resource requirements or maximum concurrent operation limits.

**Remediation:**

1. Document the resource profile of cryptographic operations in config.yaml or operations documentation, specifying argon2_memory_mb (64), max_concurrent_hash_ops (4), and behavior when limit reached (queue requests, return 429 after 10s timeout). 2. Implement a semaphore to bound concurrent Argon2 operations using asyncio.Semaphore(4) to limit maximum concurrent operations to 4 (256 MiB max). 3. Wrap synchronous _hash calls with asyncio.to_thread() to prevent event loop blocking.

---

#### FINDING-040: Absence of Critical Secrets Inventory Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-1059 |
| ASVS Sections | 13.1.4 |
| Files | `v3/server/config.yaml.example` (entire file)&lt;br&gt;`v3/steve/crypto.py` (13-19, 68-77)&lt;br&gt;`v3/steve/election.py` (91-92, 143-151, 282-295)&lt;br&gt;`v3/server/main.py` (38-42) |
| Source Reports | 13.1.4.md |
| Related Findings | FINDING-130, FINDING-249 |

**Description:**

The application employs at least 8 distinct categories of cryptographic secrets that are critical to election integrity, vote confidentiality, and voter anonymity. No documentation exists—either within the configuration template, inline code documentation, or a standalone security document—that enumerates these secrets, describes their purpose, classifies their sensitivity level, or specifies access control requirements.

**Remediation:**

Create SECURITY.md in repository root documenting all 8 secret categories: TLS Private Key, TLS Certificate, OAuth Client Secret, Database File, Election Salt, Opened Key, Per-Voter Salt, Vote Tokens, and Fernet Encryption Keys. Include storage location, access requirements, criticality level, and purpose for each. Update config.yaml.example with inline security guidance and warnings. Ensure .gitignore prevents accidental secret commits.

---

#### FINDING-041: No Secrets Management Solution for Backend Cryptographic Material

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | N/A |
| ASVS Sections | 13.3.1, 13.3.3 |
| Files | `v3/steve/election.py` (75-88, 258-274)&lt;br&gt;`v3/server/main.py` (77-78)&lt;br&gt;`v3/server/config.yaml.example` (28-29) |
| Source Reports | 13.3.1.md, 13.3.3.md |
| Related Findings | None |

**Description:**

ASVS 13.3.1 (L2) requires a secrets management solution (e.g., key vault) to securely create, store, control access to, and destroy backend secrets. The application has no integration with any secrets management system. All cryptographic key material is stored directly in SQLite or referenced by plain file paths. Affected secrets include: opened_key (election master key) stored as raw bytes in SQLite metadata table, per-voter salts stored as raw bytes in SQLite mayvote table, TLS private key referenced by file path in config.yaml, and OAuth integration secrets presumably in config.yaml or env vars. Any compromise of the SQLite database file exposes all cryptographic material needed to decrypt every vote in every election. No access controls, audit trail, or monitoring exist around secret retrieval.

**Remediation:**

Integrate a secrets management solution to protect at minimum the election master key. Use a vault to wrap/unwrap the opened_key (example provided using HashiCorp Vault transit engine). Implement SecretManager class with wrap_key() and unwrap_key() methods. Store wrapped keys in database instead of raw bytes. For TLS keys and OAuth secrets, source them from vault rather than filesystem/config by referencing vault paths in config.yaml instead of file paths.

---

#### FINDING-042: No Secret Destruction or Lifecycle Management for Election Key Material

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | N/A |
| ASVS Sections | 13.3.1 |
| Files | `v3/steve/election.py` (119-125, 52-73) |
| Source Reports | 13.3.1.md |
| Related Findings | None |

**Description:**

Once an election's opened_key is generated and stored in the database, it persists indefinitely. There is no mechanism to destroy, expire, or rotate the cryptographic key material after tallying is complete. ASVS 13.3.1 explicitly requires the ability to destroy backend secrets. The close operation only flips a flag while opened_key and all salts remain in database. The delete method only works for editable (never-opened) elections. After tallying is complete and results are finalized, the full cryptographic chain (opened_key → vote_token → Fernet key → plaintext vote) remains reconstructable from the database. An attacker who gains database access months or years later can still decrypt all votes. This violates the principle of data minimization and the ASVS requirement for secret destruction capability.

**Remediation:**

Add a post-tally key destruction step with a destroy_key_material() method that: asserts election is closed, begins a transaction, destroys the election master key, destroys per-voter salts, destroys vote tokens and ciphertexts, commits the transaction, forces SQLite to reclaim space with VACUUM to overwrite deleted pages, and logs the key material destruction event.

---

#### FINDING-043: Complete Absence of Cache-Control Headers on All Sensitive Endpoints

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1, L2, L3 |
| CWE | CWE-525 |
| ASVS Sections | 14.1.1, 14.1.2, 14.2.2, 14.2.4, 14.2.5, 14.3.2 |
| Files | `v3/server/pages.py` (60, 119, 137, 151, 156, 220, 223, 226, 238, 240, 283, 285, 286, 299, 300, 302, 320, 322, 328, 333, 343, 348, 353, 365, 380, 530, 537, 540, 545)&lt;br&gt;`v3/server/templates/header.ezt` (null)&lt;br&gt;`v3/server/templates/vote-on.ezt` (null) |
| Source Reports | 14.1.1.md, 14.1.2.md, 14.2.2.md, 14.2.4.md, 14.2.5.md, 14.3.2.md |
| Related Findings | None |

**Description:**

Every authenticated endpoint serving sensitive data returns responses without Cache-Control, Pragma, or Expires headers. Per HTTP/1.1 (RFC 7234), responses without explicit cache directives are cacheable by intermediaries. Any load balancer, CDN, or reverse proxy fronting this application may cache and serve authenticated pages to unauthorized users. Affected endpoints include voter eligibility pages, ballot content, voting interface pages, election management interfaces, administration pages, and user profile data. This enables proxy cache poisoning where one voter's personalized ballot page could be served to another user, ballot exposure revealing voter-election correlations, persistent data exposure after logout, and CSRF token leakage. Without cache-control headers, browsers cache pages containing sensitive voter information on shared computers. This is a systemic gap with no control mechanism existing anywhere in the codebase.

**Remediation:**

Add an after-request handler to set Cache-Control: no-store, no-cache, must-revalidate, max-age=0 on all authenticated responses. For authenticated/dynamic pages, also set Pragma: no-cache and Expires: 0 headers. Add Vary: Cookie header to all authenticated responses to prevent shared caches from serving authenticated content across users. Additionally, add cache meta tags to header.ezt template for defense-in-depth. Alternatively, create a decorator for sensitive routes to apply cache headers granularly.

---

#### FINDING-044: State-Changing Election Operations Use GET Method, Exposing Sensitive Operations in Logs and URLs

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-598 |
| ASVS Sections | 14.1.1, 14.1.2, 14.2.4, 14.2.5, 4.1.4 |
| Files | `v3/server/pages.py` (435, 439, 453, 457, 459, 460, 477, 481)&lt;br&gt;`v3/server/templates/manage.ezt` (266, 274, 289) |
| Source Reports | 14.1.1.md, 14.1.2.md, 14.2.4.md, 14.2.5.md, 4.1.4.md |
| Related Findings | None |

**Description:**

Critical state-changing operations (opening and closing elections) are implemented as GET requests rather than POST. This causes election IDs and management operations to be logged in web server access logs, recorded in browser history, and potentially leaked via Referrer headers. The `/do-open/<eid>` and `/do-close/<eid>` endpoints trigger irreversible cryptographic operations and state transitions via GET requests. Election IDs are designed to be unpredictable (10-character hex) to prevent enumeration attacks, but using GET for state-changing operations undermines this protection. GET responses are aggressively cached by default in HTTP caching semantics, and combined with the complete absence of cache-control headers, these state-changing responses could be cached by intermediary proxies. URLs could be prefetched by browsers, crawlers, or proxy prefetching. Election closing is irreversible per the application design, and accidental execution via cache/prefetch causes permanent damage.

**Remediation:**

Change both endpoints from `@APP.get()` to `@APP.post()` and update any frontend links to use form submissions or JavaScript POST requests. Update the templates that link to these endpoints to use forms with POST method. Example: ```python
@APP.post('/do-open/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_open_endpoint(election):
    result = await basic_info()
    # ... (rest unchanged)

@APP.post('/do-close/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_close_endpoint(election):
    result = await basic_info()
    # ... (rest unchanged)
```
Update templates: ```html
<form method="POST" action="/do-open/{{ eid }}">
    <!-- Include CSRF token when implemented -->
    <button type="submit" class="btn btn-primary">Open Election</button>
</form>
```

---

#### FINDING-045: Potential Sensitive Data Leakage Through Exception Logging During Vote Processing

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-532 |
| ASVS Sections | 14.1.2 |
| Files | `v3/server/pages.py` (425)&lt;br&gt;`v3/steve/election.py` (207) |
| Source Reports | 14.1.2.md |
| Related Findings | FINDING-144 |

**Description:**

Exception messages during vote processing are logged without sanitization in the `do_vote_endpoint` function. The error logging statement includes the full exception message `{e}`, which may contain plaintext vote content, cryptographic tokens, or per-voter salts if exceptions are raised during `election.add_vote()`, `crypto.create_vote()`, or `crypto.gen_vote_token()`. This violates documented requirements for controlling how sensitive data is logged.

**Remediation:**

Remove exception details from logging statements. Replace `_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {e}')` with `_LOGGER.error(f'Vote submission failed: election[E:{election.eid}] issue[I:{iid}]')` to log only non-sensitive metadata. Never include exception messages that may contain vote content, tokens, or salts.

#### FINDING-046: Authorization-Protected Documents Served Without Cache Prevention

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-434 |
| **ASVS Sections** | 14.2.2, 14.2.5 |
| **Files** | `v3/server/pages.py:555-565`, `v3/server/pages.py:557`, `v3/server/pages.py:572` |
| **Source Reports** | 14.2.2.md, 14.2.5.md |
| **Related Findings** | - |

**Description:**

The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serves election documents after verifying voter eligibility via the mayvote table. However, quart.send_from_directory() uses framework defaults which typically set Cache-Control: public or include max-age based on SEND_FILE_MAX_AGE_DEFAULT config. This actively encourages intermediate caches to store authorization-protected documents. When a response is served from an intermediate cache, the authorization check is bypassed, allowing non-eligible users to access cached documents containing ballot details, candidate information, or voting instructions. The endpoint also lacks cache-control headers and content-type enforcement. Election documents containing ballot details, candidate information, or procedural details are cacheable after authorized access. Missing content-type enforcement means the cache could store documents with incorrect MIME types, enabling content-type confusion attacks.

**Remediation:**

Override cache headers on the response returned by send_from_directory: set Cache-Control: no-store, no-cache, must-revalidate, private, Pragma: no-cache, and Expires: 0 headers. Implement docname validation with allowlist of characters using regex pattern ^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+$. Add content-type allowlist for served documents (e.g., .pdf, .txt, .html, .md) and check file extension before serving. Set X-Content-Type-Options: nosniff header. Return 404 for invalid docnames or disallowed content types. Additionally, audit Quart's SEND_FILE_MAX_AGE_DEFAULT configuration.

---

#### FINDING-047: No Data Retention Classification for Any Sensitive Data Category

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 14.2.7 |
| **Files** | `v3/schema.sql`, `v3/steve/election.py:64-78`, `v3/steve/election.py:80-90`, `v3/steve/election.py:180-200`, `v3/steve/persondb.py:51-64`, `v3/server/pages.py` |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | - |

**Description:**

The system handles multiple categories of sensitive data (encrypted votes, voter PII, per-voter cryptographic salts, election keys, voter-to-issue mappings) but no data retention classification exists. There are no retention period definitions, no expiration timestamps in the schema, and no administrative interfaces or scheduled processes for data lifecycle management. Sensitive data enters, is stored, and remains indefinitely with no exit path. Over time, the system accumulates an ever-growing corpus of sensitive data including voter PII and cryptographic material, expanding the attack surface and the impact of any database compromise.

**Remediation:**

1. Define a data retention classification document mapping each data type to a retention period: Encrypted votes (Audit-critical, 2 years post-close), Election keys (Delete after final tally verified), Per-voter salts (Delete after final tally verified), Person PII (Delete when no active elections reference them), Superseded votes (Immediate deletion upon re-vote). 2. Add schema support: ALTER TABLE election ADD COLUMN tallied_at INTEGER; ALTER TABLE vote ADD COLUMN created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')). 3. Implement a periodic cleanup process or CLI command.

---

#### FINDING-048: Election Cryptographic Key Material Persisted Indefinitely After Use

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 14.2.7 |
| **Files** | `v3/schema.sql`, `v3/steve/election.py:50-60`, `v3/steve/election.py:64-78`, `v3/steve/election.py:80-90`, `v3/steve/election.py:217-255` |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | - |

**Description:**

When an election is opened, a 16-byte salt and 32-byte opened_key are stored in the election table. After an election is closed and tallied, these cryptographic values remain in the database forever. There is no mechanism to purge them after they are no longer needed. The combination of election.opened_key + election.salt + per-voter mayvote.salt values enables decryption of all votes in an election. After tallying is complete, these keys serve no operational purpose, but their continued presence means that a future database compromise would allow retroactive decryption of votes from all past elections, violating the system's ballot secrecy goal.

**Remediation:**

Implement a purge_keys() method that nulls out cryptographic material after tallying is verified: def purge_keys(self): assert self.is_closed(); self.db.conn.execute('BEGIN TRANSACTION'); self.c_purge_election_keys.perform(self.eid); self.c_purge_mayvote_salts.perform(self.eid); self.db.conn.execute('COMMIT'). Add queries: c_purge_election_keys: UPDATE election SET salt = NULL, opened_key = NULL WHERE eid = ? AND closed = 1; c_purge_mayvote_salts: UPDATE mayvote SET salt = NULL WHERE iid IN (SELECT iid FROM issue WHERE eid = ?)

---

#### FINDING-049: Absence of Formal Sensitive Data Classification and Protection Levels

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 14.1.1 |
| **Files** | `v3/steve/election.py:146-157`, `v3/steve/election.py:163`, `v3/steve/persondb.py:38`, `v3/server/pages.py:57`, `v3/server/pages.py:603`, `v3/schema.sql` |
| **Source Reports** | 14.1.1.md |
| **Related Findings** | - |

**Description:**

The system processes at least six distinct categories of sensitive data (election cryptographic salt/opened_key, per-voter salts, vote content, vote tokens, voter PII, and election metadata), each requiring different protection levels, but none are formally classified. Ad-hoc protections exist (salt exclusion in specific functions, vote encryption) but there is no systematic framework to ensure consistent handling across all code paths. Without formal classification, there is no systematic way to verify that all sensitive data types are consistently protected across all code paths. Current protections are convention-based, comment-driven, and function-specific with no defense-in-depth at architectural boundaries.

**Remediation:**

Step 1: Create formal data classification document defining CRITICAL, SENSITIVE, INTERNAL, and PUBLIC tiers with specific handling rules for each classification level. Step 2: Add defense-in-depth filtering at template boundary using sanitize_for_template() function to remove CRITICAL-classified fields before template rendering. Step 3: Update postprocess_election() with classification awareness to verify no CRITICAL fields are present. Step 4: Add classification verification tests to ensure get_metadata(), get_issue(), and template sanitization exclude all CRITICAL fields.

---

#### FINDING-050: Synchronous CPU/Memory-Bound Argon2 Operations Block Async Event Loop Without Documented Mitigation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 15.1.3, 15.4.4 |
| **Files** | `v3/steve/election.py:270-285`, `v3/steve/election.py:353-378`, `v3/server/main.py:39` |
| **Source Reports** | 15.1.3.md, 15.4.4.md |
| **Related Findings** | - |

**Description:**

The application uses Quart, an async web framework, but calls synchronous CPU-bound Argon2 operations directly within the async event loop without offloading to a thread pool. This blocks the entire event loop during cryptographic operations (~500ms per call), preventing the server from handling any other requests. During the 500ms Argon2 execution, the entire async event loop is blocked and no other requests can be served. A single has_voted_upon() call for 10 issues blocks the event loop for ~5 seconds, during which ALL other requests (including health checks) are unservable. There is no documentation of this architectural constraint or mitigation strategy. This is a direct availability concern that creates cascading response delays under modest concurrent usage.

**Remediation:**

1. Document that Argon2 operations must be offloaded from the event loop. 2. Implement asyncio.run_in_executor() for all Argon2-calling paths: Create a bounded ThreadPoolExecutor (e.g., max_workers=4, limiting peak memory to 4 × 64MB = 256MB for cryptographic operations). Convert add_vote() and other Argon2-calling methods to async functions that use loop.run_in_executor(_CRYPTO_POOL, crypto.gen_vote_token, ...) to offload CPU-bound operations. 3. Document the thread pool size as the concurrency control mechanism: 'Argon2 operations are offloaded to a bounded thread pool (max_workers=4). This limits peak memory to 4 × 64MB = 256MB for cryptographic operations and prevents event loop blocking. Excess requests queue at the executor.'

---

#### FINDING-051: No Documentation Classifying Third-Party Component Risk Levels

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.1.4 |
| **Files** | `v3/steve/crypto.py:25-28`, `v3/steve/election.py:22-24`, `v3/server/main.py:37` |
| **Source Reports** | 15.1.4.md |
| **Related Findings** | - |

**Description:**

No documentation was found that identifies, classifies, or highlights third-party libraries based on their risk profile. ASVS 15.1.4 specifically requires documentation that flags 'risky components' — defined as third-party libraries that are poorly maintained, unsupported, at end-of-life, or have a history of significant vulnerabilities. The application depends on at least five third-party packages, several of which have characteristics that warrant explicit risk documentation: asfpy and asfquart (ASF-internal libraries without broad public security review processes), easydict (small convenience library with minimal maintenance activity), and argon2-cffi low-level API usage (bypasses higher-level safety defaults). Without risk classification, there is no documented vulnerability response strategy per component, no justification for using risky dependencies, and no mitigation strategy.

**Remediation:**

Create a dependency risk assessment document (e.g., DEPENDENCIES.md or integrate into an SBOM) that classifies each third-party component with risk levels, justifications, mitigation strategies, and review cadences. Document vulnerability response timeframes per component risk level (e.g., Critical CVE in risky component: Patch within 24 hours, High CVE in risky component: Patch within 72 hours). Include classifications for: easydict (Medium risk - limited maintenance, consider replacing with dataclasses or typing.NamedTuple), asfpy/asfquart (Medium risk - internal ASF libraries with limited external security review), argon2-cffi low_level API (Medium risk - bypasses safety defaults, document justification for using low-level API), and cryptography (Low risk - well-maintained, audited).

---

#### FINDING-052: Vote Decryption/Tallying Functionality Lacks Process Isolation from Web Attack Surface

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.2.5 |
| **Files** | `v3/steve/election.py:284-349`, `v3/steve/crypto.py:82-87` |
| **Source Reports** | 15.2.5.md |
| **Related Findings** | - |

**Description:**

The tally_issue() method, which decrypts all encrypted votes for a given issue, resides in the same Election class and runs in the same process as web-facing request handlers. The opened_key (the master key material that, combined with per-voter salts, can decrypt every vote) is loaded into the web server's process memory during tallying. There is no process isolation, privilege separation, sandboxing, or network isolation. A vulnerability in any web handler (e.g., SSRF, template injection, deserialization flaw) could allow an attacker to invoke tally_issue() or access opened_key in process memory, compromising all vote secrecy. This is dangerous functionality without documented additional protections required by ASVS 15.2.5.

**Remediation:**

Implement process-level separation for tallying operations. Option A (recommended for L3 compliance): Create a separate tallying service that runs as a separate process/container with restricted privileges. Use multiprocessing to isolate tallying in a subprocess where key material is destroyed when the subprocess exits. Option B (minimum): Restrict Election class API surface by removing __getattr__ proxy and using explicit method delegation. Create a separate TallyElection subclass for privileged operations that is only instantiable from CLI/privileged context.

---

#### FINDING-053: Election Close Operation Not Atomic — No State Guard in SQL

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-362 |
| **ASVS Sections** | 15.4.1, 15.4.2, 15.4.3 |
| **Files** | `v3/steve/election.py:121-127`, `v3/steve/election.py:108-113`, `v3/steve/election.py:121-128`, `v3/server/pages.py:482`, `v3/server/pages.py:378` |
| **Source Reports** | 15.4.1.md, 15.4.2.md, 15.4.3.md |
| **Related Findings** | FINDING-030, FINDING-171 |

**Description:**

The election close operation performs a state check and state update as separate database operations without transactional protection or atomic state verification in the UPDATE statement. The is_open() check is a separate read query from the c_close.perform() write query, creating a race condition where multiple close requests can execute concurrently. More critically, this allows votes to be submitted during the close operation. The UPDATE query does not include a WHERE clause checking the current state, and there is no rowcount verification after the update to confirm the state transition succeeded. The c_close query parameters suggest no conditional WHERE clause checking current state, meaning the SQL layer provides no protection.

**Remediation:**

Wrap the operation in a BEGIN IMMEDIATE transaction. Verify state within transaction via _all_metadata(S_OPEN). Modify the c_close query to include a conditional WHERE clause: UPDATE election SET closed = 1 WHERE eid = ? AND salt IS NOT NULL AND opened_key IS NOT NULL AND (closed IS NULL OR closed = 0). After execution, check that rowcount == 1 to confirm the election was actually open before closing. If rowcount != 1, raise an ElectionBadState exception indicating the state transition failed. Include proper exception handling with ROLLBACK on failure.

---

#### FINDING-054: Election Delete — State Assertion Before Transaction Creates Race Window (TOCTOU)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-367 |
| **ASVS Sections** | 15.4.2 |
| **Files** | `v3/steve/election.py:48-65` |
| **Source Reports** | 15.4.2.md |
| **Related Findings** | FINDING-029 |

**Description:**

The delete() function asserts that the election is editable before beginning a transaction to delete the election and its related data. This state check occurs outside the transaction boundary, allowing a concurrent request to open the election after the check passes but before the transaction begins, resulting in deletion of an active election. Between assert self.is_editable() passing and BEGIN TRANSACTION executing, a concurrent request could open the election via open(). The delete then proceeds on an election that is now open, destroying an active election with salts and voter data.

**Remediation:**

Move the state check inside the transaction boundary: (1) BEGIN IMMEDIATE, (2) Check state INSIDE the transaction via _all_metadata(S_EDITABLE), (3) Perform deletions (c_delete_mayvote, c_delete_issues, c_delete_election), (4) COMMIT. Include proper exception handling with ROLLBACK on failure. This ensures the state check and deletion operations are atomic.

---

#### FINDING-055: Authorization Failures Not Logged at Multiple Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3 |
| **Files** | `v3/server/pages.py:250`, `v3/server/pages.py:547`, `v3/server/pages.py:308`, `v3/server/pages.py:294-299`, `v3/server/pages.py:607-611`, `v3/server/pages.py:356-366`, `v3/server/pages.py:274-279`, `v3/server/pages.py:241-247`, `v3/server/pages.py:494-499`, `v3/server/pages.py:246-251`, `v3/server/pages.py:610-614` |
| **Source Reports** | 16.1.1.md, 16.2.1.md, 16.3.1.md, 16.3.2.md, 16.3.3.md |
| **Related Findings** | - |

**Description:**

Multiple election management endpoints contain '### check authz' comments indicating that authorization checks are planned but not implemented. This represents a Type A gap—no authorization control exists for fine-grained access (e.g., election ownership verification), therefore no authorization decisions exist to be logged. Since authorization checks are absent, any authenticated committer can open, close, or modify any election. Because no authorization decision is made, there is nothing to log as a 'failed authorization attempt.' This creates a complete blind spot—unauthorized actions appear as normal authorized operations in logs, making security incident detection impossible.

**Remediation:**

Add authorization checks in load_election (for management endpoints) and log both successful and failed authorization decisions. Create a load_election_owner decorator that verifies ownership by checking md.owner_pid against result.uid. Log authorization failures at WARNING level with user ID, election ID, and owner ID. Log successful authorization at INFO level. Example: if md.owner_pid != result.uid: _LOGGER.warning(f'Authorization failure: User[U:{result.uid}] denied management of election[E:{eid}] owned by[U:{md.owner_pid}]'); quart.abort(403)

---

#### FINDING-056: Tally CLI Security Event Logs Lack Timestamps Entirely

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.2 |
| **Files** | `v3/server/bin/tally.py:145`, `v3/server/bin/tally.py:97`, `v3/server/bin/tally.py:102`, `v3/server/bin/tally.py:105`, `v3/steve/election.py:186`, `v3/steve/election.py:197` |
| **Source Reports** | 16.2.2.md |
| **Related Findings** | - |

**Description:**

The tally CLI logging configuration uses Python's default BASIC_FORMAT which contains no timestamp field (asctime). Security events during the most sensitive phase of the election lifecycle—vote decryption and tallying—are logged without any temporal information. This prevents establishing when tally operations occurred relative to election close, whether tallies were run during authorized windows, temporal correlation with other system events for incident investigation, and creates no auditable timeline of vote counting operations.

**Remediation:**

Configure logging.basicConfig with explicit format and datefmt parameters. Use ISO 8601 UTC format and set logging.Formatter.converter = time.gmtime to enforce UTC timestamps: logging.basicConfig(level=logging.INFO, style='{', format='[{asctime}Z|{levelname}|{name}] {message}', datefmt='%Y-%m-%dT%H:%M:%S'); logging.Formatter.converter = time.gmtime

---

#### FINDING-057: No Log Immutability or Write-Protection Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.4.2 |
| **Files** | `v3/server/main.py:52-59`, `v3/server/main.py:84-91` |
| **Source Reports** | 16.4.2.md |
| **Related Findings** | - |

**Description:**

logging.basicConfig() is called without a filename parameter, directing all log output to sys.stderr. There is no configuration for: file-based logging with restricted permissions, append-only or write-once log storage, remote/centralized log forwarding (e.g., syslog, SIEM), cryptographic integrity verification of log entries, or log rotation with retention guarantees. An attacker (or malicious administrator) with process-level or filesystem access can: redirect stderr to /dev/null, silencing all audit logs; modify or delete log files if stderr is redirected to a file by a process manager; tamper with forensic evidence of vote manipulation, election state changes, or unauthorized access; and undermine the entire auditing chain that the election system's security model depends upon.

**Remediation:**

Configure logging with file-based handlers using restricted permissions (0o640), implement append-only semantics using logging.handlers.WatchedFileHandler, add remote syslog handler for immutable centralized logging to prevent local tampering, and set restrictive file permissions on log files. Example: handler = logging.handlers.WatchedFileHandler('/var/log/steve/audit.log'); os.chmod('/var/log/steve/audit.log', 0o640). Add SysLogHandler targeting separate log aggregation server using TCP for reliable delivery.

---

#### FINDING-058: Complete Absence of Remote/Separate Log Transmission

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.4.3 |
| **Files** | `v3/server/main.py:55-62`, `v3/server/main.py:97-103` |
| **Source Reports** | 16.4.3.md |
| **Related Findings** | - |

**Description:**

The application entirely lacks any mechanism for transmitting logs to a logically separate system. All security-relevant logs (authentication, voting, election state changes, tampering detection) are written exclusively to the local process's stderr via Python's default logging.basicConfig(). An attacker who compromises the application server would have full ability to modify or destroy the forensic audit trail—a critical deficiency for an election system. There is no handler configured for SysLogHandler, SocketHandler, HTTPHandler, QueueHandler, or any third-party log shipper integration.

**Remediation:**

Configure a remote log handler in addition to local output. At minimum, add a SysLogHandler targeting a separate log aggregation server using TCP for reliable delivery. For production election systems, implement: (1) TLS-encrypted syslog (RFC 5425) to prevent log interception in transit, (2) SIEM integration (Splunk HEC, Elasticsearch, etc.) via dedicated handlers, (3) Write-once storage (S3 with Object Lock, immutable log volumes), (4) Log signing to detect tampering of archived logs. Example implementation using SysLogHandler with structured format for SIEM ingestion provided in report.

---

#### FINDING-059: No Global Error Handler Defined—Unhandled Exceptions Across All Endpoints Fall to Framework Defaults

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-209 |
| **ASVS Sections** | 16.5.1, 16.5.4 |
| **Files** | `v3/server/pages.py` (entire file), `v3/server/main.py:38-44`, `v3/server/pages.py:95-117`, `v3/server/main.py:34-47` |
| **Source Reports** | 16.5.1.md, 16.5.4.md |
| **Related Findings** | FINDING-014 |

**Description:**

The application does not define a global error handler to catch unhandled exceptions. This means that any exception not explicitly caught by individual endpoint handlers will be processed by the framework's default error handling mechanism. Without an explicit global handler, the application has no defense-in-depth protection against information disclosure through error messages. If the application is ever deployed in debug mode, full tracebacks are exposed. Crypto key material (opened_key, salt), database paths, SQL query structures, and internal module names could be exposed in traceback local variables.

**Remediation:**

Register a global error handler in main.py create_app() or pages.py using @APP.errorhandler(Exception) decorator. The handler should: 1) Log the full error for debugging server-side only using _LOGGER.error() with exc_info=True, 2) Preserve intentional HTTP errors (404, 400, etc.) by checking isinstance(error, quart.exceptions.HTTPException), 3) Return a generic 500 response with message 'An unexpected error occurred. Please try again later.' for all unexpected errors. Also register @APP.errorhandler(500) as an explicit 500 handler. Additionally, add None check for JSON body in _set_election_date before calling .get() method.

---

#### FINDING-060: No Logging of Successful or Failed Authentication Attempts

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.3.1 |
| **Files** | `v3/server/pages.py:63-92`, `v3/server/main.py:36-48` |
| **Source Reports** | 16.3.1.md |
| **Related Findings** | - |

**Description:**

The application uses @asfquart.auth.require decorators for OAuth-based authentication across 15+ endpoints but never logs the outcome of authentication operations. There is no @APP.before_request handler, no @APP.after_request handler, no error handler for 401/403 responses, and no explicit authentication event logging anywhere in the application code. When the OAuth flow completes (success or failure), the application does not record this event. In an election system, the inability to audit authentication events means: impossible to detect unauthorized access attempts, no forensic trail for security incident investigation, cannot verify that only authorized individuals accessed the system during an election, and compliance failure for election auditing requirements.

**Remediation:**

Add authentication event logging hooks in main.py after app creation: (1) Add @app.before_request handler to log authentication outcomes for all requests to protected endpoints, including user ID, IP address, user agent, and path. (2) Add @app.errorhandler(401) to log authentication rejections with IP, path, and user agent. (3) Add @app.errorhandler(403) to log authorization failures with user ID (if available), IP, and path. Example code provided in report shows implementation using _LOGGER.info() for successful auth and _LOGGER.warning() for failures.

---

#### FINDING-061: No Throttling or Timing Enforcement on Vote Submission Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 2.4.1, 2.4.2 |
| **Files** | `v3/server/pages.py:412-470` |
| **Source Reports** | 2.4.1.md, 2.4.2.md |
| **Related Findings** | - |

**Description:**

The vote submission endpoint has no rate limiting, timing checks, or cooldown periods. A compromised authenticated account or malicious insider can submit automated votes at machine speed with no human-interaction timing verification. An authenticated user can submit or modify votes immediately upon receiving POST requests, enabling automated vote manipulation that violates ASVS 2.4.1 and 2.4.2 requirements. This enables: (1) rapid vote-change cycling that could interfere with tallying during race condition windows, (2) excessive database write operations (one per issue per request) creating denial-of-service conditions on the SQLite database through write lock contention, and (3) automated scripts to probe or manipulate outcomes by cycling through different ranking permutations in STV elections at hundreds of submissions per second.

**Remediation:**

Implement comprehensive timing and rate controls: (1) Add per-user rate limiting with a sliding window (e.g., 5 submissions per 60 seconds) using a rate_limit_votes decorator that tracks per-user vote timestamps. (2) Implement session-based timing controls including a per-user vote submission cooldown (e.g., 10 seconds minimum between submissions) by tracking 'last_vote_time' in the session. (3) Enforce minimum ballot dwell-time by recording when the ballot page was loaded ('ballot_loaded_at') and requiring minimum time (e.g., 5 seconds) before accepting the first vote submission. (4) Add timestamp tracking on ballot load in the vote_on_page function using time.monotonic() and quart_session. (5) Log rate limit violations for monitoring and incident response.

---

#### FINDING-062: No Content-Security-Policy Header Configured on Any Response

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3, L2 |
| **CWE** | - |
| **ASVS Sections** | 3.1.1, 3.4.3 |
| **Files** | `v3/server/main.py:32-42`, `v3/server/pages.py:53-61` |
| **Source Reports** | 3.1.1.md, 3.4.3.md |
| **Related Findings** | - |

**Description:**

The application completely lacks any Content-Security-Policy (CSP) response header implementation. No CSP header is defined, applied, or referenced anywhere in the codebase. All 10 HTML-serving endpoints return responses without any CSP protection, leaving the application vulnerable to cross-site scripting (XSS) attacks with unrestricted capabilities. Without CSP, any successful XSS injection would have unrestricted capability — loading external scripts, exfiltrating session data, or manipulating vote submissions. The rewrite_description() function already produces raw HTML (&lt;a&gt; and &lt;pre&gt; tags) from issue data without escaping, making CSP an essential defense-in-depth layer. Missing object-src 'none' allows plugin-based attacks and missing base-uri 'none' allows &lt;base&gt; tag injection to redirect relative URLs to attacker-controlled servers.

**Remediation:**

Option A (L2 compliance): Implement global CSP via after_request hook in create_app() with directives: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'. Option B (L3 compliance): Implement per-response nonce-based CSP. Also fix raise_404() function to ensure CSP headers are applied through the after_request hook.

---

#### FINDING-063: No HTTP Strict Transport Security (HSTS) Header Despite TLS Support

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3, L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 3.1.1, 3.4.1 |
| **Files** | `v3/server/main.py:79-85`, `v3/server/main.py:96` |
| **Source Reports** | 3.1.1.md, 3.4.1.md |
| **Related Findings** | - |

**Description:**

The application supports TLS configuration but never sets the `Strict-Transport-Security` header. This is a Type A gap — TLS is available but HSTS enforcement does not exist. Even when TLS is configured: (1) No HSTS header is sent to instruct browsers to always use HTTPS, (2) No HTTP→HTTPS redirect is configured, (3) No mechanism ensures the application behaves correctly (warns or blocks) when accessed over plain HTTP, (4) In ASGI mode (`run_asgi()`, line 96), TLS is delegated entirely to the reverse proxy with no application-level verification. Users connecting over HTTP (e.g., first visit, downgrade attack, misconfigured proxy) transmit authentication cookies and session data in plaintext. Election data and voter identity are exposed to network-level attackers.

**Remediation:**

Add an `@app.after_request` handler to set Strict-Transport-Security header with 'max-age=31536000; includeSubDomains' when the request is served over HTTPS (check `quart.request.is_secure` or `X-Forwarded-Proto` header). Optionally add an `@app.before_request` handler to redirect HTTP requests to HTTPS with a 301 redirect in non-debug mode.

---

#### FINDING-064: User-Uploaded Documents Served Without Content Interpretation Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.1 |
| **Files** | `v3/server/pages.py:593-608`, `v3/server/pages.py:28-35` |
| **Source Reports** | 3.2.1.md |
| **Related Findings** | FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-065, FINDING-193, FINDING-194 |

**Description:**

The serve_doc endpoint serves user-uploaded documents directly to the browser without any content interpretation controls. Files are served with inferred MIME types and no Content-Disposition: attachment header, Content-Security-Policy: sandbox directive, or X-Content-Type-Options: nosniff protection. This allows malicious HTML/SVG files to execute JavaScript in the application's origin, enabling stored XSS attacks. An attacker can upload malicious HTML files that execute in the application's origin when viewed by authenticated users, leading to session hijacking, vote manipulation, or election state changes.

**Remediation:**

Add Content-Disposition: attachment, Content-Security-Policy: sandbox, and X-Content-Type-Options: nosniff headers to the serve_doc endpoint. Validate docname to prevent path traversal. Use the as_attachment=True parameter in send_from_directory() and add security headers to the response object before returning.

---

#### FINDING-065: Stored XSS via Election/Issue Titles Rendered Without HTML Escaping

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.2 |
| **Files** | `v3/server/pages.py:456`, `v3/server/pages.py:518`, `v3/server/templates/admin.ezt:14`, `v3/server/templates/manage.ezt:8`, `v3/server/templates/manage.ezt:187`, `v3/server/templates/manage-stv.ezt:6`, `v3/server/templates/manage-stv.ezt:137`, `v3/server/templates/vote-on.ezt:9`, `v3/server/templates/vote-on.ezt:49`, `v3/server/templates/voter.ezt:33`, `v3/server/templates/voter.ezt:67` |
| **Source Reports** | 3.2.2.md |
| **Related Findings** | FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-193, FINDING-194 |

**Description:**

Election and issue titles are rendered without HTML escaping across multiple templates in HTML body context. While the [format "js,html"] directive IS used in onclick handlers, it is NOT applied to title rendering in the main HTML body, creating a Type B gap where the control exists but is inconsistently applied. This affects admin.ezt, manage.ezt, manage-stv.ezt, vote-on.ezt, and voter.ezt templates, allowing stored XSS through election/issue titles.

**Remediation:**

Apply [format "html"] to ALL user-provided values in HTML body context: &lt;h2&gt;[format "html"][e_title][end]&lt;/h2&gt;, &lt;strong&gt;[format "html"][issues.title][end]&lt;/strong&gt;, &lt;h5 class="card-title"&gt;[format "html"][owned.title][end]&lt;/h5&gt;

---

#### FINDING-066: Session Cookies Lack `Secure` Attribute Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.3.1 |
| **Files** | `v3/server/main.py:30-44`, `v3/server/pages.py:86`, `v3/server/main.py:77-80` |
| **Source Reports** | 3.3.1.md |
| **Related Findings** | - |

**Description:**

Analysis of the source code reveals that the application uses session-based authentication via `asfquart.session` (built on Quart/Flask) but does not configure the `Secure` attribute for session cookies as required by ASVS 3.3.1. The application creates session cookies through the framework when `asfquart.session.read()` is called across all authenticated endpoints, but no `SESSION_COOKIE_SECURE = True` is set in the application configuration. Additionally, TLS is only conditionally configured when `certfile` is present, meaning the application can run over plain HTTP. Without the `Secure` attribute, session cookies would be transmitted in cleartext over unencrypted connections. This affects all 17+ authenticated endpoints in pages.py, session-based flash messages in all POST handlers, and OAuth callback flows. An attacker on the same network as a voter could intercept session cookies through network sniffing or MITM attacks and impersonate authenticated users, potentially casting fraudulent votes or manipulating elections.

**Remediation:**

In the `create_app()` function in `v3/server/main.py`, add the following configuration: app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_HTTPONLY'] = True, app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

---

#### FINDING-067: Session Cookie Missing Explicit SameSite Attribute Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.3.2 |
| **Files** | `v3/server/main.py:33-49` |
| **Source Reports** | 3.3.2.md |
| **Related Findings** | - |

**Description:**

The application does not explicitly configure the `SameSite` attribute for session cookies. Session cookies are the sole authentication mechanism for the election voting system, yet no explicit security configuration is present in the application initialization code. Without explicit SameSite configuration, protection depends entirely on browser version and defaults. Combined with the placeholder CSRF token, the SameSite attribute is the only remaining browser-side defense against cross-site request forgery. Successful exploitation could allow an attacker to cast votes, create elections, open/close elections, or add/delete issues on behalf of an authenticated user.

**Remediation:**

Explicitly configure session cookie security attributes in the `create_app()` function: app.config['SESSION_COOKIE_SAMESITE'] = 'Lax', app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_HTTPONLY'] = True. Use `SameSite=Lax` rather than `Strict` due to OAuth flow requirements.

---

#### FINDING-068: Missing Content-Security-Policy frame-ancestors Directive on All Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.4.6 |
| **Files** | `v3/server/main.py:27-42`, `v3/server/pages.py:119-123`, `v3/server/pages.py:223-277`, `v3/server/pages.py:460-477`, `v3/server/pages.py:480-495`, `v3/server/pages.py:682-684` |
| **Source Reports** | 3.4.6.md |
| **Related Findings** | - |

**Description:**

No Content-Security-Policy header with a frame-ancestors directive is set on any HTTP response. The create_app() function in main.py does not register any after_request/after_response middleware to inject security headers. No individual route handler in pages.py adds CSP headers to responses. This allows the application to be embedded in iframes by any origin, enabling clickjacking attacks. All 21 HTTP endpoints are vulnerable, including critical endpoints for vote submission (/vote-on/&lt;eid&gt;), election state changes (/do-open/&lt;eid&gt;, /do-close/&lt;eid&gt;), and administrative actions. GET-based state-changing endpoints can be triggered via hidden iframes without any user interaction beyond page load.

**Remediation:**

Add a global after_request middleware in create_app() to set the CSP frame-ancestors directive on every response: response.headers['Content-Security-Policy'] = "frame-ancestors 'none'". Add defense-in-depth: response.headers['X-Frame-Options'] = 'DENY'. Additionally, change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST to eliminate auto-triggerable iframe attacks.

---

#### FINDING-069: State-Changing Operations via GET Bypass All CORS Preflight Protections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.5.2 |
| **Files** | `v3/server/pages.py:448-466`, `v3/server/pages.py:469-484` |
| **Source Reports** | 3.5.2.md |
| **Related Findings** | - |

**Description:**

Two critical state-changing operations use GET requests, which architecturally cannot trigger CORS preflight checks. GET requests are always considered 'simple requests' by the browser and will never initiate a preflight OPTIONS request, regardless of origin. This makes it impossible to use CORS preflight as a cross-origin protection mechanism for these endpoints. An attacker who knows or can guess an election ID can trick an authenticated committer into prematurely opening or closing any election they have access to by hosting a malicious page containing image tags or other GET-triggering elements pointing to these endpoints.

**Remediation:**

Implement one or more of the following: (Option A) Require application/json Content-Type to force CORS preflight for cross-origin requests, returning 415 for non-JSON requests. (Option B) Require a custom header (e.g., X-Requested-With) that forces CORS preflight, returning 403 if missing. (Option C) Validate Origin header against an allowlist on state-changing requests, returning 403 for disallowed origins.

---

#### FINDING-070: Cross-Origin Resource Loading of Authenticated Documents

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.8 |
| **Files** | `v3/server/pages.py:587-603` |
| **Source Reports** | 3.5.8.md |
| **Related Findings** | - |

**Description:**

The `/docs/<iid>/<docname>` endpoint serves authenticated documents (images, scripts, PDFs, and other files associated with election issues) without setting a `Cross-Origin-Resource-Policy` response header and without validating `Sec-Fetch-*` request headers. This allows a malicious cross-origin page to embed or load these authenticated resources on behalf of a logged-in user. Authenticated election documents (images, PDFs, scripts) can be loaded by cross-origin pages when the user has an active session. Attackers can confirm existence of specific documents and issues. Image content is directly rendered; document metadata leaks via timing/size. Election-sensitive material (candidate information, ballot details referenced via `doc:filename` in issue descriptions) exposed.

**Remediation:**

Validate Sec-Fetch-* headers to ensure same-origin navigation. Only allow same-origin or same-site requests by checking if `Sec-Fetch-Site` is in ('same-origin', 'same-site', 'none'). Only allow document/image/empty destinations by checking `Sec-Fetch-Dest`. Add `Cross-Origin-Resource-Policy: same-origin` header to the response from `send_from_directory()`.

---

#### FINDING-071: No Per-Message Digital Signatures on Vote Submission

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.1.5 |
| **Files** | `v3/server/pages.py:422-469`, `v3/steve/election.py:229-240`, `v3/steve/crypto.py:67-72`, `v3/steve/crypto.py:44-54` |
| **Source Reports** | 4.1.5.md |
| **Related Findings** | - |

**Description:**

Election open and close operations are irreversible state machine transitions performed without per-message digital signatures. These endpoints use GET methods for state-changing operations and rely only on session cookie authentication. Issues include: (1) No cryptographic confirmation of intent - opening triggers key generation and salt assignment, closing permanently ends voting, but there's no cryptographic proof of administrator's intent; (2) GET method vulnerability - easily triggerable via link injection, img tags, CSRF attacks, or browser prefetching; (3) Incomplete authorization - comments indicate authorization checking is not implemented, any authenticated committer can trigger transitions; (4) No audit trail integrity - no cryptographic binding between logged action and administrator who authorized it; (5) Fails ASVS 4.1.5 requirement for highly sensitive transactions that should have additional assurance beyond transport protection.

**Remediation:**

Change election lifecycle endpoints to POST methods with signed request bodies requiring confirmation signatures. Implementation: (1) Convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST; (2) Require JSON request body containing action, eid, timestamp, nonce, and signature; (3) Retrieve administrator's public key and verify signature on canonical JSON message; (4) Implement timestamp freshness validation (e.g., within 5 minutes) to prevent replay; (5) Implement nonce checking and consumption to prevent replay within the timestamp window; (6) Add nonce storage mechanism (Redis or database) with automatic cleanup of expired nonces; (7) Log signature verification confirmation in audit trail; (8) Return signed confirmation receipt to administrator; (9) Implement similar protection for other state-changing operations like election creation and issue management.

---

#### FINDING-072: Multiple Authentication Pathways With Inconsistent Strength Not Documented Together

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 6.1.3 |
| **Files** | `v3/ARCHITECTURE.md` (Security section), `v3/server/pages.py:443-444`, `v3/server/pages.py:464-466`, `v3/server/pages.py:486-488`, `v3/server/pages.py:506-508` |
| **Source Reports** | 6.1.3.md |
| **Related Findings** | - |

**Description:**

The application has five distinct authentication pathways/levels (public, session-only, committer, PMC member, CLI direct access), but ARCHITECTURE.md only provides minimal documentation. The documentation fails to: (1) Enumerate all authentication pathways and their strength levels, (2) Map which endpoints require which authentication level and why, (3) Document the CLI pathway's authentication model and how it relates to the web pathway, (4) Specify what security controls must be consistently enforced across all pathways, (5) Explain why related operations require different authentication strength (PMC for create vs. committer for manage). The `### need general solution` comments on 13 separate endpoints confirm this authentication model is provisional and undocumented.

**Remediation:**

Create a formal Authentication and Authorization Matrix document that includes: (1) Web Authentication Pathway with mechanism (ASF OAuth via asfquart.auth), session management details, and a table mapping authentication levels (Public, Session, Committer, Election Owner, PMC Member) to their requirements, use cases, and specific endpoints, (2) CLI Authentication Pathway documenting OS-level server access control mechanism, rationale, and controls including command execution logging, (3) Consistent Controls section listing CSRF tokens for state-changing operations, audit logging for administrative actions, and rate limiting for authentication attempts.

---

#### FINDING-073: Resource-Level Authorization Documented as Required But Never Implemented (Type B Gap)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 6.1.3, 6.3.4 |
| **Files** | `v3/server/pages.py:83`, `v3/server/pages.py:190`, `v3/server/pages.py:223`, `v3/server/pages.py:405`, `v3/server/pages.py:447`, `v3/server/pages.py:468`, `v3/server/pages.py:489`, `v3/server/pages.py:510`, `v3/server/pages.py:536`, `v3/server/pages.py:560`, `v3/server/pages.py:157-175`, `v3/server/pages.py:177-200` |
| **Source Reports** | 6.1.3.md, 6.3.4.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-024, FINDING-088, FINDING-103, FINDING-104, FINDING-105 |

**Description:**

The codebase contains 10+ explicit `### check authz` comments indicating the developers intended to implement fine-grained authorization checks at each endpoint. However, none of these checks were ever implemented. This creates a Type B gap: the security control is DEFINED (via comments documenting the intent) but NOT CALLED, giving false confidence that the security model was considered. As a result, authentication strength is not consistently enforced — any authenticated committer can perform administrative operations on ANY election, regardless of ownership. The authentication model implies per-resource authorization (election ownership is tracked via `owner_pid` in the database), but this is never enforced at the web layer.

**Remediation:**

Implement an authorization decorator that verifies election ownership: Create a `require_election_owner` decorator that wraps async functions, extracts user info via `basic_info()`, gets election metadata, compares `md.owner_pid` to `result.uid`, logs denial attempts, and aborts with 403 if ownership check fails. Apply this decorator to all management endpoints including `/do-open/<eid>`, `/do-close/<eid>`, `/do-add-issue/<eid>`, `/do-delete-issue/<eid>/<iid>`, `/do-edit-issue/<eid>/<iid>`, and `/manage/<eid>` routes. Alternative approach: If elections can be managed by PMC members collectively, verify user has `R.pmc_member` role instead of individual ownership check.

---

#### FINDING-074: No Brute-Force or Credential Stuffing Protection on Authentication Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.1 |
| **Files** | `v3/server/main.py:36-44`, `v3/server/pages.py` (entire file, all @asfquart.auth.require decorated endpoints), `v3/ARCHITECTURE.md:116-120` |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | - |

**Description:**

The application delegates credential verification to ASF OAuth (oauth.apache.org) but implements zero local controls against authentication abuse at the application boundary. Specifically: (1) No rate limiting on OAuth flow initiation - attackers can repeatedly trigger OAuth redirect flow without throttling, enabling automated credential stuffing attempts through the application as a proxy. (2) No monitoring of failed authentication callbacks - when OAuth callback returns failure or attacker replays/forges callback attempts, there is no detection, logging, or throttling. (3) No documentation of brute-force mitigation strategy in security documentation. (4) No session creation throttling after OAuth callback, enabling rapid session enumeration or replay attempts. The application serves as an amplification point with no defense-in-depth at its boundary.

**Remediation:**

Implement rate limiting middleware at the application level using quart_rate_limiter with global limits (300 req/min per IP) and specific rate limits on OAuth callback endpoints (10 attempts per minute per IP). Additionally, implement failed authentication attempt logging with IP tracking and threshold-based blocking. Document the brute-force prevention strategy in security documentation with reference to NIST SP 800-63B § 5.2.2 requirements.

---

#### FINDING-075: No Multi-Factor Authentication Enforcement for Application Access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 6.3.3, 6.3.4, 6.5.6 |
| **Files** | `v3/server/pages.py:78-88`, `v3/server/pages.py:387`, `v3/server/pages.py:430`, `v3/server/pages.py:452`, `v3/server/pages.py:473`, `v3/server/pages.py:492`, `v3/server/pages.py:518`, `v3/server/pages.py:543`, `v3/server/pages.py:375`, `v3/server/pages.py:381`, `v3/server/pages.py:136`, `v3/server/pages.py:225`, `v3/server/pages.py:283`, `v3/server/pages.py:326` |
| **Source Reports** | 6.3.3.md, 6.3.4.md, 6.5.6.md |
| **Related Findings** | - |

**Description:**

The application requires only single-factor authentication (ASF committer identity via `asfquart.auth`) for all access, including sensitive operations such as vote submission, election creation, and election state management. ASVS 6.3.3 at Level 2 mandates that "either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms must be used in order to access the application." An attacker who compromises a single authentication factor (e.g., stolen session cookie, compromised ASF password, OAuth token theft) can access the voter dashboard, cast votes on behalf of the compromised user, and if the user is an election owner, open/close elections and modify ballots.

**Remediation:**

1. Change to POST methods with CSRF protection. 2. Implement MFA verification (see CH06-007). 3. Implement the missing authorization checks to verify the requesting user is the election owner. Recommended fix: Change `@APP.get` to `@APP.post`, add `@require_mfa` and `@require_csrf` decorators, and implement authorization check `if election.owner != result.uid: quart.abort(403, 'Only election owner can open election')`. 4. Implement proper CSRF token generation and validation for all state-changing operations. 5. Update client-side JavaScript in templates to submit POST forms with CSRF tokens instead of using GET navigation.

---

#### FINDING-076: Complete Absence of Authentication Event Tracking and Storage

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-778 |
| **ASVS Sections** | 6.3.5 |
| **Files** | `v3/schema.sql` (entire file), `v3/docs/schema.md` |
| **Source Reports** | 6.3.5.md |
| **Related Findings** | None |

**Description:**

The database schema defines five tables (election, issue, person, mayvote, vote) — none of which track authentication events. There is no table for storing login attempts, login timestamps, source IP addresses, user agents, geolocation data, or authentication outcomes (success/failure). Without persistent storage of authentication events, it is structurally impossible to detect suspicious patterns or notify users. The person table stores only pid, name, and email — no last_login, last_login_ip, failed_login_count, or similar fields.

**Remediation:**

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

---

#### FINDING-077: No Suspicious Authentication Detection Logic in Session Handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-223 |
| **ASVS Sections** | 6.3.5 |
| **Files** | `v3/server/pages.py` (57-86, 136-169, 171-264, 391-398, 570-576) |
| **Source Reports** | 6.3.5.md |
| **Related Findings** | None |

**Description:**

The basic_info() function is the central session-reading function called by every authenticated endpoint. It reads uid, fullname, and email from the session but performs no analysis of authentication context. It does not capture or evaluate the client's IP address, user agent, geolocation, time since last authentication, or prior failed attempts. Authentication is delegated entirely to asfquart.auth.require decorators, but no post-authentication hook exists to evaluate the authentication event. An attacker who compromises credentials can authenticate from a completely different country/IP range, use a different browser/device, authenticate after months of dormancy, or successfully authenticate after dozens of failed attempts without any detection or notification.

**Remediation:**

Implement a post-authentication hook that captures context and evaluates suspicion. The hook should: 1) Check for unusual IP/location by comparing current IP against last authentication event, 2) Check for login after long inactivity by comparing current time against last authentication timestamp, 3) Check for success after recent failures by querying recent failed authentication attempts, 4) Record all authentication events with IP, user agent, and timestamp. Notify users via email or in-app alert when suspicious patterns are detected.

---

#### FINDING-078: Voter access cannot be revoked during open elections due to cryptographic locking of voter roster

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | None |
| **ASVS Sections** | 6.5.6 |
| **Files** | `v3/steve/election.py` (85-117, 210, 292-303) |
| **Source Reports** | 6.5.6.md |
| **Related Findings** | None |

**Description:**

When an election is opened, the entire voter roster is cryptographically bound into the opened_key via tamper detection. Any modification to the voter list causes is_tampered() to return True, preventing the election from proceeding. The Election class has add_voter() but no remove_voter(), suspend_voter(), or revoke_voter_access() method. The gather_election_data() function includes ALL voter PIDs and emails in the hash, and tamper detection verifies this hash hasn't changed. If a voter's authentication is compromised during an active election (e.g., stolen device, phished credentials), an administrator has only two options: do nothing and allow the attacker to vote as the compromised user, or close the entire election and invalidate all votes from all voters.

**Remediation:**

Implement a voter suspension mechanism that works with the tamper detection model by creating a separate suspension table that is checked during vote submission but is NOT part of the tamper-detection hash. Add suspend_voter() method to record suspensions, modify add_vote() to check _is_voter_suspended() before accepting votes, and create corresponding SQL table (suspended_voters) and admin endpoint (POST /admin/suspend-voter/&lt;eid&gt;) for managing voter suspensions. This allows individual voter access revocation without invalidating the entire election's cryptographic integrity.

---

#### FINDING-079: No Verification of IdP Authentication Strength or Method for Any Operation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | None |
| **ASVS Sections** | 6.8.4 |
| **Files** | `v3/server/main.py` (40-44), `v3/server/pages.py` (56-83, 367-407, 409-429, 433-452, 454-472) |
| **Source Reports** | 6.8.4.md |
| **Related Findings** | None |

**Description:**

The application uses Apache OAuth as its external Identity Provider, configured with custom (non-OIDC) endpoints. It never requests, receives, or validates any authentication strength metadata (equivalent to OIDC claims 'acr', 'amr', 'auth_time') from the IdP. This applies to all endpoints, including highly sensitive voting and election lifecycle operations. In a voting system, the inability to verify how a user authenticated means the application cannot distinguish between a user who authenticated with multi-factor authentication and one who used only a username/password (or a session that was hijacked/replayed). An attacker who gains access via a weaker authentication path (e.g., stolen password without MFA enforcement at the IdP) can perform all operations—including casting votes and managing elections—without the application detecting or preventing it. Since Apache OAuth (not OIDC) is used, no ID Token with standard claims is available, which per ASVS 6.8.4 specifically requires a documented fallback approach assuming minimum strength authentication was used. No such documentation or compensating control exists in the codebase or ARCHITECTURE.md.

**Remediation:**

Option A — If the IdP can provide authentication metadata (preferred): Extract authentication metadata (acr, amr, auth_time) from IdP response in session creation callback or basic_info(). Implement require_strong_auth() function to enforce minimum authentication strength for sensitive operations by checking for MFA in auth_methods and verifying recentness (within 5 minutes for sensitive operations). Option B — Documented fallback when IdP cannot provide metadata (ASVS 6.8.4 minimum): Add to ARCHITECTURE.md documentation stating that Apache OAuth does not provide acr/amr/auth_time claims and the application assumes MINIMUM strength authentication (single-factor, username/password) for all sessions. Implement compensating controls: 1) Session lifetime limited to 30 minutes for voting operations, 2) Re-authentication required before casting votes, 3) Election management restricted to verified PMC members via separate channel. Implement session age check as compensating control using require_recent_session() function with max_age_seconds parameter.

---

#### FINDING-080: No Session Inactivity Timeout or Absolute Maximum Session Lifetime Implemented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | None |
| **ASVS Sections** | 7.1.1, 7.3.1, 7.3.2, 7.1.3, 7.6.1 |
| **Files** | `v3/server/pages.py` (44-71, 62-88, 45-68), `v3/server/main.py` (33-46) |
| **Source Reports** | 7.1.1.md, 7.3.1.md, 7.3.2.md, 7.1.3.md, 7.6.1.md |
| **Related Findings** | None |

**Description:**

The application reads sessions from the federated SSO provider but implements no controls to coordinate session lifetimes. The basic_info() function — the sole session-reading code — performs a binary check (session exists or not) with no validation of session age, expiry, or freshness. If the SSO provider issues long-lived tokens, the voting application will honor them indefinitely. No idle timeout means abandoned sessions remain valid, widening the attack window. There is no evidence the application-layer session is invalidated when the SSO provider terminates the IdP session (no coordination code exists). ASVS 7.1.3 explicitly requires documentation of 'controls to coordinate session lifetimes' — none exists.

**Remediation:**

Implement session timeouts at the application layer with SESSION_INACTIVITY_TIMEOUT = 900 seconds (15 minutes per NIST AAL2 ≤30 min requirement) and SESSION_ABSOLUTE_LIFETIME = 43200 seconds (12 hours). Modify basic_info() function to: (1) check absolute session lifetime against created_at timestamp, (2) check inactivity timeout against last_active timestamp, (3) destroy expired sessions with asfquart.session.destroy() and abort with 401 error, and (4) update last_active timestamp on valid sessions. Store auth_time in session during IdP authentication callback. Configure session cookie with appropriate max-age settings using app.config['PERMANENT_SESSION_LIFETIME'], SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, and SESSION_COOKIE_SAMESITE.

---

#### FINDING-081: No Session Termination (Logout) Endpoint Exists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 7.2.4, 7.3.1, 7.4.1, 6.5.6 |
| **Files** | `v3/server/pages.py` (entire file, 1-679, 1-508) |
| **Source Reports** | 7.2.4.md, 7.3.1.md, 7.4.1.md, 6.5.6.md |
| **Related Findings** | FINDING-086, FINDING-099, FINDING-106, FINDING-107 |

**Description:**

The /settings and /profile pages are empty stubs with zero authentication factor management. A comprehensive search confirms no revocation endpoint exists anywhere in the codebase. There is no POST /logout or GET /logout endpoint, no POST /revoke-session endpoint, no POST /revoke-factor or similar endpoint, no POST /suspend-user admin endpoint, no session invalidation function anywhere in the codebase, and no user/account management functions beyond PersonDB.get_person() (read-only). If a user's authentication credentials (password, session cookie, SSO token, or any MFA factor) are compromised through theft, phishing, or device loss, there is no way to revoke the compromised authentication factor, force-invalidate active sessions, suspend the user's account, or prevent the attacker from casting votes on behalf of the compromised user.

**Remediation:**

Implement a logout endpoint that properly destroys the session: @APP.get('/logout') and @APP.post('/logout') with @asfquart.auth.require decorator. The endpoint should call await asfquart.session.destroy(), flash an info message, and redirect to home with 303 status code. For SSO integration, redirect to the IdP's logout endpoint for federated logout. Add logout links to all authenticated page templates in the base template header showing logged-in user name with a logout link when uid is present. Include audit logging for logout events matching existing event logging pattern.

---

#### FINDING-082: No Session Regeneration on Authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-384 |
| **ASVS Sections** | 7.2.4 |
| **Files** | `v3/server/pages.py` (78-90), `v3/server/main.py` (38-42) |
| **Source Reports** | 7.2.4.md |
| **Related Findings** | None |

**Description:**

The application has no session regeneration logic anywhere in the provided codebase. Authentication is handled through an OAuth flow configured in main.py and delegated to asfquart, but the application never explicitly regenerates or rotates session tokens upon successful authentication. Session is only ever READ, never regenerated. A search for session.write, session.create, session.regenerate, session.new, session.rotate, session.clear, or session.destroy yields zero results across all provided source files. This creates a session fixation vulnerability where an attacker could set a victim's session ID before authentication, then hijack the authenticated session after the victim logs in.

**Remediation:**

Add explicit session regeneration in the authentication callback. If asfquart provides a hook or post-authentication callback, use it: async def on_authentication_success(user_data): old_session = await asfquart.session.read(); if old_session: await asfquart.session.destroy(); await asfquart.session.create({'uid': user_data['uid'], 'fullname': user_data['fullname'], 'email': user_data['email'], 'auth_time': time.time()}). If asfquart does not expose session regeneration APIs, this must be raised as a framework requirement.

---

#### FINDING-083: No Re-authentication Before Critical Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 7.2.4, 7.5.3, 7.6.1 |
| **Files** | `v3/server/pages.py` (466-468, 539-541, 559-561, 372-413, 436-452, 455-470, 393, 460, 480) |
| **Source Reports** | 7.2.4.md, 7.5.3.md, 7.6.1.md |
| **Related Findings** | FINDING-027, FINDING-108 |

**Description:**

The most sensitive operations in this voting system — casting votes, opening elections, and closing elections — do not require re-authentication and therefore never trigger session regeneration or freshness validation. A stale or compromised session can perform all critical operations without proving the user is still present. Vote submission endpoint performs no re-authentication or secondary verification before recording votes. Election opening and closing operations are irreversible state transitions that require no re-authentication. If an attacker gains access to a valid session token, they can immediately perform all critical operations without any additional authentication challenge. This violates NIST SP 800-63C requirements for federation session synchronization.

**Remediation:**

Implement a re-authentication gate for critical operations with require_recent_auth(max_age_seconds) function that verifies authentication occurred within specified timeframe (300 seconds for vote submission, 900 seconds for admin operations). Check if time.time() - auth_time > max_age_seconds, destroy session if expired, and redirect to IdP for re-authentication with prompt=login or max_age parameter. Apply to: POST /do-vote/&lt;eid&gt; (max_age=300), GET /do-open/&lt;eid&gt; (max_age=300), GET /do-close/&lt;eid&gt; (max_age=300), POST /do-create-election (max_age=900), and POST /do-delete-issue/&lt;eid&gt;/&lt;iid&gt; (max_age=900). Additionally, change /do-open and /do-close endpoints to POST method and implement proper CSRF token validation.

---

#### FINDING-084: Session-Verified Identity Not Used for Election Ownership Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | None |
| **ASVS Sections** | 7.2.1, 4.4.3, 14.1.2, 14.2.4, 14.2.6, 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.1, 8.3.3, 8.4.1, 2.3.2, 2.3.5 |
| **Files** | `v3/server/pages.py` (448, 468, 486, 513, 537, 369, 375, 319, 164-185) |
| **Source Reports** | 7.2.1.md, 4.4.3.md, 14.1.2.md, 14.2.4.md, 14.2.6.md, 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.3.1.md, 8.3.3.md, 8.4.1.md, 2.3.2.md, 2.3.5.md |
| **Related Findings** | None |

**Description:**

The application defines election ownership (owner_pid) and group authorization (authz) fields in the database schema with explicit documentation stating that only the owner or members of the specified LDAP group should be able to edit elections. However, these controls are never enforced in the web layer. The load_election decorator, which is applied to all 9 management endpoints, contains only a placeholder comment '### check authz' with no actual authorization logic. This allows any authenticated committer to manipulate any election — opening, closing, adding/editing/deleting issues, and changing dates — regardless of whether they are the owner or in the authorized group. This is a Type B gap where the authorization need is explicitly recognized (via TODO comments and schema documentation) but the check is never implemented, creating dangerous false confidence. Any of the ~800+ ASF committers can perform administrative operations on any election, regardless of ownership or group membership.

**Remediation:**

Implement ownership and authorization group verification in the load_election and load_election_issue decorators or create a separate verify_election_owner function. Check if the current user's uid matches election.owner_pid or verify membership in the election.authz LDAP group. Apply this check to all management endpoints (do_open_endpoint, do_close_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint, do_set_open_at_endpoint, do_set_close_at_endpoint). Return HTTP 403 Forbidden if the user is not authorized to manage the election. Example: s = await asfquart.session.read(); md = e.get_metadata(); if s['uid'] != md.owner_pid: if md.authz and not await check_group_membership(s['uid'], md.authz): quart.abort(403, 'Not authorized to manage this election')

---

#### FINDING-085: No Session Termination When User Account Is Deleted or Disabled

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Sections** | 7.4.2 |
| **Files** | `v3/steve/persondb.py` (51-61, 28-73), `v3/server/pages.py` (78-92) |
| **Source Reports** | 7.4.2.md |
| **Related Findings** | None |

**Description:**

When user accounts are deleted via PersonDB.delete_person(), no mechanism exists to terminate active sessions. The delete_person() method removes the user record from the person table in SQLite but does not consult or modify any session store. Deleted users retain full application access until their session naturally expires. The basic_info() function reads session data (uid, fullname, email) from the session store and trusts these values directly for authorization decisions without ever consulting PersonDB to verify the user still exists or is active. Additionally, there is no disable_person() or deactivate_person() mechanism, no is_active field in the person schema, and no mechanism to temporarily or reversibly revoke access. If a user has participated in any election (has entries in the mayvote table), their account cannot be deleted due to foreign key constraints, and there is no disable mechanism.

**Remediation:**

Implement comprehensive account lifecycle management: (1) Add an is_active field to the person schema (ALTER TABLE person ADD COLUMN is_active INTEGER DEFAULT 1). (2) Implement a disable_person(pid) method that sets is_active = 0 for the specified user and terminates all their active sessions via session revocation. (3) Modify delete_person() to accept a session_manager parameter and call session_manager.revoke_all_sessions_for_user(pid) after successful deletion. (4) Modify basic_info() to verify user still exists and is active after reading session data. Open PersonDB connection and call get_person(s['uid']). If PersonNotFound exception is raised or is_active=0, destroy the session immediately using await asfquart.session.destroy() and return basic info with uid=None. (5) For performance optimization, consider caching the user-existence check with a short TTL (e.g., 60 seconds) rather than hitting the database on every request.

---

#### FINDING-086: No Administrator Capability to Terminate User Sessions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 7.4.5 |
| **Files** | `v3/server/pages.py` (All routes), `v3/schema.sql` (All tables), `v3/queries.yaml` (All queries) |
| **Source Reports** | 7.4.5.md |
| **Related Findings** | FINDING-081, FINDING-099, FINDING-106, FINDING-107 |

**Description:**

The application provides no mechanism for administrators to terminate active sessions, either for an individual user or for all users. This was confirmed by exhaustive review of all route handlers, backend classes, database schema, and CLI tools. Session management is entirely delegated to the external asfquart framework with no application-level override capability. Administrators cannot respond to account compromises by terminating sessions, and there is no emergency 'terminate all sessions' capability during a security incident. In a voting system, this means fraudulent votes can continue to be cast during an active compromise, potentially affecting election outcomes.

**Remediation:**

Implement comprehensive session management capabilities: (1) Add session storage table to v3/schema.sql with fields: session_id, pid, created_at, last_activity, expires_at, is_active, ip_address, user_agent. (2) Add session management queries to v3/queries.yaml: q_active_sessions (list all active sessions), q_user_sessions (list sessions for specific user), c_terminate_user_sessions (terminate all sessions for user), c_terminate_session (terminate specific session), c_terminate_all_sessions (emergency terminate all). (3) Add admin endpoints to v3/server/pages.py: GET /admin/sessions, POST /admin/sessions/terminate/&lt;pid&gt;, POST /admin/sessions/terminate-all, POST /admin/sessions/terminate-session/&lt;session_id&gt;. (4) Implement session validation middleware using @APP.before_request to check database session validity on each request and reject terminated sessions. (5) Create admin template showing active sessions with termination controls. (6) Add comprehensive audit logging for all session termination actions with admin identity. (7) Define dedicated admin role (R.admin) beyond R.committer for session management operations following principle of least privilege.

---

#### FINDING-087: Complete Absence of Active Session Viewing and Termination Capability for Users

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | None |
| **ASVS Sections** | 7.5.2 |
| **Files** | `v3/server/pages.py` (537-549, 68-78) |
| **Source Reports** | 7.5.2.md |
| **Related Findings** | None |

**Description:**

The application defines two user-facing account pages (/profile and /settings) that could host session management functionality, but neither provides the ability to view active sessions or terminate them. Users cannot see a list of their currently active sessions, including device information, IP addresses, last activity times, or creation timestamps. A full text search of all routes in pages.py reveals no endpoint for terminating sessions - no capability to terminate a specific session by ID, terminate all sessions except the current one, or log out from the current session. If a user's session token is stolen, the user has no mechanism to discover the compromised session exists, revoke the compromised session, or revoke all sessions as a defensive measure. ASVS 7.5.2 explicitly requires that users re-authenticate with at least one factor before terminating sessions, but the codebase has no re-authentication mechanism at all for sensitive operations.

**Remediation:**

Implement comprehensive user-facing session management: (1) Add a session listing endpoint (/sessions or integrate into /settings) that retrieves all sessions for the current user from a server-side session store and displays metadata including session ID, creation time, last activity, IP address, user agent, and whether it's the current session. (2) Implement session termination endpoints with proper re-authentication: POST /sessions/terminate/&lt;session_id&gt; to terminate a specific session after re-authentication, POST /sessions/terminate-all to revoke all sessions except the current one after re-authentication. (3) Implement a re-authentication flow that must be passed before session management operations are permitted. Create a verify_reauthentication() function that either verifies the user's password directly or checks if the user authenticated recently (e.g., within the last 5 minutes). (4) Implement a require_recent_auth() decorator to enforce re-authentication requirements on sensitive operations. (5) All termination operations should include logging for audit purposes.

---

#### FINDING-088: Missing Explicit Voter Eligibility Check on Vote Submission Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.2, 8.3.3, 8.4.1, 8.2.3 |
| **Files** | `v3/server/pages.py` (285-307, 222-228), `v3/steve/election.py` (201-207) |
| **Source Reports** | 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.3.2.md, 8.3.3.md, 8.4.1.md, 8.2.3.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-024, FINDING-073, FINDING-103, FINDING-104, FINDING-105 |

**Description:**

The vote viewing page (vote_on_page) correctly checks voter eligibility using q_find_issues before rendering the ballot. However, the vote submission endpoint (do_vote_endpoint) does not perform this check before processing votes. Instead, it relies on an implicit exception when add_vote() attempts to access .salt on a None mayvote record, which is caught by a generic exception handler and returns a vague error message. While the vote ultimately fails, the failure mode is an unhandled exception rather than a proper authorization denial. The generic error handler could mask real errors, and an attacker can probe which issues exist in which elections by observing error vs. success responses. This violates defense-in-depth principles as the GET endpoint (ballot display) has explicit authorization while the POST endpoint (vote submission) relies on implicit failure.

**Remediation:**

Add explicit voter eligibility verification in do_vote_endpoint before processing any votes. Use q_find_issues to verify the user has mayvote entries for the election and build a set of eligible issue IDs. Return 403 Forbidden with appropriate error message if user is not eligible. For each submitted vote, verify the issue ID is in the eligible set before calling add_vote(). Replace implicit exception-based failure with explicit authorization checks. Add security logging for unauthorized vote attempts with user and election identifiers. Create a VoterNotEligible exception class and add an explicit None check in add_vote() method.

### 3.3 Medium

#### FINDING-089: Argon2d Used Instead of RFC 9106-Recommended Argon2id for Key Derivation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-327 |
| **ASVS Sections** | 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.2.3, 11.2.4, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.6.1, 11.6.2, 11.7.1, 11.7.2, 6.5.2 |
| **Files** | `v3/steve/crypto.py:80-92`, `v3/steve/crypto.py:116-146` |
| **Source Reports** | 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 11.2.3.md, 11.2.4.md, 11.3.3.md, 11.4.2.md, 11.4.3.md, 11.4.4.md, 11.6.1.md, 11.6.2.md, 11.7.1.md, 11.7.2.md, 6.5.2.md |
| **Related Findings** | FINDING-153 |

**Description:**

The production `_hash()` function uses Argon2d (Type.D) while the benchmark function uses Argon2id (Type.ID). Argon2d uses data-dependent memory access patterns, making it vulnerable to side-channel attacks (cache-timing, memory bus snooping) that could leak information about the secret input. RFC 9106 Section 4 explicitly recommends Argon2id for general-purpose use because it combines Argon2i's side-channel resistance with Argon2d's GPU resistance. This affects both the election master key (opened_key) and per-voter tokens (vote_token), potentially compromising ballot encryption and vote anonymity. In shared hosting or cloud environments, an attacker with co-tenant access could use cache timing attacks to extract data-dependent memory access patterns.

**Remediation:**

Change `_hash()` to use `argon2.low_level.Type.ID` instead of Type.D to match the benchmark function and follow RFC 9106 / OWASP recommendations: `type=argon2.low_level.Type.ID`. Note: Changing the Argon2 type will change all derived key values. This must be treated as a key rotation event and cannot be applied to elections that have already been opened. Implement with version flag for new elections only or coordinate migration during maintenance window when no elections are open.

---

#### FINDING-090: Non-Constant-Time Comparison of Cryptographic Key Material in Tamper Detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-208 |
| **ASVS Sections** | 11.1.1, 11.1.2, 11.2.1, 11.2.3, 11.2.4, 11.2.5, 11.3.3, 11.4.2, 11.6.1, 11.7.1 |
| **Files** | `v3/steve/election.py:335-349` |
| **Source Reports** | 11.1.1.md, 11.1.2.md, 11.2.1.md, 11.2.3.md, 11.2.4.md, 11.2.5.md, 11.3.3.md, 11.4.2.md, 11.6.1.md, 11.7.1.md |
| **Related Findings** | - |

**Description:**

The `is_tampered()` function uses Python's standard `!=` operator to compare cryptographic keys (opened_key), which performs byte-by-byte comparison that short-circuits on the first differing byte. This leaks information about the stored key through timing differences. An attacker who can trigger tamper checks with controlled election data modifications and observe response timing could gradually reconstruct the opened_key value. The opened_key is the root of trust for the entire key derivation chain - knowledge of it combined with per-voter salts from the mayvote table would allow computing vote_token values and decrypting individual votes, breaking voter anonymity. While currently CLI-only, the method is a public API on the Election class that web handlers could invoke.

**Remediation:**

Replace the `!=` operator with `hmac.compare_digest()` for constant-time comparison: `return not hmac.compare_digest(opened_key, md.opened_key)`. Add `import hmac` at the top of the file. This prevents timing oracle attacks that could leak key material.

---

#### FINDING-091: HKDF Domain Separation Label Misidentifies Encryption Algorithm

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-320 |
| **ASVS Sections** | 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.3.3, 11.3.4, 11.3.5, 11.6.1, 11.6.2 |
| **Files** | `v3/steve/crypto.py:51-62`, `v3/steve/crypto.py:64-69` |
| **Source Reports** | 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 11.3.3.md, 11.3.4.md, 11.3.5.md, 11.6.1.md, 11.6.2.md |
| **Related Findings** | - |

**Description:**

The HKDF info parameter in `_b64_vote_key()` uses `info=b'xchacha20_key'` while the actual encryption uses Fernet (AES-128-CBC + HMAC-SHA256). This violates the principle of accurate domain separation in key derivation and creates a latent key reuse vulnerability. The HKDF info parameter provides cryptographic domain separation per NIST SP 800-56C / RFC 5869, ensuring keys derived for different purposes are cryptographically independent. If XChaCha20-Poly1305 is later added alongside Fernet (as code comments suggest), both would derive keys with `info=b'xchacha20_key'`, meaning the same key material feeds two different algorithms — a key reuse violation per NIST SP 800-57 §5.2. During algorithm migration, if the same info label is retained, identical key material would be used for both the old Fernet EtM scheme and the new XChaCha20-Poly1305 AEAD scheme, undermining security guarantees of both. The mismatch between code labels and actual behavior makes cryptographic inventory inaccurate.

**Remediation:**

Change the HKDF info parameter to accurately reflect the actual algorithm: `info=b'fernet_vote_key_v1'`. Document algorithm migration strategy before switching from Fernet to XChaCha20-Poly1305, including versioning scheme and backwards compatibility plan. When migrating to XChaCha20-Poly1305, use a distinct info value like `b'xchacha20_vote_key_v2'` to maintain proper domain separation. Note: Changing the info parameter changes all derived keys and requires coordinated migration similar to Argon2 variant change.

---

#### FINDING-092: Cryptographic Decryption Errors Propagate Without Secure Handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 11.2.5 |
| **Files** | `v3/steve/crypto.py:75`, `v3/steve/election.py:290`, `v3/steve/election.py:250` |
| **Source Reports** | 11.2.5.md |
| **Related Findings** | - |

**Description:**

Cryptographic operations in crypto.py (`decrypt_votestring`, `create_vote`, `gen_vote_token`, `_b64_vote_key`) and their callers in election.py (`tally_issue`, `add_vote`) lack exception handling. Raw exceptions from the cryptography library (`cryptography.fernet.InvalidToken`, `argon2.exceptions.*`, `ValueError`) propagate directly to the transport layer (CLI stdout or web response). This can lead to: (1) Information disclosure - stack traces reveal encryption library, algorithm choices (Fernet), and internal architecture; (2) Availability issues - a single corrupted ciphertext prevents tallying of an entire election with no graceful degradation or skip-and-log capability. While Fernet's encrypt-then-MAC design prevents padding oracle attacks specifically, the broader fail-secure principle is violated.

**Remediation:**

1. Add a dedicated `CryptoError` exception class in crypto.py to wrap all internal crypto exceptions and prevent leaking implementation details. 2. Wrap all cryptographic operations (`decrypt_votestring`, `create_vote`, `gen_vote_token`, `_b64_vote_key`) in try/except blocks that catch library-specific exceptions and raise `CryptoError` with sanitized messages. 3. Handle `CryptoError` gracefully in election.py callers - in `tally_issue`, catch decryption failures, log with vote_token hash for audit, and continue processing other votes rather than failing the entire tally. 4. Add internal debug-level logging of actual exception types for operational troubleshooting without exposing to external callers.

---

#### FINDING-093: Election and Issue IDs Generated with Insufficient Entropy (40 bits vs. 128-bit minimum)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 11.5.1, 6.6.3, 7.2.3 |
| **Files** | `v3/steve/crypto.py:118`, `v3/schema.sql:61`, `v3/schema.sql:104`, `v3/steve/election.py:370`, `v3/steve/election.py:195` |
| **Source Reports** | 11.5.1.md, 6.6.3.md, 7.2.3.md |
| **Related Findings** | - |

**Description:**

`create_id()` generates reference tokens (election IDs eid, issue IDs iid) with only 40 bits of entropy (5 bytes × 8 = 40 bits). ASVS 7.2.3 mandates a minimum of 128 bits for reference tokens. While these are resource identifiers rather than session tokens directly, they function as security-critical reference tokens within authenticated sessions. The insufficient entropy becomes a security issue due to three compounding factors: (1) Authorization is systematically incomplete - every state-changing endpoint in pages.py contains `### check authz` comments with no actual authorization enforcement, (2) IDs are exposed in URLs - patterns like `/manage/<eid>`, `/do-vote/<eid>`, `/do-open/<eid>` expose these identifiers, (3) Brute-force feasibility - 40 bits = ~1.1 trillion possible values. An authenticated attacker can enumerate valid election IDs systematically. Without authorization checks, discovering a valid eid grants full access.

**Remediation:**

Increase ID entropy to at least 128 bits (16 bytes → 32 hex characters). Update crypto.py: `def create_id(): return secrets.token_hex(16)  # 16 bytes = 128 bits → 32 hex characters`. Update schema.sql CHECK constraints for both eid and iid to enforce `length(eid) = 32` and `length(iid) = 32` with appropriate GLOB patterns. Create database migration script for existing installations. Add rate limiting on election/issue lookup endpoints as defense-in-depth. Implement monitoring for ID enumeration attempts. Document entropy requirements in developer guidelines.

---

#### FINDING-094: Argon2 Parameters Adopted from Passlib Defaults Without Application-Specific Tuning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-916 |
| **ASVS Sections** | 11.4.4, 15.1.3 |
| **Files** | `v3/steve/crypto.py:78` |
| **Source Reports** | 11.4.4.md, 15.1.3.md |
| **Related Findings** | - |

**Description:**

The application uses Argon2 key derivation with significant resource requirements (64MB memory, ~200-500ms CPU time per invocation) in multiple web request paths including vote submission (`add_vote`), ballot status checking (`has_voted_upon`), and tallying (`tally_issue`). There is no documentation identifying these operations as resource-intensive, no documented defenses against availability loss, and no documented strategies to avoid response times exceeding consumer timeouts. With 10 concurrent vote submissions: 10 × 64MB = 640MB peak memory + 10 × 500ms of CPU blocking. With `has_voted_upon()` for a voter eligible on 20 issues: 20 sequential Argon2 calls = ~10 seconds response time. For `tally_issue()` with 100 eligible voters: ~50 seconds; 1,000 voters: ~500 seconds. Without documentation, operators cannot size infrastructure appropriately, configure reverse proxy timeouts, set connection pool limits, or understand why the application becomes unresponsive under moderate load.

**Remediation:**

Create an operations/architecture document that: (1) Identifies each resource-intensive operation with its CPU/memory profile: Vote Submission (`add_vote`): 1× Argon2 derivation (64MB RAM, ~500ms CPU); Ballot Status (`has_voted_upon`): N × Argon2 where N = number of issues (64MB × N RAM, ~500ms × N CPU); Tally Operation: O(N) Argon2 derivations where N = eligible voters per issue (~0.5 seconds × N voters per issue). (2) Documents maximum concurrent requests the server can handle based on Argon2 memory (Max concurrent vote submissions = available_memory / 64MB). (3) Specifies recommended reverse proxy timeout settings and deployment configuration (worker count, memory limits). (4) Describes recommended defenses: Configure reverse proxy to limit concurrent connections; set worker count = (available_memory - base_usage) / 64MB; Limit elections to ≤ 20 issues for `has_voted_upon` or implement caching; Schedule tallying during low-usage windows for elections > 200 voters; Consider batched processing with progress output for elections > 1000 voters. (5) Provides timeout guidance: Client timeout should be ≥ 2 seconds for vote submission; For N issues, expect N × 0.5s response time for `has_voted_upon`; Tally is CLI-only, NOT exposed via web API.

---

#### FINDING-095: Missing OIDC Audience Restriction Control

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-346 |
| **ASVS Sections** | 10.1.1, 10.3.1 |
| **Files** | `v3/server/main.py:36-43`, `v3/server/main.py:36-41` |
| **Source Reports** | 10.1.1.md, 10.3.1.md |
| **Related Findings** | FINDING-101 |

**Description:**

The application explicitly overrides the framework's default OIDC configuration to use a plain OAuth flow against oauth.apache.org. By disabling OIDC, the application loses the standardized ID Token 'aud' (audience) claim verification that ensures tokens issued by the authorization server are intended exclusively for this specific client. Without audience-restricted tokens, there is no verifiable mechanism at the application layer to confirm that the access token obtained was issued specifically for the STeVe application.

**Remediation:**

Re-enable OIDC and validate the ID Token's 'aud' claim. Remove the `OAUTH_URL_INIT` and `OAUTH_URL_CALLBACK` overrides to use OIDC defaults. Configure `OIDC_CLIENT_ID` for audience validation and set `OIDC_VALIDATE_AUDIENCE` to `True` in the app configuration. Alternatively, add explicit audience validation through RFC 8707 resource parameter or JWT validation middleware.

---

#### FINDING-096: Unverified Session Transport May Expose Tokens to Browser

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-522 |
| **ASVS Sections** | 10.1.1 |
| **Files** | `v3/server/pages.py:65-95` |
| **Source Reports** | 10.1.1.md |
| **Related Findings** | - |

**Description:**

The application reads session data via `asfquart.session.read()` in every authenticated handler. Quart's default session implementation stores all session data in a client-side signed cookie (itsdangerous-signed, base64-encoded). If the asfquart.session follows Quart's default and the framework stores the OAuth access token or refresh token in the session, these tokens would be serialized into the session cookie sent to the browser with every HTTP response. There is no visible configuration in the application ensuring server-side session storage, session cookie attributes (HttpOnly, Secure, SameSite=Lax), or token exclusion from the session cookie payload.

**Remediation:**

Configure server-side session storage and secure cookie attributes: Use `SESSION_TYPE = 'filesystem'` or `'redis'`, set `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`, and `SESSION_COOKIE_NAME = '__Host-steve_session'`. Audit the asfquart framework to confirm tokens are stored server-side only and session cookies contain only a session identifier.

---

#### FINDING-097: OAuth State Parameter Security Properties Unverifiable — Framework Delegation Without Audit Visibility

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 10.1.2 |
| **Files** | `v3/server/main.py:35-38`, `v3/server/pages.py:89` |
| **Source Reports** | 10.1.2.md |
| **Related Findings** | FINDING-021, FINDING-022, FINDING-023, FINDING-192, FINDING-222 |

**Description:**

ASVS 10.1.2 requires that the state parameter is: (1) Not guessable, (2) Specific to the transaction, (3) Securely bound to the client and user agent session. The `state=%s` placeholder confirms the framework is expected to populate this value. However, the OAuth callback handler is not present in any of the provided source files and is entirely within the asfquart framework. The state generation logic, validation logic, and session binding mechanism are opaque and cannot be assessed. The `basic.csrf_token = 'placeholder'` pattern raises concern about whether the analogous OAuth state parameter handling in the framework is robust.

**Remediation:**

1) Obtain and audit the asfquart framework source code; 2) Verify that state is generated using `secrets.token_urlsafe(32)` or equivalent; 3) Verify that state is stored in a server-side session before the redirect; 4) Verify that the callback handler rejects requests where the returned state does not match the session-stored value; 5) Document the framework's OAuth security properties as part of the application's security architecture.

---

#### FINDING-098: User Identity Derived from Opaque 'uid' Session Field Without Verifiable 'iss'+'sub' Claim Origin

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-287 |
| **ASVS Sections** | 10.3.3, 10.5.2 |
| **Files** | `v3/server/pages.py:89-98`, `v3/server/pages.py:77-88` |
| **Source Reports** | 10.3.3.md, 10.5.2.md |
| **Related Findings** | FINDING-026, FINDING-100, FINDING-229, FINDING-235 |

**Description:**

The application derives user identity from a session field 'uid' without verifiable proof that this identifier originates from non-reassignable OAuth token claims ('iss' + 'sub'). All authorization decisions throughout the application depend on this single 'uid' field, which is populated by the opaque asfquart framework during OAuth token exchange. If the asfquart framework populates 'uid' from a reassignable claim (such as 'preferred_username', 'email', or a custom attribute) rather than the immutable 'sub' claim combined with 'iss' validation, a user who inherits a recycled identifier could gain access to another user's election permissions.

**Remediation:**

Implement explicit checks in the `basic_info()` function to extract and validate 'iss' and 'sub' claims from the session. Validate that the issuer matches the expected value (https://oauth.apache.org). Use the combination of 'iss' and 'sub' as the canonical identity. If the asfquart framework cannot be modified to expose 'iss' and 'sub' in the session, audit the framework's token-to-session mapping to confirm that 'uid' is derived from the 'sub' claim.

---

#### FINDING-099: Missing Authentication Recentness Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 10.3.4 |
| **Files** | `v3/server/main.py:37-43`, `v3/server/pages.py:85-95`, `v3/server/pages.py:443-482`, `v3/server/pages.py:507-525` |
| **Source Reports** | 10.3.4.md |
| **Related Findings** | FINDING-081, FINDING-086, FINDING-106, FINDING-107 |

**Description:**

The application explicitly disables OIDC and uses plain OAuth, thereby removing the standard mechanism (auth_time claim) for verifying authentication recentness. The session object contains only uid, fullname, and email — no authentication timestamp is stored or checked. Sensitive operations (voting, opening/closing elections) proceed without verifying when the user last authenticated. In a voting system, stale sessions can be exploited to cast votes on behalf of another user without requiring recent authentication.

**Remediation:**

1) Store auth_time in session during OAuth callback by recording `int(time.time())` when session is established; 2) Implement a `require_recent_auth()` helper function that checks if `(time.time() - auth_time)` exceeds the maximum allowed age (e.g., 3600 seconds for voting operations); 3) Apply this check before sensitive operations like voting, opening/closing elections; 4) Redirect to re-authentication if auth_time check fails.

---

#### FINDING-100: Missing Authentication Method and Strength Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-287 |
| **ASVS Sections** | 10.3.4 |
| **Files** | `v3/server/pages.py:443-482`, `v3/server/pages.py:507-525` |
| **Source Reports** | 10.3.4.md |
| **Related Findings** | FINDING-026, FINDING-098, FINDING-229, FINDING-235 |

**Description:**

The application has operations of varying sensitivity (viewing elections, voting, managing elections, creating elections) but performs no verification of authentication method or strength. The framework distinguishes `R.committer` from `R.pmc_member` roles but these are authorization checks on group membership — not authentication quality. There is no verification that the user authenticated with an appropriate method (e.g., MFA for administrative operations). Administrative operations on elections (open, close, create, delete issues) can be performed with any authentication method, including potentially weak ones.

**Remediation:**

1) If using OIDC (recommended), capture and verify acr/amr claims from the identity provider; 2) Implement a `require_auth_strength()` function that verifies authentication method meets requirements for sensitive operations by checking acr and amr values stored in session; 3) For election management operations requiring MFA, check that actual_amr includes values like 'mfa', 'otp', or 'hwk'; 4) Return 403 error if authentication strength is insufficient.

---

#### FINDING-101: No Authorization Server Issuer Validation Mechanism Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-346 |
| **ASVS Sections** | 10.5.3 |
| **Files** | `v3/server/main.py:37-42`, `v3/server/pages.py:83-89` |
| **Source Reports** | 10.5.3.md |
| **Related Findings** | FINDING-095 |

**Description:**

The application configures OAuth endpoints via hardcoded URL strings but defines no expected issuer URL and implements no mechanism to validate that authorization server metadata or token responses originate from the expected issuer. The comment 'Avoid OIDC' indicates a deliberate bypass of OIDC discovery, which also bypasses the metadata issuer validation this requirement mandates. Without issuer validation, a rogue authorization server could impersonate the legitimate AS by providing metadata with issuer set to 'https://oauth.apache.org'.

**Remediation:**

Configure an expected issuer URL and validate it against authorization server metadata and token responses: 1) Define `EXPECTED_ISSUER` constant as 'https://oauth.apache.org'; 2) If asfquart supports issuer validation, configure it via framework settings; 3) Add middleware to validate iss claim in session/tokens before processing, rejecting sessions from unexpected issuers; 4) If migrating to OIDC discovery, fetch metadata and validate that the metadata's issuer field exactly matches the expected issuer URL.

---

#### FINDING-102: Missing Explicit 'response_type=code' Parameter in OAuth Authorization URL

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-601 |
| **ASVS Sections** | 10.6.1, 10.4.12 |
| **Files** | `v3/server/main.py:36-41`, `v3/server/main.py:39-43` |
| **Source Reports** | 10.6.1.md, 10.4.12.md |
| **Related Findings** | - |

**Description:**

The OAuth authorization URL template does not include the required 'response_type=code' parameter. Per RFC 6749 §4.1.1, 'response_type' is a REQUIRED parameter in authorization requests. Without an explicit 'response_type=code' parameter, the RP relies entirely on the external OP's default behavior. If the OP defaults to or supports 'response_type=token', access tokens could be returned in the URL fragment, leading to token leakage vectors including browser history exposure, referrer header leakage, and JavaScript access by third-party scripts.

**Remediation:**

Explicitly include 'response_type=code' in the authorization URL template. Additionally, consider adding `response_mode=query` to explicitly specify query parameter response. Implement defense-in-depth by validating that the callback contains a 'code' parameter and not token parameters. Re-evaluate the intentional bypass of OIDC to determine if the standardized security properties OIDC provides are justified.

---

#### FINDING-103: Missing Consent Enforcement Parameters in OAuth Authorization Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 10.7.1, 10.7.2 |
| **Files** | `v3/server/main.py:36-42`, `v3/server/main.py:37-41` |
| **Source Reports** | 10.7.1.md, 10.7.2.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-024, FINDING-073, FINDING-088, FINDING-104, FINDING-105 |

**Description:**

The OAuth authorization URL configuration omits all consent-enforcing parameters and explicitly disables OIDC support. This makes it impossible to verify or guarantee that the external authorization server prompts users for consent on each authorization request. The configuration includes no 'prompt', 'consent_prompt', or 'scope' parameters, and explicitly avoids OIDC with a comment '# Avoid OIDC'. Without these parameters, the application relies entirely on the authorization server's default behavior, which may silently issue tokens for returning users without displaying a consent screen.

**Remediation:**

Switch to OIDC (or add consent parameters if the AS supports them in plain OAuth). Update the OAuth configuration to include: `response_type=code`, `scope=openid profile email`, `prompt=consent`, state parameter, and redirect_uri. If OIDC adoption is not feasible, coordinate with oauth.apache.org operators to confirm that consent is always prompted for the STeVe client registration.

---

#### FINDING-104: Authorization Tiers Not Reflected in OAuth Consent — Election Management Privileges Granted Without Specific Consent

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 10.7.2 |
| **Files** | `v3/server/pages.py:518`, `v3/server/main.py:37-39` |
| **Source Reports** | 10.7.2.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-024, FINDING-073, FINDING-088, FINDING-103, FINDING-105 |

**Description:**

The application enforces a two-tiered authorization model internally: Tier 1 (`R.committer`) for voting and Tier 2 (`R.pmc_member`) for election creation. However, the OAuth consent flow is identical for all users regardless of their eventual privilege tier. The single OAuth flow means users are never informed during consent that their ASF membership/group data will determine election management privileges, the application will query LDAP group membership to determine PMC membership, or authentication grants potential access to election administration functions.

**Remediation:**

Define distinct OAuth scopes or Rich Authorization Request (RAR) details that map to application privilege tiers, and request them contextually (e.g., `SCOPE_VOTER = 'openid profile email steve:vote'`, `SCOPE_ADMIN = 'openid profile email steve:vote steve:manage'`). If the ASF OAuth server doesn't support custom scopes, implement an application-level consent screen before granting elevated privileges.

---

#### FINDING-105: Complete Absence of Consent Management Functionality

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 10.7.3 |
| **Files** | `v3/server/pages.py:554-560`, `v3/server/pages.py:563-569` |
| **Source Reports** | 10.7.3.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-024, FINDING-073, FINDING-088, FINDING-103, FINDING-104 |

**Description:**

The application provides no mechanism for users to review, modify, or revoke OAuth consents granted through the authorization server. While the application integrates with oauth.apache.org as an OAuth client, it lacks any consent management interface required by ASVS 10.7.3. Users have no visibility into what scopes/permissions they have granted, when consent was given, or how to revoke the application's access. The profile and settings pages exist but only display basic user information (uid, name, email) without any consent-related data or controls.

**Remediation:**

Implement consent management functionality: 1) Create `/consents` page displaying active OAuth consents including application name, granted scopes, grant timestamp, and authorization server; 2) Implement `/revoke-consent` endpoint that calls the AS token revocation endpoint (RFC 7009) and clears the local session; 3) Store consent metadata in session data during OAuth callback; 4) Add consent modification interface allowing users to adjust scope permissions.

---

#### FINDING-106: No User-Facing Session or Token Revocation Mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 10.4.9, 10.6.2 |
| **Files** | `v3/server/pages.py:582-597`, `v3/server/pages.py:entire application (all 21 routes)`, `v3/server/main.py:39-42` |
| **Source Reports** | 10.4.9.md, 10.6.2.md |
| **Related Findings** | FINDING-081, FINDING-086, FINDING-099, FINDING-107 |

**Description:**

A comprehensive review of all 21 routes reveals no logout endpoint, no session revocation mechanism, and no integration with the Authorization Server's token revocation endpoint (RFC 7009). Users who authenticate via OAuth have no way to invalidate their session or trigger revocation of any tokens held by the application. An attacker who obtains a valid session cookie can use it indefinitely. The legitimate user visiting `/profile` or `/settings` will find no 'Log out' or 'Revoke sessions' option.

**Remediation:**

1) Add `/logout` endpoint that clears local session and revokes tokens at the AS using RFC 7009; 2) Add Session Management UI to `/settings` page displaying active sessions with revocation capability; 3) Update Configuration to add `OAUTH_URL_REVOKE`; 4) Add logout links in navigation on all authenticated pages; 5) Implement Back-Channel Logout Handler at `/backchannel-logout` POST endpoint.

---

#### FINDING-107: No Visible Session/Token Absolute Expiration Enforcement in OAuth Client

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 10.4.8 |
| **Files** | `v3/server/main.py:36-48`, `v3/server/pages.py:60-90` |
| **Source Reports** | 10.4.8.md |
| **Related Findings** | FINDING-081, FINDING-086, FINDING-099, FINDING-106 |

**Description:**

The application lacks visible enforcement of absolute session or token expiration at the client level. The `asfquart.construct()` call includes no session lifetime configuration, and `basic_info()` performs no timestamp-based session validation. If asfquart does not internally enforce absolute session expiration, sessions derived from OAuth tokens could persist indefinitely, even if the AS properly expires refresh tokens. This creates a gap where the client session may outlive the intended token lifetime, increasing the window for session hijacking.

**Remediation:**

Configure explicit session absolute expiration: 1) Set `PERMANENT_SESSION_LIFETIME` to a finite value (e.g., 8 hours); 2) Ensure `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and `SESSION_COOKIE_SAMESITE` are properly configured; 3) Store authentication timestamp (`created_at`) in session during OAuth callback; 4) Validate session age in `basic_info()` by checking if session age exceeds maximum allowed age, invalidating the session if expired.

---

#### FINDING-108: OAuth Client Confidentiality Classification Cannot Be Verified — No Client Type Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 10.4.16 |
| **Files** | `v3/server/main.py:35-51` |
| **Source Reports** | 10.4.16.md |
| **Related Findings** | FINDING-027, FINDING-083 |

**Description:**

ASVS 10.4.16 requires verification that the client is confidential. While the application is architecturally a server-side Quart application (appropriate for confidential client), no explicit client credential configuration or client type enforcement is visible in the codebase. The token endpoint URL passes only the authorization code, mirroring a public client pattern where the client cannot authenticate itself. No client_id/client_secret configuration, key material for client authentication, or client registration metadata showing token_endpoint_auth_method is present.

**Remediation:**

Explicitly register the client as a confidential client with the authorization server (oauth.apache.org). Configure the application with the appropriate client credentials and authentication method. Document the client type classification in application security documentation. Add configuration validation to ensure confidential client credentials are present and properly secured. Ensure client credentials are never exposed in browser-accessible responses.

---

#### FINDING-109: Tampering Detection Control Exists But Is Never Invoked Before Sensitive Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 2.3.2, 11.6.2, 9.1.1 |
| **Files** | `v3/steve/election.py:316`, `v3/steve/election.py:236`, `v3/steve/election.py:252`, `v3/server/pages.py:336` |
| **Source Reports** | 2.3.2.md, 11.6.2.md, 9.1.1.md |
| **Related Findings** | - |

**Description:**

The `opened_key` serves as a MAC/integrity hash of the complete election definition (election metadata, issues, eligible voters). It is generated via Argon2 when the election opens and stored in the database. The `is_tampered()` method recomputes this hash and compares it to the stored value to detect modifications. However, no server endpoint or internal method ever calls `is_tampered()` before accepting or acting on the election data. This represents a Type B coverage gap where the control exists but is never invoked. Post-opening modifications to election data (voter rolls, issues, election metadata) go undetected during all voting and tallying operations. The entire purpose of the `opened_key` integrity mechanism is nullified because the check is never performed.

**Remediation:**

Add a tamper check at the beginning of operations that depend on the key establishment: `def add_vote(self, pid: str, iid: str, votestring: str, pdb): # Verify election integrity before using key material if self.is_tampered(pdb): raise ElectionTampered(self.eid)`. Note: The `is_tampered()` check requires a PersonDB instance, which may not be readily available in all calling contexts. Consider caching the tamper state or passing the pdb reference during election initialization. Also note that calling `is_tampered()` on every vote submission involves Argon2 computation; consider caching the result with a short TTL or checking on election load.

---

#### FINDING-110: Missing ROLLBACK Handling in Transactional Methods

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.3.3, 16.5.2 |
| **Files** | `v3/steve/election.py:55-70`, `v3/steve/election.py:126-140` |
| **Source Reports** | 2.3.3.md, 16.5.2.md |
| **Related Findings** | - |

**Description:**

The `delete()` and `add_salts()` methods both use explicit `BEGIN TRANSACTION` / `COMMIT` blocks to wrap multi-step database operations. However, neither method includes exception handling with explicit `ROLLBACK` statements. When an exception occurs during the transaction, the `COMMIT` is never reached, leaving the database connection with an open, uncommitted transaction that holds SQLite's exclusive write lock until garbage collection occurs. Without explicit `ROLLBACK` on exception, failed transactions leave the database connection in a dirty state, potentially blocking all other write operations to the election database.

**Remediation:**

Add try/except/finally blocks to all methods using `BEGIN TRANSACTION`. In the except block, execute explicit `ROLLBACK` before re-raising the exception. In the finally block (for `delete()`), ensure the connection is closed properly. Example pattern: `try: self.db.conn.execute('BEGIN TRANSACTION'); ...; self.db.conn.execute('COMMIT'); except Exception: self.db.conn.execute('ROLLBACK'); raise; finally: self.db.close()`. This ensures transactions are always properly terminated and database locks are released.

---

#### FINDING-111: No CSV/Formula Injection Protection Architecture

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 1.2.10 |
| **Files** | `v3/server/pages.py:361-376, 414-433, 474-502`, `v3/steve/election.py:197-209, 210-265, 301-307` |
| **Source Reports** | 1.2.10.md |
| **Related Findings** | - |

**Description:**

The application stores user-controllable data (election titles, issue titles, issue descriptions, vote strings) without any sanitization of CSV formula injection characters (=, +, -, @, \t, \0). No CSV export functionality, CSV-safe utility functions, or formula injection escaping mechanisms exist anywhere in the codebase. The voting system produces tabular data through `tally_issue()` and `get_voters_for_email()` that are natural candidates for CSV/spreadsheet export. If tally results or voter/election data are ever exported to CSV/XLS/XLSX/ODF, formula injection payloads stored by authenticated users would execute in the recipient's spreadsheet application, potentially leading to arbitrary command execution on the machine of an election administrator reviewing results.

**Remediation:**

1. Add a CSV-safe export utility (csv_utils.py) with `sanitize_csv_field()` function that escapes formula injection characters (=, +, -, @, \t, \0) by prefixing with a single quote if they appear as the first character. Implement `export_csv()` function with RFC 4180 compliance (QUOTE_ALL). 2. Add vote string validation in `add_vote()` to validate votestring format for the issue type using `vtypes.vtype_module().validate_vote()`. 3. Add input validation for titles/descriptions using `sanitize_text_input()` to strip formula injection characters from leading positions.

---

#### FINDING-112: Missing Path Sanitization/Validation for Document Serving Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 1.3.6, 5.1.1, 5.2.2, 5.3.1, 5.4.1, 5.3.2 |
| **Files** | `v3/server/pages.py:527-543` |
| **Source Reports** | 1.3.6.md, 5.1.1.md, 5.2.2.md, 5.3.1.md, 5.4.1.md, 5.3.2.md |
| **Related Findings** | - |

**Description:**

The `serve_doc()` function serves arbitrary files from the `DOCSDIR / iid` directory without any filename validation, extension allowlisting, Content-Type enforcement, or safe-download headers. The developers explicitly acknowledged this gap with a TODO comment ('### verify the propriety of DOCNAME.') but never implemented the control. This is a Type B gap: the need for a security control was identified, but the control was never implemented, creating false confidence that the issue is tracked. The data flow is: User request → URL parameter docname → NO validation → `send_from_directory(DOCSDIR/iid, docname)` → File served to browser. If a malicious file evil.html containing JavaScript exists in `DOCSDIR/<valid-iid>/`, it would be served with a text/html Content-Type, executing any embedded JavaScript in the user's browser context (stored XSS). Similarly, executable files could be distributed. Without documented file handling requirements, there is no specification for what constitutes a valid document. The lack of `Content-Disposition: attachment` header means files are rendered inline, and the application does not specify a safe filename in the response header as required by ASVS 5.4.1.

**Remediation:**

First, create the documentation (Finding CH05-001). Then implement the specified controls: (1) Define `ALLOWED_DOC_EXTENSIONS` allowlist ({'.pdf', '.txt', '.md'}) and `SAFE_CONTENT_TYPES` mapping, (2) Validate filename using regex to ensure alphanumeric, hyphens, underscores, and single dot for extension only (`^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$`), (3) Validate extension against allowlist and reject with HTTP 403 if not permitted, logging the attempt with user ID, (4) Serve with explicit Content-Type from `SAFE_CONTENT_TYPES` mapping, (5) Add `Content-Disposition: attachment` header with `as_attachment=True` and sanitized filename, (6) Add `X-Content-Type-Options: nosniff` header, (7) Add `Content-Security-Policy: default-src 'none'` for defense-in-depth. Consider moving docs directory outside application tree (v3/server/) to prevent accidental exposure through web server misconfiguration.

---

#### FINDING-113: No SMTP Injection Sanitization Controls for User-Controlled Election Metadata

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-93 |
| **ASVS Sections** | 1.3.11 |
| **Files** | `v3/steve/election.py:501-507, 430-434`, `v3/server/pages.py:467-484, 534-540, 557-562` |
| **Source Reports** | 1.3.11.md |
| **Related Findings** | - |

**Description:**

The codebase contains an explicit method `get_voters_for_email()` in election.py indicating email notification functionality exists, but no SMTP/IMAP injection sanitization controls are present anywhere in the provided code. User-controlled election metadata (titles, descriptions) and issue data flows through the system without any mail-specific encoding or sanitization, creating potential SMTP header injection vulnerabilities. Data flows from user input (form.title from POST /do-create-election) through storage in the election table to email dispatch systems without CRLF filtering or header encoding. An authenticated user creating an election could inject SMTP headers via the title field, potentially allowing injection of additional headers (Bcc, Cc, To), overriding Content-Type for phishing, and adding arbitrary recipients.

**Remediation:**

Add SMTP-specific sanitization for all user-controlled data before it reaches any email system. Create a sanitization module with `sanitize_for_email_header()` function that removes CRLF sequences (\r, \n, \x00) that could enable SMTP header injection. Apply this sanitization in `Election.create()` method before storing the title. Use Python's `email.message` module for constructing emails rather than string concatenation as it provides built-in header encoding and injection protection. Apply `sanitize_for_email_header()` to issue titles and `sanitize_for_email_body()` to descriptions at the form handler level or within `add_issue()`/`edit_issue()` methods.

---

#### FINDING-114: No Cross-Field Date Consistency Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.1.2, 2.2.3 |
| **Files** | `v3/server/pages.py:79-100, 375, 382` |
| **Source Reports** | 2.1.2.md, 2.2.3.md |
| **Related Findings** | - |

**Description:**

The `_set_election_date()` function validates individual date format but does not perform cross-field validation to ensure contextual consistency between open_at and close_at dates. The combined data items (open_at + close_at) are never validated for logical consistency. An election could have close_at before open_at, or dates set in the past, creating logically inconsistent election metadata. Each date field is validated and set independently without checking the relationship to the other date field.

**Remediation:**

Add cross-field validation in `_set_election_date()` that checks `open_at < close_at` consistency. When setting open_at, verify it is before the existing close_at (if set). When setting close_at, verify it is after the existing open_at (if set). Return HTTP 400 Bad Request with descriptive error message if validation fails. Consider also validating that dates are not in the past relative to current time. Also add similar validation in `Election.create()` and create-election.py for initial election creation.

---

#### FINDING-115: No Business Logic Limits on Resource Creation or Vote Revisions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-770 |
| **ASVS Sections** | 2.1.3 |
| **Files** | `v3/server/pages.py:466, 522`, `v3/steve/election.py:256`, `v3/queries.yaml` |
| **Source Reports** | 2.1.3.md |
| **Related Findings** | - |

**Description:**

No business logic limits are defined or enforced for resource creation (elections, issues) or vote revisions. The vote storage model uses INSERT for every revision, allowing unbounded database growth. There are no per-user limits on election creation, no per-election limits on issue count, and no limits on vote revision frequency. Input length limits are also missing for title and description fields.

**Remediation:**

Define and document business logic limits as constants (e.g., `MAX_ELECTIONS_PER_USER=50`, `MAX_ISSUES_PER_ELECTION=100`, `MAX_VOTE_REVISIONS_PER_ISSUE=10`, `MAX_TITLE_LENGTH=200`, `MAX_DESCRIPTION_LENGTH=5000`). Implement enforcement checks in the respective endpoints before allowing resource creation. Consider changing the vote storage model to UPDATE existing votes instead of always INSERTing new rows.

---

#### FINDING-116: Missing Document Name Validation in File Serving Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-22 |
| **ASVS Sections** | 2.1.3 |
| **Files** | `v3/server/pages.py:613` |
| **Source Reports** | 2.1.3.md |
| **Related Findings** | - |

**Description:**

The file serving endpoint has a developer comment explicitly noting the need to verify document name propriety, but no validation is implemented. While `send_from_directory` prevents path traversal, there's no validation of filename format, no filtering of hidden/system files, and no protection against serving files with double extensions or unusual formats. The iid parameter used as a directory component also lacks format validation.

**Remediation:**

Implement regex-based validation for both iid and docname parameters to ensure they only contain safe characters (alphanumeric, hyphens, underscores, dots). Reject hidden files (starting with '.'), files containing '..', and files with suspicious patterns. Define and enforce a whitelist of allowed filename patterns.

---

#### FINDING-117: Election Can Be Opened Without Issues or Eligible Voters

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.2.3 |
| **Files** | `v3/steve/election.py:72-87`, `v3/server/pages.py:530-547` |
| **Source Reports** | 2.2.3.md |
| **Related Findings** | - |

**Description:**

The `election.open()` method allows transitioning an election to OPEN state without verifying it has any issues defined or voters assigned. Once opened, an election cannot be returned to EDITABLE state, making this transition irreversible. An election opened without issues or voters is permanently unusable - no voters can participate (no mayvote entries exist), and the opened_key is derived from an empty dataset providing weak anti-tamper protection. Election administrators must create a new election, losing the EID and any configured metadata.

**Remediation:**

Add pre-condition checks in `election.open()` before allowing state transition. Query for issues using `q_issues` and verify at least one exists. Query for mayvote entries using `q_all_issues` and verify at least one voter is assigned. Raise `ValueError` with descriptive message if either check fails. This ensures elections can only be opened when they are complete and usable.

---

#### FINDING-118: No TLS/Cipher Configuration for ASGI Deployment Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 12.1.2, 12.1.5, 12.3.1 |
| **Files** | `v3/server/main.py:94-115`, `v3/server/main.py:95-115`, `v3/server/main.py:91-109`, `v3/server/main.py:115-126` |
| **Source Reports** | 12.1.2.md, 12.1.5.md, 12.3.1.md, 12.3.3.md |
| **Related Findings** | - |

**Description:**

The ASGI mode creates the application but provides no TLS configuration whatsoever. The inline documentation suggests running via 'uv run python -m hypercorn main:steve_app', however: (1) No Hypercorn configuration file (hypercorn.toml) is provided in the codebase; (2) No --ciphers, --certfile, --keyfile, or --ssl-version command-line guidance; (3) No programmatic SSLContext configuration within `run_asgi()`; (4) Deployments following this pattern will either lack TLS entirely or use Hypercorn's permissive defaults. Production deployments using ASGI mode have no secure cipher suite baseline. Operators have no reference configuration for cipher suite hardening. Cipher suite selection is left entirely to deployment luck.

**Remediation:**

Provide a Hypercorn configuration file (hypercorn.toml) with hardened TLS settings: `bind = '0.0.0.0:58383'`, `certfile = 'certs/server.pem'`, `keyfile = 'certs/server-key.pem'`, `ciphers = 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES'`. Document the required invocation: 'uv run python -m hypercorn --config hypercorn.toml main:steve_app'. Add runtime warnings in `run_asgi()` to detect and alert on missing TLS configuration.

#### FINDING-119: Example Configuration Lacks Cipher Suite and TLS Version Settings

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | None specified |
| **ASVS Sections** | 12.1.2, 12.1.4 |
| **Files** | `v3/server/config.yaml.example:23-31` |
| **Source Reports** | 12.1.2.md, 12.1.4.md |
| **Related Findings** | None |

**Description:**

(1) No OCSP Stapling configuration exists anywhere in the example configuration or documentation. The config.yaml.example contains only certfile and keyfile — there are no fields for OCSP responder URL, stapling file path, or any revocation-related settings. (2) ASGI mode has zero TLS configuration — when running under Hypercorn, TLS would need to be configured via Hypercorn's config or command-line arguments. The codebase provides no Hypercorn configuration file, no documentation of required TLS parameters, and no programmatic OCSP stapling setup. (3) No OCSP or CRL configuration fields are defined in the configuration schema, meaning even operators who want to enable revocation checking have no supported mechanism to do so.

**Remediation:**

Add OCSP-related configuration to the example config: ocsp_staple_file, tls_minimum_version fields. For ASGI deployments, add a Hypercorn configuration template with certfile, keyfile, and ciphers. Document that the reverse proxy must be configured with OCSP Stapling using nginx ssl_stapling directives.

---

#### FINDING-120: No SSL Context Configuration Prevents mTLS Client Certificate Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | None specified |
| **ASVS Sections** | 12.1.3, 12.3.5 |
| **Files** | `v3/server/main.py:83-90`, `v3/server/main.py:79-87`, `v3/server/config.yaml.example:28-30`, `v3/server/config.yaml.example:28-31` |
| **Source Reports** | 12.1.3.md, 12.3.5.md |
| **Related Findings** | None |

**Description:**

The TLS configuration passes raw certfile and keyfile paths directly to app.runx() without constructing an ssl.SSLContext. This prevents client certificate verification as there is no ssl.SSLContext.verify_mode = ssl.CERT_REQUIRED and no trusted CA (ca_certs) configured, so client certificates are never requested or validated. The config.yaml schema has no fields for CA certificates, certificate verification mode, or CRL/OCSP configuration. Without an explicit context, the server may accept TLS 1.0/1.1 depending on underlying framework defaults, and default ciphers are used which may include weak suites. For a voting/election system handling authenticated ballot submission, the inability to layer mTLS as a defense-in-depth authentication mechanism is a notable gap.

**Remediation:**

Create an explicit ssl.SSLContext with proper configuration and provide mTLS configuration options. Step 1: Update configuration schema in config.yaml to add ca_certs, verify_client, tls_min_version, and ciphers fields. Step 2: Implement _create_ssl_context() function in main.py that creates ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), enforces minimum TLS version 1.2, loads server certificate chain, configures strong cipher suites, and when verify_client is enabled, loads CA certificates and sets verify_mode to ssl.CERT_REQUIRED to validate client certificates before use. Pass the created SSL context to app.runx() via ssl parameter instead of raw certfile/keyfile.

---

#### FINDING-121: ASGI Deployment Mode Has No Application-Level TLS Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 12.1.3 |
| **Files** | `v3/server/main.py:99-118` |
| **Source Reports** | 12.1.3.md |
| **Related Findings** | None |

**Description:**

When deployed via Hypercorn (the documented production path), TLS configuration is entirely delegated to the external ASGI server with no application-enforced constraints. The application does not configure or pass any SSL context to the ASGI runner, does not verify at startup that the ASGI server has TLS enabled, and provides no documentation or configuration validation for Hypercorn's mTLS settings (--ca-certs, --verify-mode). This means the application relies entirely on operational configuration to enforce TLS and mTLS, with no programmatic safeguard ensuring client certificates are validated when used. Misconfigured Hypercorn deployment could serve over plain HTTP or accept unverified client certificates with no defense-in-depth and no warning when deployed insecurely.

**Remediation:**

Add startup validation in run_asgi() that checks for TLS configuration by examining environment variables (e.g., HYPERCORN_SSL_CERTFILE) and logs a security warning if no TLS certificate is detected. Document required Hypercorn configuration in startup logs. Create deployment documentation (docs/deployment.md) with production deployment instructions showing how to run Hypercorn with --certfile, --keyfile, --ca-certs, and --verify-mode CERT_REQUIRED for mTLS. Include guidance on ensuring client CA bundle contains all trusted certificate authorities and monitoring logs for certificate validation failures.

---

#### FINDING-122: No Certificate Revocation Checking for Outbound OAuth Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | None specified |
| **ASVS Sections** | 12.1.4, 12.3.2 |
| **Files** | `v3/server/main.py:44-48`, `v3/server/main.py:38-41` |
| **Source Reports** | 12.1.4.md, 12.3.2.md |
| **Related Findings** | None |

**Description:**

The application makes outbound HTTPS connections to the Apache OAuth service for authentication. There is no visible configuration of certificate revocation checking (OCSP or CRL) for these outbound TLS connections. The application code provides no mechanism to: (1) Enforce OCSP checking on the OAuth endpoint's certificate, (2) Provide a CRL distribution point for validation, (3) Configure an SSL context for outbound connections with revocation verification. If the OAuth server's certificate were compromised and revoked, the application could continue to trust and send sensitive authentication tokens to an attacker-controlled endpoint presenting the revoked certificate.

**Remediation:**

Configure outbound HTTPS connections with certificate revocation verification. Create a dedicated SSL context for outbound connections with explicit certificate trust configuration: oauth_ssl_context = ssl.create_default_context(cafile=certifi.where()); oauth_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2; oauth_ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF; pass to asfquart or underlying HTTP client.

---

#### FINDING-123: No Explicit TLS Certificate Validation for OAuth Token Exchange

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-295 |
| **ASVS Sections** | 12.3.2, 12.3.4 |
| **Files** | `v3/server/main.py:38-41`, `v3/server/main.py:42-45` |
| **Source Reports** | 12.3.2.md, 12.3.4.md |
| **Related Findings** | None |

**Description:**

The application makes outbound HTTPS requests to oauth.apache.org for authentication token exchange. While the configured URLs correctly use the https:// scheme, there is no explicit SSL context creation, certificate verification enforcement, or CA trust store configuration anywhere in the application code. The application delegates all TLS client behavior to the asfquart framework with no verification that certificate validation is active. If the underlying library were ever configured or defaulted to skip verification, the application would silently accept fraudulent certificates, enabling man-in-the-middle attacks on the OAuth token exchange.

**Remediation:**

Create and pass an explicit SSL context for all outbound connections: create_oauth_ssl_context() that creates ssl.create_default_context() loading system CA certificates, sets minimum_version to TLSv1_2, verify_mode to CERT_REQUIRED, and check_hostname to True. Pass to HTTP client used for OAuth token exchange. Optionally pin to specific CA for oauth.apache.org.

---

#### FINDING-124: No Explicit SSL Context for Server-Side TLS Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-326 |
| **ASVS Sections** | 12.3.2, 12.3.4 |
| **Files** | `v3/server/main.py:76-78`, `v3/server/main.py:83-89` |
| **Source Reports** | 12.3.2.md, 12.3.4.md |
| **Related Findings** | None |

**Description:**

The server-side TLS configuration passes raw certfile and keyfile paths directly to app.runx() without constructing an ssl.SSLContext. This means there is no enforcement of minimum TLS protocol version, cipher suite selection, or other security parameters for inbound connections. While this is server-side TLS rather than client certificate validation, the pattern demonstrates the broader absence of explicit TLS configuration discipline. Without explicit SSL context configuration, the server may accept deprecated TLS versions (TLS 1.0, 1.1) or weak cipher suites depending on the framework and Python version defaults.

**Remediation:**

Create a create_server_ssl_context(certfile, keyfile) function that returns ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) with minimum_version = TLSVersion.TLSv1_2, loads cert chain, and optionally restricts cipher suites to 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20'. Pass the SSL context to app.runx() instead of raw paths.

---

#### FINDING-125: External OAuth Service Dependency Hardcoded and Undocumented in Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.1.1 |
| **Files** | `v3/server/main.py:37-40`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.1.1.md |
| **Related Findings** | None |

**Description:**

The application has a hard runtime dependency on `oauth.apache.org` for authentication, but this external service is not documented in the configuration file. The OAuth endpoints are hardcoded in source code rather than externalized as configuration parameters. An operator deploying this application would review `config.yaml.example` for network requirements, configure firewall rules based on documented communication needs, block outbound HTTPS to unknown destinations, and deploy the application resulting in authentication failures due to blocked OAuth connections.

**Remediation:**

Add OAuth configuration to `config.yaml.example` including auth_url, token_url, and documentation about redirect_uri construction. Update `main.py` to use configuration values instead of hardcoded URLs. Add comprehensive comments documenting that this is a required external service dependency for all user authentication.

---

#### FINDING-126: Absence of Comprehensive Communication Architecture Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.1.1 |
| **Files** | `v3/server/config.yaml.example`, `v3/server/main.py:38`, `v3/server/main.py:40` |
| **Source Reports** | 13.1.1.md |
| **Related Findings** | None |

**Description:**

ASVS 13.1.1 at Level 2 requires all communication needs to be documented. The current `config.yaml.example` serves as the primary configuration documentation but provides incomplete coverage of the application's communication architecture. Only 3 out of 8 communication channels are documented: inbound HTTP/HTTPS server port, TLS configuration, and SQLite database. Undocumented channels include outbound OAuth endpoints, LDAP backend, inter-process CLI tallying tools, and OAuth callbacks. A security auditor performing ASVS Level 2 compliance verification would fail the audit due to incomplete documentation.

**Remediation:**

Add comprehensive communication architecture documentation section to `config.yaml.example` that includes: (1) COMMUNICATION OVERVIEW section documenting all inbound, outbound, local, and user-controllable communication channels, (2) Configuration parameters for all external services including OAuth and LDAP, (3) Documentation that the application does not connect to user-specified URLs, (4) Documentation of inter-process communication patterns with CLI tools accessing the shared SQLite database.

---

#### FINDING-127: Debug Logging Level Enabled by Default in Both Run Modes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | None specified |
| **ASVS Sections** | 13.1.1, 13.3.1, 13.3.2, 13.4.2, 13.4.5 |
| **Files** | `v3/server/main.py:50`, `v3/server/main.py:91`, `v3/steve/election.py` |
| **Source Reports** | 13.1.1.md, 13.3.1.md, 13.3.2.md, 13.4.2.md, 13.4.5.md |
| **Related Findings** | None |

**Description:**

Both the standalone and ASGI (Hypercorn production) code paths configure `logging.DEBUG` as the default level. The `config.yaml.example` has no documented log-level setting. This creates a risk of sensitive data exposure in production logs. Evidence shows commented debug prints of cryptographic material (SALT, KEY) in election.py. If developers add debug logging during troubleshooting, vote tokens and encryption keys would appear in production logs, potentially exposing cryptographic material to log aggregation systems.

**Remediation:**

Add logging configuration to `config.yaml.example` with a `log_level` parameter defaulting to INFO for production. Update both `run_asgi()` and `run_standalone()` functions in `main.py` to read the log level from configuration using `app.cfg.server.get('log_level', 'INFO')`. Include inline comments warning that DEBUG level should not be used in production to prevent sensitive data exposure in logs.

---

#### FINDING-128: No Web Server Concurrency Limits Configured or Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 13.1.2 |
| **Files** | `v3/server/config.yaml.example`, `v3/server/main.py:50-88`, `v3/server/main.py:91-108`, `v3/server/main.py:78-80`, `v3/server/main.py:103-108` |
| **Source Reports** | 13.1.2.md |
| **Related Findings** | None |

**Description:**

The server configuration and startup code define no maximum concurrent connections, worker limits, request queue sizes, or keepalive timeouts. The `config.yaml.example` only specifies port and TLS settings. Neither standalone nor ASGI mode documents or configures concurrency boundaries. Without documented and configured connection limits, the application relies entirely on the default behavior of asfquart/Hypercorn, which may accept thousands of concurrent connections. Combined with the database and Argon2 resource issues, this creates a multiplier effect for resource exhaustion. Operations teams have no documented guidance on capacity planning or expected failure modes.

**Remediation:**

1. Add server concurrency configuration to config.yaml.example with parameters: max_connections (100), workers (2), keepalive_timeout (30 seconds), request_timeout (60 seconds), and documented behavior when max_connections reached (new connections receive 503). 2. For Hypercorn ASGI deployment, document and provide a hypercorn.toml configuration file with bind address, workers (2), backlog (100), and graceful_timeout (10 seconds).

---

#### FINDING-129: No OAuth Service Connection Limits or Failure Handling Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-1188 |
| **ASVS Sections** | 13.1.2, 13.1.3, 13.2.6 |
| **Files** | `v3/server/main.py:35-38`, `v3/server/main.py:32-37`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.1.2.md, 13.1.3.md, 13.2.6.md |
| **Related Findings** | None |

**Description:**

The application integrates with an external OAuth service (`oauth.apache.org`) for authentication. There is no documented or configured connection limit, timeout, retry policy, or fallback behavior for when the OAuth service is unreachable or slow. The URLs are hardcoded with no resilience configuration. If `oauth.apache.org` becomes slow or unresponsive, authentication requests will hang indefinitely (no timeout configured), consuming server resources (connections, worker threads). A slowloris-style attack against the OAuth provider or DNS manipulation could cause cascading failure in the voting application. No documentation exists for operators on how to detect or respond to OAuth service degradation.

**Remediation:**

Document OAuth service dependencies and limits in configuration with parameters: base_url (https://oauth.apache.org), connect_timeout (5 seconds), read_timeout (10 seconds), max_retries (2), circuit_breaker_threshold (5 failures before opening circuit), fallback behavior (display 'Authentication service unavailable' page), and recovery mechanism (auto-retry after 30 seconds). Add timeout configuration to config.yaml.example and enforce it in the OAuth client using httpx.AsyncClient with timeout configuration.

---

#### FINDING-130: Configuration Template Lacks Secret Management Guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-1059 |
| **ASVS Sections** | 13.1.4 |
| **Files** | `v3/server/config.yaml.example:1-22` |
| **Source Reports** | 13.1.4.md |
| **Related Findings** | FINDING-040, FINDING-249 |

**Description:**

The configuration template (config.yaml.example) is the primary operational reference for deploying the application. It contains no guidance about which values are security-sensitive, how secrets should be injected (e.g., environment variable overrides via asfquart), or what file permissions should be applied. The domain context indicates the application supports environment variable integration via asfquart, but this capability is completely undocumented in the template.

**Remediation:**

Replace config.yaml.example with comprehensive version including: security checklist before deployment, warnings about file permissions (0600 for config.yaml, TLS keys, database), documentation of environment variable overrides (STEVE_PORT, STEVE_CERTFILE, STEVE_KEYFILE, STEVE_DB, STEVE_OAUTH_SECRET), inline comments marking security-critical sections, deployment verification commands. Create/update .gitignore to exclude config.yaml, *.db, certs/*.pem, .env files. Create validate_config.py script to check file permissions and required environment variables before deployment.

---

#### FINDING-131: Data Layer Database Access Lacks Authentication Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.2.1 |
| **Files** | `v3/steve/election.py:40`, `v3/steve/election.py:46`, `v3/steve/election.py:365`, `v3/steve/election.py:381`, `v3/steve/election.py:390`, `v3/steve/election.py:402`, `v3/steve/election.py:412` |
| **Source Reports** | 13.2.1.md |
| **Related Findings** | None |

**Description:**

The database stores high-value cryptographic material: `opened_key` (Argon2 hash enabling vote token derivation), per-voter `salt` values (enabling vote decryption when combined with opened_key), and encrypted vote ciphertext. While SQLite is an in-process library without native authentication, ASVS 13.2.1 requires data layer access to be authenticated. No compensating controls exist — the code does not verify file ownership, permissions, or employ database-level encryption (e.g., SQLCipher). Any process running as the same user can open the database and extract `opened_key` and `salt` values, which are sufficient to derive vote tokens and decrypt all votes.

**Remediation:**

Add file permission verification in open_database() to ensure restrictive permissions (0o600 or stricter). Verify that database files are not accessible by group or other users. Set restrictive permissions on newly created databases. Consider SQLCipher or application-level database encryption for the `opened_key` and `salt` columns. Example implementation: verify file permissions using stat module, raise PermissionError if permissions are too permissive (group or other read/write), and explicitly set 0o600 permissions after database creation.

---

#### FINDING-132: OAuth Backend Communication Lacks Visible Credential Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.2.1 |
| **Files** | `v3/server/main.py:39-43`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.2.1.md |
| **Related Findings** | None |

**Description:**

The application performs a backend-to-backend HTTP call to `oauth.apache.org/token` during the OAuth token exchange, which requires OAuth client credentials (`client_id` and `client_secret`). However, config.yaml.example contains zero credential-related configuration — no OAuth settings, no environment variable references, no vault integration examples. main.py configures OAuth URLs but no visible credential passing. The asfquart framework presumably manages OAuth client secrets, but this is opaque from the application's perspective. No documentation in the configuration template indicates how secrets should be provided (environment variables, vault references, etc.).

**Remediation:**

Update config.yaml.example to document the expected secret management pattern using environment variables (e.g., STEVE_OAUTH_CLIENT_ID, STEVE_OAUTH_CLIENT_SECRET). Add explicit documentation that credentials must NOT be placed in the config file and should be rotated quarterly. In application code, verify credential source at startup and warn if secrets appear to be literal values rather than environment variable references. Provide deployment documentation for all required environment variables. Ensure the asfquart framework supports external credential configuration.

---

#### FINDING-133: All Database Connections Use Uniform Read-Write Privileges Without Least-Privilege Separation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.2.2 |
| **Files** | `v3/steve/election.py:~45` |
| **Source Reports** | 13.2.2.md |
| **Related Findings** | None |

**Description:**

All database operations, regardless of whether they require read or write access, use the same connection type with full read-write privileges. There is no mechanism to open read-only database connections for operations that only query data. Read-only operations (listing elections, checking vote status, retrieving metadata, tallying) hold connections capable of writing to the database. If any code path is compromised, the existing connection has full write access even when the intended operation is read-only. The `__getattr__` proxy means any code with an `Election` reference can invoke any database cursor, including `c_delete_election`, `c_delete_issues`, etc.

**Remediation:**

Implement separate read-only and read-write database connection methods. Modify `open_database()` to accept a `readonly` parameter. For SQLite, use URI mode with `?mode=ro` or execute `PRAGMA query_only = ON` after connection. Apply `readonly=True` to class methods: `open_to_pid()`, `owned_elections()`, `upcoming_to_pid()`, `list_closed_election_ids()`, and instance methods: `tally_issue()`, `has_voted_upon()`, `get_metadata()`. Add explicit connection closing with try/finally blocks in class methods. Review and restrict the `__getattr__` proxy scope to prevent unintended database operations through attribute access.

---

#### FINDING-134: Missing Centralized Allowlist for External Communications

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.2.4, 13.2.5 |
| **Files** | `v3/server/config.yaml.example:entire file`, `v3/server/main.py:43-46` |
| **Source Reports** | 13.2.4.md, 13.2.5.md |
| **Related Findings** | None |

**Description:**

The application configuration (config.yaml.example) defines no allowlist of permitted external resources. The application communicates with at least one external service (oauth.apache.org), and the domain context indicates LDAP and potentially email services are also used. No centralized, configurable allowlist exists to define and restrict these communications. This creates multiple risks: (1) No single auditable location documents all permitted external communications, (2) If any code path makes outbound requests based on user-controlled data, there is no enforcement mechanism to prevent SSRF or unauthorized data exfiltration, (3) New external integrations can be added without updating a central policy, (4) Deployment hardening cannot reference an application-defined list for firewall rules.

**Remediation:**

Add an external communications allowlist to the application configuration with sections for oauth, ldap, and other external resources, specifying host, port, protocol, and purpose for each. Implement an enforcement wrapper (OutboundAllowlist class) for outbound connections that validates URLs against the configured allowlist before permitting connections. The wrapper should parse URLs, extract hostname and port, and raise PermissionError for non-allowlisted destinations.

---

#### FINDING-135: OAuth Redirect URI Not Validated Against Allowlist

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.2.4 |
| **Files** | `v3/server/main.py:43-46` |
| **Source Reports** | 13.2.4.md |
| **Related Findings** | None |

**Description:**

The OAuth redirect_uri parameter in OAUTH_URL_INIT is constructed using string formatting (%s), and the value that populates this parameter comes from the asfquart framework (not visible in provided code). If the redirect_uri is derived from request-controlled data (e.g., the Host header) without validation against an allowlist of permitted callback URLs, this could allow an attacker to redirect OAuth callbacks to an attacker-controlled server, capturing authorization codes. This could lead to OAuth authorization code theft enabling account takeover, particularly impactful for election administrators.

**Remediation:**

Define an explicit allowlist for permitted OAuth redirect URIs in the configuration file (e.g., oauth.allowed_redirect_uris containing https://steve.apache.org/oauth/callback and staging variants). Validate the redirect URI against the allowlist in the create_app() function, ensuring the redirect_uri is taken from the allowlist rather than derived from request data. Use urllib.parse.quote to properly encode the allowlisted redirect URI.

---

#### FINDING-136: State-Checking Operations Unnecessarily Retrieve Full Secret Material

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.3.2 |
| **Files** | `v3/steve/election.py:125`, `v3/steve/election.py:329`, `v3/steve/election.py:318`, `v3/steve/election.py:322`, `v3/steve/election.py:326`, `v3/steve/election.py:135`, `v3/steve/election.py:78` |
| **Source Reports** | 13.3.2.md |
| **Related Findings** | None |

**Description:**

The `_all_metadata()` method retrieves complete election metadata including cryptographic secrets (`salt` and `opened_key`) for every call, even when the calling code only needs to check state or retrieve non-sensitive metadata. Six different methods call `_all_metadata()` when they only need NULL/NOT-NULL checks or non-secret fields. The `opened_key` (master election secret enabling vote decryption) is loaded into memory during every state check, metadata request, and election data gathering — operations that have no need for the actual key values. If any exception handler, debugger, or future logging change captures local variables, `md.salt` and `md.opened_key` would be exposed.

**Remediation:**

Create a separate state-only query and method that returns only the information needed for state computation. Add a new query `q_state_info: SELECT closed, (salt IS NOT NULL) AS has_salt, (opened_key IS NOT NULL) AS has_key FROM metadata WHERE eid = ?` and implement `_get_state_info()` method that returns state-relevant metadata WITHOUT secret columns. Refactor `get_state()` and related methods to use `_get_state_info()` instead of `_all_metadata()` for state checking operations. Create `_compute_state_from_flags()` method that works with boolean flags instead of actual secret values.

---

#### FINDING-137: Unrestricted Database Cursor Proxy Bypasses Secret-Filtering Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.3.2 |
| **Files** | `v3/steve/election.py:44` |
| **Source Reports** | 13.3.2.md |
| **Related Findings** | None |

**Description:**

The `Election` class implements `__getattr__()` to proxy database cursor access, which allows any code with an `Election` instance to bypass the intentional secret-filtering in `get_metadata()` by directly accessing `q_metadata` cursor. The developer intentionally created `get_metadata()` to filter `salt` and `opened_key` from public access, but the `__getattr__` proxy makes the underlying secret-returning cursor equally accessible. Any module that imports and uses the `Election` class (API handlers, page handlers, CLI tools) can directly access `q_metadata` and retrieve full secrets without going through the filtering method. This creates false confidence that secrets are protected by the `get_metadata()` abstraction.

**Remediation:**

Restrict the `__getattr__` proxy to only expose safe cursors, or make secret-accessing operations require explicit method calls. Option 1: Implement allowlist-based proxy with `_SAFE_PROXIED_ATTRS` frozenset containing only safe cursor names, and raise AttributeError for non-allowed attributes. Option 2: Create private methods like `_get_opened_key()` for explicit secret access required only for vote operations, and remove cursor proxying entirely for secret-containing queries.

---

#### FINDING-138: No Configuration Mechanism to Disable Debug Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.4.2, 13.4.5 |
| **Files** | `v3/server/main.py:51-87`, `v3/server/main.py:90-107`, `v3/server/config.yaml.example:entire file` |
| **Source Reports** | 13.4.2.md, 13.4.5.md |
| **Related Findings** | None |

**Description:**

The configuration schema has no mechanism to control debug behavior. Both execution paths (standalone and ASGI) hardcode DEBUG logging with no conditional logic to check environment or configuration settings. The config.yaml.example template contains no debug, log_level, or environment settings. Every deployment — whether standalone or ASGI — runs with DEBUG logging by default with no documented or implemented way to change this via configuration. Operators deploying the application have no way to harden logging without modifying source code, violating the principle that production configurations should be hardened by default. The standalone mode also uses app.runx() with extra_files for hot-reloading, which is a development feature. If run_standalone() is used in production, file-watching and reloading capabilities are active.

**Remediation:**

Extend configuration schema and implement environment-aware defaults. Add server.debug (default: false) and server.log_level (default: INFO) to config.yaml.example. Create a _configure_logging(cfg) function that reads these settings and configures logging appropriately. In run_standalone(), only enable extra_files watching and hot-reloading when debug mode is explicitly enabled. Implement conditional logic: if getattr(app.cfg.server, 'debug', False): enable debug features and log warning; else: use production-safe settings with no file watching.

---

#### FINDING-139: No Explicit HTTP TRACE Method Blocking at Application or Server Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 13.4.4 |
| **Files** | `v3/server/main.py:33-45`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.4.4.md |
| **Related Findings** | None |

**Description:**

The application relies entirely on Quart's implicit behavior (returning 405 for methods not registered on any route) to prevent TRACE handling. There is no explicit, defense-in-depth control: (1) No application middleware exists to reject TRACE requests before route dispatch. (2) No server configuration includes HTTP method restrictions. (3) No reverse proxy configuration is included in the codebase, despite the comment stating 'Typical usage is that a proxy sits in front of this server.' The proxy configuration, which would be the primary defense point, is not provided or templated. (4) No ASGI middleware is registered that would block TRACE before it reaches routing logic. While Quart's default behavior provides implicit protection (no route explicitly accepts TRACE), this is fragile: A catch-all error handler or routing change could inadvertently respond to TRACE. If TRACE is inadvertently enabled, an attacker could use Cross-Site Tracing (XST) to reflect HTTP request headers including authentication cookies and tokens, bypass HttpOnly cookie protections when chained with XSS, and leak OAuth session tokens used for voter authentication.

**Remediation:**

Add explicit TRACE blocking middleware to the application: In main.py, after app creation, add a before_request handler that checks if request.method == 'TRACE' and aborts with 405. Additionally, provide a production reverse proxy configuration template (nginx or Apache httpd) that blocks TRACE and TRACK methods at the infrastructure level. For nginx: use 'if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }'. For Apache: use 'TraceEnable Off'. Also add integration tests that verify TRACE returns 405 across all endpoints, and document the expected production deployment architecture including proxy TRACE blocking in a deployment guide.

---

#### FINDING-140: Hypercorn Server Header Exposes Backend Component Identity and Version

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 13.4.6 |
| **Files** | `v3/server/main.py:32-42`, `v3/server/main.py:82-103`, `v3/server/config.yaml.example:entire file` |
| **Source Reports** | 13.4.6.md |
| **Related Findings** | None |

**Description:**

The application uses Hypercorn as its production ASGI server and does not suppress the default 'Server' response header. Hypercorn sends a 'Server' response header on every HTTP response (e.g., 'server: hypercorn-h11' or 'server: hypercorn-h2'), which directly discloses the server software name and transport protocol version to any client. Neither the application startup code nor the configuration template includes any mechanism to suppress or override this header. An attacker can fingerprint the backend technology stack without any application interaction, enabling targeted attacks against known Hypercorn vulnerabilities.

**Remediation:**

Option A (recommended): Create a hypercorn.toml configuration with 'include_server_header = false' and launch with 'hypercorn --config hypercorn.toml main:steve_app'. Option B: Add after-request middleware in create_app() to strip Server and X-Powered-By headers using '@app.after_request' decorator. Option C: Add 'suppress_server_header: true' to config.yaml server section and apply during app creation.

---

#### FINDING-141: Missing Custom Error Handlers Allow Default Framework Error Pages

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 13.4.6 |
| **Files** | `v3/server/main.py:32-42` |
| **Source Reports** | 13.4.6.md |
| **Related Findings** | None |

**Description:**

The create_app() function does not register any custom error handlers for HTTP error codes (400, 404, 405, 500, etc.). Quart-based frameworks (which asfquart wraps) generate default error pages that can reveal the framework name, version, and in DEBUG-adjacent configurations, full Python stack traces including library paths and versions. Additionally, the run_asgi() production path configures the root logger at DEBUG level, increasing verbosity of information available if any unhandled exception propagates to the default error handler. Default error pages disclose the web framework name and version, and unhandled exceptions can expose Python version, library paths, and dependency versions.

**Remediation:**

Register custom error handlers for all standard HTTP error codes (404, 405, 500) and a catch-all exception handler using @app.errorhandler decorators that return generic JSON responses without framework details. Log detailed errors server-side only. Additionally, set production logging level to INFO rather than DEBUG in run_asgi() function.

---

#### FINDING-142: Sensitive Data Files Co-located in Application Directory Without File-Extension Serving Restrictions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 13.4.7 |
| **Files** | `v3/server/config.yaml.example:34`, `v3/server/main.py:28`, `v3/steve/election.py` |
| **Source Reports** | 13.4.7.md |
| **Related Findings** | None |

**Description:**

The SQLite database (steve.db), configuration file (config.yaml), query definitions (queries.yaml), TLS private key (*.pem), and Python source files (.py) all reside within or directly adjacent to the application directory tree. While static_folder=None prevents the Quart framework from serving these files, the documented deployment model uses a reverse proxy, and no proxy configuration is provided or enforced to restrict served file types. If the reverse proxy is misconfigured or a new route handler is added that inadvertently serves file contents, an attacker could obtain the SQLite database containing all election data, encrypted votes, cryptographic salts, and opened_keys, TLS private keys enabling man-in-the-middle attacks, application source code enabling targeted vulnerability discovery, and Git history potentially containing committed secrets.

**Remediation:**

1. Move sensitive data files outside the application directory tree (use absolute paths like /var/lib/steve/steve.db for database and /etc/steve/certs for certificates). 2. Add application-level middleware to restrict response content types to only allowed types (text/html, application/json, text/css, application/javascript). 3. Provide and document required reverse proxy configuration with file extension blocking rules for sensitive extensions (.db, .sqlite, .yaml, .yml, .py, .pyc, .pem, .key, .git, .env, .cfg, .ini, .log) and hidden files/directories.

---

#### FINDING-143: No Documented or Enforced Production Web Tier Hardening for File-Type Restrictions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 13.4.7 |
| **Files** | `v3/server/main.py`, `v3/server/config.yaml.example:21-23` |
| **Source Reports** | 13.4.7.md |
| **Related Findings** | None |

**Description:**

The config.yaml.example references a reverse proxy deployment model, but the codebase contains no reverse proxy configuration templates, deployment hardening documentation, or automated configuration validation to ensure file extension restrictions are applied in production. ASVS 13.4.7 Level 3 requires verification that the web tier (not just the application framework) restricts served file types. Without enforceable proxy configuration, this requirement cannot be verified as satisfied. Neither the standalone mode nor the ASGI/Hypercorn mode configures file-extension restrictions at the ASGI server level.

**Remediation:**

1. Include a production reverse proxy configuration template in the repository (e.g., v3/deploy/nginx.conf.example with file extension restrictions, deployment-checklist.md, and hardening.md). 2. Add a startup check that verifies the application is not directly exposed on ports 80/443 and warns if no proxy is detected. 3. Add ASGI middleware to reject requests for common sensitive extensions (.db, .sqlite, .yaml, .yml, .py, .pyc, .pem, .key, .env, .cfg, .ini, .log, .git, .bak, .swp, .old) as defense-in-depth.

---

#### FINDING-144: Voter-Issue Timing Correlation Recorded in Application Logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-532 |
| **ASVS Sections** | 14.1.2, 14.2.4 |
| **Files** | `v3/server/pages.py:425`, `v3/server/pages.py:426`, `v3/server/pages.py:427`, `v3/schema.sql` |
| **Source Reports** | 14.1.2.md, 14.2.4.md |
| **Related Findings** | FINDING-045 |

**Description:**

Per-issue vote logging in `do_vote_endpoint` creates a timing side channel that enables voter-vote correlation. Each vote submission triggers a separate log entry with timestamp and voter identity (`User[U:{result.uid}] voted on issue[I:{iid}]`). Combined with the `vote` table's auto-incrementing `vid` column, attackers with access to both application logs and database can correlate which votes belong to which voters through timing analysis. Vote content (votestring) is correctly excluded from logs, but the per-issue logging creates a record of exactly which issues each voter voted on. Log files maintained for operational purposes contain voter-to-issue correlations that persist beyond the election lifecycle. In elections where some issues are more sensitive than others, or where abstention patterns are meaningful, this creates an audit trail that could be used to infer voting behavior.

**Remediation:**

Replace per-issue vote logging with aggregated ballot submission logging. Log only once after all votes are submitted: `_LOGGER.info(f'User[U:{result.uid}] submitted ballot for election[E:{election.eid}] ({vote_count} issue(s))')`. This prevents timing correlation while maintaining audit capability.

---

#### FINDING-145: External Image Loaded on All Pages Leaks Voter Activity Metadata to Third-Party Server

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | None specified |
| **ASVS Sections** | 14.2.3 |
| **Files** | `v3/server/templates/header.ezt:22` |
| **Source Reports** | 14.2.3.md |
| **Related Findings** | None |

**Description:**

The application's navigation header includes an external image resource loaded from https://www.apache.org/foundation/press/kit/feather.svg. This image is automatically fetched by the browser on every page load, including sensitive voting pages. The HTTP request to apache.org transmits voter metadata outside the application's control, creating an externally-observable record of voting activity. The request transmits voter IP address, User-Agent header, Referer header (potentially including election ID), and precise timestamp of page access. No referrerpolicy attribute is set on the &lt;img&gt; tag and no Referrer-Policy HTTP header or &lt;meta&gt; tag is configured in the application.

**Remediation:**

Download and host the Apache feather logo locally. Download the image to v3/server/static/img/feather.svg and update header.ezt to use local path: &lt;img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top"&gt;. Add a Referrer-Policy header at the application level: response.headers['Referrer-Policy'] = 'same-origin'. Optionally add CSP to prevent future external resource inclusion: response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'".

---

#### FINDING-146: Voting Page Returns All Election Issues Regardless of Per-Issue Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 14.2.6 |
| **Files** | `v3/server/pages.py:244-270` |
| **Source Reports** | 14.2.6.md |
| **Related Findings** | None |

**Description:**

The voting page performs a coarse-grained eligibility check (does the voter have ANY mayvote entries for this election?) but then returns ALL issues for the election, including issues the voter is not authorized to vote on. The mayvote table is designed for per-issue authorization, but the voting interface ignores this granularity. In elections where different voter groups are authorized for different issues, a voter authorized for even one issue sees all issues and their full descriptions, including STV candidate lists embedded in client-side JavaScript.

**Remediation:**

Filter list_issues() results in vote_on_page() to return only issues the voter is authorized for based on their mayvote entries. Query q_find_issues to get authorized issue IDs, then filter the results from list_issues() to include only those issues where iid is in the authorized set before rendering the template.

---

#### FINDING-147: List Query Methods Return Raw Database Rows Without Sensitive Field Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 14.2.6 |
| **Files** | `v3/steve/election.py:410`, `v3/steve/election.py:432`, `v3/server/pages.py:137`, `v3/server/pages.py:275` |
| **Source Reports** | 14.2.6.md |
| **Related Findings** | None |

**Description:**

The get_metadata() method implements explicit field filtering to exclude cryptographic material (salt, opened_key). However, the list-query methods (open_to_pid(), upcoming_to_pid()) return raw database rows without code-level field filtering. While owned_elections() has a defensive comment noting this concern, the other methods lack equivalent protections. These raw results are passed through postprocess_election() and directly into template contexts without any sensitive field stripping. If queries return election salt or opened_key columns, this cryptographic material enters the template rendering context, creating a defense-in-depth gap where a future template change could inadvertently expose this material.

**Remediation:**

Add consistent field filtering to list query methods. Implement a _safe_election_row() method that strips sensitive fields (salt, opened_key) and apply it to open_to_pid(), upcoming_to_pid(), and owned_elections() to ensure defense-in-depth consistency with get_metadata(). This method should explicitly construct an edict with only permitted fields rather than returning raw database rows.

---

#### FINDING-148: Superseded Votes Retained Indefinitely as Unnecessary Data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | None specified |
| **ASVS Sections** | 14.2.7 |
| **Files** | `v3/schema.sql`, `v3/steve/election.py:204-215`, `v3/steve/election.py:217-255` |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | None |

**Description:**

When a voter re-votes on an issue, the system creates a new vote row with the same vote_token but a new auto-incrementing vid. Only the most recent vote is used during tallying (q_recent_vote). The superseded votes serve no purpose but remain in the database indefinitely. For a system whose core goal is ballot secrecy, retaining the history of vote changes for each vote_token provides an unnecessary information channel, particularly the count of re-votes per token and their ordering. A voter who changes their vote 5 times will have 5 encrypted vote rows in the database. An attacker with database access can observe that a specific vote_token voted 5 times and potentially correlate timing of row insertions (via vid ordering) with other events.

**Remediation:**

Modify add_vote() to delete any previous vote(s) for the same token before inserting new one: self.db.conn.execute('BEGIN TRANSACTION'); self.c_delete_prior_votes.perform(vote_token); self.c_add_vote.perform(vote_token, ciphertext); self.db.conn.execute('COMMIT'). Add query to queries.yaml: c_delete_prior_votes: DELETE FROM vote WHERE vote_token = ?

#### FINDING-149: Person PII (Name, Email) Has No Practical Deletion Path

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 14.2.7 |
| **Files** | `v3/steve/persondb.py:51-64`, `v3/steve/persondb.py:30-40`, `v3/schema.sql` |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | - |

**Description:**

The person table stores PII (name, email) for all voters ever registered. While a delete_person() method exists, referential integrity constraints from the mayvote table prevent deletion of any person who has been associated with any election. The code comment explicitly acknowledges this limitation with no resolution ('maybe we just don't delete a person, ever?'). Voter PII accumulates without any lifecycle management. For a voting system that may serve many elections over years, this creates an ever-growing store of personal data with no ability to honor data subject deletion requests or comply with data minimization principles.

**Remediation:**

Implement anonymization as alternative to blocked deletion: def anonymize_person(self, pid): self.c_anonymize_person.perform(f'[redacted-{pid[:4]}]', f'redacted@invalid', pid). Add query: c_anonymize_person: UPDATE person SET name = ?, email = ? WHERE pid = ?. This replaces name and email with anonymized values while preserving referential integrity for mayvote/vote integrity.

---

#### FINDING-150: Documents Served Without Metadata Stripping or User Consent

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 14.2.8 |
| **Files** | `v3/server/pages.py:582-597`, `v3/server/pages.py:60-68` |
| **Source Reports** | 14.2.8.md |
| **Related Findings** | - |

**Description:**

The serve_doc() function in pages.py serves files directly from DOCSDIR using quart.send_from_directory() without stripping embedded metadata. Documents may contain sensitive information in metadata fields such as author names, organization details, creation/modification timestamps, revision history, software versions, GPS coordinates, embedded comments, or tracked changes. No metadata stripping occurs at ingestion or serving time, and no user consent mechanism exists for metadata retention. In a voting system where ballot secrecy and election integrity are paramount, leaked document metadata could expose the identity of election administrators, internal organizational workflow details, timing information about election preparation, or embedded sensitive content in revision history.

**Remediation:**

Implement metadata stripping for all documents either at ingestion time (preferred) or at serving time. Option A: Strip metadata at serving time using tools like exiftool, python-pdfkit, or Pillow before returning files. Option B (preferred): Strip metadata at upload/ingestion time in CLI tools that place documents into DOCSDIR, processing once rather than on every request. Additionally: (1) Add Content-Disposition: attachment headers to force download rather than inline rendering, (2) Validate docname parameter to prevent path traversal, (3) Restrict allowed file extensions to a safe whitelist, (4) Document metadata retention policy and add user consent mechanism where appropriate.

---

#### FINDING-151: Sensitive Voter Identity Data Stored in Session (Likely Cookie-Backed)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 14.3.3 |
| **Files** | `v3/server/pages.py:62-80`, `v3/server/pages.py:107-113` |
| **Source Reports** | 14.3.3.md |
| **Related Findings** | - |

**Description:**

The application stores sensitive voter identity data (PII) directly in the session object, which in Quart's default configuration is implemented as a client-side signed cookie. The session contains uid (voter identifier), fullname (voter full name), and email (voter email address). Additionally, flash messages stored in the session may contain election-specific data such as issue IDs and election titles, potentially revealing voter-to-issue mappings. The session cookie is base64-encoded and signed but not encrypted, making it readable by anyone with access to browser DevTools, file system, or via XSS if HttpOnly flag is not set. ASVS 14.3.3 allows session tokens in cookies but not sensitive data - a session token should be an opaque identifier, not a container for user PII.

**Remediation:**

Option 1 (Recommended): Configure a server-side session backend (Redis, filesystem, SQLAlchemy, memcached) so only an opaque session ID is stored in the browser cookie. Set SESSION_TYPE to appropriate backend, configure SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, and SESSION_COOKIE_SAMESITE='Lax'. Option 2: Minimize cookie-based session data by storing only the session identifier (uid) in the cookie and looking up user details server-side on each request from persondb. Option 3: If cookie-based sessions must be used with full data, encrypt the cookie contents using an encrypted serializer with URLSafeTimedSerializer. Additionally, verify session backend configuration is documented and add security flags HttpOnly=True, Secure=True, SameSite=Lax to session cookies.

---

#### FINDING-152: easydict Library Used Without Documented Risk Assessment

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.1.4 |
| **Files** | `v3/steve/election.py:24`, `v3/steve/election.py:146-156`, `v3/steve/election.py:216`, `v3/steve/election.py:259`, `v3/steve/election.py:310` |
| **Source Reports** | 15.1.4.md |
| **Related Findings** | - |

**Description:**

easydict is used pervasively throughout the Election class to wrap database results and return data structures. This library is a small utility package with a narrow contributor base, has no documented security review process, converts dict keys to object attributes which could mask key collisions or unexpected attribute access patterns, and is used to wrap security-sensitive data (election metadata including owner_pid, authz, salt, opened_key). Per ASVS 15.1.4 definition, a library that is poorly maintained or lacks security controls around its development processes qualifies as a risky component that must be highlighted in documentation.

**Remediation:**

1. Document easydict as a risky component per ASVS 15.1.4. 2. Consider replacing with Python standard library alternatives such as dataclasses (Python 3.7+) or typing.NamedTuple to eliminate dependency on minimally-maintained third-party library. Example: Use @dataclass decorator to create ElectionMetadata, IssueData, and VoteData classes with explicit type annotations for all fields including eid, title, owner_pid, authz, state, created, salt, opened_key, owner_name, and owner_email.

---

#### FINDING-153: Low-Level Argon2 API with Argon2d Variant Not Documented as Risky Decision

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-327 |
| **ASVS Sections** | 15.1.4, 15.1.5, 15.2.5 |
| **Files** | `v3/steve/crypto.py:23`, `v3/steve/crypto.py:87-101`, `v3/steve/crypto.py:125-145` |
| **Source Reports** | 15.1.4.md, 15.1.5.md, 15.2.5.md |
| **Related Findings** | FINDING-089 |

**Description:**

The code is in a transitional state between Fernet (AES-128-CBC + HMAC-SHA256) and XChaCha20-Poly1305 encryption. The HKDF parameters are already configured for the future algorithm (info=b'xchacha20_key', length=32 for XChaCha20), but the actual encryption still uses Fernet. This creates a mismatch between the key derivation context (info parameter) and actual usage. The TODO comment indicates planned changes to a cryptographic dependency, but no documentation captures this planned migration, its timeline, or associated risks. The info parameter in HKDF provides domain separation — using xchacha20_key as the info while actually using the key for Fernet means the cryptographic binding is technically incorrect. This represents undocumented technical debt in dangerous functionality.

**Remediation:**

1. Document the cryptographic migration plan in SECURITY.md or architecture documentation including timeline and risk assessment. 2. Fix the HKDF info parameter to match current usage by changing info=b'xchacha20_key' to info=b'fernet_vote_key_v1' to correctly reflect current Fernet usage. 3. Document the future XChaCha20-Poly1305 library dependency in the component risk assessment before adoption. 4. Document migration requirements including: current state (Fernet with correct info parameter), target state (XChaCha20-Poly1305 with new info parameter like b'xchacha20_vote_key_v1'), migration requirements (re-encryption of active election votes), and requirement that HKDF info MUST change to ensure domain separation. When migrating to XChaCha20-Poly1305, update the info parameter with appropriate documentation of the cryptographic library change and security review of the new dependency.

---

#### FINDING-154: cryptography.hazmat and argon2.low_level API Usage Not Documented as Dangerous Functionality

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.1.5 |
| **Files** | `v3/steve/crypto.py:25`, `v3/steve/crypto.py:26`, `v3/steve/crypto.py:23`, `v3/steve/crypto.py:62`, `v3/steve/crypto.py:92` |
| **Source Reports** | 15.1.5.md |
| **Related Findings** | - |

**Description:**

The codebase uses two explicitly dangerous low-level cryptographic APIs without formal documentation: cryptography.hazmat module (explicitly named 'hazardous materials' by maintainers) and argon2.low_level module (bypasses high-level safety features). The cryptography library's hazmat module documentation states: 'This is a Hazardous Materials module. You should ONLY use it if you're 100% absolutely sure that you know what you're doing.' The code contains only brief inline comments but no formal documentation that inventories all hazmat/low-level crypto usage, explains why high-level APIs were insufficient, documents the security review status, or identifies the specific risks of each operation.

**Remediation:**

Create a SECURITY.md or architecture document section that inventories dangerous functionality. Document each hazmat/low-level crypto usage including: what operation is performed, why low-level API was required instead of high-level alternatives, specific risks associated with the operation, and parameter choices. Example sections: (1) HKDF-SHA256 in _b64_vote_key: Operation: Key derivation using HKDF with SHA256; Why low-level: Need raw key bytes for Fernet, not password hashing; Risks: Incorrect salt/info usage could compromise key separation; Parameters: 32-byte output for Fernet, domain-specific info parameter. (2) Argon2 hashing in _hash: Operation: Memory-hard key derivation; Why low-level: Need raw hash output, not password verification format; Risks: Parameter misconfiguration could weaken security, Type.D vulnerable to side-channels; Parameters: time_cost=2, memory_cost=65536 (64MiB), parallelism=4.

---

#### FINDING-155: Repeated Vote Submissions Trigger Unbounded Argon2 Computation Without Throttling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.2 |
| **Files** | `v3/steve/election.py:266-280` |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | - |

**Description:**

The add_vote() method allows authenticated eligible voters to submit votes without any rate limiting or throttling mechanism. Each vote submission triggers an expensive Argon2 computation (64 MiB memory, 4 CPU threads, ~100ms) before validation or deduplication checks. The code includes a TODO comment acknowledging missing votestring validation, and there is no mechanism to prevent rapid repeated submissions. An authenticated eligible voter could script rapid repeated POST requests to the vote submission endpoint, forcing 1× Argon2 computation (64 MiB memory allocation, 4 CPU threads, ~100ms), 1× HKDF + Fernet encryption, and 1× database INSERT per request. At 10 concurrent requests/second, this consumes ~640 MiB peak memory and saturates 40 CPU threads, degrading service for all other users.

**Remediation:**

1. Validate votestring before expensive operations by checking issue existence and voter eligibility first. 2. Consider short-circuit check if identical vote already exists before computing expensive token. 3. Implement rate limiting at the web layer using quart_rate_limiter with conservative limits (e.g., 5 votes per minute per user). Example: @rate_limit(5, timedelta(minutes=1)) decorator on the vote submission endpoint.

---

#### FINDING-156: has_voted_upon() Performs O(N) Argon2 Operations Per Request Without Caching or Bounds

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.2 |
| **Files** | `v3/steve/election.py:350-375` |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | - |

**Description:**

The has_voted_upon() method iterates over all issues a voter is eligible for and computes an Argon2 hash for each one to generate vote tokens. This operation scales linearly with the number of issues (O(N)) and is likely called on every page load when voters view their election dashboard. There is no caching of computed vote tokens between requests and no upper bound on the iteration count. Each page load for a voter viewing their status triggers this entire computation. With 10 issues, this takes ~1.0s CPU time; with 50 issues, ~5.0s. With concurrent users refreshing the page, server CPU is rapidly saturated.

**Remediation:**

1. Bound the number of issues processed per request (e.g., MAX_ISSUES_PER_CHECK = 100) and raise TooManyIssues exception if exceeded. 2. Consider implementing a time-limited cache for vote status at the web layer to avoid re-computation on page refreshes. 3. Implement session-level caching of vote tokens to avoid repeated Argon2 computations within the same user session.

---

#### FINDING-157: tally_issue() Computes Argon2 for Every Eligible Voter Without Resource Bounds or Timeout

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.2 |
| **Files** | `v3/steve/election.py:282-348` |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | - |

**Description:**

The tally_issue() method queries all eligible voters for an issue and computes an Argon2 hash for each one to derive their vote token, regardless of whether they actually voted. This scales linearly with the number of eligible voters (O(N)) and can result in extremely long-running operations for large elections. While tallying is documented as a privileged CLI operation, the method itself has no enforcement of this restriction and would monopolize server resources if called during normal operations. With 100 eligible voters, this takes ~10s CPU time; with 1,000 voters, ~100s. On shared infrastructure, this degrades web application availability during tallying.

**Remediation:**

1. Log expected resource consumption before starting tally operations to provide visibility into resource impact. 2. Optionally yield control periodically during processing (e.g., every 50 voters) if using async operations. 3. Consider running tally operations in a separate process or with CPU affinity to isolate resource impact from the web server. 4. Implement progress callbacks to monitor long-running tally operations.

---

#### FINDING-158: Development benchmark function present in production crypto module

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.3 |
| **Files** | `v3/steve/crypto.py:129-158`, `v3/steve/crypto.py:160-162` |
| **Source Reports** | 15.2.3.md |
| **Related Findings** | - |

**Description:**

The crypto.py module contains a benchmark_argon2() function (lines 129-158) that is development/test code exposed in the production module. This function executes 8 CPU/memory-intensive Argon2 operations with up to 128MB memory each, creating a potential denial-of-service vector if reachable through any server-side codepath. The function uses hardcoded test salts and print() statements that write to stdout/logs, potentially exposing Argon2 tuning parameters and timing information. Additionally, the benchmark uses argon2.Type.ID while production uses argon2.Type.D, indicating it is purely development tooling that does not represent production behavior.

**Remediation:**

Move the benchmark to a separate development-only script (e.g., tools/benchmark_argon2.py) excluded from the production deployment package. Remove benchmark_argon2() function (lines 129-158), the if __name__ == '__main__' block (lines 160-162), and import time (line 26, if unused elsewhere) from crypto.py. Create separate file tools/benchmark_argon2.py with the benchmark code marked as NOT for production deployment.

---

#### FINDING-159: DEBUG logging level configured in production ASGI deployment path

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.2.3 |
| **Files** | `v3/server/main.py:85-96` |
| **Source Reports** | 15.2.3.md |
| **Related Findings** | - |

**Description:**

The run_asgi() function in main.py (lines 85-96) is the production code path triggered when the module is imported by Hypercorn. It unconditionally sets logging.DEBUG level on both the root logger and the application logger (_LOGGER.setLevel(logging.DEBUG) on line 96). This causes all application-level debug messages including cryptographic operations, database queries, and election state transitions to be written to production logs. While current debug messages in election.py are relatively benign, the DEBUG level setting means any future debug logging added anywhere in the application will automatically be exposed in production, creating a latent information disclosure risk characteristic of development configuration that was not hardened for production.

**Remediation:**

Change run_asgi() to use logging.INFO as the production-appropriate level. Implement environment variable override for log level configuration: use os.environ.get('STEVE_LOG_LEVEL', 'INFO').upper() to allow operational flexibility while defaulting to secure INFO level. Update both logging.basicConfig(level=logging.INFO) and _LOGGER.setLevel() to use the environment-driven configuration.

---

#### FINDING-160: Dependency confusion risk for ASF-namespaced internal package asfquart

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.2.4 |
| **Files** | `v3/server/main.py:32-38` |
| **Source Reports** | 15.2.4.md |
| **Related Findings** | - |

**Description:**

The asfquart package is an ASF-internal web framework wrapper that provides critical security infrastructure including OAuth integration, authentication, and application construction. This package presents an elevated dependency confusion risk. If asfquart is distributed via an internal ASF package repository and the name is not defensively registered on PyPI, an attacker could register asfquart on PyPI with a higher version number. If pip or uv is configured with --extra-index-url (adding internal repo alongside PyPI), the public malicious package could be preferred due to version precedence. The malicious package would execute during import, with full access to the OAuth configuration, authentication flow, and application construction. No configuration restricting the package index source was provided for audit.

**Remediation:**

1. Configure uv or pip to use exclusive index source for ASF packages using tool.uv.sources in pyproject.toml with explicit = true flag. 2. Defensively register the asfquart package name on PyPI (even as an empty placeholder) to prevent name squatting. 3. Configure uv or pip to use --index-url exclusively for ASF packages, preventing fallback to public PyPI. 4. Document the expected repository source for all internal packages.

---

#### FINDING-161: No SBOM documenting transitive dependency tree

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.2.4 |
| **Files** | `Project root (expected location):N/A` |
| **Source Reports** | 15.2.4.md |
| **Related Findings** | - |

**Description:**

The application's direct dependencies pull in significant transitive dependency chains including cryptography (cffi, pycparser, OS-level OpenSSL bindings), argon2-cffi (argon2-cffi-bindings, cffi, pycparser), asfquart (quart, hypercorn, h11, h2, wsproto, priority, hpack, and more), asfpy (PyYAML, requests, ldap3, and others), and easydict. None of these transitive dependencies are documented in the provided audit materials. Without an SBOM, vulnerabilities in transitive dependencies cannot be tracked, the full attack surface of the application is unknown, and compliance with ASVS 15.2.4's requirement to verify 'all of their transitive dependencies' cannot be satisfied. A compromised or vulnerable transitive dependency would go undetected.

**Remediation:**

1. Generate and maintain an SBOM using CycloneDX (cyclonedx-py environment -o sbom.json --format json) or syft. 2. Integrate SBOM generation into CI/CD pipeline. 3. Store SBOM artifacts with each release. 4. Implement automated vulnerability scanning against the SBOM. 5. Review transitive dependency changes during dependency updates. 6. Establish policy for regular SBOM review and transitive dependency audits.

---

#### FINDING-162: __getattr__ Proxy Undermines Encapsulation of Dangerous Database Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.2.5 |
| **Files** | `v3/steve/election.py:56` |
| **Source Reports** | 15.2.5.md |
| **Related Findings** | - |

**Description:**

The Election class defines explicit public methods with state-machine assertions to guard dangerous operations (e.g., delete() asserts is_editable()). However, the __getattr__ proxy exposes all database cursors defined in queries.yaml to any code holding an Election instance, completely bypassing the state-machine protections. This means a programming error in any API handler that creates an Election instance could inadvertently invoke destructive or state-bypassing database operations without the intended safety checks. For example, election.c_delete_election.perform(eid) can delete an election regardless of state, bypassing the assertion in the delete() method. This undermines protections around dangerous functionality.

**Remediation:**

Replace the open proxy with explicit, controlled delegation. Remove __getattr__ proxy entirely and define explicit private properties for needed cursors. Alternatively, use __getattr__ with an allowlist: define _ALLOWED_ATTRS as a frozenset explicitly listing each allowed cursor, and raise AttributeError if name is not in the allowlist.

---

#### FINDING-163: No Explicit Field Whitelist Enforcement on Form-Handling Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.3 |
| **Files** | `v3/server/pages.py:493`, `v3/server/pages.py:549`, `v3/server/pages.py:572`, `v3/server/pages.py:453` |
| **Source Reports** | 15.3.3.md |
| **Related Findings** | - |

**Description:**

All form-handling POST endpoints capture the complete form submission into an EasyDict object without validating or restricting the set of allowed fields. While individual handlers currently extract only specific fields (e.g., form.title, form.description), unexpected fields are silently accepted rather than rejected. The EasyDict class makes any form field accessible as an attribute, meaning any code that accesses form.attacker_field will succeed if the attacker included it in the submission. This creates a structural risk where any future code accessing form.&lt;field&gt; immediately trusts attacker input with no systematic defense preventing mass assignment when handlers evolve.

**Remediation:**

Implement explicit field whitelisting per action using a helper function. Create an ALLOWED_FIELDS dictionary mapping each action to its permitted fields. Implement an extract_allowed_fields() function that validates form data against the whitelist, logs unexpected fields, and returns HTTP 400 if unexpected fields are present. Example: ALLOWED_FIELDS = {'create_election': {'title'}, 'add_issue': {'title', 'description'}, 'edit_issue': {'title', 'description'}, 'vote': set()}. Apply this helper to all form-handling endpoints before processing the data.

---

#### FINDING-164: Vote Submission Handler Does Not Restrict Writable Issue IDs to Voter's Eligible Subset

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.3 |
| **Files** | `v3/server/pages.py:453`, `v3/steve/election.py:216` |
| **Source Reports** | 15.3.3.md |
| **Related Findings** | - |

**Description:**

The vote handler accepts vote-* form fields where the issue ID portion is entirely user-controlled from the form key name. The handler validates the issue ID against ALL issues in the election (issue_dict), not the subset the voter is eligible for. The actual eligibility check is in the model's add_vote() method, but it manifests as an AttributeError when accessing .salt on a None mayvote result—not as an explicit authorization decision. This creates two problems: (1) The mayvote check exists but isn't called explicitly—eligibility enforcement happens as a side effect of None attribute access, and (2) Partial batch processing where the loop processes votes sequentially with early return on error, meaning legitimate votes submitted before a failure are committed while later votes are not, leaving the voter in a partial state. The controller layer does not limit which issue IDs (fields) are valid per the specific voter's authorization, violating the ASVS 15.3.3 principle of limiting allowed fields per action.

**Remediation:**

Pre-filter eligible issue IDs at the controller level before processing any votes. In do_vote_endpoint(), query the voter's eligible issues using election.q_find_issues.perform(result.uid, election.eid) and create a set of eligible_iids. When processing vote-* form fields, validate each extracted iid against eligible_iids before accepting it. If an ineligible iid is submitted, log the attempt and return an error before processing any votes. Additionally, add an explicit eligibility check in add_vote() that raises a custom VoterNotEligible exception if mayvote is None, rather than relying on AttributeError. Consider wrapping the vote processing loop in a database transaction to ensure atomicity.

---

#### FINDING-165: Complete Absence of Client IP Address in Security Audit Logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.4, 16.2.1, 16.3.1 |
| **Files** | `v3/server/pages.py:115`, `v3/server/pages.py:405`, `v3/server/pages.py:412`, `v3/server/pages.py:434`, `v3/server/pages.py:446`, `v3/server/pages.py:459`, `v3/server/pages.py:475`, `v3/server/pages.py:492`, `v3/server/pages.py:510`, `v3/server/pages.py:524` |
| **Source Reports** | 15.3.4.md, 16.2.1.md, 16.3.1.md |
| **Related Findings** | - |

**Description:**

ASVS 16.2.1 requires 'where' metadata for detailed investigation. For web applications, the source IP address is essential context that is completely absent from all security log entries. Every state-changing operation logs user identity and action details, but never records the IP address from which the request originated. Without source IP addresses, security teams cannot: (1) Detect Compromised Accounts - cannot identify votes/actions from unexpected geolocations, (2) Correlate Multi-Account Attacks - cannot identify single attacker using multiple compromised accounts, (3) Investigate Incidents - cannot determine which requests were malicious during incident response, (4) Enforce Rate Limiting - cannot implement IP-based rate limiting or abuse prevention, (5) Meet Compliance Requirements - many election security standards require IP address logging for audit trails.

**Remediation:**

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

---

#### FINDING-166: No Trusted Proxy Configuration for IP Forwarding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.4 |
| **Files** | `v3/server/api.py`, `v3/server/pages.py` |
| **Source Reports** | 15.3.4.md |
| **Related Findings** | - |

**Description:**

The application has no configuration for trusted proxy headers. When deployed behind a reverse proxy (standard for production web applications), `request.remote_addr` returns the proxy's IP rather than the client's. The Quart framework supports `ProxyFix`-style middleware or explicit `X-Forwarded-For` parsing, but neither is configured. This means even if the application were to start reading IP addresses, it would obtain the wrong value. Without trusted proxy configuration, an attacker can spoof their IP by injecting headers directly. If the application naively reads `X-Forwarded-For` without validating the sender is a trusted proxy, any client can claim any IP address. This impacts any future IP-based security controls (rate limiting, geo-blocking) which would operate on incorrect data, audit logs would record proxy IPs instead of real client IPs, and spoofable headers could be used to bypass IP-based restrictions.

**Remediation:**

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

---

#### FINDING-167: Missing Type Validation on JSON Request Body

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.5 |
| **Files** | `v3/server/pages.py:93-113` |
| **Source Reports** | 15.3.5.md |
| **Related Findings** | - |

**Description:**

The _set_election_date function accepts JSON request bodies without validating that the parsed data is the expected type (dict) or that nested fields have the expected types (string for date). The code makes type assumptions that can lead to unhandled exceptions. quart.request.get_json() can return None if body isn't valid JSON, causing AttributeError. The date field could be int, bool, list, dict, or null, and fromisoformat() will raise TypeError for non-string inputs, which is not caught by the except ValueError block. This results in 500 errors with potential stack trace exposure and violates ASVS 15.3.5 by making type assumptions without verification.

**Remediation:**

Add explicit type validation after JSON parsing. Check that data is a dict using isinstance(data, dict), validate that date_str is a string using isinstance(date_str, str), and catch both ValueError and TypeError exceptions from fromisoformat(). Example: if not isinstance(data, dict): quart.abort(400, 'Invalid request body'); date_str = data.get('date'); if not isinstance(date_str, str) or not date_str: quart.abort(400, 'Missing or invalid date field'); try: dt = datetime.datetime.fromisoformat(date_str).date(); except (ValueError, TypeError): quart.abort(400, 'Invalid date format')

---

#### FINDING-168: Deserialized KV Data Used Without Type Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.5 |
| **Files** | `v3/steve/election.py:365`, `v3/server/pages.py:278-281`, `v3/steve/election.py:299` |
| **Source Reports** | 15.3.5.md |
| **Related Findings** | - |

**Description:**

The json2kv method deserializes JSON strings from the database without validating that the result is the expected type (dict). Consumers of this data throughout the application assume it's a dict and call .get() methods on it, which will fail if the deserialized value is a different JSON type (array, string, number, etc.). The method returns ANY JSON type (dict, list, str, int, bool, None) and consumers in pages.py and election.py assume dict type without verification. This causes runtime errors during election display or tallying. If KV data contains unexpected types for nested values (e.g., seats as a string instead of integer), tallying could silently produce incorrect results.

**Remediation:**

Add type validation to json2kv to ensure the deserialized value is a dict, and add field-level type checks for known KV fields. Example: if not j: return None; parsed = json.loads(j); if parsed is not None and not isinstance(parsed, dict): raise ValueError(f'KV data must be a JSON object, got {type(parsed).__name__}'); return parsed. Additionally implement _validate_kv function to check specific fields like seats (must be int) and labelmap (must be dict) for each vote type.

---

#### FINDING-169: Unsanitized JSON Object Keys in Data Pipeline to Client-Side Templates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-1321 |
| **ASVS Sections** | 15.3.6 |
| **Files** | `v3/steve/election.py:444-452`, `v3/steve/election.py:448`, `v3/steve/election.py:256`, `v3/server/pages.py:258-265` |
| **Source Reports** | 15.3.6.md |
| **Related Findings** | - |

**Description:**

The `labelmap` field in STV issue KV data is an arbitrary key-value dictionary where keys represent candidate labels. These keys are: 1) Deserialized from JSON without any key filtering (`json.loads()`), 2) Converted to an `EasyDict` without filtering, 3) Iterated to produce `candidates` list where each key becomes a `label` value, 4) Passed to the template for client-side rendering. If these labels are used to construct JavaScript objects on the client side (e.g., `{[label]: value}` or `Object.assign({}, labelData)`), keys like `__proto__`, `constructor`, or `prototype` could pollute JavaScript prototypes. The data flow is: Database KV column (JSON text) → json2kv() [election.py:448] — raw json.loads(), no key filtering → list_issues() [election.py:256] — returns edict with unfiltered KV → vote_on_page() [pages.py:258] — extracts labelmap as dictionary → issue.candidates list with arbitrary 'label' keys → EZT template rendering → client-side JavaScript. If client-side JavaScript constructs objects using these labels as keys, an attacker with write access to KV data could pollute JavaScript prototypes, potentially leading to XSS, authentication bypass, or denial of service on the client side.

**Remediation:**

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

---

#### FINDING-170: No Explicit Defense Against Intra-Source HTTP Parameter Pollution in Form-Processing Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 15.3.7 |
| **Files** | `v3/server/pages.py:405`, `v3/server/pages.py:448`, `v3/server/pages.py:508`, `v3/server/pages.py:532` |
| **Source Reports** | 15.3.7.md |
| **Related Findings** | - |

**Description:**

Quart's `request.form` returns a Werkzeug `MultiDict` that preserves multiple values for the same parameter name. When this `MultiDict` is passed to `EasyDict()` (which inherits from `dict`), the constructor calls `dict.__init__()`, which invokes `MultiDict.__getitem__()` for each unique key — returning only the first submitted value and silently discarding all subsequent duplicates. This means: (1) Duplicate parameters are silently dropped with no validation, logging, or error, (2) The application has no mechanism to detect or reject HTTP parameter pollution attempts, (3) The behavior (first-value-wins) is an implicit framework artifact, not an explicit security decision. The vulnerable pattern occurs at multiple endpoints where `edict(await quart.request.form)` is used, systematically destroying the MultiDict's ability to represent duplicate parameters.

**Remediation:**

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

---

#### FINDING-171: Batch Vote Submission Without Transactional Integrity

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3, L2 |
| **CWE** | CWE-362 |
| **ASVS Sections** | 15.4.1, 15.4.2, 15.4.3, 2.3.3, 2.3.4, 16.5.2, 16.5.3 |
| **Files** | `v3/server/pages.py:397-437`, `v3/server/pages.py:373-410`, `v3/server/pages.py:307-353`, `v3/steve/election.py:268-285` |
| **Source Reports** | 15.4.1.md, 15.4.2.md, 15.4.3.md, 2.3.3.md, 2.3.4.md, 16.5.2.md, 16.5.3.md |
| **Related Findings** | FINDING-030, FINDING-053 |

**Description:**

The vote submission endpoint processes multiple votes from a single user ballot submission by iterating through each vote and calling `add_vote()` individually. Each `add_vote()` call performs a single INSERT that auto-commits immediately in autocommit mode. If any vote in the sequence fails (e.g., election closes mid-batch or an error occurs), all previously committed votes remain in the database while subsequent votes are lost, resulting in a partial ballot submission. In a voting system, the user's ballot submission is the most critical business operation. A partial ballot violates voter intent—the user believed they were submitting all votes together. In elections with multiple issues, voters may have a partial set of votes recorded without clear feedback about which votes succeeded. The user receives a generic error message and is redirected, with no indication of partial success.

**Remediation:**

Create a new `add_votes()` batch method in `election.py` that wraps all vote insertions for a single ballot in a single transaction with explicit BEGIN IMMEDIATE/COMMIT/ROLLBACK. Use `BEGIN IMMEDIATE` before processing any votes in the loop, then commit after all votes are successfully processed. Update the `do_vote_endpoint()` to use this batch method instead of iterating through individual `add_vote()` calls. Implement proper rollback on any error and provide clear feedback to the user about success or complete failure. Consider creating an `add_vote_within_transaction()` method variant that doesn't manage its own transaction boundaries.

---

#### FINDING-172: Unbounded Synchronous Vote Processing Loop Amplifies Event Loop Starvation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.4.4 |
| **Files** | `v3/server/pages.py:399-432`, `v3/steve/election.py:231-244` |
| **Source Reports** | 15.4.4.md |
| **Related Findings** | - |

**Description:**

Vote submission loops over all issues synchronously, performing database reads, PBKDF key derivation, encryption, and database writes for each issue without yielding to the event loop. For elections with many issues, this creates extended blocking proportional to the number of issues. With N issues per election, total blocking time = N × (2 queries + PBKDF + Fernet encrypt + 1 insert). For an election with 20 issues, this results in ~100 synchronous blocking operations in a single request. Additionally, _all_metadata(self.S_OPEN) is re-queried on every iteration, performing redundant state checks that add unnecessary blocking time.

**Remediation:**

Offload each blocking vote operation to thread pool using asyncio.to_thread() within the vote processing loop. Alternatively, create a bulk add_votes_bulk() method that performs a single state check and wraps all inserts in one transaction, reducing per-vote overhead and caching the repeated metadata query.

---

#### FINDING-173: Web Server Log Timestamps Use Local Time Without Timezone Offset, Year, or Seconds

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.2, 16.2.4 |
| **Files** | `v3/server/main.py:23`, `v3/server/main.py:55-59`, `v3/server/main.py:85-91`, `v3/server/main.py:20, 51-56, 85-90`, `v3/server/pages.py:101`, `v3/server/pages.py:371`, `v3/server/pages.py:374`, `v3/server/pages.py:394-395`, `v3/server/pages.py:415`, `v3/server/pages.py:428`, `v3/server/pages.py:451`, `v3/server/pages.py:472-473`, `v3/server/pages.py:489-490` |
| **Source Reports** | 16.2.2.md, 16.2.4.md |
| **Related Findings** | - |

**Description:**

The web server logging configuration uses DATE_FORMAT = '%m/%d %H:%M' which produces timestamps in local time without timezone offset, year, or seconds. This violates multiple ASVS 16.2.2 requirements: no explicit timezone offset as required, no UTC enforcement as recommended, no year for cross-year correlation, and no seconds precision for event ordering. During DST transitions, timestamps become ambiguous and the same wall-clock time can occur twice, making forensic analysis of security events impossible.

**Remediation:**

Replace the DATE_FORMAT constant with ISO 8601 UTC format and explicitly set the formatter converter to time.gmtime. Example: DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'; formatter = logging.Formatter(fmt='[{asctime}|{levelname}|{name}] {message}', datefmt=DATE_FORMAT, style='{'); formatter.converter = time.gmtime. Apply the same pattern to both run_standalone() and run_asgi().

---

#### FINDING-174: Unsynchronized Logging Configuration Between Web Server and Tally CLI Components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.2, 16.2.4 |
| **Files** | `v3/server/main.py:23`, `v3/server/main.py:55-59`, `v3/server/main.py:85-91`, `v3/server/bin/tally.py:145`, `v3/server/bin/tally.py:148`, `v3/server/main.py:51-56`, `v3/steve/election.py:186`, `v3/steve/election.py:197`, `v3/steve/election.py:381` |
| **Source Reports** | 16.2.2.md, 16.2.4.md |
| **Related Findings** | - |

**Description:**

The web server (main.py) and tally CLI (tally.py) use completely different logging configurations with incompatible formats. The web server uses '[{asctime}|{levelname}|{name}] {message}' with '%m/%d %H:%M' timestamps in local time, while the tally CLI uses Python's default format '%(levelname)s:%(name)s:%(message)s' with no timestamps at all. This means the same security event from election.py produces fundamentally different log entries depending on the entry point, making SIEM correlation impossible and violating ASVS 16.2.2's requirement that 'time sources for all logging components are synchronized'.

**Remediation:**

Create a shared logging configuration module (v3/steve/log_config.py) used by all components. Define LOG_FORMAT, LOG_DATEFMT, and LOG_STYLE constants with a configure_logging() function that both entry points can call. Use ISO 8601 UTC format with time.gmtime converter to ensure consistency. Import and use in both main.py and tally.py.

---

#### FINDING-175: Production Web Endpoints Output Form Data to Undocumented stdout Channel via print()

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Sections** | 16.1.1, 16.2.3, 16.2.4, 16.2.5, 16.4.1, 14.1.1, 14.1.2, 14.2.4 |
| **Files** | `v3/server/pages.py:508`, `v3/server/pages.py:537`, `v3/server/pages.py:493`, `v3/server/pages.py:516`, `v3/server/pages.py:510, 531`, `v3/server/pages.py:482`, `v3/server/pages.py:499`, `v3/server/pages.py:489`, `v3/server/pages.py:513`, `v3/server/pages.py:447`, `v3/server/pages.py:467` |
| **Source Reports** | 16.1.1.md, 16.2.3.md, 16.2.4.md, 16.2.5.md, 16.4.1.md, 16.4.2.md, 14.1.1.md, 14.1.2.md, 14.2.4.md |
| **Related Findings** | FINDING-176, FINDING-182 |

**Description:**

Debug `print()` statements in `do_add_issue_endpoint` and `do_edit_issue_endpoint` output unfiltered form data to stdout, including issue titles, descriptions, and potentially CSRF tokens when implemented. The do_add_issue_endpoint() and do_edit_issue_endpoint() functions contain print('FORM:', form) statements that dump all form fields to stdout. All form data including issue titles, descriptions (which may contain confidential candidate information or election details), and any future form fields are written to stdout with uncontrolled retention characteristics. Process stdout may be captured by container logs, systemd journal, or process monitoring systems without appropriate access controls. This data flows to container logs, log aggregation systems (Docker, Kubernetes, CloudWatch), and is accessible to operators/administrators who should not see election content.

**Remediation:**

Remove all debug print statements from do_add_issue_endpoint() and do_edit_issue_endpoint(). If logging is needed for debugging, log only non-sensitive metadata such as election ID and user ID, never form field values in production. Replace with structured logging at DEBUG level if needed: `_LOGGER.debug(f'Issue form received for election[E:{election.eid}]')`. Configure logging to exclude DEBUG level in production environments. Implement structured logging with SensitiveFieldFilter that removes sensitive fields from log records.

---

#### FINDING-176: Log Injection via Unsanitized User-Controlled Input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Sections** | 16.1.1, 16.4.1, 16.3.3 |
| **Files** | `v3/server/pages.py:455`, `v3/server/pages.py:101`, `v3/server/pages.py:517`, `v3/server/pages.py:542`, `v3/server/pages.py:429-431`, `v3/server/pages.py:459` |
| **Source Reports** | 16.1.1.md, 16.4.1.md, 16.3.3.md |
| **Related Findings** | FINDING-175, FINDING-182 |

**Description:**

User-controlled input from form submissions is directly interpolated into log messages using f-strings without encoding newlines or other log control characters. An attacker can inject fake log entries by including newline characters in form fields, undermining log integrity for forensic analysis. Attackers can forge log entries to cover tracks or frame other users, log analysis tools may misparse injected entries, incident investigation can be misled by fabricated audit trails, and this undermines trust in the entire logging infrastructure. Specifically affects election title logging and other user-provided form fields.

**Remediation:**

Implement and use a sanitize_for_log() utility function that removes control characters and truncates long input before logging. Example: def sanitize_for_log(value: str, max_length: int = 200) -> str: if value is None: return '&lt;none&gt;'; sanitized = re.sub(r'[\r\n\t\x00-\x1f]', ' ', str(value)); if len(sanitized) > max_length: sanitized = sanitized[:max_length] + '...[truncated]'; return sanitized. Apply to all user-controlled values in logs including titles, descriptions, usernames, etc.

---

#### FINDING-177: Exception Details in Error Logs May Expose Sensitive Data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.1.1, 16.2.5 |
| **Files** | `v3/server/pages.py:419`, `v3/server/bin/tally.py:124`, `v3/server/pages.py:399-403`, `v3/server/bin/tally.py:115-118` |
| **Source Reports** | 16.1.1.md, 16.2.5.md |
| **Related Findings** | - |

**Description:**

Exception objects are directly interpolated into log messages. During vote processing and tally operations, exceptions from cryptographic operations or database layer could expose sensitive internal state including cryptographic parameters, SQL queries, or partial vote data. Cryptographic errors could expose key material, salts, or vote tokens in logs. Database errors could expose SQL queries with parameter values. Vote processing errors could leak partial vote content (violating ballot secrecy). Logs containing sensitive data become a high-value target for attackers.

**Remediation:**

Log only exception type names at ERROR level and restrict full exception details to DEBUG level. Example: except Exception as e: _LOGGER.error(f'Vote processing failed for user[U:{result.uid}] on issue[I:{iid}]: {type(e).__name__}'); _LOGGER.debug(f'Vote error details (issue[I:{iid}]): {e}', exc_info=True). Create a centralized safe_log_exception() utility function that returns only exception type.

---

#### FINDING-178: No Documented Log Inventory or Centralized Log Destination Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.2.3 |
| **Files** | `v3/server/main.py:58-63`, `v3/server/main.py:92-97`, `v3/server/bin/tally.py:157` |
| **Source Reports** | 16.2.3.md |
| **Related Findings** | - |

**Description:**

The application lacks a documented log inventory and uses only default logging destinations across all execution modes. No persistent log storage or centralized log destination is configured. Without a log inventory, it is impossible to verify that logs are only going to approved destinations. The three different logging configurations across execution modes (standalone, ASGI, CLI) mean logs may end up in different places depending on how the application is run, with no documentation of which destinations are approved. This makes compliance with ASVS 16.2.3 unverifiable.

**Remediation:**

1. Create a formal log inventory document specifying approved log destinations. 2. Centralize logging configuration using logging.config.dictConfig with defined handlers for console and file output. 3. Configure RotatingFileHandler for persistent audit logs with appropriate maxBytes and backupCount. 4. Add linting rules or code review checks to prevent print() in production modules. Example configuration provided in report shows structured logging setup with both console and file handlers.

#### FINDING-179: add_vote Crashes on Missing Voter Eligibility Record Instead of Failing Securely

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.2 |
| **Files** | `v3/steve/election.py:207-218` |
| **Source Reports** | 16.5.2.md |
| **Related** | - |

**Description:**

The add_vote method retrieves voter eligibility records from the database but does not check for null results. When a voter attempts to vote on an issue they're not eligible for, the database query returns None, and the subsequent access to mayvote.salt raises an AttributeError instead of a proper authorization failure. This results in insecure failure that pollutes the security audit trail with implementation errors instead of recording authorization failure events, and could mask attacks where users attempt to vote on unauthorized issues.

**Remediation:**

Add explicit null check after q_get_mayvote.first_row() call. If mayvote is None, log a security warning with details (user ID, issue ID) and raise a custom VoterNotEligible exception. This provides proper authorization failure handling with appropriate audit trail and prevents AttributeError from masking security events.

---

#### FINDING-180: CLI Tally Tool Lacks Top-Level Exception Handler

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.4 |
| **Files** | `v3/server/bin/tally.py:172-185`, `v3/server/bin/tally.py:125-126` |
| **Source Reports** | 16.5.4.md |
| **Related** | - |

**Description:**

The CLI tally tool, which processes election results and is likely run as a scheduled job or manual administrative task, lacks any top-level exception handling around the main() function call. Additionally, error handling within tally_election() uses print() instead of the configured logger, bypassing structured logging. When unhandled exceptions occur (e.g., database corruption, crypto errors, permission denied), the process crashes with a traceback on stderr, and the error is NOT captured in log files. The print() call specifically bypasses the configured _LOGGER, meaning tally errors won't reach any log aggregation system. This results in loss of error details critical for audit trails (which election, what went wrong) as they are not recorded in structured log format.

**Remediation:**

Wrap the main() call in the __main__ block with a try/except handler that: 1) Catches specific exceptions like ElectionNotFound with appropriate error codes, 2) Catches all other exceptions with critical-level logging including full traceback, 3) Exits with appropriate non-zero status codes. Replace the print() call in tally_election() with _LOGGER.error() to ensure errors are captured in structured logs with full context including issue IID and exception details.

---

#### FINDING-181: Input Validation and Business Logic Bypass Attempts Not Logged

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.3.3 |
| **Files** | `v3/server/pages.py:420-422`, `v3/server/pages.py:413-415`, `v3/server/pages.py:107-111` |
| **Source Reports** | 16.3.3.md |
| **Related** | - |

**Description:**

ASVS 16.3.3 specifically requires logging of attempts to bypass security controls, such as input validation, business logic, and anti-automation. The application performs input validation and business logic checks but does not log when these checks fail. This includes: invalid issue IDs in vote submissions, empty form submissions, invalid date formats, and other validation failures. This makes automated attacks, fuzzing attempts, and manipulation attempts invisible to security monitoring.

**Remediation:**

Add _LOGGER.warning() calls for all input validation failures with 'INPUT_VALIDATION_FAILED' prefix. Include user ID, resource being accessed, validation rule that failed, and the invalid value (sanitized). Example: _LOGGER.warning('INPUT_VALIDATION_FAILED: User[U:%s] submitted vote with invalid issue[I:%s] in election[E:%s]. valid_issues=%s', result.uid, iid, election.eid, list(issue_dict.keys())). Implement rate limiting on validation failures to prevent fuzzing attacks.

---

#### FINDING-182: Log Injection via URL Path Parameters in Election Constructor

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Section(s)** | 16.4.1 |
| **Files** | `v3/steve/election.py:40`, `v3/server/main.py:57` |
| **Source Reports** | 16.4.1.md |
| **Related** | FINDING-175, FINDING-176 |

**Description:**

The Election constructor logs the eid parameter before validating it against the database, allowing log injection through 11 different endpoints that use the @load_election decorator. Any authenticated committer (lower privilege than PMC member) can inject arbitrary log entries across 11 endpoints. The injection occurs before the election ID is validated against the database, so completely arbitrary content is logged. Attackers can forge entries that appear to show election openings, closings, or vote submissions by other users. The vulnerability is exploitable because both run_standalone() and run_asgi() set the root logger to logging.DEBUG level.

**Remediation:**

Option 1 (Preferred): Move log statement after validation. Log only after validation confirms this is a real election ID. Option 2: Sanitize before logging using safe_eid = re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', str(eid))[:64] before logging. Additionally, reduce production log level from DEBUG to INFO in main.py to prevent debug-level logs from being output in production.

---

#### FINDING-183: No Rate Limiting on Election Creation Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Section(s)** | 2.4.1, 2.4.2 |
| **Files** | `v3/server/pages.py:463-490` |
| **Source Reports** | 2.4.1.md, 2.4.2.md |
| **Related** | - |

**Description:**

The election creation endpoint lacks rate limiting, quota controls, cooldown periods, and maximum count restrictions. A compromised PMC member account can create unbounded elections at machine speed, causing: (1) database bloat and garbage-data creation, (2) quota exhaustion, (3) CPU resource consumption for cryptographic key derivation (per steve.crypto) for each election, (4) SQLite write contention degrading voter experience, (5) pollution of the election list, and (6) potential disk exhaustion on the server as SQLite has no inherent size limits. An attacker could create thousands of elections in seconds.

**Remediation:**

Implement two-tier rate limiting and quota controls: (1) Add per-user election creation quota with a configurable MAX_ELECTIONS_PER_USER limit and check the count of owned elections before allowing new creation. (2) Enforce a daily per-user creation limit (e.g., 5 elections per day) by adding an Election.count_created_today() method to query the database. (3) Add a per-user cooldown period (e.g., 30 seconds minimum between creation attempts) tracked in the session using 'last_election_create' timestamp. (4) Check all constraints before allowing creation and return appropriate error messages when quota or cooldown limits are reached.

---

#### FINDING-184: No Limits on Election Size (Issues per Election)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 2.4.1 |
| **Files** | `v3/server/pages.py:523-545` |
| **Source Reports** | 2.4.1.md |
| **Related** | - |

**Description:**

The issue creation endpoint has no limits on the number of issues per election and no rate limiting. An election with unbounded issues causes resource exhaustion during: (1) voting page load (election.list_issues() fetches all issues, random.shuffle() runs per STV issue), (2) tallying operations (each issue requires vote decryption and counting), and (3) vote submission (do_vote_endpoint iterates over all submitted votes with database writes per issue, causing extended write locks). A million-issue election would make tallying computationally infeasible and create denial-of-service conditions.

**Remediation:**

Enforce configurable maximum issues per election in do_add_issue_endpoint and maximum candidates per STV issue. Implement MAX_ISSUES_PER_ELECTION constant (e.g., 100) and MAX_CANDIDATES_PER_STV_ISSUE constant. Check current issue count before allowing new issue creation and validate candidate count for STV issues. Return appropriate error messages when limits are reached to prevent resource exhaustion attacks.

---

#### FINDING-185: Election State-Change Endpoints Lack Timing Controls and Use GET for Mutations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 2.4.2 |
| **Files** | `v3/server/pages.py:485-504`, `v3/server/pages.py:507-523` |
| **Source Reports** | 2.4.2.md |
| **Related** | - |

**Description:**

The election state-change endpoints (open/close) execute immediately upon GET requests with no timing controls, confirmation steps, or cooldowns. An election could be rapidly toggled between open and closed states at machine speed, disrupting active voters. Additionally, the use of GET methods for state-changing operations violates HTTP semantics and RESTful design principles. Combined with the lack of owner-only authorization ('### check authz' is commented out), any authenticated committer can toggle any election's state with no human-paced interaction required for critical election lifecycle operations.

**Remediation:**

Implement three security improvements: (1) Change HTTP methods from GET to POST for state-changing operations to comply with HTTP semantics and prevent CSRF attacks. (2) Add per-election state-change cooldown (e.g., 60 seconds) tracked in session using an 'election_state_{eid}' key to prevent rapid state toggling. (3) Implement owner authorization check to verify that metadata.owner_pid matches the acting user's UID before allowing state changes. Provide appropriate error messages (403 for authorization failures, warning flash for cooldown violations) and redirect to the management page.

---

#### FINDING-186: No Browser Security Feature Documentation or Degradation Behavior

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.1.1, 3.7.4 |
| **Files** | `v3/server/main.py:32-42` |
| **Source Reports** | 3.1.1.md, 3.7.4.md |
| **Related** | - |

**Description:**

ASVS 3.1.1 explicitly requires that application documentation states: (1) Expected security features browsers must support (HTTPS, HSTS, CSP, etc.), (2) How the application behaves when features are unavailable (warning, blocking, graceful degradation). Neither the application code nor any referenced configuration contains such documentation. Specifically: No `SECURITY.md`, security section in README, or inline documentation of browser requirements; No runtime checks for browser security feature support; No warning mechanism for users on non-conforming browsers; No `@app.before_request` handler that validates request security properties. Without documented browser security requirements, deployment teams cannot verify that the application is served with appropriate security headers. Operations teams have no guidance on required proxy/CDN security configurations. Users are not warned when their browser lacks required security features.

**Remediation:**

Create `SECURITY.md` documenting required browser security features (HTTPS with TLS 1.2+, HSTS support, CSP Level 2, SameSite cookies), degradation behavior (HTTP→HTTPS redirect, CSP warning logging, JavaScript requirement warnings, unsupported browser banners), and deployment requirements (reverse proxy HSTS configuration, required security headers). Add runtime enforcement in `create_app()` with an `@app.after_request` handler that applies documented security headers from a REQUIRED_SECURITY_FEATURES dictionary.

---

#### FINDING-187: No X-Frame-Options or frame-ancestors CSP Directive — Clickjacking Unmitigated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.1.1, 3.5.8 |
| **Files** | `v3/server/pages.py:203`, `v3/server/pages.py:315`, `v3/server/pages.py:448`, `v3/server/pages.py:468` |
| **Source Reports** | 3.1.1.md, 3.5.8.md |
| **Related** | - |

**Description:**

No route handler or application-level middleware sets `X-Frame-Options` or a `Content-Security-Policy` `frame-ancestors` directive. This is a Type A gap. All 18+ HTML-rendering endpoints can be embedded in attacker-controlled iframes. Most critical are state-changing pages that could be clickjacked: `/vote-on/<eid>` (voting form), `/manage/<eid>` (election management), `/do-open/<eid>` (election opening - GET request), `/do-close/<eid>` (election closing - GET request). Since `/do-open/<eid>` and `/do-close/<eid>` are GET requests that perform state changes, a simple iframe load (without even requiring a click on a form button) could open or close an election. An attacker can trick an authenticated election administrator into opening/closing elections or submitting votes by framing the application page and overlaying deceptive UI elements.

**Remediation:**

Implement global `@APP.after_request` middleware that sets `Cross-Origin-Resource-Policy: same-origin` on all responses. Add `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` headers. Create a `validate_sec_fetch()` utility function to validate Sec-Fetch-* headers for state-changing and sensitive endpoints, rejecting requests where `Sec-Fetch-Site` is not in ('same-origin', 'same-site', 'none') and where `Sec-Fetch-Mode` is 'no-cors'. Apply this validation as a decorator to sensitive endpoints.

---

#### FINDING-188: Missing Upper-Bound Range Validation on STV `seats` Integer Parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 1.4.2 |
| **Files** | `v3/server/bin/create-election.py:60-61`, `v3/steve/election.py:174`, `v3/steve/vtypes/stv.py:65` |
| **Source Reports** | 1.4.2.md |
| **Related** | - |

**Description:**

The STV (Single Transferable Vote) election type accepts a `seats` parameter that determines how many candidates should be elected. While the CLI import tool validates that `seats` is a positive integer, there is no upper-bound validation anywhere in the codebase. Additionally, the core API function `election.add_issue()` performs no validation on the `kv` dictionary contents at all, creating a defense-in-depth gap. This allows extreme values (e.g., 2147483647) to pass validation and be stored in the database. When `tally()` is called, this unbounded value is passed to `stv_tool.run_stv()`, which could cause resource exhaustion, logically incorrect election results, or potential integer overflow if the underlying STV tool uses C-based numeric processing.

**Remediation:**

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

---

#### FINDING-189: Missing Exception-Safe Resource Cleanup in Transactional Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 1.4.3 |
| **Files** | `v3/steve/election.py:53-71`, `v3/steve/election.py:127-141` |
| **Source Reports** | 1.4.3.md |
| **Related** | - |

**Description:**

Transactional operations begin transactions but lack exception handling to rollback on failure and ensure resource cleanup. This leaves the database connection in an inconsistent state with open transactions holding locks. If an exception occurs between BEGIN TRANSACTION and COMMIT, the SQLite write lock is held until the connection is garbage collected. In delete(), the connection is never closed and self.db is never set to None, leaving the Election object in an inconsistent state. In add_salts() (called from open()), a stale write lock could block subsequent vote submissions.

**Remediation:**

Wrap transactional operations in try/except/finally blocks. Add ROLLBACK in except block and ensure connection cleanup in finally block. For delete() method: add try/except to catch exceptions, execute ROLLBACK on exception, and ensure conn.close() and self.db = None in finally block. For add_salts() method: add try/except to catch exceptions during iteration and execute ROLLBACK on exception.

---

#### FINDING-190: Election Instance Lacks General Resource Release Mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Section(s)** | 1.4.3, 13.1.2, 13.2.6 |
| **Files** | `v3/steve/election.py:44` |
| **Source Reports** | 1.4.3.md, 13.1.2.md, 13.2.6.md |
| **Related** | - |

**Description:**

The `Election` class opens a new, independent SQLite database connection for every operation via `open_database()`. There is no connection pool, no maximum connection limit, no timeout configuration, and no documented behavior for when the database becomes unavailable or connections are exhausted. Class-level methods each independently open new connections, meaning concurrent API requests create unbounded parallel connections. Under concurrent load, each inbound request opens at least one new SQLite connection. SQLite uses file-level locking; under write contention, connections queue on the lock with no configured timeout. Concurrent read-heavy operations (listing elections) exhaust file descriptors. No fallback or circuit-breaker exists—the application will produce unhandled exceptions (e.g., `sqlite3.OperationalError: unable to open database file` or `database is locked`), leading to cascading failures.

**Remediation:**

1. Add connection pool configuration to `config.yaml.example` with parameters: pool_size (10), pool_timeout (5 seconds), max_overflow (5), and documented behavior when pool exhausted (return HTTP 503 with Retry-After header). 2. Implement a connection pool or singleton pattern in `election.py` using threading.Lock and queue.Queue with maxsize=MAX_CONNECTIONS, raising ServiceUnavailable after POOL_TIMEOUT. 3. Document fallback behavior when limits are reached. 4. Set SQLite busy_timeout PRAGMA on every connection in open_database() using configured timeout value (default 5000ms).

---

#### FINDING-191: Missing Global Security Headers Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-693 |
| **ASVS Section(s)** | 3.2.1 |
| **Files** | `v3/server/main.py:30-43` |
| **Source Reports** | 3.2.1.md |
| **Related** | FINDING-201 |

**Description:**

The application has no after_request handler or middleware to apply security response headers globally. All 21 endpoints in the application serve responses without Content-Security-Policy, X-Content-Type-Options, or other defensive headers. This creates no defense-in-depth layer and allows browsers to MIME-sniff responses. Any response from the application lacks critical security headers, allowing MIME-sniffing attacks and providing no defense-in-depth if any endpoint inadvertently returns user-controlled content.

**Remediation:**

Implement an after_request handler in the create_app() function to set security headers globally. Add X-Content-Type-Options: nosniff to all responses and implement a default Content-Security-Policy that restricts content sources. The handler should check if CSP is already set before applying defaults to allow per-endpoint customization.

---

#### FINDING-192: API Endpoints Lack Sec-Fetch-* Context Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Section(s)** | 3.2.1 |
| **Files** | `v3/server/pages.py:376`, `v3/server/pages.py:383`, `v3/server/pages.py:390` |
| **Source Reports** | 3.2.1.md |
| **Related** | FINDING-021, FINDING-022, FINDING-023, FINDING-097, FINDING-222 |

**Description:**

API-style endpoints that accept JSON or form data and return non-HTML responses do not validate Sec-Fetch-Dest or Sec-Fetch-Mode headers to confirm the request originates from the expected context (e.g., fetch from JavaScript, not direct browser navigation). While POST mitigates direct navigation, there is no server-side enforcement that these endpoints are called only via the intended AJAX/fetch context. Without Sec-Fetch-* validation, there is no server-side assurance that API endpoints are accessed only from the application's frontend. Combined with the lack of CSRF tokens, this increases the risk that these endpoints could be triggered from external contexts.

**Remediation:**

Implement a require_fetch_context decorator that validates Sec-Fetch-Dest and Sec-Fetch-Mode headers on API endpoints. The decorator should verify that requests originate from fetch/XHR contexts and reject requests with invalid context headers with a 403 Forbidden response. Apply this decorator to all API-style endpoints that return non-HTML responses.

---

#### FINDING-193: JavaScript Injection via STV Candidate Data in Inline Script

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 3.2.2 |
| **Files** | `v3/server/templates/vote-on.ezt:STV_CANDIDATES object literal`, `v3/server/pages.py:254` |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-194 |

**Description:**

The STV_CANDIDATES JavaScript object literal in vote-on.ezt embeds user-provided issue titles and candidate names directly in JavaScript string literals without proper escaping. While [format "js,html"] exists and is used elsewhere in the codebase, it is NOT applied in this context. An issue title or candidate name containing script-breaking characters can close the existing &lt;script&gt; block and inject arbitrary JavaScript, bypassing the string literal context entirely. The client-side escapeHtml() function is bypassed because the data source is already corrupted at the template level.

**Remediation:**

Apply [format "js"] to all values in the STV_CANDIDATES object: title: "[format "js"][issues.title][end]", and for all candidate label and name fields: { label: "[format "js"][issues.candidates.label][end]", name: "[format "js"][issues.candidates.name][end]" }

---

#### FINDING-194: Reflected XSS via URL Path Parameters in Error Pages

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 3.2.2 |
| **Files** | `v3/server/templates/e_bad_eid.ezt:eid output`, `v3/server/templates/e_bad_iid.ezt:iid output`, `v3/server/pages.py:172` |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-006, FINDING-032, FINDING-033, FINDING-034, FINDING-035, FINDING-064, FINDING-065, FINDING-193 |

**Description:**

Error pages e_bad_eid.ezt and e_bad_iid.ezt render URL path parameters (eid and iid) directly in HTML without any output encoding. When Quart URL-decodes malicious path parameters like /vote-on/&lt;script&gt;alert(1)&lt;/script&gt;, the decoded value is assigned to result.eid in the load_election decorator and rendered as raw HTML in the 404 error page. This is a Type A gap with no output encoding control applied.

**Remediation:**

Apply HTML escaping to error template outputs: The Election ID ([format "html"][eid][end]) does not exist, and The Issue ID ([format "html"][iid][end]) does not exist

---

#### FINDING-195: Shared Utility Functions Declared in Global Scope Without Namespace Isolation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.2.3 |
| **Files** | `v3/server/static/js/steve.js:30-73` |
| **Source Reports** | 3.2.3.md |
| **Related** | - |

**Description:**

The shared utility file `steve.js` declares three functions at global scope without namespace isolation or strict mode enforcement. These functions are accessible as properties of the `window` object, making them vulnerable to DOM clobbering attacks where malicious HTML elements with matching `id` or `name` attributes could shadow these function references. Combined with raw HTML rendering of issue descriptions that enables injection of elements with arbitrary `id` attributes, this creates an exploitable DOM clobbering attack surface. While function declarations typically take precedence, browser inconsistencies and edge cases (especially with `<form name="...">` or `<embed name="...">`) can lead to unexpected behavior.

**Remediation:**

Wrap `steve.js` in an IIFE with 'use strict' directive and namespace isolation. Implement type checking on all `getElementById` results. Return a namespace object exposing only necessary functions. Apply the same pattern to all inline scripts.

---

#### FINDING-196: Inline Scripts in Management Templates Lack Namespace Isolation and Strict Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.2.3 |
| **Files** | `v3/server/templates/manage.ezt:inline script block`, `v3/server/templates/manage-stv.ezt:inline script block`, `v3/server/templates/admin.ezt:inline script block` |
| **Source Reports** | 3.2.3.md |
| **Related** | - |

**Description:**

Management templates contain inline JavaScript that declares multiple functions and variables at global scope without namespace isolation or strict mode. This creates pollution of the global namespace and makes these functions vulnerable to DOM clobbering attacks. The templates handle sensitive operations and render unsanitized issue descriptions, but do not use the proper isolation pattern that exists in `vote-on.ezt`. Functions like `openEditIssueModal`, `saveIssue`, `openDeleteIssueModal`, and `toggleDescription` are all exposed on the window object, creating opportunities for DOM clobbering when combined with raw HTML rendering of issue descriptions on the same page.

**Remediation:**

Wrap all template inline scripts in IIFEs with strict mode, matching the pattern already used in `vote-on.ezt`. Only expose to HTML onclick handlers via window if needed. Apply the same pattern to manage-stv.ezt and admin.ezt.

---

#### FINDING-197: No Type or Null Checking on document.getElementById() Results Across All Client-Side JavaScript

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.2.3 |
| **Files** | `v3/server/static/js/steve.js:31`, `v3/server/static/js/steve.js:42`, `v3/server/static/js/steve.js:49`, `v3/server/templates/manage.ezt:inline script - csrf-token access`, `v3/server/templates/vote-on.ezt:inline script - multiple instances`, `v3/server/templates/manage-stv.ezt:inline script - multiple instances`, `v3/server/templates/admin.ezt:inline script - multiple instances` |
| **Source Reports** | 3.2.3.md |
| **Related** | - |

**Description:**

Throughout the codebase, `document.getElementById()` is called without subsequent null or type checking. The return value is immediately used with property access (`.value`, `.classList`, `.innerHTML`) without verifying the returned element exists or is of the expected type. This creates vulnerability to DOM clobbering where an injected element of unexpected type could cause silent failures or type errors. Without type checking, DOM clobbered elements can silently substitute for expected elements, leading to silent data corruption (wrong `.value` read/written), function failures (`TypeError` on unexpected types), or bypassed client-side validation. Issue descriptions rendered as raw HTML may contain elements with `id` attributes that collide with IDs used by the application (e.g., `id="csrf-token"`, `id="vote-<iid>"`, `id="issueTitle"`), and `document.getElementById()` returns the first matching element in DOM order without verification.

**Remediation:**

Implement a safe element lookup utility with type checking and apply it to all `document.getElementById()` calls across all JavaScript files.

---

#### FINDING-198: Session Cookie Name Missing `__Host-` or `__Secure-` Prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Section(s)** | 3.3.1, 3.3.3 |
| **Files** | `v3/server/main.py:30-44`, `v3/server/main.py:36-38` |
| **Source Reports** | 3.3.1.md, 3.3.3.md |
| **Related** | - |

**Description:**

ASVS 3.3.1 requires that if the `__Host-` prefix is not used for cookie names, the `__Secure-` prefix must be used. The application uses Quart/Flask which defaults the session cookie name to `session` without any security prefix. Neither the `__Host-` nor `__Secure-` prefix is configured in the application code. The `__Secure-` prefix instructs browsers to only send the cookie over HTTPS and requires the `Secure` attribute. The `__Host-` prefix additionally restricts the cookie to the exact host and root path, preventing subdomain attacks. Without these prefixes, the browser does not enforce prefix-based cookie protections. Combined with the missing `Secure` attribute, this means no browser-enforced HTTPS-only transmission, potential for subdomain cookie injection attacks, and cookies could be overwritten by a less-secure subdomain.

**Remediation:**

In the `create_app()` function in `v3/server/main.py`, configure the session cookie name with the `__Host-` prefix: app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session', app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_PATH'] = '/', and do NOT set SESSION_COOKIE_DOMAIN (required for __Host- prefix)

---

#### FINDING-199: No Explicit HttpOnly Configuration on Session Cookie

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 3.3.4 |
| **Files** | `v3/server/main.py:42` |
| **Source Reports** | 3.3.4.md |
| **Related** | - |

**Description:**

The application does not explicitly configure session cookie security attributes (SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE) anywhere in the auditable codebase. The asfquart.construct() call is the sole application factory, and no cookie attribute configuration follows it. While Quart (based on Flask's API) defaults SESSION_COOKIE_HTTPONLY to True, the asfquart wrapper layer is not available for review and could potentially override this default. ASVS 3.3.4 requires verification that HttpOnly is set — this cannot be verified from the provided code. If HttpOnly is not set, a cross-site scripting vulnerability anywhere in the application could be leveraged to steal session tokens via document.cookie.

**Remediation:**

Explicitly configure session cookie security attributes after app construction in main.py: app.config['SESSION_COOKIE_HTTPONLY'] = True, app.config['SESSION_COOKIE_SECURE'] = True, app.config['SESSION_COOKIE_SAMESITE'] = 'Lax', app.config['SESSION_COOKIE_NAME'] = '__Host-session'

---

#### FINDING-200: No Cookie Size Validation Control

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.3.5 |
| **Files** | `v3/server/pages.py:63-94`, `v3/server/pages.py:73-78`, `v3/server/pages.py:121-128`, `v3/server/pages.py:356`, `v3/server/pages.py:519` |
| **Source Reports** | 3.3.5.md |
| **Related** | - |

**Description:**

The application has no mechanism to validate or enforce the 4096-byte cookie size limit. All session cookie management is delegated to the Quart/asfquart framework with no application-level guard. While the current session payload (uid, fullname, email, flash messages) is likely small enough, there is no defensive control preventing oversized cookies if session data grows (e.g., additional session attributes, accumulated data from framework internals, or future code changes). If the session cookie exceeds 4096 bytes (through future code changes, framework overhead growth, or unforeseen session data accumulation), the browser will silently discard it. The user's session would effectively be invalidated, preventing authentication and use of all protected functionality. This is a denial-of-service condition against individual users.

**Remediation:**

Implement middleware that validates cookie size before the response is sent using an after_request handler. Log warnings when Set-Cookie headers approach 4096 bytes. Cap flash message content length to prevent edge cases. Document session storage architecture for future developers.

---

#### FINDING-201: Complete Absence of X-Content-Type-Options Header

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-693 |
| **ASVS Section(s)** | 3.4.4 |
| **Files** | `v3/server/main.py:28-43`, `v3/server/pages.py:134`, `v3/server/pages.py:144`, `v3/server/pages.py:180`, `v3/server/pages.py:259`, `v3/server/pages.py:299`, `v3/server/pages.py:323`, `v3/server/pages.py:353`, `v3/server/pages.py:359`, `v3/server/pages.py:365`, `v3/server/pages.py:400`, `v3/server/pages.py:423`, `v3/server/pages.py:445`, `v3/server/pages.py:463`, `v3/server/pages.py:486`, `v3/server/pages.py:511`, `v3/server/pages.py:531`, `v3/server/pages.py:540`, `v3/server/pages.py:548`, `v3/server/pages.py:553-562`, `v3/server/pages.py:565-566`, `v3/server/pages.py:570-571`, `v3/server/pages.py:653-654`, `v3/server/pages.py:92-112` |
| **Source Reports** | 3.4.4.md |
| **Related** | FINDING-191 |

**Description:**

The application does not set the 'X-Content-Type-Options: nosniff' header on any HTTP response. No global middleware, after-request handler, or framework configuration was found that would inject this header. All 21+ routes return responses without this protection. This exposes the application to MIME-sniffing attacks where browsers may interpret content differently than the declared Content-Type, potentially executing attacker-controlled content as active scripts. The vulnerability is particularly critical for the /docs/&lt;iid&gt;/&lt;docname&gt; endpoint which serves user-associated documents, and the /static/&lt;path:filename&gt; endpoint which serves CSS/JS files. Without nosniff, Cross-Origin Read Blocking (CORB) protection in browsers is also weakened.

**Remediation:**

PRIMARY FIX: Add a global after_request hook in the application factory (main.py) that sets the header on every response: response.headers['X-Content-Type-Options'] = 'nosniff'. SECONDARY FIX (Defense-in-Depth): Fix manually constructed 404 response in pages.py to include the header. Consider implementing comprehensive security header policy including X-Frame-Options, Referrer-Policy, and Content-Security-Policy.

---

#### FINDING-202: Missing Referrer-Policy Header on All Application Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 3.4.5 |
| **Files** | `v3/server/main.py:31-47`, `v3/server/pages.py:125-602` |
| **Source Reports** | 3.4.5.md |
| **Related** | - |

**Description:**

The application does not set a `Referrer-Policy` HTTP response header on any responses, nor is there evidence of HTML meta tag configuration in the provided code. This violates ASVS requirement 3.4.5 and exposes sensitive election identifiers, issue IDs, and document names in URL paths to third-party services via the browser's `Referer` header. When users navigate to sensitive pages like `/vote-on/<eid>`, `/manage/<eid>`, `/manage-stv/<eid>/<iid>`, or `/docs/<iid>/<docname>`, and those pages contain links to third-party resources or the user clicks external links, the browser sends the full URL including the path (election ID, issue ID, document name) in the `Referer` header to the third party. This allows third-party services to learn internal election identifiers and navigation patterns.

**Remediation:**

Add a global `after_request` handler that sets `Referrer-Policy` on all responses. For an election system, `strict-origin-when-cross-origin` (minimum) or `no-referrer` (strictest) is recommended. Implementation: response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin' or 'no-referrer' for maximum protection.

---

#### FINDING-203: Missing Content-Security-Policy Header with Violation Reporting Directive

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.4.7 |
| **Files** | `v3/server/main.py:29-40`, `v3/server/pages.py:135-653`, `v3/server/pages.py:52` |
| **Source Reports** | 3.4.7.md |
| **Related** | - |

**Description:**

The application does not configure a Content-Security-Policy header with a violation reporting directive (report-uri or report-to) anywhere in the codebase. No CSP header is set at the application level, and there is no middleware or after-request hook that would add one with reporting capabilities. Without a CSP header, the browser applies no restrictions on script sources, style sources, frame ancestors, or other content policies, leaving the application exposed to XSS and content injection attacks. Without report-uri or report-to directives, the security team has no visibility into policy violations, cannot detect attack attempts, and cannot identify misconfigured CSP directives that break legitimate functionality.

**Remediation:**

Add an after_request handler in main.py that sets the CSP header with a reporting directive on all responses. For initial rollout, use Content-Security-Policy-Report-Only to collect violations without breaking functionality. Implement a /csp-report endpoint to collect and log violations.

---

#### FINDING-204: Missing Cross-Origin-Opener-Policy Header on All HTML Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.4.8 |
| **Files** | `v3/server/main.py:32-47`, `v3/server/pages.py:659`, `v3/server/pages.py:~125`, `v3/server/pages.py:~133`, `v3/server/pages.py:~222`, `v3/server/pages.py:~280`, `v3/server/pages.py:~320`, `v3/server/pages.py:~343`, `v3/server/pages.py:~551`, `v3/server/pages.py:~559`, `v3/server/pages.py:~567`, `v3/server/pages.py:~575` |
| **Source Reports** | 3.4.8.md |
| **Related** | - |

**Description:**

The application does not set the `Cross-Origin-Opener-Policy` (COOP) header on any HTTP response that renders HTML content. This leaves all document-rendering responses vulnerable to cross-origin window handle attacks such as tabnabbing and frame counting. An attacker page opened via a link from the voting application can retain a reference to the opener window, enabling tabnabbing (redirecting the voting page to a phishing page), frame counting (enumerating open windows/tabs to infer voting activity patterns), and window reference leakage (cross-origin state inspection via window.opener property).

**Remediation:**

Add a global `after_request` hook in the application factory to set the `Cross-Origin-Opener-Policy` header on all HTML responses: response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'. Also update the `raise_404` function to include the header. Use `same-origin` as the default directive (appropriate given OAuth uses redirects rather than popups).

---

#### FINDING-205: Externally Hosted SVG Image Without SRI or Documented Security Decision

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | `v3/server/templates/header.ezt:18` |
| **Source Reports** | 3.6.1.md |
| **Related** | - |

**Description:**

The Apache feather logo is loaded at runtime from an external domain (www.apache.org). This resource is not versioned (the URL has no version identifier, meaning content can change), has no SRI integrity attribute (the integrity attribute is not supported on &lt;img&gt; elements), and has no documented security decision justifying this external dependency. ASVS 3.6.1 requires that when SRI is not possible, there should be a documented security decision to justify this for each resource. While SVG loaded via &lt;img&gt; is sandboxed (no script execution), a compromised resource could still be used for phishing (visual replacement) or tracking. If the external host is compromised or the resource is modified, the application would display attacker-controlled visual content to all users. In a voting application, this could undermine trust or be used for social engineering.

**Remediation:**

Self-host the SVG image alongside other static assets. In fetch-thirdparty.sh, add download command for the feather SVG. In header.ezt, change to use the self-hosted version: &lt;img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top"&gt;

---

#### FINDING-206: Missing SRI for Self-Hosted Third-Party Library (bootstrap-icons.css)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | `v3/server/templates/header.ezt:10`, `v3/server/bin/fetch-thirdparty.sh:70-74` |
| **Source Reports** | 3.6.1.md |
| **Related** | - |

**Description:**

The SRI defense-in-depth pattern is applied to bootstrap.min.css and bootstrap.bundle.min.js but explicitly skipped for bootstrap-icons.css. This third-party CSS file controls @font-face declarations for web fonts. If tampered with after deployment, it could: (1) Redirect font loading to an attacker-controlled origin, (2) Inject CSS-based data exfiltration (e.g., attribute selectors with background URLs), (3) Modify visual rendering to mislead voters. The inconsistency creates a false confidence that third-party resources are integrity-protected when a significant gap exists. An attacker who can modify server-side files or intercept during deployment could alter bootstrap-icons.css without detection, while other Bootstrap files would trigger integrity failures. This creates a targeted attack vector through the weakest link.

**Remediation:**

Add SRI hash generation and template integration. In fetch-thirdparty.sh, after extracting bootstrap-icons.css, generate hash using openssl dgst. In header.ezt, add integrity attribute: &lt;link href="/static/css/bootstrap-icons.css" rel="stylesheet" integrity="sha384-GENERATED_HASH_HERE"&gt;

---

#### FINDING-207: Build Script Downloads Third-Party Assets Without Pre-Download Integrity Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | `v3/server/bin/fetch-thirdparty.sh:47`, `v3/server/bin/fetch-thirdparty.sh:60-62`, `v3/server/bin/fetch-thirdparty.sh:67`, `v3/server/bin/fetch-thirdparty.sh:82`, `v3/server/bin/fetch-thirdparty.sh:92` |
| **Source Reports** | 3.6.1.md |
| **Related** | - |

**Description:**

The build script generates SRI hashes from the downloaded content rather than verifying downloads against known-good hashes. This means: (1) curl does not use --fail flag (HTTP errors silently produce non-library content), (2) No pre-defined SHA-256/SHA-384 checksums are checked before extraction, (3) No GPG signature verification of release packages, (4) The generated SRI hash will match whatever was downloaded, including compromised content. If a supply chain attack targets the download (e.g., compromised GitHub release, DNS hijacking), the SRI mechanism would be rendered ineffective because the integrity hash would be computed from the malicious payload. A supply chain compromise during the build process would result in malicious JavaScript/CSS being served to all voters, with SRI hashes that appear valid. The existing SRI provides zero protection against this attack vector.

**Remediation:**

Add known-good hash verification before extraction. Define expected hashes from official release notes. Download with: curl -q --fail --location. Verify before extraction using sha256sum and compare against expected hash. Exit with error if verification fails. Only then extract the files.

---

#### FINDING-208: Complete Absence of External URL Navigation Warning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.7.3 |
| **Files** | `v3/server/pages.py:52-59`, `v3/server/pages.py:349-350` |
| **Source Reports** | 3.7.3.md |
| **Related** | - |

**Description:**

The application has no mechanism whatsoever to warn users before navigating to URLs outside the application's control. There is no interstitial warning page, no client-side JavaScript intercept for external links, and no server-side redirect proxy. This is a complete absence of the ASVS 3.7.3 control. The rewrite_description() function injects unescaped HTML into the page, allowing arbitrary HTML including external links to be rendered directly to voters without any warning or cancellation option. An election administrator can create an issue with external links in the description, and voters clicking these links will navigate directly to external URLs with no interstitial warning and no option to cancel. This could be used for phishing attacks or social engineering to influence voter behavior in an election context.

**Remediation:**

Implement a three-part solution: (1) Server-side redirect proxy route that validates target URL and redirects to interstitial warning page for external domains, (2) Interstitial template showing warning with continue/cancel options, (3) HTML escaping in rewrite_description() and client-side JavaScript to intercept external links and route through warning page.

#### FINDING-209: Complete Absence of Browser Security Feature Detection

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 3.7.5 |
| Files | `v3/server/static/js/steve.js:1-76` |
| Source Report(s) | 3.7.5.md |
| Related Findings | - |

**Description:**

The application's common JavaScript utility file contains zero browser security feature detection. The application implicitly depends on modern browser features (Bootstrap 5 Modal API, ES6 template literals, classList API, const declarations) but never checks whether the browser supports the security features the application relies upon. For a voting system, the browser must support Content Security Policy (CSP), Strict-Transport-Security, SameSite cookie attribute, Secure cookie flag enforcement, and SubtleCrypto/Web Crypto API if any client-side cryptographic operations are used. No feature detection, no user warning, and no access-blocking logic exists anywhere in the provided client-side code. Users on browsers lacking security feature support could be targeted with XSS or session hijacking attacks that would succeed due to missing CSP/HSTS enforcement. Voters may unknowingly cast votes on compromised sessions. The application provides false confidence that security is enforced uniformly.

**Remediation:**

Add a browser security feature detection module to steve.js that runs on page load. Implement checkBrowserSecurityFeatures() function that checks for: Content Security Policy support (CSP Level 2), Web Cryptography API, Fetch API with credentials support, HTTPS enforcement, and SameSite cookie support. Display warning messages to users when critical security features are missing. Optionally block access by disabling form submission buttons for browsers that lack critical security features. Add &lt;noscript&gt; tag warning, document minimum browser requirements, create automated tests, implement server-side User-Agent analysis, and implement telemetry.

---

#### FINDING-210: HTML Responses Created Without Explicit Charset in Content-Type

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 4.1.1 |
| Files | `v3/server/pages.py:764-766`, `v3/server/pages.py:183`, `v3/server/pages.py:211`, `v3/server/pages.py:222`, `v3/server/pages.py:318`, `v3/server/pages.py:390` |
| Source Report(s) | 4.1.1.md |
| Related Findings | - |

**Description:**

The `raise_404` function constructs explicit HTML responses with `mimetype='text/html'` but does not include a charset parameter. In Werkzeug 3.0+ (used by modern Quart), this produces a `Content-Type: text/html` header without `; charset=utf-8`. Without an explicit charset declaration, browsers must guess the character encoding, creating a window for character-encoding-based attacks (e.g., UTF-7 XSS in legacy or misconfigured clients, or multi-byte encoding attacks). The rendered templates contain URL-derived values (`eid`, `iid`) making this a plausible vector.

**Remediation:**

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

---

#### FINDING-211: No Application-Wide Content-Type Enforcement Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 4.1.1 |
| Files | `v3/server/pages.py`, `v3/server/main.py`, `v3/server/pages.py:93`, `v3/server/pages.py:679` |
| Source Report(s) | 4.1.1.md |
| Related Findings | - |

**Description:**

The application has no centralized mechanism to ensure all HTTP responses include a Content-Type header with an appropriate charset parameter. Content-Type correctness is entirely delegated to individual handler implementations and framework defaults from `@APP.use_template`, `send_from_directory`, `quart.redirect`, and `quart.abort`. There is no `@APP.after_request` hook to validate or enforce Content-Type headers with charset across all response types. This creates systemic risk: if framework default behavior changes across versions (as happened with Werkzeug 3.0's charset removal), all responses silently lose charset declarations. New endpoints added by developers may omit Content-Type charset without any safety net. 22+ response-generating endpoints rely entirely on unverifiable framework defaults.

**Remediation:**

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

---

#### FINDING-212: State-changing operations use GET method, compounding transport security risk

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 4.1.2 |
| Files | `v3/server/pages.py` |
| Source Report(s) | 4.1.2.md |
| Related Findings | - |

**Description:**

State-changing operations for opening and closing elections are exposed as GET endpoints rather than POST endpoints. This architectural choice compounds the transport security risk because GET requests are more likely to be logged, cached, and automatically redirected by intermediaries, increasing the attack surface for plaintext credential leakage. The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints use GET method for state-changing operations. GET requests are especially prone to being logged by proxies, browsers, and intermediaries. Session cookies and election IDs are exposed in the URL and headers. A blanket HTTP→HTTPS proxy redirect for GET requests allows authentication cookies to be sent in plaintext on the initial HTTP request before redirect occurs.

**Remediation:**

Convert state-changing operations to POST method. Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from @APP.get to @APP.post decorators. Ensure HTTPS enforcement is handled by before_request middleware for these endpoints. This will reduce surface area for transport security issues and prevent session token leakage in plaintext, preventing election administration hijacking.

---

#### FINDING-213: No Trusted Proxy Configuration or X-Forwarded-* Header Sanitization

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 4.1.3 |
| Files | `v3/server/main.py:34-53`, `v3/server/main.py:78-95`, `v3/server/main.py:96-113` |
| Source Report(s) | 4.1.3.md |
| Related Findings | - |

**Description:**

The application, designed to run behind a reverse proxy via Hypercorn (ASGI), lacks any configuration or middleware to sanitize, validate, or restrict intermediary-set HTTP headers (e.g., X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host). While the application reads user identity from server-side sessions rather than headers, the underlying Quart framework and OAuth redirect flow may implicitly trust these spoofable headers. This creates risks for OAuth redirect manipulation, audit log integrity issues, and scheme confusion. An attacker could inject X-Forwarded-Host: attacker.com to redirect OAuth callbacks to a malicious domain, spoof their IP address in logs, or cause HTTP URLs to be generated for HTTPS-only resources.

**Remediation:**

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

---

#### FINDING-214: No explicit HTTP request body size limits configured, enabling denial-of-service via overly long HTTP messages

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 4.2.1 |
| Files | `v3/server/main.py:31-44`, `v3/server/pages.py:403`, `v3/server/pages.py:96`, `v3/server/pages.py:440`, `v3/server/pages.py:504`, `v3/server/pages.py:531` |
| Source Report(s) | 4.2.1.md |
| Related Findings | - |

**Description:**

The Quart application does not set `max_content_length` or configure Hypercorn body size limits. The ASVS 4.2.1 parent section explicitly includes "denial of service via overly long HTTP messages" as an attack vector. Multiple POST endpoints accept unbounded request bodies. An authenticated attacker (any committer) can submit arbitrarily large HTTP request bodies that are fully buffered by the framework before reaching handler code. This can exhaust server memory and cause denial of service during an active election, potentially disrupting voting.

**Remediation:**

Set `app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024` (1 MB) in the `create_app()` function in `main.py`. Additionally, configure Hypercorn limits in the ASGI deployment using a configuration file with settings for `h11_max_incomplete_size`, `h2_max_concurrent_streams`, and `h2_max_header_list_size`.

---

#### FINDING-215: State-changing operations as GET requests increase HTTP request smuggling attack surface

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 4.2.1 |
| Files | `v3/server/pages.py:453-470`, `v3/server/pages.py:475-492` |
| Source Report(s) | 4.2.1.md |
| Related Findings | - |

**Description:**

Two state-changing operations (`/do-open/<eid>` and `/do-close/<eid>`) are implemented as GET requests. In the context of ASVS 4.2.1, this is significant because GET requests have simpler message boundary determination (no body parsing) and are therefore the easiest payloads to smuggle through a misconfigured proxy/server chain. A smuggled GET request requires only a request line and minimal headers, making successful exploitation more likely if any infrastructure component mishandles message boundaries. Additionally, authorization check stubs (`### check authz`) exist but are NOT CALLED, compounding the smuggling risk by removing the ownership check that would limit impact. If HTTP request smuggling is achievable at the infrastructure level (reverse proxy ↔ Hypercorn), any authenticated committer's session could be hijacked to open or close elections they don't own.

**Remediation:**

Convert state-changing operations to POST with CSRF protection. Change route decorators from `@APP.get()` to `@APP.post()` for both `/do-open/<eid>` and `/do-close/<eid>` endpoints. Implement ownership verification by checking `md.owner_pid != result.uid` and returning 403 if unauthorized. Add CSRF token validation using `validate_csrf_token(form.get('csrf_token'))` after parsing the request form data.

---

#### FINDING-216: No Application-Level HTTP/2 Connection-Specific Header Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.2.3 |
| Files | `v3/server/main.py:33-48`, `v3/server/main.py:91-110`, `v3/server/pages.py:93`, `v3/server/pages.py:441`, `v3/server/pages.py:499`, `v3/server/pages.py:520` |
| Source Report(s) | 4.2.3.md |
| Related Findings | - |

**Description:**

The application runs on Hypercorn, which supports HTTP/2 by default when TLS is enabled (via ALPN negotiation) and can support HTTP/3. There is no application-level middleware, Quart extension, or Hypercorn configuration to: (1) Reject incoming HTTP/2/HTTP/3 requests containing prohibited connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade, TE except for trailers), (2) Prevent connection-specific headers from being included in outgoing HTTP/2/HTTP/3 responses, (3) Validate header integrity during HTTP version conversion (e.g., if deployed behind a reverse proxy that downgrades/upgrades HTTP versions). In an HTTP/2-to-HTTP/1.1 downgrade proxy scenario, an attacker could craft requests with prohibited headers leading to request smuggling, bypassing authentication/authorization decorators, response splitting, and authorization bypass on state-changing endpoints.

**Remediation:**

1. Add ASGI middleware to validate and strip connection-specific headers for HTTP/2/HTTP/3 requests. Create a HTTP2HeaderValidationMiddleware class that checks the http_version in the ASGI scope and rejects requests with CONNECTION_SPECIFIC_HEADERS (transfer-encoding, connection, keep-alive, proxy-connection, upgrade) by returning a 400 Bad Request response. 2. Register the middleware in create_app() by wrapping app.asgi_app with HTTP2HeaderValidationMiddleware. 3. Add a Quart @after_request handler to strip connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade) from all responses. 4. Configure Hypercorn explicitly for HTTP version handling and document supported versions. 5. Convert state-changing GET endpoints (/do-open/&lt;eid&gt;, /do-close/&lt;eid&gt;) to POST methods. 6. Add integration tests validating that HTTP/2 requests with Transfer-Encoding are rejected.

---

#### FINDING-217: No Application-Level CRLF Validation on HTTP Request Headers

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.2.4 |
| Files | `v3/server/pages.py:114-628`, `v3/server/main.py:90-107` |
| Source Report(s) | 4.2.4.md |
| Related Findings | - |

**Description:**

The application has zero middleware, decorators, or configuration that validates incoming HTTP request headers for CR (\r), LF (\n), or CRLF (\r\n) sequences. ASVS 4.2.4 specifically requires this validation for HTTP/2 and HTTP/3 requests. The application supports HTTP/2 when deployed via Hypercorn but does not add any application-layer header validation. The application relies entirely on the underlying ASGI server (Hypercorn) and framework (Quart/Werkzeug) for protocol-level protection, with no defense-in-depth. This becomes critical when HTTP version conversion occurs at a reverse proxy layer, where headers containing CRLF that pass HTTP/2 binary framing could become injection vectors after protocol downgrade to HTTP/1.1.

**Remediation:**

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

---

#### FINDING-218: Redirect Responses Constructed with URL Path Parameters Without CRLF Sanitization

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.2.4 |
| Files | `v3/server/pages.py:303`, `v3/server/pages.py:363`, `v3/server/pages.py:413`, `v3/server/pages.py:416`, `v3/server/pages.py:434`, `v3/server/pages.py:455`, `v3/server/pages.py:477`, `v3/server/pages.py:496`, `v3/server/pages.py:521`, `v3/server/pages.py:547`, `v3/server/pages.py:567` |
| Source Report(s) | 4.2.4.md |
| Related Findings | - |

**Description:**

Multiple POST and GET endpoints construct redirect Location headers using URL path parameters (eid, or values derived from form input). While the load_election decorator provides database validation that would reject most injected values, not all redirect paths go through this validation, and the application places no explicit CRLF check on data flowing into response headers. The framework-level protection is version-dependent and not verified. If a future code change introduces a redirect path without database validation, header injection becomes possible with no defense-in-depth against response splitting.

**Remediation:**

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

---

#### FINDING-219: Unbounded User Input in Flash Messages Creates Potential for Oversized Cookie Header DoS

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 4.2.5 |
| Files | `v3/server/pages.py:385-395`, `v3/server/pages.py:424`, `v3/server/pages.py:485`, `v3/server/pages.py:505` |
| Source Report(s) | 4.2.5.md |
| Related Findings | - |

**Description:**

Multiple endpoints incorporate unsanitized, unbounded user input into session flash messages via `quart.flash()`. If the session uses cookie-based storage (the default for Quart/Flask frameworks), the resulting `Set-Cookie` response header can exceed the browser's cookie size limit (~4KB) or the server's incoming header size limit (~8-16KB for most ASGI servers). When the browser sends back the oversized cookie on subsequent requests, the server rejects every request before reaching application code, resulting in a persistent DoS for that user's session. The vulnerable code paths include: (1) do_vote_endpoint extracting unbounded 'iid' from form field names (vote-&lt;arbitrary_data&gt;), (2) do_create_endpoint using unbounded form.title, (3) do_add_issue_endpoint using unbounded form.title, and (4) do_edit_issue_endpoint using unbounded form.title. The data flows from HTTP POST form fields through extraction without length checks into quart.flash() which stores data in session storage, ultimately appearing in Set-Cookie response headers. A proof of concept would involve submitting a POST request with a 100KB form field name like 'vote-AAAA...[100KB]...=y', causing the server to store this in the session flash message, creating an oversized cookie that locks out the user's session permanently.

**Remediation:**

Apply length limits at two levels: (1) Truncate user input before including in flash messages by defining MAX_FLASH_INPUT_LEN = 200 and truncating inputs like 'safe_iid = iid[:MAX_FLASH_INPUT_LEN]' before passing to flash_danger/flash_success. (2) Enforce maximum request body size via Quart configuration: APP.config['MAX_CONTENT_LENGTH'] = 64 * 1024 (64KB max request body). (3) Add server-side input length validation for form fields with MAX_TITLE_LEN = 500 and MAX_DESCRIPTION_LEN = 5000, aborting requests with 400 status if exceeded.

---

#### FINDING-220: TLS is optional, not enforced for WebSocket connections

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 4.4.1 |
| Files | `v3/server/main.py:79-83`, `v3/server/main.py:85`, `v3/server/main.py:94-110`, `v3/server/config.yaml.example:27-31` |
| Source Report(s) | 4.4.1.md |
| Related Findings | - |

**Description:**

TLS is optional, not enforced. If WebSocket endpoints exist in unprovided files (pages.py, api.py), they would operate over plaintext WS when TLS is not configured. The server explicitly supports running without TLS based on configuration. In run_standalone() mode, TLS certificates are conditionally loaded based on config values that can be blank. In run_asgi() mode (production), TLS is not configured at the application level at all and depends entirely on external Hypercorn or reverse proxy configuration, with no application-level validation that the deployment is actually using TLS.

**Remediation:**

Option 1 — Enforce TLS at startup (fail-closed): Add validation in run_standalone() to check if certfile and keyfile are configured, and exit with critical error if not set. Option 2 — If plain HTTP must be supported for development, add WebSocket-specific middleware using @app.before_websocket decorator to enforce WSS scheme and reject non-TLS WebSocket connections with close code 1008. Additionally, add startup validation requiring TLS configuration in non-development modes, or add a --insecure flag that must be explicitly set to run without TLS. Document TLS requirements in deployment documentation specifying that production deployments MUST use TLS either at the application level or via reverse proxy.

---

#### FINDING-221: No WebSocket Origin Header Validation Infrastructure

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 4.4.2 |
| Files | `v3/server/main.py:36-51` |
| Source Report(s) | 4.4.2.md |
| Related Findings | - |

**Description:**

The application lacks any infrastructure for validating the `Origin` header during WebSocket handshakes. The `create_app()` function, which serves as the sole application configuration entry point, establishes zero WebSocket security controls: (1) No allowed-origins list is defined in application configuration, (2) No `before_websocket` or `before_request` middleware is registered to inspect the `Origin` header, (3) The underlying framework (`asfquart`, built on Quart) does not validate WebSocket Origin headers by default, (4) All WebSocket endpoints defined in `pages` and `api` modules inherit this unprotected configuration. This represents a Type A gap — no control exists at any layer. If WebSocket endpoints exist in `pages` or `api` modules, an attacker can perform Cross-Site WebSocket Hijacking (CSWSH). An authenticated user visiting a malicious page would have their browser establish a WebSocket connection to the voting application using their existing session cookies, allowing the attacker to: submit or modify votes on behalf of the victim, read election state or results in real-time, bypass CSRF protections (WebSocket connections are not subject to SameSite cookie restrictions in all browsers), and compromise the integrity and confidentiality of the voting process.

**Remediation:**

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

---

#### FINDING-222: State-Changing Operations via GET Requests Bypass Session Security

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-352 |
| ASVS Section(s) | 4.4.3 |
| Files | `v3/server/pages.py:323`, `v3/server/pages.py:340` |
| Source Report(s) | 4.4.3.md |
| Related Findings | FINDING-021, FINDING-022, FINDING-023, FINDING-097, FINDING-192 |

**Description:**

The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints perform critical state-changing operations (opening and closing elections) via HTTP GET requests. When combined with cookie-based session management, GET requests are inherently vulnerable to cross-site request forgery through simple link injection, image tags, or browser prefetching. These endpoints cannot carry request body tokens, making them structurally impossible to protect with CSRF tokens. Election state transitions (EDITABLE → OPEN, OPEN → CLOSED) are irreversible, and browser prefetching or extensions may trigger these URLs automatically.

**Remediation:**

Convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods. Implement CSRF token validation by checking form.get('csrf_token') against a valid token. Replace the placeholder CSRF token implementation in basic_info() with a real token generation and validation mechanism. Ensure all state-changing operations use POST with CSRF protection.

---

#### FINDING-223: Complete Absence of File Handling Documentation for Document Serving Feature

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 5.1.1 |
| Files | `v3/docs/schema.md`, `v3/ARCHITECTURE.md:18`, `v3/server/pages.py:562-580` |
| Source Report(s) | 5.1.1.md |
| Related Findings | - |

**Description:**

The application has an active document-serving feature with two components: (1) A route GET /docs/&lt;iid&gt;/&lt;docname&gt; that serves files from the DOCSDIR / iid directory, and (2) A rewrite_description() function that converts doc:filename tokens in issue descriptions into clickable download links. Neither the schema.md, ARCHITECTURE.md, nor any other provided documentation defines: permitted file types for documents associated with issues, expected file extensions (e.g., .pdf, .txt, .md), maximum file size (including unpacked size for archives), how files are made safe for end-user download and processing (Content-Disposition, Content-Type validation, anti-virus scanning), or behavior when a malicious file is detected. Without documented file handling requirements, developers have no specification to implement or test against. This has directly led to the missing validation in serve_doc(). An attacker who can place files in the docs directory (or exploit any future upload feature) could serve HTML files with embedded JavaScript (stored XSS via Content-Type sniffing), executable files disguised as documents, or excessively large files causing storage exhaustion.

**Remediation:**

Create a file handling specification document and reference it from ARCHITECTURE.md. The specification should define: Permitted file types (PDF, plain text, Markdown), Expected extensions (.pdf, .txt, .md), Maximum file size (10 MB per file, 50 MB per issue), Maximum unpacked size (N/A - archives not accepted), Safety measures (file extension validation against allowlist, explicit Content-Type header based on extension mapping, Content-Disposition: attachment for non-text files, X-Content-Type-Options: nosniff on all responses, rejection of unrecognized extensions with 403), and Malicious file behavior (logging of denied access attempts with user ID and filename, MIME type validation for uploads, HTTP 403 for extension validation failures).

---

#### FINDING-224: Issue Description Doc-Link Rewriting Generates Unvalidated File References

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 5.1.1 |
| Files | `v3/server/pages.py:52-58` |
| Source Report(s) | 5.1.1.md |
| Related Findings | - |

**Description:**

The rewrite_description() function parses issue descriptions and converts doc:filename patterns into HTML anchor tags pointing to /docs/{iid}/{filename}. The filename extracted from the description is not validated against any allowlist of permitted file types or extensions before being embedded in the HTML link. The regex r'doc:([^\s]+)' captures any non-whitespace sequence, meaning filenames like ../../../etc/passwd, evil.html, or payload.exe would be turned into clickable links. While the serve_doc endpoint's send_from_directory provides basic path traversal protection, the absence of documented permitted file types means there is no basis for validation at either the link-generation or file-serving layer. This creates a social engineering vector where attackers with issue-editing privileges can embed links to dangerous file types, and generates links to file types that should not be served.

**Remediation:**

Validate the filename in rewrite_description() against the documented allowlist. Implementation should: (1) Define ALLOWED_DOC_EXTENSIONS constant, (2) Extract file extension using pathlib.Path(filename).suffix.lower(), (3) Check if extension is in allowlist, (4) Check for path traversal characters ('/' or '\\' in filename), (5) If validation fails, replace the link with an error message like '[invalid document reference: {filename}]', (6) Only generate clickable links for valid, safe filenames.

---

#### FINDING-225: Files Served to Voters from `/docs/` Endpoint Undergo No Antivirus or Malicious Content Scanning

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 5.4.3 |
| Files | `v3/server/pages.py:638-658`, `v3/server/pages.py:52`, `v3/server/pages.py:308` |
| Source Report(s) | 5.4.3.md |
| Related Findings | - |

**Description:**

The document serving endpoint allows authenticated voters to download files associated with election issues. While the endpoint implements proper authentication and authorization checks, it completely bypasses any antivirus or malicious content scanning. Files are served directly from the filesystem without inspection, creating a potential vector for malware distribution to voters. An election administrator can place a document in DOCSDIR/&lt;iid&gt;/ containing known malware (e.g., weaponized PDF, malicious Office document, or disguised executable). When voters access the election and click the document link, the malicious file is served directly without detection. In an election system context, compromised voter machines could lead to vote manipulation or credential theft. The trust relationship between the voting system and voters amplifies the risk as voters are more likely to open documents from the official voting platform.

**Remediation:**

Integrate antivirus scanning at the point where files are placed into DOCSDIR (upload time) and optionally at serve time. Implement a scan_file() function using ClamAV (clamdscan for daemon mode) that returns True if clean or raises AVScanError if malicious or scan fails. Modify the serve_doc endpoint to: 1) Validate docname to prevent path traversal by checking that safe_name equals docname and '..' is not in docname, 2) Scan the file before serving using scan_file(filepath), 3) Block serving with 403 error if file fails security scan, 4) Log all blocked attempts. Additionally implement scanning at the point of file ingestion: hook into file upload/placement workflow to scan before writing to DOCSDIR, reject files that fail scanning before they reach the serving directory, and consider periodic background scans of DOCSDIR to catch newly-identified threats. Add file type allowlisting for serve_doc (e.g., only PDF, TXT, specific document types). Long-term: implement a controlled file upload endpoint with scanning rather than relying on out-of-band file placement.

---

#### FINDING-226: Complete absence of documentation defining authentication defense controls

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.1.1 |
| Files | `v3/TODO.md`, `v3/docs/schema.md`, `v3/server/pages.py`, `v3/server/main.py:33`, `v3/server/main.py:39-43` |
| Source Report(s) | 6.1.1.md |
| Related Findings | - |

**Description:**

ASVS 6.1.1 requires application documentation to explicitly define how rate limiting, anti-automation, and adaptive response controls defend against credential stuffing and password brute force, and how they prevent malicious account lockout. A thorough review of all provided documentation and code reveals no documentation whatsoever addressing these concerns. The application delegates authentication to Apache OAuth (oauth.apache.org) but provides no documentation explaining what brute force protections the OAuth provider implements, whether there are retry limits on the OAuth callback flow, how the application would detect or respond to credential stuffing, or how malicious account lockout is prevented at the identity provider level.

**Remediation:**

Create an authentication security document (e.g., v3/docs/authentication-security.md) that addresses: 1) Authentication flow and OAuth provider's brute force protections, 2) Rate limiting policies for login attempts, vote submission, and API endpoints including implementation details, 3) Anti-automation measures such as CAPTCHA/challenge requirements and bot detection mechanisms, 4) Adaptive response policies describing actions taken after N failed attempts and escalation procedures, 5) Account lockout prevention including lockout policy, anti-lockout measures, and election-specific protections against voter lockout during active elections, 6) Configuration details including where settings are configured, how to modify thresholds, and monitoring/alerting for attack detection.

---

#### FINDING-227: No rate limiting or throttling on vote submission and state-changing endpoints

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 6.1.1, 6.3.1 |
| Files | `v3/server/pages.py:367`, `v3/server/pages.py:408`, `v3/server/pages.py:429`, `v3/server/pages.py:448`, `v3/server/pages.py:290-323`, `v3/steve/election.py:265` |
| Source Report(s) | 6.1.1.md, 6.3.1.md |
| Related Findings | - |

**Description:**

The vote submission and election state-change endpoints have no rate limiting or throttling controls, and no documentation exists describing how such controls should be configured. An authenticated attacker (any committer) could submit rapid automated requests causing database contention in SQLite's single-writer model. The endpoints affected include /do-vote/&lt;eid&gt; for vote submission, /do-create/&lt;eid&gt; for election creation, /do-open/&lt;eid&gt; for opening elections, and /do-close/&lt;eid&gt; for closing elections. These endpoints only perform authentication checks via @asfquart.auth.require but have no rate limiting, anti-automation checks, or throttling mechanisms.

**Remediation:**

1) Implement rate limiting on sensitive endpoints using a library like quart_rate_limiter (e.g., @rate_limit(1, timedelta(seconds=5)) for vote submission to allow 1 vote per 5 seconds), 2) Document the rate limiting configuration in the authentication security document, 3) Add similar rate limiting to election state-change endpoints (e.g., @rate_limit(5, timedelta(minutes=1)) to allow 5 state changes per minute), 4) Convert state-changing GET endpoints to POST with CSRF protection as acknowledged in TODO.md. 5) Implement submission cooldown check by tracking last vote timestamp and enforcing minimum 10-second delay between resubmissions.

---

#### FINDING-228: Inconsistent Authentication Level Between Vote Display Page and Vote Submission Endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 6.1.3 |
| Files | `v3/server/pages.py:231-290`, `v3/server/pages.py:402-440` |
| Source Report(s) | 6.1.3.md |
| Related Findings | - |

**Description:**

The vote display page (`GET /vote-on/<eid>`) includes a voter eligibility check via `election.q_find_issues`, but the corresponding vote submission endpoint (`POST /do-vote/<eid>`) does not perform the same check at the web layer. While the business logic layer (`election.add_vote`) does check `q_get_mayvote`, the inconsistency in where and how security controls are applied across these related authentication pathways violates the principle of consistent enforcement. The inconsistent placement of the eligibility check means that if the business-layer check in `add_vote` fails or is modified, the web layer provides no safety net. Additionally, error messages from the business layer are caught generically, potentially revealing different information than the web-layer check would provide.

**Remediation:**

Apply consistent eligibility checking at the web layer for both endpoints. In the `do_vote_endpoint` function, add the same eligibility check used in `vote_on_page`: call `election.q_find_issues.perform(result.uid, election.eid)` and check if results exist using `fetchall()`. If no results (user not eligible), flash a danger message 'You are not eligible to vote in this election.' and redirect to '/voter' with code 303 before processing any votes.

---

#### FINDING-229: Inconsistent Authentication Strength for Election Document Access

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-287 |
| ASVS Section(s) | 6.3.4 |
| Files | `v3/server/pages.py:469-489` |
| Source Report(s) | 6.3.4.md |
| Related Findings | FINDING-026, FINDING-098, FINDING-100, FINDING-235 |

**Description:**

The `/docs/<iid>/<docname>` route serves election-related documents but requires only a bare session (`@asfquart.auth.require`) while all other election data access routes require committer-level authentication (`@asfquart.auth.require({R.committer})`). This creates an inconsistent authentication strength across the election data access pathway, violating ASVS 6.3.4's requirement for consistent security control enforcement. While the `mayvote` check provides partial mitigation by verifying voter eligibility, the authentication tier is weaker than equivalent election routes. Additionally, the unimplemented `### verify the propriety of DOCNAME` comment suggests incomplete security hardening and potential path traversal vulnerability.

**Remediation:**

Change authentication decorator from bare `@asfquart.auth.require` to `@asfquart.auth.require({R.committer})` to match other election routes. Implement docname validation to prevent directory traversal by checking for '..' and path separators. Use whitelist approach by verifying resolved file path is relative to allowed directory. Log invalid docname access attempts with user ID for security monitoring.

---

#### FINDING-230: No User-Facing Notification Mechanism for Security Events

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-356 |
| ASVS Section(s) | 6.3.5 |
| Files | `v3/server/pages.py:570-576`, `v3/server/pages.py:136-169` |
| Source Report(s) | 6.3.5.md |
| Related Findings | - |

**Description:**

Even if authentication events were tracked and analyzed, there is no delivery mechanism to notify users. The application has no email notification system for security events (the person.email field exists but is only for sending ballot links), no in-app security alert display (flash messages are only used for operational feedback), and no security event display on profile/dashboard pages. Users cannot review their own authentication history to identify compromise. For a voting system, users should be able to verify that only they have accessed their voting sessions.

**Remediation:**

Add security notification display to authenticated pages. Create a profile page that displays authentication history (recent login times, IPs, user agents) and pending security alerts. Implement an async notification function that sends both email notifications and stores in-app alerts for suspicious authentication events. Include functionality to mark alerts as read and allow users to review their complete authentication history.

---

#### FINDING-231: No User Notification When Person Details (Email/Name) Are Modified

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 6.3.7 |
| Files | `v3/steve/persondb.py:46-51`, `v3/steve/election.py:510-516` |
| Source Report(s) | 6.3.7.md |
| Related Findings | - |

**Description:**

The `add_person` method performs an upsert operation that can silently modify a user's email address without any notification to either the old or new email address. Email addresses are security-sensitive authentication details used for election-related communications, making silent modifications a security risk. The method doesn't check if values actually changed before updating, and no audit trail exists, preventing administrative oversight. A silently changed email could redirect election notifications to an attacker.

**Remediation:**

Implement change detection in `add_person()` to compare existing values before updating. Add logging to record all person detail changes with before/after values. Implement a notification service that sends alerts to BOTH the old and new email addresses when email is changed. Create an audit trail for all person detail modifications. Example implementation should check for existing person record, detect changes, log modifications, and call `_notify_detail_change()` method to send notifications to both old and new email addresses.

---

#### FINDING-232: Profile/Settings Pages Exist Without Update Notification Framework

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 6.3.7 |
| Files | `v3/server/pages.py:578-591`, `v3/server/pages.py:82` |
| Source Report(s) | 6.3.7.md |
| Related Findings | - |

**Description:**

The application provides authenticated `/profile` and `/settings` endpoints, indicating user-facing profile management is an intended feature. However, no notification framework exists anywhere in the codebase to support ASVS 6.3.7 compliance when profile update functionality is implemented. No email module, notification queue, or message templates exist. When POST handlers are added, no infrastructure guides developers toward notification implementation. The system stores and uses email addresses for election communications (as shown in `get_voters_for_email()`), but lacks security notification capability.

**Remediation:**

Implement a notification service that can be used across the application. Create a `notifications.py` module with `notify_auth_detail_change()` function that sends notifications to affected email addresses about authentication detail changes. The service should support different notification types (email_changed, name_changed, profile_updated) and notify all relevant email addresses (typically both old and new). Implement email sending infrastructure including templates that clearly explain what changed, when, and how to report unauthorized changes. Integrate this notification service into all profile update handlers before deploying POST functionality for `/profile` and `/settings` routes.

---

#### FINDING-233: Differential Response in /admin Reveals PersonDB Registration Status

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 6.3.8 |
| Files | `v3/server/pages.py:297-310` |
| Source Report(s) | 6.3.8.md |
| Related Findings | - |

**Description:**

When an authenticated ASF committer visits /admin, the application checks whether they exist in the PersonDB (the STeVe voter/person database). Two distinct responses are returned based on PersonDB registration status. If the person is in PersonDB, the application returns HTTP 200 with admin.ezt template and executes additional DB queries. If the person is NOT in PersonDB, it returns HTTP 404 with e_bad_pid.ezt template and immediately aborts. This creates three observable differentiators: (1) HTTP response code (200 vs 404), (2) Page content/template (Full admin page vs. 'Unknown Person' error), and (3) Timing (successful path executes additional DB queries and template processing). At ASVS Level 3, this differential response reveals whether an authenticated ASF committer is registered in the STeVe PersonDB, violating the principle of consistent error handling even for self-status information leakage.

**Remediation:**

Return a consistent response regardless of PersonDB status. Either show a 'setup required' page with the same HTTP 200 code, or handle the missing person case gracefully within the normal admin template. Modify the admin_page function to catch PersonNotFound exceptions and set a result.person_registered flag to False, then return HTTP 200 with the admin template showing a 'not yet registered' state rather than a 404 error page. This ensures consistent HTTP status codes, templates, and processing times regardless of PersonDB registration status.

---

#### FINDING-234: No Authentication Factor Lifecycle Management for Voting System

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 6.4.4 |
| Files | `v3/server/pages.py:64-85`, `v3/server/pages.py:133`, `v3/server/pages.py:233`, `v3/server/pages.py:397`, `v3/server/pages.py:431`, `v3/server/pages.py:449`, `v3/server/pages.py:466`, `v3/steve/persondb.py:36-43`, `v3/steve/persondb.py:46-50`, `v3/schema.sql` |
| Source Report(s) | 6.4.4.md |
| Related Findings | - |

**Description:**

The application delegates all authentication to external ASF OAuth but performs no verification of the authentication strength or MFA status of the authenticated session. The session data (uid, fullname, email) contains no information about how the user authenticated or whether MFA was used. No MFA factor recovery process exists - if a user loses an MFA factor at the ASF OAuth level and regains access through a potentially weakened identity proofing process, the voting application cannot detect or prevent access. No authentication level tracking exists via amr/acr claims. No re-authentication is required for sensitive operations like voting, opening elections, or closing elections. The person table schema contains only pid, name, and email with no mechanism for local identity proofing, secondary factor enrollment, or factor replacement tracking. In a voting system where election integrity is paramount, accepting authentication sessions without verifying that MFA factor recovery was accompanied by enrollment-level identity proofing means an attacker who social-engineers a factor recovery at the IdP level gains full voting access, elections could be manipulated through compromised accounts that bypassed proper identity re-verification, and no audit trail exists to distinguish sessions authenticated with full MFA vs. recovered credentials.

**Remediation:**

Implement multi-layered authentication verification: (1) Request amr/acr claims from ASF OAuth and store in session to enable MFA verification at application level; (2) Implement require_mfa decorator for sensitive operations including voting and election lifecycle management to prevent access from weakened/recovered sessions; (3) Add session freshness checks requiring re-authentication for critical operations to limit exposure window of compromised sessions; (4) Coordinate with ASF IdP team to document factor recovery identity proofing procedures ensuring NIST 800-63B §6.1.2.3 compliance at the IdP; (5) Add authentication event logging including auth method, time, and factor changes to audit trail for post-incident forensic analysis. Example implementation should include checking amr/acr fields from OAuth claims, enforcing step-up authentication with 5-minute session freshness for sensitive operations, and applying MFA requirements to voting, election opening, and election closing endpoints.

---

#### FINDING-235: No Automated Renewal Notification System for Expiring Authentication Factors

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | CWE-287 |
| ASVS Section(s) | 6.4.5 |
| Files | `v3/server/bin/mail-voters.py:34-73`, `v3/server/bin/mail-voters.py:45`, `v3/server/bin/mail-voters.py:60-71`, `v3/server/bin/mail-voters.py:81-88` |
| Source Report(s) | 6.4.5.md |
| Related Findings | FINDING-026, FINDING-098, FINDING-100, FINDING-229 |

**Description:**

The email infrastructure lacks all critical components required by ASVS 6.4.5 for timely authentication factor renewal notifications. The script operates as a manual, context-agnostic broadcast tool with no awareness of authentication factor expiration timelines, no automated scheduling, and no configurable reminder logic. Specific gaps include: (1) No expiration filtering - get_voters_for_email() retrieves all eligible voters without expiration context; (2) No automated scheduling - script must be invoked manually by administrator; (3) No configurable reminder thresholds - no reminder configuration, interval, or escalation logic exists; (4) No standard renewal content - email body determined entirely by user-supplied template with no enforced renewal instructions; (5) No state tracking - no mechanism to record reminders sent, preventing deduplication and escalation.

**Remediation:**

Implement a comprehensive automated renewal notification system with the following components: (1) Add expiration date tracking to voter/authentication data model with auth_expiry TIMESTAMP and renewal_token fields; (2) Implement get_voters_expiring_before(cutoff_date) query method in steve.election module; (3) Add --days-before-expiry CLI parameter to filter voters by approaching expiration; (4) Create renewal_reminders tracking table to prevent duplicate notifications; (5) Implement reminder_already_sent() and record_reminder_sent() methods for state management; (6) Create standardized renewal email templates with required fields (expiry_date, days_remaining, renewal_url); (7) Integrate with cron/systemd timer for automated daily execution at multiple thresholds (14, 7, 3, 1 day before expiry); (8) Add --dry-run flag for testing; (9) Implement escalation logic for unactioned renewals.

---

#### FINDING-236: Email-based voter notification lacks request-bound authentication token generation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 6.6.2 |
| Files | `v3/server/bin/mail-voters.py:45-68`, `v3/steve/election.py:455-460` |
| Source Report(s) | 6.6.2.md |
| Related Findings | - |

**Description:**

The email notification system provides template data consisting entirely of static, reusable identifiers. There is no mechanism anywhere in the email sending flow to generate a unique, time-limited authentication token per voter per notification, bind any token to an originating authentication request/session, store or validate a nonce for later verification, or create a cryptographically signed URL that expires. The get_voters_for_email() method returns only persistent attributes (pid, name, email). If the operator-provided EZT template constructs any voting link, that link would be identical across multiple invocations, replayable indefinitely for the election's lifetime, and not bound to any specific authentication request or session. This violates ASVS 6.6.2 which requires OOB tokens to be bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one.

**Remediation:**

Generate a cryptographically random, time-limited, single-use token per voter per email send, store it server-side bound to the authentication context, and validate it on use. Implement generate_voter_auth_token() to create tokens using secrets.token_urlsafe(32) with expiry timestamps, store tokens in a database table bound to voter_pid, election_id, and usage status. Implement validate_voter_auth_token() to check token validity, expiry, single-use status, and mark as consumed after validation. Add database table for OOB token storage with expiry and single-use enforcement. Provide application control over authentication token injection into emails. Consider implementing HMAC-signed URLs with server-validated expiry timestamps. Long-term: migrate from email-based voter notification to push notifications or TOTP for voter authentication per ASVS section guidance.

---

#### FINDING-237: No Rate Limiting on Resource Identifier Endpoints — Brute Force Enumeration Unprotected

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Section(s) | 6.6.3 |
| Files | `v3/server/pages.py:161`, `v3/server/pages.py:180`, `v3/server/pages.py:217`, `v3/server/pages.py:306`, `v3/server/pages.py:362`, `v3/server/pages.py:418`, `v3/server/pages.py:436`, `v3/server/pages.py:536` |
| Source Report(s) | 6.6.3.md |
| Related Findings | - |

**Description:**

Despite the application requiring authentication for all sensitive endpoints, no brute-force protection mechanism exists anywhere in the codebase. The absence of rate limiting on election/issue lookup endpoints means an authenticated attacker can systematically probe for valid identifiers without restriction. The `load_election` and `load_election_issue` decorators do not implement any rate limiting, account lockout, or exponential backoff. Combined with the 40-bit entropy issue (CH06-022), an authenticated attacker can systematically discover valid election IDs. ASVS 6.6.3 explicitly requires rate limiting as a defense against brute force of out-of-band codes.

**Remediation:**

Implement per-user rate limiting on election/issue lookup endpoints using quart_rate_limiter (e.g., @rate_limit(10, timedelta(minutes=1)) to allow 10 requests/minute per IP). Alternatively, implement custom tracking of failed EID lookups per session with exponential backoff. Track failed lookup attempts per user, implement rate limiting that triggers after threshold is exceeded, and return HTTP 429 when rate limit is reached.

---

#### FINDING-238: TLS Certificates Loaded Without Integrity Verification

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 6.7.1 |
| Files | `v3/server/main.py:37`, `v3/server/main.py:85-90` |
| Source Report(s) | 6.7.1.md |
| Related Findings | - |

**Description:**

The TLS certificate and private key files — which protect the OAuth authentication channel — are loaded directly from the filesystem without any integrity verification. There is no hash comparison, fingerprint validation, or signature check to ensure certificates have not been tampered with. An attacker with write access to the `server/certs/` directory could substitute a rogue certificate and key, enabling man-in-the-middle interception of the OAuth authentication flow. The certificates are explicitly added to the `extra_files` watch set (line 88), meaning the server will automatically reload when certificate files change on disk, which amplifies the risk — a certificate swap triggers immediate adoption without manual restart.

**Remediation:**

Implement certificate integrity verification before loading TLS certificates by validating against known fingerprints stored separately from the certificate files. Enforce restrictive file permissions (0o400 for key, 0o444 for cert) at startup. Store certificate fingerprints in a separate, integrity-protected configuration. Consider removing certificates from extra_files to prevent automatic reload on modification. Create a verify_certificate_integrity() function that computes SHA-256 hash of certificate file and compares against expected fingerprint from protected config, raising RuntimeError on mismatch.

#### FINDING-239: Certificate File Paths Accept Unvalidated Configuration Input

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 6.7.1 |
| Files | `v3/server/main.py:85-86` |
| Source Reports | `6.7.1.md` |
| Related Findings | - |

**Description:**

Certificate and key file paths are constructed by joining `CERTS_DIR` with values from `config.yaml` without validating that the resulting paths remain within the intended `certs/` directory. The `pathlib.Path` `/` operator does not sanitize path traversal sequences. An attacker who can modify `config.yaml` could redirect certificate loading to an arbitrary filesystem path using path traversal sequences (e.g., '../../../tmp/attacker-cert.pem'), causing the server to use an attacker-controlled certificate outside the intended certs directory.

**Remediation:**

Add path containment validation for certificate configuration values to prevent directory traversal. Implement a safe_cert_path() function that resolves the certificate path and verifies it stays within the certs directory using is_relative_to(), raising ValueError if path escapes the directory. Also verify the file exists before returning the path.

---

#### FINDING-240: User Identity Model Lacks IdP Namespacing Despite Multi-IdP Capable Framework

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 6.8.1 |
| Files | `v3/server/main.py:43-47`, `v3/server/pages.py:80-95`, `v3/steve/election.py:184-196`, `v3/steve/election.py:295`, `v3/steve/election.py:308-317`, `v3/steve/election.py:321-330` |
| Source Reports | `6.8.1.md` |
| Related Findings | - |

**Description:**

The application's identity model uses bare user identifiers (uid/pid) without IdP namespacing throughout the entire authentication and authorization flow. While currently configured with a single OAuth provider, the underlying asfquart framework explicitly supports OIDC multi-IdP authentication, which has been deliberately disabled. This architectural gap means that re-enabling OIDC or adding a second IdP would immediately introduce identity spoofing vulnerabilities with no code-level protection. The entire identity model throughout the application — session handling, PersonDB, election ownership, voter eligibility, and vote recording — uses a bare uid/pid string with no IdP identifier or namespace component. If OIDC is re-enabled or another IdP is added, identity collision becomes possible where an attacker could register at IdP-B with a username matching a legitimate user at IdP-A and gain access to their elections and voting privileges.

**Remediation:**

Implement composite identity keys combining IdP identifier and user ID throughout the application: 1) Store IdP identifier in session (e.g., idp_id = s.get('idp', 'apache-oauth')) and create composite UIDs (e.g., composite_uid = f"{idp_id}:{raw_uid}"). 2) Update PersonDB schema to include IdP namespace with columns for idp, idp_uid, and a generated composite pid. 3) Refactor all pid/uid references in pages.py, election.py, and database operations to use namespaced identifiers. 4) Add validation in election.py functions to assert pid includes IdP namespace (assert ':' in pid). 5) Implement IdP allowlist validation to ensure only approved IdPs can provide identities. 6) Add integration tests for cross-IdP identity isolation to prevent regression when OIDC is re-enabled.

---

#### FINDING-241: Authentication Assertion Signature Validation Unverifiable — Entirely Delegated to Unaudited External Library

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 6.8.2 |
| Files | `v3/server/pages.py:65-80`, `v3/server/pages.py:302-303`, `v3/server/pages.py`, `v3/steve/election.py` |
| Source Reports | `6.8.2.md` |
| Related Findings | - |

**Description:**

The application delegates 100% of its authentication assertion validation to the `asfquart` framework. No code in the audited codebase validates the presence or integrity of digital signatures on authentication assertions from the ASF Identity Provider. There is no JWT parsing, no SAML signature verification, no JWKS endpoint configuration, and no public key or certificate configuration visible anywhere in the audited files. The application trusts session data without any visible signature verification at the application layer. All authorization decisions (voting, election management, ownership) flow from this trusted but unverified session data. If the `asfquart` framework contains any deficiency in assertion validation—such as accepting unsigned JWTs, not validating the `alg` header (algorithm confusion attack), not verifying issuer/audience claims, or misconfiguring JWKS—the entire application's authentication and authorization model would be bypassed.

**Remediation:**

1. Include `asfquart` in audit scope: The `asfquart.auth` and `asfquart.session` modules MUST be audited for ASVS 6.8.2 compliance since they contain the actual assertion validation logic. 2. Add defense-in-depth assertion claim validation at the application layer to validate critical session claims, verify assertion freshness, and verify expected issuer. 3. Document IdP configuration requirements including JWKS endpoint, expected algorithm, issuer, and audience values so deployments can be verified. 4. Implement assertion validation logging to create an audit trail of authentication events and signature verification results. 5. Verify `asfquart` rejects unsigned assertions and protects against algorithm confusion attacks (alg: none). 6. Verify `asfquart` validates assertion signatures against IdP public keys with proper JWKS/certificate-based signature verification.

---

#### FINDING-242: No Authentication Recentness Check for State-Changing Election Operations

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 6.8.4 |
| Files | `v3/server/pages.py:367`, `v3/server/pages.py:433`, `v3/server/pages.py:454`, `v3/server/pages.py:367-407`, `v3/server/pages.py:433-452`, `v3/server/pages.py:454-472`, `v3/server/pages.py:56-83` |
| Source Reports | `6.8.4.md` |
| Related Findings | - |

**Description:**

Critical state-changing operations that alter election lifecycle (open, close, vote, create) perform no verification of when the user last authenticated. A session established hours or days earlier can be used to perform irreversible operations like casting votes or closing elections. A stale or long-lived session (potentially from a compromised browser, shared workstation, or session replay) can be used to perform irreversible election operations. For a voting system, this undermines the assurance that the person casting the vote is the legitimate user and was actively present at the time of voting. Proof of concept: User authenticates and receives a session, leaves browser open on a shared workstation, hours later another person uses the still-active session to cast votes or manipulate election state without any recentness check preventing this abuse.

**Remediation:**

Add session timestamp at login and verify before sensitive operations. Define SENSITIVE_OPS_MAX_AGE = 300 (5 minutes). Implement verify_session_freshness(max_age) function that reads the session, checks for auth_time or session_created timestamp, and aborts with 401 if session age exceeds max_age, requiring re-authentication. Apply this verification to sensitive endpoints like do_vote_endpoint, do_open_endpoint, and do_close_endpoint by calling await verify_session_freshness() before proceeding with the operation.

---

#### FINDING-243: State-Changing Operations via GET Bypass Session CSRF Protections

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1, L2, L3 |
| CWE | - |
| ASVS Sections | 7.2.1, 7.5.3 |
| Files | `v3/server/pages.py:448`, `v3/server/pages.py:468`, `v3/server/pages.py:84` |
| Source Reports | `7.2.1.md`, `7.5.3.md` |
| Related Findings | - |

**Description:**

Two critical state-changing operations (opening and closing elections) use GET methods. While session tokens are verified on the backend via @asfquart.auth.require({R.committer}), GET requests are inherently more vulnerable to cross-site request forgery because they can be triggered by image tags, link prefetching, or redirects without user interaction. Combined with the placeholder CSRF token (basic.csrf_token = 'placeholder' at line 84), a verified session can be abused through external trigger mechanisms. An attacker can trick an authenticated user into opening or closing an election without their knowledge by embedding malicious GET requests in external web pages. These operations are also exploitable in the context of automatic session creation without user consent (ASVS 7.6.2).

**Remediation:**

Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints to POST methods. Implement proper CSRF token generation using secrets.token_urlsafe(32) instead of the placeholder. Validate CSRF tokens on all POST requests by storing the token in the session and comparing it with the submitted form value. Example: async def basic_info(): result = await asfquart.session.read(); basic = BasicInfo(); basic.uid = result.uid; basic.csrf_token = secrets.token_urlsafe(32); await asfquart.session.write({'csrf_token': basic.csrf_token}); return basic. Add CSRF validation function and call it in all POST endpoints before processing state changes.

---

#### FINDING-244: Absence of Session Management Risk Analysis and Policy Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 7.1.1, 7.1.3 |
| Files | `v3/docs/schema.md`, `v3/ARCHITECTURE.md` |
| Source Reports | `7.1.1.md`, `7.1.3.md` |
| Related Findings | - |

**Description:**

ASVS 7.1.1 explicitly requires documentation stating session inactivity timeout value, absolute maximum session lifetime, justification for these values in combination with other controls, and justification for any deviations from NIST SP 800-63B. The project's only documentation file (schema.md) covers database schema in detail but contains no mention of session management policies, session token storage mechanism, session timeout values, SSO interaction considerations, NIST SP 800-63B analysis or deviation justification, or risk analysis for session handling decisions. ASVS 7.1.3 requires documentation of controls to coordinate session lifetimes between federated systems. Without this documentation, the session management implementation cannot be verified as intentional or appropriate for an election system.

**Remediation:**

Create a session-management.md document (or equivalent section in existing docs) containing: (1) Overview describing session management decisions for the Steve voting system per ASVS 7.1.1 requirements. (2) Session Timeout Values section documenting inactivity timeout (recommended 15 minutes) with justification that voting sessions should be short-lived to prevent unauthorized use of unattended workstations, noting NIST SP 800-63B Section 7.2 permits up to 30 minutes for AAL2; and absolute session lifetime (recommended 12 hours) with justification that elections may span workdays. (3) NIST SP 800-63B Compliance section documenting AAL level with justification based on authentication method, re-authentication requirements for vote submission, and any deviations with justification. (4) SSO Interaction section documenting how SSO session lifetime interacts with application session lifetime, session revocation on SSO logout, and IdP session coordination. (5) Risk Analysis section documenting threats (unattended workstation, stolen session token, session fixation) and corresponding mitigations (inactivity timeout, absolute lifetime, HTTPS-only cookies, session regeneration). (6) Federated identity management ecosystem documentation including SSO provider identity and integration points, session lifetime policy and rationale, idle timeout configuration, termination coordination between app and SSO provider, and re-authentication conditions.

---

#### FINDING-245: Complete Absence of Concurrent Session Limit Policy and Enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 7.1.2 |
| Files | `v3/server/pages.py:70-87`, `v3/server/pages.py:547-560`, `v3/server/main.py:39-41` |
| Source Reports | `7.1.2.md` |
| Related Findings | - |

**Description:**

The application has no documented policy, configuration, or code to define or enforce how many concurrent (parallel) sessions are permitted for a single user account. For a voting/election management system where session integrity directly impacts the trustworthiness of votes and administrative actions, this is a significant gap. The session is read and consumed with no check against any session registry or count. There is no session ID tracking, no session store enumeration, and no enforcement logic. Missing controls include: (1) No session count tracking - no database table, in-memory store, or external service tracks how many sessions exist per uid, (2) No session limit constant/configuration defined anywhere in the codebase, (3) No enforcement action to revoke oldest sessions, deny new login, or notify the user when multiple sessions exist, (4) No session listing endpoint for users to view their active sessions, (5) No session revocation endpoint for users to terminate other active sessions, (6) No documentation defining the intended concurrent session behavior.

**Remediation:**

1. Document the policy - Create a session management policy defining: maximum concurrent sessions per account (e.g., 3 for regular users, 1 during active voting), behavior when the limit is reached (e.g., terminate oldest session, or deny new login), and any role-specific limits (e.g., election administrators vs. voters). 2. Implement session tracking using a server-side session registry that tracks active sessions per user with timestamps, implements MAX_CONCURRENT_SESSIONS policy, and provides methods to register_session(), get_active_sessions(), and revoke_session(). 3. Integrate into authentication flow - Check session count at login and at basic_info(). 4. Add session management UI - Populate the existing /settings page with session listing and revocation controls. 5. Invalidate sessions on credential change - When a user's OAuth token or password changes, revoke existing sessions.

---

#### FINDING-246: No Session Invalidation Mechanism or IdP Session Synchronization

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 7.6.1, 7.4.3 |
| Files | `v3/server/pages.py` (entire file) |
| Source Reports | `7.6.1.md`, `7.4.3.md` |
| Related Findings | - |

**Description:**

The application has no mechanism to synchronize session state with the IdP beyond the initial authentication. There is no back-channel logout handler to receive notifications when the IdP terminates sessions. Complete codebase review reveals no backchannel_logout implementation, no session timeout configuration visible in application code, no IdP token introspection/validation, and no max_age/auth_time parameter handling. Sessions cannot be actively terminated by the IdP. Revoked users retain access until some external mechanism clears sessions (server restart, store expiry). There is no documented session termination behavior between RP and IdP as required by ASVS 7.6.1.

**Remediation:**

Implement IdP session synchronization mechanisms: (1) Add back-channel logout support per OIDC spec with a POST /backchannel-logout endpoint that validates logout tokens, extracts sub/sid claims, and invalidates corresponding sessions. (2) Add periodic IdP session validation that calls the IdP's token introspection or userinfo endpoint to verify the session is still active, destroying the local session if invalid. (3) Ensure the /logout endpoint redirects to the IdP's logout endpoint for federated logout. (4) Document the expected session lifetime behavior between RP and IdP.

---

#### FINDING-247: No Re-authentication Before Election Administration Operations

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 7.5.3 |
| Files | `v3/server/pages.py:416-433`, `v3/server/pages.py:472`, `v3/server/pages.py:497`, `v3/server/pages.py:518-534`, `v3/server/pages.py:360`, `v3/server/pages.py:366` |
| Source Reports | `7.5.3.md` |
| Related Findings | - |

**Description:**

Election administration operations (create, add/edit/delete issues, set dates) require no re-authentication beyond the initial session. While these operations are restricted to the editable state (before an election opens), they can corrupt election configuration when combined with the ability to open elections. Affected endpoints include: do_create_endpoint (create election), do_add_issue_endpoint (add issue), do_edit_issue_endpoint (modify issue), do_delete_issue_endpoint (delete issue), do_set_open_at_endpoint (set election date), and do_set_close_at_endpoint (set election date). All endpoints contain placeholder ### check authz comments but no actual authorization implementation. A hijacked committer session can create spurious elections, add/modify/delete issues, and combined with the ability to open elections, an attacker could configure AND open a manipulated election.

**Remediation:**

At minimum, administrative operations should require session freshness validation. Implement require_fresh_auth() middleware for administrative operations requiring authentication within the last 15 minutes (900 seconds). Check if the session's auth_time exists and if time.time() - auth_time > max_age_seconds. If authentication is stale, store the original request URL in session and redirect to IdP with prompt=login or max_age parameter for re-authentication. Apply this check to all administrative endpoints before processing the operation. Additionally, implement the ### check authz placeholders with proper ownership verification.

---

#### FINDING-248: Session Creation Without User Consent

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 7.6.2 |
| Files | `v3/server/main.py:37-40`, `v3/server/pages.py:136-165`, `v3/server/pages.py:437-453`, `v3/server/pages.py:456-472` |
| Source Reports | `7.6.2.md` |
| Related Findings | - |

**Description:**

The application does not enforce explicit user consent or action before creating new application sessions. When a user's application session expires but their IdP session remains active, visiting any protected endpoint triggers an automatic redirect chain that silently re-establishes an application session without user interaction. The OAuth integration lacks prompt parameters (prompt=login or prompt=consent) and there is no interstitial login page requiring explicit user action. When @asfquart.auth.require detects no session, it auto-redirects to the IdP which silently authenticates if the IdP session is still active, creating a new application session without user awareness. This is particularly dangerous with state-changing GET endpoints like /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; where an attacker can craft links that trigger both session creation and state changes in a single redirect chain.

**Remediation:**

1. Add prompt=login or prompt=consent to the OAuth initiation URL to force explicit user interaction at the IdP: asfquart.generics.OAUTH_URL_INIT = 'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&prompt=login'. 2. Implement an interstitial login page instead of auto-redirecting to the IdP. When @asfquart.auth.require detects no session, render a page with a Sign In button rather than auto-redirecting. Create a /login endpoint with a form requiring POST to /auth/begin. 3. Add max_age parameter to limit how recently the user must have authenticated at the IdP (e.g., max_age=300 for 5 minutes). 4. Convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST to prevent link-triggered state changes (already covered in CH07-006).

---

#### FINDING-249: No Formal Authorization Policy Document Defining Access Rules

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1, L2, L3 |
| CWE | CWE-1059 |
| ASVS Sections | 8.1.1, 8.1.2, 8.1.3 |
| Files | `v3/ARCHITECTURE.md`, `v3/docs/schema.md`, `v3/server/pages.py:101`, `v3/server/pages.py:167`, `v3/server/pages.py:194`, `v3/server/pages.py:290`, `v3/server/pages.py:335`, `v3/server/pages.py:349`, `v3/server/pages.py:363`, `v3/server/pages.py:378`, `v3/server/pages.py:394`, `v3/server/pages.py:413` |
| Source Reports | `8.1.1.md`, `8.1.2.md`, `8.1.3.md` |
| Related Findings | FINDING-040, FINDING-130 |

**Description:**

The application lacks a formal authorization policy document that defines function-level and data-specific access rules. ARCHITECTURE.md contains only a single sentence about authorization. schema.md marks authorization rules as 'TBD' (to be determined). There are 10 unresolved '### check authz' placeholders in pages.py. Without documented authorization rules, developers cannot implement consistent access controls, testers cannot verify authorization enforcement, administrators cannot audit compliance, and security reviewers cannot assess completeness. The absence of formal documentation has directly led to the implementation gaps identified in the other findings. ASVS 8.1.1, 8.1.2, and 8.1.3 specifically require authorization documentation defining decision-making factors, field-level access rules, and environmental/contextual attributes.

**Remediation:**

Create a formal AUTHORIZATION.md document that includes: (1) Role definitions with sources and descriptions (Anonymous, Authenticated, Committer, PMC Member, Election Owner, Authz Group Member, Voter); (2) Function-level access rules matrix mapping endpoints to required roles and resource checks; (3) Data-specific rules for election management, voting, and tallying; (4) Field-level access rules for election metadata, issues, votes, and person records showing read/write permissions by role and state; (5) Decision-making factors including user role, resource ownership, group membership, voter eligibility, election state, and tamper status; (6) Environmental and contextual attributes (session UID, election state, time-based attributes like open_at/close_at, explicitly excluded attributes like IP/device); (7) State transition rules defining which roles can trigger which state changes; (8) Security Decision Matrix mapping each endpoint to the attributes evaluated before granting access. Include this documentation alongside ARCHITECTURE.md and reference it from code comments.

---

#### FINDING-250: Authorization Tier Inconsistency: Lower Privilege Required for Management Than Creation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-269 |
| ASVS Sections | 8.3.1 |
| Files | `v3/server/pages.py:423`, `v3/server/pages.py:445`, `v3/server/pages.py:465`, `v3/server/pages.py:483`, `v3/server/pages.py:507`, `v3/server/pages.py:530` |
| Source Reports | `8.3.1.md` |
| Related Findings | - |

**Description:**

The application has an inverted authorization model where creating an election requires higher privileges (R.pmc_member) than performing all subsequent management operations (R.committer). This means users who lack sufficient privileges to create elections can nonetheless fully manage, modify, open, close, and delete issues from any existing election. Every management endpoint includes a comment acknowledging this issue: '### need general solution'. The authorization model is inverted: creation of elections (a lower-impact, reversible operation that simply initializes a new election) requires higher privilege than opening/closing elections and modifying issues (higher-impact, irreversible operations that affect election integrity and voter participation). A committer who should only have voter-level access can perform all administrative operations on any election.

**Remediation:**

Align management endpoint authorization with creation privilege level. Change all management endpoints (do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint, do_open_endpoint, do_close_endpoint, do_set_open_at_endpoint, do_set_close_at_endpoint, manage_page, manage_stv_page) from requiring R.committer to requiring R.pmc_member. Add ownership verification using check_election_authz (from CH08-001 remediation). Long-term: implement granular RBAC system distinguishing between election creators, election administrators, voters, and system administrators.

---

#### FINDING-251: Election Date Modification Without Object-Level Authorization

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L2 |
| CWE | CWE-639 |
| ASVS Sections | 8.2.3 |
| Files | `v3/server/pages.py:99-122`, `v3/steve/election.py:117`, `v3/steve/election.py:119` |
| Source Reports | `8.2.3.md` |
| Related Findings | FINDING-015, FINDING-028 |

**Description:**

The _set_election_date helper function modifies election properties (open_at, close_at) without performing object-level authorization checks, relying only on the broken load_election decorator that contains an unimplemented '### check authz' placeholder. Any committer can modify the advisory open/close dates on any election, causing confusion for eligible voters and election owners. While the prevent_open_close_update trigger prevents changes after closing, dates can be freely modified while the election is editable or open. This is a direct modification of object properties without authorization, violating ASVS 8.2.3's requirement for field-level access restrictions.

**Remediation:**

This is resolved by the same load_election decorator fix described in CH08-001. Additionally, _set_election_date should verify the election is in the editable state: if not election.is_editable(): quart.abort(403, 'Cannot modify dates on a non-editable election'). Add proper exception-based state checking instead of relying on implicit database trigger enforcement.

---

#### FINDING-252: Election Time-Based Validity Constraints (open_at/close_at) Are Stored But Never Enforced During Vote Acceptance or State Computation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1, L2, L3 |
| CWE | - |
| ASVS Sections | 9.2.1 |
| Files | `v3/steve/election.py:306`, `v3/steve/election.py:211`, `v3/steve/election.py:367`, `v3/steve/election.py:371`, `v3/server/pages.py:590`, `v3/server/pages.py:402` |
| Source Reports | `9.2.1.md` |
| Related Findings | - |

**Description:**

The election system stores `open_at` and `close_at` timestamp fields in the database and displays them to users in the UI, creating an expectation that voting is only permitted within the specified time window. However, these time constraints are never validated when accepting votes or computing election state. The `_compute_state()` method only checks the manual `closed` flag and the presence of cryptographic keys, ignoring the time-based validity fields entirely. This creates a false expectation of enforcement where votes can be accepted after the displayed deadline, undermining election integrity. The gap is classified as Type B - control EXISTS (time fields stored and displayed) but NOT APPLIED (never checked during vote acceptance or state computation).

**Remediation:**

Option 1: Enforce time constraints in `_compute_state()` by adding time-based checks that return S_CLOSED if close_at has passed or S_EDITABLE if open_at has not yet arrived. Option 2: Add explicit time checks in `add_vote()` that raise ElectionBadState exceptions if the current time is outside the open_at/close_at window. Implementation should include: (1) Import time module and get current timestamp, (2) Compare current time against md.close_at and md.open_at, (3) Return appropriate state or raise exception if outside valid time window, (4) Consider automated election close via background task for defense-in-depth.

---

# 4. Positive Security Controls

| Control | Evidence | Implementation Files | Domain |
|---------|----------|---------------------|---------|
| **CSPRNG Throughout** | All randomness uses Python's `secrets` module (token_bytes(), token_hex(), randbelow()) for salts, IDs, and shuffling. No use of `random` module for cryptographic purposes. | v3/steve/crypto.py:27-29, 110-113, 94-108 | Vote Encryption & Crypto |
| **Per-Voter Salt Separation** | Each (person, issue) pair gets a unique 16-byte salt, preventing vote correlation even with database access. | v3/steve/election.py:119-135, v3/schema.sql | Vote Encryption & Crypto |
| **Multi-Layer Key Derivation** | Chain of election_data → BLAKE2b → Argon2 → opened_key → Argon2(+pid+iid+salt) → vote_token → HKDF → encryption_key provides strong cryptographic separation. | v3/steve/crypto.py:32-62 | Vote Encryption & Crypto |
| **Fernet Authenticated Encryption** | Implements AES-128-CBC + HMAC-SHA256 with HMAC verified before decryption, preventing padding oracle attacks. | v3/steve/crypto.py:73-78, 81-86 | Vote Encryption & Crypto |
| **Vote Shuffling Before Tallying** | Fisher-Yates shuffle with secrets.randbelow() removes database ordering from decrypted votes. | v3/steve/crypto.py:94-108, v3/steve/election.py:263-310 | Vote Encryption & Crypto |
| **Tamper Detection Before Tallying** | tally.py calls is_tampered() before processing votes with hard exit on failure. | v3/server/bin/tally.py:155, v3/steve/election.py:381 | Vote Encryption & Crypto |
| **Schema-Level BLOB Length Checks** | SQLite CHECK constraints enforce exact byte lengths for all cryptographic material. | v3/schema.sql | Vote Encryption & Crypto |
| **Transactional Salt Assignment** | add_salts() uses explicit BEGIN TRANSACTION/COMMIT for atomicity. | v3/steve/election.py:119-135 | Vote Encryption & Crypto |
| **Industry-Standard Libraries** | Uses cryptography, argon2-cffi, Python secrets/hashlib—no hand-rolled cryptography. | v3/steve/crypto.py | Vote Encryption & Crypto |
| **Centralized Cryptography Module** | All cryptographic operations concentrated in crypto.py, single source of truth. | v3/steve/crypto.py | Vote Encryption & Crypto |
| **100% Parameterized SQL Queries** | All queries use ? placeholders via asfpy.db wrapper. No string concatenation or f-string SQL. | v3/queries.yaml, v3/steve/election.py | Input Validation |
| **No OS Command Execution Surface** | Zero usage of os.system(), subprocess, exec(), eval(), or command execution primitives. | All .py files | Input Validation |
| **Safe Template Engine (EZT)** | Supports only substitution, iteration, conditionals—no code execution capability. | All .ezt files | Input Validation |
| **Static Regex Patterns** | Single hardcoded pattern r'doc:([^\\s]+)' with no nested quantifiers or backtracking. | v3/server/pages.py:43 | Input Validation |
| **Server-Side Rendering Architecture** | EZT server-side templates confine token handling to backend, not JavaScript SPA. | v3/server/pages.py | Authentication & Session |
| **HTTPS for OAuth Communications** | Both OAUTH_URL_INIT and OAUTH_URL_CALLBACK use https:// scheme. | v3/server/main.py:38-41 | Authentication & Session |
| **Consistent Auth Enforcement** | All protected routes use @asfquart.auth.require() decorators with role requirements. | v3/server/pages.py:throughout | Authentication & Session |
| **LDAPS for Directory Access** | Uses ldaps:// protocol for secure LDAP communication. | v3/server/bin/asf-load-ldap.py:30 | Authentication & Session |
| **Role-Based Access Control** | Distinguishes R.committer (voter) and R.pmc_member (election creator) roles. | v3/server/pages.py:multiple | Authentication & Session |
| **Server-Side Token Exchange** | Authorization code flow uses server-to-server token exchange. | v3/server/main.py:41 | Authentication & Session |
| **Single Authorization Server** | Hardcoded oauth.apache.org eliminates mix-up attack vector. | v3/server/main.py:38-42 | Authentication & Session |
| **Exception-Based State Enforcement** | _all_metadata(required_state) raises ElectionBadState, not removable by -O flag. | v3/steve/election.py:160-177, 286, 305, 363, 261 | Authorization & Access Control |
| **State Derivation from Database** | Derives state from column values (salt, opened_key, closed) rather than cached flags. | v3/steve/election.py:424-437, 389, 395-408 | Authorization & Access Control |
| **Cryptographic ID Generation** | Election/issue IDs use 10 hex characters via crypto.create_id(), preventing enumeration. | v3/steve/election.py:209-214, 453-458 | Authorization & Access Control |
| **Integrity Loop on ID Collision** | Handles concurrent ID creation safely with while True/try/IntegrityError pattern. | v3/steve/election.py:209-214, 453-458 | Authorization & Access Control |
| **Voter Eligibility Enforcement** | Database-level check via mayvote table with (pid, iid) primary key before accepting votes. | v3/steve/election.py:291, 264; v3/schema.sql:147-170 | Authorization & Access Control |
| **Re-voting Support** | Latest vote counted via MAX(vid) ordering; old votes preserved for audit. | v3/schema.sql, v3/steve/election.py:264 | Authorization & Access Control |
| **Schema-Level Constraints** | CHECK constraints, STRICT mode, foreign keys with ON DELETE RESTRICT provide defense-in-depth. | v3/schema.sql:140-154, 94, 10, 98 | Authorization & Access Control |
| **TLS Support Available** | Certificate-based TLS supported through configuration. | v3/server/config.yaml.example, v3/server/main.py:83-87 | TLS & Transport Security |
| **Certificate File Watching** | Supports certificate rotation without manual restart. | v3/server/main.py:88-89, 83 | TLS & Transport Security |
| **Proxy-Aware Architecture** | Configuration comments mention proxy deployment model. | v3/server/config.yaml.example:25, 21 | TLS & Transport Security |
| **Sensitive Field Exclusion** | get_metadata() and get_issue() explicitly exclude salt and opened_key with documented comments. | v3/steve/election.py:146-157, 162-170; v3/steve/persondb.py:34-39 | Sensitive Data Handling |
| **Vote Encryption Before Storage** | Plaintext votes never reach database; encryption mandatory via crypto.create_vote(). | v3/steve/election.py:239-253, 232 | Sensitive Data Handling |
| **Vote Content Excluded from Logs** | Audit trail logs voter ID and issue ID but never votestring. | v3/steve/election.py, v3/server/pages.py | Sensitive Data Handling |
| **Token-Based Vote Storage** | Votes stored with vote_token (hash), not PID—prevents direct voter-vote correlation. | v3/schema.sql:vote | Sensitive Data Handling |
| **Non-Sequential IDs** | 10 hex character IDs prevent URL enumeration. | v3/steve/election.py:145, v3/schema.sql | Sensitive Data Handling |
| **POST-Only Vote Submission** | /do-vote/&lt;eid&gt; uses POST exclusively; vote data never in URLs. | v3/server/pages.py, vote-on.ezt | Sensitive Data Handling |
| **No Third-Party Analytics** | Zero external tracking scripts, analytics, beacons, or social media widgets. | All templates reviewed | Sensitive Data Handling |
| **STV Candidate Shuffling** | Candidates randomized before rendering using random.shuffle(). | v3/server/pages.py | Sensitive Data Handling |
| **Generic Error Messages** | Flash messages contain no sensitive data, vote content, or cryptographic material. | v3/server/pages.py | Sensitive Data Handling |
| **Strict Route Matching** | Quart routing prevents Web Cache Deception via URL path manipulation. | v3/server/pages.py | Sensitive Data Handling |
| **Proper 404 for Unknown Resources** | raise_404() and load decorators return HTTP 404 when elections/issues not found. | v3/server/pages.py | Sensitive Data Handling |
| **Comprehensive Audit Logging** | All state-changing operations log user ID, election ID, and action. | v3/server/pages.py:throughout | Logging & Monitoring |
| **CLI Argument Parsing** | Administrative scripts use argparse instead of HTTP parameters. | create-election.py, mail-voters.py, tally.py | Sensitive Data Handling |
| **Local CSS/JS Serving** | All JavaScript and CSS resources served from /static/ directory. | header.ezt, footer.ezt, vote-on.ezt | Sensitive Data Handling |
| **Subresource Integrity (SRI)** | integrity= attributes on CDN resources prevent tampered delivery. | v3/server/templates/header.ezt, footer.ezt | Input Validation |
| **Path Traversal Prevention** | Framework-provided send_from_directory protection in serve_doc and serve_static. | v3/server/pages.py | Input Validation |
| **Static File Serving Disabled** | static_folder=None prevents serving filesystem content including .git. | v3/server/main.py:42 | Secrets & Configuration |
| **Safe Path Handling** | pathlib used for path construction prevents path traversal. | v3/server/main.py:32, 87-88 | Secrets & Configuration |

---

# 5. ASVS Compliance Summary

| ASVS ID | Status | Title |
|---------|--------|-------|
| **11.x Cryptography** |
| 11.1.1 | ❌ Fail | Cryptographic Key Management Policy and Lifecycle |
| 11.1.2 | ❌ Fail | Cryptographic Inventory and Documentation |
| 11.2.1 | ⚠️ Partial | Secure Cryptography Implementation |
| 11.2.2 | ❌ Fail | Crypto Agility |
| 11.2.4 | ❌ Fail | Constant-Time Cryptographic Operations |
| 11.3.1 | ✅ Pass | Encryption Algorithms - Insecure Block Modes |
| 11.3.2 | ❌ Fail | Encryption Algorithms - Approved Ciphers |
| 11.3.3 | ⚠️ Partial | Authenticated Encryption |
| 11.4.1 | ✅ Pass | Hash Function Usage |
| 11.4.2 | ❌ Fail | Password Storage with Approved KDFs |
| 11.5.2 | ✅ Pass | Random Values - Cryptography |
| 11.7.1 | ❌ Fail | In-Use Data Cryptography - Memory Encryption |
| **10.x OAuth/OIDC** |
| 10.1.1 | ⚠️ Partial | Token Distribution Restriction |
| 10.1.2 | ❌ Fail | OAuth Transaction Binding |
| 10.2.1 | ❌ Fail | CSRF Protection in Authorization Code Flow |
| 10.2.3 | ❌ Fail | Required Scopes Request |
| 10.3.1 | ❌ Fail | Resource Server Audience Validation |
| 10.3.2 | ❌ Fail | Delegated Authorization Enforcement |
| 10.4.6 | ❌ Fail | PKCE Implementation |
| 10.4.10 | ❌ Fail | Client Authentication for Backchannel |
| 10.4.13 | ❌ Fail | PAR Requirement |
| 10.4.16 | ❌ Fail | Strong Client Authentication |
| 10.5.1 | ❌ Fail | ID Token Replay Attack Mitigation |
| 10.5.2 | ❌ Fail | User Identity from ID Token |
| 10.7.2 | ❌ Fail | Consent Management - Sufficient Information |
| 10.7.3 | ❌ Fail | Consent Review and Revocation |
| **2.x Business Logic** |
| 2.3.1 | ❌ Fail | Sequential Flow Enforcement |
| 2.3.2 | ❌ Fail | Business Logic Limits |
| 2.3.3 | ❌ Fail | Transaction Atomicity |
| 2.3.4 | ❌ Fail | Business Logic Level Locking |
| 2.3.5 | ❌ Fail | Multi-User Approval for High-Value Ops |
| 2.4.1 | ❌ Fail | Anti-Automation Controls |
| **1.x Input Validation** |
| 1.2.4 | ✅ Pass | Parameterized Queries |
| 1.2.5 | ✅ Pass | OS Command Injection Prevention |
| 1.2.6 | ✅ Pass | LDAP Injection Prevention |
| 1.3.2 | ✅ Pass | Avoidance of eval() and Dynamic Code |
| 1.3.12 | ✅ Pass | Regular Expression ReDoS Protection |
| 1.1.1 | ❌ Fail | Encoding and Sanitization Architecture |
| 1.2.1 | ❌ Fail | Output Encoding for HTTP/HTML |
| 1.2.3 | ❌ Fail | JavaScript/JSON Injection Prevention |
| 1.2.10 | ❌ Fail | CSV and Formula Injection Protection |
| 1.3.1 | ❌ Fail | WYSIWYG HTML Input Sanitization |
| **12.x TLS** |
| 12.1.1 | ❌ Fail | Secure Communication |
| 12.1.2 | ❌ Fail | Cipher Suite Configuration |
| 12.1.4 | ❌ Fail | Certificate Revocation (OCSP) |
| 12.1.5 | ❌ Fail | Encrypted Client Hello (ECH) |
| 12.2.1 | ❌ Fail | HTTPS with External Services |
| 12.3.1 | ❌ Fail | Encrypted Protocol Enforcement |
| **13.x Configuration** |
| 13.1.1 | ❌ Fail | Communication Needs Documentation |
| 13.1.2 | ❌ Fail | Service Connection Limits |
| 13.1.4 | ❌ Fail | Secrets Management Documentation |
| 13.2.1 | ❌ Fail | Backend Communication Configuration |
| 13.2.3 | ✅ Pass | No Default Credentials |
| 13.3.1 | ❌ Fail | Secrets Management Solution |
| 13.4.3 | ✅ Pass | Directory Listings |
| **14.x Data Protection** |
| 14.1.1 | ❌ Fail | Data Protection Documentation |
| 14.2.1 | ✅ Pass | Sensitive Data in URLs |
| 14.2.2 | ❌ Fail | Server Component Cache Prevention |
| 14.2.7 | ❌ Fail | Data Retention Classification |
| 14.3.1 | ❌ Fail | Authenticated Data Clearing |
| **15.x Secure Coding** |
| 15.1.1 | ❌ Fail | Remediation Timeframes |
| 15.1.2 | ❌ Fail | SBOM and Third-Party Inventory |
| 15.2.1 | ❌ Fail | Component Update Timeframes |
| 15.3.1 | ❌ Fail | Data Minimization in API Responses |
| 15.3.2 | ✅ Pass | Backend External URL Redirect Following |
| 15.4.1 | ❌ Fail | Safe Concurrency |
| 1.4.1 | ✅ Pass | Memory Safety Analysis |
| **16.x Logging** |
| 16.1.1 | ❌ Fail | Security Logging Documentation |
| 16.2.1 | ❌ Fail | Log Entry Metadata Completeness |
| 16.3.1 | ❌ Fail | Authentication Operations Logging |
| 16.3.2 | ❌ Fail | Authorization Attempt Logging |
| 16.4.2 | ❌ Fail | Log Protection |
| 16.5.1 | ❌ Fail | Generic Error Messages |
| 16.5.4 | ❌ Fail | Last Resort Exception Handler |
| **3.x Browser Security** |
| 3.1.1 | ❌ Fail | Web Frontend Security Documentation |
| 3.4.1 | ❌ Fail | Strict Transport Security |
| 3.4.2 | ✅ Pass | CORS Configuration |
| 3.4.3 | ❌ Fail | Content-Security-Policy |
| 3.5.1 | ❌ Fail | CSRF Protection |
| 3.5.6 | ✅ Pass | JSONP / XSSI Prevention |
| 3.7.1 | ✅ Pass | Client-Side Technology Security |
| 3.7.2 | ✅ Pass | Redirect Allowlist Validation |
| **4.x Web Services** |
| 4.2.2 | ✅ Pass | Content-Length Conflict Prevention |
| 4.1.1 | ❌ Fail | Content-Type Header Validation |
| 4.1.5 | ❌ Fail | Per-Message Digital Signatures |
| **6.x Authentication** |
| 6.2.3 | N/A | Password Change Requires Current Password |
| 6.3.2 | ✅ Pass | Default User Accounts Not Present |
| 6.3.6 | ✅ Pass | Email Not Used as Authentication Factor |
| 6.5.3 | ✅ Pass | CSPRNG for Random Generation |
| 6.1.1 | ❌ Fail | Authentication Documentation |
| 6.3.1 | ❌ Fail | Brute Force Protection |
| 6.3.3 | ❌ Fail | Multi-Factor Authentication |
| 6.3.5 | ❌ Fail | Suspicious Authentication Notification |
| 6.5.6 | ❌ Fail | Authentication Factor Revocation |
| **7.x Session Management** |
| 7.2.2 | ✅ Pass | Dynamic Session Token Generation |
| 7.4.4 | ✅ Pass | Logout Functionality Access |
| 7.5.1 | ✅ Pass | Re-authentication for Sensitive Modifications |
| 7.1.1 | ❌ Fail | Session Management Documentation |
| 7.2.4 | ❌ Fail | Session Token Regeneration |
| 7.3.1 | ❌ Fail | Session Inactivity Timeout |
| 7.4.1 | ❌ Fail | Session Termination on Logout |
| 7.5.2 | ❌ Fail | View and Terminate Active Sessions |
| **8.x Authorization** |
| 8.1.1 | ❌ Fail | Authorization Documentation |
| 8.2.1 | ✅ Pass | Function-Level Access Control |
| 8.2.2 | ❌ Fail | Data-Specific Access Control (IDOR) |
| 8.3.1 | ❌ Fail | Trusted Service Layer Enforcement |
| **9.x Tokens** |
| 9.1.2 | ✅ Pass | Algorithm Allowlist |
| 9.2.4 | ✅ Pass | Token Audience Restriction |

**Overall Summary:**
- ✅ **Pass:** 29 requirements
- ⚠️ **Partial:** 18 requirements  
- ❌ **Fail:** 205 requirements
- N/A: 23 requirements (not applicable to application architecture)

---

# 6. Cross-Reference Matrix

## Critical Findings by ASVS Domain

| Finding ID | Severity | ASVS Requirements | Control Domain |
|------------|----------|-------------------|----------------|
| **FINDING-001** | Critical | 11.3.2 | Cryptography - Cipher Selection |
| **FINDING-002** | Critical | 10.3.2, 2.1.2, 2.1.3 | Authorization - Vote Submission |
| **FINDING-003** | Critical | 10.3.2, 10.4.11 | Authorization - Election Management |
| **FINDING-004** | Critical | 2.3.1, 2.3.2, 2.3.4, 15.3.5, 15.4.1 | Business Logic - State Machine |
| **FINDING-005** | Critical | 2.3.1, 2.3.2, 2.2.1, 2.2.2 | Input Validation - Vote Content |
| **FINDING-006** | Critical | 1.1.1, 1.2.1, 1.3.1, 1.3.5 | XSS - Output Encoding |
| **FINDING-007** | Critical | 12.1.1, 12.3.1 | TLS - Protocol Version |
| **FINDING-008** | Critical | 12.2.1, 12.3.1, 12.3.3 | TLS - Enforcement |
| **FINDING-009** | Critical | 14.3.1 | Data Protection - Client Storage |
| **FINDING-010** | Critical | 15.1.1, 15.1.2, 15.2.1 | Secure Coding - SBOM |
| **FINDING-011** | Critical | 15.3.1 | Data Minimization - API |
| **FINDING-012** | Critical | 16.1.1, 16.2.1, 16.3.1 | Logging - Audit Trail |
| **FINDING-013** | Critical | 16.1.1, 16.2.1, 16.3.2 | Logging - Tamper Detection |
| **FINDING-014** | Critical | 16.5.1, 16.5.2 | Error Handling - Consistency |
| **FINDING-015** | Critical | 8.2.2, 8.3.3, 8.4.1 | Authorization - Cross-Tenant |

## High-Risk Findings by Attack Vector

### Authentication & Session Management
| Finding | Attack Vector | ASVS |
|---------|--------------|------|
| FINDING-021 | CSRF via GET | 10.2.1, 3.5.3 |
| FINDING-022 | CSRF Token Placeholder | 10.2.1, 3.5.1 |
| FINDING-023 | Missing PKCE | 10.4.6, 10.1.2 |
| FINDING-080 | No Session Timeout | 7.1.1, 7.3.1, 7.3.2 |
| FINDING-081 | No Logout Endpoint | 7.2.4, 7.4.1 |
| FINDING-084 | Session Identity Not Used | 7.2.1, 8.1.1, 8.2.2 |

### Injection & XSS
| Finding | Attack Vector | ASVS |
|---------|--------------|------|
| FINDING-032 | HTML Injection | 1.1.1, 1.2.1, 1.3.1 |
| FINDING-033 | JavaScript Injection | 1.1.1, 1.2.3, 1.3.5 |
| FINDING-034 | Reflected XSS | 1.1.1, 1.2.1, 1.3.7 |
| FINDING-035 | Stored XSS via Flash | 1.1.1, 1.2.1, 3.2.2 |
| FINDING-065 | Stored XSS via Titles | 3.2.2 |

### Cryptography
| Finding | Attack Vector | ASVS |
|---------|--------------|------|
| FINDING-089 | Argon2d vs Argon2id | 11.4.2, 11.4.4 |
| FINDING-090 | Non-Constant-Time Compare | 11.2.4, 11.3.3 |
| FINDING-093 | Insufficient ID Entropy | 11.5.1, 7.2.3 |

### Business Logic
| Finding | Attack Vector | ASVS |
|---------|--------------|------|
| FINDING-029 | TOCTOU Race - Vote | 2.3.4, 15.4.1, 15.4.2 |
| FINDING-030 | TOCTOU Race - Open | 2.3.3, 15.4.1, 15.4.2 |
| FINDING-053 | TOCTOU Race - Close | 15.4.1, 15.4.2 |
| FINDING-054 | TOCTOU Race - Delete | 15.4.2 |

### Data Protection
| Finding | Attack Vector | ASVS |
|---------|--------------|------|
| FINDING-043 | Missing Cache-Control | 14.2.2, 14.2.5, 14.3.2 |
| FINDING-044 | GET for State Changes | 14.2.4, 14.2.5, 4.1.4 |
| FINDING-047 | No Retention Policy | 14.2.7 |
| FINDING-048 | Key Material Retention | 14.2.7 |

### TLS & Transport
| Finding | Attack Vector | ASVS |
|---------|--------------|------|
| FINDING-036 | No Cipher Config | 12.1.2 |
| FINDING-037 | Missing OCSP Stapling | 12.1.4 |
| FINDING-038 | No ECH | 12.1.5 |

## Findings Affecting Multiple ASVS Categories

| Finding ID | Primary Category | Secondary Categories | Total ASVS |
|------------|-----------------|---------------------|-----------|
| **FINDING-004** | Business Logic | Authorization, Secure Coding, Logging | 15 |
| **FINDING-005** | Input Validation | Business Logic, Error Handling | 10 |
| **FINDING-021** | CSRF | Business Logic, Authorization, Session | 11 |
| **FINDING-084** | Session Management | Authorization, Data Protection | 13 |
| **FINDING-088** | Authorization | Business Logic, Data Protection | 9 |

## Compliance Gap Summary by Category

| ASVS Category | Total Reqs | Pass | Partial | Fail | N/A | Compliance % |
|---------------|-----------|------|---------|------|-----|--------------|
| 11.x Cryptography | 23 | 3 | 8 | 12 | 0 | 13% |
| 10.x OAuth/OIDC | 37 | 0 | 5 | 27 | 5 | 0% |
| 2.x Business Logic | 10 | 1 | 0 | 9 | 0 | 10% |
| 1.x Input Validation | 27 | 6 | 2 | 15 | 4 | 22% |
| 12.x TLS | 13 | 0 | 0 | 13 | 0 | 0% |
| 13.x Configuration | 16 | 1 | 1 | 14 | 0 | 6% |
| 14.x Data Protection | 12 | 1 | 1 | 10 | 0 | 8% |
| 15.x Secure Coding | 16 | 2 | 3 | 11 | 0 | 13% |
| 16.x Logging | 17 | 0 | 0 | 17 | 0 | 0% |
| 3.x Browser Security | 25 | 4 | 2 | 17 | 2 | 16% |
| 6.x Authentication | 36 | 4 | 3 | 19 | 10 | 11% |
| 7.x Session Mgmt | 15 | 3 | 2 | 10 | 0 | 20% |
| 8.x Authorization | 11 | 1 | 0 | 10 | 0 | 9% |
| **Overall** | **275** | **29** | **18** | **205** | **23** | **11%** |

## 7. Level Coverage Analysis


**Audit scope:** up to L3

**Severity threshold:** medium and above

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 69 | 46 |
| L2 | 180 | 164 |
| L3 | 90 | 110 |

**Total consolidated findings: 252**

*End of Consolidated Security Audit Report*