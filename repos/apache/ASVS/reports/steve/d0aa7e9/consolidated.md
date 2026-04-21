# Security Audit Consolidated Report

## apache/tooling-agents — STeVe Voting System

## Report Metadata

| Field | Value |
|---|---|
| **Repository** | `apache/tooling-agents` |
| **ASVS Level** | L1 |
| **Commit** | `d0aa7e9` |
| **Date** | Apr 21, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 29 |
| **Total Findings** | 15 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info | **Total** |
|:---:|:---:|:---:|:---:|:---:|:---:|
| 14 | 1 | 0 | 0 | 0 | **15** |

The audit consolidated **29 source reports** across **8 ASVS verification domains** scoped to **Level 1** requirements. Of the 15 unique findings, **14 are rated Critical** and **1 is rated High**, yielding a severity profile heavily concentrated at the top of the scale. No Medium, Low, or Informational findings were identified at L1 scope. This distribution reflects a codebase with strong foundational primitives in certain domains—particularly cryptographic design and SQL injection prevention—but with significant, systemic gaps in output encoding, transport security enforcement, business-logic integrity, and supply-chain governance.

### Level Coverage

All findings map to **ASVS Level 1** requirements. The eight audited domains and their finding counts are:

| Domain | Findings |
|---|:---:|
| Web Input Validation | 5 |
| TLS / Transport Security | 3 |
| Business Logic — Voting | 2 |
| Vote Encryption & Storage | 1 |
| Data Minimization & Exposure | 1 |
| Dependency Configuration | 2 |
| Authentication & Authorization | 0 |
| Admin & Tallying Operations | 0 |

Authentication and authorization, as well as admin tallying operations, produced **zero findings at L1**, reflecting the mature delegation model to ASF's OAuth infrastructure and the generally sound access-control decorator coverage.

### Top 5 Risks

**1. Pervasive Cross-Site Scripting (XSS) — 5 Critical Findings**
Findings 002–006 collectively demonstrate that the EZT template layer lacks a default-encode-on-output policy. Stored XSS vectors exist in flash messages, election/issue metadata rendered in HTML context, JavaScript string interpolation, URL path parameters in error pages, and dynamically constructed URLs. Because the application manages election data for Apache PMC members, successful exploitation could allow an attacker to act on behalf of authenticated voters or election administrators, directly compromising election integrity. The breadth of affected templates indicates a **systemic architectural gap** rather than isolated oversights.

**2. Transport Security Not Enforced — 2 Critical + 1 High Finding**
FINDING-007 (plain HTTP permitted), FINDING-008 (no TLS protocol version floor), and FINDING-015 (self-signed certificates accepted) together mean that an on-path attacker can intercept or downgrade every external-facing connection. Vote payloads, session tokens, and administrative operations may traverse the network without confidentiality or integrity protection. While TLS certificate-loading capability exists in the codebase, the **opt-in** rather than **enforced** posture leaves the default deployment exposed.

**3. Business-Logic Integrity Gaps — 2 Critical Findings**
FINDING-009 reveals that election lifecycle state enforcement relies on Python `assert` statements, which are stripped in optimized (`-O`) runtimes—converting a present control into an absent one. FINDING-010 identifies that the vote-submission flow performs **no server-side validation of vote content**, meaning malformed, empty, or out-of-range ballots can be persisted and counted. Together these findings threaten the correctness and trustworthiness of election outcomes.

**4. Incomplete Cryptographic Cipher Migration — 1 Critical Finding**
FINDING-001 documents that all vote encryption currently uses AES-128-CBC via Fernet despite an in-progress migration path toward XChaCha20-Poly1305. CBC mode, while protected by Fernet's Encrypt-then-MAC construction, does not provide the authenticated encryption with associated data (AEAD) property required by ASVS 11.3.2. The migration is structurally incomplete—no AEAD cipher path is reachable in the current commit.

**5. Absent Supply-Chain and Dependency Controls — 2 Critical Findings**
FINDING-013 and FINDING-014 identify the complete absence of a Software Bill of Materials (SBOM), dependency version pinning/tracking, and documented risk-based remediation timeframes for third-party components. For an application processing sensitive governance data, the inability to rapidly assess exposure to upstream vulnerabilities represents a material operational risk.

### Positive Controls

Despite the critical findings above, the audit identified a substantial number of well-implemented security controls that demonstrate deliberate security engineering in several domains:

- **Cryptographic Architecture.** The vote encryption subsystem employs a rigorous multi-layer key derivation chain (BLAKE2b → Argon2 → HKDF-SHA256 → Fernet), uses exclusively approved hash functions, centralizes all Argon2 operations through a single `_hash()` function, and generates all randomness via `secrets` module CSPRNGs. Password hashing uses Argon2 with appropriately configured memory-hard parameters (64 MB, time=2, parallelism=4). Salt lengths are enforced at the database schema level via `CHECK` constraints. No ECB mode, no PKCS#1 v1.5, no MD5/SHA-1, and no custom cryptographic implementations were found.

- **SQL Injection Prevention.** 100% of database operations use parameterized queries through `asfpy.db` wrapper methods (`.perform()`, `.first_row()`), providing architectural enforcement against injection. No string-concatenated query construction was identified anywhere in the codebase.

- **Command and Code Injection Elimination.** The codebase has a zero OS command execution surface—no imports of `os.system`, `subprocess`, `commands`, or `popen` exist across all 20 Python source files. Similarly, no use of `eval()`, `exec()`, `compile()`, `pickle` deserialization, or dynamic `__import__()` was found. The EZT template engine supports only substitution, iteration, and conditionals with no code execution capability.

- **XML Attack Surface Elimination.** The architecture exclusively uses non-XML data formats (JSON, URL-encoded forms, EZT templates, YAML) with zero dependencies on XML parsing libraries, completely eliminating XXE and XML-based attack vectors.

- **Authentication & Authorization Delegation.** The application correctly operates as an OAuth client, delegating all authorization server responsibilities to ASF infrastructure via the `asfquart.auth` framework. Role-based access control is enforced through decorators with differentiated privilege levels (`pmc_member` for election creation, `committer` for voting). Session data is consumed read-only, no OAuth server endpoints are exposed, and all redirects use hardcoded paths or database-constrained identifiers.

- **Selective Output Encoding Present.** While not applied universally (per the XSS findings), the codebase does demonstrate correct dual-context encoding (`[format "js,html"]`) in certain JavaScript-in-HTML-attribute contexts, client-side `escapeHtml()` for dynamic DOM manipulation, and Subresource Integrity (SRI) attributes on CDN-loaded resources.

- **Vote Integrity Controls.** Cryptographic shuffle (Fisher-Yates with `secrets.randbelow()`) prevents vote-ordering information leakage. Tamper detection via `opened_key` recomputation verifies election data integrity before tallying. Sensitive fields (`salt`, `opened_key`) are explicitly excluded from metadata API responses.

- **Input Validation.** Date inputs are validated via `datetime.fromisoformat()` with exception handling, vote types are validated against an allowlist, and election/issue existence is verified via database lookups in route decorators with 100% coverage.

---

## 3. Findings

### 3.1 Critical

#### FINDING-001: AES-128-CBC (Fernet) Used Instead of Approved AEAD Cipher; Incomplete Migration to XChaCha20-Poly1305

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 11.3.2 |
| **Affected Files** | `v3/steve/crypto.py:63-75`, `v3/steve/crypto.py:77-80`, `v3/steve/crypto.py:84-88`, `v3/steve/election.py:236`, `v3/steve/election.py:271` |
| **Source Reports** | 11.3.2.md |
| **Related Findings** | None |

**Description:**

The application uses Fernet (AES-128-CBC + HMAC-SHA256) for vote encryption instead of an approved AEAD cipher mode such as AES-GCM or XChaCha20-Poly1305. Evidence shows an incomplete migration: the HKDF key derivation is explicitly configured for XChaCha20-Poly1305 (with `info=b'xchacha20_key'` and 32-byte key length), but the actual encryption/decryption operations still use Fernet's AES-128-CBC mode. This is a Type B gap where the control EXISTS (HKDF configured for XChaCha20-Poly1305) but is NOT APPLIED (Fernet/AES-128-CBC used for actual encryption). Fernet uses AES-128-CBC (not AES-GCM or another approved AEAD mode), splits its 32-byte key into 16 bytes for HMAC-SHA256 and 16 bytes for AES-128 encryption, and while encrypt-then-MAC mitigates padding oracle attacks, CBC mode remains vulnerable to implementation-level side channels. All vote ciphertext stored in the vote table uses this unapproved cipher mode, providing only AES-128 strength instead of modern AES-256 recommendations for high-sensitivity voting data.

**Remediation:**

Complete the migration indicated by the code comments. Replace Fernet with XChaCha20-Poly1305 (as the HKDF is already configured for) using the nacl.secret.SecretBox library, or alternatively implement AES-256-GCM using cryptography.hazmat.primitives.ciphers.aead.AESGCM. For XChaCha20-Poly1305: derive a 32-byte key using the existing HKDF setup, create a nacl.secret.SecretBox with the key, and use box.encrypt() with auto-generated nonce for encryption and box.decrypt() for decryption. For AES-256-GCM: update HKDF info parameter to 'aesgcm_vote_key', create AESGCM instance with 32-byte key, generate 96-bit nonce using os.urandom(12), prepend nonce to ciphertext for storage, and split nonce from ciphertext during decryption. Note: Migration requires a re-encryption strategy for existing vote data or a version-aware decryption path to handle both old Fernet-encrypted votes and new AEAD-encrypted votes during transition.

---

#### FINDING-002: Stored XSS via Flash Messages Rendered Without HTML Encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1 |
| **Affected Files** | `v3/server/templates/flashes.ezt:1-6`, `v3/server/pages.py:455`, `v3/server/pages.py:518`, `v3/server/pages.py:537`, `v3/server/pages.py:426` |
| **Source Reports** | 1.2.1.md |
| **Related Findings** | FINDING-003, FINDING-004, FINDING-005, FINDING-006 |

**Description:**

Flash messages containing user-controlled data (election titles, issue titles, issue IDs) are rendered in HTML without encoding in the flashes.ezt template. When users create elections or issues with malicious titles, the unsanitized content is stored in the session and rendered on subsequent page loads, executing arbitrary JavaScript. The EZT template engine's [format "html"] directive exists but is not applied to [flashes.message]. User input flows from form submissions through flash_success()/flash_danger() calls with f-strings containing form.title or iid directly into the template.

**Remediation:**

Apply [format "html"] encoding to the flash message output in flashes.ezt: [for flashes]&lt;div class="alert alert-[flashes.category] alert-dismissible fade show" role="alert"&gt;[format "html"][flashes.message][end]&lt;button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"&gt;&lt;/button&gt;&lt;/div&gt;[end]

---

#### FINDING-003: Stored XSS via User-Controlled Data Rendered in HTML Context Without Encoding Across Multiple Templates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1, 1.3.1 |
| **Affected Files** | `v3/server/templates/manage.ezt:241`, `v3/server/templates/manage.ezt:283`, `v3/server/templates/manage-stv.ezt:175`, `v3/server/templates/manage-stv.ezt:196`, `v3/server/templates/admin.ezt:19`, `v3/server/templates/voter.ezt:49`, `v3/server/templates/voter.ezt:96`, `v3/server/templates/vote-on.ezt:88`, `v3/server/templates/vote-on.ezt:131`, `v3/server/templates/vote-on.ezt:163`, `v3/server/pages.py:rewrite_description function` |
| **Source Reports** | 1.2.1.md, 1.3.1.md |
| **Related Findings** | FINDING-002, FINDING-004, FINDING-005, FINDING-006 |

**Description:**

User-controlled data including election titles, issue titles, issue descriptions, owner names, and authorization strings are rendered in HTML body contexts without encoding across multiple templates (manage.ezt, manage-stv.ezt, admin.ezt, voter.ezt, vote-on.ezt). The same templates correctly use [format "js,html"] for JavaScript onclick contexts, demonstrating awareness of the encoding mechanism but inconsistent application. This allows election administrators to inject persistent JavaScript that executes for all users viewing elections. The rewrite_description() function in pages.py compounds the issue by constructing HTML from user input without pre-escaping, making template-level encoding insufficient.

**Remediation:**

Apply [format "html"] to all user-controlled template variables in HTML contexts: &lt;strong&gt;[format "html"][issues.title][end]&lt;/strong&gt;, &lt;div class="description mt-2"&gt;[format "html"][issues.description][end]&lt;/div&gt;, &lt;h5 class="card-title"&gt;[format "html"][owned.title][end]&lt;/h5&gt;, &lt;h1 class="h4 mb-0 fw-semibold"&gt;[format "html"][election.title][end]&lt;/h1&gt;. Additionally, fix rewrite_description() to HTML-encode description text before wrapping in HTML using html.escape(). For comprehensive protection, integrate a server-side HTML sanitization library (bleach or nh3) into rewrite_description() to sanitize the raw description first using bleach.clean() with tags=[], then apply the doc: link conversion on the now-safe text.

---

#### FINDING-004: Stored XSS via Unencoded Server Data Embedded in JavaScript Context in vote-on.ezt

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1, 1.2.3 |
| **Affected Files** | `v3/server/templates/vote-on.ezt:215-228`, `v3/server/pages.py:258-263` |
| **Source Reports** | 1.2.1.md, 1.2.3.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-005, FINDING-006 |

**Description:**

Server-side data including issue titles, candidate labels, and candidate names are embedded directly into an inline JavaScript object (STV_CANDIDATES) without encoding in vote-on.ezt. The template uses raw EZT variable interpolation within JavaScript string literals, allowing JavaScript injection through quote escaping. While the same template includes a client-side escapeHtml() function for dynamic DOM operations, this does not protect the server-rendered inline data block. Election administrators can inject JavaScript payloads through issue titles or candidate names in the KV labelmap that execute for every voter accessing the voting page.

**Remediation:**

Use [format "js"] or [format "js,html"] for all user-controlled values in JavaScript contexts: const STV_CANDIDATES = { "[issues.iid]": { seats: [issues.seats], title: "[format "js"][issues.title][end]", candidates: [[for issues.candidates]{ label: "[format "js"][issues.candidates.label][end]", name: "[format "js"][issues.candidates.name][end]" },[end]] } }; Alternatively, use a safer architecture pattern by serializing data as JSON from Python and embedding as a data attribute, then parsing with JSON.parse() client-side.

---

#### FINDING-005: Reflected XSS via URL Path Parameters in Error Templates Without HTML Encoding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1 |
| **Affected Files** | `v3/server/templates/e_bad_eid.ezt:8`, `v3/server/templates/e_bad_iid.ezt:8`, `v3/server/templates/e_bad_pid.ezt:8`, `v3/server/pages.py:175`, `v3/server/pages.py:200`, `v3/server/pages.py:328` |
| **Source Reports** | 1.2.1.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-004, FINDING-006 |

**Description:**

URL path parameters (eid, iid, pid) are reflected in error templates (e_bad_eid.ezt, e_bad_iid.ezt, e_bad_pid.ezt) without HTML encoding. When the load_election() or load_election_issue() decorators catch ElectionNotFound exceptions, they set result.eid/iid/pid directly from the URL-decoded path parameter and render error templates. The templates output these values using raw EZT variable interpolation [eid], [iid], [pid] without [format "html"], allowing attackers to inject HTML and JavaScript through crafted URLs. This enables reflected XSS attacks against authenticated users who click malicious links.

**Remediation:**

Apply [format "html"] to all URL parameter outputs in error templates: The Election ID ([format "html"][eid][end]) does not exist..., The Issue ID ([format "html"][iid][end]) does not exist..., The Person ID ([format "html"][pid][end]) does not exist...

---

#### FINDING-006: Stored XSS via Unencoded Untrusted Data in Dynamically Built URL

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.2 |
| **Affected Files** | `v3/server/pages.py:55-63`, `v3/server/templates/vote-on.ezt` |
| **Source Reports** | 1.2.2.md |
| **Related Findings** | FINDING-002, FINDING-003, FINDING-004, FINDING-005 |

**Description:**

The rewrite_description() function dynamically builds URLs by extracting filenames from user-controlled issue descriptions using the pattern doc:filename. These filenames are inserted directly into href attributes without URL encoding or HTML attribute encoding, creating a stored XSS vulnerability. The control (URL encoding / HTML attribute encoding) does not exist anywhere in the data flow path. The filename captured by regex doc:([^\s]+) is injected directly into an href attribute and link text. Any authenticated committer can create issues on any election (the check authz placeholder is not implemented), making this exploitable by any authenticated user against all voters.

**Remediation:**

Apply URL encoding and HTML escaping to the rewrite_description function:

```python
import html
from urllib.parse import quote

def rewrite_description(issue):
    """Rewrite issue description: wrap in <pre> and convert doc:filename to links."""
    import re
    desc = html.escape(issue.description)  # HTML-escape the entire description first
    def repl(match):
        filename = match.group(1)
        # URL-encode for path context, HTML-escape for attribute context
        safe_href = html.escape(f'/docs/{issue.iid}/{quote(filename, safe="")}')
        safe_text = html.escape(filename)
        return f'<a href="{safe_href}">{safe_text}</a>'
    desc = re.sub(r'doc:([^\s]+)', repl, desc)
    issue.description = f'<pre>{desc}</pre>'
```

Additionally: Move HTML construction to templates to pass structured data (filename, iid) to EZT templates with proper [format] directives; Implement authorization checks to complete the check authz placeholders throughout pages.py; Consider migrating from EZT to a modern templating engine with auto-escaping by default (e.g., Jinja2); Establish secure coding guidelines that all HTML construction must occur in templates, not Python code

---

#### FINDING-007: TLS Not Enforced - Application Permits Plain HTTP Operation for All External-Facing Services

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS Section(s)** | 12.2.1, 12.2.2 |
| **Affected Files** | `v3/server/main.py:84-90`, `v3/server/main.py:97-118`, `v3/server/config.yaml.example:27-31` |
| **Source Reports** | 12.2.1.md, 12.2.2.md |
| **Related Findings** | None |

**Description:**

The application implements TLS as an optional, bypassable configuration toggle rather than a mandatory security control. The conditional check `if app.cfg.server.certfile:` on line 84 means when the certfile config value is empty, blank, or absent, the server launches over plain HTTP with zero warnings, zero errors, and zero compensating controls. The configuration comments actively document this as intended behavior. There is no startup validation that rejects a missing TLS configuration, no HTTP listener that redirects to HTTPS, no HSTS header injection, and no warning log message when operating without TLS. The application silently degrades to insecure transport. In ASGI mode (`run_asgi()`), the function creates the application without any TLS parameters, delegating all transport security to the external ASGI server or reverse proxy with no verification that such protection exists. For this voting system, plain HTTP operation exposes authentication tokens (ASF OAuth tokens and session cookies transmitted in cleartext), vote contents (captured or modified during transmission before encryption), election management operations, and results in complete loss of transport security guarantees.

**Remediation:**

Make TLS mandatory by enforcing certificate validation at startup - fail with a critical error if certfile/keyfile are missing or invalid. Remove configuration documentation suggesting plain HTTP is acceptable. Add HSTS response header (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) to all responses. For ASGI mode, document mandatory Hypercorn TLS configuration and add startup validation of `X-Forwarded-Proto` or equivalent. Consider adding an HTTP listener that returns 301 redirects to HTTPS to handle accidental plaintext connections. If proxy architecture is intended, document it as a deployment requirement and add a configuration flag (e.g., `behind_proxy: true`) that explicitly acknowledges this choice with appropriate validation.

---

#### FINDING-008: No TLS Protocol Version Enforcement - Server May Accept Deprecated TLS 1.0/1.1 Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 12.1.1 |
| **Affected Files** | `v3/server/main.py:83-91`, `v3/server/main.py:99-118`, `v3/server/config.yaml.example` |
| **Source Reports** | 12.1.1.md |
| **Related Findings** | None |

**Description:**

The application constructs TLS parameters by passing only `certfile` and `keyfile` as keyword arguments to `app.runx()`. At no point in the codebase is an `ssl.SSLContext` explicitly created or configured. This means: (1) No `ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2` - Python's `ssl.SSLContext` defaults `minimum_version` to `TLSVersion.MINIMUM_SUPPORTED`, which is typically TLS 1.0 on most systems. (2) No protocol flags - No use of `ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1` to disable deprecated versions. (3) No TLS 1.3 preference - No configuration ensures TLS 1.3 is the preferred negotiation outcome. (4) Both deployment modes affected - `run_standalone()` passes raw paths; `run_asgi()` creates no SSL configuration at all, deferring entirely to Hypercorn's own defaults. An attacker can force protocol downgrade to TLS 1.0/1.1 and exploit known cryptographic weaknesses (BEAST, POODLE, Lucky Thirteen) to decrypt authentication tokens or encrypted vote payloads in transit.

**Remediation:**

Create an explicit `ssl.SSLContext` with enforced minimum version and pass it to the server framework. Implement a `_create_tls_context()` function that: (1) Creates an `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`, (2) Sets `ctx.minimum_version = ssl.TLSVersion.TLSv1_2` and `ctx.maximum_version = ssl.TLSVersion.TLSv1_3`, (3) Disables compression and enforces server cipher order with appropriate options flags, (4) Restricts cipher suites to strong modern ciphers using `ctx.set_ciphers()`, (5) Loads the certificate chain. For ASGI/Hypercorn deployment, provide a `hypercorn.toml` configuration file that enforces TLS 1.2+ with modern ciphers. Add `minimum_tls_version` and `ciphers` fields to the config schema. Implement startup warning/abort when `certfile` is empty and server is not binding to localhost.

---

#### FINDING-009: Election Lifecycle State Enforcement Uses `assert` Statements — Control Exists But Is Removable (Type B Gap)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1 |
| **Affected Files** | `v3/steve/election.py:50`, `v3/steve/election.py:70`, `v3/steve/election.py:123`, `v3/steve/election.py:208`, `v3/steve/election.py:228`, `v3/steve/election.py:241`, `v3/steve/election.py:273`, `v3/server/pages.py:447`, `v3/server/pages.py:466`, `v3/server/pages.py:483`, `v3/server/pages.py:510`, `v3/server/pages.py:534` |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | None |

**Description:**

Seven critical election lifecycle management methods rely exclusively on Python `assert` statements for state enforcement. When the application runs with the `-O` optimization flag (a standard production practice), all `assert` statements are removed from bytecode, completely eliminating state transition controls. This allows the election state machine (editable → open → closed) to be traversed in arbitrary order, including backwards transitions and step skipping. The codebase contains a proper enforcement mechanism (`_all_metadata(required_state)`) that raises `ElectionBadState` exceptions and is used correctly in voting-related methods (`add_vote()`, `tally_issue()`, `has_voted_upon()`), but this pattern was not applied to administrative lifecycle methods.

**Remediation:**

Replace all `assert` statements used for state enforcement with the existing `_all_metadata(required_state)` mechanism. For example:

```python
def open(self, pdb):
    # Verify the Election is in the editing state (raises ElectionBadState if not)
    self._all_metadata(required_state=self.S_EDITABLE)
    
    self.add_salts()
    edata = self.gather_election_data(pdb)
    salt = crypto.gen_salt()
    opened_key = crypto.gen_opened_key(edata, salt)
    self.c_open.perform(salt, opened_key, self.eid)

def close(self):
    "Close an election."
    # Verify the Election is open (raises ElectionBadState if not)
    self._all_metadata(required_state=self.S_OPEN)
    self.c_close.perform(self.eid)

def add_issue(self, title, description, vtype, kv):
    "Add a new issue with a generated unique IID."
    self._all_metadata(required_state=self.S_EDITABLE)
    if vtype not in vtypes.TYPES:
        raise ValueError(f'Invalid vote type: {vtype}')
    # ... rest of method

def delete(self):
    "Delete this Election and its Issues and Person/Issue pairs."
    self._all_metadata(required_state=self.S_EDITABLE)
    # ... rest of method
```

Apply same pattern to: edit_issue(), delete_issue(), add_voter(), add_salts()

---

#### FINDING-010: Vote Content Validation Step Entirely Absent in Vote Submission Flow (Type A Gap)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1, 2.2.1, 2.2.2 |
| **Affected Files** | `v3/steve/election.py:282-298`, `v3/server/pages.py:383-424` |
| **Source Reports** | 2.3.1.md, 2.2.1.md, 2.2.2.md |
| **Related Findings** | None |

**Description:**

The vote content (votestring) submitted by users is not validated against the issue's vote type before being encrypted and stored. The system accepts arbitrary strings for votes, which are then encrypted and stored as valid votes. This allows attackers to submit invalid vote values (e.g., invalid YNA values, non-existent STV candidates, duplicate rankings) that corrupt the vote record. A comment in the code at election.py line 229 indicates validation was intended ('### validate VOTESTRING for ISSUE.TYPE voting') but was never implemented. Client-side form controls (radio buttons for YNA, drag-and-drop for STV) can be trivially bypassed via direct HTTP requests. At tally time, the vtypes module receives corrupted data, potentially causing incorrect tally results, denial of service, or breaking voting algorithm invariants (e.g., STV single-transferable-vote requirements). This represents a Type B gap where the control was acknowledged as necessary but not implemented, creating false confidence through client-side constraints.

**Remediation:**

Implement the missing validation step using the existing `vtypes` module infrastructure:

```python
# In election.py, add_vote()
def add_vote(self, pid: str, iid: str, votestring: str):
    "Add VOTESTRING as the (latest) vote by PID for IID."

    # The Election should be open.
    md = self._all_metadata(self.S_OPEN)

    # Fetch issue to determine vote type
    issue = self.q_get_issue.first_row(iid)
    if not issue:
        raise IssueNotFound(iid)

    # Validate votestring for the issue's vote type
    vtype_mod = vtypes.vtype_module(issue.type)
    if not vtype_mod.validate(votestring, self.json2kv(issue.kv)):
        raise InvalidVoteString(iid, issue.type, votestring)

    mayvote = self.q_get_mayvote.first_row(pid, iid)
    vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
    ciphertext = crypto.create_vote(vote_token, mayvote.salt, votestring)
    self.c_add_vote.perform(vote_token, ciphertext)
```

```python
# Each vtype module should implement validate():
# vtypes/yna.py
VALID_VOTES = {'yes', 'no', 'abstain'}
def validate(votestring, kv):
    return votestring.lower().strip() in VALID_VOTES

# vtypes/stv.py  
def validate(votestring, kv):
    candidates = set(kv.get('labelmap', {}).keys())
    rankings = votestring.split(',')
    return all(r.strip() in candidates for r in rankings) and len(rankings) <= len(candidates)
```

---

#### FINDING-011: Complete Absence of Authenticated Data Clearing from Client Storage

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 14.3.1 |
| **Affected Files** | `v3/server/pages.py:72-103`, `v3/server/pages.py:148`, `v3/server/pages.py:186`, `v3/server/pages.py:528` |
| **Source Reports** | 14.3.1.md |
| **Related Findings** | None |

**Description:**

The application completely lacks mechanisms to clear authenticated data from client storage upon session termination. Specifically: (1) No `Clear-Site-Data` header is sent on any response, (2) No logout endpoint exists to trigger session termination and cleanup, (3) No `Cache-Control` headers prevent browser caching of authenticated pages, (4) No client-side JavaScript implements cleanup when sessions end or server is unreachable. This is a complete absence of the ASVS 14.3.1 Level 1 requirement, which is mandatory for all applications. In the context of a voting system, this results in: voter privacy violations through browser cache on shared computers exposing who voted and in which elections, session persistence without logout allowing session reuse, cached vote confirmation messages proving voter participation, and election administration exposure through cached management pages.

**Remediation:**

1. Add `Clear-Site-Data` header on logout response: Create a `/logout` endpoint that destroys the server-side session and sets `Clear-Site-Data: "cache", "cookies", "storage"` header. 2. Add `Cache-Control` and security headers to all authenticated responses via `after_request` middleware: Set `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`, `Pragma: no-cache`, and `Expires: 0` headers on all authenticated pages (or globally except for static assets). 3. Add client-side cleanup as fallback: Implement JavaScript that clears sessionStorage on `beforeunload` event and periodically checks session status, clearing sensitive DOM content and storage when session expires or server is unreachable. 4. Mark sensitive DOM elements with `data-sensitive` attribute in templates for targeted cleanup.

---

#### FINDING-012: Inconsistent Field Filtering — Election List Methods Return Raw Database Rows Without Python-Level Sensitive Field Exclusion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 15.3.1 |
| **Affected Files** | `v3/steve/election.py:407-412`, `v3/steve/election.py:438-446`, `v3/steve/election.py:420-436`, `v3/server/pages.py:155-162`, `v3/server/pages.py:320-324`, `v3/server/pages.py:477-519` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | None |

**Description:**

Audit of ASVS 15.3.1 (data minimization in API/data responses) reveals one CRITICAL finding related to inconsistent application of field-level filtering controls for election data objects. The codebase demonstrates awareness of the need to exclude sensitive cryptographic fields through an explicit filtering control in `get_metadata()`, but this control is not applied to three parallel code paths that also return election data to user-facing page templates. The methods `open_to_pid()`, `upcoming_to_pid()`, and `owned_elections()` return raw database rows without Python-level field filtering, potentially exposing sensitive cryptographic materials (`salt` and `opened_key`) to template rendering contexts. If the underlying SQL queries include these columns, they flow into HTTP responses for authenticated users. With `opened_key` and `mayvote.salt`, an attacker can compute `vote_token` values for any eligible voter, decrypt existing votes, and submit forged votes. This represents a Type B gap where a control exists (`get_metadata()` filtering pattern) but is not consistently applied across parallel code paths.

**Remediation:**

Apply the same explicit field construction pattern used in `get_metadata()` to all class methods that return election data. Implement a `_safe_election_summary()` static method that constructs a new edict with only safe fields (eid, title, owner_pid, closed, open_at, close_at), explicitly excluding cryptographic fields (salt, opened_key). Apply this method in `open_to_pid()`, `upcoming_to_pid()`, and `owned_elections()` by wrapping all returned rows. Additionally, add a defense-in-depth guard in `postprocess_election()` that explicitly deletes sensitive fields if they exist. Audit `queries.yaml` to confirm that queries do not select sensitive columns. Establish a coding standard requiring all methods returning data objects to callers outside the Election class to use explicit field construction (allowlist pattern) rather than raw query passthrough.

---

#### FINDING-013: No Documented Risk-Based Remediation Timeframes for Third-Party Components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **Affected Files** | `v3/steve/crypto.py:85-94`, `v3/steve/crypto.py:71-76`, `v3/steve/crypto.py:78-82`, `v3/steve/election.py:283-287`, `v3/steve/election.py:320-333` |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | None |

**Description:**

The application lacks documented risk-based remediation timeframes for third-party component vulnerabilities and general library update schedules. The application's security model depends on security-critical cryptographic libraries (argon2-cffi and cryptography) used extensively in crypto.py for vote encryption, key derivation, and tamper detection. Without documented remediation timeframes (e.g., Critical CVE → 24h, High → 7d, Medium → 30d), a published CVE in these libraries could remain unpatched indefinitely with no organizational accountability. No documentation exists defining: (1) Risk-based remediation timeframes, (2) General update schedules, (3) SBOM enumerating component versions, or (4) Classification of security-critical components. A vulnerability in these cryptographic libraries could directly compromise vote secrecy, election integrity, and key derivation security.

**Remediation:**

Create a Dependency Security Policy document (e.g., DEPENDENCY-POLICY.md) that includes: (1) Software Bill of Materials (SBOM) in CycloneDX or SPDX format generated by CI pipeline, (2) Component Risk Classification identifying 'Dangerous Functionality Components' (cryptography, argon2-cffi) and 'Risky Components', (3) Vulnerability Remediation Timeframes with severity-based response times (Critical 9.0+: 24h for dangerous functionality/48h for standard; High 7.0-8.9: 72h/7d; Medium 4.0-6.9: 14d/30d; Low 0.1-3.9: 30d/90d), (4) General Update Cadence (security-critical libraries: monthly review, update within 7 days of patch; all other dependencies: quarterly review), (5) Monitoring Process including automated dependency scanning in CI/CD, CVE notification subscription for dangerous functionality components, and quarterly manual review. Additionally, generate and maintain an SBOM using tools like cyclonedx-bom, implement automated CVE scanning (pip-audit, OSV-Scanner, Dependabot), and pin all dependency versions in a lock file.

---

#### FINDING-014: Complete Absence of SBOM and Dependency Version Tracking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1104 |
| **ASVS Section(s)** | 15.2.1 |
| **Affected Files** | `v3/server/main.py:1`, `v3/steve/crypto.py:1-10`, `v3/steve/election.py:1-10`, `Project-wide:N/A` |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | None |

**Description:**

The application lacks any mechanism to track, version, or audit third-party dependencies. While main.py declares a uv-based script runner, no dependency manifest with version constraints exists. No pyproject.toml, requirements.txt, uv.lock, Pipfile.lock, or SBOM document was found. The application's entire security model depends on cryptography (Fernet encryption of votes) and argon2-cffi (key derivation), but their versions are completely unverifiable. Without pinned versions, there is no way to verify the deployed version is patched against known CVEs. ASVS 15.2.1 requires verification that components have not breached documented update and remediation time frames - with no documented timeframes and no recorded component versions, this verification is impossible. This creates non-reproducible builds where each deployment may resolve to different dependency versions, including ones with known vulnerabilities. There is no protection against dependency confusion, typosquatting, or malicious package updates.

**Remediation:**

IMMEDIATE ACTIONS: 1) Create pyproject.toml with pinned dependency versions including asfquart, asfpy, cryptography>=44.0.0, argon2-cffi>=23.1.0, easydict>=1.13. 2) Generate and commit uv.lock file using 'uv lock' for reproducible builds. 3) Generate formal SBOM in CycloneDX or SPDX format using cyclonedx-bom tool. 4) Document update and remediation timeframes in SECURITY.md (Critical CVEs: 48 hours, High: 7 days, Medium: 30 days, routine updates: monthly). 5) Integrate automated vulnerability scanning using pip-audit or osv-scanner in CI/CD pipeline. 6) Enable GitHub Dependabot or Renovate for automated dependency update PRs. 7) Conduct initial vulnerability scan and remediate findings. 8) Implement pre-commit hooks for dependency validation. 9) Establish monthly dependency review process. 10) Integrate SBOM generation into release pipeline.

### 3.2 High

#### FINDING-015: No Certificate Trust Validation - Self-Signed and Development Certificates Permitted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-295 |
| **ASVS Sections** | 12.2.2 |
| **Files** | `v3/server/main.py:87-91`&lt;br&gt;`v3/server/config.yaml.example:31-33` |
| **Source Reports** | 12.2.2.md |
| **Related** | None |

**Description:**

When TLS is enabled, no validation occurs to ensure the provided certificate is publicly trusted. The configuration template references mkcert-generated development certificates as the example, and there is no code to detect or reject self-signed certificates, development CAs, or certificates that would not be trusted by standard browsers and clients. This allows production deployment with certificates that provide encryption but no authentication, enabling man-in-the-middle attacks where an attacker can present their own certificate without detection.

**Remediation:**

Implement certificate validation to ensure certificates are not self-signed or from development CAs. Detect mkcert patterns (check for 'mkcert' in certificate subject or issuer fields) and check certificate chain to verify it terminates in a publicly trusted root CA. Update configuration template to replace mkcert certificate references with guidance for publicly trusted certificates (Let's Encrypt, organizational CA) and add prominent comments warning against development certificates in production. Consider adding a configuration flag `allow_development_certificates: false` that must be explicitly set to true (with warnings) for non-production environments.

---

---

# 4. Positive Security Controls

| Control ID | Domain | Control Description | Evidence | Implementation Files |
|------------|--------|---------------------|----------|---------------------|
| PSC-001 | vote_encryption_storage | Authenticated encryption via Fernet (AES-128-CBC + HMAC-SHA256) | All encryption uses cryptography.fernet.Fernet with Encrypt-then-MAC construction, preventing padding oracle attacks | v3/steve/crypto.py:75, v3/steve/crypto.py:83 |
| PSC-002 | vote_encryption_storage | No ECB mode usage | Only block cipher usage is through Fernet which enforces CBC mode internally. No raw Cipher or AES instantiations found. | N/A |
| PSC-003 | vote_encryption_storage | No PKCS#1 v1.5 padding | No RSA or asymmetric encryption exists in the codebase. Fernet uses PKCS7 padding for symmetric block cipher (not the weak RSA padding scheme). | N/A |
| PSC-004 | vote_encryption_storage | Key derivation via HKDF-SHA256 | Secure key derivation for Fernet key generation; correctly applied with salt and context parameters for cryptographic key derivation | v3/steve/crypto.py:60, v3/steve/crypto.py:63 |
| PSC-005 | vote_encryption_storage | Password hashing via Argon2 | Password and token hashing uses Argon2 with appropriate parameters configured (64MB memory, time=2, parallelism=4) | v3/steve/crypto.py:91 |
| PSC-006 | vote_encryption_storage | CSPRNG for randomness | Salt generation uses secrets.token_bytes() and IDs use secrets.token_hex(); all randomness generation uses cryptographically secure source instead of pseudo-random | v3/steve/crypto.py:40, v3/steve/crypto.py:104, v3/steve/crypto.py:119 |
| PSC-007 | vote_encryption_storage | Single well-audited cryptography library | All cryptographic operations use the cryptography library, reducing risk of custom insecure implementations | v3/steve/crypto.py |
| PSC-008 | vote_encryption_storage | BLAKE2b for pre-hashing large inputs | Appropriate use for reducing Argon2 input size before memory-hard hashing, following RFC 7693 standards | v3/steve/crypto.py:44, v3/steve/crypto.py:45 |
| PSC-009 | vote_encryption_storage | Cryptographic shuffle for vote ordering | Fisher-Yates algorithm with secrets.randbelow() prevents vote ordering information leakage | v3/steve/crypto.py:104 |
| PSC-010 | vote_encryption_storage | Salt length enforcement in database schema | CHECK constraint ensures consistent 16-byte salt sizes for all cryptographic operations | v3/schema.sql:79, v3/schema.sql:173 |
| PSC-011 | vote_encryption_storage | Sensitive field exclusion from metadata API | Salt and opened_key deliberately excluded from public metadata endpoint responses | v3/steve/election.py:148 |
| PSC-012 | vote_encryption_storage | Tamper detection via opened_key recomputation | Election data integrity verified by recomputing cryptographic key before tallying votes | v3/steve/election.py:282 |
| PSC-013 | vote_encryption_storage | Multi-layer key derivation chain | Well-structured cryptographic isolation between elections, issues, and voters using election data → BLAKE2b → Argon2 → opened_key → Argon2 → vote_token → HKDF → vote_key | v3/steve/crypto.py:44-88 |
| PSC-014 | vote_encryption_storage | Exclusive use of approved hash functions | Only BLAKE2b, SHA-256 (via HKDF and Fernet), and Argon2 are used. No MD5, SHA-1, or deprecated hash functions present. | v3/steve/crypto.py:3 |
| PSC-015 | vote_encryption_storage | Centralized hash function management | All Argon2 operations go through single _hash() function, enabling easy audit and system-wide updates. | v3/steve/crypto.py:86-95 |
| PSC-016 | web_input_validation | Context-aware encoding in JS onclick handlers | Correct dual-context encoding for JavaScript embedded in HTML attributes using [format "js,html"] | v3/server/templates/manage.ezt:261 |
| PSC-017 | web_input_validation | Client-side HTML escaping for dynamic DOM manipulation | escapeHtml() function properly escapes content for dynamically created elements | v3/server/templates/vote-on.ezt:makeItem() |
| PSC-018 | web_input_validation | Parameterized database queries | All database operations use asfpy.db parameterization preventing SQL injection. Architectural enforcement via wrapper with 100% of operations using .perform() and .first_row() methods with bound parameters. | v3/steve/election.py, v3/steve/persondb.py |
| PSC-019 | web_input_validation | Hardcoded page titles in \&lt;title\&gt; element | HTML \&lt;title\&gt; uses server-set constants, not user input | v3/server/pages.py |
| PSC-020 | web_input_validation | Framework-provided path traversal protection | quart.send_from_directory() used for static file serving | v3/server/pages.py:serve_static(), v3/server/pages.py:serve_doc |
| PSC-021 | web_input_validation | Subresource Integrity (SRI) on CDN resources | integrity= attributes present on external CSS/JS resources | v3/server/templates/header.ezt, v3/server/templates/footer.ezt |
| PSC-022 | web_input_validation | All redirect URLs use hex-only EIDs | All quart.redirect() calls use secrets.token_hex() output | v3/server/pages.py |
| PSC-023 | web_input_validation | Relative URLs only (no protocol selection) | All constructed URLs start with /, eliminating javascript: / data: protocol injection | All templates and server-side redirects |
| PSC-024 | web_input_validation | Database-validated IDs before URL use | EIDs and IIDs are validated against database before any URL construction | v3/server/pages.py:load_election, v3/server/pages.py:load_election_issue |
| PSC-025 | web_input_validation | Zero OS command execution surface | None of os.system, subprocess, commands, popen are imported anywhere in the codebase | All 20 Python source files |
| PSC-026 | web_input_validation | No eval() or dynamic code execution | Complete avoidance of eval(), exec(), compile(), pickle deserialization, dynamic __import__() across all files | All files |
| PSC-027 | web_input_validation | Safe template engine (EZT) | EZT supports only substitution, iteration, conditionals — no code execution capability | All .ezt files |
| PSC-028 | web_input_validation | Complete elimination of XML attack surface | Architecture uses exclusively non-XML data formats - JSON, URL-encoded forms, EZT templates, YAML queries. Zero dependencies on XML parsing libraries. | v3/server/pages.py, v3/steve/election.py, v3/steve/persondb.py |
| PSC-029 | web_input_validation | Election state machine enforcement | State transitions use assert self.is_editable() / self.is_open() with _all_metadata(required_state) | v3/steve/election.py |
| PSC-030 | web_input_validation | Date input validation | _set_election_date() validates date format using datetime.datetime.fromisoformat() with try/except before any state change | v3/server/pages.py |
| PSC-031 | web_input_validation | Authentication decorators on protected routes | @asfquart.auth.require decorators applied to protected endpoints with ~95% coverage | v3/server/pages.py |
| PSC-032 | web_input_validation | Election and Issue existence validation via decorators | load_election and load_election_issue decorators validate database object existence for all routes with 100% coverage | v3/server/pages.py:148, v3/server/pages.py:171 |
| PSC-033 | web_input_validation | Vote type validation at creation | assert vtype in vtypes.TYPES enforces allowlist of valid vote types | v3/steve/election.py:199 |
| PSC-034 | authentication_authorization | OAuth client architecture with delegated authentication | Application acts as OAuth client, delegating all authorization server responsibilities to ASF infrastructure via asfquart.auth framework. Uses server-side session model with asfquart.session.read() for session retrieval, consistent with Authorization Code flow | v3/server/pages.py:29-30, v3/server/pages.py:33, v3/server/pages.py:65-67, v3/server/pages.py:85 |
| PSC-035 | authentication_authorization | Consistent authentication enforcement with role-based access control | All sensitive endpoints use @asfquart.auth.require() decorator with differentiated privilege levels (R.pmc_member for election creation, R.committer for voting and standard operations) | v3/server/pages.py (multiple lines) |
| PSC-036 | authentication_authorization | Secure redirect implementation | All redirects use hardcoded paths or DB-constrained identifiers with no user-controllable redirect targets | v3/server/pages.py:various |
| PSC-037 | authentication_authorization | Read-only session consumption | Session data consumed in read-only manner via asfquart.session.read(), client never attempts to modify OAuth tokens or session state | v3/server/pages.py:basic_info, v3/server/pages.py:89-103 |
| PSC-038 | authentication_authorization | Application-level authorization checks | Beyond OAuth authentication, application performs additional authorization checks including per-user voting eligibility and election state validation | v3/server/pages.py:vote_on_page |
| PSC-039 | authentication_authorization | Separation of authentication and identity management | User identity data (LDAP) separated from authentication mechanisms (OAuth), allowing independent management. Uses ldaps:// protocol for secure identity synchronization | v3/steve/persondb.py, v3/server/bin/asf-load-ldap.py:39 |
| PSC-040 | authentication_authorization | Schema-enforced data integrity | Election and issue IDs constrained by CHECK constraints to prevent format violations and injection vulnerabilities in redirect paths. Database contains no OAuth token tables, confirming external token management | v3/schema.sql |
| PSC-041 | authentication_authorization | Vote token isolation | Vote anonymization tokens are generated server-side via cryptographic functions (crypto.create_id()), stored separately from authentication tokens, and never exposed as bearer credentials. Election/issue IDs use cryptographic randomness to prevent prediction and enumeration attacks | v3/steve/election.py, v3/schema.sql |
| PSC-042 | authentication_authorization | No OAuth authorization server endpoints exposed | Application exposes no OAuth Authorization Server endpoints (/token, /authorize, /revoke, /.well-known/openid-configuration), reducing attack surface and confirming OAuth client-only role | v3/server/pages.py |
| PSC-043 | authentication_authorization | Clear separation of concerns | Authentication/authorization handled by asfquart, business logic in election.py, identity sync in asf-load-ldap.py | v3/server/pages.py, v3/steve/election.py, v3/server/bin/asf-load-ldap.py |
| PSC-044 | tls_transport_security | TLS configuration capability exists with certificate-based authentication | The mechanism for loading TLS certificates and keys is present in the codebase through configuration | v3/server/main.py:83-87, v3/server/config.yaml.example:29-30 |
| PSC-045 | tls_transport_security | Safe path handling using pathlib prevents path traversal in certificate loading | pathlib.resolve() used for path construction and certificate file handling | v3/server/main.py:26-30, v3/server/main.py:85-86 |
| PSC-046 | tls_transport_security | OAuth endpoints correctly use HTTPS scheme | OAuth over HTTPS configured with hardcoded https:// URLs | v3/server/main.py:35-38, v3/server/main.py:41-45 |
| PSC-047 | tls_transport_security | Static folder disabled to reduce attack surface | static_folder=None configuration reduces attack surface | v3/server/main.py:40, v3/server/main.py:49 |
| PSC-048 | tls_transport_security | Certificate file watching supports rotation without manual restart | Certificate rotation monitoring implemented | v3/server/main.py:88-89 |
| PSC-049 | tls_transport_security | Example config ships with TLS enabled | Secure default values provided in example configuration | v3/server/config.yaml.example:29-30 |
| PSC-050 | business_logic_voting | Proper state check via `_all_metadata(required_state)` | Exception-based enforcement mechanism that raises ElectionBadState and is not removable by `-O` flag | v3/steve/election.py:160-177, v3/steve/election.py:286, v3/steve/election.py:305, v3/steve/election.py:363 |
| PSC-051 | business_logic_voting | Election state derivation from database fields | Derives state from actual column values rather than cached flags | v3/steve/election.py:424-437 |
| PSC-052 | business_logic_voting | Cryptographic ID generation | Prevents enumeration using crypto.create_id() | v3/steve/election.py:209-214, v3/steve/election.py:453-458 |
| PSC-053 | business_logic_voting | Integrity loop on ID collision | Handles concurrent ID creation safely with while True / try / IntegrityError pattern | v3/steve/election.py:209-214, v3/steve/election.py:453-458 |
| PSC-054 | business_logic_voting | Transactional operations for multi-step modifications | Prevents partial state corruption using BEGIN TRANSACTION / COMMIT | v3/steve/election.py:46-64 |
| PSC-055 | business_logic_voting | Voter eligibility enforcement via `mayvote` table | Database-level eligibility check using q_get_mayvote.first_row(pid, iid) | v3/steve/election.py:291 |
| PSC-056 | business_logic_voting | Re-voting support via `MAX(vid)` ordering | Latest vote counted, old votes preserved for audit using AUTOINCREMENT vid | v3/schema.sql |
| PSC-057 | admin_tallying_operations | No HTTP surface area | All tools operate locally via filesystem and direct database access, eliminating the URL/query-string attack surface entirely | v3/server/bin/*.py |
| PSC-058 | admin_tallying_operations | Sensitive data stays internal | Decryption keys are derived inside election.tally_issue(), never exposed via arguments or URLs | v3/server/bin/tally.py |
| PSC-059 | admin_tallying_operations | Email body, not URL | mail-voters.py sends voter PII (email, name) in the email message body via asfpy.messaging.mail(), not appended to any URL | v3/server/bin/mail-voters.py |
| PSC-060 | admin_tallying_operations | YAML file for election config | create-election.py reads sensitive election setup data from a local YAML file rather than passing it as individual command-line arguments | v3/server/bin/create-election.py |
| PSC-061 | admin_tallying_operations | Tampering detection before data access | tally.py checks election.is_tampered(pdb) before decrypting and outputting any vote data | v3/server/bin/tally.py |
| PSC-062 | admin_tallying_operations | Structured argument parsing | All scripts use argparse for CLI input handling, providing type safety and validation | v3/server/bin/*.py |
| PSC-063 | data_minimization_exposure | Explicit field exclusion in get_metadata() | Constructs a new edict with only safe fields, explicitly excluding salt and opened_key with clear documentation: '# NOTE: do not return the SALT or OPENED_KEY' | v3/steve/election.py:145-159 |
| PSC-064 | data_minimization_exposure | Selective field extraction for issues | Both list_issues() and get_issue() construct new data objects containing only fields needed for display, never returning raw database rows. get_issue() includes comment 'NEVER return issue.salt' | v3/steve/election.py:161-228 |
| PSC-065 | data_minimization_exposure | Vote data never exposed via HTTP | No web endpoint returns vote_token, ciphertext, or decrypted vote strings. The tally_issue() method exists only for CLI tool use | v3/server/pages.py |
| PSC-066 | data_minimization_exposure | Mass assignment prevention | Every POST handler extracts specific named fields from form data rather than passing the entire form to model methods. Non-writable fields are sourced from existing database records, not from user input | v3/server/pages.py |
| PSC-067 | data_minimization_exposure | Boolean reduction in has_voted_upon() | Uses sensitive crypto materials internally but only returns a {iid: True/False} dict, properly minimizing the data returned | v3/steve/election.py:309-334 |
| PSC-068 | data_minimization_exposure | Error message minimization | Catches exceptions during vote submission, logs full error server-side, but only returns generic flash message to user | v3/server/pages.py |
| PSC-069 | data_minimization_exposure | Schema-level data typing | STRICT table mode enforces column types, preventing type confusion. CHECK constraints enforce BLOB lengths for cryptographic materials | v3/schema.sql |
| PSC-070 | dependency_configuration | Static file serving explicitly disabled | Setting static_folder=None in Quart framework completely disables built-in static file handler, preventing access to .git/, .svn/ through application | v3/server/main.py:42 |
| PSC-071 | dependency_configuration | No catch-all or file-serving routes | Application only imports explicit route modules (pages and api), no catch-all handlers, send_from_directory(), or send_file() usage found | v3/server/main.py:45-46 |
| PSC-072 | dependency_configuration | Safe path construction with pathlib | All path constructions use pathlib with .resolve() to normalize paths, parent directory anchoring, and no user-controlled components | v3/server/main.py, v3/steve/election.py |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Supporting Controls | Related Findings |
|---------|-------|--------|-------------------|------------------|
| 11.3.1 | Encryption Algorithms - Block Modes and Padding | **Pass** | PSC-001, PSC-002, PSC-003 | - |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used | **Fail** | PSC-001 (partial) | FINDING-001 |
| 11.4.1 | Hash Function Usage | **Pass** | PSC-005, PSC-008, PSC-014, PSC-015 | - |
| 1.2.1 | Output Encoding for HTTP Response, HTML Document, or XML Document | **Fail** | PSC-016, PSC-017, PSC-019 | FINDING-002, FINDING-003, FINDING-004, FINDING-005 |
| 1.2.2 | Injection Prevention - Dynamic URL Building with Untrusted Data | **Fail** | PSC-022, PSC-023, PSC-024 | FINDING-006 |
| 1.2.3 | JavaScript/JSON Injection Prevention - Output encoding when dynamically building JavaScript content | **Fail** | PSC-016 (partial) | FINDING-004 |
| 1.2.4 | Injection Prevention - Parameterized Queries and Database Injection Protection | **Pass** | PSC-018 | - |
| 1.2.5 | OS Command Injection Prevention | **Pass** | PSC-025 | - |
| 1.3.1 | Encoding and Sanitization - HTML Sanitization for WYSIWYG/Untrusted HTML Input | **Fail** | None | FINDING-003 |
| 1.3.2 | Avoid eval() or Dynamic Code Execution | **Pass** | PSC-026, PSC-027 | - |
| 1.5.1 | XML Parser Configuration - XXE Prevention | **Pass** | PSC-028 | - |
| 2.1.1 | Validation and Business Logic Documentation | **Pass** | PSC-029, PSC-030, PSC-033, PSC-050, PSC-051 | - |
| 2.2.1 | Input Validation - Business/Functional Expectations | **Fail** | PSC-030, PSC-033 (partial) | FINDING-010 |
| 2.2.2 | Input Validation - Server-Side Enforcement | **Fail** | PSC-031, PSC-032 (partial) | FINDING-010 |
| 10.4.1 | OAuth Authorization Server - Redirect URI Validation | **N/A** | PSC-034 (OAuth client only) | - |
| 10.4.2 | OAuth Authorization Code Single-Use Enforcement | **N/A** | PSC-034 (OAuth client only) | - |
| 10.4.3 | OAuth Authorization Server - Authorization Code Lifetime | **N/A** | PSC-034 (OAuth client only) | - |
| 10.4.4 | OAuth Authorization Server Grant Type Restrictions | **N/A** | PSC-034 (OAuth client only) | - |
| 10.4.5 | Refresh Token Replay Attack Mitigation for Authorization Servers | **N/A** | PSC-034 (OAuth client only) | - |
| 12.1.1 | General TLS Security Guidance - Secure Communication | **Fail** | PSC-044, PSC-046 (partial) | FINDING-008 |
| 12.2.1 | HTTPS Communication with External Facing Services | **Fail** | PSC-044, PSC-046, PSC-049 (partial) | FINDING-007 |
| 12.2.2 | HTTPS Communication with External Facing Services | **Fail** | PSC-044, PSC-046, PSC-049 (partial) | FINDING-007, FINDING-015 |
| 2.3.1 | Business Logic Sequential Flow Enforcement | **Fail** | PSC-029, PSC-050 (partial) | FINDING-009, FINDING-010 |
| 14.2.1 | General Data Protection - Sensitive Data in URLs | **N/A** | PSC-041, PSC-057, PSC-058, PSC-059 | - |
| 14.3.1 | Client-side Data Protection - Clearing authenticated data from client storage after session termination | **Fail** | None | FINDING-011 |
| 15.3.1 | Defensive Coding - Data Object Field Filtering | **Fail** | PSC-063, PSC-064 (partial) | FINDING-012 |
| 13.4.1 | Unintended Information Leakage - Source Control Metadata Exposure | **Partial** | PSC-070, PSC-071 | - |
| 15.1.1 | Secure Coding and Architecture Documentation - Risk-Based Remediation Timeframes for Third-Party Components | **Fail** | None | FINDING-013 |
| 15.2.1 | Security Architecture and Dependencies - Component Update and Remediation Timeframes | **Fail** | None | FINDING-014 |

**Summary Statistics:**
- **Pass:** 9 requirements (33%)
- **Fail:** 13 requirements (48%)
- **Partial:** 1 requirement (4%)
- **N/A:** 5 requirements (19%)

---

# 6. Cross-Reference Matrix

## 6.1 Finding → ASVS → Control Mapping

| Finding ID | Severity | ASVS Requirements | Mitigating Controls | Gap Type |
|------------|----------|-------------------|---------------------|----------|
| FINDING-001 | Critical | 11.3.2 | PSC-001 (partial - uses authenticated encryption but not AEAD) | Type A - Control absent |
| FINDING-002 | Critical | 1.2.1 | PSC-016, PSC-017 (insufficient coverage) | Type A - Control absent for flash messages |
| FINDING-003 | Critical | 1.2.1, 1.3.1 | PSC-016, PSC-017, PSC-019 (insufficient coverage) | Type A - Control absent across multiple templates |
| FINDING-004 | Critical | 1.2.1, 1.2.3 | PSC-016 (insufficient - not applied to JS context) | Type A - Control absent for JS embedding |
| FINDING-005 | Critical | 1.2.1 | PSC-019 (insufficient - not applied to error templates) | Type A - Control absent for error pages |
| FINDING-006 | Critical | 1.2.2 | PSC-022, PSC-023, PSC-024 (insufficient - gaps exist) | Type A - Control absent for href attributes |
| FINDING-007 | Critical | 12.2.1, 12.2.2 | PSC-044, PSC-046, PSC-049 (capability exists but not enforced) | Type A - Control absent (no enforcement) |
| FINDING-008 | Critical | 12.1.1 | PSC-044 (partial - TLS possible but no version control) | Type A - Control absent |
| FINDING-009 | Critical | 2.3.1 | PSC-029, PSC-050 (control exists but bypassable) | Type B - Control removable |
| FINDING-010 | Critical | 2.3.1, 2.2.1, 2.2.2 | PSC-030, PSC-033 (partial - validation exists for other inputs) | Type A - Control entirely absent |
| FINDING-011 | Critical | 14.3.1 | None | Type A - Control entirely absent |
| FINDING-012 | Critical | 15.3.1 | PSC-063, PSC-064 (partial - inconsistent application) | Type A - Control absent for list methods |
| FINDING-013 | Critical | 15.1.1 | None | Type A - Control entirely absent |
| FINDING-014 | Critical | 15.2.1 | None | Type A - Control entirely absent |
| FINDING-015 | High | 12.2.2 | PSC-044 (partial - certificate loading exists but no validation) | Type A - Control absent |

## 6.2 ASVS → Finding → Control Traceability

| ASVS ID | Status | Related Findings | Supporting Controls | Control Effectiveness |
|---------|--------|------------------|---------------------|----------------------|
| 11.3.1 | Pass | - | PSC-001, PSC-002, PSC-003 | Full |
| 11.3.2 | Fail | FINDING-001 | PSC-001 (partial) | Partial - uses authenticated encryption but not AEAD mode |
| 11.4.1 | Pass | - | PSC-005, PSC-008, PSC-014, PSC-015 | Full |
| 1.2.1 | Fail | FINDING-002, FINDING-003, FINDING-004, FINDING-005 | PSC-016, PSC-017, PSC-019 | Partial - gaps in flash messages, templates, JS context, error pages |
| 1.2.2 | Fail | FINDING-006 | PSC-022, PSC-023, PSC-024 | Partial - href attribute encoding missing |
| 1.2.3 | Fail | FINDING-004 | PSC-016 (partial) | Partial - onclick handlers covered but not JS embedding |
| 1.2.4 | Pass | - | PSC-018 | Full - 100% parameterized queries |
| 1.2.5 | Pass | - | PSC-025 | Full - zero OS command execution surface |
| 1.3.1 | Fail | FINDING-003 | None | None - no HTML sanitization library |
| 1.3.2 | Pass | - | PSC-026, PSC-027 | Full |
| 1.5.1 | Pass | - | PSC-028 | Full - no XML parsers |
| 2.1.1 | Pass | - | PSC-029, PSC-030, PSC-033, PSC-050, PSC-051 | Full |
| 2.2.1 | Fail | FINDING-010 | PSC-030, PSC-033 (partial) | Partial - vote content validation missing |
| 2.2.2 | Fail | FINDING-010 | PSC-031, PSC-032 (partial) | Partial - vote content validation missing |
| 10.4.1-10.4.5 | N/A | - | PSC-034 | N/A - OAuth client only |
| 12.1.1 | Fail | FINDING-008 | PSC-044, PSC-046 (partial) | Partial - TLS capable but no protocol version enforcement |
| 12.2.1 | Fail | FINDING-007 | PSC-044, PSC-046, PSC-049 (partial) | Partial - TLS optional, not mandatory |
| 12.2.2 | Fail | FINDING-007, FINDING-015 | PSC-044, PSC-046, PSC-049 (partial) | Partial - no certificate validation |
| 2.3.1 | Fail | FINDING-009, FINDING-010 | PSC-029, PSC-050 (partial) | Partial - assert-based controls removable, vote validation absent |
| 14.2.1 | N/A | - | PSC-041, PSC-057, PSC-058, PSC-059 | Full - no sensitive data in URLs |
| 14.3.1 | Fail | FINDING-011 | None | None |
| 15.3.1 | Fail | FINDING-012 | PSC-063, PSC-064 (partial) | Partial - inconsistent field filtering |
| 13.4.1 | Partial | - | PSC-070, PSC-071 | Partial - application prevents but proxy/web server configuration unknown |
| 15.1.1 | Fail | FINDING-013 | None | None |
| 15.2.1 | Fail | FINDING-014 | None | None |

## 6.3 Control Domain Coverage Analysis

| Domain | Total Controls | Critical Gaps | ASVS Coverage |
|--------|---------------|---------------|---------------|
| vote_encryption_storage | 15 controls | 1 (AEAD cipher) | 2/3 crypto requirements passed |
| web_input_validation | 18 controls | 4 (XSS, URL encoding) | 4/8 injection requirements passed |
| authentication_authorization | 11 controls | 0 | 5/5 OAuth requirements N/A (client-only) |
| tls_transport_security | 8 controls | 3 (enforcement, protocol version, validation) | 0/3 TLS requirements passed |
| business_logic_voting | 7 controls | 2 (assert bypass, vote validation) | 0/3 business logic requirements passed |
| admin_tallying_operations | 6 controls | 0 | N/A (no HTTP surface) |
| data_minimization_exposure | 7 controls | 2 (client storage, field filtering) | 1/2 data protection requirements passed |
| dependency_configuration | 3 controls | 2 (SBOM, remediation process) | 0/3 dependency requirements passed |

## 6.4 Risk Priority Matrix

| Risk Level | Finding Count | ASVS Requirements Affected | Control Gaps |
|------------|---------------|---------------------------|--------------|
| Critical | 14 | 13 unique requirements | 11 Type A gaps, 1 Type B gap |
| High | 1 | 1 requirement | 1 Type A gap |
| Medium | 0 | - | - |
| Low | 0 | - | - |

**Key Observations:**
1. **Cryptography domain** is mostly strong (87% control effectiveness) but has one critical AEAD gap
2. **Input validation domain** has significant XSS vulnerabilities across multiple attack vectors
3. **TLS/Transport security** has capability but lacks enforcement and validation
4. **Business logic** has one bypassable control (assert statements) and one missing control (vote validation)
5. **Dependency management** is entirely absent (0% control coverage)
6. **Authentication/authorization** is well-delegated to external OAuth provider (100% of applicable controls present)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 29 | 15 |

**Total consolidated findings: 15**

*End of Consolidated Security Audit Report*