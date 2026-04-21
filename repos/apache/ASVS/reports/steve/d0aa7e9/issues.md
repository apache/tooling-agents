# Security Issues

## Issue: FINDING-001 - AES-128-CBC (Fernet) Used Instead of Approved AEAD Cipher; Incomplete Migration to XChaCha20-Poly1305
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application uses Fernet (AES-128-CBC + HMAC-SHA256) for vote encryption instead of an approved AEAD cipher mode. Evidence shows an incomplete migration: HKDF is configured for XChaCha20-Poly1305, but actual encryption still uses Fernet's AES-128-CBC mode. This violates ASVS 11.3.2 (L1) requirements for approved cryptographic modes.

### Details
- **Affected Files:** `v3/steve/crypto.py` (lines 63-75, 77-80, 84-88), `v3/steve/election.py` (lines 236, 271)
- **ASVS Sections:** 11.3.2 (L1)
- **Type:** Type B gap - control EXISTS (HKDF configured for XChaCha20-Poly1305) but NOT APPLIED (Fernet/AES-128-CBC used)

Fernet splits its 32-byte key into 16 bytes for HMAC-SHA256 and 16 bytes for AES-128 encryption. While encrypt-then-MAC mitigates padding oracle attacks, CBC mode remains vulnerable to implementation-level side channels. All vote ciphertext stored in the vote table uses this unapproved cipher mode, providing only AES-128 strength instead of modern AES-256 recommendations for high-sensitivity voting data.

### Remediation
Complete the migration indicated by code comments. Replace Fernet with XChaCha20-Poly1305 using `nacl.secret.SecretBox`:

```python
# Derive 32-byte key using existing HKDF setup
# Create nacl.secret.SecretBox with the key
# Use box.encrypt() with auto-generated nonce for encryption
# Use box.decrypt() for decryption
```

Alternatively, implement AES-256-GCM using `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.

**Migration Strategy Required:** Implement a re-encryption strategy for existing vote data or version-aware decryption path to handle both old Fernet-encrypted votes and new AEAD-encrypted votes during transition.

### Acceptance Criteria
- [ ] XChaCha20-Poly1305 or AES-256-GCM implemented for vote encryption
- [ ] All new votes use approved AEAD cipher
- [ ] Migration path implemented for existing encrypted votes
- [ ] Unit tests added for new encryption/decryption
- [ ] Integration tests verify backward compatibility during migration
- [ ] Security review of cryptographic implementation completed

### References
- ASVS 11.3.2: Verify that approved modes of operation are used for symmetric encryption
- Source Report: 11.3.2.md

### Priority
**Critical** - All vote data uses non-compliant encryption mode

---

## Issue: FINDING-002 - Stored XSS via Flash Messages Rendered Without HTML Encoding
**Labels:** bug, security, priority:critical, xss
**Description:**
### Summary
Flash messages containing user-controlled data (election titles, issue titles, issue IDs) are rendered in HTML without encoding in the `flashes.ezt` template. This enables stored XSS attacks through malicious election/issue titles.

### Details
- **Affected Files:** `v3/server/templates/flashes.ezt` (lines 1-6), `v3/server/pages.py` (lines 455, 518, 537, 426)
- **ASVS Sections:** 1.2.1 (L1)
- **CWE:** CWE-79 (Cross-site Scripting)

User input flows from form submissions through `flash_success()`/`flash_danger()` calls with f-strings containing `form.title` or `iid` directly into the template. The EZT template engine's `[format "html"]` directive exists but is not applied to `[flashes.message]`.

**Attack Vector:** Users create elections/issues with titles like `<script>alert(document.cookie)</script>`, which executes for all users viewing the flash message.

### Remediation
Apply `[format "html"]` encoding to flash message output in `flashes.ezt`:

```ezt
[for flashes]
<div class="alert alert-[flashes.category] alert-dismissible fade show" role="alert">
  [format "html"][flashes.message][end]
  <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
</div>
[end]
```

### Acceptance Criteria
- [ ] `[format "html"]` applied to all flash message outputs
- [ ] XSS test cases added with malicious payloads in election/issue titles
- [ ] Manual testing confirms HTML entities are escaped in flash messages
- [ ] No legitimate HTML formatting broken by encoding
- [ ] Security regression tests added

### References
- ASVS 1.2.1: Verify that user input is properly encoded for output context
- CWE-79: Improper Neutralization of Input During Web Page Generation
- Related: FINDING-003, FINDING-004, FINDING-005, FINDING-006

### Priority
**Critical** - Exploitable by any authenticated user, affects all users viewing elections

---

## Issue: FINDING-003 - Stored XSS via User-Controlled Data Rendered in HTML Context Without Encoding Across Multiple Templates
**Labels:** bug, security, priority:critical, xss
**Description:**
### Summary
User-controlled data (election titles, issue titles/descriptions, owner names, authorization strings) are rendered without HTML encoding across multiple templates (manage.ezt, manage-stv.ezt, admin.ezt, voter.ezt, vote-on.ezt). The same templates correctly use `[format "js,html"]` for JavaScript contexts, demonstrating inconsistent application of security controls.

### Details
- **Affected Files:** `v3/server/templates/manage.ezt` (lines 241, 283), `manage-stv.ezt` (lines 175, 196), `admin.ezt` (line 19), `voter.ezt` (lines 49, 96), `vote-on.ezt` (lines 88, 131, 163), `v3/server/pages.py` (rewrite_description function)
- **ASVS Sections:** 1.2.1, 1.3.1 (L1)
- **CWE:** CWE-79

The `rewrite_description()` function compounds the issue by constructing HTML from user input without pre-escaping, making template-level encoding insufficient. Election administrators can inject persistent JavaScript that executes for all users viewing elections.

### Remediation
1. Apply `[format "html"]` to all user-controlled template variables in HTML contexts:
   - `<strong>[format "html"][issues.title][end]</strong>`
   - `<div class="description mt-2">[format "html"][issues.description][end]</div>`
   - `<h5 class="card-title">[format "html"][owned.title][end]</h5>`
   - `<h1 class="h4 mb-0 fw-semibold">[format "html"][election.title][end]</h1>`

2. Fix `rewrite_description()` to HTML-encode description text before wrapping in HTML using `html.escape()`

3. Integrate server-side HTML sanitization library (bleach or nh3) into `rewrite_description()`:
```python
import bleach
desc = bleach.clean(issue.description, tags=[], strip=True)
# Then apply doc: link conversion on sanitized text
```

### Acceptance Criteria
- [ ] All user-controlled variables in templates have `[format "html"]` applied
- [ ] `rewrite_description()` sanitizes input before HTML construction
- [ ] XSS test suite covers all affected templates
- [ ] Bleach or nh3 library integrated for HTML sanitization
- [ ] Code review confirms no additional unencoded outputs exist
- [ ] Security regression tests added

### References
- ASVS 1.2.1, 1.3.1: Output encoding and HTML sanitization
- Source Reports: 1.2.1.md, 1.3.1.md
- Related: FINDING-002, FINDING-004, FINDING-005, FINDING-006

### Priority
**Critical** - Exploitable by election administrators, affects all voters

---

## Issue: FINDING-004 - Stored XSS via Unencoded Server Data Embedded in JavaScript Context in vote-on.ezt
**Labels:** bug, security, priority:critical, xss
**Description:**
### Summary
Server-side data (issue titles, candidate labels, candidate names) are embedded directly into an inline JavaScript object (STV_CANDIDATES) without encoding in `vote-on.ezt`. Election administrators can inject JavaScript payloads that execute for every voter accessing the voting page.

### Details
- **Affected Files:** `v3/server/templates/vote-on.ezt` (lines 215-228), `v3/server/pages.py` (lines 258-263)
- **ASVS Sections:** 1.2.1, 1.2.3 (L1)
- **CWE:** CWE-79

The template uses raw EZT variable interpolation within JavaScript string literals, allowing JavaScript injection through quote escaping. While a client-side `escapeHtml()` function exists for dynamic DOM operations, it does not protect the server-rendered inline data block.

**Attack Vector:** Issue title `Test"; alert(1); "` or candidate name with embedded quotes breaks out of string context.

### Remediation
Use `[format "js"]` or `[format "js,html"]` for all user-controlled values in JavaScript contexts:

```ezt
const STV_CANDIDATES = {
  "[issues.iid]": {
    seats: [issues.seats],
    title: "[format "js"][issues.title][end]",
    candidates: [
      [for issues.candidates]
      {
        label: "[format "js"][issues.candidates.label][end]",
        name: "[format "js"][issues.candidates.name][end]"
      },
      [end]
    ]
  }
};
```

**Alternative (Safer Architecture):** Serialize data as JSON from Python and embed as a data attribute, then parse with `JSON.parse()` client-side.

### Acceptance Criteria
- [ ] All user-controlled values in JavaScript contexts use `[format "js"]`
- [ ] XSS test cases with quote/backslash injection in issue titles and candidate names
- [ ] Consider migration to data-attribute + JSON.parse pattern
- [ ] Manual testing confirms JavaScript syntax remains valid
- [ ] Security code review of all inline JavaScript blocks

### References
- ASVS 1.2.1, 1.2.3: Output encoding for JavaScript context
- Source Reports: 1.2.1.md, 1.2.3.md
- Related: FINDING-002, FINDING-003, FINDING-005, FINDING-006

### Priority
**Critical** - Affects all voters during voting process

---

## Issue: FINDING-005 - Reflected XSS via URL Path Parameters in Error Templates Without HTML Encoding
**Labels:** bug, security, priority:critical, xss
**Description:**
### Summary
URL path parameters (eid, iid, pid) are reflected in error templates (e_bad_eid.ezt, e_bad_iid.ezt, e_bad_pid.ezt) without HTML encoding. Attackers can craft malicious URLs that inject HTML/JavaScript when users click them.

### Details
- **Affected Files:** `v3/server/templates/e_bad_eid.ezt` (line 8), `e_bad_iid.ezt` (line 8), `e_bad_pid.ezt` (line 8), `v3/server/pages.py` (lines 175, 200, 328)
- **ASVS Sections:** 1.2.1 (L1)
- **CWE:** CWE-79

When `load_election()` or `load_election_issue()` decorators catch `ElectionNotFound` exceptions, they set `result.eid/iid/pid` directly from URL-decoded path parameters and render error templates. Templates output these values using raw EZT variable interpolation without `[format "html"]`.

**Attack Vector:** URL like `/election/<script>alert(1)</script>` reflects the script tag in the error message.

### Remediation
Apply `[format "html"]` to all URL parameter outputs in error templates:

```ezt
The Election ID ([format "html"][eid][end]) does not exist...
The Issue ID ([format "html"][iid][end]) does not exist...
The Person ID ([format "html"][pid][end]) does not exist...
```

### Acceptance Criteria
- [ ] `[format "html"]` applied to all eid/iid/pid outputs in error templates
- [ ] XSS test cases with script tags and HTML entities in URL parameters
- [ ] Manual testing with malicious URLs confirms encoding works
- [ ] Verify legitimate IDs still display correctly
- [ ] Add automated security tests for all error pages

### References
- ASVS 1.2.1: Output encoding for HTML context
- Source Report: 1.2.1.md
- Related: FINDING-002, FINDING-003, FINDING-004, FINDING-006

### Priority
**Critical** - Exploitable via phishing/social engineering against authenticated users

---

## Issue: FINDING-006 - Stored XSS via Unencoded Untrusted Data in Dynamically Built URL
**Labels:** bug, security, priority:critical, xss
**Description:**
### Summary
The `rewrite_description()` function dynamically builds URLs by extracting filenames from user-controlled issue descriptions using pattern `doc:filename`. These filenames are inserted directly into href attributes without URL encoding or HTML attribute encoding, creating a stored XSS vulnerability.

### Details
- **Affected Files:** `v3/server/pages.py` (lines 55-63), `v3/server/templates/vote-on.ezt`
- **ASVS Sections:** 1.2.2 (L1)
- **CWE:** CWE-79

The filename captured by regex `doc:([^\s]+)` is injected directly into an href attribute and link text. Any authenticated committer can create issues on any election (the `check authz` placeholder is not implemented), making this exploitable by any authenticated user against all voters.

**Attack Vector:** Issue description with `doc:foo" onclick="alert(1)` or `doc:javascript:alert(1)` creates malicious links.

### Remediation
Apply URL encoding and HTML escaping to `rewrite_description()`:

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

**Additional Recommendations:**
- Move HTML construction to templates with proper `[format]` directives
- Implement authorization checks to complete `check authz` placeholders
- Consider migrating from EZT to Jinja2 with auto-escaping
- Establish secure coding guidelines: all HTML construction in templates, not Python

### Acceptance Criteria
- [ ] URL encoding and HTML escaping implemented in `rewrite_description()`
- [ ] XSS test cases with malicious filenames (quotes, javascript:, onclick)
- [ ] Authorization checks implemented for issue creation
- [ ] Code review confirms no other Python-side HTML construction
- [ ] Consider template migration to Jinja2
- [ ] Security coding guidelines documented

### References
- ASVS 1.2.2: Output encoding for URL/attribute context
- Source Report: 1.2.2.md
- Related: FINDING-002, FINDING-003, FINDING-004, FINDING-005

### Priority
**Critical** - Exploitable by any authenticated user, affects all voters

---

## Issue: FINDING-007 - TLS Not Enforced - Application Permits Plain HTTP Operation for All External-Facing Services
**Labels:** bug, security, priority:critical, tls
**Description:**
### Summary
The application implements TLS as an optional, bypassable configuration toggle rather than a mandatory security control. When `certfile` config is empty, the server launches over plain HTTP with no warnings, no errors, and no compensating controls. This exposes authentication tokens, vote contents, and election management operations to network eavesdropping and tampering.

### Details
- **Affected Files:** `v3/server/main.py` (lines 84-90, 97-118), `v3/server/config.yaml.example` (lines 27-31)
- **ASVS Sections:** 12.2.1, 12.2.2 (L1)
- **CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

The conditional check `if app.cfg.server.certfile:` means when certfile is empty/absent, the server silently degrades to insecure transport. In ASGI mode (`run_asgi()`), the function creates the application without any TLS parameters, delegating all transport security to external ASGI server/proxy with no verification.

**Impact for Voting System:**
- Authentication tokens (ASF OAuth tokens, session cookies) transmitted in cleartext
- Vote contents captured or modified during transmission before encryption
- Election management operations exposed
- Complete loss of transport security guarantees

### Remediation
1. **Make TLS Mandatory:** Enforce certificate validation at startup - fail with critical error if certfile/keyfile are missing or invalid
2. **Remove Plain HTTP Documentation:** Update config.yaml.example to remove suggestions that plain HTTP is acceptable
3. **Add HSTS Header:** Inject `Strict-Transport-Security: max-age=31536000; includeSubDomains` to all responses
4. **ASGI Mode Protection:** Document mandatory Hypercorn TLS configuration and add startup validation of `X-Forwarded-Proto`
5. **HTTP Redirect:** Add HTTP listener that returns 301 redirects to HTTPS
6. **Proxy Mode:** If proxy architecture is intended, add `behind_proxy: true` config flag with explicit validation

### Acceptance Criteria
- [ ] Server fails to start if TLS certificates are missing/invalid
- [ ] HSTS header added to all responses
- [ ] HTTP→HTTPS redirect implemented
- [ ] ASGI mode validates proxy TLS headers
- [ ] Configuration documentation updated
- [ ] Integration tests verify TLS enforcement
- [ ] Deployment guide includes TLS requirements

### References
- ASVS 12.2.1, 12.2.2: TLS enforcement for all connections
- CWE-319: Cleartext Transmission of Sensitive Information
- Source Reports: 12.2.1.md, 12.2.2.md

### Priority
**Critical** - Fundamental transport security control missing

---

## Issue: FINDING-008 - No TLS Protocol Version Enforcement - Server May Accept Deprecated TLS 1.0/1.1 Connections
**Labels:** bug, security, priority:critical, tls
**Description:**
### Summary
The application does not enforce minimum TLS protocol versions. No `ssl.SSLContext` is explicitly created or configured, meaning Python's defaults apply (typically TLS 1.0 minimum). This allows protocol downgrade attacks exploiting known cryptographic weaknesses (BEAST, POODLE, Lucky Thirteen) to decrypt authentication tokens or vote payloads.

### Details
- **Affected Files:** `v3/server/main.py` (lines 83-91, 99-118), `v3/server/config.yaml.example`
- **ASVS Sections:** 12.1.1 (L1)
- **CWE:** CWE-327 (Use of Broken or Risky Cryptographic Algorithm)

The application passes only `certfile` and `keyfile` as keyword arguments to `app.runx()`. No explicit configuration exists for:
- `ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2`
- Protocol flags: `ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1`
- TLS 1.3 preference
- Cipher suite restrictions

Both deployment modes affected: `run_standalone()` passes raw paths; `run_asgi()` creates no SSL configuration, deferring to Hypercorn's defaults.

### Remediation
Create explicit `ssl.SSLContext` with enforced minimum version:

```python
def _create_tls_context(certfile, keyfile):
    """Create secure TLS context with modern protocol versions."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Enforce TLS 1.2+ only
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Security options
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    
    # Restrict to strong cipher suites
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    # Load certificate
    ctx.load_cert_chain(certfile, keyfile)
    
    return ctx
```

For ASGI/Hypercorn: Provide `hypercorn.toml` configuration enforcing TLS 1.2+ with modern ciphers.

### Acceptance Criteria
- [ ] `_create_tls_context()` function implemented
- [ ] TLS 1.2 enforced as minimum version
- [ ] Strong cipher suites configured
- [ ] Hypercorn configuration documented for ASGI mode
- [ ] Config schema includes `minimum_tls_version` and `ciphers` fields
- [ ] SSL Labs scan achieves A+ rating
- [ ] Tests verify TLS 1.0/1.1 connections are rejected

### References
- ASVS 12.1.1: Enforce minimum TLS version
- CWE-327: Use of Broken or Risky Cryptographic Algorithm
- Source Report: 12.1.1.md

### Priority
**Critical** - Allows cryptographic downgrade attacks

---

## Issue: FINDING-009 - Election Lifecycle State Enforcement Uses `assert` Statements — Control Exists But Is Removable (Type B Gap)
**Labels:** bug, security, priority:critical, business-logic
**Description:**
### Summary
Seven critical election lifecycle management methods rely exclusively on Python `assert` statements for state enforcement. When running with `-O` optimization flag (standard production practice), all `assert` statements are removed from bytecode, completely eliminating state transition controls. This allows arbitrary state machine traversal, including backwards transitions and step skipping.

### Details
- **Affected Files:** `v3/steve/election.py` (lines 50, 70, 123, 208, 228, 241, 273), `v3/server/pages.py` (lines 447, 466, 483, 510, 534)
- **ASVS Sections:** 2.3.1 (L1)

The codebase contains a proper enforcement mechanism (`_all_metadata(required_state)`) that raises `ElectionBadState` exceptions and is correctly used in voting-related methods (`add_vote()`, `tally_issue()`, `has_voted_upon()`), but this pattern was not applied to administrative lifecycle methods.

**Affected Methods:**
- `open()` - Opens election (should require S_EDITABLE state)
- `close()` - Closes election (should require S_OPEN state)
- `add_issue()` - Adds issue (should require S_EDITABLE state)
- `edit_issue()` - Edits issue (should require S_EDITABLE state)
- `delete_issue()` - Deletes issue (should require S_EDITABLE state)
- `add_voter()` - Adds voter (should require S_EDITABLE state)
- `delete()` - Deletes election (should require S_EDITABLE state)

### Remediation
Replace all `assert` statements with `_all_metadata(required_state)` mechanism:

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
    """Close an election."""
    self._all_metadata(required_state=self.S_OPEN)
    self.c_close.perform(self.eid)

def add_issue(self, title, description, vtype, kv):
    """Add a new issue with a generated unique IID."""
    self._all_metadata(required_state=self.S_EDITABLE)
    if vtype not in vtypes.TYPES:
        raise ValueError(f'Invalid vote type: {vtype}')
    # ... rest of method

def delete(self):
    """Delete this Election and its Issues and Person/Issue pairs."""
    self._all_metadata(required_state=self.S_EDITABLE)
    # ... rest of method
```

Apply same pattern to: `edit_issue()`, `delete_issue()`, `add_voter()`, `add_salts()`

### Acceptance Criteria
- [ ] All `assert` statements in lifecycle methods replaced with `_all_metadata()`
- [ ] Unit tests verify state enforcement with `-O` flag enabled
- [ ] Integration tests verify proper exception raising for invalid state transitions
- [ ] Test attempts to open already-open election
- [ ] Test attempts to close non-open election
- [ ] Test attempts to modify closed election
- [ ] Code review confirms no remaining security-critical `assert` statements

### References
- ASVS 2.3.1: Verify business logic flows enforce state transitions
- Source Report: 2.3.1.md

### Priority
**Critical** - State machine bypass in production with `-O` flag

---

## Issue: FINDING-010 - Vote Content Validation Step Entirely Absent in Vote Submission Flow (Type A Gap)
**Labels:** bug, security, priority:critical, business-logic
**Description:**
### Summary
Vote content (votestring) submitted by users is not validated against the issue's vote type before being encrypted and stored. The system accepts arbitrary strings for votes, allowing attackers to submit invalid vote values that corrupt the vote record and potentially break tally algorithms.

### Details
- **Affected Files:** `v3/steve/election.py` (lines 282-298), `v3/server/pages.py` (lines 383-424)
- **ASVS Sections:** 2.3.1, 2.2.1, 2.2.2 (L1)

A comment in the code at election.py line 229 indicates validation was intended ('### validate VOTESTRING for ISSUE.TYPE voting') but was never implemented. Client-side form controls (radio buttons for YNA, drag-and-drop for STV) can be trivially bypassed via direct HTTP requests.

**Attack Vectors:**
- Invalid YNA values (e.g., "maybe", "42", script tags)
- Non-existent STV candidates
- Duplicate rankings in STV
- Malformed vote strings that break tally algorithms

At tally time, the vtypes module receives corrupted data, potentially causing incorrect tally results, denial of service, or breaking voting algorithm invariants.

### Remediation
Implement the missing validation step using the existing `vtypes` module infrastructure:

```python
# In election.py, add_vote()
def add_vote(self, pid: str, iid: str, votestring: str):
    """Add VOTESTRING as the (latest) vote by PID for IID."""

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

Each vtype module should implement `validate()`:

```python
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

### Acceptance Criteria
- [ ] `InvalidVoteString` exception class created
- [ ] `validate()` method implemented in all vtype modules (yna.py, stv.py)
- [ ] Validation integrated into `add_vote()` method
- [ ] Unit tests for each vtype's validation logic
- [ ] Integration tests verify invalid votes are rejected
- [ ] Test XSS payloads in vote strings are rejected
- [ ] Test non-existent candidate IDs are rejected
- [ ] Test duplicate STV rankings are rejected
- [ ] Error messages provide clear feedback without exposing internals

### References
- ASVS 2.3.1, 2.2.1, 2.2.2: Business logic validation and input validation
- Source Reports: 2.3.1.md, 2.2.1.md, 2.2.2.md

### Priority
**Critical** - Vote integrity and tally correctness at risk

---

## Issue: FINDING-011 - Complete Absence of Authenticated Data Clearing from Client Storage
**Labels:** bug, security, priority:critical, privacy
**Description:**
### Summary
The application completely lacks mechanisms to clear authenticated data from client storage upon session termination. No `Clear-Site-Data` header, no logout endpoint, no `Cache-Control` headers, and no client-side cleanup. This violates ASVS 14.3.1 Level 1 requirement, which is mandatory for all applications.

### Details
- **Affected Files:** `v3/server/pages.py` (lines 72-103, 148, 186, 528)
- **ASVS Sections:** 14.3.1 (L1)

**Missing Controls:**
1. No `Clear-Site-Data` header on any response
2. No logout endpoint to trigger session termination
3. No `Cache-Control` headers prevent browser caching of authenticated pages
4. No client-side JavaScript implements cleanup

**Impact for Voting System:**
- Voter privacy violations through browser cache on shared computers
- Cached pages expose who voted and in which elections
- Session persistence without logout allows session reuse
- Cached vote confirmation messages prove voter participation
- Election administration exposure through cached management pages

### Remediation
1. **Add `Clear-Site-Data` header on logout:**
   - Create `/logout` endpoint
   - Destroy server-side session
   - Set `Clear-Site-Data: "cache", "cookies", "storage"` header

2. **Add `Cache-Control` and security headers via `after_request` middleware:**
```python
@app.after_request
def add_security_headers(response):
    if request.path.startswith('/static/'):
        return response  # Allow caching of static assets
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

3. **Add client-side cleanup as fallback:**
```javascript
window.addEventListener('beforeunload', function() {
    sessionStorage.clear();
    // Clear sensitive DOM elements
    document.querySelectorAll('[data-sensitive]').forEach(el => el.textContent = '');
});

// Periodic session check
setInterval(function() {
    fetch('/api/session-check')
        .catch(() => {
            // Session expired or server unreachable
            sessionStorage.clear();
            localStorage.clear();
            window.location.href = '/session-expired';
        });
}, 60000);
```

4. **Mark sensitive DOM elements in templates:**
```html
<span data-sensitive>User: [person.name]</span>
```

### Acceptance Criteria
- [ ] `/logout` endpoint created with session destruction
- [ ] `Clear-Site-Data` header sent on logout
- [ ] `Cache-Control` headers added to all authenticated responses
- [ ] Client-side cleanup on `beforeunload` implemented
- [ ] Periodic session check implemented
- [ ] Sensitive DOM elements marked with `data-sensitive`
- [ ] Manual testing on shared computer confirms data clearing
- [ ] Browser cache inspection confirms no sensitive data retained
- [ ] Test logout from multiple tabs/windows

### References
- ASVS 14.3.1: Authenticated data clearing from client storage
- Source Report: 14.3.1.md

### Priority
**Critical** - Voter privacy violation, mandatory L1 requirement

---

## Issue: FINDING-012 - Inconsistent Field Filtering — Election List Methods Return Raw Database Rows Without Python-Level Sensitive Field Exclusion
**Labels:** bug, security, priority:critical, data-exposure
**Description:**
### Summary
Election list methods (`open_to_pid()`, `upcoming_to_pid()`, `owned_elections()`) return raw database rows without Python-level field filtering, potentially exposing sensitive cryptographic materials (`salt` and `opened_key`) to template rendering contexts. With `opened_key` and `mayvote.salt`, an attacker can compute `vote_token` values for any eligible voter, decrypt existing votes, and submit forged votes.

### Details
- **Affected Files:** `v3/steve/election.py` (lines 407-412, 438-446, 420-436), `v3/server/pages.py` (lines 155-162, 320-324, 477-519)
- **ASVS Sections:** 15.3.1 (L1)
- **CWE:** CWE-200 (Exposure of Sensitive Information)

The codebase demonstrates awareness of the need to exclude sensitive fields through an explicit filtering control in `get_metadata()`, but this control is not applied to three parallel code paths. This represents a Type B gap where a control exists but is not consistently applied.

**Attack Scenario:**
If underlying SQL queries include `salt` and `opened_key` columns, they flow into HTTP responses. Attacker with these values can:
1. Compute `vote_token = crypto.gen_vote_token(opened_key, pid, iid, salt)`
2. Decrypt existing votes
3. Submit forged votes

### Remediation
Apply explicit field construction pattern to all methods returning election data:

```python
# Add static method for safe election summaries
@staticmethod
def _safe_election_summary(row):
    """Construct safe election summary with only non-sensitive fields."""
    return {
        'eid': row.eid,
        'title': row.title,
        'owner_pid': row.owner_pid,
        'closed': row.closed,
        'open_at': row.open_at,
        'close_at': row.close_at
        # Explicitly exclude: salt, opened_key
    }

def open_to_pid(self, pid):
    """Return list of open elections where PID may vote."""
    rows = self.q_open_to_pid.all_rows(pid)
    return [self._safe_election_summary(row) for row in rows]

def upcoming_to_pid(self, pid):
    """Return list of upcoming elections where PID may vote."""
    rows = self.q_upcoming_to_pid.all_rows(pid)
    return [self._safe_election_summary(row) for row in rows]

def owned_elections(self, pid):
    """Return list of elections owned by PID."""
    rows = self.q_owned_elections.all_rows(pid)
    return [self._safe_election_summary(row) for row in rows]
```

Add defense-in-depth guard in `postprocess_election()`:

```python
def postprocess_election(self, result, election):
    """Postprocess election data before template rendering."""
    # Explicitly delete sensitive fields if they exist
    if hasattr(election, 'salt'):
        delattr(election, 'salt')
    if hasattr(election, 'opened_key'):
        delattr(election, 'opened_key')
    # ... rest of postprocessing
```

Audit `queries.yaml` to confirm queries do not select sensitive columns.

### Acceptance Criteria
- [ ] `_safe_election_summary()` static method implemented
- [ ] All three methods apply safe field construction
- [ ] Defense-in-depth guard added to `postprocess_election()`
- [ ] `queries.yaml` audited for sensitive column selection
- [ ] Unit tests verify sensitive fields are excluded
- [ ] Integration tests inspect HTTP responses for sensitive data
- [ ] Code review confirms all data-returning methods use allowlist pattern
- [ ] Coding standard documented: explicit field construction for external data

### References
- ASVS 15.3.1: Data minimization in API/data responses
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- Source Report: 15.3.1.md

### Priority
**Critical** - Potential exposure of cryptographic materials enabling vote decryption/forgery

---

## Issue: FINDING-013 - No Documented Risk-Based Remediation Timeframes for Third-Party Components
**Labels:** bug, security, priority:critical, supply-chain
**Description:**
### Summary
The application lacks documented risk-based remediation timeframes for third-party component vulnerabilities and general library update schedules. The security model depends on cryptographic libraries (argon2-cffi, cryptography) used for vote encryption, key derivation, and tamper detection. Without documented remediation timeframes, a published CVE in these libraries could remain unpatched indefinitely.

### Details
- **Affected Files:** `v3/steve/crypto.py` (lines 85-94, 71-76, 78-82), `v3/steve/election.py` (lines 283-287, 320-333)
- **ASVS Sections:** 15.1.1 (L1)

**Missing Documentation:**
1. Risk-based remediation timeframes
2. General update schedules
3. SBOM enumerating component versions
4. Classification of security-critical components

**Impact:** A vulnerability in cryptographic libraries could directly compromise:
- Vote secrecy
- Election integrity
- Key derivation security

### Remediation
Create `DEPENDENCY-POLICY.md` document including:

1. **Software Bill of Materials (SBOM):**
   - CycloneDX or SPDX format generated by CI pipeline
   - Tool: `cyclonedx-bom` or `syft`

2. **Component Risk Classification:**
   - **Dangerous Functionality Components:** cryptography, argon2-cffi (handle cryptographic operations)
   - **Risky Components:** (to be identified during audit)

3. **Vulnerability Remediation Timeframes:**
   | Severity | CVSS Score | Dangerous Functionality | Standard Components |
   |----------|------------|------------------------|---------------------|
   | Critical | 9.0-10.0   | 24 hours              | 48 hours            |
   | High     | 7.0-8.9    | 72 hours              | 7 days              |
   | Medium   | 4.0-6.9    | 14 days               | 30 days             |
   | Low      | 0.1-3.9    | 30 days               | 90 days             |

4. **General Update Cadence:**
   - Security-critical libraries: Monthly review, update within 7 days of patch
   - All other dependencies: Quarterly review

5. **Monitoring Process:**
   - Automated dependency scanning in CI/CD (pip-audit, OSV-Scanner)
   - CVE notification subscription for dangerous functionality components
   - Quarterly manual review

### Acceptance Criteria
- [ ] `DEPENDENCY-POLICY.md` created with all sections
- [ ] SBOM generated and committed (CycloneDX or SPDX format)
- [ ] Security-critical components classified
- [ ] Remediation timeframes documented
- [ ] Update cadence documented
- [ ] Automated CVE scanning integrated (pip-audit or OSV-Scanner)
- [ ] CVE notification subscriptions configured
- [ ] Quarterly review process established
- [ ] Policy reviewed and approved by security team

### References
- ASVS 15.1.1: Document risk-based remediation timeframes
- Source Report: 15.1.1.md
- Related: FINDING-014

### Priority
**Critical** - Foundation for supply chain security, mandatory L1 requirement

---

## Issue: FINDING-014 - Complete Absence of SBOM and Dependency Version Tracking
**Labels:** bug, security, priority:critical, supply-chain
**Description:**
### Summary
The application lacks any mechanism to track, version, or audit third-party dependencies. No dependency manifest with version constraints exists (no pyproject.toml, requirements.txt, uv.lock, Pipfile.lock, or SBOM document). The application's security model depends on cryptography and argon2-cffi, but their versions are completely unverifiable.

### Details
- **Affected Files:** `v3/server/main.py` (line 1), `v3/steve/crypto.py` (lines 1-10), `v3/steve/election.py` (lines 1-10), Project-wide
- **ASVS Sections:** 15.2.1 (L1)
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)

**Missing Controls:**
- No version pinning
- No dependency lock file
- No SBOM document
- No CVE scanning
- No update process

**Impact:**
- Non-reproducible builds (each deployment may resolve different versions)
- No verification of deployed versions against known CVEs
- No protection against dependency confusion or typosquatting
- Impossible to verify compliance with documented update timeframes (ASVS 15.2.1)

### Remediation
**IMMEDIATE ACTIONS:**

1. **Create `pyproject.toml` with pinned dependencies:**
```toml
[project]
name = "steve-voting"
version = "3.0.0"
dependencies = [
    "asfquart>=1.0.0",
    "asfpy>=0.50.0",
    "cryptography>=44.0.0",
    "argon2-cffi>=23.1.0",
    "easydict>=1.13",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

2. **Generate and commit `uv.lock`:**
```bash
uv lock
git add uv.lock
git commit -m "Add dependency lock file"
```

3. **Generate SBOM:**
```bash
pip install cyclonedx-bom
cyclonedx-py -o sbom.json
```

4. **Document update timeframes in `SECURITY.md`:**
   - Critical CVEs: 48 hours
   - High: 7 days
   - Medium: 30 days
   - Routine updates: monthly

5. **Integrate automated vulnerability scanning:**
```yaml
# .github/workflows/security.yml
name: Security Scan
on: [push, pull_request, schedule]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v1
      - run: uv pip install pip-audit
      - run: pip-audit
```

6. **Enable Dependabot:**
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

7. **Conduct initial vulnerability scan:**
```bash
pip-audit
```

8. **Implement pre-commit hooks:**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pip-audit
        name: pip-audit
        entry: pip-audit
        language: system
        pass_filenames: false
```

9. **Establish monthly dependency review process**

10. **Integrate SBOM generation into release pipeline**

### Acceptance Criteria
- [ ] `pyproject.toml` created with all dependencies pinned
- [ ] `uv.lock` generated and committed
- [ ] SBOM generated in CycloneDX or SPDX format
- [ ] Initial vulnerability scan completed and findings remediated
- [ ] CI/CD pipeline includes automated vulnerability scanning
- [ ] Dependabot or Renovate enabled
- [ ] Pre-commit hooks implemented
- [ ] Monthly review process documented
- [ ] SBOM generation integrated into release process
- [ ] All critical/high CVEs in current dependencies resolved

### References
- ASVS 15.2.1: Verify components have not breached update timeframes
- CWE-1104: Use of Unmaintained Third Party Components
- Source Report: 15.2.1.md
- Related: FINDING-013

### Priority
**Critical** - Foundation for supply chain security, enables CVE tracking

---

## Issue: FINDING-015 - No Certificate Trust Validation - Self-Signed and Development Certificates Permitted
**Labels:** bug, security, priority:high, tls
**Description:**
### Summary
When TLS is enabled, no validation occurs to ensure the provided certificate is publicly trusted. The configuration template references mkcert-generated development certificates as the example, and there is no code to detect or reject self-signed certificates, development CAs, or certificates that would not be trusted by standard browsers. This allows production deployment with certificates that provide encryption but no authentication, enabling man-in-the-middle attacks.

### Details
- **Affected Files:** `v3/server/main.py` (lines 87-91), `v3/server/config.yaml.example` (lines 31-33)
- **ASVS Sections:** 12.2.2 (L1)
- **CWE:** CWE-295 (Improper Certificate Validation)

**Current State:**
- Configuration example shows mkcert certificates
- No validation that certificates are from trusted CAs
- No detection of self-signed certificates
- No warnings for development certificates in production

**Attack Vector:** Attacker can present their own certificate in MITM attack without detection, as application accepts any certificate with valid private key.

### Remediation
1. **Implement certificate validation:**
```python
def _validate_certificate(certfile):
    """Validate that certificate is not self-signed or from development CA."""
    import ssl
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    
    with open(certfile, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    # Check for mkcert patterns
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    
    if 'mkcert' in subject.lower() or 'mkcert' in issuer.lower():
        raise ValueError("Development certificate (mkcert) detected. Use publicly trusted certificate in production.")
    
    if subject == issuer:
        raise ValueError("Self-signed certificate detected. Use publicly trusted certificate in production.")
    
    # Verify chain terminates in trusted root
    # (implementation depends on platform trust store)
```

2. **Update configuration template:**
```yaml
server:
  # TLS Configuration (REQUIRED for production)
  # Use publicly trusted certificates from:
  #   - Let's Encrypt (recommended for public servers)
  #   - Organizational CA (for internal deployments)
  # 
  # WARNING: mkcert certificates are for DEVELOPMENT ONLY
  # DO NOT use mkcert, self-signed, or development certificates in production
  certfile: /path/to/public-trusted-cert.pem
  keyfile: /path/to/private-key.pem
```

3. **Add configuration flag:**
```python
# In config schema
allow_development_certificates: false  # Set to true ONLY for non-production
```

### Acceptance Criteria
- [ ] Certificate validation function implemented
- [ ] mkcert detection implemented
- [ ] Self-signed certificate detection implemented
- [ ] Configuration template updated with prominent warnings
- [ ] `allow_development_certificates` flag added
- [ ] Startup fails with clear error for development certificates (unless flag set)
- [ ] Tests verify rejection of mkcert/self-signed certificates
- [ ] Documentation includes certificate procurement guidance
- [ ] Let's Encrypt integration guide provided

### References
- ASVS 12.2.2: Verify certificates are trusted
- CWE-295: Improper Certificate Validation
- Source Report: 12.2.2.md
- Related: FINDING-007

### Priority
**High** - Allows MITM attacks despite TLS encryption