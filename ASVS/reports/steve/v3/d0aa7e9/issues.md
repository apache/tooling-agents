# Security Issues

## Issue: FINDING-001 - Systemic Missing HTML Output Encoding in EZT Templates Enabling Stored and Reflected XSS
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The EZT templating engine provides the `[format "html"]` directive for HTML encoding, but it is not applied at the majority of output points across all templates. User-controlled data including election titles, issue titles/descriptions, owner names, authorization strings, and URL parameters are rendered directly as `[variable]` without encoding in HTML body contexts. This enables both stored XSS (via database-persisted election/issue data) and reflected XSS (via URL parameters in error pages). Any authenticated committer can inject persistent JavaScript affecting all voters; attackers can also craft malicious URLs targeting authenticated users.

### Details
**CWE:** CWE-79  
**ASVS:** 1.1.1, 1.1.2, 1.2.1, 1.3.4, 1.3.5 (L1, L2)

The control exists and is correctly used in a few JavaScript onclick handlers, demonstrating awareness but inconsistent application (Type B gap). This creates false confidence that encoding is properly implemented.

**Affected Files:**
- `v3/server/templates/manage.ezt` (lines 176, 180, 241, 283)
- `v3/server/templates/manage-stv.ezt` (lines 134, 175, 196)
- `v3/server/templates/admin.ezt` (line 19)
- `v3/server/templates/voter.ezt` (lines 35, 49, 88, 96)
- `v3/server/templates/vote-on.ezt` (lines 88, 108, 109, 131, 163)
- `v3/server/templates/e_bad_eid.ezt` (line 8)
- `v3/server/templates/e_bad_iid.ezt` (line 8)
- `v3/server/templates/e_bad_pid.ezt` (line 8)
- `v3/server/pages.py` (lines 174-225, 240)

### Remediation
Apply `[format "html"]` to all user-controlled variables in HTML body contexts. Examples:
- Change `<strong>[issues.title]</strong>` to `<strong>[format "html"][issues.title][end]</strong>`
- Apply to all instances of: [owned.title], [owned.owner_name], [owned.authz], [e_title], [election.title], [election.owner_name], [election.authz], [issues.title], [issues.description], [open_elections.title], [open_elections.owner_name], [open_elections.authz], [upcoming_elections.title], [eid], [iid], [pid], etc.

**Alternative (strongly recommended):** Migrate to a template engine with auto-escaping by default (e.g., Jinja2 with `autoescape=True`) to eliminate this entire vulnerability class architecturally.

### Acceptance Criteria
- [ ] HTML encoding applied to all user-controlled variables in all templates
- [ ] Test cases added verifying XSS payloads are properly escaped
- [ ] Code review confirms no unescaped output points remain
- [ ] Consider migration to auto-escaping template engine

### References
- Related: FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114
- Source: 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.3.4.md, 1.3.5.md

### Priority
**CRITICAL** - Enables persistent JavaScript injection affecting all voters

---

## Issue: FINDING-002 - JavaScript Injection via Unencoded Server Data in STV Candidate JavaScript Object
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The vote-on.ezt template embeds user-controlled data (issue titles, STV candidate names/labels) directly into JavaScript string literals within a `<script>` block without JavaScript encoding. The `[format "js"]` or `[format "js,html"]` directive exists in the codebase and is correctly used in manage.ezt and manage-stv.ezt for identical scenarios, but is completely omitted in the voter-facing ballot page (Type B gap). An election administrator can inject JavaScript by including characters like `"`, `\`, or `</script>` in candidate names or issue titles, executing arbitrary JavaScript in every voter's browser.

### Details
**CWE:** CWE-79  
**ASVS:** 1.1.1, 1.1.2, 1.2.1, 1.2.3, 1.3.10, 1.3.5, 1.3.7, 1.3.3, 3.2.2 (L1, L2)

This enables session hijacking, silent vote manipulation, and complete compromise of election integrity.

**Affected Files:**
- `v3/server/templates/vote-on.ezt` (within &lt;script&gt; block - STV_CANDIDATES object)
- `v3/server/pages.py` (lines 258-263)

### Remediation
Apply `[format "js"]` to all server-supplied values in JavaScript contexts:

```javascript
const STV_CANDIDATES = {
  [for issues][is issues.vtype "stv"]
  "[format "js"][issues.iid][end]": {
    seats: [issues.seats],
    title: "[format "js"][issues.title][end]",
    candidates: [
      [for issues.candidates]{
        label: "[format "js"][issues.candidates.label][end]",
        name: "[format "js"][issues.candidates.name][end]"
      },[end]
    ]
  },[end][end]
};
```

**Alternative (recommended):** Use safer architecture by serializing data as JSON from Python using `json.dumps()` and embedding as a data attribute, then parsing with `JSON.parse()` on the client side. This eliminates the injection class entirely.

### Acceptance Criteria
- [ ] JavaScript encoding applied to all server variables in script blocks
- [ ] Test cases verify injection payloads are neutralized
- [ ] Consider JSON serialization approach for safer architecture

### References
- Related: FINDING-001, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114
- Source: 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.2.3.md, 1.3.10.md, 1.3.5.md, 1.3.7.md, 1.3.3.md, 3.2.2.md

### Priority
**CRITICAL** - Enables JavaScript execution in all voter browsers

---

## Issue: FINDING-003 - Stored XSS via Unsanitized Issue Descriptions Rendered as Raw HTML
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application accepts user-controlled issue descriptions and explicitly constructs HTML from this untrusted input without any sanitization. The `rewrite_description()` function wraps descriptions in `<pre>` tags and converts `doc:filename` patterns into HTML anchor tags, but performs no HTML sanitization on the user input before or after this transformation. An authenticated committer can inject malicious JavaScript that executes when any voter views the election page, enabling vote manipulation, session hijacking, privilege escalation, and election integrity compromise.

### Details
**CWE:** CWE-79  
**ASVS:** 1.3.1, 1.3.4, 1.3.5, 1.3.10, 1.1.1, 1.1.2, 1.2.1, 1.2.2, 1.2.9, 3.2.2 (L1, L2)

The EZT templating engine does not auto-escape HTML output. While the codebase demonstrates awareness of escaping by using `[format "js,html"]` for JavaScript contexts, this escaping is not applied when the same data is rendered in HTML body contexts, creating a critical stored XSS vulnerability.

**Affected Files:**
- `v3/server/pages.py` (lines 54-61, 466, 485, 39-48, 325-326, 27-35)
- `v3/server/templates/vote-on.ezt`
- `v3/server/templates/manage.ezt`
- `v3/server/templates/manage-stv.ezt`
- `v3/steve/election.py` (line 202)

### Remediation
**Option A (Recommended):** Use a server-side HTML sanitization library. Since `rewrite_description` intentionally constructs HTML (converting `doc:` references to links), use bleach or nh3 to allow only safe HTML elements:

```python
import bleach
import html

ALLOWED_TAGS = ['pre', 'a']
ALLOWED_ATTRIBUTES = {'a': ['href']}
ALLOWED_PROTOCOLS = ['https', 'http']

def rewrite_description(issue):
    import re
    desc = html.escape(issue.description or '')
    def repl(match):
        filename = html.escape(match.group(1))
        return f'<a href="/docs/{html.escape(issue.iid)}/{filename}">{filename}</a>'
    desc = re.sub(r'doc:([^\s]+)', repl, desc)
    issue.description = bleach.clean(
        f'<pre>{desc}</pre>',
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
    )
```

**Option B:** Apply EZT HTML escaping consistently in templates:
```html
<strong>[format "html"][issues.title][end]</strong>
<div class="description mt-2">[format "html"][issues.description][end]</div>
```

Note: Option B alone is insufficient for vote-on.ezt because rewrite_description intentionally produces HTML. Option A is required.

### Acceptance Criteria
- [ ] HTML sanitization library integrated (bleach or nh3)
- [ ] All issue descriptions sanitized before rendering
- [ ] Test cases verify XSS payloads are neutralized
- [ ] Verify legitimate HTML links still work

### References
- Related: FINDING-001, FINDING-002, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114
- Source: 1.3.1.md, 1.3.10.md, 1.3.4.md, 1.3.5.md, 1.3.9.md, 1.3.3.md, 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.2.2.md, 1.2.9.md, 3.2.2.md

### Priority
**CRITICAL** - Enables persistent JavaScript injection affecting all voters

---

## Issue: FINDING-004 - Stored XSS via Unsanitized Election Titles in All Listing Templates
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Election titles are accepted from user input without any sanitization and stored directly in the database. These titles are subsequently rendered in multiple templates without HTML escaping, creating stored XSS vulnerabilities that affect all users who view election listings. The vulnerability is particularly severe because election titles appear on listing pages viewed by ALL eligible voters, providing broad attack surface. Additionally, titles are embedded in flash messages, which are also rendered without escaping.

### Details
**CWE:** CWE-79  
**ASVS:** 1.3.1, 1.3.4, 1.3.5, 1.3.10 (L1, L2)

The impact includes vote manipulation, session hijacking, election integrity compromise, with broader reach than issue descriptions as titles appear on pages viewed by all eligible voters and higher-privileged users.

**Affected Files:**
- `v3/server/pages.py` (lines 405, 410, 147, 353)
- `v3/server/templates/admin.ezt`
- `v3/server/templates/voter.ezt`
- `v3/server/templates/manage.ezt`
- `v3/server/templates/vote-on.ezt`
- `v3/server/templates/flashes.ezt`

### Remediation
Apply `[format "html"]` escaping in all EZT templates for user-controlled data:

```html
<!-- voter.ezt -->
<h5 class="card-title mb-3">[format "html"][open_elections.title][end]</h5>

<!-- admin.ezt -->
<h5 class="card-title">[format "html"][owned.title][end]</h5>

<!-- manage.ezt -->
<h2>[format "html"][e_title][end]</h2>

<!-- flashes.ezt -->
[format "html"][flashes.message][end]
```

Additionally, sanitize at the input boundary:

```python
import html

@APP.post('/do-create-election')
@asfquart.auth.require({R.pmc_member})
async def do_create_endpoint():
    result = await basic_info()
    form = edict(await quart.request.form)
    
    clean_title = html.escape(form.title.strip())
    election = steve.election.Election.create(DB_FNAME, clean_title, result.uid)
    await flash_success(f'Created election: {html.escape(clean_title)}')
    ...
```

### Acceptance Criteria
- [ ] HTML encoding applied to all election titles in all templates
- [ ] Input sanitization added to election creation endpoint
- [ ] Test cases verify XSS payloads are properly escaped
- [ ] Flash messages properly escape user content

### References
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114
- Source: 1.3.1.md, 1.3.10.md, 1.3.4.md, 1.3.5.md

### Priority
**CRITICAL** - Affects all users viewing election listings

---

## Issue: FINDING-005 - Election Lifecycle State Enforcement Uses Removable `assert` Statements
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Multiple state-dependent write operations use Python assert statements to enforce election state requirements. Python assert statements can be globally disabled with the -O or -OO command-line flags, which removes all assertions from the bytecode. This makes state-based authorization controls bypassable through deployment configuration rather than code modification. When Python is run with optimization flags (python -O or PYTHONOPTIMIZE=1), all assert statements are removed from the bytecode, eliminating critical state machine enforcement and input validation.

### Details
**CWE:** CWE-617  
**ASVS:** 2.3.1, 2.3.2, 2.3.4, 2.1.2, 2.1.3, 8.1.2, 8.1.3, 8.1.4, 13.2.2, 15.1.5, 15.4.1, 15.4.3 (L1, L2, L3)

Per Python documentation: "assert should not be used for data validation because it can be globally disabled". This is common in production deployments for performance, which would eliminate critical state machine enforcement. Without documented remediation timeframes, vulnerabilities in argon2-cffi or cryptography could directly compromise vote secrecy, election integrity, and key derivation security.

**Affected Files:**
- `v3/steve/election.py` (lines 50, 70, 78, 107, 110, 116, 123, 127, 176, 190, 193, 205, 208, 227, 228, 241, 273, 349)

### Remediation
Replace all assert statements used for security validation with explicit if/raise patterns. Example transformation:

**Before:**
```python
assert self.is_editable()
assert vtype in vtypes.TYPES
```

**After:**
```python
if not self.is_editable():
    raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE)
if not isinstance(vtype, str) or vtype not in vtypes.TYPES:
    raise ValueError(f'Invalid vote type: {vtype!r}. Must be one of {vtypes.TYPES}')
```

Apply this pattern to all methods using assert for security checks in: delete(), open(), add_salts(), add_issue(), edit_issue(), delete_issue(), add_voter(), and _compute_state().

Additionally:
- Document this pattern in architecture documentation as a dangerous area requiring explicit runtime checks
- Add deployment documentation warning that PYTHONOPTIMIZE must never be set

### Acceptance Criteria
- [ ] All security-critical assert statements replaced with explicit validation
- [ ] Custom exception classes defined for state violations
- [ ] Architecture documentation updated with security patterns
- [ ] Deployment guide warns against PYTHONOPTIMIZE
- [ ] Test cases verify exceptions are raised correctly

### References
- Related: None (foundational security control)
- Source: 2.3.1.md, 2.3.2.md, 2.3.4.md, 2.1.2.md, 2.1.3.md, 8.1.2.md, 8.1.3.md, 8.1.4.md, 13.2.2.md, 15.1.5.md, 15.3.5.md, 15.4.1.md, 15.4.3.md

### Priority
**CRITICAL** - State machine bypass enables unauthorized election manipulation

---

## Issue: FINDING-006 - Missing Owner Authorization on All Election Management Endpoints
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application defines election ownership (owner_pid) and group authorization (authz) fields in the database schema with explicit documentation stating that only the owner or members of the specified LDAP group should be able to edit elections. However, these controls are never enforced in the web layer. The load_election and load_election_issue decorators contain only placeholder comments '### check authz' with no actual authorization logic. Any authenticated ASF committer can manipulate any election — opening, closing, adding/editing/deleting issues, and changing dates — regardless of whether they are the owner or in the authorized group.

### Details
**CWE:** CWE-862  
**ASVS:** 2.3.2, 2.3.5, 2.1.2, 2.1.3, 4.4.3, 7.2.1, 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.2.3, 8.3.1, 8.3.3, 8.4.1, 14.1.2, 14.2.4 (L1, L2, L3)

This is a Type B gap where the authorization need is explicitly recognized in documentation and schema but the check is never implemented, creating dangerous false confidence. This undermines the entire election integrity model and violates the documented authorization policy.

**Affected Files:**
- `v3/server/pages.py` (lines 193, 215, 218, 98, 81, 336, 388, 404, 422, 439, 461, 481, 489, 508, 526, 550, 572, 425, 331, 486, 510, 533, 451, 468, 375, 382, 398-401, 404-407, 170-193, 196-227)
- `v3/schema.sql` (lines 68, 73, 68-75)

### Remediation
Implement authorization checks in the load_election decorator to verify that the session user is either the owner_pid or a member of the authz LDAP group before allowing access to management endpoints.

Example implementation:
```python
def check_election_authz(election, uid):
    """Verify user is authorized to manage this election."""
    metadata = election.get_metadata()
    
    # Check if user is the owner
    if metadata.owner_pid == uid:
        return True
    
    # Check if user is member of authz group
    if metadata.authz:
        # Query LDAP to verify group membership
        if is_member_of_ldap_group(uid, metadata.authz):
            return True
    
    return False

def load_election(func):
    @functools.wraps(func)
    async def loader(eid):
        try:
            e = steve.election.Election(DB_FNAME, eid)
        except steve.election.ElectionNotFound:
            ...
        
        result = await basic_info()
        if not check_election_authz(e, result.uid):
            quart.abort(403, 'Not authorized to manage this election')
        
        return await func(e)
    return loader
```

Document authorization rules in a formal policy matrix mapping functions to required roles and resource relationships. Return 403 Forbidden for unauthorized access attempts with security logging.

### Acceptance Criteria
- [ ] Authorization check implemented in load_election decorator
- [ ] Authorization check implemented in load_election_issue decorator
- [ ] LDAP group membership verification integrated
- [ ] 403 responses returned for unauthorized access
- [ ] Security logging added for authorization failures
- [ ] Policy matrix documented
- [ ] Test cases verify authorization enforcement

### References
- Related: FINDING-049
- Source: 2.3.2.md, 2.3.5.md, 2.1.2.md, 2.1.3.md, 4.4.3.md, 7.2.1.md, 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.2.3.md, 8.3.1.md, 8.3.3.md, 8.4.1.md, 14.1.2.md, 14.2.4.md

### Priority
**CRITICAL** - Any committer can manipulate any election

---

## Issue: FINDING-007 - Irreversible State-Changing Operations Use GET Method Enabling CSRF and Accidental Triggering
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Critical state-changing operations (opening and closing elections) are implemented as GET endpoints with only client-side JavaScript confirmation dialogs. The server-side handlers perform no verification beyond authentication, and the use of GET methods means these operations can be triggered via simple URL navigation, image tags, iframe embeds, or browser prefetch mechanisms — completely bypassing the client-side confirmation. Election state transitions are irreversible operations that can be triggered by cross-site image tags, link prefetching, browser extensions, or web crawlers.

### Details
**CWE:** CWE-352  
**ASVS:** 2.3.2, 2.3.5, 2.1.2, 2.1.3, 3.3.2, 4.1.4, 4.4.3, 8.1.4, 8.3.1, 8.3.2, 10.2.1, 14.1.1, 14.1.2, 14.2.4 (L2, L3)

Combined with the missing ownership check (AUTHZ-001), this allows any authenticated committer's browser session to be weaponized to open or close any election through cross-site request forgery or social engineering. Election state (editable → open → closed) is a critical authorization decision factor — it controls whether voting is accepted, whether issues can be edited, and whether tallying is permitted.

**Affected Files:**
- `v3/server/pages.py` (lines 404, 422, 479-480, 499-500, 447, 464, 485, 505)
- `v3/server/templates/manage.ezt` (line 267)

### Remediation
1. **Immediate:** Convert do_open_endpoint() and do_close_endpoint() to POST method with CSRF token validation
2. Update manage.ezt template to use form submission instead of window.location.href navigation
3. **Short-term:** Add audit logging (structured, not access logging) for state changes with partial election IDs only
4. **Long-term:** Implement classification-aware routing policy with validate_route() method that validates HTTP method is appropriate for data classification (CRITICAL/SENSITIVE/INTERNAL identifiers require POST for state changes)

### Acceptance Criteria
- [ ] Endpoints converted to POST method
- [ ] CSRF token validation implemented
- [ ] Template updated to use form submission
- [ ] Audit logging added for state transitions
- [ ] Test cases verify GET requests are rejected
- [ ] Test cases verify CSRF protection works

### References
- Related: FINDING-008, FINDING-009, FINDING-030, FINDING-033, FINDING-034, FINDING-109
- Source: 2.3.2.md, 2.3.5.md, 2.1.2.md, 2.1.3.md, 3.3.2.md, 4.1.4.md, 4.4.3.md, 8.1.4.md, 8.3.1.md, 8.3.2.md, 10.2.1.md, 14.1.1.md, 14.1.2.md, 14.2.4.md

### Priority
**CRITICAL** - Enables trivial CSRF attacks on irreversible operations

---

## Issue: FINDING-008 - CSRF Token Is a Hardcoded Placeholder; Server Never Validates It
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The CSRF token is hardcoded as the string 'placeholder' and is never validated in any POST handler. This creates a false sense of security while leaving all state-changing operations vulnerable to CSRF attacks including vote manipulation (attacker can submit or change votes for authenticated voters) and election manipulation (attacker can create elections, add/edit/delete issues, set dates). The placeholder token creates false confidence that protection exists.

### Details
**CWE:** CWE-352  
**ASVS:** 3.5.1, 10.2.1 (L1, L2)

Affected operations include:
- POST /do-vote/&lt;eid&gt; (Submit votes)
- POST /do-create-election (Create election)
- POST /do-add-issue/&lt;eid&gt; (Add election issue)
- POST /do-edit-issue/&lt;eid&gt;/&lt;iid&gt; (Edit issue)
- POST /do-delete-issue/&lt;eid&gt;/&lt;iid&gt; (Delete issue)
- POST /do-set-open_at/&lt;eid&gt; (Set open date)
- POST /do-set-close_at/&lt;eid&gt; (Set close date)

**Affected Files:**
- `v3/server/pages.py` (lines 95, 438, 478)
- `v3/server/templates/manage.ezt`
- `v3/server/templates/vote-on.ezt`
- `v3/server/templates/admin.ezt`

### Remediation
Implement real CSRF token generation using secrets.token_hex(32) stored in session, and create a validate_csrf_token() function that checks tokens from both form data and X-CSRFToken headers.

```python
import secrets

async def generate_csrf_token():
    """Generate and store CSRF token in session."""
    s = await asfquart.session.read()
    token = secrets.token_hex(32)
    s['csrf_token'] = token
    await asfquart.session.write(s)
    return token

async def validate_csrf_token():
    """Validate CSRF token from form or header."""
    s = await asfquart.session.read()
    expected = s.get('csrf_token')
    if not expected:
        quart.abort(403, 'CSRF token missing from session')
    
    # Check form data first, then header
    form = await quart.request.form
    provided = form.get('csrf_token') or quart.request.headers.get('X-CSRFToken')
    
    if not provided or not secrets.compare_digest(expected, provided):
        quart.abort(403, 'Invalid CSRF token')
```

Apply this validation to all state-changing endpoints. Use secrets.compare_digest() for constant-time comparison to prevent timing attacks.

### Acceptance Criteria
- [ ] Real CSRF token generation implemented
- [ ] Token validation function created
- [ ] Validation applied to all POST endpoints
- [ ] Templates updated to include real tokens
- [ ] Test cases verify CSRF protection works
- [ ] Test cases verify invalid tokens are rejected

### References
- Related: FINDING-007, FINDING-009, FINDING-030, FINDING-033, FINDING-034, FINDING-109
- Source: 3.5.1.md, 10.2.1.md

### Priority
**CRITICAL** - All state-changing operations unprotected against CSRF

---

## Issue: FINDING-009 - Election Open and Close Operations Use GET Method for Irreversible State Changes
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Two critical state-changing operations (opening and closing elections) are implemented as GET requests, making them trivially exploitable through image tags, link prefetch, or simple hyperlinks. The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints permanently and irreversibly change election state without any CSRF protection, custom headers, or preflight checks. GET requests are always considered 'simple requests' by the browser and will never initiate a preflight OPTIONS request, regardless of origin. This bypasses even SameSite=Lax cookie protections and violates REST semantics.

### Details
**CWE:** CWE-352  
**ASVS:** 3.5.1, 3.5.2, 3.5.3 (L1)

An attacker who knows or can guess an election ID can trick an authenticated committer into prematurely opening or closing any election they have access to. The race window can be exploited to overwrite cryptographic material after voters have begun casting votes, effectively destroying cast ballots.

**Affected Files:**
- `v3/server/pages.py` (lines 504, 523, 536-553, 555-571, 448-466, 469-484)
- `v3/server/templates/manage.ezt` (lines 285, 297)
- `v3/steve/election.py` (lines 73, 94)

### Remediation
Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST endpoints with CSRF token validation. Update the JavaScript event handlers in manage.ezt to use form submission with POST method instead of window.location.href.

```javascript
// manage.ezt - Update event handlers
function openElection(eid) {
    if (confirm('Are you sure you want to open this election?')) {
        const form = document.createElement('form');
        form.method = 'POST';
        form.action = `/do-open/${eid}`;
        
        const csrfInput = document.createElement('input');
        csrfInput.type = 'hidden';
        csrfInput.name = 'csrf_token';
        csrfInput.value = '[csrf_token]';
        form.appendChild(csrfInput);
        
        document.body.appendChild(form);
        form.submit();
    }
}
```

Include CSRF token in the dynamically created form before submission. Add comprehensive logging for election state transitions with user ID, timestamp, and IP address. Consider implementing Sec-Fetch-* header validation middleware as defense-in-depth.

### Acceptance Criteria
- [ ] Endpoints converted to POST method
- [ ] CSRF token validation implemented
- [ ] JavaScript handlers updated to use form submission
- [ ] Audit logging added for state transitions
- [ ] Test cases verify GET requests are rejected
- [ ] Test cases verify image tag exploitation is prevented

### References
- Related: FINDING-007, FINDING-008, FINDING-030, FINDING-033, FINDING-034, FINDING-109
- Source: 3.5.1.md, 3.5.2.md, 3.5.3.md

### Priority
**CRITICAL** - Trivial exploitation via image tags or links

---

## Issue: FINDING-010 - Cross-Election Issue Data Access and Modification via Unscoped Queries
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Issue-level queries (q_get_issue, c_edit_issue, c_delete_issue) filter only by iid without constraining to the parent election's eid. Combined with the load_election_issue decorator not validating issue-election affiliation, operations on Election A can read/modify/delete issues belonging to Election B. This allows an attacker to bypass election state restrictions by routing operations through an editable election. A malicious user could supply an iid belonging to a different election, and the decorator would load it without verifying the relationship.

### Details
**CWE:** CWE-639  
**ASVS:** 8.2.2, 8.3.3, 8.4.1 (L1, L2, L3)

The queries do not include EID filters, allowing operations on issues from different elections. Combined with AUTHZ-001, this means any committer can modify any issue in any election by specifying a different election's EID in the URL path.

**Affected Files:**
- `v3/queries.yaml`
- `v3/steve/election.py` (lines 145, 151, 160, 161, 170, 171)
- `v3/server/pages.py` (lines 495, 515, 175, 193-221)

### Remediation
Add election scoping to issue queries in queries.yaml by adding 'AND eid = ?' to q_get_issue, c_edit_issue, and c_delete_issue queries.

```yaml
# queries.yaml
q_get_issue: |
  SELECT * FROM issue WHERE iid = ? AND eid = ?

c_edit_issue: |
  UPDATE issue SET title = ?, description = ?, vtype = ?
  WHERE iid = ? AND eid = ?

c_delete_issue: |
  DELETE FROM issue WHERE iid = ? AND eid = ?
```

Modify get_issue(), edit_issue(), and delete_issue() methods in election.py to pass self.eid as an additional parameter:

```python
def get_issue(self, iid):
    self.q_get_issue.perform(iid, self.eid)
    row = self.q_get_issue.fetchone()
    if not row:
        raise IssueNotFound(iid, self.eid)
    return row

def edit_issue(self, iid, title, description, vtype):
    self.c_edit_issue.perform(title, description, vtype, iid, self.eid)
    if self.db.conn.total_changes == 0:
        raise IssueNotFound(iid, self.eid)

def delete_issue(self, iid):
    self.c_delete_issue.perform(iid, self.eid)
    if self.db.conn.total_changes == 0:
        raise IssueNotFound(iid, self.eid)
```

In the load_election_issue decorator, verify that the loaded issue's eid matches the loaded election's eid.

### Acceptance Criteria
- [ ] Queries updated to include eid constraint
- [ ] Methods updated to pass eid parameter
- [ ] Rowcount checks added to detect cross-election attempts
- [ ] Custom exception raised for non-existent issues
- [ ] Decorator validates issue-election relationship
- [ ] Test cases verify cross-election access is prevented

### References
- Related: FINDING-051, FINDING-053, FINDING-153
- Source: 8.2.2.md, 8.3.3.md, 8.4.1.md

### Priority
**CRITICAL** - Enables cross-election data manipulation

---

## Issue: FINDING-011 - Vote Submission Endpoint Lacks Voter Eligibility Authorization Check
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The vote submission endpoint fails to verify that the authenticated user (`sub` claim from OAuth token, stored as `uid` in session) is eligible to vote in the target election. While the GET handler (`vote_on_page`) correctly checks voter eligibility using `election.q_find_issues.perform(result.uid, election.eid)`, the POST handler that actually records votes performs no such check. The endpoint has an explicit `### check authz` comment stub at line 426, indicating the developers intended to implement this check but never did. Any authenticated committer can vote in any election, even those they are not eligible for.

### Details
**ASVS:** 10.3.2, 10.4.11 (L2)

This compromises the integrity of election results by allowing unauthorized voting.

**Affected Files:**
- `v3/server/pages.py` (lines 424-467, 426, 411-456)

### Remediation
Add voter eligibility verification in the `do_vote_endpoint` function before recording votes:

```python
@APP.post('/do-vote/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_vote_endpoint(election):
    result = await basic_info()

    # Verify voter is eligible for this election
    election.q_find_issues.perform(result.uid, election.eid)
    if not election.q_find_issues.fetchall():
        await flash_danger('You are not authorized to vote in this election.')
        return quart.redirect('/voter', code=303)

    form = edict(await quart.request.form)
    ...
```

Deploy immediately to prevent unauthorized vote manipulation.

### Acceptance Criteria
- [ ] Eligibility check added to POST handler
- [ ] Test cases verify unauthorized voters are rejected
- [ ] Test cases verify authorized voters can still vote
- [ ] Security logging added for unauthorized attempts

### References
- Related: None (standalone authorization issue)
- Source: 10.3.2.md, 10.4.11.md

### Priority
**CRITICAL** - Any committer can vote in any election

---

## Issue: FINDING-012 - Election Management Endpoints Missing Ownership Authorization
**Labels:** bug, security, priority:critical
**Description:**
### Summary
All election management endpoints fail to verify that the authenticated user (identified by the `sub` claim from the OAuth token, stored as `uid` in the session) owns the election being modified. The `uid` claim is available throughout the application but is never compared against election ownership. The `Election.owned_elections(DB_FNAME, result.uid)` query exists and is used in `admin_page` for display purposes, but is never used as an enforcement gate for state-changing operations. Any authenticated committer can tamper with elections they don't own — opening elections prematurely, closing them early to suppress votes, deleting issues, or modifying election content.

### Details
**ASVS:** 10.3.2, 10.4.11 (L2)

**Affected Files:**
- `v3/server/pages.py` (lines 493, 498, 515, 520, 410, 98, 417, 534, 539, 559, 564, 583, 588, 355, 195, 97, 193, 217, 227, 487, 508, 527, 554, 581)

### Remediation
Implement ownership verification in the `load_election` decorator to protect all management endpoints:

```python
def load_election(func):
    @functools.wraps(func)
    async def loader(eid):
        try:
            e = steve.election.Election(DB_FNAME, eid)
        except steve.election.ElectionNotFound:
            ...

        # Enforce ownership: verify the authenticated user's uid matches
        # the election owner (using 'sub' claim from token/session)
        s = await asfquart.session.read()
        metadata = e.get_metadata()
        if metadata.owner_pid != s['uid']:
            quart.abort(403)

        return await func(e)
    return loader
```

This single fix protects all 8 management endpoints.

### Acceptance Criteria
- [ ] Ownership check implemented in load_election decorator
- [ ] 403 responses returned for non-owners
- [ ] Test cases verify ownership enforcement
- [ ] Test cases verify owners can still manage elections
- [ ] Security logging added for unauthorized attempts

### References
- Related: None (standalone authorization issue)
- Source: 10.3.2.md, 10.4.11.md

### Priority
**CRITICAL** - Any committer can manage any election

---

## Issue: FINDING-013 - No TLS Protocol Version Enforcement — Server May Accept Deprecated TLS 1.0/1.1 Connections
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application provides no explicit TLS protocol version enforcement. When TLS is enabled via certificate configuration, the server passes raw certfile/keyfile paths to the underlying framework without constructing or configuring an ssl.SSLContext, leaving protocol version negotiation entirely to system-level OpenSSL defaults. This means no minimum_version is set, no protocol flags disable TLS 1.0/1.1, no TLS 1.3 preference is configured, and both deployment modes (standalone and ASGI) are affected. This violates ASVS requirements for TLS 1.2+ minimum version enforcement and allows negotiation of deprecated protocols with known vulnerabilities (BEAST, POODLE, Lucky13).

### Details
**ASVS:** 12.1.1, 12.3.1 (L1, L2)

**Affected Files:**
- `v3/server/main.py` (lines 83-91, 99-118, 76-82)
- `v3/server/config.yaml.example`

### Remediation
Create an explicit ssl.SSLContext with enforced minimum version and pass it to the server framework:

```python
import ssl

def _create_tls_context(certfile, keyfile):
    """Create hardened TLS context."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Enforce TLS 1.2 minimum, TLS 1.3 maximum
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Set secure options
    ctx.options |= ssl.OP_NO_COMPRESSION
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= ssl.OP_SINGLE_DH_USE
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    
    # Restrict to strong ciphers
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES')
    
    # Load certificate
    ctx.load_cert_chain(certfile, keyfile)
    
    return ctx

# In run_standalone():
if app.cfg.server.certfile:
    ssl_context = _create_tls_context(
        app.cfg.server.certfile,
        app.cfg.server.keyfile
    )
    kwargs['ssl'] = ssl_context
```

For ASGI/Hypercorn deployment, provide a hypercorn.toml configuration file with certfile, keyfile, and ciphers configuration. Add minimum_tls_version and ciphers fields to the config schema. Add a startup warning/abort when certfile is empty and the server is not binding to localhost.

### Acceptance Criteria
- [ ] SSL context creation function implemented
- [ ] TLS 1.2 minimum version enforced
- [ ] Strong cipher suites configured
- [ ] Hypercorn configuration template provided
- [ ] Config schema updated
- [ ] Startup validation added
- [ ] Test cases verify TLS 1.0/1.1 are rejected

### References
- Related: None (foundational TLS control)
- Source: 12.1.1.md, 12.3.1.md

### Priority
**CRITICAL** - May accept deprecated TLS protocols with known vulnerabilities

---

## Issue: FINDING-014 - Application Falls Back to Plain HTTP When TLS Not Configured
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The TLS control exists but is implemented as an optional, bypassable configuration toggle. The `if app.cfg.server.certfile:` conditional means when the certfile config value is empty, blank, or absent, the server launches over plain HTTP with zero warnings, zero errors, and zero compensating controls. The configuration comments actively document this as intended behavior. There is no enforcement at any layer - no startup validation that rejects a missing TLS configuration, no HTTP listener that redirects to HTTPS, no HSTS header injection, and no warning log message when operating without TLS. The application silently degrades to an insecure transport.

### Details
**CWE:** CWE-319  
**ASVS:** 12.2.1, 12.3.1, 12.3.3, 4.4.1 (L1, L2)

For this voting system, plain HTTP operation exposes:
- Authentication tokens (ASF OAuth tokens and session cookies transmitted in cleartext)
- Vote contents (transmitted from client to server in HTTP request body before encryption)
- Election management operations
- Complete loss of transport security guarantees

This directly violates ASVS 12.2.1 and 12.3.1 requirements that the server must not fall back to insecure or unencrypted communications.

**Affected Files:**
- `v3/server/main.py` (lines 84-90, 98-117, 77-80, 98-104)
- `v3/server/config.yaml.example` (lines 27-31, 28-31)

### Remediation
Make TLS mandatory by enforcing certificate validation at startup:

```python
def create_app(cfg):
    # Validate TLS configuration
    if not cfg.server.certfile or not cfg.server.keyfile:
        raise RuntimeError('TLS certificate and key are mandatory. Set certfile and keyfile in config.')
    
    if not os.path.exists(cfg.server.certfile):
        raise RuntimeError(f'Certificate file not found: {cfg.server.certfile}')
    if not os.path.exists(cfg.server.keyfile):
        raise RuntimeError(f'Key file not found: {cfg.server.keyfile}')
    
    # Create explicit SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES')
    ssl_context.load_cert_chain(cfg.server.certfile, cfg.server.keyfile)
    
    # Add HSTS header to all responses
    @app.after_request
    async def add_hsts(response):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
```

Remove config documentation suggesting plain HTTP is acceptable. For ASGI mode, document mandatory Hypercorn TLS configuration and add startup validation of `X-Forwarded-Proto` or equivalent. Consider adding an HTTP listener that returns 301 redirects to HTTPS to handle accidental plaintext connections.

### Acceptance Criteria
- [ ] Startup validation fails if TLS not configured
- [ ] Certificate/key file existence validated
- [ ] Explicit SSL context created
- [ ] HSTS header added to all responses
- [ ] Config documentation updated
- [ ] ASGI deployment guide includes TLS requirements
- [ ] Test cases verify plain HTTP is rejected

### References
- Related: FINDING-178
- Source: 12.2.1.md, 12.3.1.md, 12.3.3.md, 4.4.1.md

### Priority
**CRITICAL** - Application can run without transport security

---

## Issue: FINDING-015 - AES-128-CBC (Fernet) Used Instead of Approved AEAD Cipher; Incomplete Migration to XChaCha20-Poly1305
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application uses Fernet (AES-128-CBC + HMAC-SHA256) for vote encryption, which violates ASVS 11.3.2's requirement for approved AEAD cipher modes such as AES-GCM or ChaCha20-Poly1305. Evidence of an incomplete cryptographic migration exists: the key derivation function is explicitly configured for XChaCha20-Poly1305 (HKDF with info=b'xchacha20_key', 32-byte key length), but the actual encryption operations still use Fernet. This represents a Type B gap where the control exists but is not applied, creating false confidence that an approved cipher is in use.

### Details
**ASVS:** 11.3.2 (L1)

Fernet uses AES-128-CBC (not an approved AEAD mode), splits the 32-byte key into 16 bytes for HMAC-SHA256 and 16 bytes for AES-128 encryption, and while the encrypt-then-MAC construction mitigates classic padding oracle attacks, CBC mode remains vulnerable to implementation-level side channels. All vote ciphertext stored in the vote table uses this unapproved cipher mode.

**Affected Files:**
- `v3/steve/crypto.py` (lines 63-75, 77-80, 84-88)
- `v3/steve/election.py` (lines 236, 271)

### Remediation
Complete the migration indicated by the code comments. Replace Fernet with XChaCha20-Poly1305 (as the HKDF is already configured for) using a library like pynacl/nacl.secret.SecretBox, or alternatively use AES-256-GCM from the cryptography library.

```python
from nacl.secret import SecretBox
from nacl.encoding import Base64Encoder

def _derive_vote_key(opened_key, pid, iid, salt):
    """Derive vote-specific encryption key using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # XChaCha20-Poly1305 key size
        salt=salt,
        info=b'xchacha20_key',
    )
    return hkdf.derive(opened_key + pid.encode() + iid.encode())

def create_vote(vote_token, salt, votestring):
    """Encrypt vote using XChaCha20-Poly1305."""
    box = SecretBox(vote_token)
    ciphertext = box.encrypt(votestring.encode(), encoder=Base64Encoder)
    return ciphertext.decode()

def decrypt_votestring(vote_token, ciphertext):
    """Decrypt vote using XChaCha20-Poly1305."""
    box = SecretBox(vote_token)
    plaintext = box.decrypt(ciphertext.encode(), encoder=Base64Encoder)
    return plaintext.decode()
```

Update the HKDF info parameter to match the chosen cipher. Implement a re-encryption strategy for existing vote data or a version-aware decryption path to handle the migration of stored ciphertext.

### Acceptance Criteria
- [ ] Fernet replaced with XChaCha20-Poly1305 or AES-256-GCM
- [ ] All encryption/decryption operations updated
- [ ] Migration strategy for existing votes implemented
- [ ] Test cases verify new cipher works correctly
- [ ] Test cases verify old votes can still be decrypted (if migration path chosen)

### References
- Related: None (cryptographic primitive upgrade)
- Source: 11.3.2.md

### Priority
**CRITICAL** - Using unapproved cipher mode for vote encryption

---

## Issue: FINDING-016 - Complete Absence of Authenticated Data Clearing from Client Storage
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application completely lacks mechanisms to clear authenticated data from client storage after session termination. Specifically: (1) No `Clear-Site-Data` HTTP header is sent on any response, (2) No logout endpoint exists to trigger session termination and cleanup, (3) No `Cache-Control` headers prevent browser caching of authenticated pages, (4) No client-side JavaScript clears DOM/storage when session ends. All 12+ authenticated routes inject voter identity (uid, name, email) and election data into HTML responses via the `basic_info()` function. Without cache-control headers, browsers cache these pages containing sensitive voter information.

### Details
**CWE:** CWE-524  
**ASVS:** 14.3.1 (L1)

In a voting system context, this enables voter privacy violations through browser cache on shared computers, exposing who voted and in which elections, violating ballot secrecy principles.

**Affected Files:**
- `v3/server/pages.py` (lines 85-95, 148, 186, 528)

### Remediation
1. Add logout endpoint with `Clear-Site-Data` header:
```python
@APP.get('/logout')
@asfquart.auth.require({R.committer})
async def logout():
    # Invalidate server-side session
    s = await asfquart.session.read()
    s.clear()
    await asfquart.session.write(s)
    
    # Clear client-side data
    response = quart.make_response(quart.redirect('/'))
    response.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    return response
```

2. Add `Cache-Control` headers to all authenticated responses via `after_request` middleware:
```python
@APP.after_request
async def add_cache_control(response):
    if hasattr(quart.g, 'authenticated') and quart.g.authenticated:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
```

3. Add client-side cleanup JavaScript as fallback that clears sessionStorage on beforeunload and implements periodic session checks to clear DOM if session expires

4. Mark sensitive DOM elements in templates with `data-sensitive` attribute for targeted cleanup

### Acceptance Criteria
- [ ] Logout endpoint implemented with Clear-Site-Data header
- [ ] Cache-Control headers added to authenticated responses
- [ ] Client-side cleanup JavaScript implemented
- [ ] Test cases verify data is cleared after logout
- [ ] Test cases verify authenticated pages are not cached

### References
- Related: FINDING-072
- Source: 14.3.1.md

### Priority
**CRITICAL** - Voter privacy violation through browser cache

---

## Issue: FINDING-017 - Complete Absence of SBOM, Dependency Manifest, and Remediation Timeframes for Security-Critical Dependencies
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application has no Software Bill of Materials (SBOM), no dependency version pinning, no documented update/remediation timeframes, and no formal dependency manifest. The entire vote secrecy guarantee depends on cryptographic libraries (argon2-cffi and cryptography) that have no documented remediation timeframes for vulnerabilities. The codebase uses `uv` as indicated by the shebang, but lacks the required PEP 723 inline metadata block, and no requirements.txt, pyproject.toml, or lock file exists.

### Details
**CWE:** CWE-1395  
**ASVS:** 15.1.1, 15.1.2, 15.2.1 (L1, L2)

This creates multiple critical gaps:
1. A published CVE in cryptographic libraries could remain unpatched indefinitely with no organizational accountability
2. Each deployment may resolve to different dependency versions including ones with known vulnerabilities
3. Transitive dependencies are completely invisible
4. ASVS 15.2.1 is completely unauditable as there are no documented timeframes to verify compliance against
5. Builds are not reproducible across environments

Without documented remediation timeframes, vulnerabilities in argon2-cffi or cryptography could directly compromise vote secrecy (all encrypted votes could be decrypted), election integrity (tamper detection relies on these libraries), and key derivation security (foundation of all vote tokens).

**Affected Files:**
- `v3/server/main.py` (line 1)
- `v3/steve/crypto.py` (lines 21-24, 58-94)
- `v3/steve/election.py` (lines 24-25)
- `v3/server/main.py` (lines 29, 37-38)

### Remediation
1. Create pyproject.toml with pinned dependencies:
```toml
[project]
name = "steve-voting"
version = "3.0.0"
dependencies = [
    "asfquart>=1.0.0,<2",
    "asfpy>=0.1.0,<1",
    "cryptography>=43.0.0,<44",
    "argon2-cffi>=23.1.0,<24",
    "easydict>=1.13,<2",
]
```

2. Generate and commit lock file using `uv lock` or `pip-compile --generate-hashes` for reproducible builds

3. Generate machine-readable SBOM in CycloneDX or SPDX format:
```bash
cyclonedx-py environment -o sbom.json
# or
syft dir:./v3 -o cyclonedx-json > sbom.json
```

4. Create DEPENDENCY-POLICY.md documenting:
   - Component Risk Classification (Dangerous Functionality Components: cryptography, argon2-cffi; Risky Components: asfquart, asfpy, easydict)
   - Vulnerability Remediation Timeframes (Critical 9.0+: 24h for dangerous functionality/48h for standard; High 7.0-8.9: 72h/7d; Medium 4.0-6.9: 14d/30d; Low 0.1-3.9: 30d/90d)
   - General Update Cadence (security-critical libraries: monthly review with 7-day update window; all other dependencies: quarterly review)
   - Monitoring Process (automated CVE scanning in CI/CD, CVE notification subscriptions for dangerous functionality components, quarterly manual reviews)

5. Implement automated dependency scanning using pip-audit, OSV-Scanner, or Dependabot

6. Use hash verification in requirements.txt format for critical packages

7. Integrate SBOM generation into CI/CD pipeline and store with each release

### Acceptance Criteria
- [ ] pyproject.toml created with pinned dependencies
- [ ] Lock file generated and committed
- [ ] SBOM generated in CycloneDX or SPDX format
- [ ] DEPENDENCY-POLICY.md created with remediation timeframes
- [ ] Automated dependency scanning implemented in CI/CD
- [ ] Hash verification added for critical packages
- [ ] SBOM generation integrated into release process

### References
- Related: None (foundational dependency management)
- Source: 15.1.1.md, 15.1.2.md, 15.2.1.md

### Priority
**CRITICAL** - No visibility or accountability for cryptographic library vulnerabilities

---

## Issue: FINDING-018 - Tampering Detection Event Bypasses Structured Logging Framework
**Labels:** bug, security, priority:critical
**Description:**
### Summary
Election tampering detection—the most critical security event in the voting system—outputs to stdout via print() instead of using the configured _LOGGER framework. The logger is imported and used elsewhere in the same file, but this critical event bypasses structured logging entirely. This means tampering alerts may not reach log aggregation systems (especially in daemon/cron/systemd deployments), have no timestamp or operator identity for forensic investigation, cannot be correlated with other security events in SIEM systems, and create false security confidence that all events are logged. In production ASGI environments where stdout may not be captured, this critical security signal could be completely lost.

### Details
**ASVS:** 16.1.1, 16.2.1, 16.2.3, 16.2.4, 16.3.3 (L2)

**Affected Files:**
- `v3/server/bin/tally.py` (lines 153-155, 119, 129, 133-136, 140-141, 145-147, 151, 161-162)

### Remediation
Replace print() statement with _LOGGER.critical() to log tampering detection with complete ASVS 16.2.1 metadata:

```python
import getpass
import socket

# In tampering detection code:
operator = getpass.getuser()
hostname = socket.gethostname()

_LOGGER.critical(
    f'TAMPERING_DETECTED: election[E:{election_id}] integrity check failed. '
    f'Tally aborted. operator={operator} host={hostname} pid={os.getpid()} '
    f'db_path={db_fname} spy_on_open={spy_on_open}'
)

# Keep print() for CLI user feedback
print('TAMPERING DETECTED. Tally aborted.')
```

Keep print() for CLI user feedback but ensure critical event reaches security logs.

### Acceptance Criteria
- [ ] Tampering detection logged via _LOGGER.critical()
- [ ] Log includes operator identity, timestamp, election ID, database path
- [ ] Print() retained for CLI user feedback
- [ ] Test cases verify log output format
- [ ] Test cases verify logs reach aggregation systems

### References
- Related: None (standalone logging issue)
- Source: 16.1.1.md, 16.2.1.md, 16.2.3.md, 16.2.4.md, 16.3.3.md

### Priority
**CRITICAL** - Most important security event bypasses logging framework

---

## Issue: FINDING-019 - Tally Operations Create No Audit Trail With Operator Identity
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The tally operation—which decrypts all votes and computes election results—is the most security-sensitive operation in the system but creates no meaningful security audit trail. There is no logging of who initiated the tally, when it occurred, whether --spy-on-open-elections was used (allowing premature result access), completion status, or summary of results. No forensic evidence exists of when tallying occurred or who performed it, making insider threats and unauthorized result access completely invisible. This directly contradicts domain requirements that tally operations must create audit trails and violates ASVS requirements for logging security-sensitive operations.

### Details
**ASVS:** 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3, 16.2.2 (L2, L3)

**Affected Files:**
- `v3/server/bin/tally.py` (lines 136-160, 102-133, 88-142, 76-113, 116-142, 120-150, 85-115, 138-165, 98-135, 145-171)

### Remediation
Add comprehensive audit logging for tally lifecycle:

```python
import getpass
import socket
import os

operator = getpass.getuser()
hostname = socket.gethostname()

# (1) Log tally initiation
_LOGGER.info(
    f'TALLY_INITIATED: operator={operator} host={hostname} pid={os.getpid()} '
    f'election[E:{election_id}] issue_id={issue_id} spy_on_open={spy_on_open} '
    f'db_path={db_fname} output_format={output_format}'
)

# (2) Log each issue being tallied
for idx, issue in enumerate(issues, 1):
    _LOGGER.info(f'TALLY_PROGRESS: issue {idx}/{len(issues)} iid={issue.iid}')

# (3) Log successful completion
_LOGGER.info(
    f'TALLY_COMPLETED: operator={operator} election[E:{election_id}] '
    f'issues_tallied={len(issues)} total_voters={voter_count}'
)

# (4) Log tampering check results
if tampering_detected:
    _LOGGER.critical(
        f'TAMPERING_DETECTED: election[E:{election_id}] integrity check failed'
    )
else:
    _LOGGER.info(f'INTEGRITY_CHECK_PASSED: election[E:{election_id}]')
```

### Acceptance Criteria
- [ ] Tally initiation logged with operator identity
- [ ] Progress logging for each issue
- [ ] Completion logging with summary statistics
- [ ] Tampering check results logged
- [ ] All logs include election ID and operator context
- [ ] Test cases verify log output format

### References
- Related: None (standalone audit logging issue)
- Source: 16.1.1.md, 16.2.1.md, 16.3.1.md, 16.3.2.md, 16.3.3.md, 16.2.2.md, 16.2.4.md

### Priority
**CRITICAL** - Most sensitive operation has no audit trail

---

## Issue: FINDING-020 - No Global Error Handler Defined - Unhandled Exceptions Expose Internal Details
**Labels:** bug, security, priority:critical
**Description:**
### Summary
The application does not define a global error handler to catch unhandled exceptions. Any exception not explicitly caught by individual endpoint handlers will be processed by the framework's default error handling mechanism. Without an explicit global handler, if the application is deployed in debug mode (run_standalone() uses logging.basicConfig(level=logging.DEBUG)), full tracebacks with cryptographic key material (opened_key, salt), database paths, SQL query structures, and internal module names could be exposed to users. This represents a complete lack of defense-in-depth protection against information disclosure through error messages.

### Details
**CWE:** CWE-209  
**ASVS:** 16.5.1 (L2)

**Affected Files:**
- `v3/server/pages.py` (line 1)
- `v3/server/main.py` (lines 38-44)
- `v3/server/pages.py` (lines 95-117)

### Remediation
Register a global error handler in main.py create_app() or pages.py:

```python
@APP.errorhandler(Exception)
async def handle_exception(error):
    """Global error handler - log details server-side, return generic message to user."""
    # Preserve intentional HTTP errors
    if isinstance(error, quart.exceptions.HTTPException):
        return error
    
    # Log full error server-side
    _LOGGER.error(
        f'Unhandled exception: {type(error).__name__}: {error}',
        exc_info=True
    )
    
    # Return generic message to user
    return quart.jsonify({
        'error': 'An unexpected error occurred. Please try again later.'
    }), 500

@APP.errorhandler(500)
async def handle_500(error):
    """Explicit handler for 500 errors."""
    _LOGGER.error(f'Internal server error: {error}', exc_info=True)
    return quart.jsonify({
        'error': 'An unexpected error occurred. Please try again later.'
    }), 500
```

Additionally, add a None check for JSON body in _set_election_date before calling .get() to prevent AttributeError on malformed requests.

### Acceptance Criteria
- [ ] Global error handler registered
- [ ] Full errors logged server-side
- [ ] Generic messages returned to users
- [ ] HTTP exceptions preserved
- [ ] Test cases verify error handling works
- [ ] Test cases verify sensitive data is not exposed

### References
- Related: FINDING-021, FINDING-226
- Source: 16.5.1.md

### Priority
**CRITICAL** - Unhandled exceptions may expose cryptographic material

---

## Issue: FINDING-021 - Error Handling Pattern Not Applied to State-Changing Endpoints
**Labels:** bug, security, priority:critical
**Description:**
### Summary
A secure error handling pattern exists in do_vote_endpoint that catches exceptions, logs details server-side, and returns generic error messages to users. However, this pattern is NOT applied to five other state-changing endpoints (do_open_endpoint, do_close_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint). These unprotected endpoints call business logic methods that use assert statements for state validation, which will raise unhandled AssertionError exceptions when violated. Stack traces could expose cryptographic parameters (opened_key, salt values), database file paths and query structures, internal election state machine design, and in debug mode: full source code context and all local variables in each stack frame.

### Details
**CWE:** CWE-209  
**ASVS:** 16.5.1 (L2)

**Affected Files:**
- `v3/server/pages.py` (lines 498, 520, 538, 563, 586)
- `v3/steve/election.py` (lines 75-89, 122-128, 190-207, 209-220, 222-233)

### Remediation
**Option A:** Apply try-except pattern to each endpoint (consistent with do_vote_endpoint):

```python
@APP.post('/do-open/<eid>')
@asfquart.auth.require({R.pmc_member})
@load_election
async def do_open_endpoint(election):
    try:
        election.open(PEOPLEDB_FNAME)
        await flash_success('Election opened successfully')
        return quart.redirect(f'/manage/{election.eid}', code=303)
    except Exception as e:
        _LOGGER.error(f'Error opening election {election.eid}: {e}', exc_info=True)
        await flash_danger('Failed to open election. Please try again.')
        return quart.redirect(f'/manage/{election.eid}', code=303)
```

**Option B (preferred):** Replace assert statements with proper validation that returns user-friendly errors:

```python
# In election.py
def open(self, pdb):
    if not self.is_editable():
        raise ElectionBadState(
            self.eid,
            self.get_state(),
            self.S_EDITABLE,
            'Cannot open election - not in editable state'
        )
    # ... rest of method
```

### Acceptance Criteria
- [ ] Try-except pattern applied to all state-changing endpoints OR
- [ ] Assert statements replaced with proper validation
- [ ] Custom exception classes defined
- [ ] Generic error messages returned to users
- [ ] Full errors logged server-side
- [ ] Test cases verify error handling works

### References
- Related: FINDING-020, FINDING-226
- Source: 16.5.1.md

### Priority
**CRITICAL** - State-changing endpoints may expose sensitive details via exceptions

---

## Issue: FINDING-022 - Reflected XSS via URL Path Parameters in Error Templates Without Escaping
**Labels:** bug, security, priority:high
**Description:**
### Summary
URL path parameters (election ID and issue ID) are extracted from the request path and passed directly to error templates without HTML entity escaping. When an invalid ID is provided, the error template renders the raw parameter value in the HTML body, enabling reflected XSS attacks through crafted URLs. An attacker can craft malicious URLs containing JavaScript payloads that execute when error pages are rendered.

### Details
**CWE:** CWE-79  
**ASVS:** 1.3.10, 1.3.5, 1.3.7, 1.3.3 (L2)

**Affected Files:**
- `v3/server/pages.py` (lines 163-166, 185-188, 199-202, 142-153)
- `v3/server/templates/e_bad_eid.ezt` (line 8)
- `v3/server/templates/e_bad_iid.ezt` (line 8)
- `v3/server/templates/e_bad_pid.ezt`

### Remediation
Apply `[format "html"]` escaping in error templates:

```html
<!-- e_bad_eid.ezt -->
The Election ID ([format "html"][eid][end]) does not exist...

<!-- e_bad_iid.ezt -->
The Issue ID ([format "html"][iid][end]) does not exist...

<!-- e_bad_pid.ezt -->
The Person ID ([format "html"][pid][end]) does not exist...
```

Additionally, implement server-side allowlist validation:

```python
import re

EID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

if not EID_PATTERN.match(eid):
    quart.abort(400, 'Invalid election ID format')
```

### Acceptance Criteria
- [ ] HTML encoding applied to all ID parameters in error templates
- [ ] Server-side validation implemented
- [ ] Test cases verify XSS payloads are escaped
- [ ] Test cases verify invalid formats are rejected

### References
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114
- Source: 1.3.10.md, 1.3.5.md, 1.3.7.md, 1.3.3.md

### Priority
**HIGH** - Reflected XSS via error pages

---

## Issue: FINDING-023 - Election Opening Operation Lacks Atomic Transaction Control
**Labels:** bug, security, priority:high
**Description:**
### Summary
The election opening operation is a critical state transition that involves multiple database modifications across two separate committed transactions. The open() method first calls add_salts(), which commits its own transaction containing per-voter salt generation, then separately executes cryptographic operations and commits the election state change. This split-transaction approach violates ASVS 2.3.3's requirement for atomic business operations. If steps after add_salts() fail, the database retains committed salts while the election remains in 'editable' state, creating an inconsistent state. Concurrent open() calls can interleave, causing cryptographic material to be overwritten.

### Details
**CWE:** CWE-362  
**ASVS:** 2.3.3, 2.3.4, 15.4.1, 15.4.2 (L2, L3)

If the race window is exploited, the election's cryptographic material can be overwritten after voters have already begun casting votes. Votes encrypted with the first set of keys become permanently undecryptable, effectively destroying cast ballots.

**Affected Files:**
- `v3/steve/election.py` (lines 74-89, 126-140, 73-84, 121-139)
- `v3/server/pages.py` (line 472)

### Remediation
Wrap the entire open() operation in a single transaction using IMMEDIATE mode to acquire write lock before checking state:

```python
def open(self, pdb):
    """Open election with atomic transaction."""
    self.db.conn.execute('BEGIN IMMEDIATE')
    
    try:
        # Check state within transaction
        md = self._all_metadata(self.S_EDITABLE)
        
        # Set mayvote salts within same transaction
        self.q_all_issues.perform(self.eid)
        for mayvote in self.q_all_issues.fetchall():
            salt = crypto.gen_salt()
            self.c_salt_mayvote.perform(salt, mayvote.rowid)
        
        # Gather election data and generate keys
        edata = self.gather_election_data(pdb)
        salt = crypto.gen_salt()
        opened_key = crypto.gen_opened_key(edata, salt)
        
        # Update election state
        self.c_open.perform(salt, opened_key, self.eid)
        
        # Commit everything
        self.db.conn.execute('COMMIT')
    except Exception:
        self.db.conn.execute('ROLLBACK')
        raise
```

Add try/except blocks with explicit ROLLBACK on failure. Add comprehensive logging for election state transitions with user ID, timestamp, and IP address.

### Acceptance Criteria
- [ ] Entire open() operation wrapped in single transaction
- [ ] BEGIN IMMEDIATE used to acquire write lock
- [ ] Explicit ROLLBACK on failure
- [ ] Logging added for state transitions
- [ ] Test cases verify atomicity
- [ ] Test cases verify concurrent operations are serialized

### References
- Related: FINDING-024, FINDING-087
- Source: 2.3.3.md, 2.3.4.md, 15.4.1.md, 15.4.2.md

### Priority
**HIGH** - Race condition can corrupt election cryptographic material

---

## Issue: FINDING-024 - Batch Vote Submission Lacks Transactional Atomicity
**Labels:** bug, security, priority:high
**Description:**
### Summary
The vote submission endpoint processes multiple votes from a single user ballot submission by iterating through each vote and calling add_vote() individually. Each add_vote() call performs a single INSERT that auto-commits immediately. If any vote in the sequence fails, all previously committed votes remain in the database while subsequent votes are lost, resulting in a partial ballot submission that violates voter intent and election integrity. In a voting system, the user's ballot submission is the most critical business operation and must be atomic.

### Details
**CWE:** CWE-362  
**ASVS:** 2.3.3, 2.3.4, 15.4.1, 15.4.2, 15.4.3 (L2, L3)

When a voter submits votes for multiple issues in a single request, each vote is processed as an independent transaction in autocommit mode. If the election closes or an error occurs mid-batch, some votes may be recorded while others are lost, with no clear feedback to the voter about which votes succeeded.

**Affected Files:**
- `v3/server/pages.py` (lines 376-417, 403-446)
- `v3/steve/election.py` (lines 201-212, 258-269)

### Remediation
Create a new add_votes() method in election.py that accepts a dictionary of {iid: votestring} and wraps all vote insertions in a single transaction:

```python
def add_votes(self, pid, votes_dict):
    """Add multiple votes atomically."""
    self.db.conn.execute('BEGIN IMMEDIATE')
    
    try:
        for iid, votestring in votes_dict.items():
            # Validate issue exists and belongs to this election
            issue = self.get_issue(iid)
            
            # Add vote within transaction (no auto-commit)
            mayvote = self.q_get_mayvote.first_row(pid, iid)
            vote_token = crypto.gen_vote_token(
                self._all_metadata(self.S_OPEN).opened_key,
                pid, iid, mayvote.salt
            )
            ciphertext = crypto.create_vote(vote_token, mayvote.salt, votestring)
            self.c_add_vote.perform(vote_token, ciphertext)
        
        # Commit all votes together
        self.db.conn.execute('COMMIT')
    except Exception as e:
        self.db.conn.execute('ROLLBACK')
        raise
```

Update do_vote_endpoint() in pages.py to call this batch method instead of iterating and calling add_vote() individually. Ensure all votes are validated before beginning the transaction, and roll back the entire batch if any single vote fails. Provide clear feedback about transaction success or complete rollback.

### Acceptance Criteria
- [ ] Batch add_votes() method created
- [ ] All votes wrapped in single transaction
- [ ] Validation performed before transaction begins
- [ ] Explicit ROLLBACK on any failure
- [ ] Clear feedback to user on success/failure
- [ ] Test cases verify atomicity
- [ ] Test cases verify partial submissions are prevented

### References
- Related: FINDING-023, FINDING-087
- Source: 2.3.3.md, 2.3.4.md, 15.4.1.md, 15.4.2.md, 15.4.3.md

### Priority
**HIGH** - Partial ballot submissions violate voter intent

---

## Issue: FINDING-025 - TOCTOU Race Condition Allows Vote Insertion After Election Closure
**Labels:** bug, security, priority:high
**Description:**
### Summary
The vote submission pathway has a Time-of-Check-to-Time-of-Use (TOCTOU) race condition. The add_vote method checks that the election is open at line 261, but the actual vote insertion occurs after CPU-intensive cryptographic operations. During this window, the election can be closed by another request, yet the vote will still be recorded. With multi-worker deployments, the window between _all_metadata(S_OPEN) and c_add_vote.perform() is widened by the CPU-intensive gen_vote_token() and create_vote() operations (key derivation with PBKDF/Argon2).

### Details
**CWE:** CWE-367  
**ASVS:** 2.3.4, 15.4.1, 15.4.2, 15.4.3 (L2, L3)

Votes can be recorded and tallied for elections that have already been officially closed. The tampered vote is cryptographically valid (uses the correct opened_key and salt), so it cannot be distinguished from a legitimate vote during tallying.

**Affected Files:**
- `v3/steve/election.py` (lines 258-269, 113-119)
- `v3/server/pages.py` (lines 403-446)
- `v3/schema.sql` (line 179)

### Remediation
Wrap the entire check-and-write in a transaction with IMMEDIATE mode to acquire a write lock before reading state:

```python
def add_vote(self, pid, iid, votestring):
    """Add vote with atomic check-and-write."""
    self.db.conn.execute('BEGIN IMMEDIATE')
    
    try:
        # Check state within transaction
        md = self._all_metadata(self.S_OPEN)
        
        # Get mayvote record
        mayvote = self.q_get_mayvote.first_row(pid, iid)
        
        # Generate vote token and encrypt
        vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
        ciphertext = crypto.create_vote(vote_token, mayvote.salt, votestring)
        
        # Insert vote
        self.c_add_vote.perform(vote_token, ciphertext)
        
        # Commit
        self.db.conn.execute('COMMIT')
    except Exception:
        self.db.conn.execute('ROLLBACK')
        raise
```

Additionally, add a database trigger as defense-in-depth to check election state from the vote table:

```sql
CREATE TRIGGER vote_state_check
BEFORE INSERT ON vote
BEGIN
    SELECT CASE
        WHEN (SELECT state FROM election WHERE eid = NEW.eid) != 'open'
        THEN RAISE(ABORT, 'Election is not open')
    END;
END;
```

### Acceptance Criteria
- [ ] Vote insertion wrapped in transaction with IMMEDIATE lock
- [ ] Database trigger added as defense-in-depth
- [ ] Test cases verify race condition is prevented
- [ ] Test cases verify votes cannot be added to closed elections

### References
- Related: FINDING-088
- Source: 2.3.4.md, 15.4.1.md, 15.4.2.md, 15.4.3.md

### Priority
**HIGH** - Race condition allows votes after election closure

---

## Issue: FINDING-026 - No Multi-User Approval for Irreversible Election State Transitions
**Labels:** bug, security, priority:high
**Description:**
### Summary
Opening and closing elections are the highest-value operations in this system. Opening an election is explicitly irreversible (generates cryptographic salt and opened_key, sets per-voter salts), and closing permanently terminates voting. Neither operation requires approval from a second authorized user. A single user (or an attacker who compromises a single committer account) can unilaterally open an election prematurely, close an election early (disenfranchising voters), or trigger tallying. The election.open() method generates cryptographic material and the state machine prevents reversal. No approval workflow exists for any election lifecycle operation.

### Details
**ASVS:** 2.3.5 (L3)

ASVS 2.3.5 specifically requires multi-user approval for high-value business logic flows to prevent unauthorized or accidental actions.

**Affected Files:**
- `v3/server/pages.py` (lines 479-515)
- `v3/steve/election.py` (lines 70-120)

### Remediation
Implement a two-phase approval workflow:

1. Add approval_request table to schema:
```sql
CREATE TABLE approval_request (
    request_id TEXT PRIMARY KEY,
    eid TEXT NOT NULL,
    action TEXT NOT NULL, -- 'open' or 'close'
    requested_by TEXT NOT NULL,
    requested_at INTEGER NOT NULL,
    approved_by TEXT,
    approved_at INTEGER,
    status TEXT NOT NULL, -- 'pending', 'approved', 'rejected'
    CHECK (requested_by != approved_by),
    FOREIGN KEY (eid) REFERENCES election(eid)
);
```

2. Create separate endpoints for requesting operations:
```python
@APP.post('/do-request-open/<eid>')
@asfquart.auth.require({R.pmc_member})
@load_election
async def request_open_endpoint(election):
    result = await basic_info()
    request_id = secrets.token_hex(16)
    
    # Create approval request
    election.db.conn.execute(
        'INSERT INTO approval_request VALUES (?, ?, ?, ?, ?, NULL, NULL, ?)',
        (request_id, election.eid, 'open', result.uid, int(time.time()), 'pending')
    )
    
    await flash_success('Open request submitted. Awaiting approval.')
    return quart.redirect(f'/manage/{election.eid}', code=303)
```

3. Create approval endpoints:
```python
@APP.post('/do-approve-open/<request_id>')
@asfquart.auth.require({R.pmc_member})
async def approve_open_endpoint(request_id):
    result = await basic_info()
    
    # Load request
    request = db.execute(
        'SELECT * FROM approval_request WHERE request_id = ?',
        (request_id,)
    ).fetchone()
    
    # Verify approver is different from requester
    if request['requested_by'] == result.uid:
        await flash_danger('Cannot approve your own request.')
        return quart.redirect('/admin', code=303)
    
    # Verify approver is authorized for the election
    election = steve.election.Election(DB_FNAME, request['eid'])
    if not check_election_authz(election, result.uid):
        quart.abort(403)
    
    # Execute the operation
    election.open(PEOPLEDB_FNAME)
    
    # Update request status
    db.execute(
        'UPDATE approval_request SET approved_by = ?, approved_at = ?, status = ? WHERE request_id = ?',
        (result.uid, int(time.time()), 'approved', request_id)
    )
    
    await flash_success('Election opened successfully.')
    return quart.redirect(f'/manage/{election.eid}', code=303)
```

4. The approval endpoint must verify the approver is different from the requester and is also authorized for the election

5. Only execute the irreversible operation after successful approval by a second authorized user

### Acceptance Criteria
- [ ] Approval request table added to schema
- [ ] Request endpoints implemented
- [ ] Approval endpoints implemented
- [ ] Two-person rule enforced (requester != approver)
- [ ] Authorization verified for both requester and approver
- [ ] Audit logging added for all approval actions
- [ ] Test cases verify two-person rule works
- [ ] Test cases verify single user cannot complete operation

### References
- Related: None (standalone approval workflow)
- Source: 2.3.5.md

### Priority
**HIGH** - Single user can perform irreversible operations

---

## Issue: FINDING-027 - No Throttling or Timing Enforcement on Vote Submission Endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
The vote submission endpoint has no rate limiting, timing checks, or cooldown periods. A compromised authenticated account or malicious insider can submit automated votes at machine speed with no human-interaction timing verification. This enables rapid vote-change cycling that could interfere with tallying if done during a race condition window, and generates excessive database write operations (one per issue per request), creating denial-of-service conditions on the SQLite database through write lock contention. An automated script could load the ballot and immediately POST votes for all issues, or repeatedly change votes hundreds of times per second.

### Details
**ASVS:** 2.4.1, 2.4.2 (L2, L3)

ASVS 2.4.2 specifically requires realistic human timing for business logic flows to prevent excessively rapid transaction submissions.

**Affected Files:**
- `v3/server/pages.py` (lines 426-470, 412-460)

### Remediation
Implement per-user rate limiting on `/do-vote/<eid>`:

```python
import time

VOTE_RATE_LIMIT = 5  # max submissions
VOTE_RATE_WINDOW = 60  # seconds
VOTE_MIN_DELAY_SECS = 3  # minimum time between page load and vote

def rate_limit_votes(func):
    """Rate limit vote submissions."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        s = await asfquart.session.read()
        now = time.time()
        
        # Initialize tracking
        if 'vote_timestamps' not in s:
            s['vote_timestamps'] = []
        
        # Remove old timestamps outside window
        s['vote_timestamps'] = [
            ts for ts in s['vote_timestamps']
            if now - ts < VOTE_RATE_WINDOW
        ]
        
        # Check rate limit
        if len(s['vote_timestamps']) >= VOTE_RATE_LIMIT:
            await flash_danger(
                f'Too many vote submissions. Please wait {VOTE_RATE_WINDOW} seconds.'
            )
            return quart.redirect(quart.request.referrer or '/voter', code=303)
        
        # Check minimum delay since ballot load
        ballot_load_time = s.get('ballot_load_time', 0)
        if now - ballot_load_time < VOTE_MIN_DELAY_SECS:
            await flash_danger('Please review your ballot before submitting.')
            return quart.redirect(quart.request.referrer or '/voter', code=303)
        
        # Record this submission
        s['vote_timestamps'].append(now)
        await asfquart.session.write(s)
        
        return await func(*args, **kwargs)
    return wrapper

@APP.post('/do-vote/<eid>')
@asfquart.auth.require({R.committer})
@load_election
@rate_limit_votes
async def do_vote_endpoint(election):
    ...
```

Add timestamp tracking on ballot load:
```python
@APP.get('/vote-on/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def vote_on_page(election):
    s = await asfquart.session.read()
    s['ballot_load_time'] = time.time()
    await asfquart.session.write(s)
    ...
```

Flash warning messages when timing requirements are not met and redirect back to the ballot page.

### Acceptance Criteria
- [ ] Rate limiting implemented with sliding window
- [ ] Minimum delay enforced between page load and submission
- [ ] Cooldown period enforced between submissions
- [ ] Clear feedback provided to users
- [ ] Test cases verify rate limiting works
- [ ] Test cases verify legitimate users are not blocked

### References
- Related: None (standalone rate limiting)
- Source: 2.4.1.md, 2.4.2.md

### Priority
**HIGH** - No protection against automated vote manipulation

---

## Issue: FINDING-028 - User-Uploaded Documents Served Without Content Interpretation Controls
**Labels:** bug, security, priority:high
**Description:**
### Summary
The serve_doc endpoint serves user-uploaded documents directly to the browser without any content interpretation controls. Files are served with inferred MIME types and no Content-Disposition: attachment header, Content-Security-Policy: sandbox directive, or X-Content-Type-Options: nosniff protection. This allows malicious HTML/SVG files to execute JavaScript in the application's origin, enabling stored XSS attacks. An attacker can upload malicious HTML files that execute in the application's origin when viewed by authenticated users, leading to session hijacking, vote manipulation, or election state changes.

### Details
**CWE:** CWE-79  
**ASVS:** 3.2.1 (L1)

**Affected Files:**
- `v3/server/pages.py` (lines 593-608, 28-35)

### Remediation
Add Content-Disposition: attachment header, Content-Security-Policy: sandbox directive, and X-Content-Type-Options: nosniff to the serve_doc endpoint:

```python
@APP.get('/docs/<iid>/<docname>')
@asfquart.auth.require({R.committer})
@load_election_issue
async def serve_doc(election, issue, docname):
    result = await basic_info()
    
    # Validate voter eligibility
    election.q_get_mayvote.perform(result.uid, issue.iid)
    if not election.q_get_mayvote.fetchone():
        quart.abort(403)
    
    # Validate docname (prevent path traversal)
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', docname):
        quart.abort(400)
    
    # Serve with security headers
    response = await quart.send_from_directory(
        DOCSDIR / issue.iid,
        docname,
        as_attachment=True  # Force download instead of inline rendering
    )
    
    # Add security headers
    response.headers['Content-Security-Policy'] = "default-src 'none'; sandbox"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response
```

Validate docname to prevent path traversal. Use Quart's as_attachment=True parameter in send_from_directory() and add security headers to the response object before returning.

### Acceptance Criteria
- [ ] Content-Disposition: attachment header added
- [ ] CSP sandbox directive added
- [ ] X-Content-Type-Options: nosniff added
- [ ] Filename validation implemented
- [ ] Test cases verify malicious HTML cannot execute
- [ ] Test cases verify files are downloaded, not rendered

### References
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-031, FINDING-091, FINDING-113, FINDING-114
- Source: 3.2.1.md

### Priority
**HIGH** - Stored XSS via uploaded documents

---

## Issue: FINDING-029 - Session Cookies Lack Secure Attribute Configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses session-based authentication via asfquart.session but does not configure the Secure attribute for session cookies. Session cookies are created through asfquart.session.read() calls across all authenticated endpoints, but no SESSION_COOKIE_SECURE = True configuration is set. Additionally, TLS is conditionally configured only when certfile is present, meaning the application can run over plain HTTP. Without the Secure attribute, session cookies would be transmitted in cleartext over unencrypted connections, allowing attackers on the same network to intercept session cookies through network sniffing or MITM attacks and impersonate authenticated users.

### Details
**ASVS:** 3.3.1 (L1)

**Affected Files:**
- `v3/server/main.py` (lines 30-44)
- `v3/server/pages.py` (line 86)
- `v3/server/main.py` (lines 77-80)

### Remediation
Set SESSION_COOKIE_SECURE = True in the create_app() function in main.py:

```python
def create_app(cfg):
    app = quart.Quart(__name__)
    app.config.from_mapping(cfg.server)
    
    # Configure session cookie security
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    
    # ... rest of initialization
    return app
```

Additionally configure SESSION_COOKIE_HTTPONLY = True and SESSION_COOKIE_SAMESITE = 'Lax' for defense in depth.

### Acceptance Criteria
- [ ] SESSION_COOKIE_SECURE set to True
- [ ] SESSION_COOKIE_HTTPONLY set to True
- [ ] SESSION_COOKIE_SAMESITE set to Lax
- [ ] Test cases verify cookie attributes are set correctly
- [ ] Test cases verify cookies are not sent over HTTP

### References
- Related: None (foundational session security)
- Source: 3.3.1.md

### Priority
**HIGH** - Session cookies can be intercepted over HTTP

---

## Issue: FINDING-030 - Session Cookie Missing Explicit SameSite Attribute Configuration
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not explicitly configure the SameSite attribute for session cookies. Session cookies are the sole authentication mechanism for the election voting system, yet no explicit security configuration is present in the application initialization code. Without explicit SameSite configuration, protection depends entirely on browser version and defaults. Combined with the placeholder CSRF token (acknowledged in TODO.md), the SameSite attribute is the only remaining browser-side defense against cross-site request forgery. Successful exploitation could allow an attacker to cast votes, create elections, open/close elections, or add/delete issues on behalf of an authenticated user.

### Details
**CWE:** CWE-352  
**ASVS:** 3.3.2 (L2)

**Affected Files:**
- `v3/server/main.py` (lines 33-49)

### Remediation
Explicitly configure session cookie security attributes in the create_app() function:

```python
def create_app(cfg):
    app = quart.Quart(__name__)
    app.config.from_mapping(cfg.server)
    
    # Configure session cookie security
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # minimum; 'Strict' if OAuth flow allows
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    
    # ... rest of initialization
    return app
```

Set SESSION_COOKIE_SAMESITE = 'Lax' as the minimum requirement. Note that SameSite=Strict would break the OAuth flow which redirects to oauth.apache.org.

### Acceptance Criteria
- [ ] SESSION_COOKIE_SAMESITE explicitly set to Lax
- [ ] SESSION_COOKIE_SECURE set to True
- [ ] SESSION_COOKIE_HTTPONLY set to True
- [ ] Test cases verify cookie attributes are set correctly
- [ ] OAuth flow tested to ensure it still works

### References
- Related: FINDING-007, FINDING-008, FINDING-009, FINDING-033, FINDING-034, FINDING-109
- Source: 3.3.2.md

### Priority
**HIGH** - Only remaining browser-side CSRF defense

---

## Issue: FINDING-031 - Stored XSS via Election/Issue Titles Rendered Without HTML Escaping
**Labels:** bug, security, priority:high
**Description:**
### Summary
Election and issue titles are rendered without HTML escaping across multiple templates in HTML body context. While the [format "js,html"] directive IS used in onclick handlers, it is NOT applied to title rendering in HTML body contexts. This creates a Type B gap where the escaping control exists and is used in some contexts but not others, creating false confidence. Any admin can inject JavaScript via election or issue titles that executes in the browsers of all users viewing election listings or management pages.

### Details
**CWE:** CWE-79  
**ASVS:** 3.2.2 (L1)

**Affected Files:**
- `v3/server/templates/admin.ezt` (line 14)
- `v3/server/templates/manage.ezt` (lines 8, 187)
- `v3/server/templates/manage-stv.ezt` (lines 6, 137)
- `v3/server/templates/vote-on.ezt` (lines 9, 49)
- `v3/server/templates/voter.ezt` (lines 33, 67)
- `v3/server/pages.py` (lines 456, 518)

### Remediation
Apply [format "html"] to ALL user-provided values in HTML body context:

```html
<!-- admin.ezt -->
<h5 class="card-title">[format "html"][owned.title][end]</h5>

<!-- manage.ezt -->
<h2>[format "html"][e_title][end]</h2>
<strong>[format "html"][issues.title][end]</strong>

<!-- manage-stv.ezt -->
<h2>[format "html"][e_title][end]</h2>
<strong>[format "html"][issues.title][end]</strong>

<!-- vote-on.ezt -->
<h2>[format "html"][election.title][end]</h2>
<strong>[format "html"][issues.title][end]</strong>

<!-- voter.ezt -->
<h5 class="card-title mb-3">[format "html"][open_elections.title][end]</h5>
<h5 class="card-title">[format "html"][upcoming_elections.title][end]</h5>
```

Apply this pattern consistently across all templates.

### Acceptance Criteria
- [ ] HTML encoding applied to all title variables in all templates
- [ ] Test cases verify XSS payloads are properly escaped
- [ ] Code review confirms consistent escaping across all templates

### References
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-091, FINDING-113, FINDING-114
- Source: 3.2.2.md

### Priority
**HIGH** - Stored XSS affecting all users viewing listings

---

## Issue: FINDING-032 - Missing Content-Security-Policy frame-ancestors Directive on All Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application completely lacks any Content-Security-Policy (CSP) response header implementation. No CSP header is defined, applied, or referenced anywhere in the codebase. All 10 HTML-serving endpoints return responses without any CSP protection, leaving the application vulnerable to cross-site scripting (XSS) attacks with unrestricted capabilities. Without CSP, any successful XSS injection would have unrestricted capability — loading external scripts, exfiltrating session data, or manipulating vote submissions.

### Details
**ASVS:** 3.4.6, 3.4.3 (L2)

The rewrite_description() function already produces raw HTML (&lt;a&gt; and &lt;pre&gt; tags) from issue data without escaping, making CSP an essential defense-in-depth layer. Missing object-src 'none' allows plugin-based attacks, and missing base-uri 'none' allows &lt;base&gt; tag injection to redirect relative URLs to attacker-controlled servers.

**Affected Files:**
- `v3/server/main.py` (lines 27-42)
- `v3/server/pages.py` (lines 119-123, 223-277, 460-477, 480-495, 682-684)

### Remediation
**Option A (L2 compliance):** Implement global CSP via after_request hook in create_app() function:

```python
@app.after_request
async def add_csp(response):
    """Add Content-Security-Policy header to all responses."""
    if response.content_type and 'text/html' in response.content_type:
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        )
    return response
```

**Option B (L3 compliance):** Implement per-response nonce-based CSP:

```python
import secrets

@app.before_request
async def generate_csp_nonce():
    """Generate unique nonce for this request."""
    quart.g.csp_nonce = secrets.token_hex(16)

@app.after_request
async def add_csp_with_nonce(response):
    """Add Content-Security-Policy header with nonce."""
    if response.content_type and 'text/html' in response.content_type:
        nonce = quart.g.get('csp_nonce', '')
        response.headers['Content-Security-Policy'] = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            f"style-src 'self' 'nonce-{nonce}'; "
            f"img-src 'self'; "
            f"font-src 'self'; "
            f"object-src 'none'; "
            f"base-uri 'none'; "
            f"form-action 'self'; "
            f"frame-ancestors 'none'"
        )
    return response
```

Update all templates to include nonce attributes:
```html
<script nonce="[csp_nonce]">...</script>
<style nonce="[csp_nonce]">...</style>
```

Also fix raise_404() function to ensure CSP headers are applied to custom error responses.

### Acceptance Criteria
- [ ] CSP header implemented via after_request hook
- [ ] All required directives included
- [ ] Templates updated if using nonce-based CSP
- [ ] Test cases verify CSP header is present
- [ ] Test cases verify inline scripts are blocked without nonce
- [ ] Custom error responses include CSP header

### References
- Related: None (foundational XSS defense)
- Source: 3.4.6.md, 3.4.3.md

### Priority
**HIGH** - No CSP defense against XSS attacks

---

## Issue: FINDING-033 - Vote Submission Endpoint Lacks CSRF Protection, Enabling Vote Manipulation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The vote submission endpoint processes votes without validating the CSRF token, despite the token being present in the form. The /do-vote/&lt;eid&gt; endpoint parses form data and calls election.add_vote() to record or overwrite votes without any origin verification. This allows attackers to cast or modify votes on behalf of authenticated users through cross-site form submissions, undermining election integrity.

### Details
**CWE:** CWE-352  
**ASVS:** 3.5.1 (L1)

**Affected Files:**
- `v3/server/pages.py` (line 438)
- `v3/server/templates/vote-on.ezt`

### Remediation
Add CSRF token validation as the first operation in do_vote_endpoint() before any form processing or vote recording occurs:

```python
@APP.post('/do-vote/<eid>')
@asfquart.auth.require({R.committer})
@load_election
async def do_vote_endpoint(election):
    result = await basic_info()
    
    # Validate CSRF token FIRST
    await validate_csrf_token()
    
    form = edict(await quart.request.form)
    ...
```

Call await validate_csrf_token() immediately after the result = await basic_info() line. This will ensure that votes can only be submitted from legitimate forms originating from the application itself, preventing cross-site vote manipulation attacks.

### Acceptance Criteria
- [ ] CSRF token validation added to vote endpoint
- [ ] Validation occurs before any form processing
- [ ] Test cases verify invalid tokens are rejected
- [ ] Test cases verify cross-site submissions fail
- [ ] Test cases verify legitimate submissions still work

### References
- Related: FINDING-007, FINDING-008, FINDING-009, FINDING-030, FINDING-034, FINDING-109
- Source: 3.5.1.md

### Priority
**HIGH** - Vote manipulation via CSRF

---

## Issue: FINDING-034 - POST Endpoints Accept CORS-Safelisted Content Types Without Cross-Origin Verification
**Labels:** bug, security, priority:high
**Description:**
### Summary
All state-changing POST endpoints accept 'application/x-www-form-urlencoded' content type, which is a CORS-safelisted content type. Requests using this content type do not trigger CORS preflight checks, allowing cross-origin form submissions with credentials. No Origin header validation, Content-Type enforcement, custom header requirements, or CSRF token validation exists on any of these endpoints. An attacker can host a malicious page with HTML forms that auto-submit to these endpoints, performing unauthorized actions including vote manipulation, election creation, and issue tampering.

### Details
**CWE:** CWE-352  
**ASVS:** 3.5.2, 3.5.4 (L1, L2)

If session cookies lack SameSite=Lax or SameSite=Strict, all state-changing operations are vulnerable to cross-origin form submission.

**Affected Files:**
- `v3/server/pages.py` (lines 380-423, 425-446, 490-514, 516-538, 540-558, 410, 457, 515, 538, 559, 93)

### Remediation
Implement one or more of the following cross-origin protections:

**Option A:** Enforce 'application/json' Content-Type to force CORS preflight for cross-origin requests

**Option B (Recommended):** Require a custom header (e.g., 'X-Requested-With') that forces CORS preflight:

```python
async def require_custom_header(func):
    """Require custom header to prevent simple CORS requests."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        if not quart.request.headers.get('X-Requested-With'):
            quart.abort(403, 'Missing required header')
        return await func(*args, **kwargs)
    return wrapper

@APP.post('/do-vote/<eid>')
@asfquart.auth.require({R.committer})
@load_election
@require_custom_header
async def do_vote_endpoint(election):
    ...
```

**Option C:** Validate Origin header against an allowlist on all state-changing requests:

```python
async def validate_origin():
    """Validate Origin header matches expected values."""
    origin = quart.request.headers.get('Origin')
    if origin and not origin.startswith('https://vote.apache.org'):
        quart.abort(403, 'Invalid origin')
```

Generate real CSRF tokens per session using cryptographically secure random values instead of static 'placeholder'. Create a validation decorator (require_csrf) that checks form data or headers against session token. Apply decorator to all POST endpoints. Explicitly set SameSite=Lax and Secure attributes on session cookies via app.config.

### Acceptance Criteria
- [ ] Custom header requirement implemented OR
- [ ] Origin validation implemented OR
- [ ] Content-Type enforcement implemented
- [ ] Real CSRF tokens generated and validated
- [ ] SameSite and Secure attributes set on cookies
- [ ] Test cases verify cross-origin requests are blocked
- [ ] Test cases verify legitimate requests still work

### References
- Related: FINDING-007, FINDING-008, FINDING-009, FINDING-030, FINDING-033, FINDING-109
- Source: 3.5.2.md, 3.5.4.md

### Priority
**HIGH** - All POST endpoints vulnerable to cross-origin attacks

---

## Issue: FINDING-035 - Cross-Origin Resource Loading of Authenticated Documents Without Sec-Fetch-* Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serves authenticated documents (images, scripts, PDFs, and other files associated with election issues) without setting a Cross-Origin-Resource-Policy response header and without validating Sec-Fetch-* request headers. This allows a malicious cross-origin page to embed or load these authenticated resources on behalf of a logged-in user. Authenticated election documents can be loaded by cross-origin pages when the user has an active session. Attackers can confirm existence of specific documents and issues. Image content is directly rendered; document metadata leaks via timing/size. Election-sensitive material (candidate information, ballot details referenced via doc:filename in issue descriptions) exposed.

### Details
**ASVS:** 3.5.8 (L3)

**Affected Files:**
- `v3/server/pages.py` (lines 587-603)

### Remediation
Validate Sec-Fetch-* headers to ensure same-origin navigation:

```python
@APP.get('/docs/<iid>/<docname>')
@asfquart.auth.require({R.committer})
@load_election_issue
async def serve_doc(election, issue, docname):
    result = await basic_info()
    
    # Validate Sec-Fetch-* headers
    fetch_site = quart.request.headers.get('Sec-Fetch-Site', '')
    fetch_dest = quart.request.headers.get('Sec-Fetch-Dest', '')
    
    # Only allow same-origin or same-site requests
    if fetch_site not in ('same-origin', 'same-site', 'none', ''):
        quart.abort(403, 'Cross-origin document access forbidden')
    
    # Only allow document/image/empty destinations
    if fetch_dest and fetch_dest not in ('document', 'image', 'empty', ''):
        quart.abort(403, 'Invalid fetch destination')
    
    # Validate voter eligibility
    election.q_get_mayvote.perform(result.uid, issue.iid)
    if not election.q_get_mayvote.fetchone():
        quart.abort(403)
    
    # Serve with security headers
    response = await quart.send_from_directory(
        DOCSDIR / issue.iid,
        docname,
        as_attachment=True
    )
    
    # Set Cross-Origin-Resource-Policy header
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    return response
```

Only allow same-origin or same-site requests by checking Sec-Fetch-Site header. Only allow document/image/empty destinations by validating Sec-Fetch-Dest header. Set Cross-Origin-Resource-Policy: same-origin header on all document responses.

### Acceptance Criteria
- [ ] Sec-Fetch-Site validation implemented
- [ ] Sec-Fetch-Dest validation implemented
- [ ] Cross-Origin-Resource-Policy header set
- [ ] Test cases verify cross-origin requests are blocked
- [ ] Test cases verify same-origin requests still work

### References
- Related: None (standalone cross-origin protection)
- Source: 3.5.8.md

### Priority
**HIGH** - Authenticated documents accessible cross-origin

---

## Issue: FINDING-036 - State-Changing GET Endpoints Vulnerable to Cross-Origin Resource Embedding
**Labels:** bug, security, priority:high
**Description:**
### Summary
The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints perform irreversible state-changing operations (opening and closing elections) via GET requests. Combined with the complete absence of Sec-Fetch-* header validation, these endpoints can be triggered by a cross-origin page embedding the URL as a resource (e.g., &lt;img&gt;, &lt;link&gt;, &lt;script&gt;). This is distinct from general CSRF because the attack vector is specifically through cross-origin resource loading. An attacker can force-open elections prematurely (before proper voter rolls, issues, or dates are finalized) or force-close open elections, permanently ending voting. Both operations are explicitly irreversible.

### Details
**ASVS:** 3.5.8 (L3)

The open() operation triggers salt generation and key derivation; close() permanently marks the election closed.

**Affected Files:**
- `v3/server/pages.py` (lines 462, 481)
- `v3/server/templates/manage.ezt` (lines 277, 285)

### Remediation
Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods. Implement Sec-Fetch-* header validation to reject requests where Sec-Fetch-Dest is 'image'/'script'/'style', Sec-Fetch-Site is 'cross-site', or Sec-Fetch-Mode is 'no-cors':

```python
async def validate_sec_fetch():
    """Validate Sec-Fetch-* headers for state-changing operations."""
    fetch_dest = quart.request.headers.get('Sec-Fetch-Dest', '')
    fetch_site = quart.request.headers.get('Sec-Fetch-Site', '')
    fetch_mode = quart.request.headers.get('Sec-Fetch-Mode', '')
    
    # Reject resource embedding attempts
    if fetch_dest in ('image', 'script', 'style'):
        quart.abort(403, 'Resource embedding forbidden')
    
    # Reject cross-site requests
    if fetch_site == 'cross-site':
        quart.abort(403, 'Cross-site requests forbidden')
    
    # Reject no-cors mode
    if fetch_mode == 'no-cors':
        quart.abort(403, 'No-CORS mode forbidden')

@APP.post('/do-open/<eid>')
@asfquart.auth.require({R.pmc_member})
@load_election
async def do_open_endpoint(election):
    await validate_sec_fetch()
    ...
```

Update the JavaScript in manage.ezt template to use fetch() with POST method instead of window.location.href for state-changing operations.

### Acceptance Criteria
- [ ] Endpoints converted to POST method
- [ ] Sec-Fetch-* validation implemented
- [ ] JavaScript updated to use POST
- [ ] Test cases verify resource embedding is blocked
- [ ] Test cases verify legitimate requests still work

### References
- Related: None (standalone cross-origin protection)
- Source: 3.5.8.md

### Priority
**HIGH** - Irreversible operations triggerable via resource embedding

---

## Issue: FINDING-037 - No Per-Message Digital Signatures on Vote Submission
**Labels:** bug, security, priority:high
**Description:**
### Summary
Vote submission, the most sensitive operation in an election system, lacks per-message digital signatures. The endpoint relies solely on session cookie authentication over TLS, with no cryptographic binding between the authenticated voter identity and the vote payload at the application layer. This creates risks of intermediary tampering, lack of non-repudiation, replay attacks without detection, and no voter-verifiable receipt. The system fails ASVS 4.1.5 requirement for additional assurance beyond transport protection.

### Details
**ASVS:** 4.1.5 (L3)

**Affected Files:**
- `v3/server/pages.py` (lines 422-469)
- `v3/steve/election.py` (lines 229-240)
- `v3/steve/crypto.py` (lines 67-72, 44-54)

### Remediation
Implement client-side signing of vote payloads using Web Crypto API with Ed25519 or ECDSA. Server-side should verify per-message signatures before processing votes.

Example implementation:
1. Generate/retrieve voter's key pair at enrollment
2. Create canonical JSON vote payload
3. Sign payload with private key
4. Submit signed vote with signature
5. Server verifies signature against registered public key before processing

Alternatively, implement JWS (JSON Web Signatures) for vote payloads. Add voter key registration flow, nonce/timestamp validation for replay protection, and return signed vote receipts to voters.

### Acceptance Criteria
- [ ] Client-side signing implemented using Web Crypto API
- [ ] Server-side signature verification implemented
- [ ] Voter key registration flow added
- [ ] Nonce/timestamp validation for replay protection
- [ ] Signed vote receipts returned to voters
- [ ] Test cases verify signature validation works
- [ ] Test cases verify invalid signatures are rejected

### References
- Related: None (additional assurance layer)
- Source: 4.1.5.md

### Priority
**HIGH** - No cryptographic binding between voter and vote

---

## Issue: FINDING-038 - Document Serving Endpoint Lacks Comprehensive Filename Validation and Safe-Download Controls
**Labels:** bug, security, priority:high
**Description:**
### Summary
The serve_doc() function serves arbitrary files from the DOCSDIR / iid directory without any filename validation, extension allowlisting, Content-Type enforcement, or safe-download headers. The developers explicitly acknowledged this gap with a TODO comment ('verify the propriety of DOCNAME') but never implemented the control. This is a Type B gap: the need for a security control was identified, but the control was never implemented, creating false confidence that the issue is tracked. The file is served directly via send_from_directory without validation.

### Details
**CWE:** CWE-434  
**ASVS:** 5.1.1, 5.2.2, 5.3.1, 5.4.1, 2.1.3 (L1, L2)

Multiple security issues exist:
1. No file extension whitelist - any file type present in the directory can be served
2. No filename character validation - special characters in filenames are not filtered
3. No Content-Disposition: attachment header - browsers will attempt inline rendering
4. No Content-Type enforcement - files are served with their native MIME types
5. No X-Content-Type-Options: nosniff header

If a malicious file like evil.html containing JavaScript exists in DOCSDIR/&lt;valid-iid&gt;/, it would be served with a text/html Content-Type and rendered inline, executing any embedded JavaScript in the user's browser context (stored XSS). Similarly, executable files could be distributed as malware. Files with server-executable extensions (.py, .php, .jsp) would be served as-is, and HTML/SVG files would execute in the application's origin with full access to cookies, session, and DOM.

**Affected Files:**
- `v3/server/pages.py` (lines 576-580, 594-609, 428-441, 602-618, 47)

### Remediation
Implement comprehensive validation:

```python
import re
import mimetypes

ALLOWED_DOC_EXTENSIONS = {'.pdf', '.txt', '.md', '.png', '.jpg', '.jpeg', '.gif'}
SAFE_CONTENT_TYPES = {
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.md': 'text/plain',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
}

@APP.get('/docs/<iid>/<docname>')
@asfquart.auth.require({R.committer})
@load_election_issue
async def serve_doc(election, issue, docname):
    result = await basic_info()
    
    # (1) Validate filename format
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', docname):
        _LOGGER.warning(f'Invalid docname format: user={result.uid} docname={docname}')
        quart.abort(403, 'Invalid filename format')
    
    # (2) Validate extension
    _, ext = os.path.splitext(docname.lower())
    if ext not in ALLOWED_DOC_EXTENSIONS:
        _LOGGER.warning(f'Disallowed extension: user={result.uid} docname={docname}')
        quart.abort(403, 'File type not allowed')
    
    # (3) Validate voter eligibility
    election.q_get_mayvote.perform(result.uid, issue.iid)
    if not election.q_get_mayvote.fetchone():
        quart.abort(403)
    
    # (4) Serve with explicit Content-Type and security headers
    response = await quart.send_from_directory(
        DOCSDIR / issue.iid,
        docname,
        as_attachment=True,  # Force download
        mimetype=SAFE_CONTENT_TYPES.get(ext, 'application/octet-stream')
    )
    
    # (5) Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    
    return response
```

For full ASVS 5.2.2 compliance, add content validation using magic byte validation with libraries like python-magic to verify file content matches its extension before accepting.

### Acceptance Criteria
- [ ] Filename format validation implemented
- [ ] Extension allowlist enforced
- [ ] Content-Disposition: attachment header added
- [ ] Explicit Content-Type set from safe mapping
- [ ] X-Content-Type-Options: nosniff added
- [ ] CSP header added for defense-in-depth
- [ ] Validation failures logged with user ID
- [ ] Test cases verify malicious files are rejected
- [ ] Test cases verify allowed files are served correctly

### References
- Related: None (standalone file serving security)
- Source: 5.1.1.md, 5.2.2.md, 5.3.1.md, 5.4.1.md, 2.1.3.md

### Priority
**HIGH** - Arbitrary file serving without validation

---

## Issue: FINDING-039 - User-Controlled `iid` Used in Directory Path Construction Without Path Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `iid` URL parameter is directly concatenated into a filesystem directory path without explicit validation: `DOCSDIR / iid`. Quart's `send_from_directory(directory, filename)` uses Werkzeug's `safe_join` to protect the filename parameter against traversal, but the directory parameter is trusted and not validated. This means if `iid` contains `..`, the base directory escapes `DOCSDIR`. Current protection relies on an incidental database authorization check (q_get_mayvote.first_row) that returns no row for malformed IIDs, but this is not a path validation control. The developer explicitly acknowledged the gap with a TODO comment: `### verify the propriety of DOCNAME.` This represents a Type B gap where the control is acknowledged as needed but not implemented.

### Details
**CWE:** CWE-22  
**ASVS:** 5.3.2 (L1)

If authorization logic changes or is bypassed, path traversal becomes directly exploitable, potentially exposing configuration files, templates, source code, or database files.

**Affected Files:**
- `v3/server/pages.py` (lines 585-600, 600, 597)

### Remediation
Add explicit path validation for both `iid` and `docname` before any filesystem operations:

```python
import re
from pathlib import Path

SAFE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
SAFE_DOCNAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$')

@APP.get('/docs/<iid>/<docname>')
@asfquart.auth.require({R.committer})
@load_election_issue
async def serve_doc(election, issue, docname):
    result = await basic_info()
    
    # (1) Validate iid format
    if not SAFE_ID_PATTERN.match(issue.iid):
        quart.abort(404)
    
    # (2) Validate docname format
    if not SAFE_DOCNAME_PATTERN.match(docname):
        quart.abort(404)
    
    # (3) Defense-in-depth: verify resolved path is within DOCSDIR
    doc_dir = (DOCSDIR / issue.iid).resolve()
    if not str(doc_dir).startswith(str(DOCSDIR.resolve())):
        _LOGGER.error(f'Path traversal attempt: iid={issue.iid} docname={docname}')
        quart.abort(404)
    
    # (4) Validate voter eligibility
    election.q_get_mayvote.perform(result.uid, issue.iid)
    if not election.q_get_mayvote.fetchone():
        quart.abort(403)
    
    # (5) Serve file
    response = await quart.send_from_directory(
        doc_dir,
        docname,
        as_attachment=True
    )
    
    return response
```

Perform validation before any filesystem operations or database queries. Return 404 for any validation failures.

### Acceptance Criteria
- [ ] iid format validation implemented
- [ ] docname format validation implemented
- [ ] Path containment verification added
- [ ] Validation occurs before filesystem operations
- [ ] Test cases verify path traversal is prevented
- [ ] Test cases verify legitimate paths still work

### References
- Related: FINDING-101
- Source: 5.3.2.md

### Priority
**HIGH** - Path traversal vulnerability if authorization bypassed

---

## Issue: FINDING-040 - No Brute-Force or Credential Stuffing Protection on Authentication Flow
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application delegates credential verification to ASF OAuth (oauth.apache.org) but implements zero local controls against authentication abuse at the application boundary. Specifically: (1) No rate limiting on OAuth flow initiation - attackers can repeatedly trigger OAuth redirect flow without throttling, enabling automated credential stuffing attempts through the application as a proxy. (2) No monitoring of failed authentication callbacks when OAuth returns failures or attackers replay/forge callback attempts. (3) No documentation of brute-force mitigation strategy in security documentation. (4) No session creation throttling after OAuth callback, enabling rapid session enumeration or replay attempts.

### Details
**ASVS:** 6.3.1 (L1)

The application treats the external OAuth provider as a complete solution but implements no defense-in-depth at its own boundary, violating NIST SP 800-63B § 5.2.2 requirements for rate limiting regardless of where credential verification occurs.

**Affected Files:**
- `v3/server/main.py` (lines 36-44)
- `v3/server/pages.py` (entire file - all @asfquart.auth.require decorated endpoints)

### Remediation
Implement rate limiting middleware at the application level using quart_rate_limiter:

```python
from quart_rate_limiter import RateLimiter, rate_limit

# In create_app():
rate_limiter = RateLimiter(app)

# Global rate limit
@app.before_request
@rate_limit(300, timedelta(minutes=1))  # 300 req/min per IP
async def global_rate_limit():
    pass

# Specific OAuth callback rate limit
@APP.get('/oauth-callback')
@rate_limit(10, timedelta(minutes=1))  # 10 attempts per minute per IP
async def oauth_callback():
    ...
```

Implement failed authentication attempt logging with monitoring:

```python
@app.after_request
async def log_auth_failures(response):
    if response.status_code == 401:
        _LOGGER.warning(
            f'AUTH_FAILURE: ip={quart.request.remote_addr} '
            f'path={quart.request.path}'
        )
        
        # Increment counter for this IP
        # Block IP after threshold (e.g., 10 failures in 5 minutes)
    
    return response
```

Add session creation throttling after OAuth callback. Document brute-force prevention strategy in security documentation including responsibility delegation to OAuth provider with verification requirements.

### Acceptance Criteria
- [ ] Rate limiting middleware implemented
- [ ] Global rate limits configured
- [ ] OAuth callback specific limits configured
- [ ] Failed authentication logging implemented
- [ ] IP blocking after threshold implemented
- [ ] Session creation throttling added
- [ ] Security documentation updated
- [ ] Test cases verify rate limiting works

### References
- Related: None (foundational authentication security)
- Source: 6.3.1.md

### Priority
**HIGH** - No protection against authentication abuse

## Issue: FINDING-041 - No Session Inactivity Timeout or Absolute Maximum Session Lifetime Implemented
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application reads sessions from the federated SSO provider but implements no controls to coordinate session lifetimes. Sessions are validated only as binary (exists or not) with no checks for age, expiry, or freshness, allowing long-lived tokens to be honored indefinitely and abandoned sessions to remain valid.

### Details
- `basic_info()` performs only binary session existence checks without validating session age, expiry, or freshness
- No idle timeout mechanism - abandoned sessions remain valid indefinitely
- No integration point to invalidate application-side sessions when SSO provider credentials change
- No mechanism to track IdP authentication event timing or enforce maximum session lifetime
- No storage of session lifecycle timestamps (`created_at`, `last_activity`, `auth_time`)
- Violates ASVS 7.1.1, 7.1.3, 7.3.1, 7.3.2, 7.6.1 (L2)

**Affected files:**
- `v3/server/pages.py:44-71, 62-88`
- `v3/server/main.py:33-46`

### Remediation
1. Store session lifecycle timestamps in session data: `created_at`, `last_activity`, `auth_time`
2. Validate session freshness in `basic_info()` against:
   - `SESSION_MAX_AGE` (1 hour absolute)
   - `SESSION_IDLE_TIMEOUT` (30 minutes)
3. Destroy stale sessions immediately using `await asfquart.session.destroy()`
4. Update `last_activity` on each request
5. Create session management documentation covering SSO provider integration, lifetime policy, idle timeout configuration, termination coordination, and re-authentication conditions
6. Implement backchannel logout handler to process IdP-initiated session termination

### Acceptance Criteria
- [ ] Session timestamps stored and validated
- [ ] Idle timeout enforced (30 min)
- [ ] Absolute timeout enforced (1 hour)
- [ ] Stale sessions destroyed automatically
- [ ] Session management documentation created
- [ ] Tests added for timeout enforcement

### References
- CWE: Not specified
- ASVS: 7.1.1, 7.1.3, 7.3.1, 7.3.2, 7.6.1

### Priority
High

---

## Issue: FINDING-042 - No Session Logout/Termination Endpoint Exists
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application configures itself as an OIDC/OAuth Relying Party but implements zero logout functionality - no `/logout` endpoint, no session destruction mechanism, no front-channel or back-channel logout handlers.

### Details
- No `/logout` endpoint exists
- No RP-Initiated Logout per OIDC RP-Initiated Logout 1.0
- No back-channel logout handler to process OP-initiated logout notifications
- Sessions persist until natural expiry with no user-initiated termination
- Attack scenario: User A authenticates and votes, User B accesses same browser and uses valid session cookie to cast votes as User A
- Violates ASVS 7.1.3, 7.2.4, 7.3.1, 7.4.1, 7.6.1, 10.6.2 (L1/L2/L3)
- CWE-613: Insufficient Session Expiration

**Affected files:**
- `v3/server/pages.py` (entire file)

### Remediation
1. **Add RP-Initiated Logout Endpoint:**
   - Create `/logout` route that reads `id_token_hint` from session
   - Destroy RP-side session using `asfquart.session.clear()`
   - Redirect to OP logout endpoint with `id_token_hint` and `post_logout_redirect_uri`

2. **Implement Back-Channel Logout Handler:**
   - Create `POST /backchannel-logout` endpoint
   - Validate logout token (JWT signed by OP)
   - Verify signature, `iss`, `aud`, and `events` claim
   - Invalidate session(s) for the subject

3. **Configure Logout URL in main.py:**
   - Add `OAUTH_URL_LOGOUT` configuration with proper parameters

4. **Register Logout URIs with OP:**
   - Register `https://steve.apache.org/backchannel-logout` as back-channel logout URI
   - Register `https://steve.apache.org/` as allowed post-logout redirect URI

5. **Add logout link to UI** on all authenticated pages

### Acceptance Criteria
- [ ] `/logout` endpoint implemented
- [ ] Back-channel logout handler implemented
- [ ] Logout URLs configured and registered with OP
- [ ] Logout link added to UI
- [ ] Tests added for logout flows

### References
- CWE-613: Insufficient Session Expiration
- ASVS: 7.1.3, 7.2.4, 7.3.1, 7.4.1, 7.6.1, 10.6.2
- Related: FINDING-047

### Priority
High

---

## Issue: FINDING-043 - No Session Regeneration on Authentication or Re-authentication
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application never explicitly regenerates or rotates session tokens upon successful authentication, creating a session fixation vulnerability where attackers could set a victim's session ID before authentication and hijack the authenticated session.

### Details
- No session regeneration logic anywhere in codebase
- Sessions are only READ, never regenerated
- No calls to `session.write`, `session.create`, `session.regenerate`, `session.new`, `session.rotate`, `session.clear`, or `session.destroy`
- Authentication delegated to asfquart without explicit regeneration
- Violates ASVS 7.2.4 (L1) requirement for session token regeneration on authentication
- CWE-384: Session Fixation

**Affected files:**
- `v3/server/pages.py:78-90`
- `v3/server/main.py:38-42`

### Remediation
Add explicit session regeneration in the authentication callback:
1. Terminate old session using `await asfquart.session.destroy()`
2. Create new session with new token using `await asfquart.session.create()` with user data (`uid`, `fullname`, `email`)
3. Store `auth_time` timestamp for session lifetime validation
4. If asfquart does not expose session regeneration APIs, raise as framework requirement

### Acceptance Criteria
- [ ] Session regenerated on authentication
- [ ] Old session terminated
- [ ] New session created with fresh token
- [ ] `auth_time` stored
- [ ] Tests added for session regeneration

### References
- CWE-384: Session Fixation
- ASVS: 7.2.4

### Priority
High

---

## Issue: FINDING-044 - No Re-authentication Required Before Critical Operations
**Labels:** bug, security, priority:high
**Description:**
### Summary
Critical operations (casting votes, opening/closing elections, election administration) do not require re-authentication. Stale or compromised sessions can perform all critical operations without proving user presence, significantly increasing session hijacking attack windows.

### Details
- No re-authentication before: vote submission, election open/close, election administration
- Sessions with arbitrarily old IdP authentication can still perform critical operations
- Combined with no session timeout enforcement and no IdP auth timestamp tracking
- Violates ASVS 7.1.3, 7.2.4, 7.5.3, 7.6.1 (L2/L3)
- CWE-306: Missing Authentication for Critical Function

**Affected files:**
- `v3/server/pages.py:372-413, 436, 455, 466-468, 539-561, 416, 472, 497`

### Remediation
1. Store `auth_time` in session during IdP authentication callback
2. Create `require_recent_auth(max_age_seconds)` function that:
   - Validates authentication recency
   - Redirects to re-authentication if stale
3. Apply to critical endpoints with thresholds:
   - Vote submission: 600 seconds (10 minutes)
   - Election open/close: 300 seconds (5 minutes)
   - Election administration: 900 seconds (15 minutes)
4. Use OAuth `prompt=login` or `max_age` parameter to force IdP re-authentication
5. Regenerate session token after successful re-authentication per ASVS 7.2.4

### Acceptance Criteria
- [ ] `auth_time` stored in session
- [ ] `require_recent_auth()` function implemented
- [ ] Applied to vote submission endpoints
- [ ] Applied to election open/close endpoints
- [ ] Applied to admin endpoints
- [ ] Session regenerated after re-auth
- [ ] Tests added for re-authentication requirements

### References
- CWE-306: Missing Authentication for Critical Function
- ASVS: 7.1.3, 7.2.4, 7.5.3, 7.6.1
- Related: FINDING-163

### Priority
High

---

## Issue: FINDING-045 - No Session Termination When User Account Is Deleted or Disabled
**Labels:** bug, security, priority:high
**Description:**
### Summary
When user accounts are deleted via `PersonDB.delete_person()`, active sessions remain valid, allowing deleted users to continue accessing the application until natural session expiry. No disable/deactivate mechanism exists.

### Details
- `delete_person()` removes user record but does not modify session store
- `basic_info()` reads uid from session without verifying user still exists
- No `disable_person()` or `deactivate_person()` method
- No `is_active` field in person schema
- No mechanism to temporarily revoke access
- Violates ASVS 7.4.2 (L1)
- Affects all 16+ authenticated endpoints including vote casting and election management

**Affected files:**
- `v3/steve/persondb.py:51-61, 28-73`
- `v3/server/pages.py:78-92`

### Remediation
1. Add `is_active` field to person schema: `ALTER TABLE person ADD COLUMN is_active INTEGER DEFAULT 1`
2. Implement `disable_person(pid)` method that:
   - Sets `is_active = 0`
   - Calls `session_manager.revoke_all_sessions_for_user(pid)`
3. Modify `delete_person()` to:
   - Accept `session_manager` parameter
   - Call `session_manager.revoke_all_sessions_for_user(pid)` after deletion
4. Implement `SessionManager` class with `revoke_all_sessions_for_user()` method
5. Modify `basic_info()` to:
   - Verify user still exists by calling `pdb.get_person(s['uid'])`
   - Check `is_active` flag
   - Destroy session immediately if user not found or disabled

### Acceptance Criteria
- [ ] `is_active` field added to schema
- [ ] `disable_person()` method implemented
- [ ] `delete_person()` terminates sessions
- [ ] `SessionManager` class implemented
- [ ] `basic_info()` validates user existence and status
- [ ] Tests added for session termination on deletion/disable

### References
- CWE: Not specified
- ASVS: 7.4.2

### Priority
High

---

## Issue: FINDING-046 - No Mechanism to Terminate Sessions After Authentication Factor Changes
**Labels:** bug, security, priority:high
**Description:**
### Summary
No functionality exists to terminate active sessions after authentication factor changes. Since authentication is delegated to external SSO but the application maintains independent sessions, there's no integration to invalidate application-side sessions when SSO credentials change.

### Details
- No integration point with SSO provider for credential change notifications
- No 'Terminate All Sessions' endpoint
- No session management UI
- No backchannel logout handler
- Users cannot view or terminate their active sessions
- Compromised sessions persist even after user changes credentials at SSO provider
- Violates ASVS 7.4.3 (L2)

**Affected files:**
- `v3/server/pages.py:63-76, 506-520, 514-520`

### Remediation
1. Implement 'Terminate All Sessions' endpoint that:
   - Allows users to invalidate all other active sessions except current one
2. Integrate with SSO backchannel logout (if supported):
   - Handle SSO provider notifications of credential changes
3. Add session management UI to `/settings` page:
   - Display active sessions (device info, IP, last activity)
   - Allow users to terminate individual sessions
4. Extend session store to support:
   - `terminate_all_for_user()` method
   - `list_for_user()` method
5. Implement comprehensive session lifecycle management including timeout, renewal, and monitoring

### Acceptance Criteria
- [ ] 'Terminate All Sessions' endpoint implemented
- [ ] Backchannel logout integration added
- [ ] Session management UI added to settings page
- [ ] Session store extended with bulk operations
- [ ] Tests added for session termination after credential changes

### References
- CWE: Not specified
- ASVS: 7.4.3

### Priority
High

---

## Issue: FINDING-047 - No Administrator Capability to Terminate User Sessions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application provides no mechanism for administrators to terminate active sessions for individual users or all users. Session management is entirely delegated to asfquart with no application-level override capability.

### Details
- No session table exists in database for server-side session invalidation
- No mechanism to view active sessions
- No mechanism to terminate specific user session
- No mechanism to terminate all sessions
- No CLI tools for session management
- Under compromise, fraudulent votes could continue during active attack
- Violates ASVS 7.4.5 (L2)
- CWE-613: Insufficient Session Expiration

**Affected files:**
- `v3/server/pages.py` (all routes)
- `v3/schema.sql` (all tables)
- `v3/queries.yaml` (all queries)

### Remediation
1. **Add session storage table** in `v3/schema.sql`:
   - `session_id` (PK)
   - `pid` (FK to person)
   - `created_at`, `last_activity`, `expires_at`
   - `is_active`, `ip_address`, `user_agent`

2. **Add session management queries** in `v3/queries.yaml`:
   - `q_active_sessions`, `q_user_sessions`
   - `c_terminate_user_sessions`, `c_terminate_session`, `c_terminate_all_sessions`

3. **Add admin session management endpoints:**
   - `GET /admin/sessions` - list all active sessions
   - `POST /admin/sessions/terminate/<pid>` - terminate user sessions
   - `POST /admin/sessions/terminate-all` - emergency termination
   - `POST /admin/sessions/terminate-session/<session_id>` - specific session

4. **Implement session validation middleware:**
   - Use `@APP.before_request` to check `is_active` status
   - Raise `ServiceUnavailable` for inactive sessions

5. **Create admin template** displaying active sessions with termination actions

6. **Add comprehensive audit logging** for all session termination actions

7. **Define dedicated `R.admin` role** for session management operations

### Acceptance Criteria
- [ ] Session storage table created
- [ ] Session management queries added
- [ ] Admin endpoints implemented
- [ ] Session validation middleware added
- [ ] Admin UI template created
- [ ] Audit logging implemented
- [ ] Admin role defined
- [ ] Tests added for admin session management

### References
- CWE-613: Insufficient Session Expiration
- ASVS: 7.4.5
- Related: FINDING-042

### Priority
High

---

## Issue: FINDING-048 - Complete Absence of Active Session Viewing and Termination Capability for Users
**Labels:** bug, security, priority:high
**Description:**
### Summary
Users cannot view their active sessions or terminate them. Neither `/profile` nor `/settings` pages provide session management functionality, preventing users from discovering or revoking compromised sessions.

### Details
- No endpoint for listing user's active sessions
- No capability to terminate specific session by ID
- No capability to terminate all sessions except current
- No capability to log out from current session
- Users cannot see: device information, IP addresses, last activity times, creation timestamps
- If session token stolen, user has no mechanism to discover or revoke it
- Violates ASVS 7.5.2 (L2)

**Affected files:**
- `v3/server/pages.py:537-549, 68-78`

### Remediation
1. **Add session listing endpoint** `/sessions`:
   - Show all active sessions for authenticated user
   - Include metadata: `session_id`, `created_at`, `last_active`, `ip_address`, `user_agent`, `is_current`

2. **Implement session termination endpoints:**
   - `POST /sessions/terminate/<session_id>` - terminate specific session
   - `POST /sessions/terminate-all` - terminate all except current

3. **Implement re-authentication flow:**
   - Create `verify_reauthentication()` function (verify password or check recent auth within 5 min)
   - Create `require_recent_auth()` decorator
   - Apply to all session management endpoints

4. **Implement server-side session store** that tracks sessions per user

5. **Add session management UI** to `/settings` page with list and termination controls

### Acceptance Criteria
- [ ] `/sessions` endpoint implemented
- [ ] Session termination endpoints implemented
- [ ] Re-authentication flow implemented
- [ ] Server-side session store implemented
- [ ] Session management UI added to settings
- [ ] Tests added for session viewing and termination

### References
- CWE: Not specified
- ASVS: 7.5.2

### Priority
High

---

## Issue: FINDING-049 - Missing Explicit Voter Eligibility Check on Vote Submission Endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
The vote submission endpoint (`do_vote_endpoint`) does not perform explicit voter eligibility checks before processing votes. It relies on implicit exception handling when accessing `.salt` on a None mayvote record, masking authorization failures as generic errors.

### Details
- Vote viewing page correctly checks eligibility using `q_find_issues`
- Vote submission relies on implicit `AttributeError` when `mayvote` is None
- Generic exception handler masks authorization failures
- No audit trail for unauthorized vote attempts
- Attackers can probe election structure by observing error vs. success responses
- Violates ASVS 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.2, 8.3.3, 8.4.1 (L1/L2/L3)
- CWE-862: Missing Authorization

**Affected files:**
- `v3/server/pages.py:285-307, 257, 376, 308, 324, 389-419, 390-427`
- `v3/steve/election.py:201-207, 229, 254-268`

### Remediation
1. Add explicit voter eligibility check in `do_vote_endpoint` before processing votes
2. Verify user has `mayvote` entries for the election using `q_find_issues`
3. Check each submitted issue ID against eligible_issues set
4. Return proper 403 Forbidden responses with clear error messages for ineligible voters
5. Add explicit None check in `add_vote()` method with descriptive `VoterNotEligible` exception
6. Include security logging for all unauthorized vote attempts with:
   - User ID
   - Election ID
   - Attempted issue ID

### Acceptance Criteria
- [ ] Explicit eligibility check added to vote submission
- [ ] Proper 403 responses for ineligible voters
- [ ] `VoterNotEligible` exception implemented
- [ ] Security logging added for unauthorized attempts
- [ ] Tests added for authorization enforcement

### References
- CWE-862: Missing Authorization
- ASVS: 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.2, 8.3.3, 8.4.1
- Related: FINDING-006

### Priority
High

---

## Issue: FINDING-050 - authz Field Defined in Schema and Documented but Never Evaluated in Access Control Decisions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The database schema defines an `authz` field for group-based election editing permissions with explicit documentation, but this field is only retrieved for display and never evaluated in any authorization decision.

### Details
- Schema defines `authz` field for group-based access control
- Documentation describes `authz` as 'allowed to edit'
- Field only used for display in templates
- Never evaluated in authorization logic
- Type B gap: control DEFINED but NOT CALLED
- Creates false confidence in security architecture
- Violates ASVS 8.1.2, 8.1.3 (L2/L3)
- CWE-285: Improper Authorization

**Affected files:**
- `v3/schema.sql:52`
- `v3/docs/schema.md`
- `v3/steve/election.py:143`
- `v3/server/pages.py`

### Remediation
1. Create authorization policy document
2. Implement `authz` group checks in `load_election` decorator (see AUTHZ-001 remediation)
3. Integrate with ASF LDAP infrastructure to evaluate group membership
4. Authorization check should verify:
   - If `md.owner_pid` matches authenticated user's UID → authorize
   - Else if `md.authz` is set → check if user is member of that LDAP group
   - Else → deny access with 403 Forbidden

### Acceptance Criteria
- [ ] Authorization policy document created
- [ ] `authz` group checks implemented
- [ ] LDAP integration added
- [ ] Tests added for group-based authorization

### References
- CWE-285: Improper Authorization
- ASVS: 8.1.2, 8.1.3

### Priority
High

---

## Issue: FINDING-051 - Per-Issue Voter Eligibility Not Enforced — Issue Properties Exposed Without Field-Level Authorization
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application performs only election-level eligibility checks, exposing properties (titles, descriptions, candidate lists) of issues the user is not authorized to vote on. This violates Broken Object Property Level Authorization (BOPLA) principles.

### Details
- Only election-level eligibility checks performed before displaying all issues
- Vote submission relies on implicit `AttributeError` instead of explicit authorization
- Properties of non-eligible issues exposed: titles, descriptions, candidate lists, seat counts
- Direct BOPLA violation per ASVS 8.2.3
- If per-issue eligibility used (e.g., PMC-specific votes), exposes confidential ballot information
- Violates ASVS 8.2.3 (L2)
- CWE-639: Authorization Bypass Through User-Controlled Key

**Affected files:**
- `v3/server/pages.py:225-272, 236-241, 247`
- `v3/steve/election.py:183-191, 196-207`

### Remediation
1. **Filter issues by user eligibility** in `vote_on_page`:
   - Query `q_find_issues` to get eligible issue IDs
   - Filter issue list to only include eligible issues before rendering

2. **Add explicit checks** in `do_vote_endpoint`:
   - Verify each submitted issue ID is in eligible set before processing

3. **In `election.py` `add_vote`:**
   - Add explicit authorization check
   - Raise proper `VoterNotEligible` exception instead of relying on `AttributeError`

This ensures field-level access control based on `mayvote` relationship.

### Acceptance Criteria
- [ ] Issue list filtered by eligibility before rendering
- [ ] Explicit eligibility checks in vote submission
- [ ] Proper `VoterNotEligible` exception added
- [ ] Tests added for field-level authorization

### References
- CWE-639: Authorization Bypass Through User-Controlled Key
- ASVS: 8.2.3
- Related: FINDING-010, FINDING-053, FINDING-153

### Priority
High

---

## Issue: FINDING-052 - No Sender-Constrained Access Token Implementation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application implements OAuth 2.0 but provides no mechanism to bind access tokens to the presenting client (neither Mutual TLS nor DPoP), allowing stolen tokens to be replayed from any network location.

### Details
- Plain OAuth 2.0 authorization code flow without sender-constraining
- No Mutual TLS (RFC 8705) implementation
- No Demonstration of Proof-of-Possession (DPoP, RFC 9449) implementation
- All resource server endpoints validate sessions/tokens without proof-of-possession verification
- Stolen access tokens can be replayed from anywhere
- Particularly critical for voting system integrity
- Violates ASVS 10.3.5, 10.4.14 (L3)
- CWE-294: Authentication Bypass by Capture-replay

**Affected files:**
- `v3/server/main.py:37-41, 77-80, 82-84`
- `v3/server/pages.py` (all 21 protected endpoints)

### Remediation
**Implement DPoP (RFC 9449) as primary sender-constraining mechanism:**

1. Coordinate with asfquart framework maintainers to add DPoP support for OAuth token exchange

2. Implement DPoP proof validation middleware:
   - Validate DPoP proof JWT
   - Verify `htm`/`htu` claims match request method/URL
   - Validate `ath` claim matches access token hash
   - Verify JWK thumbprint matches token's `cnf.jkt` claim

3. Configure token introspection to verify `cnf` claims

4. Update all 21 protected endpoints to require DPoP proof validation

5. Test thoroughly with legitimate clients

**Alternative: Implement Mutual TLS (RFC 8705)** with certificate thumbprint binding (requires infrastructure changes)

**Interim compensating controls:**
- Reduce token lifetime
- Implement IP address binding for sessions
- Enhanced monitoring for suspicious token usage
- Rate limiting on authentication endpoints
- Require MFA for high-value operations

### Acceptance Criteria
- [ ] DPoP support added to framework
- [ ] DPoP proof validation middleware implemented
- [ ] Token introspection configured for cnf claims
- [ ] All protected endpoints require DPoP validation
- [ ] Tests added for DPoP flow
- [ ] Documentation updated

### References
- CWE-294: Authentication Bypass by Capture-replay
- ASVS: 10.3.5, 10.4.14
- RFC 9449 (DPoP), RFC 8705 (Mutual TLS)

### Priority
High

---

## Issue: FINDING-053 - Authorization Code Grant Without Pushed Authorization Requests (PAR)
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses OAuth authorization code grant but constructs authorization requests using traditional URL query strings instead of Pushed Authorization Requests (PAR), exposing parameters through browser history, server logs, and referrer headers.

### Details
- Authorization parameters passed directly in URL query strings
- Violates ASVS 10.4.13 Level 3 requirement for PAR with authorization code grant
- Per RFC 9126, correct PAR flow requires: POST to PAR endpoint → receive `request_uri` → redirect with only `request_uri` and `client_id`
- Current implementation bypasses server-side pre-validation
- Authorization parameters exposed through: browser history, server logs, referrer headers
- Allows authorization request tampering
- Violates ASVS 10.4.13, 10.4.15 (L3)
- CWE-639: Authorization Bypass Through User-Controlled Key

**Affected files:**
- `v3/server/main.py:37-42, 38-42`

### Remediation
1. **Verify AS PAR Support:** Coordinate with oauth.apache.org operators to confirm PAR endpoint availability

2. **Update Framework:** Modify asfquart to implement PAR flow:
   - Add `OAUTH_PAR_ENDPOINT` configuration
   - Update `OAUTH_URL_INIT` to only use `client_id` and `request_uri`

3. **Implement PAR Flow:**
   - POST authorization parameters to PAR endpoint server-to-server
   - Receive `request_uri` from AS
   - Store `request_uri` with expiration for validation
   - Redirect user with only `client_id` and `request_uri`

4. **Enforce PAR at AS:** Request AS configuration update: `require_pushed_authorization_requests: true`

5. **Implement PKCE alongside PAR** for defense-in-depth

6. **Use `private_key_jwt` or `tls_client_auth`** for client authentication instead of `client_secret_basic`

7. **Set short expiration** for `request_uri` (recommended: 60 seconds)

8. **Implement `request_uri` validation** in callback handler

9. **Add monitoring** for non-PAR authorization attempts

### Acceptance Criteria
- [ ] PAR endpoint support verified with AS
- [ ] Framework updated for PAR flow
- [ ] PAR flow implemented
- [ ] PAR enforced at AS level
- [ ] PKCE implemented
- [ ] Strong client authentication configured
- [ ] Request URI expiration configured
- [ ] Validation implemented in callback
- [ ] Monitoring added
- [ ] Tests added for PAR flow

### References
- CWE-639: Authorization Bypass Through User-Controlled Key
- ASVS: 10.4.13, 10.4.15
- RFC 9126 (PAR)
- Related: FINDING-010, FINDING-051, FINDING-153

### Priority
High

---

## Issue: FINDING-054 - OAuth Client Authentication Lacks Public-Key-Based Methods (mTLS / private_key_jwt)
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 10.4.16 requires OAuth clients use strong, public-key-based client authentication methods (mutual TLS or `private_key_jwt`) resistant to replay attacks. The application shows no evidence of configuring such methods, likely using symmetric shared secrets or no authentication.

### Details
- No client certificate (mTLS) configuration
- No `client_assertion`/`client_assertion_type` (`private_key_jwt`)
- No configuration for `token_endpoint_auth_method`
- Token endpoint URL template only formats authorization code
- Vulnerable to credential theft and replay attacks
- Violates ASVS 10.4.16 (L3)

**Affected files:**
- `v3/server/main.py:38-43`

### Remediation
**Option A: Mutual TLS (`tls_client_auth`):**
```python
import httpx

# Configure HTTP client with mTLS for token endpoint
oauth_http_client = httpx.AsyncClient(
    cert=("/path/to/client-cert.pem", "/path/to/client-key.pem"),
    verify="/path/to/ca-bundle.pem",
)

# Register with AS using token_endpoint_auth_method = "tls_client_auth"
# per RFC 8705 Section 2
```

**Option B: Private Key JWT (`private_key_jwt`):**
```python
import time
import jwt
import secrets

def build_client_assertion(client_id, token_endpoint, private_key):
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + 60,  # Short-lived to prevent replay
        "jti": secrets.token_hex(16),  # Unique ID prevents replay
    }
    return jwt.encode(claims, private_key, algorithm="RS256")

# Token request includes:
# client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
# client_assertion=<signed_jwt>
```

### Acceptance Criteria
- [ ] Public-key-based authentication method chosen
- [ ] mTLS or private_key_jwt implemented
- [ ] Configuration updated
- [ ] Registered with AS
- [ ] Tests added for authentication method

### References
- CWE: Not specified
- ASVS: 10.4.16
- RFC 8705 (mTLS), RFC 7523 (JWT Bearer)

### Priority
High

---

## Issue: FINDING-055 - No ID Token Handling - Custom OAuth Bypasses OIDC
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application explicitly configures custom OAuth endpoints with comment '# Avoid OIDC', meaning no ID Token is issued or consumed. Critical validations are absent: cryptographic signature verification, issuer/audience validation, temporal validity checks, and nonce validation.

### Details
- Custom OAuth endpoints configured, explicitly avoiding OIDC
- No ID Token issued or consumed
- 'sub' claim (locally unique, never-reassigned identifier) not used
- Missing critical validations:
  - Cryptographic signature verification
  - Issuer ('iss') validation
  - Audience ('aud') validation
  - Temporal validity ('exp'/'iat') checks
  - Nonce validation for replay protection
- User identity for authorization decisions obtained without OIDC security guarantees
- Affects: voting eligibility, election management, audit logging
- Violates ASVS 10.5.2 (L2/L3)

**Affected files:**
- `v3/server/main.py:38-43`

### Remediation
1. **Migrate from custom OAuth to standard OIDC** with ID Token validation

2. **Configure OIDC with proper ID Token validation:**
   - Use OIDC discovery endpoint for automatic key/endpoint configuration

3. **In session establishment:**
   - Use 'sub' claim as unique, non-reassignable user identifier
   - NOT email, NOT preferred_username
   - Example: `session['uid'] = id_token_claims['sub']`

4. **Verify critical claims:**
   - Issuer matches expected OP
   - Audience includes this client

### Acceptance Criteria
- [ ] OIDC configuration implemented
- [ ] ID Token validation added
- [ ] 'sub' claim used for user identification
- [ ] Issuer validation implemented
- [ ] Audience validation implemented
- [ ] Tests added for OIDC flow

### References
- CWE: Not specified
- ASVS: 10.5.2

### Priority
High

---

## Issue: FINDING-056 - No Visible ID Token Audience (aud) Claim Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application deliberately overrides OIDC with comment 'Avoid OIDC' and implements custom OAuth without any ID Token audience (aud) claim validation, allowing potential token confusion attacks where tokens intended for other services could gain access.

### Details
- Deliberate OIDC override with custom OAuth configuration
- No `client_id` configured or referenced
- No `aud` validation logic exists
- Allows token confusion attacks: attacker with token for another Apache service could access election system
- Violates ASVS 10.5.4 (L2/L3)

**Affected files:**
- `v3/server/main.py:35-48`
- `v3/server/pages.py:79`

### Remediation
1. Remove 'Avoid OIDC' override and use proper OIDC endpoints with full ID Token validation

2. Configure `client_id` in application (e.g., 'steve-voting-app')

3. Implement validation that ID Token's 'aud' claim matches configured `client_id` before accepting token

4. If using asfquart framework:
   - Audit token handling code to verify `aud` validation
   - OR add middleware to validate token audience before session creation

5. Add integration tests verifying tokens with incorrect `aud` values are rejected

### Acceptance Criteria
- [ ] OIDC properly configured
- [ ] `client_id` configured
- [ ] Audience validation implemented
- [ ] Framework token handling audited
- [ ] Tests added for audience validation

### References
- CWE: Not specified
- ASVS: 10.5.4

### Priority
High

---

## Issue: FINDING-057 - Complete Absence of Cipher Suite Configuration in Standalone TLS Server
**Labels:** bug, security, priority:high
**Description:**
### Summary
The server passes raw certificate/key file paths to Quart/Hypercorn without creating an `ssl.SSLContext`, resulting in no cipher suite restrictions, no cipher preference order, no forward secrecy enforcement, and potential TLS 1.0/1.1 negotiation.

### Details
- No `ssl.SSLContext` created
- All system-default ciphers enabled (potentially including RC4, 3DES, NULL, EXPORT, CBC-mode)
- No cipher preference order (`ssl.OP_CIPHER_SERVER_PREFERENCE` not set)
- No forward secrecy enforcement (non-ECDHE/DHE suites available)
- No TLS version pinning (TLS 1.0/1.1 may be negotiated)
- Weak ciphers allow passive decryption if private key compromised
- No mechanism to enforce trust policy on internal connections
- Violates ASVS 12.1.2, 12.3.1, 12.3.3, 12.3.4 (L2/L3)
- CWE-326: Inadequate Encryption Strength

**Affected files:**
- `v3/server/main.py:79-84, 83-89, 98-104`

### Remediation
Create properly configured `SSLContext`:

```python
import ssl

def create_ssl_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Set minimum TLS version to 1.2, maximum to 1.3
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    
    # Configure strong cipher suites only
    ctx.set_ciphers(
        'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:'
        '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'
    )
    
    # Enable server cipher preference
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= ssl.OP_NO_COMPRESSION
    
    # Load certificate chain
    ctx.load_cert_chain(certfile, keyfile)
    
    return ctx

# Pass SSLContext to app.runx() via ssl parameter
ssl_context = create_ssl_context(certfile, keyfile)
app.runx(..., ssl=ssl_context)
```

For mutual TLS with reverse proxy:
```python
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_verify_locations(cafile=ca_cert_path)
```

### Acceptance Criteria
- [ ] `SSLContext` creation function implemented
- [ ] Strong cipher suites configured
- [ ] TLS 1.2+ enforced
- [ ] Server cipher preference enabled
- [ ] Certificate chain loaded via context
- [ ] Context passed to server instead of raw paths
- [ ] Tests added for TLS configuration

### References
- CWE-326: Inadequate Encryption Strength
- ASVS: 12.1.2, 12.3.1, 12.3.3, 12.3.4

### Priority
High

---

## Issue: FINDING-058 - Missing OCSP Stapling Configuration in Server TLS Setup
**Labels:** bug, security, priority:high
**Description:**
### Summary
The TLS setup passes only certfile and keyfile paths without creating a custom `ssl.SSLContext`, preventing OCSP Stapling configuration. Clients cannot efficiently check certificate revocation status, and if the server's certificate is revoked, clients may not detect it.

### Details
- No `ssl.SSLContext` created
- No OCSP Stapling callback registered
- Clients must independently query CA's OCSP responder (introduces latency, privacy leakage)
- Many clients skip revocation checking entirely
- If server certificate revoked, clients have no reliable mechanism to learn of revocation
- No SSL context parameters set (protocol version, cipher suites, verification modes rely on framework defaults)
- Violates ASVS 12.1.4 (L3)

**Affected files:**
- `v3/server/main.py:93-100`

### Remediation
**Create explicit `ssl.SSLContext` with OCSP Stapling support:**

```python
import ssl

def _create_ssl_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    
    # Set OCSP server callback
    ctx.set_ocsp_server_callback(ocsp_callback_function)
    
    # Harden cipher selection
    ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:...')
    
    return ctx
```

**Production recommendation:** OCSP Stapling most effectively handled by reverse proxy:
```nginx
# Nginx configuration
ssl_stapling on;
ssl_stapling_verify on;
```

Document as deployment requirement.

### Acceptance Criteria
- [ ] `SSLContext` with OCSP support created
- [ ] OCSP callback implemented
- [ ] Cipher suite hardening added
- [ ] Reverse proxy deployment option documented
- [ ] Tests added for OCSP configuration

### References
- CWE: Not specified
- ASVS: 12.1.4

### Priority
High

---

## Issue: FINDING-059 - Encrypted Client Hello (ECH) Not Implemented
**Labels:** bug, security, priority:high
**Description:**
### Summary
The TLS setup passes raw file paths without ECH configuration, meaning Server Name Indication (SNI) is transmitted in plaintext during TLS ClientHello. For a voting system, this metadata leakage can reveal voter participation patterns.

### Details
- No ECH key pair generated or referenced
- No `ech_config` parameter in TLS settings
- No `ssl.SSLContext` created where ECH could be enabled
- No DNS HTTPS record guidance or ECHConfig publication mechanism
- No ECH retry configuration
- SNI transmitted in plaintext, allowing network observers to identify specific server/election connections
- Reveals voter participation patterns in voting system
- Violates ASVS 12.1.5 (L3)

**Affected files:**
- `v3/server/main.py:82-88`
- `v3/server/config.yaml.example:28-31`

### Remediation
**ECH requires server-side support in TLS library and DNS publication.**

**Immediate approach:** Deploy behind TLS-terminating reverse proxy (e.g., Cloudflare or nginx with OpenSSL 3.2+) that supports ECH, and publish ECHConfig via DNS HTTPS resource records.

**Application-level implementation:**

1. Add ECH configuration fields to `config.yaml`:
   - `ech_keyfile`
   - `ech_config_list`

2. Create SSL context with TLS 1.3 minimum:
```python
import ssl

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3

# Configure cipher suites
ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')

# Load certificate chain
ctx.load_cert_chain(certfile, keyfile)

# Configure ECH keys when supported by ssl module/OpenSSL 3.2+
# (API pending Python ssl module support)
```

3. Publish ECHConfig via DNS HTTPS records

4. Pass context to `app.runx()` via `ssl` parameter

### Acceptance Criteria
- [ ] Reverse proxy deployment option documented
- [ ] ECH configuration fields added to config
- [ ] SSL context created with TLS 1.3 minimum
- [ ] Cipher suite configuration added
- [ ] ECH key configuration prepared for future support
- [ ] DNS HTTPS record publication documented
- [ ] Tests added when ECH support available

### References
- CWE: Not specified
- ASVS: 12.1.5

### Priority
High

---

## Issue: FINDING-060 - No SSL Context Configuration Prevents mTLS Client Certificate Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The TLS configuration passes raw certfile/keyfile paths without constructing an `ssl.SSLContext`, preventing mTLS client certificate validation. No mechanism exists to require, verify, or validate client certificates, and service identity is not cryptographically verified.

### Details
- No `ssl.SSLContext` created
- No client certificate verification (`ssl.CERT_REQUIRED` not set)
- No trusted CA (`ca_certs`) configured
- No configuration surface for mTLS in `config.yaml`
- No TLS version floor (may accept TLS 1.0/1.1)
- No cipher restrictions
- OAuth used for authentication instead of mTLS
- No defense-in-depth authentication mechanism
- Any process reaching backend port can impersonate legitimate proxy
- Violates ASVS 12.1.3, 12.3.4, 12.3.5 (L2/L3)

**Affected files:**
- `v3/server/main.py:83-90, 79-87`
- `v3/server/config.yaml.example:28-30, 28-31`

### Remediation
**Step 1: Update configuration schema** in `config.yaml`:
```yaml
server:
  ca_certs: ca-chain.pem  # CA certificate for client verification
  verify_client: true      # Enable client certificate verification
  tls_min_version: 1.2     # Minimum TLS version
  ciphers: ...             # Cipher suite configuration
```

**Step 2: Implement SSL context creation:**
```python
import ssl

def _create_ssl_context(certfile, keyfile, config):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Enforce minimum TLS version 1.2
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    
    # Load server certificate chain
    ctx.load_cert_chain(certfile, keyfile)
    
    # Configure strong cipher suites
    ctx.set_ciphers(
        'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:'
        '!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'
    )
    
    # If mTLS enabled, configure client certificate validation
    if getattr(config.server, 'verify_client', False):
        ctx.verify_mode = ssl.CERT_REQUIRED
        ca_certs_path = CERTS_DIR / config.server.ca_certs
        ctx.load_verify_locations(cafile=ca_certs_path)
    
    return ctx
```

**Step 3: Modify `run_standalone()`:**
```python
ssl_context = _create_ssl_context(certfile, keyfile, app.cfg)
app.runx(..., ssl=ssl_context)
```

### Acceptance Criteria
- [ ] mTLS configuration fields added to config schema
- [ ] `_create_ssl_context()` function implemented
- [ ] TLS 1.2+ enforced
- [ ] Strong cipher suites configured
- [ ] Client certificate verification configurable
- [ ] CA certificate loading implemented
- [ ] Context passed to server
- [ ] Tests added for mTLS configuration

### References
- CWE: Not specified
- ASVS: 12.1.3, 12.3.4, 12.3.5

### Priority
High

---

## Issue: FINDING-061 - TLS Not Enforced and No Certificate Trust Validation for External Services
**Labels:** bug, security, priority:high
**Description:**
### Summary
TLS configuration is optional via `if app.cfg.server.certfile:` check, allowing the voting application to serve all endpoints (authentication, vote submission, election management) over plain HTTP. No validation ensures provided certificates are publicly trusted.

### Details
- TLS silently skipped when `certfile` configuration empty
- All external endpoints can run over plain HTTP: authentication, vote submission, election management
- No validation of certificate public trust
- No TLS protocol version restrictions
- No cipher suite restrictions
- Configuration template references mkcert-generated development certificates (not publicly trusted)
- In ASGI mode, TLS configuration entirely absent
- Violates ASVS 12.2.2 (L1) - external services must use publicly trusted TLS certificates

**Affected files:**
- `v3/server/main.py:87-91, 97-117`
- `v3/server/config.yaml.example:31-33`

### Remediation
1. **Enforce TLS as mandatory:**
   - Validate `certfile` and `keyfile` configured before server startup
   - Exit with critical error if missing

2. **Validate certificate files:**
   - Check files exist at specified paths

3. **Implement `ssl.SSLContext`:**
   - Enforce minimum TLS version 1.2 using `ssl.TLSVersion.TLSv1_2`

4. **Update `config.yaml.example`:**
   - Reference publicly trusted certificates (e.g., Let's Encrypt)
   - Remove mkcert development certificate references
   - Add warnings against self-signed/development certificates in production

5. **For ASGI mode:**
   - Document TLS requirements
   - Add validation checks

6. **If proxy architecture intended:**
   - Add explicit configuration flag (e.g., `behind_proxy: true`)
   - Document deployment requirements

### Acceptance Criteria
- [ ] TLS enforcement implemented
- [ ] Certificate file validation added
- [ ] `SSLContext` with TLS 1.2+ created
- [ ] Config template updated with production certificate guidance
- [ ] ASGI mode TLS requirements documented
- [ ] Proxy deployment option documented
- [ ] Tests added for TLS enforcement

### References
- CWE: Not specified
- ASVS: 12.2.2

### Priority
High

---

## Issue: FINDING-062 - Absence of Formal Cryptographic Inventory and Post-Quantum Migration Plan
**Labels:** bug, security, priority:high
**Description:**
### Summary
The codebase uses six distinct cryptographic primitives (BLAKE2b, Argon2d, HKDF-SHA256, Fernet/AES-128-CBC, HMAC-SHA256, CSPRNG) across multiple files, but no formal cryptographic inventory document exists. This prevents systematic response to algorithm deprecations, PQC migration, compliance audits, and incident response.

### Details
- Six cryptographic primitives used: BLAKE2b, Argon2d, HKDF-SHA256, Fernet/AES-128-CBC, HMAC-SHA256, CSPRNG
- No formal cryptographic inventory document
- Code comments show awareness ('still using Fernet now, but will switch soon') but not formalized
- Type B gap: awareness EXISTS but NOT FORMALIZED
- Cannot systematically respond to:
  - Algorithm deprecations
  - PQC migration requirements
  - Compliance audits
  - Incident response
  - Developer onboarding
- Inconsistencies persist: no algorithm registry, no key boundary documentation, no data protection mapping, no key lifecycle documentation
- Violates ASVS 11.1.1, 11.1.2, 11.1.3, 11.1.4 (L2/L3)

**Affected files:**
- `v3/steve/crypto.py` (entire file)
- `v3/steve/election.py` (entire file)
- `v3/schema.sql`
- All files in codebase

### Remediation
**Create formal `CRYPTO_INVENTORY.md` document** at repository root including:

1. **Complete algorithm catalog** with ID, library, version, key size, purpose, status, PQC risk, justification for each primitive

2. **Keys and boundaries:**
   - Derivation
   - What data can/cannot be protected
   - Storage locations
   - Authorized accessors

3. **Usage contexts** mapping algorithms to code locations

4. **Key lifecycle policies:**
   - Generation, storage, access, rotation, destruction procedures
   - Maximum key lifetime per election state
   - Key destruction procedures post-tallying
   - Compromise response procedures

5. **Post-quantum cryptography migration plan:**
   - Risk assessment
   - Timeline:
     - Q2 2026: Complete inventory
     - Q3 2026: Migrate Argon2d to Argon2id
     - Q4 2026: Migrate Fernet to XChaCha20-Poly1305
     - Q1 2027: Implement algorithm versioning
     - Q2 2027: Evaluate NIST PQC standards (ML-KEM-768, ML-DSA-65)
     - Q4 2027: Proof-of-concept hybrid classical+PQC KDF
     - 2028+: Production PQC deployment
   - Breaking change management

6. **Parameter justification** for all configurations

7. **Compliance mapping** to standards (NIST SP 800-57, RFC 9106, ASVS)

8. **Review history** and scheduled cadence

**Establish processes:**
- Quarterly inventory reviews with documented sign-off
- Annual PQC threat assessments
- Immediate reviews upon algorithm deprecation announcements

**Implement automated crypto scanning:**
- CI/CD detection of crypto imports outside `crypto.py`
- Verify inventory matches actual usage
- Decorator-based crypto registration system with `CRYPTO_REGISTRY`

**Implement key destruction:**
- `archive_and_destroy_keys()` method after tally completion
- Verify tally exported/signed
- Destroy election-level keys (`SET salt=NULL, opened_key=NULL`)
- Destroy per-voter salts (`SET mayvote.salt=NULL`)
- Add timestamp columns: `keys_created_at`, `keys_destroyed_at`

**Implement schema versioning** to enable future migrations

**Add automated tests** validating inventory matches implementation

### Acceptance Criteria
- [ ] `CRYPTO_INVENTORY.md` created with all sections
- [ ] Algorithm catalog complete
- [ ] Key boundaries documented
- [ ] Lifecycle policies defined
- [ ] PQC migration plan documented
- [ ] Review schedule established
- [ ] Automated crypto scanning implemented
- [ ] Key destruction implemented
- [ ] Schema versioning added
- [ ] Tests added for inventory validation

### References
- CWE: Not specified
- ASVS: 11.1.1, 11.1.2, 11.1.3, 11.1.4

### Priority
High

---

## Issue: FINDING-063 - Absence of Cryptographic Abstraction Layer Prevents Algorithm Agility
**Labels:** bug, security, priority:high
**Description:**
### Summary
All cryptographic algorithms are directly instantiated without abstraction, configuration, or strategy pattern. The application lacks a cryptographic provider layer enabling algorithm substitution without code changes, blocking migration to post-quantum cryptography.

### Details
- All algorithms hardcoded: Fernet (AES-128-CBC+HMAC), HKDF-SHA256, Argon2, BLAKE2b
- No abstraction or configuration layer
- Swapping algorithms requires code modifications
- No configuration-driven algorithm selection
- Blocks PQC migration without complete rewrite
- Violates ASVS 11.2.2 (L2)

**Affected files:**
- `v3/steve/crypto.py:62, 69, 53, 77, 38`

### Remediation
**Introduce crypto provider abstraction:**

1. **Create `CryptoProvider` class:**
```python
class CryptoProvider:
    ENCRYPTION_REGISTRY = {
        'fernet-v1': FernetEncryptor,
        'xchacha20-v1': XChaCha20Encryptor,
        # Future: 'ml-kem-768-v1': PostQuantumEncryptor
    }
    
    def __init__(self, config):
        self.config = config
        self.algorithm = config.encryption_algorithm
    
    def encrypt(self, data, key):
        encryptor = self.ENCRYPTION_REGISTRY[self.algorithm]
        return encryptor.encrypt(data, key)
```

2. **Create `CryptoConfig` dataclass:**
```python
@dataclass
class CryptoConfig:
    encryption_algorithm: str  # Load from YAML
    kdf_algorithm: str
    hash_algorithm: str
```

3. **Implement version-aware methods:**
```python
def decrypt_versioned(self, ciphertext):
    version = self._extract_version(ciphertext)
    encryptor = self._get_encryptor_for_version(version)
    return encryptor.decrypt(ciphertext)
```

4. **Add methods:**
   - `_extract_version()` - parse version from ciphertext
   - `_get_encryptor_for_version()` - support backward compatibility

This enables:
- Algorithm substitution without code changes
- Path for PQC adoption
- Backward compatibility during migrations

### Acceptance Criteria
- [ ] `CryptoProvider` class implemented
- [ ] Algorithm registry created
- [ ] `CryptoConfig` dataclass added
- [ ] Version-aware encryption/decryption implemented
- [ ] Configuration-driven algorithm selection
- [ ] Tests added for multiple algorithms
- [ ] Documentation updated

### References
- CWE: Not specified
- ASVS: 11.2.2

### Priority
High

---

## Issue: FINDING-064 - Unbounded Database Connection Creation Without Pooling, Limits, or Documented Recovery
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `Election` class opens a new, independent SQLite database connection for every operation via `open_database()` with no connection pool, maximum limit, timeout configuration, or documented behavior for database unavailability.

### Details
- New connection created for every operation
- No connection pool
- No maximum connection limit
- No timeout configuration
- No documented behavior when database unavailable
- Class-level methods independently open new connections
- Concurrent requests create unbounded parallel connections
- Under write contention, connections queue on SQLite file-level lock with no timeout
- Read-heavy operations exhaust file descriptors
- No fallback or circuit-breaker
- Unhandled exceptions: `sqlite3.OperationalError: unable to open database file` or `database is locked`
- Cascading failures under load
- Violates ASVS 13.1.2, 13.2.6 (L3)

**Affected files:**
- `v3/steve/election.py:42-48`
- `v3/server/config.yaml.example`

### Remediation
1. **Add connection pool configuration** to `config.yaml.example`:
```yaml
database:
  pool_size: 10
  pool_timeout: 5  # seconds
  max_overflow: 5
  # Behavior when pool exhausted: return HTTP 503 with Retry-After header
```

2. **Implement connection pool** in `election.py`:
```python
import threading
import queue

class ConnectionPool:
    def __init__(self, max_connections, timeout):
        self.pool = queue.Queue(maxsize=max_connections)
        self.timeout = timeout
        self.lock = threading.Lock()
    
    def get_connection(self):
        try:
            return self.pool.get(timeout=self.timeout)
        except queue.Empty:
            raise ServiceUnavailable("Connection pool exhausted")
```

OR implement singleton pattern with `threading.Lock`

3. **Document fallback behavior** when limits reached

### Acceptance Criteria
- [ ] Connection pool configuration added
- [ ] Connection pool or singleton implemented
- [ ] Maximum connection limit enforced
- [ ] Timeout configuration added
- [ ] Fallback behavior documented
- [ ] HTTP 503 returned when pool exhausted
- [ ] Tests added for connection limits

### References
- CWE: Not specified
- ASVS: 13.1.2, 13.2.6

### Priority
High

---

## Issue: FINDING-065 - No Concurrency Limits on Memory-Intensive Argon2 Operations Enabling Resource Exhaustion
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses Argon2 key derivation with significant resource requirements (64MB memory, ~200-500ms CPU time per invocation) in multiple web request paths without documentation, defenses, or concurrency limits, enabling resource exhaustion attacks.

### Details
- Argon2 parameters: 64MB memory, ~200-500ms CPU time per invocation
- No documentation identifying resource-intensive operations
- No documented defenses against availability loss
- No documented strategies for timeout avoidance
- Quart (async framework) calls synchronous Argon2 directly, blocking event loop
- Resource impact scenarios:
  - Vote submission: 1× Argon2 per request (10 concurrent = 640MB + CPU saturation)
  - Ballot status: N × Argon2 where N = issues (20 issues = ~10s response)
  - Tally: O(N) where N = voters (100 voters = ~50s, 1000 voters = ~500s)
- During Argon2 execution, entire event loop blocked (no health checks served)
- No documented execution time expectations
- No guidance on maximum election sizes
- No documented timeout or processing strategy
- Violates ASVS 13.1.2, 15.1.3, 15.2.2 (L2/L3)

**Affected files:**
- `v3/steve/crypto.py:88-98`
- `v3/steve/election.py:230-243`

### Remediation
1. **Create operations/architecture document:**
   - Identify each resource-intensive operation with CPU/memory profile
   - Vote Submission: 1× Argon2 = 64MB RAM + ~500ms CPU
   - Ballot Status: N × Argon2 where N = issues
   - Tally: N × Argon2 where N = eligible voters
   - Document maximum concurrent requests server can handle
   - Specify recommended reverse proxy timeout settings
   - Describe recommended deployment configuration (worker count, memory limits)
   - Document expected execution times for various voter counts

2. **Implement `asyncio.run_in_executor()`:**
```python
executor = ThreadPoolExecutor(max_workers=4)  # Limit: 4 × 64MB = 256MB

async def add_vote_async(self, ...):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        executor,
        self._add_vote_sync,  # CPU-bound operation
        ...
    )
```

3. **Document thread pool as concurrency control:**
   - "Argon2 operations offloaded to bounded thread pool (max_workers=4)"
   - "Limits peak memory to 256MB and prevents event loop blocking"
   - "Excess requests queue at executor"

4. **Implement rate limiting** using `quart_rate_limiter`:
   - E.g., 5 votes per minute per user

5. **Add maximum issue count check:**
```python
MAX_ISSUES_PER_CHECK = 100
if len(issues) > MAX_ISSUES_PER_CHECK:
    raise ValueError(f"Too many issues: {len(issues)}")
```

6. **For tally operations:**
   - Document as CLI-only
   - Add logging of expected resource consumption
   - Implement progress callback mechanism
   - Consider separate process with CPU affinity

7. **Document operational planning:**
   - "For elections > 200 voters, schedule tallying during low-usage windows"
   - "Maximum supported: tested up to N voters"

### Acceptance Criteria
- [ ] Operations/architecture document created
- [ ] `asyncio.run_in_executor()` implemented for Argon2 paths
- [ ] Thread pool concurrency limits configured
- [ ] Rate limiting implemented
- [ ] Maximum issue count check added
- [ ] Tally operations documented as CLI-only
- [ ] Operational planning guidance documented
- [ ] Tests added for concurrency limits

### References
- CWE: Not specified
- ASVS: 13.1.2, 15.1.3, 15.2.2

### Priority
High

---

## Issue: FINDING-066 - Absence of Critical Secrets Inventory Documentation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application employs at least 8 distinct categories of cryptographic secrets critical to election integrity, but no documentation exists enumerating these secrets, describing their purpose, classifying sensitivity, or specifying access controls.

### Details
- 8 categories of secrets:
  1. TLS Certificate/Key
  2. OAuth Client Secrets
  3. Election Salt
  4. Opened Key
  5. Per-voter Salts
  6. Vote Tokens
  7. Fernet Encryption Keys
  8. Database File
- No documentation in configuration template, inline code, or standalone security document
- Operations staff cannot properly protect unknown secrets
- Incident response cannot systematically identify/rotate compromised secrets
- Violates ASVS 13.1.4 (L3)
- CWE-1059: Incomplete Documentation

**Affected files:**
- `v3/server/config.yaml.example:1-22`
- `v3/steve/crypto.py:13-77`
- `v3/steve/election.py:82-94, 143-151`
- `v3/server/main.py:38-49`

### Remediation
**Create `SECURITY.md`** in repository root with comprehensive secrets inventory:

**Infrastructure Secrets:**
- TLS Private Key
- TLS Certificate
- OAuth Client Secret
- Database File

**Cryptographic Secrets:**
- Election Salt
- Opened Key
- Per-Voter Salt
- Vote Tokens
- Fernet Encryption Keys

**For each secret, document:**
- Storage location
- Access requirements
- Criticality level
- Purpose

**Include configuration management guidance:**
- Secrets MUST NOT be stored in `config.yaml`
- Must be provided via environment variables or secure filesystem with restricted permissions

**Create access control matrix** defining which roles can access which secrets

### Acceptance Criteria
- [ ] `SECURITY.md` created
- [ ] All 8 secret categories documented
- [ ] Storage locations specified
- [ ] Access requirements defined
- [ ] Criticality levels assigned
- [ ] Purpose explained for each
- [ ] Configuration management guidance added
- [ ] Access control matrix created

### References
- CWE-1059: Incomplete Documentation
- ASVS: 13.1.4
- Related: FINDING-151, FINDING-190

### Priority
High

---

## Issue: FINDING-067 - No Secret Rotation Schedule or Rotation Capability
**Labels:** bug, security, priority:high
**Description:**
### Summary
No rotation schedule is defined for any secret. More critically, the cryptographic architecture structurally prevents rotation for election-bound secrets. Once an election is opened, its salt, opened_key, per-voter salts, and derived vote tokens are permanently fixed with no recovery path if compromised.

### Details
- No rotation schedule for any secret
- Election-scoped secrets permanently fixed once election opened:
  - salt
  - opened_key
  - per-voter salts
  - derived vote tokens
- No key versioning
- No re-encryption mechanism
- No documented procedure for rotating infrastructure secrets (TLS certificates, OAuth credentials)
- HKDF info parameter is fixed constant (`b'xchacha20_key'`) with no version indicator
- If election-scoped secret compromised, no recovery path without closing election
- Violates ASVS 13.1.4 (L3)
- CWE-320: Key Management Errors

**Affected files:**
- `v3/steve/crypto.py:68-77`
- `v3/steve/election.py:82-94, 143-151, 282-295`

### Remediation
**Document rotation schedule and constraints** in `SECURITY.md`:

**Infrastructure Secrets:**
- TLS Certificate: Annual or 30 days before expiry
- OAuth Client Secret: Annual or on compromise

**Election-Scoped Secrets:**
- Explicitly document that these CANNOT be rotated (bound to election lifecycle)

**Create rotation procedures:**
- TLS certificate renewal process
- OAuth secret rotation process

**Add key versioning support:**
```python
def _b64_vote_key(self, vote_token, salt, version=1):
    info = f'vote_key_v{version}'.encode()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return base64.urlsafe_b64encode(hkdf.derive(vote_token))
```

**Store key version** in database alongside votes

**Implement `decrypt()` function** supporting multiple key versions for backward compatibility

### Acceptance Criteria
- [ ] Rotation schedule documented in `SECURITY.md`
- [ ] Constraints documented for election-scoped secrets
- [ ] Rotation procedures created for infrastructure secrets
- [ ] Key versioning support added to `crypto.py`
- [ ] Key version stored in database
- [ ] Multi-version decrypt function implemented
- [ ] Tests added for key versioning

### References
- CWE-320: Key Management Errors
- ASVS: 13.1.4
- Related: FINDING-069

### Priority
High

---

## Issue: FINDING-068 - No Secrets Management Solution for Backend Cryptographic Material
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 13.3.1 (L2) requires a secrets management solution (e.g., key vault) to securely create, store, control access to, and destroy backend secrets. The application has no integration with any secrets management system - all cryptographic key material is stored directly in SQLite or referenced by plain file paths.

### Details
- No integration with secrets management system
- All cryptographic material stored in SQLite or plain file paths:
  - `opened_key` (election master key) - raw bytes in SQLite metadata table
  - Per-voter salts - raw bytes in SQLite mayvote table
  - TLS private key - file path in config.yaml
  - OAuth secrets - presumably in config.yaml or environment variables
- SQLite database compromise exposes all cryptographic material for all elections
- No access controls around secret retrieval
- No audit trail
- No monitoring
- Violates ASVS 13.3.1, 13.3.4 (L2/L3)

**Affected files:**
- `v3/steve/election.py:75-88, 258-274`
- `v3/server/main.py:77-78`
- `v3/server/config.yaml.example:28-29`

### Remediation
**Add post-tally key destruction step:**

```python
def destroy_key_material(self):
    """Destroy cryptographic material after tally completion."""
    # Assert election is closed
    if self.state != 'closed':
        raise ValueError("Can only destroy keys for closed elections")
    
    # Begin transaction
    with self.db:
        # Destroy election master key
        self.c_destroy_election_key(eid=self.eid)
        
        # Destroy per-voter salts
        self.c_destroy_voter_salts(eid=self.eid)
        
        # Destroy vote tokens and ciphertexts
        self.c_destroy_vote_data(eid=self.eid)
    
    # Force SQLite to reclaim space and overwrite deleted pages
    self.db.execute('VACUUM')
    
    # Log key material destruction
    _LOGGER.info(f"Key material destroyed for election {self.eid}")
```

**Call after tallying complete and results finalized:**
```python
# After tally
election.tally_all_issues()
election.export_results()
election.sign_results()
election.destroy_key_material()
```

**Add `purge_crypto()` method** and integrate into post-tally lifecycle

**Add 'archived' state** to election lifecycle tracking key material destruction

### Acceptance Criteria
- [ ] `destroy_key_material()` method implemented
- [ ] Post-tally key destruction integrated
- [ ] Database queries for key destruction added
- [ ] VACUUM operation implemented
- [ ] Key destruction logging added
- [ ] 'archived' state added to lifecycle
- [ ] Tests added for key destruction

### References
- CWE: Not specified
- ASVS: 13.3.1, 13.3.4

### Priority
High

---

## Issue: FINDING-069 - Master Election Key (opened_key) Stored in Application Database Co-located with Encrypted Votes
**Labels:** bug, security, priority:high
**Description:**
### Summary
The master election key (`opened_key`) used to derive vote encryption keys is stored directly in the same SQLite database file containing encrypted votes and per-voter salts. An attacker with read access to `steve.db` can extract all components needed for complete de-anonymization in 4-8 minutes.

### Details
- `opened_key`, per-voter salts, and encrypted votes all in same SQLite file
- All three components needed for de-anonymization in single security boundary
- No external secret required
- With Argon2 parameters (time_cost=2, memory_cost=64MB):
  - Complete de-anonymization of 500 voters × 5 issues = 4-8 minutes
- Violates ASVS 13.3.3 (L3) requirement for isolated key storage
- CWE-320: Key Management Errors

**Affected files:**
- `v3/steve/election.py:67-84, 118-131, 222-236, 257-299, 238-256`

### Remediation
**Store `opened_key` in external secrets manager** (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or cloud KMS) requiring separate compromise vector.

**Option A: Use vault/KMS to store key:**
```python
def open(self):
    # Generate opened_key
    opened_key = self._generate_opened_key()
    
    # Store in vault instead of database
    vault_client.store_secret(
        path=f'elections/{self.eid}/opened_key',
        secret=opened_key
    )
    
    # Store only vault reference in database
    self.c_set_vault_ref(
        eid=self.eid,
        vault_ref=f'elections/{self.eid}/opened_key'
    )
```

**Option B: XOR with master key from environment:**
```python
import os

def _store_opened_key(self, opened_key):
    master_key = os.environ['STEVE_MASTER_KEY'].encode()
    encrypted_key = bytes(a ^ b for a, b in zip(opened_key, master_key))
    self.c_set_opened_key(eid=self.eid, key=encrypted_key)

def _retrieve_opened_key(self):
    master_key = os.environ['STEVE_MASTER_KEY'].encode()
    encrypted_key = self.q_get_opened_key(eid=self.eid)
    return bytes(a ^ b for a, b in zip(encrypted_key, master_key))
```

**Implement vault client integration** in `open()` function

**Retrieve keys from vault** in `_all_metadata()` rather than database

### Acceptance Criteria
- [ ] External secrets manager integration designed
- [ ] Vault client implemented
- [ ] Key storage migrated to vault
- [ ] Vault reference stored in database
- [ ] Key retrieval updated to use vault
- [ ] OR master key XOR approach implemented
- [ ] Tests added for external key storage

### References
- CWE-320: Key Management Errors
- ASVS: 13.3.3
- Related: FINDING-067

### Priority
High

---

## Issue: FINDING-070 - Absence of Formal Sensitive Data Classification and Protection Levels
**Labels:** bug, security, priority:high
**Description:**
### Summary
The system processes at least six distinct categories of sensitive data (election cryptographic material, per-voter salts, vote content, vote tokens, voter PII, election metadata), each requiring different protection levels, but none are formally classified. Ad-hoc protections exist but no systematic framework ensures consistent handling.

### Details
- Six categories of sensitive data:
  1. Election cryptographic salt/opened_key
  2. Per-voter salts
  3. Vote content
  4. Vote tokens
  5. Voter PII
  6. Election metadata
- No formal classification
- Ad-hoc protections: salt exclusion in specific functions, vote encryption
- Protections are convention-based, comment-driven, function-specific
- Not architecturally enforced
- No systematic verification of consistent protection across all code paths
- Ballot secrecy guarantee cannot be verified as complete
- Violates ASVS 14.1.1 (L2)

**Affected files:**
- `v3/steve/election.py:146-157, 163`
- `v3/steve/persondb.py:38`
- `v3/server/pages.py:57, 603`
- `v3/schema.sql`

### Remediation
1. **Create formal data classification document:**
   - CRITICAL: Election keys, per-voter salts, vote tokens
   - SENSITIVE: Vote content, voter PII
   - INTERNAL: Election metadata
   - PUBLIC: Election titles, descriptions

2. **Implement defense-in-depth filtering** at template boundary:
```python
def sanitize_for_template(data, classification):
    """Remove fields based on classification."""
    if classification == 'CRITICAL':
        return {k: v for k, v in data.items() 
                if k not in ['salt', 'opened_key', 'vote_token']}
    # ...
```

3. **Update `postprocess_election()`** with classification awareness and verification

4. **Add classification verification tests:**
   - Test `get_metadata()` excludes CRITICAL fields
   - Test `get_issue()` excludes CRITICAL fields
   - Test template sanitization

5. **Implement classification-aware data access layer** with automatic field filtering

6. **Add runtime classification validation** in data processing functions

### Acceptance Criteria
- [ ] Data classification document created
- [ ] Classification tiers defined (CRITICAL/SENSITIVE/INTERNAL/PUBLIC)
- [ ] `sanitize_for_template()` function implemented
- [ ] `postprocess_election()` updated
- [ ] Classification verification tests added
- [ ] Data access layer implements automatic filtering
- [ ] Runtime validation added
- [ ] Documentation updated

### References
- CWE: Not specified
- ASVS: 14.1.1

### Priority
High

---

## Issue: FINDING-071 - Potential Sensitive Data Leakage Through Exception Logging During Vote Processing
**Labels:** bug, security, priority:high
**Description:**
### Summary
Exception messages during vote processing are logged without sanitization in `do_vote_endpoint`. If exceptions occur in `election.add_vote()`, `crypto.create_vote()`, or `crypto.gen_vote_token()`, the exception message may include plaintext vote content, cryptographic vote tokens, or per-voter salts, violating ballot secrecy.

### Details
- Exception details logged: `_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {e}')`
- Exception message may include:
  - Plaintext vote content (`votestring`)
  - Cryptographic vote tokens
  - Per-voter salts
- Violates ballot secrecy
- Exposes cryptographic material in application logs
- Violates ASVS 14.1.2 (L2)
- CWE-532: Insertion of Sensitive Information into Log File

**Affected files:**
- `v3/server/pages.py:~425-432`
- `v3/steve/election.py:~207`

### Remediation
**Remove exception details from logging:**

```python
# BEFORE (insecure):
_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {e}')

# AFTER (secure):
_LOGGER.error(
    f'Error adding vote for user on issue[I:{iid}] in election[E:{election.eid}]'
)
# Never include {e} in logs
```

**For debugging purposes:**
- Detailed exceptions should only go to secure debug logs with restricted access
- Separate from standard application logs

### Acceptance Criteria
- [ ] Exception details removed from standard logs
- [ ] Only non-sensitive metadata logged
- [ ] Secure debug logging mechanism created (if needed)
- [ ] Tests added verifying no sensitive data in logs
- [ ] Documentation updated on logging practices

### References
- CWE-532: Insertion of Sensitive Information into Log File
- ASVS: 14.1.2
- Related: FINDING-200

### Priority
High

---

## Issue: FINDING-072 - Complete Absence of Cache-Control Headers on All Sensitive Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
Pages displaying sensitive election data (voter eligibility, candidate lists, election structure, voting interfaces) are served without Cache-Control headers or equivalent meta tags. This allows browser back-button, history, and proxy caches to reveal voter participation, election structure, administrative access, and PII.

### Details
- No Cache-Control headers on sensitive endpoints
- Attack scenarios:
  - Shared workstations: next user presses Back button
  - Misconfigured proxy caches serving authenticated pages to wrong users
  - Browser forensics extracting cached election data
  - Mobile device theft allowing access to cached voting pages without authentication
- Affected endpoints: `/`, `/election/<eid>`, `/vote/<eid>`, `/vote-submit`, `/manage/<eid>`, `/profile`, `/settings`, plus 15+ more
- Data classification not enforced through caching policy
- Violates ASVS 14.1.2, 14.2.2, 14.2.4, 14.2.5, 14.3.2, 14.1.1 (L2/L3)
- CWE-524: Use of Cache Containing Sensitive Information

**Affected files:**
- `v3/server/pages.py:60, 137, 220, 283, 320, 343, 530, 540` (and 15+ more endpoints)

### Remediation
**Add after-request handler to set Cache-Control on all authenticated responses:**

```python
@APP.after_request
async def set_cache_control(response):
    """Prevent caching of sensitive authenticated content."""
    if response.mimetype == 'text/html':
        response.headers['Cache-Control'] = (
            'no-store, no-cache, must-revalidate, max-age=0'
        )
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
```

**Alternative: Create decorator for sensitive routes:**
```python
def no_cache(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        response = await func(*args, **kwargs)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    return wrapper

@APP.route('/vote/<eid>')
@no_cache
async def vote_on_page(eid):
    ...
```

### Acceptance Criteria
- [ ] After-request handler added OR decorator created
- [ ] Cache-Control headers set on all authenticated endpoints
- [ ] Headers include: no-store, no-cache, must-revalidate, max-age=0
- [ ] Pragma: no-cache header added
- [ ] Expires: 0 header added
- [ ] Tests added verifying headers present
- [ ] Documentation updated

### References
- CWE-524: Use of Cache Containing Sensitive Information
- ASVS: 14.1.2, 14.2.2, 14.2.4, 14.2.5, 14.3.2, 14.1.1
- Related: FINDING-016

### Priority
High

---

## Issue: FINDING-073 - Election Management Endpoints Lack Ownership Authorization
**Labels:** bug, security, priority:high
**Description:**
### Summary
Election management endpoints require only `R.committer` authentication but perform no ownership or authorization verification. Any authenticated committer can access `/manage/<eid>` for ANY election, receiving sensitive management data and being able to modify elections they don't own.

### Details
- Management endpoints only check `R.committer` authentication
- No ownership verification
- Any authenticated committer can:
  - Access `/manage/<eid>` for any election
  - Receive sensitive election management data
  - Modify elections via do-open, do-close, do-add-issue, do-edit-issue, do-delete-issue
- Exposes data exceeding minimum required for voter role
- Violates ASVS 14.2.6 (L3)

**Affected files:**
- `v3/server/pages.py:308, 355, 361, 423, 441, 457, 479, 500`

### Remediation
**Implement ownership/authz verification on all management endpoints:**

```python
def load_election_for_management(func):
    """Decorator that loads election and verifies ownership."""
    @wraps(func)
    async def wrapper(eid, *args, **kwargs):
        result = await basic_info()
        election = Election(eid)
        md = election.get_metadata()
        
        # Verify ownership or authorized group membership
        if md.owner_pid != result.uid:
            if md.authz:
                # Check LDAP group membership
                if not user_in_group(result.uid, md.authz):
                    abort(403, "Not authorized to manage this election")
            else:
                abort(403, "Not authorized to manage this election")
        
        return await func(eid, election, md, *args, **kwargs)
    return wrapper

@APP.route('/manage/<eid>')
@asfquart.auth.require(R.committer)
@load_election_for_management
async def manage_page(eid, election, md):
    ...
```

**Apply to all management endpoints:**
- `manage_page`
- `do_open_endpoint`
- `do_close_endpoint`
- `do_add_issue_endpoint`
- `do_edit_issue_endpoint`
- `do_delete_issue_endpoint`

### Acceptance Criteria
- [ ] `load_election_for_management` decorator created
- [ ] Ownership verification implemented
- [ ] Authorized group verification implemented
- [ ] Applied to all management endpoints
- [ ] 403 responses for unauthorized access
- [ ] Tests added for authorization enforcement

### References
- CWE: Not specified
- ASVS: 14.2.6

### Priority
High

---

## Issue: FINDING-074 - No Data Retention Classification for Any Sensitive Data Category
**Labels:** bug, security, priority:high
**Description:**
### Summary
The system handles multiple categories of sensitive data (encrypted votes, voter PII, per-voter cryptographic salts, election keys, voter-to-issue mappings) but no data retention classification exists. No retention periods, expiration timestamps, administrative interfaces, or scheduled processes for data lifecycle management.

### Details
- Multiple sensitive data categories with no retention classification:
  - Encrypted votes
  - Voter PII (names, emails)
  - Per-voter cryptographic salts
  - Election keys
  - Voter-to-issue mappings
- No retention period definitions
- No expiration timestamps in schema
- No administrative interfaces for data lifecycle management
- No scheduled processes for cleanup
- Sensitive data enters, is stored, remains indefinitely with no exit path
- Violates ASVS 14.2.7 (L3)

**Affected files:**
- `v3/schema.sql` (vote table, person table)
- `v3/steve/election.py:180-200, 64-78`
- `v3/steve/persondb.py:51-64`
- `v3/server/pages.py` (past_elections feature)

### Remediation
1. **Define data retention classification document:**
   - Encrypted votes: Retain per-policy (e.g., 2 years post-close)
   - Election keys: Delete after final tally verified
   - Per-voter salts: Delete after final tally verified
   - Person PII: Delete when no active elections reference them
   - Superseded votes: Delete immediately upon re-vote

2. **Add schema support:**
```sql
ALTER TABLE election ADD COLUMN tallied_at INTEGER;
ALTER TABLE vote ADD COLUMN created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'));
```

3. **Implement periodic cleanup process or CLI command:**
```python
def cleanup_expired_data():
    # Delete votes older than retention period
    # Delete keys for tallied elections
    # Delete PII for users with no active elections
    ...
```

### Acceptance Criteria
- [ ] Data retention classification document created
- [ ] Retention periods defined for each data type
- [ ] Schema updated with timestamp columns
- [ ] Cleanup process or CLI command implemented
- [ ] Scheduled cleanup configured (if applicable)
- [ ] Tests added for data retention enforcement
- [ ] Documentation updated

### References
- CWE: Not specified
- ASVS: 14.2.7

### Priority
High

---

## Issue: FINDING-075 - Election Cryptographic Key Material Persisted Indefinitely After Use
**Labels:** bug, security, priority:high
**Description:**
### Summary
When an election is opened, cryptographic values (16-byte salt, 32-byte opened_key) are stored and remain in the database forever after tallying completes. Future database compromise would allow retroactive decryption of votes from all past elections, violating ballot secrecy.

### Details
- Cryptographic material stored when election opened:
  - 16-byte salt
  - 32-byte opened_key
  - Per-voter salts
- Material remains after election closed and tallied
- No purge mechanism
- Combination of `election.opened_key` + `election.salt` + `mayvote.salt` enables decryption of all votes
- After tallying, keys serve no operational purpose
- Future database compromise allows retroactive vote decryption for all past elections
- Violates ballot secrecy goal
- Violates ASVS 14.2.7, 11.2.2 (L2/L3)

**Affected files:**
- `v3/schema.sql` (election table, mayvote table)
- `v3/steve/election.py:64-78, 80-90, 217-255, 50-60`

### Remediation
**Add algorithm version fields:**

```sql
-- For vote table
ALTER TABLE vote ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;

-- For election and mayvote tables
ALTER TABLE election ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE mayvote ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
```

**Relax fixed-length CHECK constraints:**
```sql
-- Instead of: CHECK (length(salt) = 16)
-- Use: CHECK (salt IS NULL OR length(salt) >= 16)
```

This enables:
- Phased migration where new data uses new algorithms
- Old data processed with legacy algorithms based on version field
- Future algorithm upgrades without breaking changes

**Implement key destruction after tally:**
```python
def destroy_keys_after_tally(self):
    """Destroy cryptographic material after tally verified."""
    if not self.is_tallied():
        raise ValueError("Can only destroy keys after tally")
    
    # SET salt=NULL, opened_key=NULL
    self.c_destroy_election_keys(eid=self.eid)
    
    # SET mayvote.salt=NULL
    self.c_destroy_voter_salts(eid=self.eid)
    
    # Log destruction
    _LOGGER.info(f"Keys destroyed for election {self.eid}")
```

### Acceptance Criteria
- [ ] Algorithm version fields added to schema
- [ ] CHECK constraints relaxed for variable-length outputs
- [ ] Key destruction method implemented
- [ ] Destruction integrated into post-tally workflow
- [ ] Logging added for key destruction
- [ ] Tests added for versioned crypto and key destruction

### References
- CWE: Not specified
- ASVS: 14.2.7, 11.2.2

### Priority
High

---

## Issue: FINDING-076 - No Documentation Classifying Third-Party Component Risk Levels
**Labels:** bug, security, priority:high
**Description:**
### Summary
No documentation exists identifying, classifying, or highlighting third-party libraries based on risk profile. ASVS 15.1.4 requires documentation flagging 'risky components' - libraries that are poorly maintained, unsupported, EOL, or have significant vulnerability history.

### Details
- No risk classification for dependencies
- At least five packages warrant explicit risk documentation:
  - `asfpy` and `asfquart`: ASF-internal libraries without broad public security review
  - `easydict`: Small convenience library, minimal maintenance, narrow contributor base, used for security-sensitive data (election metadata with salt and opened_key)
  - `argon2-cffi` low-level API: Bypasses higher-level safety defaults
- `easydict` converts dict keys to object attributes (could mask key collisions or unexpected attribute access)
- Without risk assessment:
  - Vulnerability response timeframes cannot be differentiated by component risk
  - No documented update cadence for risky vs. standard components
- Violates ASVS 15.1.4 (L3)

**Affected files:**
- `v3/steve/crypto.py:25-28`
- `v3/steve/election.py:22-24, 146-156, 216, 259, 310`
- `v3/server/main.py:37`

### Remediation
**Create dependency risk assessment document** (e.g., `DEPENDENCIES.md` or integrate into SBOM):

**Classify each component with:**
1. Risk Level (Critical/High/Medium/Low)
2. Justification (maintenance status, security review process, contributor base, CVE history)
3. Mitigations (version pinning, monitoring strategy, alternative evaluation timeline)
4. Review Cadence (Critical: weekly, High: monthly, Medium/Low: quarterly)

**Document vulnerability response timeframes:**
- Critical CVE in risky component: Patch within 24 hours
- High CVE in risky component: Patch within 72 hours

**Component classifications:**

**Dangerous Functionality (Critical risk):**
- `cryptography`, `argon2-cffi`: Cryptographic operations

**Risky Components (High risk):**
- `asfquart`, `asfpy`: Internal ASF libraries without broad security review
- `easydict`: Minimal maintenance, narrow contributor base, used for security-sensitive data

**Consider replacing easydict:**
- Use Python standard library alternatives:
  - `dataclasses` (Python 3.7+)
  - `typing.NamedTuple`
- Eliminates dependency on minimally-maintained library for security-sensitive structures

### Acceptance Criteria
- [ ] Dependency risk assessment document created
- [ ] All dependencies classified by risk level
- [ ] Justifications documented
- [ ] Mitigations specified
- [ ] Review cadence defined
- [ ] Vulnerability response timeframes documented
- [ ] easydict replacement evaluated
- [ ] Documentation updated

### References
- CWE: Not specified
- ASVS: 15.1.4

### Priority
High

---

## Issue: FINDING-077 - cryptography.hazmat and argon2.low_level API Usage Not Documented as Dangerous Functionality
**Labels:** bug, security, priority:high
**Description:**
### Summary
The codebase uses two explicitly dangerous low-level cryptographic APIs without formal documentation: `cryptography.hazmat` module (explicitly named 'hazardous materials' with warnings about misuse) and `argon2.low_level` module (bypasses high-level safety features). ASVS 15.1.5 requires documentation highlighting 'dangerous functionality' usage.

### Details
- Two dangerous low-level APIs used:
  1. `cryptography.hazmat`: Explicitly named "hazardous materials" by maintainers
  2. `argon2.low_level`: Bypasses parameter validation, automatic encoding, type selection
- Library documentation states: "This is a Hazardous Materials module. You should ONLY use it if you're 100% absolutely sure that you know what you're doing."
- Only brief inline comments exist
- No formal documentation:
  - Inventorying all hazmat/low-level crypto usage
  - Explaining why high-level APIs insufficient
  - Documenting security review status
  - Identifying specific risks of each operation
- APIs are foundation for vote encryption/decryption and election integrity
- Violates ASVS 15.1.5 (L3)

**Affected files:**
- `v3/steve/crypto.py:23, 25, 26, 62, 92-103`

### Remediation
**Create `SECURITY.md` or architecture document section** inventorying dangerous functionality:

**1. cryptography.hazmat (HKDF-SHA256 in `_b64_vote_key`):**
- **Purpose:** Key stretching of vote tokens
- **Justification:** Low-level API required for specific Fernet key format
- **Risk:** Incorrect parameter selection could weaken encryption keys
- **Parameters:** SHA256, 32-byte output, salt from vote_token, info='xchacha20_key' (note: should match actual algorithm)

**2. argon2.low_level (Argon2 hashing in `_hash`):**
- **Purpose:** opened_key generation and vote tokens
- **Justification:** Low-level API required for raw byte output (high-level returns encoded string)
- **Risk:** Incorrect parameter tuning could weaken brute-force resistance
- **Parameters:** time_cost=2, memory_cost=64MB, parallelism=4, Type=D (note: should be Type.ID per RFC 9106)

**3. Include:**
- Security review status
- Date of last cryptographic review
- Documentation that modules require specialized cryptographic expertise for modifications

### Acceptance Criteria
- [ ] Dangerous functionality inventory created
- [ ] cryptography.hazmat usage documented
- [ ] argon2.low_level usage documented
- [ ] Purpose and justification for each
- [ ] Risks identified
- [ ] Parameters documented
- [ ] Security review status included
- [ ] Expertise requirements documented

### References
- CWE: Not specified
- ASVS: 15.1.5

### Priority
High

---

## Issue: FINDING-078 - Vote Decryption/Tallying Functionality Lacks Process Isolation from Web Attack Surface
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `tally_issue()` method, which decrypts all encrypted votes, runs in the same process as web-facing request handlers. The `opened_key` (master key for all vote decryption) is loaded into web server process memory during tallying with no process isolation, privilege separation, sandboxing, or network isolation.

### Details
- `tally_issue()` in same Election class as web handlers
- Runs in same process as web-facing code
- `opened_key` loaded into web server process memory during tallying
- No process isolation
- No privilege separation
- No sandboxing
- No network isolation
- Vulnerability in any web handler could allow:
  - Invoking `tally_issue()`
  - Accessing `opened_key` in process memory
  - Compromising all vote secrecy
- `__getattr__` proxy exposes all database cursors to any code with Election instance:
  - Bypasses state-machine protections
  - Direct access to `c_delete_election`, `c_open`, `c_close`, `c_add_vote` without state checks
- Violates ASVS 15.2.5, 11.7.2 (L3)

**Affected files:**
- `v3/steve/election.py:56, 284-349`
- `v3/steve/crypto.py:82-87`

### Remediation
**Implement process-level separation for tallying:**

**Option A (recommended for L3 compliance): Separate tallying service:**

```python
import multiprocessing

def isolated_tally(eid, issue_id):
    """Run tally in separate process."""
    election = Election(eid)
    try:
        result = election.tally_issue(issue_id)
        return result
    finally:
        # Destroy key material when subprocess exits
        election.destroy_keys()

def tally_with_isolation(eid, issue_id):
    """Tally in isolated process."""
    process = multiprocessing.Process(
        target=isolated_tally,
        args=(eid, issue_id)
    )
    process.start()
    process.join()
    
    # Drop capabilities after opening database (Linux)
    # Use prctl or similar
```

**Run tally service in separate container** with minimal permissions

**Communicate results via IPC** (pipe/queue) rather than shared memory

**Option B (minimum): Restrict Election class API surface:**

```python
# Remove __getattr__ proxy entirely
# OR use allowlist:

_ALLOWED_ATTRS = frozenset([
    'q_get_metadata',
    'q_get_issues',
    # ... explicit list
])

def __getattr__(self, item):
    if item not in _ALLOWED_ATTRS:
        raise AttributeError(f"'{item}' not permitted")
    return self.db.get_cursor(item)
```

**Create separate `TallyElection` subclass** for privileged operations:
- Only instantiable from CLI/privileged context
- Not exposed via web endpoints

**Document:** Tally operations must never be exposed via web endpoints

### Acceptance Criteria
- [ ] Process isolation implemented for tallying OR
- [ ] API surface restricted with allowlist
- [ ] `TallyElection` subclass created for privileged ops
- [ ] Tally operations documented as CLI-only
- [ ] Separate container deployment option documented
- [ ] IPC communication implemented (if separate process)
- [ ] Tests added for isolation
- [ ] Documentation updated

### References
- CWE: Not specified
- ASVS: 15.2.5, 11.7.2

### Priority
High

---

## Issue: FINDING-079 - Authorization Failures Not Logged at Multiple Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
Multiple endpoints perform authorization checks (PersonDB lookup, mayvote eligibility verification, document access control) but silently deny access by returning 404 responses without creating any log entry. Authorization failures are high-signal security events indicating potential attacks or misconfigurations.

### Details
- Authorization failures return 404 without logging
- Affected endpoints:
  - `vote_on_page()`: Voter eligibility checks
  - `serve_doc()`: Document access authorization
  - `admin_page()`: Admin access control
- Prevents detection of:
  - Unauthorized access attempts
  - Privilege escalation probing
  - Reconnaissance attacks
- No visibility for security incident investigation
- No pattern detection capability
- Affects 16+ authenticated endpoints
- Violates ASVS 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3 (L2/L3)

**Affected files:**
- `v3/server/pages.py:250, 294-299, 356-366, 274-279, 241-247, 274-354, 308, 547, 607-611, 494-499, 589-625, 246-251, 610-614`

### Remediation
**Add `_LOGGER.warning()` calls before all authorization failure responses:**

```python
# Example for vote_on_page:
if not eligible:
    _LOGGER.warning(
        f'AUTHZ_DENIED: User[U:{result.uid}] attempted to access '
        f'election[E:{election.eid}] without voter eligibility. '
        f'source_ip={quart.request.remote_addr}'
    )
    return await render_template('404.html'), 404

# Example for serve_doc:
if not authorized:
    _LOGGER.warning(
        f'AUTHZ_DENIED: User[U:{result.uid}] attempted to access '
        f'document for issue[I:{iid}] (file: {docname}) without eligibility. '
        f'source_ip={quart.request.remote_addr}'
    )
    return await render_template('404.html'), 404
```

**Include in logs:**
- User ID
- Requested resource (election ID, issue ID, document name)
- IP address (`quart.request.remote_addr`)
- Reason for denial

**Consider rate limiting detection:**
```python
if failure_count_5min >= 10:
    _LOGGER.error(
        f'POSSIBLE_ATTACK: User[U:{result.uid}] exceeded authorization '
        f'failure threshold. source_ip={quart.request.remote_addr}'
    )
```

### Acceptance Criteria
- [ ] Authorization failure logging added to all endpoints
- [ ] User ID logged
- [ ] Requested resource logged
- [ ] IP address logged
- [ ] Denial reason logged
- [ ] Rate limiting detection considered
- [ ] Tests added for logging

### References
- CWE: Not specified
- ASVS: 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3

### Priority
High

---

## Issue: FINDING-080 - No Authentication Event Logging Framework
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application uses `@asfquart.auth.require` decorators for OAuth-based authentication across 15+ endpoints but never logs authentication operation outcomes. No handlers exist for before_request, after_request, or 401/403 errors.

### Details
- OAuth authentication via `@asfquart.auth.require` decorators on 15+ endpoints
- No authentication event logging
- No `@APP.before_request` handler
- No `@APP.after_request` handler
- No error handler for 401/403 responses
- OAuth flow completion (success or failure) not recorded
- In election system, impossible to:
  - Detect unauthorized access attempts
  - Create forensic trail for security incidents
  - Verify only authorized individuals accessed system during election
  - Meet compliance requirements for election auditing
- Violates ASVS 16.3.1 (L2)

**Affected files:**
- `v3/server/pages.py:63-92`
- `v3/server/main.py:36-48`

### Remediation
**Add before_request handler for authentication logging:**

```python
@APP.before_request
async def log_authentication():
    """Log authentication outcomes for protected endpoints."""
    # Check if endpoint requires authentication
    if request.endpoint and hasattr(APP.view_functions[request.endpoint], '_auth_required'):
        result = await basic_info()
        if result:
            _LOGGER.info(
                f'AUTH_SUCCESS: User[U:{result.uid}] authenticated. '
                f'endpoint={request.endpoint} '
                f'source_ip={request.remote_addr} '
                f'user_agent={request.user_agent}'
            )
```

**Add error handlers for authentication failures:**

```python
@APP.errorhandler(401)
async def log_auth_failure_401(error):
    """Log authentication rejections."""
    _LOGGER.warning(
        f'AUTH_REJECTED: Authentication failed (401). '
        f'endpoint={request.endpoint} '
        f'source_ip={request.remote_addr} '
        f'user_agent={request.user_agent}'
    )
    return error

@APP.errorhandler(403)
async def log_auth_failure_403(error):
    """Log authorization failures."""
    _LOGGER.warning(
        f'AUTHZ_DENIED: Authorization failed (403). '
        f'endpoint={request.endpoint} '
        f'source_ip={request.remote_addr} '
        f'user_agent={request.user_agent}'
    )
    return error
```

**Include metadata in all authentication logs:**
- User ID (if available)
- IP address (`quart.request.remote_addr`)
- User agent
- Request path
- Authentication method

### Acceptance Criteria
- [ ] Before_request handler added for authentication logging
- [ ] Error handlers added for 401/403
- [ ] User ID logged (when available)
- [ ] IP address logged
- [ ] User agent logged
- [ ] Request path logged
- [ ] Authentication method logged
- [ ] Tests added for authentication logging

### References
- CWE: Not specified
- ASVS: 16.3.1

### Priority
High

## Issue: FINDING-081 - Input Validation and Business Logic Bypass Attempts Not Logged
**Labels:** bug, security, priority:high
**Description:**
### Summary
ASVS 16.3.3 requires logging of attempts to bypass security controls, such as input validation, business logic, and anti-automation. The application performs input validation and business logic checks but does not log when these checks fail. This includes invalid issue IDs in votes, empty vote submissions, invalid date formats, and election state machine violations (enforced by assert statements). This makes automated attacks, fuzzing attempts, and manipulation attempts invisible to security monitoring.

### Details
**Affected Files:**
- `v3/server/pages.py:420-422`
- `v3/server/pages.py:413-415`
- `v3/server/pages.py:107-111`

**ASVS References:** 16.3.3 (L2)

Attackers can probe the system without generating any alerts. Input validation failures in vote submission, date parsing, and state transitions occur silently without audit trail.

### Remediation
Add `_LOGGER.warning()` calls for all input validation failures with context about the invalid input. Log user ID, election/issue ID, validation type that failed, and the invalid value (sanitized). Implement rate limiting on validation failures to prevent fuzzing attacks. Add SIEM rules to alert on high volumes of validation failures.

Example:
```python
_LOGGER.warning('INPUT_VALIDATION_FAILED: User[U:%s] submitted vote with invalid issue[I:%s] in election[E:%s]. valid_issues=%s', 
                result.uid, iid, election.eid, list(issue_dict.keys()))
```

### Acceptance Criteria
- [ ] Input validation failures logged with user context
- [ ] Rate limiting implemented on validation failures
- [ ] SIEM alerting rules documented
- [ ] Test added for logging behavior

### References
- Source: 16.3.3.md
- Related: FINDING-082

### Priority
High

---

## Issue: FINDING-082 - Election State Violation Attempts Not Logged (Assert-Based Enforcement)
**Labels:** bug, security, priority:high
**Description:**
### Summary
The Election class enforces business logic rules about which operations are valid in each election state (editable, open, closed) using Python assert statements. These assertions produce no log output when they fail, are disabled by Python's -O optimization flag, and raise generic AssertionError exceptions with no security context. Attempts to bypass these business logic controls are invisible to security monitoring.

### Details
**Affected Files:**
- `v3/steve/election.py:57, 61, 77, 82, 128, 135, 137, 196, 197, 215, 216, 228, 248, 257, 268`

**ASVS References:** 16.3.3 (L2), 16.5.3 (L3)

Multiple methods use assert for security-critical state checks including `delete()`, `open()`, `close()`, `add_salts()`, `add_issue()`, `edit_issue()`, `delete_issue()`, and `add_voter()`. Attempts to vote on closed elections, modify opened elections, or add issues to closed elections generate no audit trail.

### Remediation
Replace all assert statements used for security/business logic with explicit state validation that includes logging. Create a `_require_state()` helper method that logs state violations before raising exceptions.

Example:
```python
def _require_state(self, required_state, operation):
    current = self.get_state()
    if current != required_state:
        _LOGGER.warning('STATE_VIOLATION: election[E:%s] operation=%s current_state=%s required_state=%s', 
                        self.eid, operation, current, required_state)
        raise ElectionBadState(...)
```

Apply to all state-dependent methods. Add enhanced exception handlers in `pages.py` to log business logic violations with user context.

### Acceptance Criteria
- [ ] Assert statements replaced with explicit validation
- [ ] State violations logged with context
- [ ] Exception handlers enhanced in pages.py
- [ ] Tests added for state violation logging

### References
- Source: 16.3.3.md, 16.5.3.md
- Related: FINDING-081

### Priority
High

---

## Issue: FINDING-083 - No Log Immutability or Write-Protection Controls
**Labels:** bug, security, priority:high
**Description:**
### Summary
`logging.basicConfig()` is called without a filename parameter, directing all log output to sys.stderr. There is no configuration for file-based logging with restricted permissions, append-only or write-once log storage, remote/centralized log forwarding (e.g., syslog, SIEM), cryptographic integrity verification of log entries, or log rotation with retention guarantees. An attacker with process-level or filesystem access can redirect stderr to /dev/null, modify or delete log files, or tamper with forensic evidence.

### Details
**Affected Files:**
- `v3/server/main.py:52-59`
- `v3/server/main.py:84-91`

**ASVS References:** 16.4.2 (L2), 16.4.3 (L2)

The entire auditing chain that the election system's security model depends upon can be undermined by an attacker with sufficient access.

### Remediation
Configure a remote log handler in addition to local output. At minimum, add a SysLogHandler targeting a separate log aggregation server using TCP for reliable delivery. Implement structured format for SIEM ingestion.

For production election systems, consider:
1. TLS-encrypted syslog (RFC 5425) to prevent log interception in transit
2. SIEM integration (Splunk HEC, Elasticsearch, etc.) via dedicated handlers
3. Write-once storage (S3 with Object Lock, immutable log volumes)
4. Log signing to detect tampering of archived logs

### Acceptance Criteria
- [ ] Remote log handler configured
- [ ] Structured logging format implemented
- [ ] Log forwarding tested
- [ ] Documentation for production deployment

### References
- Source: 16.4.2.md, 16.4.3.md
- Merged from: AUDIT_LOGGING-017

### Priority
High

---

## Issue: FINDING-084 - Missing Vote Content Validation - Invalid Votes Stored Without Validation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `add_vote()` method contains a TODO comment where vote content validation should occur but has no implementation. Any arbitrary string is accepted, encrypted, and stored as a vote regardless of the issue's vote type (yna or stv). This is a fail-open condition where the validation step is absent, and the transaction (vote storage) proceeds unconditionally. Invalid votes corrupt election tallying results.

### Details
**Affected Files:**
- `v3/steve/election.py:260`
- `v3/server/pages.py:437`

**ASVS References:** 16.5.3 (L3)

For YNA: non-standard vote strings may be counted or cause tally errors. For STV: malformed ranking data could crash the STV algorithm or produce incorrect seat allocations.

### Remediation
Implement vote content validation in the `add_vote()` method. Validate votestring against the issue type by retrieving the issue, loading its vtype module, and calling a `validate(votestring, kv)` function. Each vtype module should implement validation logic (e.g., `vtypes/yna.py` validates that votestring is in ('y', 'n', 'a'); `vtypes/stv.py` validates ranking format and candidate labels). Raise `InvalidVote(iid, votestring)` exception if validation fails. Log validation failures with `_LOGGER.warning()` including user ID and issue ID.

### Acceptance Criteria
- [ ] Vote validation implemented in add_vote()
- [ ] Validation functions added to vtype modules
- [ ] Invalid votes rejected with appropriate exception
- [ ] Validation failures logged
- [ ] Tests added for each vote type

### References
- Source: 16.5.3.md
- Related: FINDING-095, FINDING-099

### Priority
High

---

## Issue: FINDING-085 - CLI Tally Tool Lacks Top-Level Exception Handler
**Labels:** bug, security, priority:high
**Description:**
### Summary
The CLI tally tool, which processes election results and is likely run as a scheduled job or manual administrative task, lacks any top-level exception handling. The `__main__` block invokes `main()` without any try/except wrapper, and errors within `tally_election()` are printed to stdout rather than logged. This means tallying errors during election processing are lost if stderr is not captured by the deployment environment, and error details critical for audit trails are not recorded in structured log format.

### Details
**Affected Files:**
- `v3/server/bin/tally.py:172-185`
- `v3/server/bin/tally.py:125-126`

**ASVS References:** 16.5.4 (L3)

This violates ASVS 16.5.4 requirement for a last resort error handler.

### Remediation
Wrap the `main()` call in a try/except block with structured logging. Catch `ElectionNotFound`, `ElectionBadState`, and general `Exception` separately with appropriate exit codes. Log all errors using `_LOGGER` with appropriate severity levels.

Example:
```python
try:
    main(args.spy_on_open_elections, args.election_id, args.issue_id, args.db_path, args.output)
except steve.election.ElectionNotFound as e:
    _LOGGER.error('Election not found: %s', e)
    sys.exit(2)
except Exception:
    _LOGGER.critical('Unexpected error during tally', exc_info=True)
    sys.exit(99)
```

Also fix `tally_election()` to use `_LOGGER.error()` instead of `print()`.

### Acceptance Criteria
- [ ] Top-level exception handler added
- [ ] All error paths use structured logging
- [ ] Exit codes documented
- [ ] Tests added for error scenarios

### References
- Source: 16.5.4.md

### Priority
High

---

## Issue: FINDING-086 - add_vote Crashes on Missing Voter Eligibility Record Instead of Failing Securely
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `add_vote` method retrieves voter eligibility records from the database but does not check for null results. When a voter attempts to vote on an issue they're not eligible for, the database query returns None, and the subsequent access to `mayvote.salt` raises an AttributeError instead of a proper authorization failure. This results in insecure authorization check failure, polluted security audit trails with implementation errors instead of authorization failure events, and could mask attacks where users attempt to vote on unauthorized issues.

### Details
**Affected Files:**
- `v3/steve/election.py:207-218`

**ASVS References:** 16.5.2 (L2)

This violates ASVS 16.5.2 requirement for graceful degradation on external resource failure.

### Remediation
Add null check after `q_get_mayvote.first_row()` call. If the result is None, log a warning about authorization failure and raise a custom `VoterNotEligible` exception with proper context (pid, iid).

Example:
```python
mayvote = self.q_get_mayvote.first_row(pid, iid)
if not mayvote:
    _LOGGER.warning(f'AUTHZ_DENIED: User[U:{pid}] attempted to vote on issue[I:{iid}] without eligibility')
    raise VoterNotEligible(pid, iid)
```

This ensures authorization failures are handled explicitly and recorded correctly in audit logs.

### Acceptance Criteria
- [ ] Null check added after eligibility query
- [ ] Custom VoterNotEligible exception created
- [ ] Authorization failures logged appropriately
- [ ] Tests added for unauthorized vote attempts

### References
- Source: 16.5.2.md

### Priority
High

---

## Issue: FINDING-087 - Election Close Operation Not Atomic — No State Guard in SQL
**Labels:** bug, security, priority:high
**Description:**
### Summary
The election close operation performs a state check and state update as separate database operations without transactional protection or atomic state verification in the UPDATE statement. This creates a race condition where multiple close requests can execute concurrently, and more critically, allows votes to be submitted during the close operation. The `c_close` SQL likely does not include WHERE clause checking current state (e.g., `WHERE closed IS NULL OR closed = 0`), meaning it doesn't atomically verify the election was actually open before closing.

### Details
**Affected Files:**
- `v3/steve/election.py:121-127`
- `v3/steve/election.py:108-113`
- `v3/steve/election.py:121-128`
- `v3/server/pages.py:482`
- `v3/server/pages.py:378`

**ASVS References:** 15.4.1 (L3), 15.4.2 (L3), 15.4.3 (L3)
**CWE:** CWE-362

### Remediation
Use an atomic UPDATE with a state-checking WHERE clause:
```sql
UPDATE election SET closed=1 
WHERE eid=? AND salt IS NOT NULL AND opened_key IS NOT NULL 
AND (closed IS NULL OR closed = 0)
```

Verify `rowcount == 1` after execution. Raise `ElectionBadState` exception if the update affects 0 rows, indicating the election was not in the expected state. Wrap in BEGIN IMMEDIATE transaction.

### Acceptance Criteria
- [ ] SQL UPDATE includes state verification
- [ ] Rowcount verification added
- [ ] Transaction boundary enforced
- [ ] Tests added for concurrent close attempts
- [ ] Tests added for vote-during-close scenarios

### References
- Source: 15.4.1.md, 15.4.2.md, 15.4.3.md
- Related: FINDING-023, FINDING-024

### Priority
High

---

## Issue: FINDING-088 - Election Delete — State Assertion Before Transaction Creates Race Window (TOCTOU)
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `delete()` function asserts that the election is editable before beginning a transaction to delete the election and its related data. This state check occurs outside the transaction boundary, allowing a concurrent request to open the election after the check passes but before the transaction begins, resulting in deletion of an active election. Between `assert self.is_editable()` passing and BEGIN TRANSACTION executing, a concurrent request could open the election via `open()`. The delete then proceeds on an election that is now open, destroying an active election with salts and voter data.

### Details
**Affected Files:**
- `v3/steve/election.py:48-65`

**ASVS References:** 15.4.2 (L3)
**CWE:** CWE-367

### Remediation
Move the state check inside the transaction boundary. Use BEGIN IMMEDIATE before checking state, then verify the election is editable using `_all_metadata(self.S_EDITABLE)` within the transaction. This ensures the state check and deletion operations are atomic. Include proper exception handling with ROLLBACK on failure.

### Acceptance Criteria
- [ ] State check moved inside transaction
- [ ] BEGIN IMMEDIATE used
- [ ] Exception handling with ROLLBACK added
- [ ] Tests added for concurrent delete/open scenarios

### References
- Source: 15.4.2.md
- Related: FINDING-025

### Priority
High

---

## Issue: FINDING-089 - Synchronous Blocking Database I/O in Async Event Loop Without Thread Pool
**Labels:** bug, security, priority:high
**Description:**
### Summary
Election opening performs CPU-intensive Argon2 key derivation and holds a database write lock during an unbounded iteration over all voter-issue combinations. The entire operation executes synchronously in the async event loop, blocking all concurrent requests for potentially 1-5+ seconds depending on election size and Argon2 parameters. The `add_salts()` transaction holds SQLite's file-level write lock for the entire iteration over potentially hundreds of voter-issue combinations, blocking even separate database connections from writing. Argon2 key derivation is deliberately CPU-intensive; running it synchronously in the event loop blocks all async task scheduling for its full duration. Combined, these create a multi-second window where the application is completely unresponsive.

### Details
**Affected Files:**
- `v3/steve/election.py:38-43`
- `v3/server/pages.py:181`
- `v3/server/pages.py:399-432`
- `v3/server/pages.py:144-172`

**ASVS References:** 15.4.4 (L3)

### Remediation
Wrap all synchronous Election method calls in `asyncio.to_thread()` to offload them to a thread pool.

Example:
```python
e = await asyncio.to_thread(steve.election.Election, DB_FNAME, eid)
```

Alternatively, adopt an async SQLite driver such as aiosqlite for native async database operations. Configure thread pool size via `asyncio.get_event_loop().set_default_executor(ThreadPoolExecutor(max_workers=N))` to match expected concurrency.

### Acceptance Criteria
- [ ] All Election method calls wrapped in to_thread()
- [ ] Thread pool configured appropriately
- [ ] Performance testing under concurrent load
- [ ] Documentation updated with concurrency model

### References
- Source: 15.4.4.md
- Merged from: MISC-010

### Priority
High

---

## Issue: FINDING-090 - No Application-Level Memory Protection for Sensitive Cryptographic Material
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application handles highly sensitive cryptographic material (encryption keys, plaintext votes, voter tokens) but implements no memory protection mechanisms. Python's immutable bytes and str objects cannot be overwritten, and no memory locking or zeroing is performed. Specific concerns include: (1) Immutable bytes for keys persist until garbage collected with no guaranteed zeroing, (2) Immutable str for plaintext votes cannot be zeroed, (3) No mlock() means sensitive memory pages can be swapped to disk, (4) Bulk accumulation during tally where the entire election's decrypted votes exist in memory simultaneously. A memory dump during vote submission or tallying could recover plaintext votes, cryptographic keys, and voter-to-vote mappings.

### Details
**Affected Files:**
- `v3/steve/crypto.py:60-71, 74-79, 82-87, 40-50`
- `v3/steve/election.py:262-320, 247-260`
- `v3/server/bin/tally.py:103-145`

**ASVS References:** 11.7.1 (L3)

### Remediation
Implement secure memory handling:

```python
import ctypes
import mmap
import os

def secure_zero(data: bytearray):
    """Securely zero a mutable byte buffer."""
    ctypes.memset(ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data)), 0, len(data))

def _b64_vote_key(vote_token: bytes, salt: bytes) -> tuple[bytes, bytearray]:
    """Key-stretch the vote_token, returning key and a cleanup handle."""
    keymaker = hkdf.HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'fernet_vote_key',
    )
    # Use mutable bytearray for key material
    vote_key = bytearray(keymaker.derive(vote_token))
    b64key = base64.urlsafe_b64encode(bytes(vote_key))
    secure_zero(vote_key)  # Zero the raw key immediately
    return b64key

# For tallying, process and aggregate incrementally rather than accumulating all plaintext
def tally_issue_secure(self, iid):
    """Process votes one at a time, zeroing each after processing."""
    tally_accumulator = vtypes.vtype_module(issue.type).create_accumulator()
    for mayvote in self.q_tally.fetchall():
        vote_token = crypto.gen_vote_token(md.opened_key, mayvote.pid, iid, mayvote.salt)
        row = self.q_recent_vote.first_row(vote_token)
        if row is None:
            continue
        votestring = crypto.decrypt_votestring(vote_token, mayvote.salt, row.ciphertext)
        tally_accumulator.add(votestring)
        del votestring  # Hint to GC
    return tally_accumulator.result()
```

Additionally, deploy with: OS-level memory encryption (Intel TME, AMD SME/SEV), mlockall(MCL_CURRENT | MCL_FUTURE) to prevent swapping, and disable core dumps for the application process.

### Acceptance Criteria
- [ ] Secure memory zeroing implemented
- [ ] Incremental tally processing implemented
- [ ] Memory locking configured for production
- [ ] Core dumps disabled
- [ ] Documentation for deployment requirements

### References
- Source: 11.7.1.md

### Priority
High

---

## Issue: FINDING-091 - Stored XSS via Flash Messages Containing Unencoded User Input
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Flash messages are constructed by interpolating user-controlled values (election titles, issue titles, issue IDs extracted from form field names) directly into message strings using Python f-strings without HTML encoding. These messages are stored in the session and rendered in flashes.ezt without the `[format "html"]` directive. The `iid` in `do_vote_endpoint` is extracted from form field names (`vote-<iid>`), making it directly controllable by the requester. XSS executes on the page redirect after a state-changing action. Primarily a self-XSS risk for the attacker's own session, but could be exploited if combined with CSRF.

### Details
**Affected Files:**
- `v3/server/templates/flashes.ezt:1-6`
- `v3/server/pages.py:413, 426, 447, 455, 504, 508, 518, 533, 535, 537, 598`

**ASVS References:** 1.1.1 (L1), 1.1.2 (L1), 1.2.1 (L2)
**CWE:** CWE-79

### Remediation
Either encode at the template level by changing `[flashes.message]` to `[format "html"][flashes.message][end]`, or encode when constructing flash messages using `html.escape()`.

Example:
```python
await flash_success(f'Created election: {html.escape(form.title)}')
await flash_danger(f'Invalid issue ID: {html.escape(iid)}')
await flash_success(f'Issue "{html.escape(form.title)}" has been added.')
```

### Acceptance Criteria
- [ ] HTML encoding applied to all flash messages
- [ ] Template updated or message construction fixed
- [ ] Tests added for XSS prevention
- [ ] Code review for other user-controlled output

### References
- Source: 1.1.1.md, 1.1.2.md, 1.2.1.md
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-113, FINDING-114

### Priority
Medium

---

## Issue: FINDING-092 - Missing Upper-Bound Range Validation on STV `seats` Integer Parameter
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The STV election type accepts a `seats` parameter that determines how many candidates should be elected. While the CLI import tool validates that `seats` is a positive integer, there is no upper-bound validation anywhere in the codebase. The core API function `election.add_issue()` performs no validation on the `kv` dictionary contents at all, creating a defense-in-depth gap. This allows extreme values (e.g., INT32_MAX: 2147483647) to pass validation, get stored in the database, and be passed to `stv_tool.run_stv()` during tallying. Depending on the STV algorithm's implementation, this could exhaust memory, produce logically incorrect election results if seats exceeds the number of candidates, or cause integer overflow if the underlying STV tool uses C-based numeric processing.

### Details
**Affected Files:**
- `v3/server/bin/create-election.py:60-61`
- `v3/steve/election.py:174`
- `v3/steve/vtypes/stv.py:65`

**ASVS References:** 1.4.2 (L2)

### Remediation
Add range validation at multiple layers for defense-in-depth:

1. In `election.py:add_issue()` - API layer validation to check seats is positive integer, seats <= 100 (reasonable upper bound), and seats <= len(labelmap)
2. In `stv.py:tally()` - validate before algorithm execution
3. In `create-election.py:validate_issue()` - add upper bound check

### Acceptance Criteria
- [ ] Upper bound validation added to add_issue()
- [ ] Validation added to STV tally function
- [ ] CLI tool validation enhanced
- [ ] Tests added for boundary conditions
- [ ] Documentation updated with limits

### References
- Source: 1.4.2.md

### Priority
Medium

---

## Issue: FINDING-093 - Database Connection Resource Leak in Class Methods
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Every Election instance created via `__init__` opens a SQLite database connection. The only code paths that close this connection are `delete()` and `_disappeared()` - specific to election deletion and missing election detection. Normal operations (creating an Election to read metadata, check vote status, add a vote, or tally results) never close the connection. The class provides no `close()`, `__del__`, `__enter__/__exit__`, or other standard resource release mechanism. Each web request that instantiates an Election object leaks one database connection for the duration of the request (at minimum) and potentially longer if reference cycles exist. Over many requests, this accumulates leaked file descriptors, SQLite locks preventing concurrent access, and memory overhead from buffered connection state. Under high load, this leads to resource exhaustion and application failure.

### Details
**Affected Files:**
- `v3/steve/election.py:393-408, 414-423, 425-436, 438-447, 449-456`

**ASVS References:** 1.4.3 (L2)

### Remediation
Add explicit connection cleanup using try/finally blocks or implement context manager support.

Example:
```python
@classmethod
def open_to_pid(cls, db_fname, pid):
    db = cls.open_database(db_fname)
    try:
        db.q_open_to_me.perform(pid)
        return [row for row in db.q_open_to_me.fetchall()]
    finally:
        db.conn.close()
```

Or better, add context manager support to Election/DB class:
```python
@classmethod
def open_to_pid(cls, db_fname, pid):
    with cls.open_database(db_fname) as db:
        db.q_open_to_me.perform(pid)
        return [row for row in db.q_open_to_me.fetchall()]
```

### Acceptance Criteria
- [ ] Context manager support added to Election class
- [ ] All class methods updated to use context manager
- [ ] Connection cleanup verified in all code paths
- [ ] Tests added for resource cleanup
- [ ] Load testing to verify no leaks

### References
- Source: 1.4.3.md
- Merged from: INPUT_ENCODING-007, INPUT_ENCODING-008

### Priority
Medium

---

## Issue: FINDING-094 - No CSV/Formula Injection Protection Architecture
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application stores user-controllable data (election titles, issue titles, issue descriptions, vote strings) without any sanitization of CSV formula injection characters. No CSV export functionality, CSV-safe utility functions, or formula injection escaping mechanisms exist anywhere in the codebase. The voting system produces tabular data through `tally_issue()` and `get_voters_for_email()` that are natural candidates for CSV/spreadsheet export, yet no architectural provision has been made for safe export. If tally results or voter/election data are ever exported to CSV/XLS/XLSX/ODF (a common operational need for voting systems), formula injection payloads stored by authenticated users would execute in the recipient's spreadsheet application. Vote strings are stored without format validation (as noted by TODO in `add_vote()`), allowing formula characters in vote data.

### Details
**Affected Files:**
- `v3/server/pages.py:361-376, 414-433, 474-502`
- `v3/steve/election.py:197-209, 210-265, 301-307`

**ASVS References:** 1.2.10 (L3)

### Remediation
1. Add a CSV-safe export utility with RFC 4180 compliance and formula character escaping (=, +, -, @, \t, \0) by prefixing with a single quote when they appear as the first character
2. Add vote string validation in `add_vote()` per vote type (e.g., YNA accepts only y/n/a; STV accepts only comma-separated valid candidate labels)
3. Add input validation for election/issue titles rejecting or escaping leading formula characters
4. Document CSV export security requirements in a developer guide to prevent regression when export features are added

### Acceptance Criteria
- [ ] CSV export utility created with formula escaping
- [ ] Vote string validation implemented
- [ ] Title validation added for formula characters
- [ ] Developer documentation created
- [ ] Tests added for CSV injection prevention

### References
- Source: 1.2.10.md
- Merged from: ASVS-1210-MED-002

### Priority
Medium

---

## Issue: FINDING-095 - Missing Vote String Format Validation (Type B Gap)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote submission flow completely skips the validation step that should verify vote content matches the issue's vote type before encryption and storage. The expected sequential steps are: (1) authenticate user, (2) verify election is open, (3) verify voter eligibility, (4) validate vote content, (5) encrypt and store vote. Step 4 is entirely missing, acknowledged by a TODO comment (`### validate VOTESTRING for ISSUE.TYPE voting`) that was never implemented. Raw user input travels directly from HTTP form fields to encrypted storage without any domain validation. Invalid votes (e.g., 'INVALID_VALUE' for YNA issues, malformed rankings for STV issues) are successfully encrypted and stored, only to corrupt election results during tallying. The damage is irreversible once encrypted, and there's no mechanism to distinguish valid from invalid votes without decrypting all of them. Client-side form controls can be trivially bypassed via direct HTTP requests.

### Details
**Affected Files:**
- `v3/steve/election.py:253-268`
- `v3/server/pages.py:430-445`

**ASVS References:** 1.2.7 (L2), 1.3.8 (L2), 1.3.9 (L2), 1.3.3 (L2), 2.3.1 (L2), 2.3.2 (L2), 2.2.1 (L1), 2.2.2 (L1), 2.2.3 (L2), 2.1.2 (L2), 2.1.3 (L2)
**CWE:** CWE-20

### Remediation
Implement the missing validation step in the `add_vote()` method before encryption:

1. Fetch the issue to determine its vote type using `q_get_issue.first_row(iid)`
2. Load the appropriate vote type module using `vtypes.vtype_module(issue.type)`
3. Call a new `validate(votestring, kv)` function on the module to verify the vote content is valid for that type
4. Raise `InvalidVoteString` exception if validation fails
5. Implement `validate()` functions in each vote type module (vtypes/yna.py, vtypes/stv.py, etc.) that check vote strings against the allowed format and values for that type

For example, YNA should only accept 'yes', 'no', or 'abstain'; STV should verify rankings reference valid candidates and contain no duplicates.

Add defense-in-depth validation in `do_vote_endpoint()` handler before calling `add_vote()`. For YNA votes, check votestring in ('y', 'n', 'a'). For STV votes, validate submitted labels exist in issue's labelmap, check for duplicates, ensure non-empty ranking.

### Acceptance Criteria
- [ ] Validation step implemented in add_vote()
- [ ] Validate functions added to all vtype modules
- [ ] Defense-in-depth validation in endpoint handler
- [ ] InvalidVoteString exception created
- [ ] Tests added for each vote type validation
- [ ] Tests for bypass attempts

### References
- Source: 1.2.7.md, 1.3.8.md, 1.3.9.md, 1.3.3.md, 2.3.1.md, 2.3.2.md, 2.2.1.md, 2.2.2.md, 2.2.3.md, 2.1.2.md, 2.1.3.md
- Related: FINDING-098, FINDING-099
- Merged from: ENCODING-008, BUSLOG-002

### Priority
Medium

---

## Issue: FINDING-096 - No SMTP Injection Sanitization Controls for User-Controlled Election Metadata
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The codebase contains email notification functionality via the `get_voters_for_email()` method in election.py, but no SMTP/IMAP injection sanitization controls are present. User-controlled election metadata (titles, descriptions) flows through the system without any mail-specific encoding or sanitization, creating potential SMTP header injection vulnerabilities. User input from form.title is stored via `Election.create()` and later retrieved by `get_metadata()` and `get_voters_for_email()` for email dispatch. An authenticated user creating an election could inject SMTP headers via the title field using CRLF sequences (%0d%0a), potentially injecting additional headers (Bcc:, Cc:, To:), overriding Content-Type for phishing, or adding arbitrary recipients.

### Details
**Affected Files:**
- `v3/steve/election.py:501-507, 430-434`
- `v3/server/pages.py:467-484, 524-544, 534-540, 557-562`

**ASVS References:** 1.3.11 (L2)
**CWE:** CWE-93

### Remediation
Add SMTP-specific sanitization for all user-controlled data before it reaches any email system. Create a new sanitize.py module with `sanitize_for_email_header()` function that removes CRLF sequences (\r, \n, \x00) that could enable SMTP header injection. Apply this sanitization in `Election.create()` method before storing the title. Use Python's email.message module for constructing emails rather than string concatenation, as it provides built-in header encoding and injection protection. Apply `sanitize_for_email_header()` to issue titles and `sanitize_for_email_body()` to descriptions at the form handler level or within `add_issue()`/`edit_issue()` methods. Strip \r, \n, \x00 from issue titles before database storage as these characters are never legitimate in single-line fields. Add input length limits on title and description fields at the web handler level.

### Acceptance Criteria
- [ ] Sanitization module created
- [ ] SMTP header sanitization applied to titles
- [ ] Email construction uses email.message module
- [ ] Issue title/description sanitization added
- [ ] Length limits enforced
- [ ] Tests added for CRLF injection attempts

### References
- Source: 1.3.11.md
- Merged from: ASVS-1311-MED-002

### Priority
Medium

---

## Issue: FINDING-097 - Missing Path Sanitization/Validation for Document Serving Endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `docname` parameter is user-controllable via the URL and is passed directly to `quart.send_from_directory` without any application-level validation. The developer explicitly recognized this gap with the comment `### verify the propriety of DOCNAME.` but did not implement the control. This violates the ASVS 1.3.6 principle of validating untrusted data against an allowlist of paths and sanitizing dangerous characters before using the data to access a resource. Reliance on a single framework-level protection without defense-in-depth is a risk if a bypass is discovered in `safe_join`. While `safe_join` should block path traversal, null-byte or encoding bypasses in specific framework versions could allow access to unintended files within the DOCSDIR tree.

### Details
**Affected Files:**
- `v3/server/pages.py:527-543`

**ASVS References:** 1.3.6 (L2)

### Remediation
Implement explicit allowlist validation for the `docname` parameter using a regex pattern that only permits safe characters (alphanumeric, hyphens, underscores, dots). Explicitly reject path traversal components like `..` or leading dots.

Example implementation:
```python
import re

# Allowlist for document filenames: alphanumeric, hyphens, underscores, dots
SAFE_DOCNAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$')

@APP.get('/docs/<iid>/<docname>')
@asfquart.auth.require
async def serve_doc(iid, docname):
    result = await basic_info()

    # Validate docname against allowlist
    if not SAFE_DOCNAME.match(docname):
        quart.abort(400, 'Invalid document name')
    
    # Reject path traversal components explicitly
    if '..' in docname or docname.startswith('.'):
        quart.abort(400, 'Invalid document name')

    db = steve.election.Election.open_database(DB_FNAME)
    row = db.q_get_mayvote.first_row(result.uid, iid)
    if not row:
        quart.abort(404)

    return await quart.send_from_directory(DOCSDIR / iid, docname)
```

### Acceptance Criteria
- [ ] Allowlist validation implemented
- [ ] Path traversal explicitly rejected
- [ ] Tests added for various bypass attempts
- [ ] Tests for valid filenames

### References
- Source: 1.3.6.md

### Priority
Medium

---

## Issue: FINDING-098 - No Input Length Limits on User-Supplied Text Fields
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 1.3.3 specifically requires 'trimming input which is too long.' No server-side length limits exist on any text input field (election titles, issue titles, issue descriptions). No client-side maxlength attributes are set on form inputs. SQLite TEXT columns accept up to 1 billion characters. This allows arbitrarily long inputs to be stored and rendered, causing storage bloat, slow template rendering, and potential denial of service.

### Details
**Affected Files:**
- `v3/server/pages.py:398, 457, 479`
- `v3/server/templates/admin.ezt`
- `v3/server/templates/manage.ezt`

**ASVS References:** 1.3.3 (L2)
**CWE:** CWE-20

### Remediation
Implement server-side length limits: MAX_ELECTION_TITLE = 200, MAX_ISSUE_TITLE = 200, MAX_ISSUE_DESCRIPTION = 10000. In all form-handling endpoints (do_create_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint), apply:

```python
title = (form.get('title') or '').strip()[:MAX_TITLE_LEN]
```

Add client-side enforcement in all templates:
```html
<input maxlength="200" ...>
```

Reject empty titles after trimming.

### Acceptance Criteria
- [ ] Server-side length limits defined
- [ ] Length enforcement in all form handlers
- [ ] Client-side maxlength added to templates
- [ ] Empty title rejection added
- [ ] Tests added for length limits

### References
- Source: 1.3.3.md
- Related: FINDING-095, FINDING-099

### Priority
Medium

---

## Issue: FINDING-099 - STV Vote String Parser Inconsistency Between Submission and Tallying
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `add_vote()` method accepts vote values from users without validating them against the expected vote type for the issue. The code contains an explicit TODO comment acknowledging this validation requirement, but the validation is not implemented. No validation of votestring length, format, or content against the issue's vote type occurs before passing the data to expensive cryptographic operations (Argon2 computation: 64 MiB memory, 4 CPU threads, ~100ms). This allows: (1) Arbitrary strings to be encrypted and stored as votes regardless of whether they match the issue's voting format (YNA, STV, etc.), (2) Voters to submit arbitrarily large or malformed votestrings that consume disproportionate resources during encryption, storage, and later decryption during tallying, (3) Repeated vote submissions to trigger unbounded Argon2 computation without throttling. A voter could submit a votestring of 10 MiB, which bypasses all vote-type validation, forces Fernet encryption of the full payload, stores the encrypted blob in SQLite, and must decrypt the full blob during tallying. Election integrity is compromised as invalid votes are encrypted and stored, then when tallied by vtypes modules, the behavior is unpredictable — tallying may crash, produce incorrect results, or silently discard/miscount votes.

### Details
**Affected Files:**
- `v3/steve/election.py:200-213`
- `v3/steve/vtypes/stv.py:46-63`
- `v3/server/pages.py:321`

**ASVS References:** 1.5.3 (L3), 15.2.2 (L2), 15.3.5 (L2)
**CWE:** CWE-20

### Remediation
Implement explicit type and format validation in the add_vote method before expensive operations:

1. Implement hard limit on votestring size (e.g., MAX_VOTESTRING_LEN = 4096)
2. Validate that votestring is a string type: `if not isinstance(votestring, str): raise ValueError(f'votestring must be a string, got {type(votestring).__name__}')`
3. Retrieve the issue and validate it exists before processing: `issue = self.q_get_issue.first_row(iid); if not issue: raise IssueNotFound(iid)`
4. Use the vtypes module's validate_vote function to ensure the vote format matches the issue type: `m = vtypes.vtype_module(issue.type); if not m.validate_vote(votestring, self.json2kv(issue.kv)): raise ValueError(f'Invalid vote format for {issue.type}: {votestring!r}')`
5. Consider short-circuit check if identical vote already exists before computing expensive token
6. Implement rate limiting at the web layer using quart_rate_limiter with conservative limits (e.g., 5 votes per minute per user)

Example implementation:
```python
def add_vote(self, pid: str, iid: str, votestring: str):
    if not isinstance(votestring, str):
        raise ValueError(f'votestring must be a string, got {type(votestring).__name__}')
    if len(votestring) > MAX_VOTESTRING_LEN:
        raise ValueError(f'votestring exceeds maximum length')
    issue = self.q_get_issue.first_row(iid)
    if not issue:
        raise IssueNotFound(iid)
    m = vtypes.vtype_module(issue.type)
    if not m.validate_vote(votestring, self.json2kv(issue.kv)):
        raise ValueError(f'Invalid vote format for {issue.type}: {votestring!r}')
    md = self._all_metadata(self.S_OPEN)
    mayvote = self.q_get_mayvote.first_row(pid, iid)
    vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt)
    ciphertext = crypto.create_vote(vote_token, mayvote.salt, votestring)
    self.c_add_vote.perform(vote_token, ciphertext)
```

### Acceptance Criteria
- [ ] Vote string length limit implemented
- [ ] Type validation added
- [ ] Issue existence check added
- [ ] Vote format validation implemented
- [ ] Rate limiting added at web layer
- [ ] Tests added for all validation scenarios

### References
- Source: 1.5.3.md, 15.2.2.md, 15.3.5.md
- Related: FINDING-095, FINDING-098
- Merged from: DEPENDENCIES-012

### Priority
Medium

---

## Issue: FINDING-100 - Election Date Serialization/Deserialization Inconsistency
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The election date write path uses `datetime.fromisoformat()` to parse JSON date strings and stores datetime.date objects (serialized as ISO strings like '2024-06-15'), but all read paths use `datetime.fromtimestamp()` expecting numeric Unix timestamps. This parser inconsistency causes TypeError exceptions when displaying elections whose dates were set via the API, resulting in 500 errors and denial of service for election administration. The tally CLI tool similarly fails when listing elections, preventing tallying operations.

### Details
**Affected Files:**
- `v3/server/pages.py:105-127, 489-494`
- `v3/server/bin/tally.py:79-81`

**ASVS References:** 1.5.3 (L3)
**CWE:** CWE-838

### Remediation
Normalize to Unix timestamp at write time to match all read paths. Modify `_set_election_date()` to convert the parsed datetime to a Unix timestamp using `int(dt.timestamp())` before storing. This ensures consistency with the `fromtimestamp()` calls in `postprocess_election()` and tally.py:

```python
dt = datetime.fromisoformat(date_str)
timestamp = int(dt.timestamp())
# Store timestamp instead of ISO string
```

### Acceptance Criteria
- [ ] Date serialization fixed to use timestamps
- [ ] All date read/write paths consistent
- [ ] Tests added for date handling
- [ ] Existing elections with ISO dates migrated

### References
- Source: 1.5.3.md

### Priority
Medium

---

## Issue: FINDING-101 - Document URL Construction/Parsing Inconsistency
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Document URLs are constructed from issue descriptions using regex extraction without URL encoding, while the route handler receives URL-decoded parameters from the ASGI server. This parser inconsistency creates ambiguity for filenames containing percent-encoded sequences, special characters like # or ?, or path traversal sequences. The iid parameter is used directly in path construction (DOCSDIR / iid) without validation. The TODO comment '### verify the propriety of DOCNAME' confirms missing validation. While send_from_directory provides baseline protection for docname, the lack of validation on iid and the encoding inconsistency create potential security risks.

### Details
**Affected Files:**
- `v3/server/pages.py:50-57, 454-465`

**ASVS References:** 1.5.3 (L3)
**CWE:** CWE-22

### Remediation
Add URL encoding at construction time using `urllib.parse.quote()` with safe='' to encode all special characters. Add validation at the route handler to verify both iid and docname match expected patterns (alphanumeric, underscore, hyphen, and period only):

```python
import urllib.parse
import re

# In rewrite_description:
encoded_filename = urllib.parse.quote(filename, safe='')
encoded_iid = urllib.parse.quote(issue.iid, safe='')
return f'<a href="/docs/{encoded_iid}/{encoded_filename}">{html.escape(filename)}</a>'

# In serve_doc:
DOCNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]+$')
IID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

if not DOCNAME_PATTERN.match(docname) or not IID_PATTERN.match(iid):
    quart.abort(400)
```

### Acceptance Criteria
- [ ] URL encoding added at construction
- [ ] Pattern validation added at handler
- [ ] Tests added for special characters
- [ ] Tests for path traversal attempts

### References
- Source: 1.5.3.md
- Related: FINDING-039

### Priority
Medium

---

## Issue: FINDING-102 - Missing ROLLBACK Handling in Transactional Methods
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Multiple methods explicitly begin database transactions but fail to include rollback logic in exception handlers. If any operation within the transaction fails (crypto operation, database write, disk full), the transaction is neither committed nor rolled back, leaving the database connection in an undefined state. In add_salts, partial salt assignment means some voters have salts and some don't, breaking the election opening process. In delete, partial deletion could leave orphaned records that violate referential integrity. SQLite's rollback journal may hold a lock, blocking other connections.

### Details
**Affected Files:**
- `v3/steve/election.py:55-70, 126-140`

**ASVS References:** 2.3.3 (L2), 16.5.2 (L2)

### Remediation
Add try/except blocks with explicit ROLLBACK logic to all methods using BEGIN TRANSACTION. Ensure that any exception during the transaction triggers a rollback before re-raising. Replace security-critical assert statements with explicit if/raise patterns. Add error logging for all rollback scenarios.

Example:
```python
try:
    self.db.conn.execute('BEGIN TRANSACTION')
    ...
    self.db.conn.commit()
except Exception as e:
    _LOGGER.error(f'Transaction failed for election[E:{self.eid}]: {type(e).__name__}', exc_info=True)
    self.db.conn.rollback()
    raise
```

### Acceptance Criteria
- [ ] ROLLBACK handling added to all transactions
- [ ] Error logging added
- [ ] Tests added for transaction failures
- [ ] Assert statements replaced where security-critical

### References
- Source: 2.3.3.md, 16.5.2.md
- Merged from: AUDIT_LOGGING-025

### Priority
Medium

---

## Issue: FINDING-103 - Tampering Detection Control Exists But Is Never Invoked Before Sensitive Operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application implements a cryptographic tampering detection mechanism (`is_tampered()` method) that computes an opened_key hash to detect if election data has been modified after opening. The method's own docstring states it should prevent voting when tampered and prevent tallying if tampered. However, this control is never called in any operational code path. Neither `add_vote()` (vote submission) nor `tally_issue()` (tallying) invoke `is_tampered()`, and the voting page display also doesn't check for tampering. If election data (issues, voters) is tampered with after opening, the system will silently accept votes and produce tallies against corrupted data, rendering the integrity protection mechanism useless. This is a Type B gap where the control exists but is never called.

### Details
**Affected Files:**
- `v3/steve/election.py:316, 236, 252`
- `v3/server/pages.py:336`

**ASVS References:** 2.3.2 (L2), 9.1.1 (L1), 11.6.2 (L3)
**CWE:** CWE-353

### Remediation
Add tamper checks before every sensitive operation that relies on election data. The most effective approach is to integrate it into `_all_metadata()` or create a wrapper.

Option A: Integrate into _all_metadata for open/closed elections by adding a `check_integrity` parameter that calls `is_tampered()` when the election has an `opened_key`.

Option B: Add explicit checks at each entry point in pages.py before processing votes or closing elections.

Additionally, use constant-time comparison (`hmac.compare_digest()`) for the MAC check instead of Python's `!=` operator to prevent timing side-channels.

### Acceptance Criteria
- [ ] Tamper checks integrated into metadata retrieval or entry points
- [ ] Constant-time comparison used for MAC
- [ ] Tests added for tamper detection
- [ ] Tests verify operations fail when tampered

### References
- Source: 2.3.2.md, 9.1.1.md, 11.6.2.md
- Merged from: JWT_TOKEN-1, CRYPTO-010

### Priority
Medium

---

## Issue: FINDING-104 - No Cross-Field Date Consistency Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_set_election_date()` function validates individual date formats but does not perform cross-field validation to ensure logical consistency between open_at and close_at dates. The application accepts close_at dates that are before open_at dates, or dates in the past, creating logically inconsistent election metadata. This represents failure to validate contextual consistency of the combined data items (open_at + close_at). Administrators can set close_at to a date before open_at, creating logically impossible election configurations that undermine trust in the election process and cause confusing information to be displayed to voters.

### Details
**Affected Files:**
- `v3/server/pages.py:79-100, 77-101, 375, 382`

**ASVS References:** 2.1.2 (L2), 2.2.3 (L2)

### Remediation
Add cross-field validation in `_set_election_date()` that:

1. Retrieves current election metadata
2. When setting open_at, checks that it is before close_at if close_at exists
3. When setting close_at, checks that it is after open_at if open_at exists
4. Returns 400 Bad Request with descriptive error message if validation fails

Also add similar validation in `Election.create()` and create-election.py CLI tool to prevent invalid date configurations at election creation time.

### Acceptance Criteria
- [ ] Cross-field validation added to _set_election_date()
- [ ] Validation added to Election.create()
- [ ] CLI tool validation enhanced
- [ ] Error messages clear and helpful
- [ ] Tests added for invalid date combinations

### References
- Source: 2.1.2.md, 2.2.3.md
- Merged from: ASVS-223-MED-002

### Priority
Medium

---

## Issue: FINDING-105 - Election Can Be Opened Without Issues or Eligible Voters
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `election.open()` method does not verify that the election has at least one issue and at least one eligible voter before transitioning to OPEN state. Since opening an election is an irreversible state transition, this allows administrators to permanently render elections unusable by opening them before they are properly configured. An empty election in OPEN state cannot be returned to EDITABLE state, has no voteable content, and must be abandoned in favor of creating a new election.

### Details
**Affected Files:**
- `v3/steve/election.py:72-87`
- `v3/server/pages.py:530-547`

**ASVS References:** 2.2.3 (L2)

### Remediation
Add pre-condition checks in `election.open()` method before allowing state transition. Query for issues associated with the election and raise ValueError if none exist. Query for mayvote entries (eligible voters) and raise ValueError if none exist. This ensures only complete, usable elections can be opened. The checks should occur after the `is_editable()` assertion but before `add_salts()` is called.

### Acceptance Criteria
- [ ] Issue count validation added
- [ ] Voter eligibility validation added
- [ ] Appropriate exceptions raised
- [ ] Tests added for empty elections
- [ ] Error messages clear to administrators

### References
- Source: 2.2.3.md

### Priority
Medium

---

## Issue: FINDING-106 - No Business Logic Limits on Resource Creation or Vote Revisions
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No business logic limits are defined or enforced for resource creation (elections, issues) or vote revisions. The vote storage model uses INSERT for every revision, allowing unbounded database growth. There are no per-user limits on election creation, no per-election limits on issue count, and no limits on vote revision count. This enables resource exhaustion attacks through election creation spam, unbounded issue creation per election, and rapid vote-change cycling. Each election creates cryptographic keys consuming CPU resources for key derivation. The SQLite database has no inherent size limits — unchecked creation leads to disk exhaustion on the server.

### Details
**Affected Files:**
- `v3/server/pages.py:466, 522, 473-490, 523-545`
- `v3/steve/election.py:256`

**ASVS References:** 2.1.3 (L2), 2.4.1 (L2)
**CWE:** CWE-770

### Remediation
Define and document business logic limits (e.g., MAX_ELECTIONS_PER_USER=50, MAX_ISSUES_PER_ELECTION=100, MAX_VOTE_REVISIONS_PER_ISSUE=10, MAX_TITLE_LENGTH=200, MAX_DESCRIPTION_LENGTH=5000, MAX_CANDIDATES_PER_STV=50). Implement enforcement checks before allowing resource creation. Add input length validation for title and description fields. For election creation, add per-user election creation quota and check the count of owned elections before allowing creation. For issue creation, enforce maximum issues per election and maximum candidates per STV issue. Return error messages and redirect when limits are reached.

### Acceptance Criteria
- [ ] Business logic limits defined and documented
- [ ] Per-user election quota enforced
- [ ] Per-election issue limit enforced
- [ ] Vote revision limit enforced
- [ ] Input length limits added
- [ ] Tests added for all limits

### References
- Source: 2.1.3.md, 2.4.1.md
- Merged from: ASVS-241-MEDIUM-003

### Priority
Medium

---

## Issue: FINDING-107 - Election Creation and State-Change Endpoints Lack Rate Limiting and Timing Controls
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The election creation endpoint and state-change endpoints (open/close) lack rate limiting, cooldown periods, and timing controls. A compromised PMC member account can create unbounded elections at machine speed, causing database bloat, garbage-data creation, and quota exhaustion. Elections could be rapidly toggled between open and closed states, disrupting active voters mid-ballot. Each election creates cryptographic keys consuming CPU resources. The SQLite database has no inherent size limits — unchecked creation leads to disk exhaustion. The state-change endpoints execute immediately upon GET requests with no timing controls, confirmation steps, or cooldowns, violating HTTP semantics and enabling trivial CSRF exploitation.

### Details
**Affected Files:**
- `v3/server/pages.py:473-490, 463-482, 485-504, 507-523`

**ASVS References:** 2.4.1 (L2), 2.4.2 (L3)

### Remediation
For election creation:
- Add per-user election creation quota (e.g., MAX_ELECTIONS_PER_USER=50) and check the count of owned elections before allowing creation
- Implement a per-user cooldown period (e.g., 30 seconds) between election creations tracked in session
- Add a daily limit (e.g., 5 elections per user per day) enforced via database query

For state-change endpoints:
- Change endpoints from GET to POST methods
- Add owner authorization check to verify metadata.owner_pid matches the requesting user
- Implement a cooldown period (e.g., 60 seconds) on state changes per election tracked in session using an 'election_state_{eid}' key
- Flash warning messages when cooldown is active or limits are exceeded and redirect appropriately

### Acceptance Criteria
- [ ] Rate limiting implemented for election creation
- [ ] Cooldown periods enforced
- [ ] Daily limits tracked
- [ ] State-change endpoints converted to POST
- [ ] Owner authorization added
- [ ] Tests added for rate limiting
- [ ] Tests for cooldown enforcement

### References
- Source: 2.4.1.md, 2.4.2.md
- Merged from: ASVS-242-MED-002

### Priority
Medium

---

## Issue: FINDING-108 - Missing Global Security Headers Framework
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no after_request handler or middleware to apply security response headers globally. All 21 endpoints in the application serve responses without Content-Security-Policy, X-Content-Type-Options, or other defensive headers. This creates no defense-in-depth layer and allows browsers to MIME-sniff responses. Any response from the application lacks critical security headers, allowing MIME-sniffing attacks and providing no defense-in-depth if any endpoint inadvertently returns user-controlled content.

### Details
**Affected Files:**
- `v3/server/main.py:30-43`

**ASVS References:** 3.2.1 (L1)
**CWE:** CWE-693

### Remediation
Implement an after_request handler in the create_app function that sets X-Content-Type-Options: nosniff and a default Content-Security-Policy for all responses. The CSP should restrict content sources with directives like default-src 'self', script-src 'self', style-src 'self' 'unsafe-inline', img-src 'self' data:, and frame-ancestors 'none'.

### Acceptance Criteria
- [ ] Global after_request handler implemented
- [ ] X-Content-Type-Options header set
- [ ] Content-Security-Policy configured
- [ ] Tests verify headers on all endpoints

### References
- Source: 3.2.1.md
- Related: FINDING-119

### Priority
Medium

---

## Issue: FINDING-109 - API Endpoints Lack Sec-Fetch-* Context Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
API-style endpoints that accept JSON or form data and return non-HTML responses do not validate Sec-Fetch-Dest or Sec-Fetch-Mode headers to confirm the request originates from the expected context (e.g., fetch from JavaScript, not direct browser navigation). While POST mitigates direct navigation, there is no server-side enforcement that these endpoints are called only via the intended AJAX/fetch context. Without Sec-Fetch-* validation, there is no server-side assurance that API endpoints are accessed only from the application's frontend. Combined with the lack of CSRF tokens, this increases the risk that these endpoints could be triggered from external contexts.

### Details
**Affected Files:**
- `v3/server/pages.py:376, 383, 390`

**ASVS References:** 3.2.1 (L1)
**CWE:** CWE-352

### Remediation
Create a require_fetch_context decorator that validates Sec-Fetch-Dest and Sec-Fetch-Mode headers on API endpoints. The decorator should check that sec_fetch_dest is 'empty' or blank and sec_fetch_mode is 'cors', 'same-origin', 'no-cors', or blank. Apply this decorator to all API-style endpoints that return non-HTML responses.

### Acceptance Criteria
- [ ] require_fetch_context decorator created
- [ ] Decorator applied to all API endpoints
- [ ] Tests verify header validation
- [ ] Tests for invalid contexts rejected

### References
- Source: 3.2.1.md
- Related: FINDING-007, FINDING-008, FINDING-009, FINDING-030, FINDING-033, FINDING-034

### Priority
Medium

---

## Issue: FINDING-110 - Session Cookie Name Missing __Host- or __Secure- Prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Quart (and Flask) default the session cookie name to 'session'. ASVS 3.3.1 requires that if the __Host- prefix is not used, the __Secure- prefix must be used. Neither prefix is configured anywhere in the provided application code. The __Secure- prefix instructs browsers to only send the cookie over HTTPS and requires the Secure attribute. The __Host- prefix additionally restricts the cookie to the exact host and root path, preventing subdomain attacks. Without the __Secure- or __Host- prefix, the browser does not enforce prefix-based cookie protections. Combined with the missing Secure attribute, this means no browser-enforced HTTPS-only transmission, potential for subdomain cookie injection attacks, and cookies could be overwritten by a less-secure subdomain.

### Details
**Affected Files:**
- `v3/server/main.py:30-44, 36-38, 44-46`
- `v3/server/pages.py:70`

**ASVS References:** 3.3.1 (L1), 3.3.3 (L2)

### Remediation
Use __Host- prefix for maximum cookie security. The __Host- prefix requires: Secure attribute, Path=/, and no Domain attribute.

Example:
```python
app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_PATH'] = '/'
# Do NOT set SESSION_COOKIE_DOMAIN (required for __Host- prefix)
```

Alternative: Use __Secure- prefix (less restrictive).

### Acceptance Criteria
- [ ] Cookie prefix configured
- [ ] Secure attribute set
- [ ] Path configured correctly
- [ ] Domain not set (for __Host-)
- [ ] Tests verify cookie attributes

### References
- Source: 3.3.1.md, 3.3.3.md
- Merged from: ASVS-333-SEV-001

### Priority
Medium

---

## Issue: FINDING-111 - No Explicit HttpOnly Configuration on Session Cookie
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not explicitly configure session cookie security attributes (SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE) anywhere in the auditable codebase. The asfquart.construct() call is the sole application factory, and no cookie attribute configuration follows it. While Quart (based on Flask's API) defaults SESSION_COOKIE_HTTPONLY to True, the asfquart wrapper layer is not available for review and could potentially override this default. ASVS 3.3.4 requires verification that HttpOnly is set — this cannot be verified from the provided code. If HttpOnly is not set, a cross-site scripting vulnerability anywhere in the application could be leveraged to steal session tokens via document.cookie.

### Details
**Affected Files:**
- `v3/server/main.py:42`

**ASVS References:** 3.3.4 (L2)

### Remediation
Explicitly configure session cookie security attributes after app construction in main.py:

```python
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_NAME'] = '__Host-session'  # Cookie prefix for additional protection
```

### Acceptance Criteria
- [ ] All cookie security attributes explicitly configured
- [ ] Configuration verified in tests
- [ ] Documentation updated

### References
- Source: 3.3.4.md

### Priority
Medium

---

## Issue: FINDING-112 - No Cookie Size Validation Control
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no mechanism to validate or enforce the 4096-byte cookie size limit. All session cookie management is delegated to the Quart/asfquart framework with no application-level guard. While the current session payload (uid, fullname, email, flash messages) is likely small enough, there is no defensive control preventing oversized cookies if session data grows (e.g., additional session attributes, accumulated data from framework internals, or future code changes). If the session cookie exceeds 4096 bytes (through future code changes, framework overhead growth, or unforeseen session data accumulation), the browser will silently discard it. The user's session would effectively be invalidated, preventing authentication and use of all protected functionality. This is a denial-of-service condition against individual users.

### Details
**Affected Files:**
- `v3/server/pages.py:63-94, 73-78, 121-128, 356, 519`

**ASVS References:** 3.3.5 (L3)

### Remediation
Implement middleware that validates cookie size before the response is sent using @APP.after_request. Check Set-Cookie headers for cookies exceeding 4096 bytes and take corrective action (clear session, log, alert). Add after_request middleware to log warnings when Set-Cookie headers approach 4096 bytes. Document session storage architecture and cap flash message content length to prevent edge cases.

### Acceptance Criteria
- [ ] Cookie size validation middleware added
- [ ] Warning logging for approaching limit
- [ ] Session clearing on oversized cookies
- [ ] Flash message length limits enforced
- [ ] Tests for cookie size scenarios

### References
- Source: 3.3.5.md

### Priority
Medium

---

## Issue: FINDING-113 - Reflected XSS via URL Path Parameters in Error Pages
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Error templates e_bad_eid.ezt and e_bad_iid.ezt render URL path parameters (eid and iid) directly without HTML escaping. When a user visits an invalid election or issue URL, Quart URL-decodes the path parameter and the load_election decorator assigns it to result.eid or result.iid, which is then rendered as raw HTML in the 404 error page. An attacker can craft URLs containing HTML/JavaScript that, when clicked by authenticated users, execute in their browser session.

### Details
**Affected Files:**
- `v3/server/templates/e_bad_eid.ezt`
- `v3/server/templates/e_bad_iid.ezt`
- `v3/server/pages.py:172`

**ASVS References:** 3.2.2 (L1)
**CWE:** CWE-79

### Remediation
Apply [format "html"] to error template outputs.

In e_bad_eid.ezt:
```
The Election ID ([format "html"][eid][end]) does not exist.
```

In e_bad_iid.ezt:
```
The Issue ID ([format "html"][iid][end]) does not exist.
```

Apply same fix to e_bad_pid.ezt if it exists.

### Acceptance Criteria
- [ ] HTML escaping added to error templates
- [ ] Tests verify XSS prevention
- [ ] All error templates reviewed

### References
- Source: 3.2.2.md
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-114

### Priority
Medium

---

## Issue: FINDING-114 - Reflected XSS via Flash Messages Containing User-Provided Input
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Multiple flash messages interpolate user-provided input (form.title, iid from form keys) directly into message strings without HTML escaping. Flash messages are stored in the session via quart.flash() and retrieved via get_flashed_messages() in basic_info(), then rendered as raw HTML in templates. For title-based vectors, an admin submitting a form with HTML in the title field will see that HTML executed when the success message is displayed. For iid-based vectors (e.g., in do_vote_endpoint), a crafted form key like 'vote-&lt;img src=x onerror="alert(1)"&gt;' directly injects into the flash message when an invalid issue ID error occurs.

### Details
**Affected Files:**
- `v3/server/pages.py:459, 521, 543, 427, 435, 73-77`

**ASVS References:** 3.2.2 (L1)
**CWE:** CWE-79

### Remediation
Option 1 - Server-side escaping in pages.py:
```python
import html
await flash_success(f'Created election: {html.escape(form.title)}')
```

Option 2 - Template-side escaping:
```html
<div class="alert alert-[flashes.category]">[format "html"][flashes.message][end]</div>
```

Option 1 is preferred to ensure all flash messages are safe by default.

### Acceptance Criteria
- [ ] HTML escaping applied to all flash messages
- [ ] Tests verify XSS prevention
- [ ] All flash message locations reviewed

### References
- Source: 3.2.2.md
- Related: FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113

### Priority
Medium

---

## Issue: FINDING-115 - Shared Utility Functions Declared in Global Scope Without Namespace Isolation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The shared utility file steve.js declares three functions at global scope without namespace isolation or strict mode enforcement. These functions are accessible as properties of the window object, making them vulnerable to DOM clobbering attacks where malicious HTML elements with matching id or name attributes could shadow these function references. An authorized committer can inject HTML elements with matching IDs/names through issue descriptions, which are rendered as raw HTML. This can cause denial of service for election management operations by preventing form submissions when the clobbered references are accessed.

### Details
**Affected Files:**
- `v3/server/static/js/steve.js:30-73`

**ASVS References:** 3.2.3 (L3)

### Remediation
Wrap steve.js in an IIFE with 'use strict' and expose functions through a namespace object (e.g., SteVe.showModal()). Add type checking with instanceof to verify elements returned by getElementById are of expected types (HTMLElement, HTMLFormElement, HTMLButtonElement, etc.) before using them.

### Acceptance Criteria
- [ ] Functions wrapped in IIFE with strict mode
- [ ] Namespace object created
- [ ] Type checking added for DOM elements
- [ ] Tests for DOM clobbering prevention

### References
- Source: 3.2.3.md

### Priority
Medium

---

## Issue: FINDING-116 - Inline Scripts in Management Templates Lack Namespace Isolation and Strict Mode
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Management templates (manage.ezt, manage-stv.ezt, admin.ezt) contain inline JavaScript that declares multiple functions and variables at global scope without namespace isolation or strict mode. This creates pollution of the global namespace and makes these functions vulnerable to DOM clobbering attacks. The templates render issue descriptions as raw HTML, allowing injection of elements with matching IDs/names. While vote-on.ezt properly wraps its script in an IIFE with 'use strict', the management templates do not use this pattern despite handling equally sensitive operations and rendering the same unsanitized issue descriptions.

### Details
**Affected Files:**
- `v3/server/templates/manage.ezt` (inline script block)
- `v3/server/templates/manage-stv.ezt` (inline script block)
- `v3/server/templates/admin.ezt` (inline script block)

**ASVS References:** 3.2.3 (L3)

### Remediation
Wrap all template inline scripts in IIFEs with strict mode, matching the pattern already used in vote-on.ezt. Only expose to HTML onclick handlers via window if needed:

```javascript
window.toggleDescription = toggleDescription;
window.openAddIssueModal = openAddIssueModal;
// etc.
```

### Acceptance Criteria
- [ ] All inline scripts wrapped in IIFE
- [ ] Strict mode enabled
- [ ] Only necessary functions exposed to window
- [ ] Tests verify functionality preserved

### References
- Source: 3.2.3.md

### Priority
Medium

---

## Issue: FINDING-117 - No Type or Null Checking on document.getElementById() Results Across All Client-Side JavaScript
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Throughout the codebase, document.getElementById() is called without subsequent null or type checking. The return value is immediately used with property access (.value, .classList, .innerHTML) without verifying the returned element exists or is of the expected type. This creates vulnerability to DOM clobbering where an injected element of unexpected type could cause silent failures or type errors. Issue descriptions rendered as raw HTML may contain elements with id attributes that collide with IDs used by the application (e.g., id='csrf-token', id='vote-&lt;iid&gt;', id='issueTitle'). If a clobbered element of different type is returned, accessing properties like .value returns undefined rather than the expected string, causing silent data corruption or TypeError.

### Details
**Affected Files:**
- `v3/server/static/js/steve.js:31, 42, 49`
- `v3/server/templates/manage.ezt` (inline script - csrf-token access)
- `v3/server/templates/vote-on.ezt` (inline script - multiple instances)

**ASVS References:** 3.2.3 (L3)

### Remediation
Implement a safe element lookup utility function that performs null and type checking.

Example:
```javascript
function safeGetElement(id, expectedType) {
    const el = document.getElementById(id);
    if (!el) {
        console.error(`Element not found: #${id}`);
        return null;
    }
    if (expectedType && !(el instanceof expectedType)) {
        console.error(`Element #${id} is ${el.constructor.name}, expected ${expectedType.name}`);
        return null;
    }
    return el;
}
```

### Acceptance Criteria
- [ ] Safe element lookup utility created
- [ ] All getElementById calls updated
- [ ] Error handling for missing elements
- [ ] Tests for DOM clobbering scenarios

### References
- Source: 3.2.3.md

### Priority
Medium

---

## Issue: FINDING-118 - Missing Strict-Transport-Security Header on All Responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application supports TLS configuration but never sets the `Strict-Transport-Security` header. This is a Type A gap — TLS is available but HSTS enforcement does not exist. Even when TLS is configured: (1) No HSTS header is sent to instruct browsers to always use HTTPS. (2) No HTTP→HTTPS redirect is configured. (3) No mechanism ensures the application behaves correctly (warns or blocks) when accessed over plain HTTP. (4) In ASGI mode (`run_asgi()`, line 96), TLS is delegated entirely to the reverse proxy with no application-level verification. Users connecting over HTTP (e.g., first visit, downgrade attack, misconfigured proxy) transmit authentication cookies and session data in plaintext. Election data and voter identity are exposed to network-level attackers.

### Details
**Affected Files:**
- `v3/server/main.py:31-47`
- `v3/server/pages.py` (all routes)
- `v3/server/config.yaml.example`
- `v3/ARCHITECTURE.md`

**ASVS References:** 3.4.1 (L1), 3.7.4 (L2), 3.1.1 (L3)

### Remediation
```python
@app.after_request
async def set_hsts(response):
    # Only set HSTS when served over HTTPS
    if quart.request.is_secure or quart.request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )
    return response

# Optionally redirect HTTP to HTTPS
@app.before_request
async def enforce_https():
    if not quart.request.is_secure and not app.debug:
        url = quart.request.url.replace('http://', 'https://', 1)
        return quart.redirect(url, code=301)
```

### Acceptance Criteria
- [ ] HSTS header middleware implemented
- [ ] HTTP to HTTPS redirect added
- [ ] Configuration documented
- [ ] Tests verify HSTS on HTTPS requests
- [ ] Tests verify redirect from HTTP

### References
- Source: 3.4.1.md, 3.7.4.md, 3.1.1.md
- Merged from: SESSION_CSRF-012, MISC-008

### Priority
Medium

---

## Issue: FINDING-119 - Complete Absence of X-Content-Type-Options Header
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not set the 'X-Content-Type-Options: nosniff' header on any HTTP response. No global middleware, after-request handler, or framework configuration was found that would inject this header. All 21+ routes return responses without this protection. This allows browsers to MIME-sniff responses and interpret content differently than the declared Content-Type, potentially executing attacker-controlled content as active scripts. The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serving user-associated documents presents the highest risk, as documents served as text/plain could be sniffed and executed as text/html containing JavaScript. The /static/&lt;path:filename&gt; endpoint serving CSS/JS has weakened Cross-Origin Read Blocking (CORB) protection. In the context of a voting system, MIME-sniffing XSS could lead to session hijacking or vote manipulation.

### Details
**Affected Files:**
- `v3/server/main.py:28-43`
- `v3/server/pages.py` (all routes: 134, 144, 180, 259, 299, 323, 353, 359, 365, 400, 423, 445, 463, 486, 511, 531, 540, 548, 553-562, 565-566, 570-571, 653-654, 92-112)

**ASVS References:** 3.4.4 (L2)
**CWE:** CWE-693

### Remediation
Primary Fix: Add a global after_request hook in the application factory (main.py create_app() function) that sets the X-Content-Type-Options: nosniff header on every response.

Secondary Fix (Defense-in-Depth): Explicitly set the header on manually constructed Response objects in raise_404() function.

The after_request hook approach is preferred because it provides single point of enforcement and cannot be forgotten when new routes are added.

### Acceptance Criteria
- [ ] Global after_request hook implemented
- [ ] X-Content-Type-Options header set on all responses
- [ ] Tests verify header on all endpoints
- [ ] Manual Response objects also set header

### References
- Source: 3.4.4.md
- Related: FINDING-108

### Priority
Medium

---

## Issue: FINDING-120 - Missing Referrer-Policy Header on All Application Responses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not set a Referrer-Policy HTTP response header on any responses, nor is there evidence of HTML meta tag configuration in the provided code. This violates ASVS requirement 3.4.5 and exposes sensitive election identifiers, issue IDs, and document names in URL paths to third-party services via the browser's Referer header. When users navigate to sensitive pages (e.g., /vote-on/abc123 or /manage-stv/abc123/issue456), the HTML response is rendered without a Referrer-Policy header. If any page contains links to third-party resources or the user clicks an external link, the browser sends the full URL including the path (election ID, issue ID, document name) in the Referer header to the third party. This allows third-party services to learn internal election identifiers and navigation patterns.

### Details
**Affected Files:**
- `v3/server/main.py:31-47`
- `v3/server/pages.py:125-602`

**ASVS References:** 3.4.5 (L2)

### Remediation
Add a global after_request handler that sets Referrer-Policy on all responses. For an election system, 'strict-origin-when-cross-origin' (minimum) or 'no-referrer' (strictest) is recommended:

```python
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
```

For maximum protection (recommended for a voting system):
```python
response.headers['Referrer-Policy'] = 'no-referrer'
```

Alternatively, if templates are controlled, a fallback HTML meta tag can be added in the base template:
```html
<meta name="referrer" content="strict-origin-when-cross-origin">
```

### Acceptance Criteria
- [ ] Referrer-Policy header added via after_request
- [ ] Policy configured appropriately for voting system
- [ ] Tests verify header on all responses
- [ ] Documentation updated with policy choice rationale

### References
- Source: 3.4.5.md

### Priority
Medium

## Issue: FINDING-121 - Missing Content-Security-Policy Header with Violation Reporting Directive
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not configure a Content-Security-Policy header with a violation reporting directive anywhere in the codebase, leaving it exposed to XSS and content injection attacks with no visibility into policy violations.

### Details
The application lacks CSP enforcement at the application level with no middleware or after-request hook to add reporting capabilities. This results in:
1. No CSP enforcement - browser applies no restrictions on script sources, style sources, frame ancestors, or other content policies
2. No violation reporting - security team has no visibility into policy violations or attack attempts
3. No monitoring baseline - cannot establish a CSP in report-only mode first to test policies before enforcement

**Affected Files:**
- `v3/server/main.py` (lines 29-40)
- `v3/server/pages.py` (lines 135-653)

**ASVS:** 3.4.7, 3.1.1 (Level 3)

### Remediation
In `main.py` `create_app()`, add after_request handler:
```python
@app.after_request
async def set_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'; "
        "base-uri 'self'"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response
```

### Acceptance Criteria
- [ ] CSP header with reporting directive implemented
- [ ] Additional security headers (X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) added
- [ ] Test added to verify headers are present on all responses

### References
- ASVS 3.4.7, 3.1.1
- Source: 3.4.7.md, 3.1.1.md

### Priority
High

---

## Issue: FINDING-122 - Missing Cross-Origin-Opener-Policy Header on All HTML Responses
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not set the Cross-Origin-Opener-Policy (COOP) header on any HTTP response, leaving all HTML responses vulnerable to cross-origin window handle attacks such as tabnabbing and frame counting.

### Details
Without COOP, the window.opener property leaks a reference across origins, enabling:
- Cross-origin page navigation to phishing pages mimicking the voting UI
- Cross-origin state inspection through browsing context enumeration
- Undermining of the system's anonymity goals

**Affected Files:**
- `v3/server/main.py` (lines 32-47)
- `v3/server/pages.py` (lines 125, 133, 222, 280, 320, 343, 551, 559, 567, 575, 659)

**ASVS:** 3.4.8 (Level 3)

### Remediation
Add a global after_request hook in the application factory to set the Cross-Origin-Opener-Policy header on all HTML responses. In `v3/server/main.py`, inside `create_app()`, add an after_request handler that checks content type and sets `Cross-Origin-Opener-Policy: same-origin` for text/html responses. Also update the `raise_404` function in `v3/server/pages.py` to include the header on manual responses.

### Acceptance Criteria
- [ ] COOP header set to `same-origin` on all HTML responses
- [ ] After_request hook implemented in application factory
- [ ] raise_404 function updated to include COOP header
- [ ] Test added to verify COOP header presence

### References
- ASVS 3.4.8
- Source: 3.4.8.md

### Priority
High

---

## Issue: FINDING-123 - JSON Endpoints Lack Explicit Content-Type Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
JSON endpoints use `quart.request.get_json()` without explicit Content-Type validation, relying on incidental protection that could be accidentally removed during refactoring.

### Details
The protection is fragile because:
- `get_json()` without `force=True` incidentally requires `Content-Type: application/json`
- This is not an explicit security control and could be removed by adding `force=True` or None checks
- Error handling returns unhandled 500 exceptions rather than proper 403/415 responses
- The Content-Type requirement forces a CORS preflight check, but this is not intentional

**Affected Files:**
- `v3/server/pages.py` (lines 88-108, 368-372, 374-378)

**ASVS:** 3.5.2 (Level 1)

### Remediation
Make the Content-Type requirement explicit by:
1. Adding explicit validation that checks if `application/json` is in the Content-Type header before processing
2. Returning proper 415 (Unsupported Media Type) error for invalid Content-Type
3. Adding validation that the JSON body is not None and returning 400 for invalid JSON

### Acceptance Criteria
- [ ] Explicit Content-Type validation added
- [ ] Proper 415 error returned for invalid Content-Type
- [ ] Proper 400 error returned for invalid JSON
- [ ] Test added to verify Content-Type validation

### References
- ASVS 3.5.2
- Source: 3.5.2.md

### Priority
Medium

---

## Issue: FINDING-124 - Systemic Absence of Cross-Origin Resource Protection Headers
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has no global mechanism to set Cross-Origin-Resource-Policy response headers or validate Sec-Fetch-* request headers, affecting all 15+ authenticated endpoints.

### Details
This systemic architectural gap results in:
- No browser-enforced cross-origin resource blocking on any authenticated response
- Authenticated HTML pages can be iframed by malicious sites (clickjacking vector)
- Cross-origin scripts can probe authenticated endpoints for timing/error-based information disclosure
- Application relies solely on Same-Origin Policy, which does not prevent resource loading

**Affected Files:**
- `v3/server/pages.py` (all endpoints)

**ASVS:** 3.5.8 (Level 3)

### Remediation
Implement global @APP.after_request middleware that:
1. Sets `Cross-Origin-Resource-Policy: same-origin` on all responses
2. Adds `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff` headers
3. Creates a `validate_sec_fetch()` utility function that checks Sec-Fetch-Site and Sec-Fetch-Mode
4. Applies validation as a decorator to sensitive endpoints
5. Implements Content-Security-Policy with frame-ancestors directive

### Acceptance Criteria
- [ ] Global after_request middleware implemented
- [ ] Cross-Origin-Resource-Policy header set on all responses
- [ ] Sec-Fetch-* validation implemented
- [ ] Test added to verify header presence and validation

### References
- ASVS 3.5.8
- Source: 3.5.8.md

### Priority
High

---

## Issue: FINDING-125 - Complete Absence of External URL Navigation Warning
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has no mechanism to warn users before navigating to URLs outside the application's control, allowing potential phishing attacks.

### Details
The `rewrite_description()` function injects unescaped HTML into the page, allowing:
- Arbitrary HTML including external links to be rendered directly to voters
- No interstitial warning page or cancellation option
- No client-side JavaScript intercept for external links
- No server-side redirect proxy

An election administrator can create an issue with external links in the description, and voters clicking these links will navigate directly to external URLs with no warning.

**Affected Files:**
- `v3/server/pages.py` (lines 52-59, 349-350)

**ASVS:** 3.7.3 (Level 3)

### Remediation
Implement a three-part solution:
1. Server-side redirect proxy route that validates URLs and shows an interstitial warning page for external domains
2. Interstitial template with explicit warning text, target domain display, and both 'Continue' and 'Cancel' options
3. HTML escaping in `rewrite_description()` to prevent arbitrary HTML injection, and client-side JavaScript to intercept external link clicks

### Acceptance Criteria
- [ ] Server-side redirect proxy implemented
- [ ] Interstitial warning page template created
- [ ] HTML escaping added to rewrite_description()
- [ ] Client-side JavaScript intercept implemented
- [ ] Test added to verify warning display

### References
- ASVS 3.7.3
- Source: 3.7.3.md

### Priority
High

---

## Issue: FINDING-126 - Complete Absence of Browser Security Feature Detection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's common JavaScript utility file contains zero browser security feature detection, with no user warning or access-blocking logic for outdated browsers.

### Details
The application implicitly depends on modern browser features but never checks whether the browser supports:
- Content Security Policy (CSP)
- Strict-Transport-Security
- SameSite cookie attribute
- Secure cookie flag enforcement
- SubtleCrypto/Web Crypto API

Users accessing with outdated browsers would:
- Receive the page normally with no warning
- Have server-sent security headers silently ignored
- Be vulnerable to attacks (XSS, session hijacking)
- Have no indication their session is less secure

**Affected Files:**
- `v3/server/static/js/steve.js` (lines 1-76)

**ASVS:** 3.7.5 (Level 3)

### Remediation
Add a browser security feature detection module to `steve.js` that runs on page load and checks for:
1. Content Security Policy support (`window.SecurityPolicyViolationEvent`)
2. Web Cryptography API (`window.crypto.subtle`)
3. Fetch API with credentials support (`window.fetch`)
4. HTTPS enforcement (`location.protocol`)
5. SameSite cookie support

If critical features are missing, display a warning message and optionally disable form submission buttons.

### Acceptance Criteria
- [ ] Browser feature detection module implemented
- [ ] Warning message displayed for missing features
- [ ] Form submission disabled when required features missing
- [ ] `<noscript>` tag warning added
- [ ] Test added to verify detection and warnings

### References
- ASVS 3.7.5
- Source: 3.7.5.md

### Priority
Medium

---

## Issue: FINDING-127 - HTML Responses Created Without Explicit Charset in Content-Type
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `raise_404` function creates explicit HTML responses without specifying a charset parameter in the Content-Type header, creating a window for character-encoding-based attacks.

### Details
Setting `mimetype='text/html'` produces `Content-Type: text/html` without `; charset=utf-8`. In Werkzeug 3.0+, the Response class no longer automatically appends a charset when only mimetype is supplied. Without an explicit charset declaration:
- Browsers must guess the character encoding
- Creates window for UTF-7 XSS in legacy or misconfigured clients
- Enables multi-byte encoding attacks

**Affected Files:**
- `v3/server/pages.py` (lines 183, 211, 222, 318, 390, 764-766)

**ASVS:** 4.1.1 (Level 1)

### Remediation
Change the `raise_404` function to use `content_type='text/html; charset=utf-8'` instead of `mimetype='text/html'`:
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
- [ ] raise_404 function updated to use content_type parameter
- [ ] All HTML responses include explicit charset
- [ ] Test added to verify Content-Type header format

### References
- ASVS 4.1.1
- Source: 4.1.1.md

### Priority
Medium

---

## Issue: FINDING-128 - No Application-Wide Content-Type Enforcement Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no centralized mechanism to ensure all HTTP responses include a Content-Type header with an appropriate charset parameter, creating systemic risks.

### Details
Content-Type correctness is entirely delegated to individual handler implementations and framework defaults with no `@APP.after_request` hook for validation. This creates risks:
- If framework default behavior changes across versions, all responses silently lose charset declarations
- New endpoints added by developers may omit Content-Type charset without any safety net
- Error responses generated by `quart.abort()` inherit framework defaults with no override
- 22+ response-generating endpoints with no defense-in-depth

**Affected Files:**
- `v3/server/pages.py`
- `v3/server/main.py`

**ASVS:** 4.1.1 (Level 1)

### Remediation
Add an `after_request` hook to enforce Content-Type charset on all text-based responses:
```python
@APP.after_request
async def set_content_type_charset(response):
    """Ensure all text-based responses include charset=utf-8."""
    content_type = response.content_type or ''
    if content_type:
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
- [ ] after_request hook implemented
- [ ] All text-based responses include charset
- [ ] Test added to verify charset enforcement across all endpoints

### References
- ASVS 4.1.1
- Source: 4.1.1.md

### Priority
Medium

---

## Issue: FINDING-129 - No Differentiation Between Browser Pages and Action/API Endpoints for Transport Security
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not implement any mechanism to differentiate transport security requirements between user-facing browser endpoints and action/API endpoints, allowing action endpoints to silently accept HTTP requests.

### Details
All endpoints are treated identically with respect to HTTP/HTTPS handling. When a reverse proxy implements blanket HTTP→HTTPS redirect:
- Action endpoints like `/do-vote/<eid>` are silently redirected instead of rejected
- Vote data, session cookies, and election management commands may be transmitted in plaintext without detection
- Configuration explicitly documents TLS as optional with "leave these two fields blank for plain HTTP"

**Affected Files:**
- `v3/server/main.py` (lines 76-82)
- `v3/server/pages.py` (all route definitions)
- `v3/server/config.yaml.example` (lines 24-30)

**ASVS:** 4.1.2 (Level 2)

### Remediation
Implement middleware that:
1. Enforces HTTPS on action/API endpoints and only redirects on browser-facing GET endpoints
2. Adds before_request middleware to check X-Forwarded-Proto when behind reverse proxy
3. For browser-facing GET endpoints, redirects to HTTPS with 301
4. For action/API endpoints (POST, or state-changing GET like `/do-*`), rejects with 403 error and does NOT redirect
5. Sets HSTS headers (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) for browser clients

### Acceptance Criteria
- [ ] before_request middleware implemented
- [ ] HTTPS enforcement on action/API endpoints
- [ ] Browser-facing GET endpoints redirect to HTTPS
- [ ] HSTS headers set
- [ ] Test added to verify enforcement

### References
- ASVS 4.1.2
- Source: 4.1.2.md

### Priority
Medium

---

## Issue: FINDING-130 - State-changing Operations Use GET Method, Compounding Transport Security Risk
**Labels:** bug, security, priority:medium
**Description:**
### Summary
State-changing operations for opening and closing elections are exposed as GET endpoints rather than POST endpoints, increasing the attack surface for plaintext credential leakage.

### Details
GET requests are more likely to be:
- Logged by proxies, browsers, and intermediaries
- Cached
- Automatically redirected by intermediaries

Election open/close operations as GET endpoints mean:
- Session cookies and election IDs are exposed in the URL and headers
- A blanket HTTP→HTTPS proxy redirect for GET requests may execute the state-changing operation after redirect, but authentication cookies were already sent in plaintext
- Session tokens leaked in plaintext allow election administration hijacking

**Affected Files:**
- `v3/server/pages.py` (`/do-open/<eid>`, `/do-close/<eid>`)

**ASVS:** 4.1.2 (Level 2)

### Remediation
Convert state-changing operations to POST method:
1. Change `@APP.get('/do-open/<eid>')` to `@APP.post('/do-open/<eid>')`
2. Change `@APP.get('/do-close/<eid>')` to `@APP.post('/do-close/<eid>')`
3. HTTPS enforcement will be handled by the before_request middleware recommended in FINDING-129

### Acceptance Criteria
- [ ] State-changing operations converted to POST
- [ ] Templates updated to use forms instead of links
- [ ] Test added to verify POST method requirement

### References
- ASVS 4.1.2
- Source: 4.1.2.md
- Related: FINDING-129

### Priority
Medium

---

## Issue: FINDING-131 - No Trusted Proxy Configuration or X-Forwarded-* Header Sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application, designed to run behind a reverse proxy, lacks any configuration or middleware to sanitize, validate, or restrict intermediary-set HTTP headers, creating risks for OAuth redirect manipulation and audit log integrity.

### Details
The application lacks:
- Configuration for trusted proxy IPs
- Middleware to sanitize X-Forwarded-* headers
- Validation of proxy-set headers

While the application reads user identity from server-side sessions rather than headers, the underlying Quart framework and OAuth redirect flow may implicitly trust these spoofable headers, creating risks for:
- OAuth redirect manipulation
- Audit log integrity compromise
- Scheme confusion leading to insecure URL generation

**Affected Files:**
- `v3/server/main.py` (lines 34-53, 78-95, 96-113)

**ASVS:** 4.1.3 (Level 2)

### Remediation
Configure trusted proxy handling at the ASGI server level and/or within the application:

**Option 1:** Configure Hypercorn with `--forwarded-allow-ips="127.0.0.1,10.0.0.0/8"`

**Option 2:** Add ProxyFixMiddleware in create_app():
```python
from quart.middleware import ProxyFixMiddleware
app.asgi_app = ProxyFixMiddleware(
    app.asgi_app,
    mode="modern",
    trusted_hops=1,
)
```

**Option 3:** Strip dangerous headers in a before_request handler

### Acceptance Criteria
- [ ] Trusted proxy configuration implemented
- [ ] X-Forwarded-* headers validated or stripped
- [ ] Test added to verify header handling

### References
- ASVS 4.1.3
- Source: 4.1.3.md

### Priority
Medium

---

## Issue: FINDING-132 - No Per-Message Digital Signatures on Election Lifecycle Transitions
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Election open and close operations are irreversible state machine transitions performed without per-message digital signatures, relying only on session cookie authentication.

### Details
These endpoints use GET methods for state-changing operations and lack:
- Cryptographic confirmation of administrator intent
- Cryptographic binding in audit logs
- Protection against CSRF attacks via link injection, img tags, or browser prefetching
- Complete authorization checking (marked with '### check authz' comments)

Opening an election triggers cryptographic key generation and salt assignment; closing permanently ends voting. There is no cryptographic confirmation of administrator intent or cryptographic binding in audit logs.

**Affected Files:**
- `v3/server/pages.py` (lines 496-517, 520-538)
- `v3/steve/election.py` (lines 269-282, 285-296)
- `v3/steve/crypto.py` (lines 31-41)

**ASVS:** 4.1.5 (Level 3)

### Remediation
Change `/do-open/<eid>` and `/do-close/<eid>` to POST methods with signed request bodies:
1. Require confirmation signatures from administrators using Ed25519 or similar
2. JSON payload containing action, eid, timestamp, and nonce
3. Administrator signs payload with private key
4. Server verifies signature against registered admin public key
5. Validate timestamp freshness (e.g., within 5 minutes)
6. Check and consume nonce to prevent replay
7. Log with signature verification confirmation

Add nonce storage infrastructure (Redis or database) for replay protection.

### Acceptance Criteria
- [ ] Digital signature requirement implemented
- [ ] Nonce storage and validation added
- [ ] Timestamp freshness validation added
- [ ] Audit logging includes signature verification
- [ ] Test added to verify signature requirement

### References
- ASVS 4.1.5
- Source: 4.1.5.md

### Priority
Medium

---

## Issue: FINDING-133 - No HTTP Request Body Size Limits Configured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Quart application does not set `max_content_length` or configure Hypercorn body size limits, enabling denial-of-service via overly long HTTP messages.

### Details
Multiple POST endpoints accept unbounded request bodies. An authenticated attacker (any committer) can:
- Submit arbitrarily large HTTP request bodies
- Exhaust server memory through full buffering by the framework
- Cause denial of service during an active election
- Potentially disrupt voting

ASVS 4.2.1 explicitly includes "denial of service via overly long HTTP messages" as an attack vector.

**Affected Files:**
- `v3/server/main.py` (lines 31-44)
- `v3/server/pages.py` (lines 96, 403, 440, 504, 531)

**ASVS:** 4.2.1 (Level 2)

### Remediation
Set `app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024` (1 MB) in the `create_app()` function in `main.py`. Additionally, configure Hypercorn limits in the ASGI deployment using a hypercorn.toml configuration file with settings for:
- `h11_max_incomplete_size`
- `h2_max_concurrent_streams`
- `h2_max_header_list_size`

### Acceptance Criteria
- [ ] MAX_CONTENT_LENGTH configured in application
- [ ] Hypercorn limits configured
- [ ] Test added to verify size limit enforcement

### References
- ASVS 4.2.1
- Source: 4.2.1.md

### Priority
Medium

---

## Issue: FINDING-134 - State-changing GET Requests Increase HTTP Request Smuggling Attack Surface
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Two state-changing operations (`/do-open/<eid>` and `/do-close/<eid>`) are implemented as GET requests, making them easier payloads to smuggle and compounding the risk with missing authorization checks.

### Details
GET requests have simpler message boundary determination (no body parsing) and are therefore the easiest payloads to smuggle through a misconfigured proxy/server chain. Additionally:
- Authorization check stubs (`### check authz`) exist but are NOT CALLED
- This removes the ownership check that would limit impact
- If HTTP request smuggling is achievable at the infrastructure level, any authenticated committer's session could be hijacked to open or close elections they don't own

**Affected Files:**
- `v3/server/pages.py` (lines 453-470, 475-492)

**ASVS:** 4.2.1 (Level 2)

### Remediation
Convert state-changing operations to POST with CSRF protection:
1. Change `@APP.get('/do-open/<eid>')` to `@APP.post('/do-open/<eid>')`
2. Change `@APP.get('/do-close/<eid>')` to `@APP.post('/do-close/<eid>')`
3. Implement ownership verification by checking if `md.owner_pid != result.uid` and abort with 403 if unauthorized
4. Add CSRF token validation using `validate_csrf_token(form.get('csrf_token'))`

### Acceptance Criteria
- [ ] State-changing operations converted to POST
- [ ] Ownership verification implemented
- [ ] CSRF token validation added
- [ ] Test added to verify authorization and CSRF protection

### References
- ASVS 4.2.1
- Source: 4.2.1.md

### Priority
Medium

---

## Issue: FINDING-135 - No Application-Level HTTP/2 Connection-Specific Header Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application runs on Hypercorn with HTTP/2 support but has no application-level middleware to reject prohibited connection-specific headers or prevent their inclusion in responses.

### Details
The application lacks:
1. Rejection of incoming HTTP/2/HTTP/3 requests containing prohibited connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade, TE except for trailers)
2. Prevention of connection-specific headers in outgoing HTTP/2/HTTP/3 responses
3. Validation of header integrity during HTTP version conversion

In an HTTP/2-to-HTTP/1.1 downgrade proxy scenario, this could enable request smuggling attacks, allowing attackers to bypass authentication/authorization decorators.

**Affected Files:**
- `v3/server/main.py` (lines 33-48, 43, 77-78, 91-110)
- `v3/server/pages.py` (lines 93, 441, 499, 520)

**ASVS:** 4.2.3 (Level 3)

### Remediation
Add ASGI middleware to validate and strip connection-specific headers for HTTP/2/HTTP/3 requests:
1. Create a HTTP2HeaderValidationMiddleware class that rejects HTTP/2+ requests containing connection-specific header fields per RFC 9113 Section 8.2.2
2. Register the middleware in main.py by wrapping app.asgi_app
3. Add a Quart after_request handler to strip connection-specific headers from all responses
4. Configure Hypercorn explicitly for HTTP version handling
5. Convert state-changing GET endpoints to POST methods

### Acceptance Criteria
- [ ] HTTP/2 header validation middleware implemented
- [ ] Connection-specific headers stripped from responses
- [ ] Hypercorn HTTP version handling configured
- [ ] Test added to verify HTTP/2 requests with Transfer-Encoding are rejected

### References
- ASVS 4.2.3
- Source: 4.2.3.md

### Priority
Medium

---

## Issue: FINDING-136 - No Application-Level CRLF Validation on HTTP Request Headers
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has zero middleware, decorators, or configuration that validates incoming HTTP request headers for CR, LF, or CRLF sequences, creating potential for header injection attacks.

### Details
The application:
- Supports HTTP/2 when deployed via Hypercorn
- Has no application-layer header validation
- Relies entirely on the underlying ASGI server and framework for protocol-level protection
- Lacks defense-in-depth

This becomes critical when HTTP version conversion occurs at a reverse proxy layer where HTTP/2 requests are converted to HTTP/1.1, potentially allowing CRLF characters that pass HTTP/2 binary framing to become injection vectors after protocol downgrade.

**Affected Files:**
- `v3/server/pages.py` (lines 114-628)
- `v3/server/main.py` (lines 90-107)

**ASVS:** 4.2.4 (Level 3)

### Remediation
Add Quart before_request middleware to validate all incoming request headers:

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
- [ ] CRLF validation middleware implemented
- [ ] Requests with CRLF in headers rejected with 400
- [ ] Test added to verify CRLF rejection

### References
- ASVS 4.2.4
- Source: 4.2.4.md

### Priority
Medium

---

## Issue: FINDING-137 - Redirect Responses Constructed Without CRLF Sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Multiple POST and GET endpoints construct redirect Location headers using URL path parameters without explicit CRLF checks, creating potential for response splitting attacks.

### Details
While the `load_election` decorator provides database validation that would reject most injected values:
- Not all redirect paths go through this validation
- The application places no explicit CRLF check on data flowing into response headers
- Framework-level protection is version-dependent and not verified
- If a future code change introduces a redirect path without database validation, header injection becomes possible with no defense-in-depth

**Affected Files:**
- `v3/server/pages.py` (lines 303, 363, 413, 416, 434, 455, 477, 496, 521, 547, 567)

**ASVS:** 4.2.4 (Level 3)

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

Additionally, add an after_request hook to validate all outgoing headers:

```python
@APP.after_request
async def validate_response_headers(response):
    """Ensure no CRLF injection in response headers."""
    for header_name, header_value in response.headers:
        if CRLF_PATTERN.search(str(header_value)):
            _LOGGER.error(f'CRLF detected in response header: {header_name}')
            quart.abort(500)
    return response
```

### Acceptance Criteria
- [ ] safe_redirect helper function implemented
- [ ] All redirect calls updated to use safe_redirect
- [ ] after_request hook for response header validation added
- [ ] Test added to verify CRLF rejection in redirects

### References
- ASVS 4.2.4
- Source: 4.2.4.md

### Priority
Medium

---

## Issue: FINDING-138 - Unbounded User Input in Flash Messages Creates Cookie Header DoS Risk
**Labels:** bug, security, priority:high
**Description:**
### Summary
Multiple endpoints incorporate unsanitized, unbounded user input into session flash messages, which if stored in cookies can exceed browser cookie size limits and cause persistent DoS.

### Details
The vulnerable code paths include:
1. `do_vote_endpoint` extracting unbounded `iid` from form field names and passing to flash_danger
2. `do_create_endpoint` passing unbounded `form.title` to flash_success
3. `do_add_issue_endpoint` passing unbounded `form.title` to flash_success
4. `do_edit_issue_endpoint` passing unbounded `form.title` to flash_success

Data flows from HTTP POST form fields through extraction without length checks into `quart.flash()`, then to session storage and Set-Cookie response headers. The browser then sends oversized Cookie headers that the server rejects with persistent 431 errors, resulting in DoS for that user's session.

**Affected Files:**
- `v3/server/pages.py` (lines 369, 385-395, 410, 424, 467, 485, 489, 505)

**ASVS:** 4.2.5 (Level 3)

### Remediation
Apply length limits at three levels:
1. Truncate user input before including in flash messages using MAX_FLASH_INPUT_LEN constant (e.g., 200 characters)
2. Enforce maximum request body size via `APP.config['MAX_CONTENT_LENGTH'] = 64 * 1024` (64KB)
3. Add server-side input length validation for form fields with constants like MAX_TITLE_LEN = 500 and MAX_DESCRIPTION_LEN = 5000

Example:
```python
MAX_FLASH_INPUT_LEN = 200
safe_iid = iid[:MAX_FLASH_INPUT_LEN]
title = form.title[:MAX_FLASH_INPUT_LEN]
```

### Acceptance Criteria
- [ ] Input truncation implemented for flash messages
- [ ] MAX_CONTENT_LENGTH configured
- [ ] Form field length validation added
- [ ] Test added to verify length limits

### References
- ASVS 4.2.5
- Source: 4.2.5.md

### Priority
High

---

## Issue: FINDING-139 - No WebSocket Origin Header Validation Infrastructure
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application lacks any infrastructure for validating the `Origin` header during WebSocket handshakes, enabling Cross-Site WebSocket Hijacking (CSWSH) attacks.

### Details
The `create_app()` function establishes zero WebSocket security controls:
1. No allowed-origins list is defined in application configuration
2. No `before_websocket` or `before_request` middleware is registered to inspect the `Origin` header
3. The underlying framework does not validate WebSocket Origin headers by default
4. All WebSocket endpoints inherit this unprotected configuration

An attacker can perform CSWSH where an authenticated user visiting a malicious page would have their browser establish a WebSocket connection using their existing session cookies, allowing the attacker to:
- Submit or modify votes on behalf of the victim
- Read election state or results in real-time
- Bypass CSRF protections
- Compromise the integrity and confidentiality of the voting process

**Affected Files:**
- `v3/server/main.py` (lines 36-51)

**ASVS:** 4.4.2 (Level 2)

### Remediation
Add a `before_websocket` hook in `create_app()` that validates the `Origin` header against an explicit allow-list:

```python
def create_app():
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)

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

Add to configuration file:
```yaml
server:
  allowed_origins:
    - https://steve.apache.org
    - https://voting.apache.org
```

### Acceptance Criteria
- [ ] before_websocket hook implemented
- [ ] Origin validation against allow-list added
- [ ] Configuration option for allowed origins added
- [ ] Test added to verify Origin validation

### References
- ASVS 4.4.2
- Source: 4.4.2.md

### Priority
High

---

## Issue: FINDING-140 - Complete Absence of File Handling Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has an active document-serving feature but neither the schema.md, ARCHITECTURE.md, nor any other documentation defines file handling requirements, security measures, or behavior for malicious files.

### Details
The application has:
1. A route GET /docs/&lt;iid&gt;/&lt;docname&gt; that serves files from the DOCSDIR / iid directory
2. A rewrite_description() function that converts doc:filename tokens into clickable download links

Neither component has documentation defining:
- Permitted file types for documents
- Expected file extensions
- Maximum file size
- How files are made safe for download (Content-Disposition, Content-Type validation, anti-virus scanning)
- Behavior when a malicious file is detected

Without documented requirements, an attacker who can place files in the docs directory could serve:
- HTML files with embedded JavaScript (stored XSS via Content-Type sniffing)
- Executable files disguised as documents
- Excessively large files causing storage exhaustion

**Affected Files:**
- `v3/docs/schema.md`
- `v3/ARCHITECTURE.md` (line 18)
- `v3/server/pages.py` (lines 562-580)

**ASVS:** 5.1.1 (Level 2)

### Remediation
Create a file handling specification document and reference it from ARCHITECTURE.md. The specification should define:
1. Permitted file types (PDF, plain text, Markdown)
2. Expected extensions (.pdf, .txt, .md)
3. Maximum file size (10 MB per file, 50 MB per issue)
4. Safety measures (file extension validation, explicit Content-Type headers, Content-Disposition: attachment, X-Content-Type-Options: nosniff, rejection of unrecognized extensions)
5. Malicious file behavior (logging and HTTP 403 for files failing validation)

### Acceptance Criteria
- [ ] File handling specification document created
- [ ] Document referenced from ARCHITECTURE.md
- [ ] Permitted file types and extensions documented
- [ ] Security measures documented
- [ ] Malicious file handling behavior documented

### References
- ASVS 5.1.1
- Source: 5.1.1.md

### Priority
Medium

---

## Issue: FINDING-141 - Issue Description Doc-Link Rewriting Generates Unvalidated File References
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `rewrite_description()` function parses issue descriptions and converts doc:filename patterns into HTML anchor tags without validating filenames against any allowlist of permitted file types.

### Details
The regex `r'doc:([^\s]+)'` captures any non-whitespace sequence, meaning filenames like:
- `../../../etc/passwd`
- `evil.html`
- `payload.exe`

would be turned into clickable links. While the serve_doc endpoint's send_from_directory provides basic path traversal protection, the absence of documented permitted file types means there is no basis for validation at either the link-generation or file-serving layer. This:
- Generates links to file types that should not be served (executables, HTML, etc.)
- Creates a social engineering vector where attackers with issue-editing privileges can embed links to dangerous file types

**Affected Files:**
- `v3/server/pages.py` (lines 52-58)

**ASVS:** 5.1.1 (Level 2)

### Remediation
Validate the filename in `rewrite_description()` against the documented allowlist:
1. Define ALLOWED_DOC_EXTENSIONS constant
2. Extract file extension using pathlib.Path().suffix
3. Check extension against allowlist
4. Validate that filename does not contain path separators ('/' or '\\')
5. Return placeholder text '[invalid document reference: {filename}]' for invalid references
6. Only generate `<a>` tags for validated filenames

### Acceptance Criteria
- [ ] Filename validation implemented
- [ ] Extension allowlist defined
- [ ] Path separator validation added
- [ ] Invalid references replaced with placeholder text
- [ ] Test added to verify validation

### References
- ASVS 5.1.1
- Source: 5.1.1.md
- Related: FINDING-140

### Priority
Medium

---

## Issue: FINDING-142 - Files Served to Voters Undergo No Antivirus Scanning
**Labels:** bug, security, priority:high
**Description:**
### Summary
The document serving endpoint allows authenticated voters to download files associated with election issues without any antivirus or malicious content scanning.

### Details
Files are served directly from the filesystem without inspection, creating a potential vector for malware distribution to voters. An election administrator can place a document containing malware in DOCSDIR/&lt;iid&gt;/, reference it in an issue description, and it will be served to voters without detection. In an election system context, compromised voter machines could lead to:
- Vote manipulation
- Credential theft

**Affected Files:**
- `v3/server/pages.py` (lines 52, 308, 638-658)

**ASVS:** 5.4.3 (Level 2)

### Remediation
Integrate antivirus scanning at the point where files are placed into DOCSDIR (upload time) and optionally at serve time:
1. Implement a scan_file() function using ClamAV (clamdscan) that scans files before serving
2. Function should return True if clean, raise AVScanError if malicious or scan fails
3. Add the scanning check in the serve_doc handler before calling send_from_directory
4. Implement scanning at the point of file ingestion (upload or placement)
5. Reject files that fail scanning before they reach the serving directory
6. Consider periodic background scans of DOCSDIR to catch newly-identified threats
7. Complete the TODO comment for DOCNAME validation with explicit path validation
8. Consider adding file type allowlisting for serve_doc

### Acceptance Criteria
- [ ] Antivirus scanning function implemented
- [ ] Scanning integrated into serve_doc handler
- [ ] Files scanned at ingestion time
- [ ] Failed scans rejected before serving
- [ ] Test added to verify scanning

### References
- ASVS 5.4.3
- Source: 5.4.3.md

### Priority
High

---

## Issue: FINDING-143 - Complete Absence of Authentication Defense Controls Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application lacks any documentation defining how rate limiting, anti-automation, and adaptive response controls defend against credential stuffing, password brute force, and malicious account lockout.

### Details
A thorough review of all provided documentation and code reveals no documentation addressing:
- What brute force protections the OAuth provider implements
- Whether there are retry limits on the OAuth callback flow
- How the application would detect or respond to credential stuffing
- How malicious account lockout is prevented at the identity provider level

The application delegates authentication to Apache OAuth (oauth.apache.org) but provides no documentation explaining these critical security controls.

**Affected Files:**
- `v3/TODO.md`
- `v3/docs/schema.md`
- `v3/server/pages.py`
- `v3/server/main.py` (lines 33, 39-43)

**ASVS:** 6.1.1 (Level 1)

### Remediation
Create an authentication security document (e.g., v3/docs/authentication-security.md) that addresses:
1. Authentication flow and OAuth provider's brute force protections
2. Rate limiting policies for login attempts, vote submission, and API endpoints
3. Anti-automation controls (CAPTCHA/challenge requirements, bot detection)
4. Adaptive response policies (actions after N failed attempts, escalation procedures)
5. Account lockout prevention (lockout policy, anti-lockout measures, election-specific protections)
6. Configuration details (where settings are configured, how to modify thresholds, monitoring/alerting)

### Acceptance Criteria
- [ ] Authentication security document created
- [ ] All required topics documented
- [ ] Document referenced from main documentation
- [ ] Configuration examples provided

### References
- ASVS 6.1.1
- Source: 6.1.1.md

### Priority
Medium

---

## Issue: FINDING-144 - No Rate Limiting on Vote Submission and State-Changing Endpoints
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote submission and election state-change endpoints have no rate limiting or throttling controls, allowing authenticated attackers to submit rapid automated requests.

### Details
An authenticated attacker (any committer) could:
- Submit rapid automated requests causing database contention in SQLite (single-writer model)
- Abuse election state changes
- Exploit state-changing GET requests which combine absence of CSRF protection with absence of rate limiting

The following functions process requests immediately without any rate limiting checks or anti-automation controls:
- `do_vote_endpoint()`
- `do_create_endpoint()`
- `do_open_endpoint()`
- `do_close_endpoint()`

**Affected Files:**
- `v3/server/pages.py` (lines 367, 408, 429, 448)

**ASVS:** 6.1.1 (Level 1)

### Remediation
1. Implement rate limiting on sensitive endpoints using a library like quart_rate_limiter (e.g., @rate_limit(1, timedelta(seconds=5)) for vote submission)
2. Document the rate limiting configuration in the authentication security document referenced in FINDING-143
3. Add similar rate limiting to election state-change endpoints (e.g., @rate_limit(5, timedelta(minutes=1)))
4. Convert state-changing GET endpoints to POST with CSRF protection as acknowledged in TODO.md

### Acceptance Criteria
- [ ] Rate limiting implemented on vote submission endpoint
- [ ] Rate limiting implemented on state-change endpoints
- [ ] Rate limiting configuration documented
- [ ] Test added to verify rate limiting enforcement

### References
- ASVS 6.1.1
- Source: 6.1.1.md
- Related: FINDING-143

### Priority
Medium

---

## Issue: FINDING-145 - No Throttling on Vote Submission Endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The vote submission endpoint (POST /do-vote/&lt;eid&gt;) has no throttling mechanism, allowing authenticated attackers to submit rapid automated vote changes with expensive cryptographic operations.

### Details
An authenticated attacker or compromised account could:
1. Submit rapid automated vote changes to create timing side-channels
2. Flood the endpoint to cause resource exhaustion (each vote triggers expensive cryptographic operations with Argon2 key derivation and Fernet encryption)
3. Abuse the 'last vote wins' behavior for race-condition vote manipulation

The `add_vote()` method performs multiple cryptographic operations per call without any throttling. No rate limiting, submission cooldown, or duplicate detection exists at the HTTP layer.

**Affected Files:**
- `v3/server/pages.py` (lines 290-323)
- `v3/steve/election.py` (line 265)

**ASVS:** 6.3.1 (Level 1)

### Remediation
1. Add endpoint-specific rate limiting using @rate_limit decorator (e.g., max 5 vote submissions per minute per user)
2. Implement submission cooldown check: track last vote timestamp per user per election and enforce minimum 10-second wait between submissions
3. Add duplicate detection at the HTTP layer to prevent rapid resubmission of identical votes

### Acceptance Criteria
- [ ] Rate limiting decorator added to vote submission endpoint
- [ ] Submission cooldown tracking implemented
- [ ] Duplicate detection added
- [ ] Test added to verify throttling enforcement

### References
- ASVS 6.3.1
- Source: 6.3.1.md

### Priority
Medium

---

## Issue: FINDING-146 - No Rate Limiting on Resource Identifier Endpoints
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application lacks any rate limiting mechanism on election and issue identifier lookup endpoints, allowing brute force enumeration of valid identifiers.

### Details
Despite requiring authentication via ASF OAuth, no brute-force protection exists anywhere in the codebase. The `load_election` and `load_election_issue` decorators perform direct database lookups without:
- Tracking failed attempts
- Implementing delays
- Enforcing request limits

An authenticated attacker can send unlimited rapid requests to endpoints like `/manage/<eid>` with sequential or random EID guesses, using the 404/200 response codes as an oracle to discover valid identifiers. Combined with the 40-bit entropy issue (ASVS-663-SEV-001), systematic enumeration becomes tractable.

**Affected Files:**
- `v3/server/pages.py` (lines 161, 180, 217, 306, 362, 418, 436, 536)

**ASVS:** 6.6.3 (Level 2)

### Remediation
Implement rate limiting on election/issue lookup endpoints to prevent brute force enumeration attacks:

**Option 1:** Use quart-rate-limiter library with @rate_limit(10, timedelta(minutes=1)) decorator (10 requests/minute per IP)

**Option 2:** Implement custom tracking with exponential backoff including:
- is_rate_limited() check
- record_failed_lookup() tracking
- 429 responses for rate-limited requests

Additionally, complete the missing authorization checks marked with '### check authz' comments to prevent unauthorized access to discovered elections.

### Acceptance Criteria
- [ ] Rate limiting implemented on lookup endpoints
- [ ] Failed lookup tracking added
- [ ] 429 responses for rate-limited requests
- [ ] Authorization checks completed
- [ ] Test added to verify rate limiting

### References
- ASVS 6.6.3
- Source: 6.6.3.md

### Priority
High

---

## Issue: FINDING-147 - State-Changing Operations via GET Bypass Session CSRF Protections
**Labels:** bug, security, priority:high
**Description:**
### Summary
Two critical state-changing operations (opening and closing elections) use GET methods, making them inherently more vulnerable to cross-site request forgery despite session token verification.

### Details
While session tokens are verified on the backend via `@asfquart.auth.require({R.committer})`, GET requests can be triggered by:
- Image tags
- Link prefetching
- Redirects without user interaction

Combined with the placeholder CSRF token (`basic.csrf_token = 'placeholder'` at line 84), a verified session can be abused through external trigger mechanisms. An attacker can trick an authenticated user into opening or closing an election without their knowledge. This is particularly dangerous with automatic session creation (ASVS-762-MED-001) where third-party content can trigger both session creation and state changes in a single redirect chain.

**Affected Files:**
- `v3/server/pages.py` (lines 84, 437-453, 448, 456-472, 468)

**ASVS:** 7.2.1, 7.5.3, 7.6.2 (Levels 1, 2, 3)

### Remediation
1. Change `/do-open/<eid>` and `/do-close/<eid>` to POST methods
2. Replace the placeholder CSRF token with a cryptographically secure token using `secrets.token_urlsafe(32)`
3. Store the token in the session and validate it on POST requests
4. Ensure all state-changing operations use POST methods with CSRF protection
5. Update templates to use forms with CSRF tokens instead of direct links

### Acceptance Criteria
- [ ] State-changing operations converted to POST
- [ ] Cryptographically secure CSRF token implemented
- [ ] CSRF token validation added
- [ ] Templates updated to use forms
- [ ] Test added to verify CSRF protection

### References
- ASVS 7.2.1, 7.5.3, 7.6.2
- Source: 7.2.1.md, 7.5.3.md, 7.6.2.md

### Priority
High

---

## Issue: FINDING-148 - Absence of Session Management Risk Analysis and Policy Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 7.1.1 requires documentation of session management policies including timeout values, maximum lifetime, and NIST SP 800-63B compliance. No such documentation exists.

### Details
The project's documentation covers database schema but contains no mention of:
- Session management policies
- Session token storage mechanism
- Session timeout values
- SSO interaction considerations
- NIST SP 800-63B analysis or deviation justification
- Risk analysis for session handling decisions

A risk analysis with documented security decisions related to session handling must be conducted as a prerequisite to implementation and testing.

**Affected Files:**
- `v3/docs/schema.md`
- `v3/ARCHITECTURE.md`

**ASVS:** 7.1.1 (Level 2)

### Remediation
Create a session-management.md document (or equivalent section in existing docs) containing:
1. Session timeout values with justification (recommend 15-minute inactivity timeout and 12-hour absolute lifetime)
2. NIST SP 800-63B compliance section documenting AAL level, re-authentication requirements, and any deviations with justification
3. SSO interaction documentation covering how SSO session lifetime interacts with application session lifetime and session revocation on SSO logout
4. Risk analysis documenting threats (unattended workstation, stolen session token) and corresponding mitigations
5. Justification for timeout values based on voting system sensitivity and operational requirements

### Acceptance Criteria
- [ ] Session management documentation created
- [ ] All required topics documented
- [ ] NIST SP 800-63B compliance addressed
- [ ] Risk analysis included
- [ ] Document referenced from main documentation

### References
- ASVS 7.1.1
- Source: 7.1.1.md

### Priority
Medium

---

## Issue: FINDING-149 - Complete Absence of Concurrent Session Limit Policy and Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has no documented policy, configuration, or code to define or enforce how many concurrent (parallel) sessions are permitted for a single user account.

### Details
For a voting/election management system where session integrity directly impacts trustworthiness, missing controls include:
1. No session count tracking—no database table, in-memory store, or external service tracks how many sessions exist per uid
2. No session limit constant/configuration—no MAX_SESSIONS or equivalent defined
3. No enforcement action—no code path to revoke oldest sessions, deny new login, or notify the user
4. No session listing endpoint—users cannot view their active sessions
5. No session revocation endpoint—users cannot terminate other active sessions
6. No documentation—no policy defines intended concurrent session behavior

**Affected Files:**
- `v3/server/pages.py` (lines 70-87, 547-560)
- `v3/server/main.py` (lines 39-41)

**ASVS:** 7.1.2 (Level 2)

### Remediation
1. Document the policy defining:
   - Maximum concurrent sessions per account (e.g., 3 for regular users, 1 during active voting)
   - Behavior when the limit is reached (e.g., terminate oldest session, or deny new login)
   - Any role-specific limits
2. Implement session tracking using a server-side session registry that tracks active sessions per user with timestamps
3. Integrate into authentication flow—check session count at login and at basic_info()
4. Add session management UI—populate the existing /settings page with session listing and revocation controls

### Acceptance Criteria
- [ ] Concurrent session policy documented
- [ ] Session tracking registry implemented
- [ ] Session count enforcement added to authentication flow
- [ ] Session management UI added to /settings page
- [ ] Test added to verify session limit enforcement

### References
- ASVS 7.1.2
- Source: 7.1.2.md

### Priority
Medium

---

## Issue: FINDING-150 - Session Creation Without User Consent or Explicit Action
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not enforce explicit user consent or action before creating new application sessions, allowing passive authentication where sessions are created without the subscriber's explicit awareness.

### Details
When a user's application session expires but their IdP session remains active, visiting any protected endpoint triggers an automatic redirect chain that silently re-establishes an application session without user interaction. The OAuth integration:
- Lacks prompt parameters (prompt=login or prompt=consent)
- Does not implement an interstitial login page
- Allows passive authentication

This violates NIST SP 800-63C guidance and makes application session timeout policies ineffective. Combined with state-changing GET endpoints, third-party content can trigger both session creation and state changes in a single redirect chain.

**Affected Files:**
- `v3/server/main.py` (lines 37-40)
- `v3/server/pages.py` (lines 136-165)

**ASVS:** 7.6.2 (Level 2)

### Remediation
1. Add 'prompt=login' or 'prompt=consent' to the OAuth initiation URL in main.py to force explicit user interaction at the IdP
2. Implement an interstitial login page with a 'Sign In' button instead of auto-redirecting to the IdP when @asfquart.auth.require detects no session
3. Add 'max_age' parameter to limit how recently the user must have authenticated at the IdP (e.g., max_age=300 for 5 minutes)
4. Convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST to prevent link-triggered state changes

### Acceptance Criteria
- [ ] OAuth prompt parameter added
- [ ] Interstitial login page implemented
- [ ] max_age parameter configured
- [ ] State-changing operations converted to POST
- [ ] Test added to verify explicit user action requirement

### References
- ASVS 7.6.2
- Source: 7.6.2.md

### Priority
High

---

## Issue: FINDING-151 - No Formal Authorization Policy Document Defining Access Rules
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application lacks a formal authorization policy document that defines function-level, data-specific, and field-level access rules, with critical authorization rules explicitly marked as incomplete ('TBD').

### Details
The existing documentation provides only minimal coverage:
- ARCHITECTURE.md contains only a single sentence on authorization
- schema.md describes the authz field as 'TBD'
- There are 10+ unresolved authorization placeholders (### check authz) in pages.py

Without documented authorization rules:
- Developers cannot implement consistent access controls
- Testers cannot verify authorization enforcement
- Administrators cannot audit compliance
- Security reviewers cannot assess completeness

This absence of comprehensive documentation has directly led to the implementation gaps identified in other findings.

**Affected Files:**
- `v3/ARCHITECTURE.md`
- `v3/docs/schema.md`
- `v3/server/pages.py` (lines 101, 167, 194, 290, 335, 349, 363, 378, 394, 413)

**ASVS:** 8.1.1, 8.1.2, 8.1.3 (Levels 1, 2, 3)
**CWE:** CWE-1059

### Remediation
Create a formal authorization policy document (e.g., AUTHORIZATION.md) that includes:
1. Role definitions with sources and descriptions (anonymous, authenticated, committer, pmc_member, election_owner, authz_group)
2. Function-level access rules mapping endpoints to required roles and resource checks
3. Data-specific rules for election management, voting, and tallying
4. Field-level access matrix showing which roles can read/write which fields based on election state
5. Decision-making factors including user role, resource ownership, group membership, voter eligibility, election state, and tamper status
6. Environmental and contextual attributes used (or explicitly NOT used) in authorization decisions
7. State transition authorization rules
8. Authorization matrix mapping roles to permitted functions

### Acceptance Criteria
- [ ] Authorization policy document created
- [ ] All required topics documented
- [ ] Document referenced from main documentation
- [ ] Authorization matrix included
- [ ] Field-level access rules documented

### References
- ASVS 8.1.1, 8.1.2, 8.1.3
- Source: 8.1.1.md, 8.1.2.md, 8.1.3.md
- CWE-1059
- Related: FINDING-066, FINDING-190

### Priority
High

---

## Issue: FINDING-152 - Authorization Tier Inconsistency: Lower Privilege Required for Management Than Creation
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application has an inverted authorization model where creating an election requires higher privileges (R.pmc_member) than performing all subsequent management operations (R.committer).

### Details
Every management endpoint includes a comment acknowledging this issue: '### need general solution'. The authorization model is inverted:
- Creation of elections (a lower-impact, reversible operation) requires R.pmc_member
- Opening/closing elections and modifying issues (higher-impact, irreversible operations) require only R.committer

A committer who should only have voter-level access can perform all administrative operations on any election. The authorization check stubs (`### check authz`) exist but are NOT CALLED, removing the ownership check that would limit impact.

**Affected Files:**
- `v3/server/pages.py` (lines 423, 445, 465, 483, 507, 530)

**ASVS:** 8.3.1 (Level 1)
**CWE:** CWE-269

### Remediation
Align management endpoint authorization with creation by:
1. Requiring R.pmc_member role for all management operations
2. Adding ownership checks using the load_election_owned decorator to all management endpoints:
   - do_add_issue_endpoint
   - do_edit_issue_endpoint
   - do_delete_issue_endpoint
   - do_open_endpoint
   - do_close_endpoint
   - do_set_open_at_endpoint
   - do_set_close_at_endpoint
   - manage_page
   - manage_stv_page
3. Consider implementing a more granular role-based access control system

### Acceptance Criteria
- [ ] Management endpoints require appropriate privilege level
- [ ] Ownership checks implemented on all management operations
- [ ] Authorization tier consistency verified
- [ ] Test added to verify authorization enforcement

### References
- ASVS 8.3.1
- Source: 8.3.1.md
- CWE-269

### Priority
High

---

## Issue: FINDING-153 - _set_election_date Modifies Election Properties Without Object-Level Authorization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `_set_election_date` helper function modifies election properties (open_at, close_at) without performing object-level authorization checks, relying only on the broken load_election decorator.

### Details
The function relies on the load_election decorator that contains an unimplemented '### check authz' placeholder. Any committer can modify the advisory open/close dates on any election, causing:
- Confusion for eligible voters and election owners
- Manipulation of election timelines

While the prevent_open_close_update trigger prevents changes after closing, dates can be freely modified while the election is editable or open. This is a direct modification of object properties without authorization, violating ASVS 8.2.3's requirement for field-level access restrictions.

**Affected Files:**
- `v3/server/pages.py` (lines 99-122)
- `v3/steve/election.py` (lines 117, 119)

**ASVS:** 8.2.3 (Level 2)
**CWE:** CWE-639

### Remediation
This is resolved by the same load_election decorator fix described in AUTHZ-001. Additionally, `_set_election_date` should:
1. Verify the election is in the editable state before allowing date modifications
2. Add explicit state check: `if not election.is_editable(): quart.abort(403, 'Cannot modify dates on a non-editable election')`

This ensures field-level write access is properly restricted based on both ownership and resource state.

### Acceptance Criteria
- [ ] Object-level authorization check added
- [ ] Election state validation added
- [ ] Ownership verification implemented
- [ ] Test added to verify authorization enforcement

### References
- ASVS 8.2.3
- Source: 8.2.3.md
- CWE-639
- Related: FINDING-010, FINDING-051, FINDING-053

### Priority
Medium

---

## Issue: FINDING-154 - Election Time-Based Validity Constraints Never Enforced
**Labels:** bug, security, priority:high
**Description:**
### Summary
The election system stores open_at and close_at timestamp fields in the database and displays them to users, but these time constraints are never validated when accepting votes or computing election state.

### Details
The `_compute_state()` method only checks:
- The manual closed flag
- The presence of cryptographic keys

It ignores the time-based validity fields entirely. This allows:
- Votes to be accepted after the displayed deadline
- Undermining of election integrity
- Creation of false expectations of enforcement

**Affected Files:**
- `v3/steve/election.py` (lines 211-222, 306-318, 367, 371)
- `v3/server/pages.py` (lines 402-412, 590-600)

**ASVS:** 9.2.1 (Level 1)

### Remediation
**Option 1:** Enforce time constraints in `_compute_state()` by:
- Adding time-based checks that compare current time against open_at and close_at fields
- Returning S_CLOSED if close_at has passed
- Returning S_EDITABLE if open_at has not yet arrived

**Option 2:** Add explicit time checks in `add_vote()` that:
- Raise ElectionBadState if the current time is outside the valid voting window

Consider implementing automated election close via background task for defense-in-depth.

### Acceptance Criteria
- [ ] Time-based validity constraints enforced
- [ ] Votes rejected outside valid time window
- [ ] Election state computation includes time checks
- [ ] Test added to verify time-based enforcement

### References
- ASVS 9.2.1
- Source: 9.2.1.md

### Priority
High

---

## Issue: FINDING-155 - Missing OIDC Audience Restriction Control
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application explicitly overrides the framework's default OIDC configuration to use a plain OAuth flow, losing the standardized ID Token 'aud' (audience) claim verification.

### Details
By disabling OIDC, the application loses audience-restricted tokens, meaning there is no verifiable mechanism at the application layer to confirm that:
1. The access token obtained was issued specifically for the STeVe application
2. Token confusion attacks (where a token issued for one relying party is replayed against another) are prevented

The developer comment '### is this really needed right now?' indicates uncertainty about whether this OIDC override is still necessary, suggesting this may be a transitional configuration that was never revisited.

**Affected Files:**
- `v3/server/main.py` (lines 36-43)

**ASVS:** 10.1.1, 10.3.1 (Level 2)
**CWE:** CWE-346

### Remediation
Re-enable OIDC and validate the ID Token's 'aud' claim:
1. Remove the OAUTH_URL_INIT and OAUTH_URL_CALLBACK overrides to use OIDC defaults
2. Configure OIDC_CLIENT_ID for audience validation
3. Set OIDC_VALIDATE_AUDIENCE to True in the app configuration

Example:
```python
def create_app():
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    app.config['OIDC_CLIENT_ID'] = 'steve-voting-app'
    app.config['OIDC_VALIDATE_AUDIENCE'] = True
    # Remove OAUTH_URL overrides
    import pages
    import api
    return app
```

### Acceptance Criteria
- [ ] OIDC re-enabled
- [ ] OIDC_CLIENT_ID configured
- [ ] OIDC_VALIDATE_AUDIENCE enabled
- [ ] Test added to verify audience validation

### References
- ASVS 10.1.1, 10.3.1
- Source: 10.1.1.md, 10.3.1.md
- CWE-346

### Priority
Medium

---

## Issue: FINDING-156 - Unverified Session Transport May Expose Tokens to Browser
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application reads session data via `asfquart.session.read()` in every authenticated handler. If the framework stores OAuth tokens in the session using Quart's default client-side signed cookie, these tokens would be exposed to the browser.

### Details
Quart's default session implementation stores all session data in a client-side signed cookie (itsdangerous-signed, base64-encoded). If the asfquart.session follows this default and stores OAuth tokens, these tokens would be:
1. Serialized into the session cookie sent to the browser with every HTTP response
2. Readable by any JavaScript on the page (if the cookie lacks HttpOnly)
3. Sent by the browser with every subsequent request to the domain

There is no visible configuration ensuring:
- Server-side session storage
- Session cookie attributes (HttpOnly, Secure, SameSite=Lax)
- Token exclusion from the session cookie payload

**Affected Files:**
- `v3/server/pages.py` (lines 65-95)

**ASVS:** 10.1.1 (Level 2)
**CWE:** CWE-522

### Remediation
Configure server-side session storage and secure cookie attributes:

```python
def create_app():
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    
    # Use server-side sessions (only session ID in cookie)
    app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'database'
    app.config['SESSION_FILE_DIR'] = '/secure/session/storage'
    
    # Harden session cookie
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session'
    
    import pages
    import api
    return app
```

Additionally, audit the asfquart framework to confirm tokens are stored server-side only.

### Acceptance Criteria
- [ ] Server-side session storage configured
- [ ] Session cookie attributes hardened
- [ ] Framework audit confirms server-side token storage
- [ ] Test added to verify session cookie security

### References
- ASVS 10.1.1
- Source: 10.1.1.md
- CWE-522

### Priority
High

---

## Issue: FINDING-157 - OAuth Authorization Flow Lacks PKCE
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application explicitly overrides the framework's OAuth URL templates without including PKCE (Proof Key for Code Exchange) parameters, leaving the authorization code flow vulnerable to interception attacks.

### Details
The authorization URL includes only 'state' and 'redirect_uri' with no 'code_challenge' or 'code_challenge_method' parameters. The token exchange URL includes only 'code' with no 'code_verifier' parameter.

Without PKCE:
- An attacker who intercepts an authorization code can exchange it at the token endpoint
- No proof of the original requestor is required
- The 'state' parameter alone prevents CSRF but does not prevent authorization code injection

**Affected Files:**
- `v3/server/main.py` (lines 35-42)

**ASVS:** 10.1.2, 10.2.1, 10.4.6 (Levels 2, 3)

### Remediation
1. Implement PKCE parameter generation function that creates:
   - Cryptographically random code_verifier (43-128 characters)
   - S256 code_challenge per RFC 7636
2. Update OAuth URL templates to include:
   - code_challenge and code_challenge_method=S256 in OAUTH_URL_INIT
   - code_verifier in OAUTH_URL_CALLBACK
3. Integrate PKCE into OAuth flow by:
   - Storing code_verifier in server-side session during authorization request
   - Retrieving it for token exchange
4. Coordinate with oauth.apache.org administrators to ensure PKCE is enforced
5. Implement automated tests to verify PKCE parameters

### Acceptance Criteria
- [ ] PKCE parameter generation implemented
- [ ] OAuth URLs updated with PKCE parameters
- [ ] code_verifier stored in session
- [ ] Test added to verify PKCE presence

### References
- ASVS 10.1.2, 10.2.1, 10.4.6
- Source: 10.1.2.md, 10.2.1.md, 10.4.6.md

### Priority
High

---

## Issue: FINDING-158 - OAuth State Parameter Security Properties Unverifiable
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The 'state' parameter security properties are unverifiable because the OAuth callback handler is entirely within the 'asfquart' framework, which is not available for audit.

### Details
ASVS 10.1.2 requires that the 'state' parameter is:
1. Not guessable — generated with a cryptographically secure random number generator
2. Specific to the transaction — unique per authorization request
3. Securely bound to the client and user agent session

However:
- The OAuth callback handler is not present in any of the provided source files
- The state generation logic is not visible
- The state validation logic is not visible
- The session binding mechanism is opaque
- The 'basic.csrf_token = placeholder' pattern raises concern about whether OAuth state parameter handling is robust

**Affected Files:**
- `v3/server/main.py` (lines 35-38)
- `v3/server/pages.py` (line 89)

**ASVS:** 10.1.2, 10.5.1 (Levels 2, 3)

### Remediation
1. Obtain and audit the 'asfquart' framework source code — specifically the OAuth callback handler, state generation, and state validation logic
2. Verify that 'state' is generated using `secrets.token_urlsafe(32)` or equivalent
3. Verify that 'state' is stored in a server-side session before the redirect
4. Verify that the callback handler rejects requests where the returned 'state' does not match the session-stored value
5. Document the framework's OAuth security properties as part of the application's security architecture

### Acceptance Criteria
- [ ] Framework source code audited
- [ ] State generation verified as cryptographically secure
- [ ] State validation verified
- [ ] Session binding verified
- [ ] OAuth security properties documented

### References
- ASVS 10.1.2, 10.5.1
- Source: 10.1.2.md, 10.5.1.md

### Priority
Medium

---

## Issue: FINDING-159 - OAuth Authorization Request Does Not Specify Required Scopes
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The OAuth authorization request URL template does not include a `scope` parameter, preventing the authorization server from presenting users with information about what data or permissions the application is requesting.

### Details
Without scopes:
- The authorization server cannot present the user with information about requested authorizations
- Users cannot make informed consent decisions about personal data sharing (uid, name, email)
- The authorization server's consent screen cannot distinguish between minimal authentication and full profile data

The URL template includes only `state` and `redirect_uri` parameters with no `scope` parameter (e.g., `openid`, `profile`, `email`).

**Affected Files:**
- `v3/server/main.py` (lines 37-41)
- `v3/server/pages.py` (lines 85-91)

**ASVS:** 10.2.3, 10.3.2, 10.4.11, 10.7.2 (Levels 2, 3)

### Remediation
**Option 1 — Direct URL Template Modification:**

```python
REQUIRED_SCOPES = 'openid uid email'

asfquart.generics.OAUTH_URL_INIT = (
    f'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&scope={REQUIRED_SCOPES}'
)
```

**Option 2 — Framework Configuration:**

```python
app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
app.config['OAUTH_SCOPES'] = 'openid uid email'
```

**Additional Steps:**
1. Document the rationale for each requested scope
2. Map scopes to specific session fields consumed by the application
3. Coordinate with oauth.apache.org administrators to confirm available scopes
4. Verify that the minimal scope set still provides all required functionality
5. Validate returned scopes in the token response

### Acceptance Criteria
- [ ] Scope parameter added to OAuth URL
- [ ] Minimal required scopes documented
- [ ] Scope rationale documented
- [ ] Test added to verify scope presence

### References
- ASVS 10.2.3, 10.3.2, 10.4.11, 10.7.2
- Source: 10.2.3.md, 10.3.2.md, 10.4.11.md, 10.7.2.md

### Priority
Medium

---

## Issue: FINDING-160 - User Identity Derived from Opaque `uid` Session Field Without Verifiable Token Claims
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application derives user identity from a session field `uid` without verifiable proof that this identifier originates from non-reassignable OAuth token claims (`iss` + `sub`).

### Details
All authorization decisions throughout the application depend on this single `uid` field, which is populated by the opaque `asfquart` framework during OAuth token exchange. The application code has no mechanism to verify that this `uid` was derived from the non-reassignable combination of `iss` (issuer) and `sub` (subject) claims.

If the framework populates `uid` from a reassignable claim (such as `preferred_username`, `email`, or a custom attribute), a user who inherits a recycled identifier could gain access to another user's:
- Election permissions
- Votes
- Administrative privileges

The entire authorization chain depends on the external framework making the correct claim selection—a trust assumption that is neither documented nor verified.

**Affected Files:**
- `v3/server/pages.py` (lines 89-98, 157, 274, 329, 438, 475, 496, 514, 626)
- `v3/server/main.py` (lines 38-42)

**ASVS:** 10.3.3 (Level 2)

### Remediation
The application should explicitly verify that user identity is derived from `iss` + `sub` claims. Implement verification in the `basic_info()` function to:
1. Extract `iss` and `sub` claims from the session
2. Validate the expected issuer (https://oauth.apache.org)
3. Use the iss+sub combination as the canonical identity
4. Map this to uid via a verified lookup

**Immediate actions:**
- Audit the `asfquart` framework to verify that the `uid` session field is derived from non-reassignable token claims

**Short-term:**
- Expose `iss` and `sub` in the session for application-level validation
- Add issuer validation check in `basic_info()`

**Long-term:**
- Document the identity model explicitly, mapping uid to LDAP uid to OAuth sub claim

### Acceptance Criteria
- [ ] Framework audit confirms uid derived from non-reassignable claims
- [ ] iss and sub claims exposed in session
- [ ] Issuer validation added
- [ ] Identity model documented
- [ ] Test added to verify identity derivation

### References
- ASVS 10.3.3
- Source: 10.3.3.md

### Priority
High

## Issue: FINDING-161 - Missing Authentication Recentness Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not verify authentication recentness before allowing sensitive operations (voting, opening/closing elections). The session contains only uid, fullname, and email without authentication timestamps, allowing stale sessions to be exploited for unauthorized actions.

### Details
- OIDC is explicitly disabled, removing the standard `auth_time` claim mechanism
- No authentication timestamp is stored in the session object
- Sensitive operations proceed without verifying when the user last authenticated
- Stale sessions can be exploited to cast votes without requiring recent authentication
- Affects core security property of the voting system

**Affected Files:**
- `v3/server/main.py` (lines 37-43)
- `v3/server/pages.py` (lines 85-95, 443-482, 507-525, 528-544, 485-504)

**ASVS:** 10.3.4 (L2)

### Remediation
1. Store `auth_time` in session during OAuth callback: Record `int(time.time())` when session is established
2. Implement a `require_recent_auth()` helper function that checks if `(time.time() - auth_time)` exceeds the maximum age threshold
3. Apply recentness checks before sensitive operations, particularly voting (MAX_AUTH_AGE_VOTING = 3600 seconds)
4. Redirect users to re-authenticate if auth_time check fails

### Acceptance Criteria
- [ ] Authentication timestamp stored in session during OAuth callback
- [ ] `require_recent_auth()` helper function implemented
- [ ] Recentness checks applied before voting operations
- [ ] Recentness checks applied before election management operations
- [ ] Test added for expired authentication scenarios
- [ ] Test added for valid recent authentication

### References
- ASVS 10.3.4
- Source: 10.3.4.md

### Priority
Medium

---

## Issue: FINDING-162 - Missing Authentication Method and Strength Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application performs no verification of authentication method or strength despite having operations of varying sensitivity. Administrative operations can be performed with any authentication method, including potentially weak ones, without MFA requirements.

### Details
- No verification of authentication method (e.g., MFA for administrative operations)
- Framework distinguishes R.committer from R.pmc_member roles but these are authorization checks only
- Election integrity relies entirely on initial authentication quality
- Administrative operations (open, close, create, delete issues) lack authentication strength requirements
- No capture or verification of `acr` or `amr` claims from identity provider

**Affected Files:**
- `v3/server/pages.py` (lines 443-482, 507-525, 528-544, 485-504)

**ASVS:** 10.3.4 (L2)

### Remediation
1. If using OIDC (recommended), capture and verify `acr` (Authentication Context Class Reference) and `amr` (Authentication Methods References) claims during session creation
2. Implement a `require_auth_strength()` function that verifies actual_acr matches required_acr for the operation sensitivity level
3. For administrative operations (election management), require MFA methods in amr claim (e.g., 'mfa', 'otp', 'hwk')
4. Return HTTP 403 with descriptive error if authentication strength is insufficient
5. Long-term: Evaluate OIDC adoption to gain standard acr/amr/auth_time claims from the identity provider

### Acceptance Criteria
- [ ] Authentication method claims captured during session creation
- [ ] `require_auth_strength()` function implemented
- [ ] MFA required for election management operations
- [ ] Appropriate HTTP 403 responses for insufficient auth strength
- [ ] Test added for MFA requirement enforcement
- [ ] Test added for non-MFA rejection on admin operations

### References
- ASVS 10.3.4
- Source: 10.3.4.md

### Priority
Medium

---

## Issue: FINDING-163 - No Visible Client Authentication for OAuth Token Exchange
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The server-side application should operate as a confidential OAuth client but has no visible client authentication mechanism in the codebase. Critical authentication elements are missing for backchannel requests to the authorization server.

### Details
- No `client_secret` configuration visible in code or configuration
- No client certificate for mTLS configured
- No `private_key_jwt` configuration with signing keys
- Token URL format uses query parameters (`token?code=%s`) potentially exposing authorization codes in server logs
- Framework (`asfquart`) handles token endpoint requests but internals cannot be verified
- Violates RFC 6749 §2.1 requirement for confidential client authentication

**Affected Files:**
- `v3/server/main.py` (lines 38-41)

**ASVS:** 10.4.10 (L2)
**CWE:** CWE-306

### Remediation
**Immediate Actions:**
1. Verify current configuration by obtaining and reviewing `asfquart` framework source code
2. Confirm client registration with Apache Infrastructure as a confidential client

**Implementation Options:**
- **Option 1 (Minimum):** Client Secret - Add `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` from environment variables, `OAUTH_CLIENT_AUTH_METHOD = 'client_secret_post'`
- **Option 2 (Recommended):** Private Key JWT - Configure `OAUTH_CLIENT_AUTH_METHOD = 'private_key_jwt'`, `OAUTH_SIGNING_KEY_PATH`, `OAUTH_SIGNING_ALG = 'RS256'`
- **Option 3:** Mutual TLS - Configure `OAUTH_CLIENT_AUTH_METHOD = 'tls_client_auth'` with client certificate

**Token Exchange Protocol Fix:**
- Ensure authorization code transmitted via POST body parameters rather than query parameters

### Acceptance Criteria
- [ ] Client authentication method determined and documented
- [ ] Client credentials configured (secret, certificate, or private key)
- [ ] Token exchange uses POST body parameters
- [ ] Debug logging enabled for OAuth token exchange
- [ ] Test verifies token exchange fails with invalid credentials
- [ ] Security configuration documented

### References
- ASVS 10.4.10
- RFC 6749 §2.1, §4.1.3
- Related: FINDING-044
- Source: 10.4.10.md

### Priority
Medium

---

## Issue: FINDING-164 - OAuth Client Authorization Request Does Not Explicitly Specify response_mode
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The authorization URL template omits `response_mode` parameter, relying entirely on external AS enforcement. Without explicit specification, an attacker could manipulate the request to use fragment-based responses, potentially intercepting authorization codes.

### Details
- Authorization URL template omits both `response_mode` and `response_type`
- No defense-in-depth from client side
- Attacker could append `response_mode=fragment` causing authorization code to be returned in URL fragment
- Fragment-based responses not sent to server and can be intercepted by client-side scripts
- Can be leaked via Referer header
- Comment `# Avoid OIDC` suggests deliberate departure from OIDC defaults

**Affected Files:**
- `v3/server/main.py` (lines 39-43)

**ASVS:** 10.4.12 (L3)

### Remediation
**Option 1 (Recommended):** Explicitly specify `response_mode` and `response_type`:
```python
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?response_type=code&response_mode=query&state=%s&redirect_uri=%s'
)
```

**Option 2:** Use Pushed Authorization Requests (PAR) per RFC 9126

**Option 3:** Use JWT-Secured Authorization Request (JAR) per RFC 9101

### Acceptance Criteria
- [ ] `response_mode=query` explicitly specified in authorization URL
- [ ] `response_type=code` explicitly specified
- [ ] Test verifies fragment responses are rejected
- [ ] Consider PKCE implementation for additional security
- [ ] Validation added for callback containing `code` parameter

### References
- ASVS 10.4.12
- RFC 9126 (PAR)
- RFC 9101 (JAR)
- Source: 10.4.12.md

### Priority
Medium

---

## Issue: FINDING-165 - OAuth Client Confidentiality Classification Cannot Be Verified
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application's OAuth client confidentiality classification cannot be verified due to lack of explicit client credential configuration or client type enforcement. No mechanism exists to ensure the client authenticates as a confidential client.

### Details
- Application is architecturally a server-side confidential client
- No explicit client credential configuration (client_id/client_secret) visible
- No client registration metadata shows `token_endpoint_auth_method` set to confidential method
- Token endpoint URL passes only authorization code, mirroring public client pattern
- Cannot verify client's ability to maintain credential confidentiality

**Affected Files:**
- `v3/server/main.py` (lines 35-51)

**ASVS:** 10.4.16 (L3)

### Remediation
1. Explicitly register the client as a confidential client with the authorization server (oauth.apache.org)
2. Configure the application with appropriate client credentials and authentication method
3. Document the client type classification in application security documentation
4. Add configuration validation to ensure confidential client credentials are present and properly secured

### Acceptance Criteria
- [ ] Client registered as confidential with authorization server
- [ ] Client credentials configured and secured
- [ ] Client type documented in security documentation
- [ ] Configuration validation added for confidential client requirements
- [ ] Test added verifying client authentication occurs

### References
- ASVS 10.4.16
- RFC 6749 §2.1
- Source: 10.4.16.md

### Priority
Medium

---

## Issue: FINDING-166 - No Visible Session/Token Absolute Expiration Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application lacks visible enforcement of absolute session or token expiration at the client level. Sessions derived from OAuth tokens could persist indefinitely, increasing the window for session hijacking in a voting application.

### Details
- No application-level mechanism to ensure sessions respect absolute expiration boundaries
- `asfquart.construct()` call includes no session lifetime configuration
- `basic_info()` performs no timestamp-based session validation
- Client session may outlive intended token lifetime even if AS properly expires refresh tokens
- Long-lived sessions particularly problematic for voting application with temporal security requirements

**Affected Files:**
- `v3/server/main.py` (lines 36-48)
- `v3/server/pages.py` (lines 60-90)

**ASVS:** 10.4.8 (L2, L3)

### Remediation
**Step 1:** Configure explicit session absolute expiration:
```python
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(hours=8)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

**Step 2:** Store authentication timestamp in session (`created_at` field) and validate in `basic_info()`:
```python
if (time.time() - session.get('created_at', 0)) > MAX_SESSION_AGE:
    # Invalidate session
```

**Step 3:** Store creation timestamp in OAuth callback handler using `time.time()`

### Acceptance Criteria
- [ ] Session absolute expiration configured (8 hours)
- [ ] Session cookie security flags set
- [ ] Authentication timestamp stored in session
- [ ] Session age validation in `basic_info()`
- [ ] Test added for session expiration
- [ ] Test added for valid session within time limit

### References
- ASVS 10.4.8
- Source: 10.4.8.md

### Priority
Medium

---

## Issue: FINDING-167 - No User-Facing Session or Token Revocation Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application provides no logout endpoint, session revocation mechanism, or integration with the Authorization Server's token revocation endpoint. Users cannot invalidate their sessions or trigger token revocation.

### Details
- No logout endpoint exists among all 21 routes
- No session revocation mechanism implemented
- No integration with RFC 7009 token revocation endpoint
- `/profile` and `/settings` pages contain no session management functionality
- Attacker with valid session cookie can use it indefinitely
- No user-accessible option to revoke sessions

**Affected Files:**
- `v3/server/pages.py` (lines 582-597, entire application scope)
- `v3/server/main.py` (lines 39-42)

**ASVS:** 10.4.9 (L2, L3)

### Remediation
1. **Add Logout Endpoint:** Create `/logout` route that clears local session and revokes tokens at AS using RFC 7009 Token Revocation endpoint
2. **Add Session Management UI:** Enhance `/settings` page to display active sessions with per-session revocation capability
3. **Update Configuration:** Add `OAUTH_URL_REVOKE` configuration pointing to AS revocation endpoint (https://oauth.apache.org/revoke)
4. **Add Logout Links:** Include logout links in navigation on all authenticated pages
5. **Implement Session Listing:** Display sessions with 'last accessed' timestamps

### Acceptance Criteria
- [ ] `/logout` endpoint implemented
- [ ] Session cleared on logout
- [ ] Token revocation called at AS
- [ ] Session management UI added to `/settings`
- [ ] Logout links added to navigation
- [ ] Test added for logout functionality
- [ ] Test added for token revocation

### References
- ASVS 10.4.9
- RFC 7009 (Token Revocation)
- Source: 10.4.9.md

### Priority
Medium

---

## Issue: FINDING-168 - No Technical Enforcement of Identifier Immutability
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application uses `s['uid']` as the sole user identifier for all security decisions without technical enforcement that the identifier originates from a non-reassignable claim. No compound identifier (iss + sub) is used to ensure uniqueness across identity providers.

### Details
- `uid` populated by asfquart framework during OAuth callback
- No verification that `uid` originates from contractually non-reassignable claim
- No verification `uid` hasn't been modified between IdP and session
- No binding to single identity provider (no 'iss' + 'sub' compound key)
- Risk of user identity confusion if identity provider changes or system deployed in different context

**Affected Files:**
- `v3/server/pages.py` (lines 77-88)
- `v3/server/bin/asf-load-ldap.py` (lines 55-59)

**ASVS:** 10.5.2 (L2, L3)

### Remediation
Use compound identifier ('iss' + 'sub') or validate that identifier source guarantees non-reassignment:

```python
basic.update(
    uid=s['sub'],
    issuer=s['iss'],
    name=s['fullname'],
    email=s['email']
)
```

This ensures uniqueness across federated identity providers and provides technical enforcement of identifier immutability.

### Acceptance Criteria
- [ ] Compound identifier (iss + sub) implemented
- [ ] Session stores both issuer and subject
- [ ] User lookups use compound identifier
- [ ] Database schema updated if needed
- [ ] Migration path for existing sessions documented
- [ ] Test added for identifier uniqueness across issuers

### References
- ASVS 10.5.2
- OIDC Core 1.0
- Source: 10.5.2.md

### Priority
Medium

---

## Issue: FINDING-169 - No Authorization Server Issuer Validation Mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application defines no expected issuer URL and implements no mechanism to validate that authorization server metadata or token responses originate from the expected issuer. Deliberate OIDC bypass also bypasses metadata issuer validation.

### Details
- OAuth endpoints configured via hardcoded URL strings
- No expected issuer URL defined
- Comment 'Avoid OIDC' indicates deliberate bypass of OIDC discovery
- Bypasses metadata issuer validation requirement
- DNS hijack or MITM could allow rogue AS impersonation
- No validation that metadata originates from legitimate AS

**Affected Files:**
- `main.py` (lines 37-42)
- `pages.py` (lines 83-89)

**ASVS:** 10.5.3 (L2, L3)

### Remediation
Configure expected issuer URL and validate against AS metadata and token responses:

1. Define `EXPECTED_ISSUER` constant: `'https://oauth.apache.org'`
2. Configure asfquart framework to validate issuer if supported
3. Add middleware to validate `iss` claim in session/tokens before processing
4. Reject sessions from unexpected issuers
5. If migrating to OIDC discovery, implement metadata fetching with exact issuer match validation

### Acceptance Criteria
- [ ] Expected issuer URL configured
- [ ] Issuer validation implemented for tokens/sessions
- [ ] Middleware added to check issuer before processing
- [ ] Sessions from unexpected issuers rejected
- [ ] Test added for issuer mismatch rejection
- [ ] Test added for valid issuer acceptance

### References
- ASVS 10.5.3
- OIDC Discovery 1.0
- Source: 10.5.3.md

### Priority
Medium

---

## Issue: FINDING-170 - Missing Explicit response_type=code Parameter in OAuth Authorization URL
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The OAuth authorization URL template does not include the required `response_type=code` parameter. Without explicit specification, the application relies entirely on external OP default behavior, risking token leakage if implicit flow is used.

### Details
- `response_type=code` is REQUIRED per RFC 6749 §4.1.1
- Callback URL pattern implies code flow expected but authorization request doesn't enforce it
- If OP defaults to `response_type=token`, access tokens returned in URL fragment
- Token leakage vectors: browser history, referrer header, JavaScript access, server logs
- Directly contradicts ASVS 10.6.1 prohibition of implicit flow

**Affected Files:**
- `v3/server/main.py` (lines 36-41)

**ASVS:** 10.6.1 (L2, L3)

### Remediation
Explicitly include `response_type=code` in authorization URL:

```python
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?response_type=code&state=%s&redirect_uri=%s'
)
```

**Additional Recommendations:**
1. Verify whether `asfquart` framework adds `response_type` internally
2. Consider adding PKCE parameters
3. Implement defense-in-depth by validating callback contains `code` parameter
4. Re-evaluate intentional OIDC bypass

### Acceptance Criteria
- [ ] `response_type=code` explicitly added to authorization URL
- [ ] Callback validation ensures `code` parameter present
- [ ] Test added for implicit flow rejection
- [ ] PKCE implementation considered and documented
- [ ] Framework behavior documented

### References
- ASVS 10.6.1
- RFC 6749 §4.1.1
- Source: 10.6.1.md

### Priority
Medium

---

## Issue: FINDING-171 - Missing Consent Enforcement Parameters in OAuth Authorization Flow
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The OAuth authorization URL configuration omits all consent-enforcing parameters and explicitly disables OIDC support, making it impossible to verify or guarantee user consent on each authorization request.

### Details
- No `prompt`, `consent_prompt`, or `scope` parameters included
- Explicitly avoids OIDC (which provides standardized consent mechanisms)
- AS may silently issue tokens without displaying consent screen
- Silent re-authorization possible without user awareness
- Critical for voting system where explicit consent is essential

**Affected Files:**
- `v3/server/main.py` (lines 36-42)

**ASVS:** 10.7.1 (L2, L3)

### Remediation
Switch to OIDC or add consent parameters:

**Option 1 (Recommended):** Use OIDC with explicit consent:
```python
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?'
    'response_type=code&'
    'scope=openid+profile+email&'
    'prompt=consent&'
    'state=%s&redirect_uri=%s'
)
```

**Option 2:** If OIDC not feasible:
- Coordinate with oauth.apache.org operators to confirm consent always prompted
- Document as compensating control
- Add `scope` parameter so consent screen shows permissions
- Log whether authorization was freshly consented vs. silent

### Acceptance Criteria
- [ ] Consent parameters added or OIDC adopted
- [ ] Scope parameter included in authorization URL
- [ ] Consent prompt enforced
- [ ] Authorization consent status logged
- [ ] Test added verifying consent screen displayed
- [ ] Compensating controls documented if applicable

### References
- ASVS 10.7.1
- OIDC Core 1.0
- Source: 10.7.1.md

### Priority
Medium

---

## Issue: FINDING-172 - Deliberate OIDC Avoidance Eliminates Standardized Consent and Identity Claims
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application deliberately overrides framework's default OAuth/OIDC URLs to 'avoid OIDC,' eliminating standardized consent mechanisms including well-defined scopes, standardized claims, and the `prompt=consent` parameter.

### Details
- Custom ASF OAuth endpoint replaces OIDC
- Loss of standardized `scope` values mapping to well-defined data categories
- Loss of `prompt=consent` mechanism
- Loss of ID Token claims documenting authorized data
- Loss of client identification in consent presentation
- Users may be authenticated without consent prompt
- Generic prompts don't specify STeVe application name or data access

**Affected Files:**
- `v3/server/main.py` (lines 35-36, 37-41)

**ASVS:** 10.7.2 (L2, L3)

### Remediation
Re-evaluate OIDC bypass decision. If ASF OAuth server supports OIDC:

```python
def create_app():
    # Use standard OIDC flow for proper consent management
    # Do NOT override asfquart.generics.OAUTH_URL_INIT
    # Let framework use default OIDC endpoints
    
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    
    # If custom endpoints needed, preserve OIDC parameters
    import pages
    import api
    return app
```

### Acceptance Criteria
- [ ] OIDC bypass decision re-evaluated and documented
- [ ] If OIDC adopted, standard scopes used
- [ ] Consent mechanism properly configured
- [ ] Client identification visible in consent screen
- [ ] Test added for OIDC consent flow
- [ ] Justification documented if OIDC not adopted

### References
- ASVS 10.7.2
- OIDC Core 1.0
- Source: 10.7.2.md

### Priority
Medium

---

## Issue: FINDING-173 - Authorization Tiers Not Reflected in OAuth Consent
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application enforces a two-tiered authorization model internally (committer vs. PMC member) but the OAuth consent flow is identical for all users regardless of privilege tier. Users are not informed during consent that LDAP group membership determines administrative privileges.

### Details
- Tier 1 (R.committer): voting, election viewing, election management
- Tier 2 (R.pmc_member): election creation (higher privilege)
- Single OAuth flow for all users regardless of eventual privileges
- Users not informed LDAP group membership determines privileges
- No scope differentiation between basic voter and admin access
- AS consent screen cannot distinguish access levels

**Affected Files:**
- `v3/server/pages.py` (lines 518, 540, 561, 580, 632, 476)
- `v3/server/main.py` (lines 37-39)

**ASVS:** 10.7.2 (L2, L3)

### Remediation
Define distinct OAuth scopes or Rich Authorization Request (RAR) details mapping to privilege tiers:

```python
# Define scope sets for different authorization contexts
SCOPE_VOTER = 'openid profile email steve:vote'
SCOPE_ADMIN = 'openid profile email steve:vote steve:manage'

# Request elevated scopes for admin functions
# Or implement step-up consent for management operations
```

**Alternative:** If custom scopes not supported, implement application-level consent screen before granting elevated privileges showing specific privileges, session duration, and data access.

### Acceptance Criteria
- [ ] Distinct scopes defined for voter vs. admin access
- [ ] Consent flow differentiates privilege levels
- [ ] Users informed of LDAP group membership usage
- [ ] Application-level consent for admin operations if needed
- [ ] Authorization lifetime disclosed
- [ ] Test added for tiered consent flow

### References
- ASVS 10.7.2
- RFC 9396 (Rich Authorization Requests)
- Source: 10.7.2.md

### Priority
Medium

---

## Issue: FINDING-174 - Complete Absence of Consent Management Functionality
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application provides no mechanism for users to review, modify, or revoke OAuth consents granted through the authorization server. Users cannot exercise control over delegated authorization or review application data access.

### Details
- No consent management interface exists
- Users cannot review what data application accesses
- Cannot revoke application access without visiting AS directly
- No visibility into granted permissions
- No consent history or audit trail

**Affected Files:**
- `v3/server/pages.py` (lines 554-560, 563-569)

**ASVS:** 10.7.3 (L2, L3)

### Remediation
Implement comprehensive consent management:

1. **Consent Review Page:** Create `/consents` endpoint displaying active grants, scopes, timestamps
2. **Consent Revocation Endpoint:** Create `/revoke-consent` POST endpoint that calls AS token revocation (RFC 7009), clears local session, logs revocation
3. **Store Consent Metadata:** Store access_token, granted_scopes, auth_time, authorization_server URL at authentication
4. **Add UI Links:** Integrate into `/profile` and `/settings` pages
5. **Scope Modification:** Allow users to adjust scope permissions
6. **Consent History:** Track grants, modifications, revocations for audit

### Acceptance Criteria
- [ ] `/consents` page implemented showing active grants
- [ ] `/revoke-consent` endpoint implemented
- [ ] Consent metadata stored at authentication
- [ ] UI links added to profile/settings
- [ ] Scope modification capability added
- [ ] Consent history tracking implemented
- [ ] Test added for consent review
- [ ] Test added for consent revocation

### References
- ASVS 10.7.3
- RFC 7009 (Token Revocation)
- Source: 10.7.3.md

### Priority
Medium

---

## Issue: FINDING-175 - No TLS/Cipher Configuration for ASGI Deployment Mode
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ASGI deployment mode provides no TLS configuration whatsoever. No Hypercorn configuration file, command-line guidance, or programmatic SSLContext configuration exists, leaving deployments without secure cipher suite baselines.

### Details
- ASGI mode creates application but provides no TLS configuration
- No hypercorn.toml configuration file provided
- No --ciphers, --certfile, --keyfile, --ssl-version guidance documented
- No programmatic SSLContext configuration in run_asgi()
- Deployments will lack TLS or use permissive defaults
- No cipher suite baseline for production
- Application performs no check that TLS is active in ASGI environment

**Affected Files:**
- `v3/server/main.py` (lines 94-115, 99-118, 91-109, 115-126, 95-115)

**ASVS:** 12.1.2, 12.1.3, 12.3.1, 12.3.3 (L2)

### Remediation
1. **Provide Hypercorn Configuration:** Create hypercorn.toml with bind, certfile, keyfile, ciphers using recommended cipher suite string
2. **Document Invocation:** `uv run python -m hypercorn --config hypercorn.toml main:steve_app`
3. **Enforce TLS 1.2+:** Configure minimum TLS version and forward-secret cipher suites only
4. **Add Startup Validation:** Check TLS configuration exists in ASGI mode, exit with critical error if not configured
5. **Runtime Warnings:** Alert operators about TLS configuration requirements in ASGI mode
6. **Update Documentation:** Provide secure invocation examples with --certfile and --keyfile flags

### Acceptance Criteria
- [ ] hypercorn.toml configuration file created
- [ ] TLS 1.2+ enforced in configuration
- [ ] Forward-secret cipher suites configured
- [ ] Startup validation added for TLS configuration
- [ ] Runtime warnings implemented
- [ ] Documentation updated with secure examples
- [ ] Test added verifying TLS enforcement

### References
- ASVS 12.1.2, 12.1.3, 12.3.1, 12.3.3
- Source: 12.1.2.md, 12.1.3.md, 12.3.1.md, 12.3.3.md, 12.1.5.md

### Priority
Medium

---

## Issue: FINDING-176 - Example Configuration Lacks Cipher Suite and TLS Version Settings
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The example configuration file (config.yaml.example) is the primary deployment reference but only includes certfile and keyfile settings. No cipher suite configuration, TLS version settings, or OCSP stapling configuration exists.

### Details
- config.yaml.example contains only certfile and keyfile
- No cipher suite configuration options
- No tls_version_min or ciphers fields
- Every deployment inherits Python/system default cipher suites
- No configuration-driven ASVS 12.1.2 compliance mechanism
- Operators must modify source code for compliant cipher configuration
- No OCSP Stapling configuration anywhere

**Affected Files:**
- `v3/server/config.yaml.example` (lines 23-31, 28-30)
- `v3/server/main.py` (lines 103-120)

**ASVS:** 12.1.2, 12.1.4 (L2, L3)

### Remediation
Extend configuration schema to include TLS hardening:

```yaml
server:
  tls_min_version: '1.2'
  ciphers: 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'
  prefer_server_ciphers: true
  ocsp_staple_file: /path/to/ocsp.der
  certfile: localhost.apache.org+3.pem
  keyfile: localhost.apache.org+3-key.pem
```

Update configuration parser in main.py to consume settings when constructing SSLContext. For ASGI, provide hypercorn_config.py template. Document reverse proxy OCSP Stapling configuration.

### Acceptance Criteria
- [ ] Configuration schema extended with TLS settings
- [ ] Example config updated with cipher suite configuration
- [ ] OCSP stapling configuration added
- [ ] Configuration parser updated to apply settings
- [ ] Hypercorn configuration template created
- [ ] Reverse proxy OCSP documentation provided
- [ ] Test added for configuration parsing

### References
- ASVS 12.1.2, 12.1.4
- Source: 12.1.2.md, 12.1.4.md

### Priority
Medium

---

## Issue: FINDING-177 - No Certificate Revocation Checking for Outbound OAuth Connections
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application makes outbound HTTPS connections to Apache OAuth service without visible certificate revocation checking (OCSP or CRL). Compromised and revoked OAuth server certificates would still be trusted.

### Details
- No OCSP checking configuration for OAuth endpoint certificate
- No CRL distribution point for validation
- No SSL context for outbound connections with revocation verification
- Compromised OAuth server certificate would be trusted even after revocation
- MITM attack with revoked certificate would not be detected
- Authorization codes and tokens could be intercepted

**Affected Files:**
- `v3/server/main.py` (lines 44-48, 38-41, 42-45)

**ASVS:** 12.1.4, 12.3.2, 12.3.4 (L2, L3)
**CWE:** CWE-295

### Remediation
Configure outbound HTTPS connections with certificate revocation verification:

```python
import ssl
import certifi

def create_secure_ssl_context():
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
    return ctx

oauth_ssl_context = create_secure_ssl_context()
# Pass to asfquart or underlying HTTP client
```

Optionally pin to Let's Encrypt / specific CA for oauth.apache.org.

### Acceptance Criteria
- [ ] SSL context created with revocation checking
- [ ] OCSP checking enabled for outbound connections
- [ ] Certificate verification enforced
- [ ] Context passed to OAuth HTTP client
- [ ] CA bundle configured (certifi)
- [ ] Test added for revocation checking
- [ ] Test added for revoked certificate rejection

### References
- ASVS 12.1.4, 12.3.2, 12.3.4
- Source: 12.1.4.md, 12.3.2.md, 12.3.4.md

### Priority
Medium

---

## Issue: FINDING-178 - TLS Configuration Allows Plain HTTP as Valid Deployment Mode
**Labels:** bug, security, priority:high
**Description:**
### Summary
TLS configuration is entirely optional. Leaving certfile/keyfile blank results in plain HTTP without warnings or startup failure. All internal communication between reverse proxy and application would occur in plaintext, exposing authentication tokens, OAuth credentials, vote data, and session cookies.

### Details
- Example config explicitly documents plain HTTP mode
- Conditional `if app.cfg.server.certfile:` allows silent HTTP degradation
- No warning or startup failure without TLS
- Proxy-to-application internal link should always be encrypted
- OAuth tokens, ballot submissions, session cookies exposed without TLS
- No validation that TLS termination occurs somewhere in chain

**Affected Files:**
- `v3/server/config.yaml.example` (lines 30-32, 28-31)
- `v3/server/main.py` (lines 83-86, 79-87)

**ASVS:** 12.3.4, 12.3.5, 13.3.4 (L2, L3)
**CWE:** CWE-319

### Remediation
Make TLS mandatory by failing startup if certificates not configured:

```python
if app.cfg.server.certfile and app.cfg.server.keyfile:
    # configure TLS
else:
    _LOGGER.critical('TLS is not configured! Set server.certfile and server.keyfile in config.yaml. Refusing to start without TLS.')
    sys.exit(1)
```

Update config.yaml.example to remove 'leave blank for plain HTTP' guidance:
```yaml
# REQUIRED: Specify the .pem files to serve using TLS.
# The server will not start without valid TLS configuration.
certfile: localhost.apache.org+3.pem
keyfile: localhost.apache.org+3-key.pem
```

Add startup validation with explicit `require_tls: true` configuration option.

### Acceptance Criteria
- [ ] TLS made mandatory in code
- [ ] Startup fails without TLS configuration
- [ ] Config example updated to require TLS
- [ ] `require_tls` configuration option added
- [ ] Critical log message for missing TLS
- [ ] Test added for startup failure without TLS
- [ ] Test added for successful TLS startup
- [ ] Related: FINDING-014

### References
- ASVS 12.3.4, 12.3.5, 13.3.4
- CWE-319
- Source: 12.3.4.md, 12.3.5.md, 13.3.4.md

### Priority
High

---

## Issue: FINDING-179 - Non-Constant-Time Comparison of Cryptographic Key Material
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The tamper detection mechanism (`is_tampered()` function) compares recomputed opened_key against stored value using Python's standard `!=` operator, which short-circuits on the first differing byte, creating a timing side-channel that could leak key material.

### Details
- Python's `!=` operator short-circuits at first differing byte
- Creates timing side-channel for key material comparison
- `opened_key` is root from which all vote tokens are derived
- Attacker with local access could measure timing differences
- Could incrementally reconstruct stored opened_key
- While Argon2 computation dominates timing, local attacker could exploit
- Violates NIST SP 800-57 key material protection requirements

**Affected Files:**
- `v3/steve/election.py` (lines 335-349, 375, 362-375, 264, 381)
- `v3/server/bin/tally.py` (line 155)

**ASVS:** 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.2.3, 11.2.4, 11.2.5, 11.3.3, 11.4.2, 11.6.1, 11.6.2, 11.7.1 (L2, L3)
**CWE:** CWE-208

### Remediation
Replace non-constant-time comparison with `hmac.compare_digest()`:

```python
import hmac

# In is_tampered() function:
return not hmac.compare_digest(opened_key, md.opened_key)
```

This prevents timing oracle attacks on cryptographic material comparison.

### Acceptance Criteria
- [ ] `hmac.compare_digest()` used for key comparison
- [ ] Import statement added
- [ ] All cryptographic comparisons use constant-time functions
- [ ] Test added for timing attack resistance
- [ ] Related: FINDING-180

### References
- ASVS 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.2.3, 11.2.4, 11.2.5, 11.3.3, 11.4.2, 11.6.1, 11.6.2, 11.7.1
- NIST SP 800-57
- CWE-208
- Source: 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 11.2.3.md, 11.2.4.md, 11.2.5.md, 11.3.3.md, 11.4.2.md, 11.6.1.md, 11.6.2.md, 11.7.1.md

### Priority
Medium

---

## Issue: FINDING-180 - Argon2d Variant Used Instead of Argon2id
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The production `_hash()` function uses Argon2d instead of the recommended Argon2id variant. Argon2d uses data-dependent memory access patterns vulnerable to side-channel attacks, while Argon2id provides side-channel resistance. This affects both election master keys and per-voter tokens.

### Details
- Production uses `argon2.low_level.Type.D` (Argon2d)
- Benchmark function correctly uses `argon2.low_level.Type.ID` (Argon2id)
- Argon2d vulnerable to cache-timing and memory bus snooping attacks
- RFC 9106 §4 explicitly recommends Argon2id for general-purpose use
- Affects election master key and per-voter tokens
- Compromises ballot encryption and vote anonymity
- In shared hosting/cloud, co-tenant could use cache timing attacks

**Affected Files:**
- `v3/steve/crypto.py` (lines 88, 31-38, 43-46, 130, 97, 48, 55, 82-92, 83, 76-84, 40-47, 50-54, 88-98, 79-89, 80)

**ASVS:** 11.2.3, 11.2.4, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1, 15.1.4, 15.1.5, 11.7.1, 11.7.2 (L2, L3)
**CWE:** CWE-208

### Remediation
1. **Fix Argon2 variant:** Change to `type=argon2.low_level.Type.ID` or use high-level API:
```python
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)
```

2. **Fix HKDF info parameter:** Use `b'fernet_vote_key_v1'` instead of `b'xchacha20_key'`

3. **Document migration plan:** Timeline and risk assessment in SECURITY.md

4. **Document XChaCha20 dependency:** Before adoption, add to component risk assessment

5. **Update info parameter:** When migrating encryption, use `b'xchacha20_key_v1'`

**CRITICAL NOTE:** Changing Argon2 type alters derived keys, making existing encrypted votes unrecoverable. Requires coordinated migration plan.

### Acceptance Criteria
- [ ] Argon2id variant used in production
- [ ] HKDF info parameter corrected
- [ ] Migration plan documented
- [ ] Existing elections migration strategy defined
- [ ] Test added for Argon2id usage
- [ ] Cryptographic inventory updated
- [ ] Related: FINDING-179

### References
- ASVS 11.2.3, 11.2.4, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.6.1, 11.6.2, etc.
- RFC 9106 §4
- CWE-208
- Source: Multiple ASVS sections

### Priority
Medium

---

## Issue: FINDING-181 - HKDF Domain Separation Label Mismatches Actual Encryption Algorithm
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The HKDF info parameter identifies the derived key as 'xchacha20_key' while actual encryption uses Fernet (AES-128-CBC + HMAC-SHA256). This violates accurate domain separation and creates latent key reuse vulnerability if XChaCha20-Poly1305 is later added.

### Details
- HKDF `info=b'xchacha20_key'` but actual cipher is Fernet
- Violates accurate domain separation per NIST SP 800-56C / RFC 5869
- If XChaCha20-Poly1305 added with same info value, creates key reuse
- Inventory falsification: automated inventory would incorrectly record algorithm
- Unsafe algorithm migration: identical keys for old and new algorithms
- Eliminates cryptographic domain separation between algorithms

**Affected Files:**
- `v3/steve/crypto.py` (lines 59-70, 73-78, 59-69, 73-76, 60-71, 74-79, 82-87, 52-57, 53, 53-62)

**ASVS:** 11.3.3, 11.3.4, 11.3.5, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1 (L2, L3)
**CWE:** CWE-327

### Remediation
Change HKDF info parameter from `b'xchacha20_key'` to `b'fernet_vote_key_v1'`:

```python
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=b'fernet_vote_key_v1',  # Changed from b'xchacha20_key'
)
```

Update comment from '32-byte key for XChaCha20-Poly1305' to '32 bytes: 16-byte signing key + 16-byte AES-128 key (Fernet spec)'.

When migrating to XChaCha20-Poly1305, use distinct info value `b'xchacha20_vote_key_v2'`.

**CRITICAL NOTE:** Changing info parameter changes all derived keys. Requires coordinated migration similar to Argon2 type change.

### Acceptance Criteria
- [ ] HKDF info parameter corrected to match actual algorithm
- [ ] Comment updated to reflect Fernet usage
- [ ] Migration plan documented for algorithm change
- [ ] Version suffix added to info parameter
- [ ] Future XChaCha20 migration uses distinct info value
- [ ] Cryptographic inventory updated
- [ ] Test added for correct domain separation

### References
- ASVS 11.3.3, 11.3.4, 11.3.5, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1
- NIST SP 800-56C
- RFC 5869
- CWE-327
- Source: Multiple ASVS sections

### Priority
Medium

---

## Issue: FINDING-182 - Cryptographic Decryption Errors Propagate Without Secure Handling
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Cryptographic operations in crypto.py lack exception handling, allowing raw exceptions to propagate through election.py to the transport layer. This can lead to information disclosure via stack traces and availability issues where a single corrupted ciphertext prevents tallying an entire election.

### Details
- No exception handling in crypto.py encryption/decryption operations
- Raw exceptions (`cryptography.fernet.InvalidToken`, `argon2.exceptions.*`, `ValueError`) propagate
- Stack traces reveal encryption library, algorithm choices (Fernet), internal architecture
- Single corrupted ciphertext prevents entire election tallying
- No graceful degradation for decryption failures
- Violates fail-secure principle

**Affected Files:**
- `v3/steve/crypto.py` (line 75)
- `v3/steve/election.py` (lines 290, 250)

**ASVS:** 11.2.5 (L3)

### Remediation
1. **Add dedicated crypto error class:**
```python
class CryptoError(Exception):
    """Wraps internal crypto exceptions to prevent implementation leakage"""
    pass
```

2. **Wrap decrypt_votestring():**
```python
try:
    # decryption logic
except (cryptography.fernet.InvalidToken, Exception) as e:
    _LOGGER.debug(f"Decryption failed: {type(e).__name__}")
    raise CryptoError("Decryption failed") from None
```

3. **Handle gracefully in tally_issue:**
```python
try:
    votestring = decrypt_votestring(...)
except CryptoError:
    _LOGGER.warning(f"Failed to decrypt vote {hash(vote_token)}")
    continue  # Tally other votes
```

### Acceptance Criteria
- [ ] `CryptoError` exception class created
- [ ] Exception handling added to crypto operations
- [ ] Sanitized error messages (no implementation details)
- [ ] Graceful degradation in tally operations
- [ ] Debug-level logging for crypto failures
- [ ] Test added for corrupted ciphertext handling
- [ ] Test added for continued tallying after single failure

### References
- ASVS 11.2.5
- Source: 11.2.5.md

### Priority
Medium

---

## Issue: FINDING-183 - Election and Issue IDs Generated with Insufficient Entropy
**Labels:** bug, security, priority:medium
**Description:**
### Summary
`create_id()` generates reference tokens (election IDs, issue IDs) with only 40 bits of entropy (5 bytes × 8 = 40 bits). ASVS 7.2.3 mandates minimum 128 bits for reference tokens. Combined with incomplete authorization checks, this creates brute-force enumeration vulnerability.

### Details
- Only 40 bits entropy (~1.1 trillion possible values)
- ASVS 7.2.3 requires minimum 128 bits
- IDs exposed in URLs: `/manage/<eid>`, `/do-vote/<eid>`, `/do-open/<eid>`
- Authorization systematically incomplete ('### check authz' comments)
- Authenticated attacker can enumerate valid election IDs
- Without authorization checks, valid eid grants full access

**Affected Files:**
- `v3/steve/crypto.py` (line 118)
- `v3/schema.sql` (lines 61, 104)
- `v3/steve/election.py` (lines 370, 195)

**ASVS:** 11.5.1, 7.2.3 (L2, L1)

### Remediation
Increase ID entropy to at least 128 bits:

1. **Update create_id():**
```python
def create_id() -> str:
    return secrets.token_hex(16)  # 16 bytes = 128 bits = 32 hex chars
```

2. **Update schema.sql CHECK constraints:**
```sql
CHECK(length(eid) = 32 AND eid GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f]...')
CHECK(length(iid) = 32 AND iid GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f]...')
```

3. **Create database migration script** for existing installations

4. **Add rate limiting** on election/issue lookup endpoints as defense-in-depth

### Acceptance Criteria
- [ ] ID generation uses 128 bits entropy (16 bytes)
- [ ] Schema constraints updated to enforce 32-character IDs
- [ ] Database migration script created
- [ ] Rate limiting added to lookup endpoints
- [ ] Test added for ID length and entropy
- [ ] Test added for ID uniqueness

### References
- ASVS 11.5.1, 7.2.3
- Source: 11.5.1.md, 7.2.3.md

### Priority
Medium

---

## Issue: FINDING-184 - Argon2 Parameters Adopted from Passlib Defaults Without Tuning
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Argon2 parameters are explicitly annotated as 'Passlib default' with no evidence of application-specific tuning. While a benchmark function exists, production parameters use untuned defaults. This represents a process gap in security parameter selection.

### Details
- Parameters explicitly marked as 'Passlib default'
- Parallelism of 4 higher than OWASP recommendations (p=1)
- No documented tuning rationale
- `benchmark_argon2()` function exists but not used for production parameters
- ASVS 11.4.4 requires deliberate parameter selection based on threat model
- Parameters not inherently weak but lack justification

**Affected Files:**
- `v3/steve/crypto.py` (line 78)

**ASVS:** 11.4.4 (L2)

### Remediation
1. **Run benchmark:** Execute existing `benchmark_argon2()` on production hardware
2. **Select parameters:** Target 100-500ms computation time per derivation
3. **Document rationale:**
```python
# Argon2id parameters tuned on [hardware description]
# Target: 250ms computation time
# Benchmark date: [date]
# References: OWASP Password Storage Cheat Sheet, RFC 9106 §4
time_cost=3,      # Increased from 2 after benchmarking
memory_cost=65536,  # 64 MiB
parallelism=1,    # Reduced from 4 per OWASP recommendation
```
4. **Consider reducing parallelism** from 4 to 1 and increasing time_cost

### Acceptance Criteria
- [ ] Benchmark run on production hardware
- [ ] Parameters selected based on benchmark results
- [ ] Tuning rationale documented in code
- [ ] Hardware description documented
- [ ] Target computation time documented
- [ ] References to OWASP and RFC 9106 added
- [ ] Test added verifying computation time within acceptable range

### References
- ASVS 11.4.4
- OWASP Password Storage Cheat Sheet
- RFC 9106 §4
- Source: 11.4.4.md

### Priority
Medium

---

## Issue: FINDING-185 - External OAuth Service Dependency Hardcoded and Undocumented
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application has hard runtime dependency on oauth.apache.org for authentication, but this external service is not documented in configuration. OAuth endpoints are hardcoded in source code rather than externalized as configuration parameters, preventing accurate network security planning.

### Details
- Hard dependency on oauth.apache.org not documented
- OAuth endpoints hardcoded in source code
- No configuration parameters for OAuth URLs
- Prevents operators from performing network security planning
- Violates ASVS 13.1.1 requirement to document external service dependencies

**Affected Files:**
- `v3/server/main.py` (lines 37-40)
- `v3/server/config.yaml.example` (entire file)

**ASVS:** 13.1.1 (L2)

### Remediation
Add OAuth configuration to config.yaml.example:

```yaml
oauth:
    auth_url: "https://oauth.apache.org/auth"
    token_url: "https://oauth.apache.org/token"
    # redirect_uri constructed as: {server.base_url}/oauth/callback
```

Update main.py to use configuration values:
```python
asfquart.generics.OAUTH_URL_INIT = f'{app.cfg.oauth.auth_url}?state=%s&redirect_uri=%s'
asfquart.generics.OAUTH_URL_CALLBACK = f'{app.cfg.oauth.token_url}?code=%s'
```

### Acceptance Criteria
- [ ] OAuth configuration section added to config.yaml.example
- [ ] Configuration includes auth_url and token_url
- [ ] main.py updated to read from configuration
- [ ] Hardcoded URLs removed from source code
- [ ] Documentation updated with OAuth dependency
- [ ] Test added for configuration loading

### References
- ASVS 13.1.1
- Source: 13.1.1.md

### Priority
Medium

---

## Issue: FINDING-186 - Absence of Comprehensive Communication Architecture Documentation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ASVS 13.1.1 L2 requires all communication needs to be documented. Current config.yaml.example provides incomplete coverage, documenting only 3 out of 8 communication channels (inbound HTTP/HTTPS, TLS, SQLite). Missing documentation for OAuth endpoints, LDAP backend, CLI tools IPC, and OAuth callbacks.

### Details
- Only 3 of 8 communication channels documented
- Missing: OAuth endpoints (outbound), LDAP backend, CLI tallying tools IPC, OAuth callbacks (inbound)
- No comprehensive communication architecture documentation
- Operators lack complete picture of network dependencies
- Cannot perform complete security planning

**Affected Files:**
- `v3/server/config.yaml.example` (entire file)
- `v3/server/main.py` (lines 38, 40)

**ASVS:** 13.1.1 (L2)

### Remediation
Add comprehensive communication architecture documentation to config.yaml.example:

```yaml
# COMMUNICATION ARCHITECTURE
# INBOUND:
#   - HTTPS on configured port (user requests)
#   - OAuth callback from oauth.apache.org
# OUTBOUND:
#   - HTTPS to oauth.apache.org (authentication)
#   - LDAPS to LDAP server (authorization)
# LOCAL:
#   - SQLite database file
#   - CLI tools database access
# USER-CONTROLLABLE DESTINATIONS:
#   - Application does not connect to user-specified URLs

server:
  port: 8000
  base_url: "https://localhost:8000"  # Used for OAuth redirect_uri construction
  certfile: localhost.apache.org+3.pem
  keyfile: localhost.apache.org+3-key.pem

oauth:
  auth_url: "https://oauth.apache.org/auth"
  token_url: "https://oauth.apache.org/token"

ldap:
  url: "ldaps://ldap.apache.org"
  base_dn: "dc=apache,dc=org"
```

### Acceptance Criteria
- [ ] Communication architecture section added to config
- [ ] All 8 communication channels documented
- [ ] Inbound channels listed with protocols
- [ ] Outbound channels listed with destinations
- [ ] Local communication documented
- [ ] User-controllable destinations addressed
- [ ] Complete configuration sections for oauth and ldap

### References
- ASVS 13.1.1
- Source: 13.1.1.md

### Priority
Medium

---

## Issue: FINDING-187 - Debug Logging Level Enabled by Default in Production
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `run_asgi()` production code path unconditionally sets logging.DEBUG level, causing all application-level debug messages to be written to production logs. This creates latent information disclosure risk and exposes extraneous development functionality in production.

### Details
- `run_asgi()` is production code path triggered by Hypercorn
- Unconditionally sets `logging.DEBUG` on basicConfig and _LOGGER
- All debug messages including crypto operations, DB queries, election state written to logs
- Future debug logging anywhere automatically exposed in production
- Violates ASVS 15.2.3 requirement against exposing development functionality

**Affected Files:**
- `v3/server/main.py` (lines 50, 91)
- `v3/server/config.yaml.example` (entire file)

**ASVS:** 13.1.1, 13.4.2, 15.2.3, 13.4.6 (L2, L3)

### Remediation
Set production logging to INFO level with environment variable override:

```python
def run_asgi():
    log_level = os.environ.get('STEVE_LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    _LOGGER.setLevel(getattr(logging, log_level, logging.INFO))
    
    # ... rest of function
```

Document in deployment guide that DEBUG should only be enabled temporarily for troubleshooting.

Consider separate log levels for different components (web, crypto, database).

### Acceptance Criteria
- [ ] Production logging set to INFO level
- [ ] Environment variable override implemented (STEVE_LOG_LEVEL)
- [ ] Default log level is INFO, not DEBUG
- [ ] Deployment documentation updated
- [ ] Warning added against leaving DEBUG enabled
- [ ] Test added for log level configuration
- [ ] Related: FINDING-187 (multiple sources)

### References
- ASVS 13.1.1, 13.4.2, 15.2.3, 13.4.6
- Source: 13.1.1.md, 13.4.2.md, 15.2.3.md, 13.4.6.md

### Priority
Medium

---

## Issue: FINDING-188 - No Web Server Concurrency Limits Configured or Documented
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The server configuration defines no maximum concurrent connections, worker limits, request queue sizes, or keepalive timeouts. Without documented and configured connection limits, the application may accept thousands of concurrent connections, creating resource exhaustion vulnerability.

### Details
- config.yaml.example only specifies port and TLS settings
- No concurrency boundaries configured
- Neither standalone nor ASGI mode documents limits
- Relies entirely on asfquart/Hypercorn defaults
- Combined with database and Argon2 resource issues creates multiplier effect
- No capacity planning guidance for operations teams

**Affected Files:**
- `v3/server/config.yaml.example` (no relevant content)
- `v3/server/main.py` (lines 50-88, 91-108)

**ASVS:** 13.1.2 (L3)

### Remediation
1. **Add server concurrency configuration to config.yaml.example:**
```yaml
server:
  max_connections: 100
  workers: 2
  keepalive_timeout: 30  # seconds
  request_timeout: 60    # seconds
  # Behavior when max_connections reached: new connections receive 503
```

2. **For Hypercorn ASGI deployment, provide hypercorn.toml:**
```toml
bind = ["0.0.0.0:8000"]
workers = 2
backlog = 100
graceful_timeout = 10
```

### Acceptance Criteria
- [ ] Concurrency configuration added to config.yaml.example
- [ ] max_connections configured (100)
- [ ] workers configured (2)
- [ ] Timeout values configured
- [ ] Behavior documented for max connections
- [ ] hypercorn.toml provided for ASGI deployment
- [ ] Test added for connection limit enforcement

### References
- ASVS 13.1.2
- Source: 13.1.2.md

### Priority
Medium

---

## Issue: FINDING-189 - No OAuth Service Connection Limits or Failure Handling
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application integrates with external OAuth service (oauth.apache.org) with no documented or configured connection limit, timeout, retry policy, or fallback behavior. OAuth service degradation could cause cascading failure in the voting application.

### Details
- No connection limit, timeout, or retry policy for OAuth service
- URLs hardcoded with no resilience configuration
- Slow/unresponsive oauth.apache.org causes indefinite hangs
- No timeout configured for authentication requests
- Slowloris-style attack or DNS manipulation could cause cascading failure
- No documentation for detecting/responding to OAuth service degradation

**Affected Files:**
- `v3/server/main.py` (lines 35-38, 32-37)
- `v3/server/config.yaml.example` (no relevant content)

**ASVS:** 13.1.2, 13.1.3, 13.2.6 (L3)

### Remediation
Document OAuth service dependencies and limits in configuration:

```yaml
oauth:
  base_url: "https://oauth.apache.org"
  connect_timeout: 5  # seconds
  read_timeout: 10    # seconds
  max_retries: 2
  circuit_breaker_threshold: 5  # failures before opening circuit
  fallback_behavior: "Display 'Authentication service unavailable' page"
  recovery_mechanism: "Auto-retry after 30 seconds"
```

Configure HTTP client used by asfquart.generics to apply these parameters.

### Acceptance Criteria
- [ ] OAuth connection limits configured
- [ ] Timeout values configured (connect: 5s, read: 10s)
- [ ] Retry policy configured (max 2 retries)
- [ ] Circuit breaker implemented
- [ ] Fallback behavior documented and implemented
- [ ] Recovery mechanism implemented
- [ ] HTTP client configured with parameters
- [ ] Test added for OAuth service timeout
- [ ] Test added for circuit breaker

### References
- ASVS 13.1.2, 13.1.3, 13.2.6
- Source: 13.1.2.md, 13.1.3.md, 13.2.6.md

### Priority
Medium

---

## Issue: FINDING-190 - Configuration Template Lacks Secret Management Guidance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The configuration template (config.yaml.example) contains no guidance about which values are security-sensitive, how secrets should be injected, or what file permissions should be applied. Environment variable integration via asfquart is completely undocumented.

### Details
- No indication which values are security-sensitive
- No secret injection guidance (environment variables)
- No file permissions guidance
- No warning that keyfile contains private key
- No mention of OAuth credentials outside this file
- No .gitignore reference to prevent committing secrets
- asfquart supports environment variables but completely undocumented

**Affected Files:**
- `v3/server/config.yaml.example` (lines 1-22)

**ASVS:** 13.1.4 (L3)
**CWE:** CWE-1059

### Remediation
Replace config.yaml.example with comprehensive security guidance:

```yaml
# SECURITY CHECKLIST - Review before deployment:
# [ ] All secrets injected via environment variables, not hardcoded
# [ ] File permissions: config.yaml (0644), keyfile (0600), database (0600)
# [ ] .gitignore includes config.yaml, *.db, certs/*.pem, .env
# [ ] Production deployment does not use example values

# SECRETS MANAGEMENT
# NEVER store secrets directly in this file in production.
# Use environment variables for all sensitive values:
#   STEVE_PORT, STEVE_CERTFILE, STEVE_KEYFILE, STEVE_DB, STEVE_OAUTH_SECRET

server:
  port: ${STEVE_PORT:-8000}
  certfile: ${STEVE_CERTFILE}  # SENSITIVE: Private key access
  keyfile: ${STEVE_KEYFILE}    # SENSITIVE: Requires 0600 permissions
  
database:
  path: ${STEVE_DB:-steve.db}  # SENSITIVE: Contains encryption keys

# FILE PERMISSIONS (Unix):
# chmod 0600 ${STEVE_KEYFILE}
# chmod 0600 ${STEVE_DB}
# chmod 0644 ${STEVE_CERTFILE}
# chmod 0644 config.yaml
```

Create/update .gitignore and provide validate_config.py script.

### Acceptance Criteria
- [ ] Security checklist added to config template
- [ ] Secrets management section added
- [ ] Environment variables documented
- [ ] Inline security comments for each sensitive value
- [ ] File permissions documented with commands
- [ ] .gitignore updated
- [ ] Configuration validation script created
- [ ] Test added for configuration security validation
- [ ] Related: FINDING-066, FINDING-151

### References
- ASVS 13.1.4
- CWE-1059
- Source: 13.1.4.md

### Priority
Medium

## Issue: FINDING-201 - Per-Voter Cryptographic Salts Never Expire or Rotate
**Labels:** security, priority:medium, crypto, key-management
**Description:**
### Summary
Per-voter cryptographic salts in the mayvote table are generated once when an election is opened and never expire or rotate. The complete key derivation chain (opened_key → vote_token → vote_key) remains reconstructable from database contents alone without any time-bound protection.

### Details
While per-voter salts are critical for vote anonymity (preventing cross-voter correlation), there is no mechanism for the salts to have a defined maximum lifetime or be securely zeroed after use. Combined with the indefinite persistence of the election master key, this creates a long-term cryptographic exposure.

**Affected Files:**
- `v3/steve/election.py` (lines 134-154)
- `v3/steve/crypto.py` (lines 35-37)

**ASVS References:** 13.3.4 (L3)

### Remediation
1. Integrate salt destruction into the purge_crypto() method from the secret destruction finding
2. Add a created_at timestamp to the mayvote salt records to enable age-based expiration policies
3. Track salt age and enforce maximum lifetime policies

### Acceptance Criteria
- [ ] Salt destruction integrated into purge_crypto()
- [ ] created_at timestamp added to mayvote table
- [ ] Age-based expiration policy implemented
- [ ] Test added for salt lifecycle management

### References
- Source: 13.3.4.md
- CWE: None specified
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-202 - No Explicit HTTP TRACE Method Blocking at Application or Server Level
**Labels:** security, priority:medium, http-security, defense-in-depth
**Description:**
### Summary
The application relies entirely on Quart's implicit behavior (returning 405 for unregistered methods) to prevent TRACE handling. There is no explicit, defense-in-depth control at application middleware, server configuration, or reverse proxy level.

### Details
Multiple gaps exist:
1. No application middleware to reject TRACE requests before route dispatch
2. No server configuration (config.yaml.example) includes HTTP method restrictions
3. No reverse proxy configuration provided despite deployment model expecting one
4. No ASGI middleware registered to block TRACE before routing logic

While Quart's default behavior provides implicit protection, this is fragile:
- A catch-all error handler could inadvertently respond to TRACE
- The pages and api modules could register routes accepting all methods
- Without reverse proxy config, there's no verifiable TRACE blocking at infrastructure tier

**Affected Files:**
- `v3/server/main.py` (lines 33-45)
- `v3/server/config.yaml.example`

**ASVS References:** 13.4.4 (L2)

### Remediation
1. Add explicit TRACE blocking middleware to main.py using before_request hook to abort with 405 if request.method == 'TRACE'
2. Provide production reverse proxy configuration template (nginx.conf.example or Apache config) with TRACE/TRACK blocking directives
3. Add integration tests to verify TRACE returns 405 across all endpoints
4. Document expected production deployment architecture in deployment guide

### Acceptance Criteria
- [ ] Application-level TRACE blocking middleware added
- [ ] Reverse proxy configuration template provided
- [ ] Integration tests verify TRACE blocking
- [ ] Deployment documentation updated

### References
- Source: 13.4.4.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-203 - Production ASGI Deployment Path Enables DEBUG-Level Logging
**Labels:** security, priority:medium, logging, information-disclosure
**Description:**
### Summary
The production deployment entry point `run_asgi()` configures the logging system with DEBUG-level verbosity, causing extensive operational details to be logged in production environments that may expose connection details, timing information, or internal state.

### Details
Production logs capture DEBUG-level output from all application and library modules, including:
- Internal operation details (election IDs, retry behavior, database interactions)
- Verbose library logging (asyncio, HTTP handling, TLS)
- Connection details and timing information

This violates ASVS principle that "Production configurations should be hardened to avoid disclosing unnecessary data."

**Affected Files:**
- `v3/server/main.py` (lines 95-99, 104)
- `v3/steve/election.py` (lines 46, 189, 403)

**ASVS References:** 13.4.5 (L2)

### Remediation
1. Change production log level to WARNING in `run_asgi()`
2. Set application logger to INFO
3. Make log level configurable through `config.yaml` with a `log_level` setting
4. Example: `logging.basicConfig(level=logging.WARNING, ...)` and `_LOGGER.setLevel(logging.INFO)`
5. Add configuration: `server: { log_level: WARNING }` in config.yaml template

### Acceptance Criteria
- [ ] Production log level changed to WARNING
- [ ] Application logger set to INFO
- [ ] Log level made configurable via config.yaml
- [ ] Configuration template updated

### References
- Source: 13.4.5.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-204 - No Production Configuration Controls for Endpoint Exposure and Debug Mode
**Labels:** security, priority:medium, configuration, hardening
**Description:**
### Summary
The production configuration template provides no mechanism to explicitly control debug mode, log levels, or endpoint exposure. This prevents operators from verifying production hardening through configuration review and provides no defense-in-depth mechanism to disable debug features.

### Details
The configuration file lacks settings to:
1. Explicitly disable debug mode
2. Control log verbosity
3. Disable framework-provided endpoints
4. Enable/disable monitoring endpoints

Production deployments cannot be audited for proper hardening through configuration review alone, and it is unclear which endpoints the `asfquart` framework registers by default.

**Affected Files:**
- `v3/server/config.yaml.example` (lines 1-12)
- `v3/server/main.py` (lines 33-43, 88-107)

**ASVS References:** 13.4.5 (L2)

### Remediation
1. Add production hardening settings to `config.yaml.example`: `debug: false`, `log_level: WARNING`, `enable_health_endpoint: false`
2. Enforce these settings in `create_app()` by checking `app.cfg.server.get('debug', False)`
3. Set `app.debug = False` and `app.config['TESTING'] = False` when debug is disabled
4. Provide documented endpoint inventory and exposure controls

### Acceptance Criteria
- [ ] Production hardening settings added to config template
- [ ] Settings enforced in create_app()
- [ ] Endpoint inventory documented
- [ ] Configuration validation added

### References
- Source: 13.4.5.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-205 - Hypercorn Server Header Exposes Backend Component Identity and Version
**Labels:** security, priority:medium, information-disclosure, fingerprinting
**Description:**
### Summary
The application uses Hypercorn as its production ASGI server, which by default sends a `Server` response header on every HTTP response (e.g., `server: hypercorn-h11`), directly disclosing the server software name and transport protocol version to any client.

### Details
Neither the application startup code nor the configuration template includes any mechanism to suppress or override this header. An attacker can fingerprint the backend technology stack without any application interaction, enabling:
- Targeted attacks against known Hypercorn vulnerabilities
- Reduced attacker reconnaissance effort

**Affected Files:**
- `v3/server/main.py` (lines 32-42, 82-103)
- `v3/server/config.yaml.example` (entire file)

**ASVS References:** 13.4.6 (L3)

### Remediation
**Option A (recommended):** Create a `hypercorn.toml` configuration with `include_server_header = false` and launch with `hypercorn --config hypercorn.toml main:steve_app`

**Option B:** Add after-request middleware in `create_app()` to strip Server and X-Powered-By headers using `@app.after_request` decorator

**Option C:** Add `suppress_server_header: true` to config.yaml and apply during app creation

### Acceptance Criteria
- [ ] Server header suppression implemented
- [ ] Configuration documented
- [ ] Test added to verify header removal

### References
- Source: 13.4.6.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-206 - Sensitive Data Files Co-Located in Application Directory Without File-Extension Serving Restrictions
**Labels:** security, priority:medium, file-access, path-traversal
**Description:**
### Summary
The SQLite database (steve.db), configuration file (config.yaml), query definitions (queries.yaml), TLS private key (*.pem), and Python source files (.py) all reside within or directly adjacent to the application directory tree. While static_folder=None prevents framework serving, the documented deployment model uses a reverse proxy with no provided configuration.

### Details
If the reverse proxy is misconfigured or a new route handler inadvertently serves file contents, an attacker could obtain:
- SQLite database containing all election data, encrypted votes, cryptographic salts, and opened_keys enabling offline decryption
- TLS private keys enabling man-in-the-middle attacks
- Application source code enabling targeted vulnerability discovery
- Git history potentially containing committed secrets

**Affected Files:**
- `v3/server/config.yaml.example` (line 34)
- `v3/server/main.py` (line 28)

**ASVS References:** 13.4.7 (L3)

### Remediation
1. Move sensitive data files outside the application directory tree:
   - Use absolute paths outside web root for database (e.g., /var/lib/steve/steve.db)
   - Store certificates in /etc/steve/certs
2. Add application-level middleware to restrict response content types to allowed types (text/html, application/json, text/css, application/javascript)
3. Provide and document required reverse proxy configuration with rules to block access to sensitive file extensions (.db, .sqlite, .yaml, .yml, .py, .pyc, .pem, .key, .git, .env, .cfg, .ini, .log)

### Acceptance Criteria
- [ ] Sensitive files moved outside web root
- [ ] Application-level content-type restrictions added
- [ ] Reverse proxy configuration template provided
- [ ] Deployment documentation updated

### References
- Source: 13.4.7.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-207 - No Documented or Enforced Production Web Tier Hardening for File-Type Restrictions
**Labels:** security, priority:medium, deployment, documentation
**Description:**
### Summary
The config.yaml.example references a reverse proxy deployment model ('a proxy sits in front of this server'), but the codebase contains no reverse proxy configuration templates, deployment hardening documentation, or automated configuration validation to ensure file extension restrictions are applied in production.

### Details
ASVS 13.4.7 Level 3 requires verification that the web tier (not just the application framework) restricts served file types. Without enforceable proxy configuration:
- Deployments may omit file-extension restrictions entirely
- New team members or automated deployments may expose the application directly without proper proxy configuration
- The ASVS requirement cannot be verified as consistently met across deployments

**Affected Files:**
- `v3/server/main.py`
- `v3/server/config.yaml.example`

**ASVS References:** 13.4.7 (L3)

### Remediation
1. Include production reverse proxy configuration template in repository (v3/deploy/ directory with nginx.conf.example, deployment-checklist.md, and hardening.md)
2. Add startup check that verifies application is not directly exposed by warning if running on ports 80/443
3. Add ASGI middleware to reject requests for common sensitive extensions (.db, .sqlite, .yaml, .yml, .py, .pyc, .pem, .key, .env, .cfg, .ini, .log, .git, .bak, .swp, .old) with logging and 404 responses

### Acceptance Criteria
- [ ] Reverse proxy configuration template added
- [ ] Startup exposure check implemented
- [ ] ASGI middleware for file extension blocking added
- [ ] Deployment documentation created

### References
- Source: 13.4.7.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-208 - Debug Logging of Unclassified Form Data to Standard Output
**Labels:** security, priority:medium, logging, data-classification
**Description:**
### Summary
Debug print() statements in do_add_issue_endpoint() and do_edit_issue_endpoint() dump all form fields (including issue titles, descriptions containing confidential candidate information) to stdout with uncontrolled retention.

### Details
This data flows to:
- Container logs
- Log aggregation systems (ELK, Splunk, CloudWatch) with extended retention
- Operations teams who should not see election content

The presence of print() statements demonstrates that form data has not been assigned a protection level with handling rules.

**Affected Files:**
- `v3/server/pages.py` (lines 487, 507, 509, 533)

**ASVS References:** 14.1.1, 14.1.2, 14.2.4 (L2)

### Remediation
1. **Immediate:** Remove all debug print() statements from do_add_issue_endpoint() and do_edit_issue_endpoint()
2. **Short-term:** Implement structured logging with SensitiveFieldFilter that removes sensitive fields from log records
3. **Long-term:** Add data classification to logging policy with is_loggable() method that determines if a field can be logged based on its classification (CRITICAL/SENSITIVE: never log, INTERNAL: log field name only, PUBLIC: log freely)

### Acceptance Criteria
- [ ] All debug print() statements removed
- [ ] Structured logging with field filtering implemented
- [ ] Data classification policy documented
- [ ] Test added to prevent print() in production code

### References
- Source: 14.1.1.md, 14.1.2.md, 14.2.4.md
- CWE: None specified
- Related: FINDING-227, FINDING-228

### Priority
Medium

---

## Issue: FINDING-209 - Voter-Issue Timing Correlation Recorded in Application Logs
**Labels:** security, priority:medium, ballot-secrecy, timing-attack
**Description:**
### Summary
Per-issue vote logging in `do_vote_endpoint` creates a timing side channel that enables voter-vote correlation. The code logs each individual vote submission inside the vote processing loop, combined with the `vote` table's auto-incrementing `vid` column.

### Details
An attacker with access to both application logs and the database can:
- Map log timestamps to `vid` ranges to narrow down which vote tokens belong to which voters
- Observe that a specific vote_token voted N times
- Correlate timing of row insertions (via vid ordering) with other events

This undermines the cryptographic separation designed to protect ballot secrecy.

**Affected Files:**
- `v3/server/pages.py` (lines 425-427)
- `v3/steve/election.py` (line ~207)
- `v3/schema.sql` (vote table definition)

**ASVS References:** 14.1.2, 14.2.4 (L2)
**CWE:** CWE-203 (Observable Discrepancy)

### Remediation
Replace per-issue vote logging with aggregated ballot submission logging:
1. Before the vote processing loop, count the number of votes: `vote_count = len(votes)`
2. Remove the logging statement from inside the loop
3. After the loop completes successfully, log a single aggregated entry: `_LOGGER.info(f'User[U:{result.uid}] submitted ballot for election[E:{election.eid}] ({vote_count} issue(s))')`

This maintains audit capability while preventing timing correlation attacks.

### Acceptance Criteria
- [ ] Per-issue logging removed from vote loop
- [ ] Aggregated ballot submission logging implemented
- [ ] Test verifies single log entry per ballot submission
- [ ] Timing correlation attack mitigated

### References
- Source: 14.1.2.md, 14.2.4.md
- CWE: CWE-203

### Priority
Medium

---

## Issue: FINDING-210 - Authorization-Protected Documents Served via send_from_directory Without Cache Prevention
**Labels:** security, priority:medium, caching, authorization
**Description:**
### Summary
The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serves election documents after verifying voter eligibility via the mayvote table. However, quart.send_from_directory() uses framework defaults which typically set Cache-Control: public or include max-age, actively encouraging intermediate caches to store authorization-protected documents.

### Details
Election documents containing ballot details, candidate information, or voting instructions could be:
- Served from cache to unauthorized users, bypassing the authorization check
- Stored in intermediate proxies or CDN caches
- Accessible after voter authorization expires

**Affected Files:**
- `v3/server/pages.py` (lines 555-565, 557)

**ASVS References:** 14.2.2, 14.2.5 (L2, L3)

### Remediation
Override cache headers on the response from send_from_directory() before returning:
1. After calling send_from_directory, set:
   - `response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'`
   - `response.headers['Pragma'] = 'no-cache'`
   - `response.headers['Expires'] = '0'`
2. Validate the docname parameter to prevent path traversal
3. Enforce allowed content types

### Acceptance Criteria
- [ ] Cache prevention headers added to document responses
- [ ] Path traversal validation implemented
- [ ] Content type enforcement added
- [ ] Test verifies cache headers present

### References
- Source: 14.2.2.md, 14.2.5.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-211 - External Image Loaded on All Pages Leaks Voter Activity Metadata to Third-Party Server
**Labels:** security, priority:medium, privacy, third-party-leak
**Description:**
### Summary
The application's navigation header includes an external image resource loaded from `https://www.apache.org/foundation/press/kit/feather.svg`. This image is automatically fetched by the browser on every page load, including sensitive voting pages, transmitting voter metadata outside the application's control.

### Details
The HTTP request to apache.org transmits:
- Voter IP address
- User-Agent header
- Referer header (potentially including election ID)
- Precise timestamp of page access

Apache.org's web server logs record correlations between voter network identity, voting system origin, specific election being accessed, and precise timing. This creates an external record of voting activity that violates ballot secrecy principles.

**Affected Files:**
- `v3/server/templates/header.ezt` (line 22)

**ASVS References:** 14.2.3 (L2)

### Remediation
**Immediate Fix (Priority 1):**
1. Download and host the Apache feather logo locally:
   ```bash
   curl -o v3/server/static/img/feather.svg https://www.apache.org/foundation/press/kit/feather.svg
   ```
2. Update `header.ezt` to use local path:
   ```html
   <img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top">
   ```

**Defense-in-Depth (Priority 2):**
1. Add `Referrer-Policy` header: `response.headers['Referrer-Policy'] = 'same-origin'`
2. Add CSP to prevent future external resource inclusion

### Acceptance Criteria
- [ ] Logo downloaded and hosted locally
- [ ] Template updated to use local path
- [ ] Referrer-Policy header added
- [ ] Test verifies no external requests on page load

### References
- Source: 14.2.3.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-212 - Missing Vote Content Validation Before Encryption
**Labels:** security, priority:medium, data-validation, election-integrity
**Description:**
### Summary
Arbitrary strings are accepted as vote content and encrypted without validation against the issue's vote type. Invalid votes cannot be detected until decryption during tallying, when correction is impossible.

### Details
The add_vote() function contains a comment '### validate VOTESTRING for ISSUE.TYPE voting' but no actual implementation. Invalid vote content (e.g., 'xyz' for a YNA vote, or 'a,a,a,b' with duplicates for STV) would either:
- Produce incorrect tallies
- Cause tally-time errors

Since votes are encrypted, invalid content cannot be detected until the offline tallying process when the election is closed.

**Affected Files:**
- `v3/steve/election.py` (line 221)

**ASVS References:** 14.2.4 (L2)

### Remediation
Implement vote validation in add_vote() before encryption:
```python
issue = self.q_get_issue.first_row(iid)
m = vtypes.vtype_module(issue.type)
if not m.validate(votestring, self.json2kv(issue.kv)):
    raise ValueError(f'Invalid vote format for {issue.type} issue')
```

This ensures data integrity verification at the point of collection.

### Acceptance Criteria
- [ ] Vote validation implemented before encryption
- [ ] Validation uses vote type module
- [ ] Invalid votes rejected with clear error message
- [ ] Tests added for each vote type validation

### References
- Source: 14.2.4.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-213 - Voting Page Returns All Issues Instead of Per-Issue Authorization
**Labels:** security, priority:medium, authorization, information-disclosure
**Description:**
### Summary
The voting page performs a coarse-grained eligibility check (does the voter have ANY mayvote entries for this election?) but then returns ALL issues for the election, including issues the voter is not authorized to vote on.

### Details
The mayvote table is designed for per-issue authorization, but the voting interface ignores this granularity. In elections where different voter groups are authorized for different issues:
- A voter authorized for even one issue sees all issues and their full descriptions
- This includes STV candidate lists for issues they cannot vote on
- Ballot secrecy and need-to-know principles are violated

**Affected Files:**
- `v3/server/pages.py` (lines 244-270)

**ASVS References:** 14.2.6 (L3)

### Remediation
Filter list_issues() results in vote_on_page() to return only issues the voter is authorized for:
1. Query q_find_issues to get authorized issue IDs (iids)
2. Filter all_issues to only include those matching the authorized set before rendering to the template

### Acceptance Criteria
- [ ] Issue list filtered by voter authorization
- [ ] Only authorized issues displayed
- [ ] Test verifies unauthorized issues not shown
- [ ] Authorization check per-issue not per-election

### References
- Source: 14.2.6.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-214 - List Query Methods Return Raw Database Rows Without Field Filtering
**Labels:** security, priority:medium, defense-in-depth, data-exposure
**Description:**
### Summary
The get_metadata() method implements explicit field filtering to exclude cryptographic material (salt, opened_key). However, the list-query methods (open_to_pid(), upcoming_to_pid()) return raw database rows without code-level field filtering.

### Details
While owned_elections() has a defensive comment noting this concern, the other methods lack equivalent protections. These raw results are passed through postprocess_election() and directly into template contexts without any sensitive field stripping. If queries return election salt or opened_key columns, this cryptographic material enters the template rendering context, creating a defense-in-depth gap.

**Affected Files:**
- `v3/steve/election.py` (lines 410, 432)
- `v3/server/pages.py` (lines 137, 275)

**ASVS References:** 14.2.6 (L3)

### Remediation
Add consistent field filtering to list query methods:
1. Implement a _safe_election_row() method that strips sensitive fields (salt, opened_key)
2. Apply it to open_to_pid(), upcoming_to_pid(), and owned_elections()
3. Ensure defense-in-depth consistency with get_metadata()

This ensures cryptographic material is explicitly excluded at the code level rather than relying on template rendering behavior.

### Acceptance Criteria
- [ ] _safe_election_row() method implemented
- [ ] Applied to all list query methods
- [ ] Test verifies sensitive fields excluded
- [ ] Consistent with get_metadata() filtering

### References
- Source: 14.2.6.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-215 - Superseded Votes Retained Indefinitely as Unnecessary Data
**Labels:** security, priority:medium, ballot-secrecy, data-minimization
**Description:**
### Summary
When a voter re-votes on an issue, the system creates a new vote row with the same vote_token but a new auto-incrementing vid. Only the most recent vote is used during tallying (q_recent_vote). The superseded votes serve no purpose but remain in the database indefinitely.

### Details
For a system whose core goal is ballot secrecy, retaining the history of vote changes for each vote_token provides an unnecessary information channel:
- Count of re-votes per token is observable
- Ordering via vid reveals timing
- A voter who changes their vote 5 times will have 5 encrypted vote rows in the database

An attacker with database access can observe voting patterns and potentially correlate timing of row insertions with other events.

**Affected Files:**
- `v3/schema.sql` (vote table definition)
- `v3/steve/election.py` (lines 204-215, 217-255)

**ASVS References:** 14.2.7 (L3)

### Remediation
Modify add_vote() to delete previous votes before inserting new one:
1. Add query to queries.yaml: `c_delete_prior_votes: DELETE FROM vote WHERE vote_token = ?`
2. Execute within transaction: `self.c_delete_prior_votes.perform(vote_token)` before `self.c_add_vote.perform(vote_token, ciphertext)`

### Acceptance Criteria
- [ ] Delete query added to queries.yaml
- [ ] add_vote() modified to delete prior votes
- [ ] Transaction ensures atomicity
- [ ] Test verifies only one vote per token stored

### References
- Source: 14.2.7.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-216 - Person PII (Name, Email) Has No Practical Deletion Path
**Labels:** security, priority:medium, privacy, data-retention, gdpr
**Description:**
### Summary
The person table stores PII (name, email) for all voters ever registered. While a delete_person() method exists, referential integrity constraints from the mayvote table prevent deletion of any person who has been associated with any election.

### Details
The code comment explicitly acknowledges this limitation with no resolution. Voter PII accumulates without any lifecycle management. For a voting system that may serve many elections over years, this creates:
- Ever-growing store of personal data
- No ability to honor data subject deletion requests
- Non-compliance with data minimization principles

**Affected Files:**
- `v3/steve/persondb.py` (lines 51-64, 30-40)
- `v3/schema.sql` (mayvote foreign key constraints)

**ASVS References:** 14.2.7 (L3)

### Remediation
Implement anonymization as an alternative to blocked deletion:
1. Add anonymize_person() method that replaces name and email with anonymized values while keeping the PID reference intact for mayvote/vote integrity
2. Add query: `c_anonymize_person: UPDATE person SET name = ?, email = ? WHERE pid = ?`
3. Use format like 'ANONYMIZED_&lt;timestamp&gt;' for name and 'anonymized_&lt;pid&gt;@deleted.local' for email

### Acceptance Criteria
- [ ] anonymize_person() method implemented
- [ ] Query added to queries.yaml
- [ ] PID reference preserved for integrity
- [ ] Test verifies anonymization works
- [ ] Documentation updated with data retention policy

### References
- Source: 14.2.7.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-217 - Documents Served Without Metadata Stripping or User Consent
**Labels:** security, priority:medium, metadata, privacy
**Description:**
### Summary
The application serves documents to authorized voters through the serve_doc() endpoint without removing embedded metadata. Election administrators place supporting documents in DOCSDIR/&lt;iid&gt;/ which are then served via /docs/&lt;iid&gt;/&lt;docname&gt; using quart.send_from_directory() with all embedded metadata intact.

### Details
No metadata stripping occurs at any stage (neither at ingestion nor at serving time), and no user consent mechanism exists for metadata retention. Raw files are returned with potentially sensitive information such as:
- Author names
- Organization details
- Creation/modification timestamps
- Revision history
- Software version information
- GPS coordinates
- Embedded comments
- Tracked changes

**Affected Files:**
- `v3/server/pages.py` (lines 582-597, 60-68)

**ASVS References:** 14.2.8 (L3)

### Remediation
Implement metadata stripping for all documents:

**Option A:** Strip metadata at serving time using tools like exiftool, python-pdfkit, or Pillow before returning files

**Option B (preferred):** Strip metadata at upload/ingestion time in the CLI tool or upload handler that places documents, processing files once during ingestion

**Additionally:**
1. Add Content-Disposition: attachment headers to serve_doc() responses to force download rather than inline rendering
2. Validate the docname parameter to prevent path traversal (address the TODO comment '### verify the propriety of DOCNAME')
3. Document metadata policy - if some metadata is intentionally retained for transparency, document this decision and add user consent mechanisms where appropriate

### Acceptance Criteria
- [ ] Metadata stripping implemented (ingestion or serving)
- [ ] Content-Disposition headers added
- [ ] Path traversal validation implemented
- [ ] Metadata policy documented
- [ ] Test verifies metadata removal

### References
- Source: 14.2.8.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-218 - Sensitive Voter Identity Data Stored in Session (Likely Cookie-Backed)
**Labels:** security, priority:medium, session-management, pii-exposure
**Description:**
### Summary
The application stores sensitive voter identity data (PII) directly in the session object, which in Quart's default configuration is implemented as a client-side signed cookie. The session contains uid (voter identifier), fullname (voter full name), and email (voter email address).

### Details
The session cookie is base64-encoded and signed but not encrypted, making it readable by anyone with access to:
- Browser DevTools
- File system
- XSS if HttpOnly flag is not set

Additionally, flash messages stored in the session may contain election-specific data such as issue IDs and election titles, potentially revealing voter-to-issue mappings.

ASVS 14.3.3 allows session tokens in cookies but not sensitive data - a session token should be an opaque identifier, not a container for user PII.

**Affected Files:**
- `v3/server/pages.py` (lines 62-80, 107-113)

**ASVS References:** 14.3.3 (L2)

### Remediation
**Option 1 (Recommended):** Configure a server-side session backend (Redis, filesystem, sqlalchemy, or memcached) so only an opaque session ID is stored in the browser cookie. Set:
- SESSION_TYPE='redis'
- SESSION_COOKIE_HTTPONLY=True
- SESSION_COOKIE_SECURE=True
- SESSION_COOKIE_SAMESITE='Lax'

**Option 2:** Store only the session identifier (UID) in the cookie and look up user details server-side on each request from the PersonDB

**Option 3:** If cookie-based sessions must be used with full data, encrypt the cookie contents using an encrypted serializer

All options should include security flags: HttpOnly=True, Secure=True, SameSite=Lax

### Acceptance Criteria
- [ ] Server-side session storage configured OR cookie encryption implemented
- [ ] Security flags set on session cookie
- [ ] PII removed from client-side storage
- [ ] Test verifies session data not readable in cookie

### References
- Source: 14.3.3.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-219 - Dependency Confusion Risk for ASF-Namespaced Internal Package asfquart
**Labels:** security, priority:medium, supply-chain, dependencies
**Description:**
### Summary
The asfquart package is an ASF-internal web framework wrapper that provides critical security infrastructure including OAuth integration, authentication, and application construction. This package presents an elevated dependency confusion risk if not properly restricted to internal repositories.

### Details
If asfquart is distributed via an internal ASF package repository and the name is not defensively registered on PyPI, an attacker could register asfquart on PyPI with a higher version number. If pip or uv is configured with --extra-index-url (adding internal repo alongside PyPI), the public malicious package could be preferred due to version precedence.

A malicious asfquart package could:
- Intercept OAuth tokens
- Modify authentication flows
- Exfiltrate voter data
- Manipulate election results

This is the foundational framework of the application, making it the highest-value target for a supply chain attack.

**Affected Files:**
- `v3/server/main.py` (lines 32-38)

**ASVS References:** 15.2.4 (L3)

### Remediation
1. Configure uv workspace sources to restrict asfquart to internal repository using explicit index mapping in pyproject.toml:
   ```toml
   [[tool.uv.index]]
   name = "asf-internal"
   url = "https://internal.apache.org/pypi/simple"
   explicit = true
   
   [tool.uv.sources]
   asfquart = { index = "asf-internal" }
   ```
2. Defensively register the asfquart package name on PyPI (even as an empty placeholder with a README explaining it's internal-only) to prevent name squatting
3. Configure uv or pip to use --index-url exclusively for ASF packages, preventing fallback to public PyPI
4. Document the expected repository source for all internal packages in DEPENDENCIES.md
5. Implement hash pinning for asfquart in lock file to detect tampering

### Acceptance Criteria
- [ ] Package source restrictions configured
- [ ] Defensive registration completed or documented
- [ ] Repository source documented
- [ ] Hash pinning implemented

### References
- Source: 15.2.4.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-220 - No SBOM Documenting Transitive Dependency Tree
**Labels:** security, priority:medium, supply-chain, sbom, compliance
**Description:**
### Summary
The application's direct dependencies pull in significant transitive dependency chains. None of these transitive dependencies are documented in the provided audit materials. Without an SBOM, vulnerabilities in transitive dependencies cannot be tracked and the full attack surface is unknown.

### Details
Direct dependencies like cryptography, argon2-cffi, asfquart, asfpy, and easydict have extensive transitive dependencies including cffi, pycparser, quart, hypercorn, h11, h2, wsproto, priority, hpack, PyYAML, requests, ldap3, and others.

Without an SBOM:
1. Vulnerabilities in transitive dependencies cannot be tracked
2. The full attack surface of the application is unknown
3. Compliance with ASVS 15.2.4's requirement to verify 'all of their transitive dependencies' cannot be satisfied
4. A compromised or vulnerable transitive dependency would go undetected

**Affected Files:**
- Project root (N/A)

**ASVS References:** 15.2.4 (L3)

### Remediation
1. Generate and maintain an SBOM using CycloneDX format:
   ```bash
   cyclonedx-py environment -o sbom.json --format json
   # OR
   syft dir:./v3 -o cyclonedx-json > sbom.json
   ```
2. Integrate SBOM generation into CI/CD pipeline to automatically regenerate on dependency changes
3. Store SBOM artifacts with each release for audit trail
4. Implement automated vulnerability scanning against the SBOM using tools like grype:
   ```bash
   grype sbom:sbom.json
   ```
5. Review transitive dependency changes during dependency updates to identify new attack surface
6. Document process for evaluating transitive dependency security in DEPENDENCY-POLICY.md

### Acceptance Criteria
- [ ] SBOM generation implemented
- [ ] CI/CD integration completed
- [ ] Vulnerability scanning automated
- [ ] Dependency policy documented

### References
- Source: 15.2.4.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-221 - Development Benchmark Function Present in Production Crypto Module
**Labels:** security, priority:medium, code-hygiene, dos-risk
**Description:**
### Summary
The crypto.py module contains a benchmark_argon2() function (lines 129-158) that is development/test code exposed in the production module. This function executes 8 CPU/memory-intensive Argon2 operations with up to 128MB memory each, creating a denial-of-service vector if reachable through any server-side codepath.

### Details
The function:
- Uses hardcoded test salts
- Contains print() statements that write to stdout/logs, potentially exposing Argon2 tuning parameters and timing information
- Uses argon2.Type.ID while production uses argon2.Type.D, indicating it is purely development tooling that doesn't represent production behavior

ASVS 15.2.3 requires that production environments only include functionality required for the application to function and do not expose extraneous functionality such as test code.

**Affected Files:**
- `v3/steve/crypto.py` (lines 26, 129-158, 160-162)

**ASVS References:** 15.2.3 (L2)

### Remediation
Move the benchmark to a separate development-only script excluded from production deployment:
1. Create tools/benchmark_argon2.py with appropriate header indicating it is NOT for production deployment
2. Remove benchmark_argon2() function (lines 129-158) from crypto.py
3. Remove the if __name__ == '__main__' block (lines 160-162) from crypto.py
4. Remove `import time` (line 26) from crypto.py if unused elsewhere
5. Update deployment documentation to exclude tools/ directory from production packages
6. Add comment in crypto.py indicating benchmark was moved to tools/ for development use only

### Acceptance Criteria
- [ ] Benchmark function moved to tools/ directory
- [ ] Production module cleaned of test code
- [ ] Deployment documentation updated
- [ ] Comment added explaining relocation

### References
- Source: 15.2.3.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-222 - Web Server Log Timestamps Use Local Time Without Timezone, Year, or Seconds
**Labels:** security, priority:medium, logging, audit-trail
**Description:**
### Summary
The web server logging configuration uses DATE_FORMAT = '%m/%d %H:%M' which lacks timezone offset, UTC enforcement, year, and seconds. During DST transitions, timestamps become ambiguous, making it impossible to distinguish legitimate operations from unauthorized actions occurring in the duplicate time window.

### Details
The format lacks:
1. Timezone offset (%z or %Z) required by ASVS 16.2.2
2. UTC enforcement (defaults to time.localtime())
3. Year (%Y) needed for cross-year correlation
4. Seconds (%S) for proper event ordering

This prevents:
- Reliable log correlation across time periods
- Proper ordering of rapid event sequences
- Correlation with distributed systems
- Forensic analysis during DST transitions

All security events in pages.py (election creation, opening, closing, vote submission, issue management) are affected.

**Affected Files:**
- `v3/server/main.py` (lines 23, 55-59, 85-91, 20, 51-56)
- `v3/server/pages.py` (lines 101, 371, 374, 394-395, 415, 428, 451, 472-473, 489-490)

**ASVS References:** 16.2.2, 16.2.4 (L2)

### Remediation
Change DATE_FORMAT to '%Y-%m-%dT%H:%M:%SZ' for ISO 8601 UTC format. Create a custom formatter with formatter.converter = time.gmtime to enforce UTC timestamps. Configure the root logger with this formatter instead of using basicConfig with datefmt only.

Example:
```python
formatter = logging.Formatter(
    fmt='[{asctime}|{levelname}|{name}] {message}',
    datefmt='%Y-%m-%dT%H:%M:%SZ',
    style='{'
)
formatter.converter = time.gmtime
```

Apply to both run_standalone() and run_asgi() configurations.

### Acceptance Criteria
- [ ] Log format changed to ISO 8601 UTC
- [ ] Custom formatter with UTC converter implemented
- [ ] Applied to all logging configurations
- [ ] Test verifies UTC timestamps

### References
- Source: 16.2.2.md, 16.2.4.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-223 - Unsynchronized Logging Configuration Between Web Server and Tally CLI Components
**Labels:** security, priority:medium, logging, audit-trail
**Description:**
### Summary
The web server (main.py) and tally CLI (tally.py) use completely different logging configurations with incompatible formats. The same election.py module produces different log formats depending on which entry point calls it, making SIEM correlation impossible.

### Details
Format divergence:
- Web server: '[{asctime}|{levelname}|{name}] {message}' with '%m/%d %H:%M' timestamps in local time
- Tally CLI: Python's default format '%(levelname)s:%(name)s:%(message)s' with no timestamps at all

This violates ASVS 16.2.2 requirement that 'time sources for all logging components are synchronized'. This format divergence creates a correlation gap at the most critical phase of the election lifecycle.

**Affected Files:**
- `v3/server/main.py` (lines 23, 55-59, 85-91, 51-56)
- `v3/server/bin/tally.py` (lines 145, 148)
- `v3/steve/election.py` (lines 186, 197, 381)

**ASVS References:** 16.2.2, 16.2.4 (L2)

### Remediation
Create a shared logging configuration module (e.g., v3/steve/log_config.py) with a configure_logging() function that sets consistent format, date format, style, and UTC converter. Import and call this function from both main.py and tally.py entry points.

Example shared config:
```python
LOG_FORMAT = '[{asctime}|{levelname}|{name}] {message}'
LOG_DATEFMT = '%Y-%m-%dT%H:%M:%SZ'
formatter.converter = time.gmtime
```

This ensures unified log processing across all components.

### Acceptance Criteria
- [ ] Shared logging configuration module created
- [ ] Both entry points use shared config
- [ ] Log formats consistent across components
- [ ] Test verifies format consistency

### References
- Source: 16.2.2.md, 16.2.4.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-224 - Source IP Address Missing From All Web Security Log Entries
**Labels:** security, priority:medium, logging, audit-trail, incident-response
**Description:**
### Summary
ASVS 16.2.1 requires 'where' metadata for detailed investigation. For web applications, the source IP address is essential context that is completely absent from all security log entries. Every state-changing operation logs user identity and action details, but never records the IP address from which the request originated.

### Details
Without source IP addresses, security teams cannot:
- Detect compromised accounts (votes/actions from unexpected geolocations)
- Correlate multi-account attacks (single attacker using multiple compromised accounts)
- Investigate incidents (determine which requests were malicious)
- Enforce rate limiting (IP-based abuse prevention)
- Meet compliance requirements (election security standards often require IP address logging)

**Affected Files:**
- `v3/server/pages.py` (lines 116, 438, 468, 490, 505, 529, 547, 565, 410-443, 455-473, 476-493, 495-509, 511-532, 534-555, 557-575, 475, 498, 513)

**ASVS References:** 16.2.1, 16.3.1 (L2)

### Remediation
Create a centralized security logging helper function that captures source IP address from quart.request.remote_addr, request ID from X-Request-ID header, and User-Agent for device fingerprinting.

Example:
```python
async def log_security_event(action: str, details: str, level: int = logging.INFO) -> None:
    source_ip = quart.request.remote_addr or 'unknown'
    request_id = quart.request.headers.get('X-Request-ID', 'none')
    user_agent = quart.request.headers.get('User-Agent', 'unknown')[:100]
    _LOGGER.log(
        level,
        f'[ip:{source_ip}] [req:{request_id}] User[U:{result.uid}] '
        f'action={action} {details} user_agent="{user_agent}"'
    )
```

Refactor all endpoint logging to use this helper. For enhanced security, consider migrating to structured JSON logging using structlog.

### Acceptance Criteria
- [ ] Centralized logging helper function created
- [ ] All security events log source IP
- [ ] Request ID and User-Agent captured
- [ ] Test verifies IP logging

### References
- Source: 16.2.1.md, 16.3.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-225 - Log Injection via Unsanitized User-Controlled Input in Election Title and Form Fields
**Labels:** security, priority:medium, log-injection, input-validation
**Description:**
### Summary
User-controlled input from form submissions (election titles, issue titles, descriptions, date strings) is directly interpolated into log messages using f-strings without encoding newlines or other log control characters. An attacker can inject fake log entries by including newline characters in form fields, undermining log integrity for forensic analysis.

### Details
This allows attackers to:
- Forge log entries to cover tracks or frame other users
- Cause log analysis tools to misparse injected entries
- Undermine trust in the entire logging infrastructure

The vulnerability affects election creation, issue management, and date configuration endpoints.

**Affected Files:**
- `v3/server/pages.py` (lines 455, 101, 517, 542, 459, 429-431)

**ASVS References:** 16.1.1, 16.3.3, 16.4.1 (L2)
**CWE:** CWE-117 (Improper Output Neutralization for Logs)

### Remediation
Implement a sanitize_for_log() utility function that removes or replaces control characters (newlines, tabs, carriage returns, and other characters in the range \x00-\x1f) with spaces or escaped representations, and truncates excessively long values to prevent log flooding.

Example:
```python
def sanitize_for_log(value: str) -> str:
    if value is None:
        return 'None'
    return re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', ' ', str(value))[:256]
```

Then use:
```python
_LOGGER.info(
    f'User[U:{result.uid}] created election[E:{election.eid}]; '
    f'title: "{sanitize_for_log(form.title)}"'
)
```

Apply to all log statements with user input.

### Acceptance Criteria
- [ ] sanitize_for_log() function implemented
- [ ] Applied to all user input in logs
- [ ] Test verifies newline injection prevented
- [ ] Max length enforcement added

### References
- Source: 16.1.1.md, 16.3.3.md, 16.4.1.md
- CWE: CWE-117
- Related: FINDING-227, FINDING-228

### Priority
Medium

---

## Issue: FINDING-226 - Exception Details in Error Logs May Expose Sensitive Data
**Labels:** security, priority:medium, logging, information-disclosure
**Description:**
### Summary
Exception objects are directly interpolated into log messages using {e}. During vote processing, exceptions from cryptographic operations or database layer could expose sensitive internal state including cryptographic parameters, SQL queries with parameter values, or partial vote data (violating ballot secrecy).

### Details
Logs containing sensitive data become a high-value target for attackers. This affects:
- Vote submission error handling in pages.py
- Tally error handling in tally.py

Exceptions may expose:
- Cryptographic parameters (key material, salts, vote tokens)
- SQL queries with parameter values
- Partial vote data

**Affected Files:**
- `v3/server/pages.py` (lines 419, 399-403)
- `v3/server/bin/tally.py` (lines 124, 115-118)

**ASVS References:** 16.1.1, 16.2.5 (L2)
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

### Remediation
Log only the exception type name (type(e).__name__) at ERROR level for production logs, and use a separate DEBUG-level log entry with exc_info=True for detailed exception information that should only be enabled in development environments.

Example:
```python
_LOGGER.error(
    f'Vote processing failed for user[U:{result.uid}] on issue[I:{iid}]: '
    f'{type(e).__name__}'
)
_LOGGER.debug(f'Vote error details (issue[I:{iid}]): {e}', exc_info=True)
```

For tally errors:
```python
_LOGGER.error(
    f'Tally failed for issue[I:{issue.iid}]: {type(e).__name__} '
    f'(details suppressed to protect vote data)'
)
```

### Acceptance Criteria
- [ ] Exception type-only logging at ERROR level
- [ ] Detailed exceptions at DEBUG level only
- [ ] Applied to vote and tally error handling
- [ ] Test verifies sensitive data not logged

### References
- Source: 16.1.1.md, 16.2.5.md
- CWE: CWE-209
- Related: FINDING-020, FINDING-021

### Priority
Medium

---

## Issue: FINDING-227 - Debug print() Statements Output Raw Form Data to Unprotected stdout
**Labels:** security, priority:medium, logging, code-hygiene
**Description:**
### Summary
Production code contains print('FORM:', form) statements in issue management endpoints (do_add_issue_endpoint and do_edit_issue_endpoint) that dump raw request form data to stdout. This bypasses the logging framework entirely, has no log level classification, no timestamp, and intermingles with structured logs in ASGI deployments.

### Details
Form data (issue titles, descriptions, potentially election configuration) is written to an unstructured, unprotected output stream accessible to anyone who can read captured logs. These print() statements:
- Cannot be suppressed by adjusting log levels—they always execute
- Have no timestamp or context
- In ASGI deployments (Hypercorn), stdout is captured alongside structured log output

**Affected Files:**
- `v3/server/pages.py` (lines 508, 537, 493, 516, 489, 513, 510, 531, 482, 499, 447, 467)

**ASVS References:** 16.1.1, 16.2.3, 16.2.4, 16.2.5, 16.4.1, 16.4.2 (L2)
**CWE:** CWE-117 (Improper Output Neutralization for Logs)

### Remediation
Remove all print('FORM:', form) statements entirely from production code. If debugging is needed, replace with appropriate structured logging that logs only metadata about the action, not form contents:

```python
_LOGGER.debug(f'Issue form submitted for election[E:{election.eid}]')
```

Establish a policy to replace all print() calls with _LOGGER calls at appropriate levels. This ensures form data is only logged when DEBUG level is explicitly enabled and flows through the protected logging framework.

### Acceptance Criteria
- [ ] All debug print() statements removed
- [ ] Policy established against print() in production
- [ ] Code review checklist updated
- [ ] Linting rule added to detect print()

### References
- Source: 16.1.1.md, 16.2.3.md, 16.2.4.md, 16.2.5.md, 16.4.1.md, 16.4.2.md
- CWE: CWE-117
- Related: FINDING-225, FINDING-228

### Priority
Medium

---

## Issue: FINDING-228 - Log Injection via URL Path Parameters in Election Constructor
**Labels:** security, priority:medium, log-injection, input-validation
**Description:**
### Summary
The Election constructor logs the eid parameter before validating it against the database, allowing log injection through 11 different endpoints that use the @load_election decorator. The injection occurs at DEBUG level which is enabled in production configurations.

### Details
Any authenticated committer can inject arbitrary log entries across multiple endpoints before the election ID is validated. The eid parameter is user-controlled from URL paths and is logged with f-string interpolation without sanitization.

Affected endpoints include:
- /manage/&lt;eid&gt;
- /vote-on/&lt;eid&gt;
- /do-open/&lt;eid&gt;
- /do-close/&lt;eid&gt;
- All issue management endpoints

**Affected Files:**
- `v3/steve/election.py` (line 40)
- `v3/server/main.py` (line 57)

**ASVS References:** 16.4.1 (L2)
**CWE:** CWE-117 (Improper Output Neutralization for Logs)

### Remediation
**Option 1 (Preferred):** Move log statement after validation. Only log after self.q_check_election confirms the eid exists in the database.

**Option 2:** Sanitize before logging using:
```python
re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', str(eid))[:64]
```

Additionally, reduce production log level from DEBUG to INFO in main.py to reduce attack surface.

### Acceptance Criteria
- [ ] Log statement moved after validation OR sanitization added
- [ ] Production log level reduced to INFO
- [ ] Test verifies injection prevented
- [ ] Applied to all URL parameter logging

### References
- Source: 16.4.1.md
- CWE: CWE-117
- Related: FINDING-225, FINDING-227

### Priority
Medium

---

## Issue: FINDING-229 - No Documented Log Inventory or Centralized Log Destination Configuration
**Labels:** security, priority:medium, logging, audit-trail, compliance
**Description:**
### Summary
The application lacks a documented log inventory and uses only default logging destinations across all execution modes. No persistent log storage or centralized log destination is configured. All three execution contexts (standalone, ASGI, CLI) configure logging.basicConfig() without persistent handlers.

### Details
Without a log inventory:
- It is impossible to verify that logs are only going to approved destinations per ASVS 16.2.3
- The three different logging configurations across execution modes mean logs may end up in different places depending on how the application is run
- No documentation of which destinations are approved

**Affected Files:**
- `v3/server/main.py` (lines 58-63, 92-97)
- `v3/server/bin/tally.py` (line 157)

**ASVS References:** 16.2.3 (L2)

### Remediation
1. Create a formal log inventory document specifying approved log destinations
2. Centralize logging configuration using logging.config.dictConfig() with explicit handlers (console, audit_file, remote_syslog)
3. Configure at minimum a RotatingFileHandler for persistent audit logs with restricted permissions (0o640)
4. Use same configuration across standalone, ASGI, and CLI modes
5. Add linting rules or code review checks to prevent print() in production modules

### Acceptance Criteria
- [ ] Log inventory document created
- [ ] Centralized logging configuration implemented
- [ ] Persistent audit log handler added
- [ ] Same config used across all modes
- [ ] Log destinations documented

### References
- Source: 16.2.3.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-230 - Multi-Issue Vote Submission Lacks Atomicity; Partial Failure Creates Inconsistent State
**Labels:** security, priority:medium, data-integrity, transaction-management
**Description:**
### Summary
The vote submission endpoint processes multiple issue votes in a loop, with each vote committed individually. If a failure occurs mid-loop (database lock, crypto failure, disk full), votes processed before the failure are permanently recorded while subsequent votes are lost.

### Details
The voter receives only a generic error message and cannot determine which votes were successfully recorded. This creates an election integrity violation where partial vote recording without voter awareness could alter election outcomes.

This violates:
- ASVS 16.5.2 (graceful degradation)
- ASVS 16.5.3 (secure failure)

**Affected Files:**
- `v3/server/pages.py` (lines 349-378, 425-444)

**ASVS References:** 16.5.2, 16.5.3 (L2, L3)

### Remediation
Implement atomic batch vote submission by wrapping all vote operations in a single database transaction:
1. Add a new add_votes_batch() method in election.py that uses BEGIN TRANSACTION/COMMIT/ROLLBACK
2. Ensure all votes succeed or none are committed
3. Validate all votes before committing any
4. Provide clear feedback to users about whether the entire batch succeeded or failed
5. Log transaction start, commit, and rollback events with user context

### Acceptance Criteria
- [ ] add_votes_batch() method implemented
- [ ] All votes wrapped in single transaction
- [ ] Pre-commit validation added
- [ ] Clear user feedback on success/failure
- [ ] Transaction events logged

### References
- Source: 16.5.2.md, 16.5.3.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-231 - Election State-Change Operations Lack Error Handling and Recovery
**Labels:** security, priority:medium, error-handling, audit-trail
**Description:**
### Summary
The election opening and closing endpoints lack error handling for external resource access failures. The multi-step election.open() operation can fail partway through, leaving the election in an inconsistent state with no rollback mechanism.

### Details
Database and cryptographic operation failures are not caught, and no audit trail is created for failures:
- If PersonDB.open() fails, unhandled exceptions occur with no audit trail
- If failure occurs after add_salts() but before c_open.perform(), the election has salts applied but remains 'editable', creating an inconsistent state

**Affected Files:**
- `v3/server/pages.py` (lines 399, 419)
- `v3/steve/election.py` (line 70)

**ASVS References:** 16.5.2 (L2)

### Remediation
1. Wrap PersonDB.open() and election.open() calls in try/except blocks with proper error logging and user-friendly error messages
2. Make election.open() atomic by wrapping the entire multi-step process (salts + state change) in a single database transaction with rollback on failure
3. Add audit logging for all failure scenarios with _LOGGER.error() including user context, election ID, and operation that failed

### Acceptance Criteria
- [ ] Error handling added to state-change operations
- [ ] election.open() made atomic with transaction
- [ ] Audit logging added for all failures
- [ ] User-friendly error messages provided
- [ ] Test verifies rollback on failure

### References
- Source: 16.5.2.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-232 - No X-Frame-Options or frame-ancestors CSP Directive — Clickjacking Unmitigated
**Labels:** security, priority:medium, clickjacking, headers
**Description:**
### Summary
No route handler or application-level middleware sets `X-Frame-Options` or a `Content-Security-Policy` `frame-ancestors` directive. All 18+ HTML-rendering endpoints can be embedded in attacker-controlled iframes.

### Details
Most critical are state-changing pages that could be clickjacked:
- `/vote-on/<eid>` (voting form, line 203)
- `/manage/<eid>` (election management, line 315)
- `/do-open/<eid>` (election opening, line 448, GET request — doubly vulnerable)
- `/do-close/<eid>` (election closing, line 468, GET request)

Since `/do-open/<eid>` and `/do-close/<eid>` are GET requests that perform state changes, a simple iframe load (without even requiring a click on a form button) could open or close an election.

An attacker can trick an authenticated election administrator into opening/closing elections or submitting votes by framing the application page and overlaying deceptive UI elements.

**Affected Files:**
- `v3/server/pages.py` (lines 203, 315, 448, 468)

**ASVS References:** 3.1.1 (L3)

### Remediation
```python
@app.after_request
async def prevent_clickjacking(response):
    response.headers['X-Frame-Options'] = 'DENY'
    # Also set via CSP for modern browsers:
    csp = response.headers.get('Content-Security-Policy', '')
    if 'frame-ancestors' not in csp:
        response.headers['Content-Security-Policy'] = csp + "; frame-ancestors 'none'"
    return response
```

Additionally, convert state-changing GET endpoints to POST:
```python
# Change from GET to POST
@APP.post('/do-open/<eid>')  # was @APP.get
@APP.post('/do-close/<eid>')  # was @APP.get
```

### Acceptance Criteria
- [ ] X-Frame-Options header added
- [ ] CSP frame-ancestors directive added
- [ ] State-changing endpoints converted to POST
- [ ] Test verifies clickjacking prevention

### References
- Source: 3.1.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-233 - No Browser Security Feature Documentation or Degradation Behavior
**Labels:** security, priority:medium, documentation, compliance
**Description:**
### Summary
ASVS 3.1.1 explicitly requires that application documentation states expected security features browsers must support and how the application behaves when features are unavailable. Neither the application code nor any referenced configuration contains such documentation.

### Details
Missing documentation:
- No `SECURITY.md`, security section in README, or inline documentation of browser requirements
- No runtime checks for browser security feature support
- No warning mechanism for users on non-conforming browsers
- No `@app.before_request` handler that validates request security properties

Without documented browser security requirements:
- Deployment teams cannot verify that the application is served with appropriate security headers
- Operations teams have no guidance on required proxy/CDN security configurations
- Users are not warned when their browser lacks required security features

**Affected Files:**
- `v3/server/main.py` (lines 32-42)

**ASVS References:** 3.1.1 (L3)

### Remediation
1. Create `SECURITY.md` documenting required browser security features:

```markdown
# Browser Security Requirements

## Required Browser Features
- **HTTPS**: All connections MUST use TLS 1.2+
- **HSTS**: Browsers must honor Strict-Transport-Security
- **CSP**: Content-Security-Policy Level 2 support required
- **SameSite Cookies**: Browsers must support SameSite=Lax/Strict

## Degradation Behavior
- HTTP connections: Redirected to HTTPS (301)
- Missing CSP support: Application functions but logs warning
- JavaScript disabled: Critical voting forms require JS; warning displayed
- Unsupported browsers: Banner displayed recommending upgrade

## Deployment Requirements
- Reverse proxy MUST set HSTS with max-age >= 31536000
- CSP header MUST be set (see security_headers.py for values)
- X-Frame-Options: DENY must be set
```

2. Add runtime enforcement in `create_app()`:

```python
REQUIRED_SECURITY_FEATURES = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; ...",
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
}

@app.after_request
async def apply_documented_security_headers(response):
    for header, value in REQUIRED_SECURITY_FEATURES.items():
        response.headers[header] = value
    return response
```

### Acceptance Criteria
- [ ] SECURITY.md created with requirements
- [ ] Runtime enforcement implemented
- [ ] Deployment requirements documented
- [ ] Degradation behavior specified

### References
- Source: 3.1.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-234 - Externally Hosted SVG Image Without SRI or Documented Security Decision
**Labels:** security, priority:medium, third-party, supply-chain
**Description:**
### Summary
The Apache feather logo is loaded at runtime from an external domain (www.apache.org). This resource is not versioned, has no SRI integrity attribute (not supported on &lt;img&gt; elements), and has no documented security decision justifying this external dependency.

### Details
ASVS 3.6.1 requires that when SRI is not possible, there should be a documented security decision to justify this for each resource.

While SVG loaded via &lt;img&gt; is sandboxed (no script execution), a compromised resource could still be used for:
- Phishing (visual replacement)
- Tracking

If the external host is compromised or the resource is modified, the application would display attacker-controlled visual content to all users. In a voting application, this could undermine trust or be used for social engineering.

**Affected Files:**
- `v3/server/templates/header.ezt` (line 18)

**ASVS References:** 3.6.1 (L3)

### Remediation
Self-host the SVG image alongside other static assets:

In fetch-thirdparty.sh, add:
```bash
FEATHER_URL="https://www.apache.org/foundation/press/kit/feather.svg"
echo "Fetching: ${FEATHER_URL}"
curl -q --fail "${FEATHER_URL}" --output "${STATIC_DIR}/img/feather.svg"
```

In header.ezt, change to:
```html
<img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top">
```

### Acceptance Criteria
- [ ] SVG downloaded and hosted locally
- [ ] Template updated to use local path
- [ ] Build script updated
- [ ] Test verifies no external requests

### References
- Source: 3.6.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-235 - Missing SRI for Self-Hosted Third-Party Library (bootstrap-icons.css)
**Labels:** security, priority:medium, sri, defense-in-depth
**Description:**
### Summary
The SRI defense-in-depth pattern is applied to bootstrap.min.css and bootstrap.bundle.min.js but explicitly skipped for bootstrap-icons.css. This third-party CSS file controls @font-face declarations for web fonts.

### Details
If tampered with after deployment, it could:
1. Redirect font loading to an attacker-controlled origin
2. Inject CSS-based data exfiltration (e.g., attribute selectors with background URLs)
3. Modify visual rendering to mislead voters

The inconsistency creates a false confidence that third-party resources are integrity-protected when a significant gap exists. An attacker who can modify server-side files or intercept during deployment could alter bootstrap-icons.css without detection, while other Bootstrap files would trigger integrity failures.

**Affected Files:**
- `v3/server/templates/header.ezt` (line 10)
- `v3/server/bin/fetch-thirdparty.sh` (lines 70-74)

**ASVS References:** 3.6.1 (L3)

### Remediation
Add SRI hash generation and template integration:

In fetch-thirdparty.sh, after extracting bootstrap-icons.css:
```bash
echo "bootstrap-icons.css:"
echo -n "sha384-"
openssl dgst -sha384 -binary "${STATIC_DIR}/css/bootstrap-icons.css" | openssl base64 -A
echo ""
```

In header.ezt:
```html
<link href="/static/css/bootstrap-icons.css" rel="stylesheet" integrity="sha384-GENERATED_HASH_HERE">
```

### Acceptance Criteria
- [ ] SRI hash generation added to build script
- [ ] Template updated with integrity attribute
- [ ] Test verifies SRI enforcement
- [ ] Documentation updated

### References
- Source: 3.6.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-236 - Build Script Downloads Third-Party Assets Without Pre-Download Integrity Verification
**Labels:** security, priority:medium, supply-chain, build-security
**Description:**
### Summary
The build script generates SRI hashes from the downloaded content rather than verifying downloads against known-good hashes. This means curl does not use --fail flag, no pre-defined checksums are checked before extraction, no GPG signature verification of release packages, and the generated SRI hash will match whatever was downloaded, including compromised content.

### Details
If a supply chain attack targets the download (e.g., compromised GitHub release, DNS hijacking), the SRI mechanism would be rendered ineffective because the integrity hash would be computed from the malicious payload.

A supply chain compromise during the build process would result in malicious JavaScript/CSS being served to all voters, with SRI hashes that appear valid. The existing SRI provides zero protection against this attack vector.

**Affected Files:**
- `v3/server/bin/fetch-thirdparty.sh` (lines 47, 60-62, 67, 82, 92)

**ASVS References:** 3.6.1 (L3)

### Remediation
Add known-good hash verification before extraction:

1. Define expected hashes from official release notes (e.g., EXPECTED_BS_SHA256="a4a04c..." from https://github.com/twbs/bootstrap/releases)
2. Download with curl -q --fail --location "${B_URL}" --output "${ZIPFILE}"
3. Verify:
```bash
ACTUAL_HASH=$(sha256sum "${ZIPFILE}" | cut -d' ' -f1)
if [ "${ACTUAL_HASH}" != "${EXPECTED_BS_SHA256}" ]; then
    echo "ERROR: Bootstrap download integrity check failed!"
    echo "Expected: ${EXPECTED_BS_SHA256}"
    echo "Got: ${ACTUAL_HASH}"
    rm -f "${ZIPFILE}"
    exit 1
fi
```
4. Only then extract the files

### Acceptance Criteria
- [ ] Known-good hashes defined for all downloads
- [ ] Pre-download verification implemented
- [ ] Build fails on hash mismatch
- [ ] Documentation updated with hash sources

### References
- Source: 3.6.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-237 - TLS Certificates Loaded Without Integrity Verification
**Labels:** security, priority:medium, tls, certificate-management
**Description:**
### Summary
The TLS certificate and private key files — which protect the OAuth authentication channel — are loaded directly from the filesystem without any integrity verification. There is no hash comparison, fingerprint validation, or signature check to ensure certificates have not been tampered with.

### Details
An attacker with write access to the `server/certs/` directory could substitute a rogue certificate and key, enabling man-in-the-middle interception of the OAuth authentication flow.

The certificates are explicitly added to the `extra_files` watch set, meaning the server will automatically reload when certificate files change on disk, which amplifies the risk — a certificate swap triggers immediate adoption without manual restart.

A malicious certificate could:
- Intercept OAuth tokens
- Modify authentication flows
- Exfiltrate voter data
- Manipulate election results

**Affected Files:**
- `v3/server/main.py` (lines 37, 85-90)

**ASVS References:** 6.7.1 (L3)

### Remediation
Implement certificate integrity verification before loading TLS certificates:

```python
import hashlib

EXPECTED_CERT_FINGERPRINT = "sha256:abc123..."  # Store in separate, protected config

def verify_certificate_integrity(cert_path, expected_fingerprint):
    """Verify certificate file matches expected fingerprint before use."""
    with open(cert_path, 'rb') as f:
        cert_data = f.read()
    actual = "sha256:" + hashlib.sha256(cert_data).hexdigest()
    if actual != expected_fingerprint:
        raise RuntimeError(
            f"Certificate integrity check failed for {cert_path}. "
            f"Expected {expected_fingerprint}, got {actual}"
        )
    return cert_path

# In run_standalone():
if app.cfg.server.certfile:
    cert_path = CERTS_DIR / app.cfg.server.certfile
    key_path = CERTS_DIR / app.cfg.server.keyfile
    verify_certificate_integrity(cert_path, app.cfg.server.cert_fingerprint)
    kwargs['certfile'] = cert_path
    kwargs['keyfile'] = key_path
```

Additionally:
1. Enforce restrictive file permissions (0o400 for key, 0o444 for cert) at startup
2. Store certificate fingerprints in a separate, integrity-protected configuration
3. Consider removing certificates from extra_files to prevent automatic reload on modification

### Acceptance Criteria
- [ ] Certificate integrity verification implemented
- [ ] Fingerprints stored in protected config
- [ ] File permissions enforced
- [ ] Test verifies tampering detection

### References
- Source: 6.7.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-238 - Certificate File Paths Accept Unvalidated Configuration Input
**Labels:** security, priority:medium, path-traversal, configuration
**Description:**
### Summary
Certificate and key file paths are constructed by joining `CERTS_DIR` with values from `config.yaml` without validating that the resulting paths remain within the intended `certs/` directory. The `pathlib.Path` `/` operator does not sanitize path traversal sequences.

### Details
An attacker who can modify `config.yaml` (but not necessarily the code or certs directory) could redirect certificate loading to an arbitrary filesystem path, causing the server to use an attacker-controlled certificate.

While config file modification requires some prior access, defense-in-depth demands path validation.

**Affected Files:**
- `v3/server/main.py` (lines 85, 86)

**ASVS References:** 6.7.1 (L3)

### Remediation
Add path containment validation for certificate configuration values:

```python
def safe_cert_path(certs_dir, filename):
    """Ensure certificate path stays within the certs directory."""
    resolved = (certs_dir / filename).resolve()
    if not resolved.is_relative_to(certs_dir.resolve()):
        raise ValueError(
            f"Certificate path escapes certs directory: {filename}"
        )
    if not resolved.is_file():
        raise FileNotFoundError(f"Certificate file not found: {resolved}")
    return resolved

# Usage:
kwargs['certfile'] = safe_cert_path(CERTS_DIR, app.cfg.server.certfile)
kwargs['keyfile'] = safe_cert_path(CERTS_DIR, app.cfg.server.keyfile)
```

### Acceptance Criteria
- [ ] Path containment validation implemented
- [ ] Path traversal attempts rejected
- [ ] Test verifies directory escape prevented
- [ ] Error messages clear and actionable

### References
- Source: 6.7.1.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-239 - Cryptographic Key Material Not Cleared From Memory After Use
**Labels:** security, priority:medium, crypto, memory-management
**Description:**
### Summary
Per-voter encryption keys, the election opened_key, and derived key material remain in process memory beyond their operational need. During tallying, key material for every voter/issue pair accumulates across loop iterations. No cleanup mechanism exists for sensitive cryptographic material after use.

### Details
The vulnerable functions include:
- create_vote()
- decrypt_votestring()
- _b64_vote_key()
- add_vote()
- tally_issue()

Memory disclosure vulnerabilities (e.g., via /proc/&lt;pid&gt;/mem, heap inspection, or swap) would expose these keys, allowing decryption of any intercepted ciphertexts. The opened_key (election master key) remaining in the md variable is particularly critical as it enables derivation of all vote tokens.

**Affected Files:**
- `v3/steve/crypto.py` (lines 65, 73, 51)
- `v3/steve/election.py` (lines 224, 238)

**ASVS References:** 11.7.2 (L3)

### Remediation
While Python doesn't natively support secure memory erasure for immutable types, use bytearray for mutable key storage and explicit zeroing:

1. Implement a _secure_zero() function using ctypes.memset for critical material
2. Wrap key operations in try/finally blocks to ensure cleanup
3. Consider using ctypes-based wrappers or compiled-language crypto modules for the most sensitive operations to achieve better memory control

Example:
```python
import ctypes

def _secure_zero(data):
    """Attempt to zero sensitive data in memory."""
    if isinstance(data, bytearray):
        ctypes.memset(id(data) + 32, 0, len(data))  # Offset for bytearray header
```

### Acceptance Criteria
- [ ] _secure_zero() function implemented
- [ ] Key operations wrapped in try/finally
- [ ] bytearray used for mutable key storage
- [ ] Test verifies cleanup occurs

### References
- Source: 11.7.2.md
- CWE: None specified

### Priority
Medium

---

## Issue: FINDING-240 - Unbounded Synchronous Vote Processing Loop Amplifies Event Loop Starvation
**Labels:** security, priority:medium, performance, async
**Description:**
### Summary
Vote submission loops over all issues synchronously, performing database reads, PBKDF key derivation, encryption, and database writes for each issue without yielding to the event loop. For elections with many issues, this creates extended blocking proportional to the number of issues.

### Details
Each add_vote() call includes key derivation (PBKDF), which is deliberately slow. This multiplied across N issues creates significant starvation. Multiple voters submitting simultaneously will serialize completely, with each voter's full submission blocking all others.

Additionally, _all_metadata(self.S_OPEN) is re-queried on every iteration, performing redundant state checks that add unnecessary blocking time.

For an election with 20 issues, approximately 100 synchronous blocking operations occur in a single request.

**Affected Files:**
- `v3/server/pages.py` (lines 399-432)
- `v3/steve/election.py` (lines 231-244)

**ASVS References:** 15.4.4 (L3)

### Remediation
**Option 1:** Offload each blocking add_vote() call to thread pool:
```python
await asyncio.to_thread(election.add_vote, result.uid, iid, votestring)
```

**Option 2 (preferred):** Create a bulk add_votes_bulk() method that:
- Caches the metadata query
- Wraps all inserts in a single transaction
- Reduces per-vote overhead and redundant state checks

### Acceptance Criteria
- [ ] Blocking operations offloaded to thread pool OR bulk method implemented
- [ ] Event loop starvation eliminated
- [ ] Redundant state checks removed
- [ ] Performance test verifies improvement

### References
- Source: 15.4.4.md
- CWE: None specified

### Priority
Medium