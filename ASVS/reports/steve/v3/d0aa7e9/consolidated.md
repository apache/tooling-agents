# Security Audit Consolidated Report — apache/tooling-agents

## Report Metadata

| Field | Value |
|---|---|
| **Repository** | `apache/tooling-agents` |
| **ASVS Level** | L3 (includes L1 and L2 requirements) |
| **Severity Threshold** | None — all findings included |
| **Commit** | `d0aa7e9` |
| **Date** | Apr 23, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 345 |
| **Total Findings** | 240 |

## Executive Summary

### Severity Distribution

| Severity | Count | Pct |
|---|--:|--:|
| **Critical** | 21 | 8.8% |
| **High** | 69 | 28.7% |
| **Medium** | 150 | 62.5% |
| **Low** | 0 | 0.0% |
| **Info** | 0 | 0.0% |
| **Total** | **240** | **100%** |

The finding population is dominated by Medium-severity issues (62.5%), but the 21 Critical findings represent fundamental control absences — not edge cases — in authorization, CSRF, XSS prevention, and audit logging. The absence of any Low or Informational findings reflects the severity profile of a pre-hardening codebase: the issues that exist tend to be structural rather than cosmetic.

### ASVS Level Coverage

The audit evaluated requirements across all three ASVS levels. Findings span the full level hierarchy:

| Applicable Level | Findings | Notes |
|---|--:|---|
| **L1** (minimum) | ~45 | Fundamental controls — XSS, CSRF, TLS enforcement, session basics |
| **L2** (standard) | ~185 | Authorization policy, logging, OAuth integration, header hardening |
| **L3** (advanced) | ~120 | Concurrency, cryptographic governance, secrets management, isolation |

Many findings are tagged at multiple levels (e.g., a Critical authorization bypass is relevant at L1 *and* L2), indicating that foundational gaps persist into higher assurance tiers rather than being confined to one level.

### Top 5 Risks

**1. Complete Absence of Authorization on Election Management Endpoints**
*(FINDING-006, -010, -011, -012, -049, -051, -073)*

No ownership or role verification exists on any election management operation. Any authenticated user — regardless of relationship to an election — can modify its properties, add or remove issues, open or close voting, delete the election, and submit votes on behalf of others. The `authz` field is defined in the schema and documented but is never evaluated in any access-control decision. Combined with the missing voter-eligibility check on the vote submission endpoint, this constitutes a total authorization control failure for the application's primary asset: election integrity.

**2. Systemic Cross-Site Scripting Across All Template-Rendered Pages**
*(FINDING-001, -002, -003, -004, -022, -031, -091, -113, -114)*

The EZT template engine does not apply HTML output encoding by default, and the vast majority of template substitutions render user-controlled data — election titles, issue descriptions, candidate names, flash messages, URL path parameters — as raw HTML. This produces stored XSS vectors on every listing and management page, and reflected XSS on error pages. Because elections are multi-user environments where administrators and voters view the same data, an attacker with election-creation privileges can target any authenticated user, including administrators. A partial mitigation exists (`[format "js,html"]`) but is applied only in isolated JavaScript attribute contexts, leaving the primary HTML body unprotected.

**3. Non-Functional CSRF Protection Combined with GET-Based State Changes**
*(FINDING-007, -008, -009, -033, -034, -036)*

The application's CSRF token is a hardcoded placeholder string that the server never validates, rendering form-based CSRF protection entirely inoperative. This is compounded by the use of GET requests for irreversible, state-changing operations — opening elections, closing elections, and deleting elections — which bypasses even theoretical CSRF defenses and exposes these operations to triggering via image tags, prefetch links, or any cross-origin resource embed. POST endpoints additionally accept CORS-safelisted content types without origin verification. Together, these gaps allow any external website visited by an authenticated administrator to silently manipulate election state.

**4. Election State Machine Enforced by Removable `assert` Statements**
*(FINDING-005, -025, -082, -087, -088)*

The election lifecycle state machine — the core control preventing vote acceptance after closure, premature tallying, or modifications to finalized elections — is enforced exclusively through Python `assert` statements. These are silently and completely removed when the Python interpreter runs with the `-O` (optimize) flag, a common production deployment practice. No database-level state guards, no application-level exception-based checks, and no SQL `WHERE` clauses enforce state constraints on the critical paths for election open, close, delete, and vote-accept operations. A separate TOCTOU race condition in the close and delete paths further allows concurrent requests to bypass the state check even when assertions are active.

**5. Absence of Audit Logging, Session Lifecycle Controls, and Cryptographic Governance**
*(FINDING-019, -042, -062, -068, -070, -079, -080, -083)*

The application has no logout endpoint, no session inactivity or absolute timeout, no mechanism for administrators to terminate sessions, and no session regeneration on authentication state changes — meaning compromised sessions persist indefinitely. Tally operations (the most sensitive post-election action) produce no audit trail identifying who initiated them or when. Authorization failures, authentication events, and business-logic bypass attempts are not logged. No cryptographic inventory or algorithm migration plan exists despite active use of both legacy (AES-128-CBC/Fernet) and modern (XChaCha20-Poly1305) primitives, with the election master key stored in the same database as the encrypted votes it protects.

### Positive Controls Identified

Despite the severity of the findings above, the audit identified multiple well-implemented defensive controls that materially reduce the application's attack surface in several categories.

**Input and Injection Prevention**

The application achieves strong injection resistance in its data layer. All SQL queries across `queries.yaml` use parameterized `?` placeholders via the `asfpy.db` wrapper, with zero instances of string concatenation in query construction. The codebase contains no usage of `os.system()`, `subprocess`, `eval()`, `exec()`, `compile()`, or `pickle` deserialization — eliminating OS command injection, code injection, and unsafe deserialization as attack classes entirely. YAML parsing uses `yaml.safe_load()`. LDAP filters are hardcoded constants with no user-derived components. The single regex pattern (`r'doc:([^\s]+)'`) is static with O(n) complexity and no backtracking risk. Python as the implementation language provides inherent memory safety, eliminating buffer overflows, use-after-free, and stack-based attacks. Data is stored in canonical (raw) form without pre-encoding, and the Quart framework performs URL decoding exactly once, satisfying the single-decode principle.

**Cryptographic Design for Vote Anonymity**

The vote anonymization architecture is well-designed. Per-voter, per-issue cryptographic salts drive vote-token derivation through `(opened_key, pid, iid, salt)`, providing strong separation between voter identity and vote content. Votes are shuffled (`crypto.shuffle()`) before tallying to prevent database-insertion-order leakage. Cryptographic parameters (Argon2, HKDF) are hardcoded constants, preventing user-controlled manipulation at the cryptographic boundary. A tamper-detection mechanism (`is_tampered()`) recomputes the `opened_key` binding from current election data to detect post-opening modifications.

**Data Integrity and Schema Enforcement**

SQLite tables use `STRICT` mode with explicit type constraints, foreign key constraints with `ON DELETE RESTRICT`, and a database trigger (`prevent_open_close_update`) that prevents modification of advisory timestamps after election closure. Election and issue IDs are generated via `crypto.create_id()` with collision-safe retry loops catching `IntegrityError`. Multi-step modifications use explicit `BEGIN TRANSACTION` / `COMMIT` boundaries. The `MAX(vid)` ordering scheme for re-voting preserves full vote history while ensuring only the latest vote counts.

**Defense in Depth**

External CDN resources carry Subresource Integrity (SRI) attributes. File serving uses Quart's `send_from_directory()`, providing framework-level path-traversal prevention. The EZT template engine supports only substitution, iteration, and conditionals — with no code-execution capability — inherently preventing server-side template injection. Context-specific escaping (`[format "js,html"]`) is correctly applied in JavaScript attribute contexts in management templates. A client-side `escapeHtml()` function provides additional defense for dynamically generated DOM content. API response methods (`get_metadata()`, `get_issue()`) explicitly exclude sensitive fields (`salt`, `opened_key`) with documented intent. All data-modifying endpoints require authentication via `@asfquart.auth.require`. LDAP communication uses `ldaps://` for transport encryption.

---

## 3. Findings

### 3.1 Critical

#### FINDING-001: Systemic Missing HTML Output Encoding in EZT Templates Enabling Stored and Reflected XSS

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.1.1, 1.1.2, 1.2.1, 1.3.4, 1.3.5 |
| **Files** | `v3/server/templates/manage.ezt:176,180,241,283`&lt;br&gt;`v3/server/templates/manage-stv.ezt:134,175,196`&lt;br&gt;`v3/server/templates/admin.ezt:19`&lt;br&gt;`v3/server/templates/voter.ezt:35,49,88,96`&lt;br&gt;`v3/server/templates/vote-on.ezt:88,108,109,131,163`&lt;br&gt;`v3/server/templates/e_bad_eid.ezt:8`&lt;br&gt;`v3/server/templates/e_bad_iid.ezt:8`&lt;br&gt;`v3/server/templates/e_bad_pid.ezt:8`&lt;br&gt;`v3/server/pages.py:174-225,240` |
| **Source Reports** | 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.3.4.md, 1.3.5.md |
| **Related** | FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

The EZT templating engine provides the `[format "html"]` directive for HTML encoding, but it is not applied at the majority of output points across all templates. User-controlled data including election titles, issue titles/descriptions, owner names, authorization strings, and URL parameters are rendered directly as `[variable]` without encoding in HTML body contexts. The control exists and is correctly used in a few JavaScript onclick handlers, demonstrating awareness but inconsistent application (Type B gap). This enables both stored XSS (via database-persisted election/issue data) and reflected XSS (via URL parameters in error pages). Any authenticated committer can inject persistent JavaScript affecting all voters; attackers can also craft malicious URLs targeting authenticated users.

**Remediation:**

Apply `[format "html"]` to all user-controlled variables in HTML body contexts. Examples: Change `<strong>[issues.title]</strong>` to `<strong>[format "html"][issues.title][end]</strong>`. Apply to all instances of [owned.title], [owned.owner_name], [owned.authz], [e_title], [election.title], [election.owner_name], [election.authz], [issues.title], [issues.description], [open_elections.title], [open_elections.owner_name], [open_elections.authz], [upcoming_elections.title], [eid], [iid], [pid], etc. Alternative (strongly recommended): Migrate to a template engine with auto-escaping by default (e.g., Jinja2 with `autoescape=True`) to eliminate this entire vulnerability class architecturally.

---

#### FINDING-002: JavaScript Injection via Unencoded Server Data in STV Candidate JavaScript Object

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.1.1, 1.1.2, 1.2.1, 1.2.3, 1.3.10, 1.3.5, 1.3.7, 1.3.3, 3.2.2 |
| **Files** | `v3/server/templates/vote-on.ezt:within <script> block (STV_CANDIDATES object)`&lt;br&gt;`v3/server/pages.py:258-263` |
| **Source Reports** | 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.2.3.md, 1.3.10.md, 1.3.5.md, 1.3.7.md, 1.3.3.md, 3.2.2.md |
| **Related** | FINDING-001, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

The vote-on.ezt template embeds user-controlled data (issue titles, STV candidate names/labels) directly into JavaScript string literals within a `<script>` block without JavaScript encoding. The `[format "js"]` or `[format "js,html"]` directive exists in the codebase and is correctly used in manage.ezt and manage-stv.ezt for identical scenarios, but is completely omitted in the voter-facing ballot page (Type B gap). An election administrator can inject JavaScript by including characters like `"`, `\`, or `</script>` in candidate names or issue titles, breaking out of the string context. This executes arbitrary JavaScript in every voter's browser, enabling session hijacking, silent vote manipulation, and complete compromise of election integrity.

**Remediation:**

Apply `[format "js"]` to all server-supplied values in JavaScript contexts: `const STV_CANDIDATES = { [for issues][is issues.vtype "stv"] "[format "js"][issues.iid][end]": { seats: [issues.seats], title: "[format "js"][issues.title][end]", candidates: [ [for issues.candidates]{ label: "[format "js"][issues.candidates.label][end]", name: "[format "js"][issues.candidates.name][end]" },[end] ] },[end][end] };`. Alternative (recommended): Use safer architecture by serializing data as JSON from Python using `json.dumps()` and embedding as a data attribute, then parsing with `JSON.parse()` on the client side. This eliminates the injection class entirely.

---

#### FINDING-003: Stored XSS via Unsanitized Issue Descriptions Rendered as Raw HTML

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.3.1, 1.3.4, 1.3.5, 1.3.10, 1.1.1, 1.1.2, 1.2.1, 1.2.2, 1.2.9, 3.2.2 |
| **Files** | `v3/server/pages.py:54-61,466,485,39-48,325-326,27-35`&lt;br&gt;`v3/server/templates/vote-on.ezt:N/A`&lt;br&gt;`v3/server/templates/manage.ezt:N/A`&lt;br&gt;`v3/server/templates/manage-stv.ezt:N/A`&lt;br&gt;`v3/steve/election.py:202` |
| **Source Reports** | 1.3.1.md, 1.3.10.md, 1.3.4.md, 1.3.5.md, 1.3.9.md, 1.3.3.md, 1.1.1.md, 1.1.2.md, 1.2.1.md, 1.2.2.md, 1.2.9.md, 3.2.2.md |
| **Related** | FINDING-001, FINDING-002, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

The application accepts user-controlled issue descriptions and explicitly constructs HTML from this untrusted input without any sanitization. The `rewrite_description()` function wraps descriptions in `<pre>` tags and converts `doc:filename` patterns into HTML anchor tags, but performs no HTML sanitization on the user input before or after this transformation. The EZT templating engine does not auto-escape HTML output. While the codebase demonstrates awareness of escaping by using `[format "js,html"]` for JavaScript contexts, this escaping is not applied when the same data is rendered in HTML body contexts, creating a critical stored XSS vulnerability. An authenticated committer can inject malicious JavaScript that executes when any voter views the election page, enabling vote manipulation, session hijacking, privilege escalation, and election integrity compromise.

**Remediation:**

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

---

#### FINDING-004: Stored XSS via Unsanitized Election Titles in All Listing Templates

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.3.1, 1.3.4, 1.3.5, 1.3.10 |
| **Files** | `v3/server/pages.py:405,410,147,353`&lt;br&gt;`v3/server/templates/admin.ezt:N/A`&lt;br&gt;`v3/server/templates/voter.ezt:N/A`&lt;br&gt;`v3/server/templates/manage.ezt:N/A`&lt;br&gt;`v3/server/templates/vote-on.ezt:N/A`&lt;br&gt;`v3/server/templates/flashes.ezt:N/A` |
| **Source Reports** | 1.3.1.md, 1.3.10.md, 1.3.4.md, 1.3.5.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

Election titles are accepted from user input without any sanitization and stored directly in the database. These titles are subsequently rendered in multiple templates without HTML escaping, creating stored XSS vulnerabilities that affect all users who view election listings. The vulnerability is particularly severe because election titles appear on listing pages viewed by ALL eligible voters, providing broad attack surface. Additionally, titles are embedded in flash messages, which are also rendered without escaping. The impact includes vote manipulation, session hijacking, election integrity compromise, with broader reach than issue descriptions as titles appear on pages viewed by all eligible voters and higher-privileged users.

**Remediation:**

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

---

#### FINDING-005: Election Lifecycle State Enforcement Uses Removable `assert` Statements

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-617 |
| **ASVS Sections** | 2.3.1, 2.3.2, 2.3.4, 2.1.2, 2.1.3, 8.1.2, 8.1.3, 8.1.4, 13.2.2, 15.1.5, 15.4.1, 15.4.3 |
| **Files** | `v3/steve/election.py:50,70,78,107,110,116,123,127,176,190,193,205,208,227,228,241,273,349` |
| **Source Reports** | 2.3.1.md, 2.3.2.md, 2.3.4.md, 2.1.2.md, 2.1.3.md, 8.1.2.md, 8.1.3.md, 8.1.4.md, 13.2.2.md, 15.1.5.md, 15.3.5.md, 15.4.1.md, 15.4.3.md |
| **Related** | None |

**Description:**

Multiple state-dependent write operations use Python assert statements to enforce election state requirements. Python assert statements can be globally disabled with the -O or -OO command-line flags, which removes all assertions from the bytecode. This makes state-based authorization controls bypassable through deployment configuration rather than code modification. The election state machine's integrity depends entirely on these assertions. Per Python documentation: 'assert should not be used for data validation because it can be globally disabled'. When Python is run with optimization flags (python -O or PYTHONOPTIMIZE=1), all assert statements are removed from the bytecode. This is common in production deployments for performance, which would eliminate critical state machine enforcement and input validation. The documentation defines the election state model as a security control (editable state restricts modifications), but the enforcement mechanism is bypassable. Some state checks are advisory (assert) while others are mandatory (exception-based, as correctly implemented in add_vote).

**Remediation:**

Replace all assert statements used for security validation with explicit if/raise patterns. Example transformation: Before: `assert self.is_editable()` and `assert vtype in vtypes.TYPES`. After: `if not self.is_editable(): raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE)` and `if not isinstance(vtype, str) or vtype not in vtypes.TYPES: raise ValueError(f'Invalid vote type: {vtype!r}. Must be one of {vtypes.TYPES}')`. Apply this pattern to all methods using assert for security checks in delete(), open(), add_salts(), add_issue(), edit_issue(), delete_issue(), add_voter(), and _compute_state(). Additionally, document this pattern in architecture documentation as a dangerous area requiring explicit runtime checks, and add deployment documentation warning that PYTHONOPTIMIZE must never be set.

---

#### FINDING-006: Missing Owner Authorization on All Election Management Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2, L3, L1 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 2.3.2, 2.3.5, 2.1.2, 2.1.3, 4.4.3, 7.2.1, 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.2.3, 8.3.1, 8.3.3, 8.4.1, 14.1.2, 14.2.4 |
| **Files** | `v3/server/pages.py:193,215,218,98,81,336,388,404,422,439,461,481,489,508,526,550,572,425,331,486,510,533,451,468,375,382,398-401,404-407,170-193,196-227`&lt;br&gt;`v3/schema.sql:68,73,68-75` |
| **Source Reports** | 2.3.2.md, 2.3.5.md, 2.1.2.md, 2.1.3.md, 4.4.3.md, 7.2.1.md, 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.2.3.md, 8.3.1.md, 8.3.3.md, 8.4.1.md, 14.1.2.md, 14.2.4.md |
| **Related** | FINDING-049 |

**Description:**

The application defines election ownership (owner_pid) and group authorization (authz) fields in the database schema with explicit documentation stating that only the owner or members of the specified LDAP group should be able to edit elections. However, these controls are never enforced in the web layer. The load_election and load_election_issue decorators, which are applied to all 9-11 management endpoints, contain only placeholder comments '### check authz' with no actual authorization logic. Any authenticated ASF committer can manipulate any election — opening, closing, adding/editing/deleting issues, and changing dates — regardless of whether they are the owner or in the authorized group. This undermines the entire election integrity model and violates the documented authorization policy. This is a Type B gap where the authorization need is explicitly recognized in documentation and schema but the check is never implemented, creating dangerous false confidence.

**Remediation:**

Implement authorization checks in the load_election decorator to verify that the session user is either the owner_pid or a member of the authz LDAP group before allowing access to management endpoints. Add is_authorized_manager() function to check ownership and group membership. Document authorization rules in a formal policy matrix mapping functions to required roles and resource relationships. Return 403 Forbidden for unauthorized access attempts with security logging. Example implementation: Create a check_election_authz() function that verifies the authenticated user's UID matches the election's owner_pid or is a member of the authz group. Apply this check in both load_election and load_election_issue decorators before returning the election/issue objects.

---

#### FINDING-007: Irreversible State-Changing Operations Use GET Method Enabling CSRF and Accidental Triggering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 2.3.2, 2.3.5, 2.1.2, 2.1.3, 3.3.2, 4.1.4, 4.4.3, 8.1.4, 8.3.1, 8.3.2, 10.2.1, 14.1.1, 14.1.2, 14.2.4 |
| **Files** | `v3/server/pages.py:404,422,479-480,499-500,447,464,485,505`&lt;br&gt;`v3/server/templates/manage.ezt:267` |
| **Source Reports** | 2.3.2.md, 2.3.5.md, 2.1.2.md, 2.1.3.md, 3.3.2.md, 4.1.4.md, 4.4.3.md, 8.1.4.md, 8.3.1.md, 8.3.2.md, 10.2.1.md, 14.1.1.md, 14.1.2.md, 14.2.4.md |
| **Related** | FINDING-008, FINDING-009, FINDING-030, FINDING-033, FINDING-034, FINDING-109 |

**Description:**

Critical state-changing operations (opening and closing elections) are implemented as GET endpoints with only client-side JavaScript confirmation dialogs. The server-side handlers perform no verification beyond authentication, and the use of GET methods means these operations can be triggered via simple URL navigation, image tags, iframe embeds, or browser prefetch mechanisms — completely bypassing the client-side confirmation. Election state transitions are irreversible operations that can be triggered by cross-site image tags, link prefetching, browser extensions, or web crawlers. Combined with the missing ownership check (AUTHZ-001), this allows any authenticated committer's browser session to be weaponized to open or close any election through cross-site request forgery or social engineering. Election state (editable → open → closed) is a critical authorization decision factor — it controls whether voting is accepted, whether issues can be edited, and whether tallying is permitted. ASVS 8.3.2 requires that changes to authorization decision values be controlled. Using GET for these operations means the authorization state change is trivially triggerable without the user's explicit intent.

**Remediation:**

1. Immediate: Convert do_open_endpoint() and do_close_endpoint() to POST method with CSRF token validation. 2. Update manage.ezt template to use form submission instead of window.location.href navigation. 3. Short-term: Add audit logging (structured, not access logging) for state changes with partial election IDs only. 4. Long-term: Implement classification-aware routing policy with validate_route() method that validates HTTP method is appropriate for data classification (CRITICAL/SENSITIVE/INTERNAL identifiers require POST for state changes).

---

#### FINDING-008: CSRF Token Is a Hardcoded Placeholder; Server Never Validates It

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.1, 10.2.1 |
| **Files** | `v3/server/pages.py:95,438,478`&lt;br&gt;`v3/server/templates/manage.ezt`&lt;br&gt;`v3/server/templates/vote-on.ezt`&lt;br&gt;`v3/server/templates/admin.ezt` |
| **Source Reports** | 3.5.1.md, 10.2.1.md |
| **Related** | FINDING-007, FINDING-009, FINDING-030, FINDING-033, FINDING-034, FINDING-109 |

**Description:**

The CSRF token is hardcoded as the string 'placeholder' and is never validated in any POST handler. This creates a false sense of security while leaving all state-changing operations vulnerable to CSRF attacks. All state-changing operations on the OAuth client are unprotected against CSRF including vote manipulation (attacker can submit or change votes for authenticated voters), election manipulation (attacker can create elections, add/edit/delete issues, set dates). The placeholder token creates false confidence that protection exists. Affected operations include: POST /do-vote/&lt;eid&gt; (Submit votes), POST /do-create-election (Create election), POST /do-add-issue/&lt;eid&gt; (Add election issue), POST /do-edit-issue/&lt;eid&gt;/&lt;iid&gt; (Edit issue), POST /do-delete-issue/&lt;eid&gt;/&lt;iid&gt; (Delete issue), POST /do-set-open_at/&lt;eid&gt; (Set open date), POST /do-set-close_at/&lt;eid&gt; (Set close date).

**Remediation:**

Implement real CSRF token generation using secrets.token_hex(32) stored in session, and create a validate_csrf_token() function that checks tokens from both form data and X-CSRFToken headers. Apply this validation to all state-changing endpoints including: /do-vote/&lt;eid&gt;, /do-create-election, /do-add-issue/&lt;eid&gt;, /do-edit-issue/&lt;eid&gt;/&lt;iid&gt;, /do-delete-issue/&lt;eid&gt;/&lt;iid&gt;, /do-set-open_at/&lt;eid&gt;, and /do-set-close_at/&lt;eid&gt;. Use secrets.compare_digest() for constant-time comparison to prevent timing attacks.

---

#### FINDING-009: Election Open and Close Operations Use GET Method for Irreversible State Changes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.1, 3.5.2, 3.5.3 |
| **Files** | `v3/server/pages.py:504,523,536-553,555-571,448-466,469-484`&lt;br&gt;`v3/server/templates/manage.ezt:285,297`&lt;br&gt;`v3/steve/election.py:73,94` |
| **Source Reports** | 3.5.1.md, 3.5.2.md, 3.5.3.md |
| **Related** | FINDING-007, FINDING-008, FINDING-030, FINDING-033, FINDING-034, FINDING-109 |

**Description:**

Two critical state-changing operations (opening and closing elections) are implemented as GET requests, making them trivially exploitable through image tags, link prefetch, or simple hyperlinks. The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints permanently and irreversibly change election state without any CSRF protection, custom headers, or preflight checks. GET requests are always considered 'simple requests' by the browser and will never initiate a preflight OPTIONS request, regardless of origin. This bypasses even SameSite=Lax cookie protections, violates REST semantics, and makes it impossible to use CORS preflight as a cross-origin protection mechanism. An attacker who knows or can guess an election ID can trick an authenticated committer into prematurely opening or closing any election they have access to.

**Remediation:**

Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST endpoints with CSRF token validation. Update the JavaScript event handlers in manage.ezt to use form submission with POST method instead of window.location.href. Include CSRF token in the dynamically created form before submission. This will require preflight checks and proper token validation, preventing trivial exploitation via image tags or links. Add comprehensive logging for election state transitions with user ID, timestamp, and IP address. Consider implementing Sec-Fetch-* header validation middleware as defense-in-depth.

---

#### FINDING-010: Cross-Election Issue Data Access and Modification via Unscoped Queries

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.2, 8.3.3, 8.4.1 |
| **Files** | `v3/queries.yaml:N/A`&lt;br&gt;`v3/steve/election.py:145,151,160,161,170,171`&lt;br&gt;`v3/server/pages.py:495,515,175,193-221` |
| **Source Reports** | 8.2.2.md, 8.3.3.md, 8.4.1.md |
| **Related** | FINDING-051, FINDING-053, FINDING-153 |

**Description:**

Issue-level queries (q_get_issue, c_edit_issue, c_delete_issue) filter only by iid without constraining to the parent election's eid. Combined with the load_election_issue decorator not validating issue-election affiliation, operations on Election A can read/modify/delete issues belonging to Election B. This allows an attacker to bypass election state restrictions by routing operations through an editable election. The queries do not include EID filters, allowing operations on issues from different elections. A malicious user could supply an iid belonging to a different election, and the decorator would load it without verifying the relationship. Combined with AUTHZ-001, this means any committer can modify any issue in any election by specifying a different election's EID in the URL path.

**Remediation:**

Add election scoping to issue queries in queries.yaml by adding 'AND eid = ?' to q_get_issue, c_edit_issue, and c_delete_issue queries. Modify get_issue(), edit_issue(), and delete_issue() methods in election.py to pass self.eid as an additional parameter. Add rowcount checks to detect when no rows are affected (indicating cross-election attempts or non-existent issues). Raise IssueNotFound exception when rowcount is 0. In the load_election_issue decorator, verify that the loaded issue's eid matches the loaded election's eid.

---

#### FINDING-011: Vote Submission Endpoint Lacks Voter Eligibility Authorization Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 10.3.2, 10.4.11 |
| **Files** | `v3/server/pages.py:424-467,426,411-456` |
| **Source Reports** | 10.3.2.md, 10.4.11.md |
| **Related** | None |

**Description:**

The vote submission endpoint fails to verify that the authenticated user (`sub` claim from OAuth token, stored as `uid` in session) is eligible to vote in the target election. While the GET handler (`vote_on_page`) correctly checks voter eligibility using `election.q_find_issues.perform(result.uid, election.eid)`, the POST handler that actually records votes performs no such check. The endpoint has an explicit `### check authz` comment stub at line 426, indicating the developers intended to implement this check but never did. Any authenticated committer can vote in any election, even those they are not eligible for, compromising the integrity of election results.

**Remediation:**

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

---

#### FINDING-012: Election Management Endpoints Missing Ownership Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 10.3.2, 10.4.11 |
| **Files** | `v3/server/pages.py:493,498,515,520,410,98,417,534,539,559,564,583,588,355,195,97,193,217,227,487,508,527,554,581` |
| **Source Reports** | 10.3.2.md, 10.4.11.md |
| **Related** | None |

**Description:**

All election management endpoints fail to verify that the authenticated user (identified by the `sub` claim from the OAuth token, stored as `uid` in the session) owns the election being modified. The `uid` claim is available throughout the application but is never compared against election ownership. The `Election.owned_elections(DB_FNAME, result.uid)` query exists and is used in `admin_page` for display purposes, but is never used as an enforcement gate for state-changing operations. Any authenticated committer can tamper with elections they don't own — opening elections prematurely, closing them early to suppress votes, deleting issues, or modifying election content.

**Remediation:**

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

---

#### FINDING-013: No TLS Protocol Version Enforcement — Server May Accept Deprecated TLS 1.0/1.1 Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 12.1.1, 12.3.1 |
| **Files** | `v3/server/main.py:83-91,99-118,76-82`&lt;br&gt;`v3/server/config.yaml.example` |
| **Source Reports** | 12.1.1.md, 12.3.1.md |
| **Related** | None |

**Description:**

The application provides no explicit TLS protocol version enforcement. When TLS is enabled via certificate configuration, the server passes raw certfile/keyfile paths to the underlying framework without constructing or configuring an ssl.SSLContext, leaving protocol version negotiation entirely to system-level OpenSSL defaults. This means no minimum_version is set, no protocol flags disable TLS 1.0/1.1, no TLS 1.3 preference is configured, and both deployment modes (standalone and ASGI) are affected. The application constructs TLS parameters by passing only certfile and keyfile as keyword arguments to app.runx(), with no explicit ssl.SSLContext creation or configuration at any point in the codebase. This violates ASVS requirements for TLS 1.2+ minimum version enforcement and allows negotiation of deprecated protocols with known vulnerabilities (BEAST, POODLE, Lucky13).

**Remediation:**

Create an explicit ssl.SSLContext with enforced minimum version and pass it to the server framework. The remediation includes: (1) Create a _create_tls_context() function that instantiates ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) with minimum_version set to TLSv1_2 and maximum_version set to TLSv1_3; (2) Configure SSL options including OP_NO_COMPRESSION, OP_CIPHER_SERVER_PREFERENCE, OP_SINGLE_DH_USE, and OP_SINGLE_ECDH_USE; (3) Restrict cipher suites to strong modern ciphers using set_ciphers() with 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES'; (4) Load the certificate chain and pass the ssl_context to app.runx() via kwargs['ssl']; (5) For ASGI/Hypercorn deployment, provide a hypercorn.toml configuration file with certfile, keyfile, and ciphers configuration; (6) Add minimum_tls_version and ciphers fields to the config schema; (7) Provide a hardened hypercorn.toml template for ASGI deployments; (8) Add a startup warning/abort when certfile is empty and the server is not binding to localhost.

---

#### FINDING-014: Application Falls Back to Plain HTTP When TLS Not Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-319 |
| **ASVS Sections** | 12.2.1, 12.3.1, 12.3.3, 4.4.1 |
| **Files** | `v3/server/main.py:84-90,98-117,77-80,98-104`&lt;br&gt;`v3/server/config.yaml.example:27-31,28-31` |
| **Source Reports** | 12.2.1.md, 12.3.1.md, 12.3.3.md, 4.4.1.md |
| **Related** | FINDING-178 |

**Description:**

The TLS control exists but is implemented as an optional, bypassable configuration toggle. The `if app.cfg.server.certfile:` conditional means when the certfile config value is empty, blank, or absent, the server launches over plain HTTP with zero warnings, zero errors, and zero compensating controls. The configuration comments actively document this as intended behavior. There is no enforcement at any layer - no startup validation that rejects a missing TLS configuration, no HTTP listener that redirects to HTTPS, no HSTS header injection, and no warning log message when operating without TLS. The application silently degrades to an insecure transport. ASGI mode has no TLS configuration at all - the `run_asgi()` function creates the application without any TLS parameters, delegating all transport security to the external ASGI server or reverse proxy with no verification that such protection exists. For this voting system, plain HTTP operation exposes authentication tokens (ASF OAuth tokens and session cookies transmitted in cleartext), vote contents (transmitted from client to server in HTTP request body before encryption), election management operations, and causes complete loss of transport security guarantees. This directly violates ASVS 12.2.1 and 12.3.1 requirements that the server must not fall back to insecure or unencrypted communications.

**Remediation:**

Make TLS mandatory by enforcing certificate validation at startup - fail with critical error if certfile/keyfile are missing or invalid. Remove config documentation suggesting plain HTTP is acceptable. Create explicit `ssl.SSLContext` with `minimum_version=TLSv1_2` and restricted cipher suites (ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!RC4:!3DES) instead of passing raw file paths. Add HSTS response header (`Strict-Transport-Security: max-age=31536000; includeSubDomains`) to all responses. For ASGI mode, document mandatory Hypercorn TLS configuration and add startup validation of `X-Forwarded-Proto` or equivalent. Consider adding an HTTP listener that returns 301 redirects to HTTPS to handle accidental plaintext connections. Add validation logic to check that certificate and key files exist before starting the server. Update config.yaml.example to remove the "leave blank for plain HTTP" guidance and document TLS as mandatory.

---

#### FINDING-015: AES-128-CBC (Fernet) Used Instead of Approved AEAD Cipher; Incomplete Migration to XChaCha20-Poly1305

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 11.3.2 |
| **Files** | `v3/steve/crypto.py:63-75,77-80,84-88`&lt;br&gt;`v3/steve/election.py:236,271` |
| **Source Reports** | 11.3.2.md |
| **Related** | None |

**Description:**

The application uses Fernet (AES-128-CBC + HMAC-SHA256) for vote encryption, which violates ASVS 11.3.2's requirement for approved AEAD cipher modes such as AES-GCM or ChaCha20-Poly1305. Evidence of an incomplete cryptographic migration exists: the key derivation function is explicitly configured for XChaCha20-Poly1305 (HKDF with info=b'xchacha20_key', 32-byte key length), but the actual encryption operations still use Fernet. This represents a Type B gap where the control exists but is not applied, creating false confidence that an approved cipher is in use. Fernet uses AES-128-CBC (not an approved AEAD mode), splits the 32-byte key into 16 bytes for HMAC-SHA256 and 16 bytes for AES-128 encryption, and while the encrypt-then-MAC construction mitigates classic padding oracle attacks, CBC mode remains vulnerable to implementation-level side channels. All vote ciphertext stored in the vote table uses this unapproved cipher mode.

**Remediation:**

Complete the migration indicated by the code comments. Replace Fernet with XChaCha20-Poly1305 (as the HKDF is already configured for) using a library like pynacl/nacl.secret.SecretBox, or alternatively use AES-256-GCM from the cryptography library. Update the _derive_vote_key(), create_vote(), and decrypt_votestring() functions to use the approved AEAD cipher. Update the HKDF info parameter to match the chosen cipher. Implement a re-encryption strategy for existing vote data or a version-aware decryption path to handle the migration of stored ciphertext.

---

#### FINDING-016: Complete Absence of Authenticated Data Clearing from Client Storage

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-524 |
| **ASVS Sections** | 14.3.1 |
| **Files** | `v3/server/pages.py:85-95,148,186,528` |
| **Source Reports** | 14.3.1.md |
| **Related** | FINDING-072 |

**Description:**

The application completely lacks mechanisms to clear authenticated data from client storage after session termination. Specifically: (1) No `Clear-Site-Data` HTTP header is sent on any response, (2) No logout endpoint exists to trigger session termination and cleanup, (3) No `Cache-Control` headers prevent browser caching of authenticated pages, (4) No client-side JavaScript clears DOM/storage when session ends. All 12+ authenticated routes inject voter identity (uid, name, email) and election data into HTML responses via the `basic_info()` function. Without cache-control headers, browsers cache these pages containing sensitive voter information. In a voting system context, this enables voter privacy violations through browser cache on shared computers, exposing who voted and in which elections, violating ballot secrecy principles.

**Remediation:**

1. Add logout endpoint with `Clear-Site-Data` header that invalidates server-side session and sends `Clear-Site-Data: "cache", "cookies", "storage"` header. 2. Add `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` headers to all authenticated responses via `after_request` middleware. 3. Add client-side cleanup JavaScript as fallback that clears sessionStorage on beforeunload and implements periodic session checks to clear DOM if session expires. 4. Mark sensitive DOM elements in templates with `data-sensitive` attribute for targeted cleanup.

---

#### FINDING-017: Complete Absence of SBOM, Dependency Manifest, and Remediation Timeframes for Security-Critical Dependencies

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-1395 |
| **ASVS Sections** | 15.1.1, 15.1.2, 15.2.1 |
| **Files** | `v3/server/main.py:1`&lt;br&gt;`v3/steve/crypto.py:21-24,58-94`&lt;br&gt;`v3/steve/election.py:24-25`&lt;br&gt;`v3/server/main.py:29,37-38` |
| **Source Reports** | 15.1.1.md, 15.1.2.md, 15.2.1.md |
| **Related** | None |

**Description:**

The application has no Software Bill of Materials (SBOM), no dependency version pinning, no documented update/remediation timeframes, and no formal dependency manifest. The entire vote secrecy guarantee depends on cryptographic libraries (argon2-cffi and cryptography) that have no documented remediation timeframes for vulnerabilities. The codebase uses `uv` as indicated by the shebang, but lacks the required PEP 723 inline metadata block, and no requirements.txt, pyproject.toml, or lock file exists. This creates multiple critical gaps: (1) A published CVE in cryptographic libraries could remain unpatched indefinitely with no organizational accountability, (2) Each deployment may resolve to different dependency versions including ones with known vulnerabilities, (3) Transitive dependencies are completely invisible, (4) ASVS 15.2.1 is completely unauditable as there are no documented timeframes to verify compliance against, (5) Builds are not reproducible across environments. Without documented remediation timeframes, vulnerabilities in argon2-cffi or cryptography could directly compromise vote secrecy (all encrypted votes could be decrypted), election integrity (tamper detection relies on these libraries), and key derivation security (foundation of all vote tokens).

**Remediation:**

1. Create pyproject.toml with pinned dependencies: asfquart, asfpy, cryptography>=43.0.0,&lt;44, argon2-cffi&gt;=23.1.0,&lt;24, easydict&gt;=1.13. 2. Generate and commit lock file using `uv lock` or `pip-compile --generate-hashes` for reproducible builds. 3. Generate machine-readable SBOM in CycloneDX or SPDX format using cyclonedx-py or syft: `cyclonedx-py environment -o sbom.json` or `syft dir:./v3 -o cyclonedx-json > sbom.json`. 4. Create DEPENDENCY-POLICY.md documenting: (a) Component Risk Classification (Dangerous Functionality Components: cryptography, argon2-cffi; Risky Components: asfquart, asfpy, easydict), (b) Vulnerability Remediation Timeframes (Critical 9.0+: 24h for dangerous functionality/48h for standard; High 7.0-8.9: 72h/7d; Medium 4.0-6.9: 14d/30d; Low 0.1-3.9: 30d/90d), (c) General Update Cadence (security-critical libraries: monthly review with 7-day update window; all other dependencies: quarterly review), (d) Monitoring Process (automated CVE scanning in CI/CD, CVE notification subscriptions for dangerous functionality components, quarterly manual reviews). 5. Implement automated dependency scanning using pip-audit, OSV-Scanner, or Dependabot. 6. Use hash verification in requirements.txt format for critical packages. 7. Integrate SBOM generation into CI/CD pipeline and store with each release.

---

#### FINDING-018: Tampering Detection Event Bypasses Structured Logging Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.1.1, 16.2.1, 16.2.3, 16.2.4, 16.3.3 |
| **Files** | `v3/server/bin/tally.py:153-155,119,129,133-136,140-141,145-147,151,161-162` |
| **Source Reports** | 16.1.1.md, 16.2.1.md, 16.2.3.md, 16.2.4.md, 16.3.3.md |
| **Related** | None |

**Description:**

Election tampering detection—the most critical security event in the voting system—outputs to stdout via print() instead of using the configured _LOGGER framework. The logger is imported and used elsewhere in the same file, but this critical event bypasses structured logging entirely. This means tampering alerts may not reach log aggregation systems (especially in daemon/cron/systemd deployments), have no timestamp or operator identity for forensic investigation, cannot be correlated with other security events in SIEM systems, and create false security confidence that all events are logged. In production ASGI environments where stdout may not be captured, this critical security signal could be completely lost.

**Remediation:**

Replace print() statement with _LOGGER.critical() to log tampering detection with complete ASVS 16.2.1 metadata including operator identity (using getpass.getuser()), timestamp, election ID, and database path. Example: _LOGGER.critical(f'TAMPERING_DETECTED: election[E:{election_id}] integrity check failed. Tally aborted. operator={operator} db_path={db_fname} spy_on_open={spy_on_open}'). Keep print() for CLI user feedback but ensure critical event reaches security logs.

---

#### FINDING-019: Tally Operations Create No Audit Trail With Operator Identity

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3, 16.2.2 |
| **Files** | `v3/server/bin/tally.py:136-160,102-133,88-142,76-113,116-142,120-150,85-115,138-165,98-135,145-171` |
| **Source Reports** | 16.1.1.md, 16.2.1.md, 16.3.1.md, 16.3.2.md, 16.3.3.md, 16.2.2.md, 16.2.4.md |
| **Related** | None |

**Description:**

The tally operation—which decrypts all votes and computes election results—is the most security-sensitive operation in the system but creates no meaningful security audit trail. There is no logging of who initiated the tally, when it occurred, whether --spy-on-open-elections was used (allowing premature result access), completion status, or summary of results. No forensic evidence exists of when tallying occurred or who performed it, making insider threats and unauthorized result access completely invisible. This directly contradicts domain requirements that tally operations must create audit trails and violates ASVS requirements for logging security-sensitive operations.

**Remediation:**

Add comprehensive audit logging for tally lifecycle: (1) Log tally initiation with _LOGGER.info() including operator identity (getpass.getuser()), hostname (socket.gethostname()), process ID, election ID, issue ID, spy_on_open flag, db_path, and output_format. (2) Log each issue being tallied with progress counter. (3) Log successful completion with summary statistics (issues_tallied, total_voters). (4) Log tampering check results with _LOGGER.critical() for failures and _LOGGER.info() for passes. Example: _LOGGER.info(f'TALLY_INITIATED: operator={operator} host={hostname} pid={os.getpid()} election[E:{election_id}] issue_id={issue_id} spy_on_open={spy_on_open} db_path={db_fname}')

---

#### FINDING-020: No Global Error Handler Defined - Unhandled Exceptions Expose Internal Details

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-209 |
| **ASVS Sections** | 16.5.1 |
| **Files** | `v3/server/pages.py:1`&lt;br&gt;`v3/server/main.py:38-44`&lt;br&gt;`v3/server/pages.py:95-117` |
| **Source Reports** | 16.5.1.md |
| **Related** | FINDING-021, FINDING-226 |

**Description:**

The application does not define a global error handler to catch unhandled exceptions. Any exception not explicitly caught by individual endpoint handlers will be processed by the framework's default error handling mechanism. Without an explicit global handler, if the application is deployed in debug mode (run_standalone() uses logging.basicConfig(level=logging.DEBUG)), full tracebacks with cryptographic key material (opened_key, salt), database paths, SQL query structures, and internal module names could be exposed to users. This represents a complete lack of defense-in-depth protection against information disclosure through error messages.

**Remediation:**

Register a global error handler in main.py create_app() or pages.py using @APP.errorhandler(Exception) that logs the full error server-side using _LOGGER.error() with exc_info=True, and returns a generic message to users ('An unexpected error occurred. Please try again later.'). Preserve intentional HTTP errors (404, 400, etc.) by checking isinstance(error, quart.exceptions.HTTPException). Also register an explicit @APP.errorhandler(500) handler. Additionally, add a None check for JSON body in _set_election_date before calling .get() to prevent AttributeError on malformed requests.

---

#### FINDING-021: Error Handling Pattern Not Applied to State-Changing Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔴 Critical |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-209 |
| **ASVS Sections** | 16.5.1 |
| **Files** | `v3/server/pages.py:498,520,538,563,586`&lt;br&gt;`v3/steve/election.py:75-89,122-128,190-207,209-220,222-233` |
| **Source Reports** | 16.5.1.md |
| **Related** | FINDING-020, FINDING-226 |

**Description:**

A secure error handling pattern exists in do_vote_endpoint that catches exceptions, logs details server-side, and returns generic error messages to users. However, this pattern is NOT applied to five other state-changing endpoints (do_open_endpoint, do_close_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint). These unprotected endpoints call business logic methods that use assert statements for state validation, which will raise unhandled AssertionError exceptions when violated. Stack traces could expose cryptographic parameters (opened_key, salt values), database file paths and query structures, internal election state machine design, and in debug mode: full source code context and all local variables in each stack frame.

**Remediation:**

Option A: Apply try-except pattern to each endpoint (consistent with do_vote_endpoint). Wrap all business logic calls in try-except blocks that catch Exception, log full details server-side using _LOGGER.error(), and return generic error messages to users via flash_danger(). Option B (preferred): Replace assert statements with proper validation that returns user-friendly errors. Replace 'assert self.is_editable()' with 'if not self.is_editable(): raise ElectionBadState(self.eid, self.get_state(), self.S_EDITABLE)' to produce catchable, typed exceptions that can be handled appropriately at the web layer.

---

### 3.2 High

#### FINDING-022: 🟠 Reflected XSS via URL Path Parameters in Error Templates Without Escaping

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.3.10, 1.3.5, 1.3.7, 1.3.3 |
| **Files** | `v3/server/pages.py:163-166`, `v3/server/pages.py:185-188`, `v3/server/pages.py:199-202`, `v3/server/pages.py:142-153`, `v3/server/templates/e_bad_eid.ezt:8`, `v3/server/templates/e_bad_iid.ezt:8`, `v3/server/templates/e_bad_pid.ezt:N/A` |
| **Source Reports** | 1.3.10.md, 1.3.5.md, 1.3.7.md, 1.3.3.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-028, FINDING-031, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

URL path parameters (election ID and issue ID) are extracted from the request path and passed directly to error templates without HTML entity escaping. When an invalid ID is provided, the error template renders the raw parameter value in the HTML body, enabling reflected XSS attacks through crafted URLs. An attacker can craft malicious URLs containing JavaScript payloads that execute when error pages are rendered.

**Remediation:**

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
EID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')

if not EID_PATTERN.match(eid):
    quart.abort(400, 'Invalid election ID format')
```

---

#### FINDING-023: 🟠 Election Opening Operation Lacks Atomic Transaction Control

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-362 |
| **ASVS Sections** | 2.3.3, 2.3.4, 15.4.1, 15.4.2 |
| **Files** | `v3/steve/election.py:74-89`, `v3/steve/election.py:126-140`, `v3/steve/election.py:73-84`, `v3/steve/election.py:121-139`, `v3/server/pages.py:472` |
| **Source Reports** | 2.3.3.md, 2.3.4.md, 15.4.1.md, 15.4.2.md |
| **Related** | FINDING-024, FINDING-087 |

**Description:**

The election opening operation is a critical state transition that involves multiple database modifications across two separate committed transactions. The open() method first calls add_salts(), which commits its own transaction containing per-voter salt generation, then separately executes cryptographic operations and commits the election state change. This split-transaction approach violates ASVS 2.3.3's requirement for atomic business operations. If steps after add_salts() fail, the database retains committed salts while the election remains in 'editable' state, creating an inconsistent state. Concurrent open() calls can interleave, causing cryptographic material to be overwritten. If the race window is exploited, the election's cryptographic material can be overwritten after voters have already begun casting votes. Votes encrypted with the first set of keys become permanently undecryptable, effectively destroying cast ballots.

**Remediation:**

Wrap the entire open() operation in a single transaction using IMMEDIATE mode to acquire write lock before checking state. Begin with 'BEGIN IMMEDIATE', inline the salt generation logic instead of calling add_salts() with its own transaction, perform all salt updates, gather election data, generate cryptographic keys, update election state with c_open.perform(), and finally 'COMMIT'. Add try/except blocks with explicit ROLLBACK on failure. Example: self.db.conn.execute('BEGIN IMMEDIATE'); try: md = self._all_metadata(self.S_EDITABLE); # Set mayvote salts within same transaction; self.q_all_issues.perform(self.eid); for mayvote in self.q_all_issues.fetchall(): salt = crypto.gen_salt(); self.c_salt_mayvote.perform(salt, mayvote.rowid); edata = self.gather_election_data(pdb); salt = crypto.gen_salt(); opened_key = crypto.gen_opened_key(edata, salt); self.c_open.perform(salt, opened_key, self.eid); self.db.conn.execute('COMMIT'); except Exception: self.db.conn.execute('ROLLBACK'); raise

---

#### FINDING-024: 🟠 Batch Vote Submission Lacks Transactional Atomicity

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-362 |
| **ASVS Sections** | 2.3.3, 2.3.4, 15.4.1, 15.4.2, 15.4.3 |
| **Files** | `v3/server/pages.py:376-417`, `v3/server/pages.py:403-446`, `v3/steve/election.py:201-212`, `v3/steve/election.py:258-269` |
| **Source Reports** | 2.3.3.md, 2.3.4.md, 15.4.1.md, 15.4.2.md, 15.4.3.md |
| **Related** | FINDING-023, FINDING-087 |

**Description:**

The vote submission endpoint processes multiple votes from a single user ballot submission by iterating through each vote and calling add_vote() individually. Each add_vote() call performs a single INSERT that auto-commits immediately. If any vote in the sequence fails, all previously committed votes remain in the database while subsequent votes are lost, resulting in a partial ballot submission that violates voter intent and election integrity. In a voting system, the user's ballot submission is the most critical business operation and must be atomic. When a voter submits votes for multiple issues in a single request, each vote is processed as an independent transaction in autocommit mode. If the election closes or an error occurs mid-batch, some votes may be recorded while others are lost, with no clear feedback to the voter about which votes succeeded.

**Remediation:**

Create a new add_votes() method in election.py that accepts a dictionary of {iid: votestring} and wraps all vote insertions in a single transaction with BEGIN IMMEDIATE/COMMIT/ROLLBACK. Update do_vote_endpoint() in pages.py to call this batch method instead of iterating and calling add_vote() individually. Ensure all votes are validated before beginning the transaction, and roll back the entire batch if any single vote fails. Example: election.db.conn.execute('BEGIN IMMEDIATE'); try: for iid, votestring in votes.items(): if iid not in issue_dict: raise ValueError(f'Invalid issue ID: {iid}'); election.add_vote_within_transaction(result.uid, iid, votestring); election.db.conn.execute('COMMIT'); except Exception as e: election.db.conn.execute('ROLLBACK'); await flash_danger(f'Error submitting votes: {e}'); return quart.redirect(f'/vote-on/{election.eid}', code=303). Provide clear feedback about transaction success or complete rollback.

---

#### FINDING-025: 🟠 TOCTOU Race Condition Allows Vote Insertion After Election Closure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-367 |
| **ASVS Sections** | 2.3.4, 15.4.1, 15.4.2, 15.4.3 |
| **Files** | `v3/steve/election.py:258-269`, `v3/steve/election.py:113-119`, `v3/server/pages.py:403-446`, `v3/schema.sql:179` |
| **Source Reports** | 2.3.4.md, 15.4.1.md, 15.4.2.md, 15.4.3.md |
| **Related** | FINDING-088 |

**Description:**

The vote submission pathway has a Time-of-Check-to-Time-of-Use (TOCTOU) race condition. The add_vote method checks that the election is open at line 261, but the actual vote insertion occurs after CPU-intensive cryptographic operations. During this window, the election can be closed by another request, yet the vote will still be recorded. With multi-worker deployments, the window between _all_metadata(S_OPEN) and c_add_vote.perform() is widened by the CPU-intensive gen_vote_token() and create_vote() operations (key derivation with PBKDF/Argon2). Votes can be recorded and tallied for elections that have already been officially closed. The tampered vote is cryptographically valid (uses the correct opened_key and salt), so it cannot be distinguished from a legitimate vote during tallying.

**Remediation:**

Wrap the entire check-and-write in a transaction with IMMEDIATE mode to acquire a write lock before reading state. Example: self.db.conn.execute('BEGIN IMMEDIATE'); try: md = self._all_metadata(self.S_OPEN); mayvote = self.q_get_mayvote.first_row(pid, iid); vote_token = crypto.gen_vote_token(md.opened_key, pid, iid, mayvote.salt); ciphertext = crypto.create_vote(vote_token, mayvote.salt, votestring); self.c_add_vote.perform(vote_token, ciphertext); self.db.conn.execute('COMMIT'); except Exception: self.db.conn.execute('ROLLBACK'); raise. Additionally, add a database trigger as defense-in-depth to check election state from the vote table.

---

#### FINDING-026: 🟠 No Multi-User Approval for Irreversible Election State Transitions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 2.3.5 |
| **Files** | `v3/server/pages.py:479-515`, `v3/steve/election.py:70-120` |
| **Source Reports** | 2.3.5.md |
| **Related** | - |

**Description:**

Opening and closing elections are the highest-value operations in this system. Opening an election is explicitly irreversible (generates cryptographic salt and opened_key, sets per-voter salts), and closing permanently terminates voting. Neither operation requires approval from a second authorized user. A single user (or an attacker who compromises a single committer account) can unilaterally open an election prematurely, close an election early (disenfranchising voters), or trigger tallying. The election.open() method generates cryptographic material and the state machine prevents reversal. No approval workflow exists for any election lifecycle operation. ASVS 2.3.5 specifically requires multi-user approval for high-value business logic flows to prevent unauthorized or accidental actions.

**Remediation:**

Implement a two-phase approval workflow: (1) Add approval_request table to schema tracking pending requests with requested_by, approved_by, action type, and status, with CHECK constraint ensuring requested_by != approved_by. (2) Create separate endpoints for requesting operations (e.g., /do-request-open/) and approving them (e.g., /do-approve-open/). (3) The approval endpoint must verify the approver is different from the requester and is also authorized for the election. (4) Only execute the irreversible operation after successful approval by a second authorized user.

---

#### FINDING-027: 🟠 No Throttling or Timing Enforcement on Vote Submission Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 2.4.1, 2.4.2 |
| **Files** | `v3/server/pages.py:426-470`, `v3/server/pages.py:412-460` |
| **Source Reports** | 2.4.1.md, 2.4.2.md |
| **Related** | - |

**Description:**

The vote submission endpoint has no rate limiting, timing checks, or cooldown periods. A compromised authenticated account or malicious insider can submit automated votes at machine speed with no human-interaction timing verification. This enables rapid vote-change cycling that could interfere with tallying if done during a race condition window, and generates excessive database write operations (one per issue per request), creating denial-of-service conditions on the SQLite database through write lock contention. An automated script could load the ballot and immediately POST votes for all issues, or repeatedly change votes hundreds of times per second. ASVS 2.4.2 specifically requires realistic human timing for business logic flows to prevent excessively rapid transaction submissions.

**Remediation:**

Implement per-user rate limiting on `/do-vote/<eid>` with: (1) A sliding window (e.g., 5 submissions per 60 seconds) tracked in session; (2) Minimum delay between ballot page load and submission (e.g., 3-5 seconds) by tracking ballot load timestamp in session; (3) A cooldown period (e.g., 10 seconds) between vote submissions. Add a rate_limit_votes decorator that tracks per-user timestamps, enforces VOTE_RATE_LIMIT (5 max submissions), VOTE_RATE_WINDOW (60 seconds), and VOTE_MIN_DELAY_SECS (3 seconds minimum time between page load and vote). Add timestamp tracking on ballot load in the vote_on_page function to record when the ballot was first displayed. Flash warning messages when timing requirements are not met and redirect back to the ballot page.

---

#### FINDING-028: 🟠 User-Uploaded Documents Served Without Content Interpretation Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.1 |
| **Files** | `v3/server/pages.py:593-608`, `v3/server/pages.py:28-35` |
| **Source Reports** | 3.2.1.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-031, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

The serve_doc endpoint serves user-uploaded documents directly to the browser without any content interpretation controls. Files are served with inferred MIME types and no Content-Disposition: attachment header, Content-Security-Policy: sandbox directive, or X-Content-Type-Options: nosniff protection. This allows malicious HTML/SVG files to execute JavaScript in the application's origin, enabling stored XSS attacks. An attacker can upload malicious HTML files that execute in the application's origin when viewed by authenticated users, leading to session hijacking, vote manipulation, or election state changes.

**Remediation:**

Add Content-Disposition: attachment header, Content-Security-Policy: sandbox directive, and X-Content-Type-Options: nosniff to the serve_doc endpoint. Validate docname to prevent path traversal. Use Quart's as_attachment=True parameter in send_from_directory() and add security headers to the response object before returning.

---

#### FINDING-029: 🟠 Session Cookies Lack Secure Attribute Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.3.1 |
| **Files** | `v3/server/main.py:30-44`, `v3/server/pages.py:86`, `v3/server/main.py:77-80` |
| **Source Reports** | 3.3.1.md |
| **Related** | - |

**Description:**

The application uses session-based authentication via asfquart.session but does not configure the Secure attribute for session cookies. Session cookies are created through asfquart.session.read() calls across all authenticated endpoints, but no SESSION_COOKIE_SECURE = True configuration is set. Additionally, TLS is conditionally configured only when certfile is present, meaning the application can run over plain HTTP. Without the Secure attribute, session cookies would be transmitted in cleartext over unencrypted connections, allowing attackers on the same network to intercept session cookies through network sniffing or MITM attacks and impersonate authenticated users.

**Remediation:**

Set SESSION_COOKIE_SECURE = True in the create_app() function in main.py. Additionally configure SESSION_COOKIE_HTTPONLY = True and SESSION_COOKIE_SAMESITE = 'Lax' for defense in depth. Example: app.config['SESSION_COOKIE_SECURE'] = True; app.config['SESSION_COOKIE_HTTPONLY'] = True; app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

---

#### FINDING-030: 🟠 Session Cookie Missing Explicit SameSite Attribute Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.3.2 |
| **Files** | `v3/server/main.py:33-49` |
| **Source Reports** | 3.3.2.md |
| **Related** | FINDING-007, FINDING-008, FINDING-009, FINDING-033, FINDING-034, FINDING-109 |

**Description:**

The application does not explicitly configure the SameSite attribute for session cookies. Session cookies are the sole authentication mechanism for the election voting system, yet no explicit security configuration is present in the application initialization code. Without explicit SameSite configuration, protection depends entirely on browser version and defaults. Combined with the placeholder CSRF token (acknowledged in TODO.md), the SameSite attribute is the only remaining browser-side defense against cross-site request forgery. Successful exploitation could allow an attacker to cast votes, create elections, open/close elections, or add/delete issues on behalf of an authenticated user.

**Remediation:**

Explicitly configure session cookie security attributes in the create_app() function: app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' (minimum; 'Strict' if OAuth flow allows); app.config['SESSION_COOKIE_SECURE'] = True; app.config['SESSION_COOKIE_HTTPONLY'] = True. Set SESSION_COOKIE_SAMESITE = 'Lax' as the minimum requirement. Note that SameSite=Strict would break the OAuth flow which redirects to oauth.apache.org.

---

#### FINDING-031: 🟠 Stored XSS via Election/Issue Titles Rendered Without HTML Escaping

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.2 |
| **Files** | `v3/server/templates/admin.ezt:14`, `v3/server/templates/manage.ezt:8`, `v3/server/templates/manage.ezt:187`, `v3/server/templates/manage-stv.ezt:6`, `v3/server/templates/manage-stv.ezt:137`, `v3/server/templates/vote-on.ezt:9`, `v3/server/templates/vote-on.ezt:49`, `v3/server/templates/voter.ezt:33`, `v3/server/templates/voter.ezt:67`, `v3/server/pages.py:456`, `v3/server/pages.py:518` |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-091, FINDING-113, FINDING-114 |

**Description:**

Election and issue titles are rendered without HTML escaping across multiple templates in HTML body context. While the [format "js,html"] directive IS used in onclick handlers, it is NOT applied to title rendering in HTML body contexts. This creates a Type B gap where the escaping control exists and is used in some contexts but not others, creating false confidence. Any admin can inject JavaScript via election or issue titles that executes in the browsers of all users viewing election listings or management pages.

**Remediation:**

Apply [format "html"] to ALL user-provided values in HTML body context: &lt;h2&gt;[format "html"][e_title][end]&lt;/h2&gt;, &lt;strong&gt;[format "html"][issues.title][end]&lt;/strong&gt;, &lt;h5 class="card-title"&gt;[format "html"][owned.title][end]&lt;/h5&gt;. Apply this pattern consistently across all templates: admin.ezt, manage.ezt, manage-stv.ezt, vote-on.ezt, and voter.ezt.

---

#### FINDING-032: 🟠 Missing Content-Security-Policy frame-ancestors Directive on All Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.4.6, 3.4.3 |
| **Files** | `v3/server/main.py:27-42`, `v3/server/pages.py:119-123`, `v3/server/pages.py:223-277`, `v3/server/pages.py:460-477`, `v3/server/pages.py:480-495`, `v3/server/pages.py:682-684` |
| **Source Reports** | 3.4.6.md, 3.4.3.md |
| **Related** | - |

**Description:**

The application completely lacks any Content-Security-Policy (CSP) response header implementation. No CSP header is defined, applied, or referenced anywhere in the codebase. All 10 HTML-serving endpoints return responses without any CSP protection, leaving the application vulnerable to cross-site scripting (XSS) attacks with unrestricted capabilities. Without CSP, any successful XSS injection would have unrestricted capability — loading external scripts, exfiltrating session data, or manipulating vote submissions. The rewrite_description() function already produces raw HTML (&lt;a&gt; and &lt;pre&gt; tags) from issue data without escaping, making CSP an essential defense-in-depth layer. Missing object-src 'none' allows plugin-based attacks, and missing base-uri 'none' allows &lt;base&gt; tag injection to redirect relative URLs to attacker-controlled servers.

**Remediation:**

Option A (L2 compliance): Implement global CSP via after_request hook in create_app() function with directives: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'. Option B (L3 compliance): Implement per-response nonce-based CSP by generating a unique nonce per request, storing it in quart.g, setting CSP header with nonce-{nonce}, and updating all templates to include nonce attributes. Also fix raise_404() function to ensure CSP headers are applied to custom error responses.

---

#### FINDING-033: 🟠 Vote Submission Endpoint Lacks CSRF Protection, Enabling Vote Manipulation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.1 |
| **Files** | `v3/server/pages.py:438`, `v3/server/templates/vote-on.ezt:null` |
| **Source Reports** | 3.5.1.md |
| **Related** | FINDING-007, FINDING-008, FINDING-009, FINDING-030, FINDING-034, FINDING-109 |

**Description:**

The vote submission endpoint processes votes without validating the CSRF token, despite the token being present in the form. The /do-vote/&lt;eid&gt; endpoint parses form data and calls election.add_vote() to record or overwrite votes without any origin verification. This allows attackers to cast or modify votes on behalf of authenticated users through cross-site form submissions, undermining election integrity.

**Remediation:**

Add CSRF token validation as the first operation in do_vote_endpoint() before any form processing or vote recording occurs. Call await validate_csrf_token() immediately after the result = await basic_info() line. This will ensure that votes can only be submitted from legitimate forms originating from the application itself, preventing cross-site vote manipulation attacks.

---

#### FINDING-034: 🟠 POST Endpoints Accept CORS-Safelisted Content Types Without Cross-Origin Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.5.2, 3.5.4 |
| **Files** | `v3/server/pages.py:380-423`, `v3/server/pages.py:425-446`, `v3/server/pages.py:490-514`, `v3/server/pages.py:516-538`, `v3/server/pages.py:540-558`, `v3/server/pages.py:410`, `v3/server/pages.py:457`, `v3/server/pages.py:515`, `v3/server/pages.py:538`, `v3/server/pages.py:559`, `v3/server/pages.py:93` |
| **Source Reports** | 3.5.2.md, 3.5.4.md |
| **Related** | FINDING-007, FINDING-008, FINDING-009, FINDING-030, FINDING-033, FINDING-109 |

**Description:**

All state-changing POST endpoints accept 'application/x-www-form-urlencoded' content type, which is a CORS-safelisted content type. Requests using this content type do not trigger CORS preflight checks, allowing cross-origin form submissions with credentials. No Origin header validation, Content-Type enforcement, custom header requirements, or CSRF token validation exists on any of these endpoints. An attacker can host a malicious page with HTML forms that auto-submit to these endpoints, performing unauthorized actions including vote manipulation, election creation, and issue tampering. If session cookies lack SameSite=Lax or SameSite=Strict, all state-changing operations are vulnerable to cross-origin form submission.

**Remediation:**

Implement one or more of the following cross-origin protections: (Option A) Enforce 'application/json' Content-Type to force CORS preflight for cross-origin requests; (Option B) Require a custom header (e.g., 'X-Requested-With') that forces CORS preflight; (Option C) Validate Origin header against an allowlist on all state-changing requests. Generate real CSRF tokens per session using cryptographically secure random values instead of static 'placeholder'. Create a validation decorator (require_csrf) that checks form data or headers against session token. Apply decorator to all POST endpoints. Explicitly set SameSite=Lax and Secure attributes on session cookies via app.config. Recommended approach is requiring a custom header as it is framework-agnostic and forces preflight.

---

#### FINDING-035: 🟠 Cross-Origin Resource Loading of Authenticated Documents Without Sec-Fetch-* Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.8 |
| **Files** | `v3/server/pages.py:587-603` |
| **Source Reports** | 3.5.8.md |
| **Related** | - |

**Description:**

The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serves authenticated documents (images, scripts, PDFs, and other files associated with election issues) without setting a Cross-Origin-Resource-Policy response header and without validating Sec-Fetch-* request headers. This allows a malicious cross-origin page to embed or load these authenticated resources on behalf of a logged-in user. Authenticated election documents can be loaded by cross-origin pages when the user has an active session. Attackers can confirm existence of specific documents and issues. Image content is directly rendered; document metadata leaks via timing/size. Election-sensitive material (candidate information, ballot details referenced via doc:filename in issue descriptions) exposed.

**Remediation:**

Validate Sec-Fetch-* headers to ensure same-origin navigation. Only allow same-origin or same-site requests by checking Sec-Fetch-Site header. Only allow document/image/empty destinations by validating Sec-Fetch-Dest header. Set Cross-Origin-Resource-Policy: same-origin header on all document responses. Add validation logic before sending files to reject cross-origin requests (Sec-Fetch-Site not in 'same-origin', 'same-site', 'none') and inappropriate destinations (Sec-Fetch-Dest not in 'document', 'image', 'empty', '').

---

#### FINDING-036: 🟠 State-Changing GET Endpoints Vulnerable to Cross-Origin Resource Embedding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.8 |
| **Files** | `v3/server/pages.py:462`, `v3/server/pages.py:481`, `v3/server/templates/manage.ezt:277`, `v3/server/templates/manage.ezt:285` |
| **Source Reports** | 3.5.8.md |
| **Related** | - |

**Description:**

The /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; endpoints perform irreversible state-changing operations (opening and closing elections) via GET requests. Combined with the complete absence of Sec-Fetch-* header validation, these endpoints can be triggered by a cross-origin page embedding the URL as a resource (e.g., &lt;img&gt;, &lt;link&gt;, &lt;script&gt;). This is distinct from general CSRF because the attack vector is specifically through cross-origin resource loading. An attacker can force-open elections prematurely (before proper voter rolls, issues, or dates are finalized) or force-close open elections, permanently ending voting. Both operations are explicitly irreversible. The open() operation triggers salt generation and key derivation; close() permanently marks the election closed.

**Remediation:**

Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST methods. Implement Sec-Fetch-* header validation to reject requests where Sec-Fetch-Dest is 'image'/'script'/'style', Sec-Fetch-Site is 'cross-site', or Sec-Fetch-Mode is 'no-cors'. Update the JavaScript in manage.ezt template to use fetch() with POST method instead of window.location.href for state-changing operations. Add validate_sec_fetch() middleware call to both endpoints.

---

#### FINDING-037: 🟠 No Per-Message Digital Signatures on Vote Submission

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.1.5 |
| **Files** | `v3/server/pages.py:422-469`, `v3/steve/election.py:229-240`, `v3/steve/crypto.py:67-72`, `v3/steve/crypto.py:44-54` |
| **Source Reports** | 4.1.5.md |
| **Related** | - |

**Description:**

Vote submission, the most sensitive operation in an election system, lacks per-message digital signatures. The endpoint relies solely on session cookie authentication over TLS, with no cryptographic binding between the authenticated voter identity and the vote payload at the application layer. This creates risks of intermediary tampering, lack of non-repudiation, replay attacks without detection, and no voter-verifiable receipt. The system fails ASVS 4.1.5 requirement for additional assurance beyond transport protection.

**Remediation:**

Implement client-side signing of vote payloads using Web Crypto API with Ed25519 or ECDSA. Server-side should verify per-message signatures before processing votes. Example implementation: (1) Generate/retrieve voter's key pair at enrollment, (2) Create canonical JSON vote payload, (3) Sign payload with private key, (4) Submit signed vote with signature, (5) Server verifies signature against registered public key before processing. Alternatively, implement JWS (JSON Web Signatures) for vote payloads. Add voter key registration flow, nonce/timestamp validation for replay protection, and return signed vote receipts to voters.

---

#### FINDING-038: 🟠 Document Serving Endpoint Lacks Comprehensive Filename Validation and Safe-Download Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-434 |
| **ASVS Sections** | 5.1.1, 5.2.2, 5.3.1, 5.4.1, 2.1.3 |
| **Files** | `v3/server/pages.py:576-580`, `v3/server/pages.py:594-609`, `v3/server/pages.py:428-441`, `v3/server/pages.py:602-618`, `v3/server/pages.py:47` |
| **Source Reports** | 5.1.1.md, 5.2.2.md, 5.3.1.md, 5.4.1.md, 2.1.3.md |
| **Related** | - |

**Description:**

The serve_doc() function serves arbitrary files from the DOCSDIR / iid directory without any filename validation, extension allowlisting, Content-Type enforcement, or safe-download headers. The developers explicitly acknowledged this gap with a TODO comment ('verify the propriety of DOCNAME') but never implemented the control. This is a Type B gap: the need for a security control was identified, but the control was never implemented, creating false confidence that the issue is tracked. The file is served directly via send_from_directory without validation. Multiple security issues exist: (1) No file extension whitelist - any file type present in the directory can be served, (2) No filename character validation - special characters in filenames are not filtered, (3) No Content-Disposition: attachment header - browsers will attempt inline rendering, (4) No Content-Type enforcement - files are served with their native MIME types, (5) No X-Content-Type-Options: nosniff header. If a malicious file like evil.html containing JavaScript exists in DOCSDIR/&lt;valid-iid&gt;/, it would be served with a text/html Content-Type and rendered inline, executing any embedded JavaScript in the user's browser context (stored XSS). Similarly, executable files could be distributed as malware. Files with server-executable extensions (.py, .php, .jsp) would be served as-is, and HTML/SVG files would execute in the application's origin with full access to cookies, session, and DOM.

**Remediation:**

First, create the documentation (Finding FILE_PATH-1). Then implement comprehensive validation: (1) Define ALLOWED_DOC_EXTENSIONS allowlist ({'.pdf', '.txt', '.md', '.png', '.jpg', '.jpeg', '.gif'}), (2) Validate filename format using regex (alphanumeric, hyphens, underscores, single dot for extension) - pattern: ^[a-zA-Z0-9][a-zA-Z0-9._-]*$, (3) Validate extension against allowlist, (4) Serve with explicit Content-Type from SAFE_CONTENT_TYPES mapping, (5) Add Content-Disposition: attachment header using as_attachment=True parameter, (6) Add X-Content-Type-Options: nosniff header, (7) Add Content-Security-Policy: default-src 'none' header for defense-in-depth, (8) Log all validation failures with user ID and filename, (9) Return HTTP 403 for invalid requests. For full ASVS 5.2.2 compliance, add content validation using magic byte validation with libraries like python-magic to verify file content matches its extension before accepting.

---

#### FINDING-039: 🟠 User-Controlled `iid` Used in Directory Path Construction Without Path Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Sections** | 5.3.2 |
| **Files** | `v3/server/pages.py:585-600`, `v3/server/pages.py:600`, `v3/server/pages.py:597` |
| **Source Reports** | 5.3.2.md |
| **Related** | FINDING-101 |

**Description:**

The `iid` URL parameter is directly concatenated into a filesystem directory path without explicit validation: `DOCSDIR / iid`. Quart's `send_from_directory(directory, filename)` uses Werkzeug's `safe_join` to protect the filename parameter against traversal, but the directory parameter is trusted and not validated. This means if `iid` contains `..`, the base directory escapes `DOCSDIR`. Current protection relies on an incidental database authorization check (q_get_mayvote.first_row) that returns no row for malformed IIDs, but this is not a path validation control. The developer explicitly acknowledged the gap with a TODO comment: `### verify the propriety of DOCNAME.` This represents a Type B gap where the control is acknowledged as needed but not implemented. If authorization logic changes or is bypassed, path traversal becomes directly exploitable, potentially exposing configuration files, templates, source code, or database files.

**Remediation:**

Add explicit path validation for both `iid` and `docname` before any filesystem operations: (1) Validate `iid` against a strict allowlist pattern (e.g., `^[a-zA-Z0-9_-]+$`) to match crypto-generated hex strings, (2) Validate `docname` against a strict allowlist pattern (e.g., `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`) with no path separators or `..`, (3) Add defense-in-depth using `pathlib.Path.resolve()` to verify the final path is contained within `DOCSDIR`, (4) Perform validation before any filesystem operations or database queries, (5) Return 404 for any validation failures. Example: Use SAFE_ID_PATTERN and SAFE_DOCNAME_PATTERN regex validation, resolve path and verify containment within DOCSDIR.resolve(), abort with 404 on validation failures.

---

#### FINDING-040: 🟠 No Brute-Force or Credential Stuffing Protection on Authentication Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.1 |
| **Files** | `v3/server/main.py:36-44`, `v3/server/pages.py:entire file (all @asfquart.auth.require decorated endpoints)` |
| **Source Reports** | 6.3.1.md |
| **Related** | - |

**Description:**

The application delegates credential verification to ASF OAuth (oauth.apache.org) but implements zero local controls against authentication abuse at the application boundary. Specifically: (1) No rate limiting on OAuth flow initiation - attackers can repeatedly trigger OAuth redirect flow without throttling, enabling automated credential stuffing attempts through the application as a proxy. (2) No monitoring of failed authentication callbacks when OAuth returns failures or attackers replay/forge callback attempts. (3) No documentation of brute-force mitigation strategy in security documentation. (4) No session creation throttling after OAuth callback, enabling rapid session enumeration or replay attempts. The application treats the external OAuth provider as a complete solution but implements no defense-in-depth at its own boundary, violating NIST SP 800-63B § 5.2.2 requirements for rate limiting regardless of where credential verification occurs.

**Remediation:**

Implement rate limiting middleware at the application level using quart_rate_limiter with global limits (e.g., 300 req/min per IP) and specific limits for OAuth callback endpoints (e.g., 10 attempts per minute per IP). Implement failed authentication attempt logging with monitoring: log client IP and path for all 401 responses, increment counters, and block IPs after threshold. Add session creation throttling after OAuth callback. Document brute-force prevention strategy in security documentation including responsibility delegation to OAuth provider with verification requirements.

---

#### FINDING-041: 🟠 No Session Inactivity Timeout or Absolute Maximum Session Lifetime Implemented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.1.1, 7.3.1, 7.3.2, 7.1.3, 7.6.1 |
| **Files** | `v3/server/pages.py:44-71`, `v3/server/pages.py:62-88`, `v3/server/main.py:33-46` |
| **Source Reports** | 7.1.1.md, 7.3.1.md, 7.3.2.md, 7.1.3.md, 7.6.1.md |
| **Related** | - |

**Description:**

The application reads sessions from the federated SSO provider but implements no controls to coordinate session lifetimes. The basic_info() function performs a binary check (session exists or not) with no validation of session age, expiry, or freshness. If the SSO provider issues long-lived tokens, the voting application will honor them indefinitely. No idle timeout means abandoned sessions remain valid, widening the attack window. ASVS 7.1.3 explicitly requires documentation of 'controls to coordinate session lifetimes'—none exists. There is no integration point to invalidate application-side sessions when a user's credentials are changed at the SSO provider, and no mechanism to track when the IdP authentication event occurred or enforce a maximum session lifetime aligned with IdP policy.

**Remediation:**

Implement session lifetime controls: (1) Store 'created_at', 'last_activity', and 'auth_time' timestamps in session data, (2) Validate session freshness in basic_info() against SESSION_MAX_AGE (1 hour absolute) and SESSION_IDLE_TIMEOUT (30 minutes), (3) Destroy stale sessions immediately using await asfquart.session.destroy(), (4) Update last_activity on each request. Create session management documentation covering: SSO provider identity and integration points, session lifetime policy and rationale, idle timeout configuration, termination coordination between app and SSO provider, and re-authentication conditions. Implement backchannel logout handler to process IdP-initiated session termination.

---

#### FINDING-042: 🟠 No Session Logout/Termination Endpoint Exists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 7.1.3, 7.2.4, 7.3.1, 7.4.1, 7.6.1, 10.6.2 |
| **Files** | `v3/server/pages.py:entire file` |
| **Source Reports** | 7.1.3.md, 7.2.4.md, 7.3.1.md, 7.4.1.md, 7.6.1.md, 10.6.2.md |
| **Related** | FINDING-047 |

**Description:**

The application configures itself as an OIDC/OAuth Relying Party against oauth.apache.org but implements zero logout functionality. There is no /logout endpoint, no session destruction mechanism, no front-channel logout URI, and no back-channel logout handler. This creates security gaps: (1) Users cannot terminate their sessions - once authenticated, sessions persist until natural expiry, (2) The RP cannot initiate logout with the OP - no RP-Initiated Logout per OIDC RP-Initiated Logout 1.0, (3) The RP cannot process OP-initiated logout - if oauth.apache.org implements OIDC Front-Channel or Back-Channel Logout, this RP would not honor those notifications, leaving orphaned sessions. Attack scenario: User A authenticates and votes, navigates away (no logout option exists), User B accesses the same browser and User A's session cookie is still valid, allowing User B to cast votes as User A.

**Remediation:**

1. Add RP-Initiated Logout Endpoint: Create a /logout route that reads current session to get id_token_hint if available, destroys the RP-side session using asfquart.session.clear(), and redirects to the OP logout endpoint with id_token_hint and post_logout_redirect_uri parameters. 2. Implement Back-Channel Logout Handler: Create a POST /backchannel-logout endpoint that validates the logout token (JWT signed by the OP), verifies signature, iss, aud, and events claim, and invalidates session(s) for the subject. 3. Configure Logout URL in main.py: Add OAUTH_URL_LOGOUT configuration with proper parameters. 4. Register Logout URIs with the OP: Register https://steve.apache.org/backchannel-logout as the back-channel logout URI and https://steve.apache.org/ as an allowed post-logout redirect URI. 5. Add logout link to UI on all authenticated pages to provide users with a session termination mechanism.

---

#### FINDING-043: 🟠 No Session Regeneration on Authentication or Re-authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-384 |
| **ASVS Sections** | 7.2.4 |
| **Files** | `v3/server/pages.py:78-90`, `v3/server/main.py:38-42` |
| **Source Reports** | 7.2.4.md |
| **Related** | - |

**Description:**

The application has no session regeneration logic anywhere in the codebase. Authentication is handled through OAuth configured in main.py and delegated to asfquart, but the application never explicitly regenerates or rotates session tokens upon successful authentication. Sessions are only READ, never regenerated. No calls to session.write, session.create, session.regenerate, session.new, session.rotate, session.clear, or session.destroy exist. This creates a session fixation vulnerability where an attacker could set a victim's session ID before authentication, and if the framework doesn't regenerate it, the attacker could hijack the authenticated session. ASVS requires session token regeneration on user authentication, including re-authentication, and termination of the current session token.

**Remediation:**

Add explicit session regeneration in the authentication callback. If asfquart provides a hook or post-authentication callback, use it to: (1) Terminate the old session using await asfquart.session.destroy(), (2) Create a completely new session with new token using await asfquart.session.create() with user data (uid, fullname, email), (3) Store 'auth_time' timestamp for session lifetime validation. If asfquart does not expose session regeneration APIs, this must be raised as a framework requirement.

---

#### FINDING-044: 🟠 No Re-authentication Required Before Critical Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 7.1.3, 7.2.4, 7.5.3, 7.6.1 |
| **Files** | `v3/server/pages.py:372-413`, `v3/server/pages.py:436`, `v3/server/pages.py:455`, `v3/server/pages.py:466-468`, `v3/server/pages.py:539-561`, `v3/server/pages.py:416`, `v3/server/pages.py:472`, `v3/server/pages.py:497` |
| **Source Reports** | 7.1.3.md, 7.2.4.md, 7.5.3.md, 7.6.1.md |
| **Related** | FINDING-163 |

**Description:**

The most sensitive operations in the voting system—casting votes, opening elections, closing elections, and election administration—do not require re-authentication and therefore never trigger session regeneration. A stale or compromised session can perform all critical operations without proving the user is still present. ASVS requires re-authentication with at least one factor before highly sensitive transactions and before allowing modifications to sensitive account attributes. Sessions whose IdP authentication occurred arbitrarily far in the past can still cast votes or manage elections. Combined with no session timeout enforcement and no IdP authentication event timestamp tracking, this significantly increases the window for session hijacking attacks to result in fraudulent votes or election manipulation.

**Remediation:**

Implement a re-authentication gate for critical operations: (1) Store 'auth_time' in session during IdP authentication callback, (2) Create require_recent_auth(max_age_seconds) function that validates authentication recency and redirects to re-authentication if stale, (3) Apply to critical endpoints with appropriate thresholds: vote submission (600 seconds/10 minutes), election open/close (300 seconds/5 minutes), election administration (900 seconds/15 minutes). Use OAuth prompt=login or max_age parameter to force IdP re-authentication. After successful re-authentication, regenerate the session token per ASVS 7.2.4.

---

#### FINDING-045: 🟠 No Session Termination When User Account Is Deleted or Disabled

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.4.2 |
| **Files** | `v3/steve/persondb.py:51-61`, `v3/server/pages.py:78-92`, `v3/steve/persondb.py:28-73` |
| **Source Reports** | 7.4.2.md |
| **Related** | - |

**Description:**

When user accounts are deleted via PersonDB.delete_person(), no mechanism exists to terminate active sessions. The delete_person() method removes the user record from the person table but does not consult or modify any session store. Deleted users' active sessions remain valid, allowing them to continue accessing the application on subsequent requests until their session naturally expires. The basic_info() function reads uid from the session without verifying the user still exists. There is no disable_person() or deactivate_person() method, no is_active field in the person schema, and no mechanism to temporarily revoke access. ASVS 7.4.2 requires the application to terminate all active sessions when a user account is disabled or deleted. This affects all 16+ authenticated endpoints including vote casting and election management.

**Remediation:**

1. Add an is_active field to the person schema (ALTER TABLE person ADD COLUMN is_active INTEGER DEFAULT 1). 2. Implement disable_person(pid) method that sets is_active = 0 and calls session_manager.revoke_all_sessions_for_user(pid). 3. Modify delete_person() to accept session_manager parameter and call session_manager.revoke_all_sessions_for_user(pid) after successful deletion. 4. Implement SessionManager class with revoke_all_sessions_for_user() method. 5. Modify basic_info() to verify user still exists and is active by calling pdb.get_person(s['uid']) and checking is_active flag, destroying session immediately if user not found or disabled.

---

#### FINDING-046: 🟠 No Mechanism to Terminate Sessions After Authentication Factor Changes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.4.3 |
| **Files** | `v3/server/pages.py:63-76`, `v3/server/pages.py:506-520`, `v3/server/pages.py:514-520` |
| **Source Reports** | 7.4.3.md |
| **Related** | - |

**Description:**

The application provides no functionality to terminate all other active sessions after a change or removal of any authentication factor. Since authentication is delegated to an external SSO provider (ASF OAuth), but the application maintains its own independent sessions via asfquart.session, there is no integration point to invalidate application-side sessions when a user's credentials are changed at the SSO provider. Users cannot view their active sessions or terminate them. There is no 'Terminate All Sessions' endpoint, no session management UI, and no backchannel logout handler. ASVS 7.4.3 requires the application to give users the option to terminate all other active sessions after successful authentication factor changes. This creates a gap where compromised sessions persist even after a user changes their credentials at the SSO provider.

**Remediation:**

1. Implement a 'Terminate All Sessions' endpoint that allows users to invalidate all other active sessions except the current one. 2. Integrate with SSO backchannel logout (if supported) to handle SSO provider notifications of credential changes. 3. Add session management UI to the /settings page to display active sessions (with device info, IP, last activity) and allow users to terminate them. 4. Extend session store to support bulk operations including terminate_all_for_user() and list_for_user() methods. 5. Implement comprehensive session lifecycle management including timeout, renewal, and monitoring capabilities.

---

#### FINDING-047: 🟠 No Administrator Capability to Terminate User Sessions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 7.4.5 |
| **Files** | `v3/server/pages.py:all routes`, `v3/schema.sql:all tables`, `v3/queries.yaml:all queries` |
| **Source Reports** | 7.4.5.md |
| **Related** | FINDING-042 |

**Description:**

The application provides no mechanism for administrators to terminate active sessions, either for an individual user or for all users. Session management is entirely delegated to the external asfquart framework with no application-level override capability. No session table exists in the database that would allow server-side session invalidation. When an administrator detects a compromised account, there is no mechanism to view active sessions, terminate a specific user session, terminate all sessions, or access any CLI tools for session management. ASVS 7.4.5 requires that application administrators are able to terminate active sessions for an individual user or for all users. In a voting system, compromised sessions could continue casting fraudulent votes during an active compromise.

**Remediation:**

1. Add session storage table in v3/schema.sql with fields: session_id (PK), pid (FK to person), created_at, last_activity, expires_at, is_active, ip_address, user_agent. 2. Add session management queries in v3/queries.yaml: q_active_sessions, q_user_sessions, c_terminate_user_sessions, c_terminate_session, c_terminate_all_sessions. 3. Add admin session management endpoints: GET /admin/sessions (list all), POST /admin/sessions/terminate/&lt;pid&gt; (terminate user sessions), POST /admin/sessions/terminate-all (emergency), POST /admin/sessions/terminate-session/&lt;session_id&gt; (specific). 4. Implement session validation middleware using @APP.before_request that checks session is_active status. 5. Create admin template displaying active sessions with termination actions. 6. Add comprehensive audit logging for all session termination actions. 7. Define dedicated R.admin role for session management operations.

---

#### FINDING-048: 🟠 Complete Absence of Active Session Viewing and Termination Capability for Users

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.5.2 |
| **Files** | `v3/server/pages.py:537-549`, `v3/server/pages.py:68-78` |
| **Source Reports** | 7.5.2.md |
| **Related** | - |

**Description:**

Users cannot view their active sessions or terminate them. The application defines two user-facing account pages (/profile and /settings) but neither provides session management functionality. Users cannot see a list of their currently active sessions, including device information, IP addresses, last activity times, or creation timestamps. A full text search reveals no endpoint for terminating sessions—no capability to terminate a specific session by ID, terminate all sessions except the current one, or log out from the current session. ASVS 7.5.2 requires users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. If a user's session token is stolen, they have no mechanism to discover the compromised session exists or revoke it.

**Remediation:**

1. Add a session listing endpoint /sessions that shows all active sessions for the authenticated user with metadata: session_id, created_at, last_active, ip_address, user_agent, is_current. 2. Implement session termination endpoints: POST /sessions/terminate/&lt;session_id&gt; (specific session), POST /sessions/terminate-all (all except current). 3. Implement re-authentication flow: create verify_reauthentication() function that verifies password or checks recent authentication (within 5 minutes), create require_recent_auth() decorator, apply to all session management endpoints. 4. Implement server-side session store that tracks sessions per user. 5. Add session management UI to /settings page with list and termination controls.

---

#### FINDING-049: 🟠 Missing Explicit Voter Eligibility Check on Vote Submission Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-862 |
| **ASVS Sections** | 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.2, 8.3.3, 8.4.1 |
| **Files** | `v3/server/pages.py:285-307`, `v3/server/pages.py:257`, `v3/server/pages.py:376`, `v3/server/pages.py:308`, `v3/server/pages.py:324`, `v3/server/pages.py:389-419`, `v3/server/pages.py:390-427`, `v3/steve/election.py:201-207`, `v3/steve/election.py:229`, `v3/steve/election.py:254-268` |
| **Source Reports** | 8.1.1.md, 8.1.2.md, 8.1.4.md, 8.2.2.md, 8.3.2.md, 8.3.3.md, 8.4.1.md |
| **Related** | FINDING-006 |

**Description:**

The vote viewing page (vote_on_page) correctly checks voter eligibility using q_find_issues before rendering the ballot. However, the vote submission endpoint (do_vote_endpoint) does not perform this explicit check before processing votes. Instead, it relies on an implicit exception when add_vote() attempts to access .salt on a None mayvote record, which is caught by a generic exception handler and returns a vague error message. While the vote ultimately fails, the failure mode is an unhandled exception rather than a proper authorization denial. The generic error handler could mask real errors. An attacker can probe which issues exist in which elections by observing error vs. success responses, potentially leaking information about election structure. Authorization failure is masked as a generic error with no audit trail for unauthorized vote attempts, violating defense-in-depth principles.

**Remediation:**

Add explicit voter eligibility check in do_vote_endpoint before processing any votes. Verify the user has mayvote entries for the election using q_find_issues. Check each submitted issue ID against the eligible_issues set. Return proper 403 Forbidden responses with clear error messages for ineligible voters instead of relying on exception handling. Add explicit None check in add_vote() method with a descriptive VoterNotEligible exception. Include security logging for all unauthorized vote attempts with user ID, election ID, and attempted issue ID.

---

#### FINDING-050: 🟠 authz Field Defined in Schema and Documented but Never Evaluated in Access Control Decisions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-285 |
| **ASVS Sections** | 8.1.2, 8.1.3 |
| **Files** | `v3/schema.sql:52`, `v3/docs/schema.md:N/A`, `v3/steve/election.py:143`, `v3/server/pages.py:N/A` |
| **Source Reports** | 8.1.2.md, 8.1.3.md |
| **Related** | - |

**Description:**

The database schema defines an authz field for group-based election editing permissions, and the schema documentation explicitly describes its access control purpose ('allowed to edit'). However, this field is only retrieved for display purposes in templates and is never evaluated in any authorization decision. The schema documentation describes authz as an access control mechanism, creating false confidence in security architecture. Authorization rules for group-based editing are documented in schema but completely absent from implementation. This is a Type B gap where the control is DEFINED in documentation and schema but NOT CALLED in any endpoint.

**Remediation:**

Create an authorization policy document and implement authz group checks in the load_election decorator (see AUTHZ-001 remediation). Integrate with ASF LDAP infrastructure to evaluate group membership against the authz field value. The check should verify: if md.owner_pid matches the authenticated user's UID, authorize; else if md.authz is set, check if the user is a member of that LDAP group; else deny access with 403 Forbidden.

---

#### FINDING-051: 🟠 Per-Issue Voter Eligibility Not Enforced — Issue Properties Exposed Without Field-Level Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.3 |
| **Files** | `v3/server/pages.py:225-272`, `v3/server/pages.py:236-241`, `v3/server/pages.py:247`, `v3/steve/election.py:183-191`, `v3/steve/election.py:196-207` |
| **Source Reports** | 8.2.3.md |
| **Related** | FINDING-010, FINDING-053, FINDING-153 |

**Description:**

The application performs only election-level eligibility checks before displaying all issues to voters, exposing properties (titles, descriptions, candidate lists) of issues the user is not authorized to vote on. Vote submission relies on an implicit AttributeError when accessing mayvote.salt on None rather than explicit authorization validation. Properties of issues the user is not eligible to vote on (titles, descriptions, candidate lists, seat counts) are exposed on the voting page - this is a direct BOPLA violation per ASVS 8.2.3. Vote submission for non-eligible issues fails via an unhandled exception rather than a proper authorization denial, potentially leaking error details. If per-issue eligibility is used (e.g., PMC-specific votes within a broader election), this exposes confidential ballot information to ineligible voters.

**Remediation:**

Filter issues by user eligibility in vote_on_page: query q_find_issues to get eligible issue IDs, then filter the issue list to only include eligible issues before rendering. Add explicit checks in do_vote_endpoint: verify each submitted issue ID is in the eligible set before processing. In election.py add_vote, add explicit authorization check with proper VoterNotEligible exception instead of relying on AttributeError. This ensures field-level access control is enforced based on the mayvote relationship.

---

#### FINDING-052: No Sender-Constrained Access Token Implementation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-294 |
| ASVS Sections | 10.3.5, 10.4.14 |
| Files | `v3/server/main.py:37-41`, `v3/server/pages.py:multiple (all 21 protected endpoints)`, `v3/server/main.py:77-80`, `v3/server/main.py:82-84` |
| Source Reports | 10.3.5.md, 10.4.14.md |
| Related | - |

**Description:**

The application implements OAuth 2.0 authentication through Apache's OAuth infrastructure but provides no mechanism to bind access tokens to the presenting client. Neither Mutual TLS (RFC 8705) nor Demonstration of Proof-of-Possession (DPoP, RFC 9449) is implemented. This allows stolen access tokens or session tokens to be replayed from any network location by any attacker who obtains them. The OAuth configuration shows a plain OAuth 2.0 authorization code flow, and all resource server endpoints validate sessions/tokens without any proof-of-possession verification. This leaves the system vulnerable to stolen access token replay attacks, particularly critical for a voting system where vote integrity is essential.

**Remediation:**

Implement DPoP (RFC 9449) as the primary sender-constraining mechanism:

1. Coordinate with asfquart framework maintainers to add DPoP support for OAuth token exchange
2. Implement DPoP proof validation middleware that validates DPoP proof JWT, verifies htm/htu claims match request method/URL, validates ath claim matches access token hash, and verifies JWK thumbprint matches token's cnf.jkt claim
3. Configure token introspection to verify cnf claims when validating access tokens
4. Update all 21 protected endpoints to require DPoP proof validation before processing requests
5. Test thoroughly with legitimate clients

Alternatively, implement Mutual TLS (RFC 8705) with certificate thumbprint binding, though this requires infrastructure-level changes including reverse proxy configuration and certificate management.

Interim compensating controls: reduce token lifetime, implement IP address binding for sessions, enhance monitoring for suspicious token usage patterns, implement rate limiting on authentication endpoints, and require multi-factor authentication for high-value operations.

---

#### FINDING-053: Authorization Code Grant Without Pushed Authorization Requests (PAR)

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-639 |
| ASVS Sections | 10.4.13, 10.4.15 |
| Files | `v3/server/main.py:37-42`, `v3/server/main.py:38-42` |
| Source Reports | 10.4.13.md, 10.4.15.md |
| Related | FINDING-010, FINDING-051, FINDING-153 |

**Description:**

The application uses the OAuth authorization code grant type but constructs authorization requests using the traditional approach of passing parameters directly in URL query strings. This violates ASVS 10.4.13 Level 3 requirement that the authorization code grant type must always be used together with Pushed Authorization Requests (PAR). Per RFC 9126, the correct PAR-based flow requires: (1) Client POSTs authorization parameters to the AS's PAR endpoint, (2) AS validates parameters server-side and returns a request_uri, (3) Client redirects user with only request_uri and client_id. The current implementation bypasses this security mechanism entirely, exposing authorization parameters through browser history, server logs, referrer headers, and allowing authorization request tampering without server-side pre-validation.

**Remediation:**

1. Verify AS PAR Support: Coordinate with oauth.apache.org operators to confirm PAR endpoint availability and configuration. 2. Update Framework: Modify asfquart framework to implement PAR flow by adding OAUTH_PAR_ENDPOINT configuration and updating OAUTH_URL_INIT to only use client_id and request_uri. 3. Implement PAR Flow: Add PAR request handling that POSTs authorization parameters to PAR endpoint server-to-server, receives request_uri from AS, stores request_uri with expiration for validation, and redirects user with only client_id and request_uri. 4. Enforce PAR at AS: Request AS configuration update to set require_pushed_authorization_requests: true for the client. 5. Implement PKCE alongside PAR for defense-in-depth. 6. Use private_key_jwt or tls_client_auth for client authentication instead of client_secret_basic. 7. Set short expiration times for request_uri (recommended: 60 seconds). 8. Implement request_uri validation in callback handler. 9. Add monitoring for non-PAR authorization attempts.

---

#### FINDING-054: OAuth Client Authentication Lacks Public-Key-Based Methods (mTLS / private_key_jwt)

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 10.4.16 |
| Files | `v3/server/main.py:38-43` |
| Source Reports | 10.4.16.md |
| Related | - |

**Description:**

ASVS 10.4.16 requires that the OAuth client uses strong, public-key-based client authentication methods (mutual TLS or `private_key_jwt`) that are resistant to replay attacks. The application shows no evidence of configuring or using any public-key-based client authentication method for the token endpoint exchange. The token endpoint URL template formats only the authorization code with no client certificate (mTLS) configuration, no client_assertion/client_assertion_type (private_key_jwt), and no configuration for token_endpoint_auth_method. Without public-key-based client authentication, the client likely authenticates using symmetric shared secrets or no client authentication at all, making it vulnerable to credential theft and replay attacks.

**Remediation:**

Configure the OAuth client to use one of the following methods:

Option A: Mutual TLS (tls_client_auth):
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

Option B: Private Key JWT (private_key_jwt):
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

---

#### FINDING-055: No ID Token Handling - Custom OAuth Bypasses OIDC

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 10.5.2 |
| Files | `v3/server/main.py:38-43` |
| Source Reports | 10.5.2.md |
| Related | - |

**Description:**

The application explicitly configures custom OAuth endpoints and comments '# Avoid OIDC'. This means no ID Token is issued or consumed, and the 'sub' claim (which OIDC guarantees to be a locally unique, never-reassigned identifier) is not used. Without OIDC ID Token processing, critical validations are absent: cryptographic signature verification of identity assertions, 'iss' (issuer) validation, 'aud' (audience) validation ensuring the token was intended for this client, 'exp'/'iat' temporal validity checks on the identity assertion, and 'nonce' validation for replay protection. The user identity used for all authorization decisions (voting eligibility, election management, audit logging) is obtained through a custom OAuth flow without the security guarantees that OIDC ID Token validation provides.

**Remediation:**

Migrate from the custom OAuth flow to standard OIDC, consuming and validating the ID Token. Configure OIDC with proper ID Token validation using OIDC discovery endpoint for automatic key/endpoint configuration. In session establishment, use 'sub' claim as the unique, non-reassignable user identifier (NOT email, NOT preferred_username). Verify issuer matches expected OP and verify audience includes this client. Example: session['uid'] = id_token_claims['sub'] where sub claim is guaranteed non-reassignable per issuer.

---

#### FINDING-056: No Visible ID Token Audience (aud) Claim Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 10.5.4 |
| Files | `v3/server/main.py:35-48`, `v3/server/pages.py:79` |
| Source Reports | 10.5.4.md |
| Related | - |

**Description:**

The application explicitly overrides OIDC behavior and implements custom OAuth URL configuration without any visible ID Token audience (aud) claim validation. The code contains a deliberate comment 'Avoid OIDC' and manually configures OAuth endpoints, bypassing standard OIDC token validation mechanisms. No client_id is configured or referenced anywhere in the application code, and no aud validation logic exists. This allows potential token confusion attacks where an attacker with a token intended for another Apache service could gain authenticated access to the election system.

**Remediation:**

1. Remove the 'Avoid OIDC' override and use proper OIDC endpoints with full ID Token validation. 2. Configure a client_id in the application (e.g., 'steve-voting-app'). 3. Implement validation that the ID Token's 'aud' claim matches the configured client_id before accepting the token. 4. If using the asfquart framework, audit its token handling code to verify aud validation is performed, or add middleware to validate token audience before session creation. 5. Add integration tests that verify tokens with incorrect aud values are rejected.

---

#### FINDING-057: Complete Absence of Cipher Suite Configuration in Standalone TLS Server

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-326 |
| ASVS Sections | 12.1.2, 12.3.1, 12.3.3, 12.3.4 |
| Files | `v3/server/main.py:79-84`, `v3/server/main.py:83-89`, `v3/server/main.py:98-104` |
| Source Reports | 12.1.2.md, 12.3.1.md, 12.3.3.md, 12.3.4.md |
| Related | - |

**Description:**

The server passes raw certificate/key file paths to the underlying Quart/Hypercorn runtime without creating an ssl.SSLContext. This results in: (1) No cipher suite restriction - all system-default ciphers are enabled, including potentially weak ones (RC4, 3DES, NULL, EXPORT, CBC-mode ciphers vulnerable to BEAST/Lucky13); (2) No cipher preference order - server does not enforce strongest-first ordering (ssl.OP_CIPHER_SERVER_PREFERENCE is not set); (3) No forward secrecy enforcement - non-ECDHE/DHE cipher suites remain available; (4) No TLS version pinning - TLS 1.0 and 1.1 may be negotiated, which support weaker cipher suites. Weak cipher suites allow passive decryption by an attacker who compromises the server's private key (no forward secrecy). Certain legacy ciphers have known cryptographic weaknesses exploitable by active or passive attackers. This fails ASVS 12.1.2 L2 (recommended ciphers only) and L3 (forward secrecy requirement). Without an SSL context, there is no mechanism to enforce trust policy or protocol security on internal connections.

**Remediation:**

Create a properly configured SSLContext with restricted cipher suites, TLS 1.2+ minimum version, and server cipher preference enabled. Use cipher suite string 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'. Set ssl.OP_CIPHER_SERVER_PREFERENCE and ssl.OP_NO_COMPRESSION options. Load certificate chain using ctx.load_cert_chain() and pass the SSLContext object to app.runx() via ssl parameter instead of raw certfile/keyfile paths. Set minimum TLS version to 1.2, maximum to 1.3. Configure strong cipher suites only. For mutual TLS with reverse proxy, set ssl_context.verify_mode = ssl.CERT_REQUIRED and load CA certificates with ssl_context.load_verify_locations().

---

#### FINDING-058: Missing OCSP Stapling Configuration in Server TLS Setup

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 12.1.4 |
| Files | `v3/server/main.py:93-100` |
| Source Reports | 12.1.4.md |
| Related | - |

**Description:**

The TLS setup passes only certfile and keyfile paths directly to app.runx() without creating a custom ssl.SSLContext. This means: (1) No OCSP Stapling callback is registered, so the server cannot provide stapled OCSP responses to connecting clients. Clients must independently query the CA's OCSP responder, which introduces latency and privacy leakage, or (more critically) many clients will skip revocation checking entirely. (2) No control over revocation behavior — if the application's own certificate is revoked by the CA, clients relying on default behavior may not detect this. (3) No SSL context parameters are set — protocol version minimums, cipher suites, and certificate verification modes all rely on framework defaults which are not auditable from this code. If the server's TLS certificate is compromised and subsequently revoked by the CA, clients connecting to the server will have no reliable mechanism to learn of the revocation. The revoked certificate would continue to be accepted by clients, maintaining a false sense of trust.

**Remediation:**

Create an explicit ssl.SSLContext with OCSP Stapling support and pass it to the server. Example implementation: import ssl and create _create_ssl_context() function that creates ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), sets minimum_version to TLSv1_2, loads cert chain, sets OCSP server callback with ctx.set_ocsp_server_callback(), and hardens cipher selection. For production deployments, OCSP Stapling is most effectively handled by a reverse proxy (e.g., Nginx with ssl_stapling on; ssl_stapling_verify on;). This should be documented as a deployment requirement.

---

#### FINDING-059: Encrypted Client Hello (ECH) Not Implemented

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 12.1.5 |
| Files | `v3/server/main.py:82-88`, `v3/server/config.yaml.example:28-31` |
| Source Reports | 12.1.5.md |
| Related | - |

**Description:**

The TLS setup passes raw file paths for certificate and key to app.runx(). There is no ECH key pair generated or referenced, no ech_config parameter in TLS settings, no ssl.SSLContext created where ECH could be enabled, no DNS HTTPS record guidance or ECHConfig publication mechanism, and no ECH retry configuration for client compatibility. Without ECH, the Server Name Indication (SNI) field is transmitted in plaintext during the TLS ClientHello, allowing network observers to identify which specific server/election the client is connecting to. For a voting system, this metadata leakage can reveal voter participation patterns. The lack of an SSL context is the foundational gap that prevents ECH implementation and all other TLS hardening.

**Remediation:**

ECH requires server-side support in the TLS library and DNS publication. Immediate approach: Deploy behind a TLS-terminating reverse proxy (e.g., Cloudflare or nginx compiled with OpenSSL 3.2+) that supports ECH, and publish ECHConfig via DNS HTTPS resource records. For application-level implementation: 1) Add ECH configuration fields to config.yaml (ech_keyfile, ech_config_list), 2) Create SSL context with TLS 1.3 minimum version, 3) Configure ECH keys when supported by ssl module/OpenSSL 3.2+, 4) Publish ECHConfig via DNS HTTPS records. Create an explicit ssl.SSLContext object: import ssl; create ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); set ctx.minimum_version = ssl.TLSVersion.TLSv1_3; configure cipher suites with ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20'); load certificate chain with ctx.load_cert_chain(certfile, keyfile); pass the context to app.runx() via ssl parameter instead of raw certfile/keyfile paths.

---

#### FINDING-060: No SSL Context Configuration Prevents mTLS Client Certificate Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 12.1.3, 12.3.4, 12.3.5 |
| Files | `v3/server/main.py:83-90`, `v3/server/main.py:79-87`, `v3/server/config.yaml.example:28-30`, `v3/server/config.yaml.example:28-31` |
| Source Reports | 12.1.3.md, 12.3.4.md, 12.3.5.md |
| Related | - |

**Description:**

The TLS configuration passes raw `certfile` and `keyfile` paths directly to `app.runx()` without constructing an `ssl.SSLContext`. This has several consequences directly relevant to ASVS 12.1.3 and 12.3.4: (1) No client certificate verification - there is no `ssl.SSLContext.verify_mode = ssl.CERT_REQUIRED` and no trusted CA (`ca_certs`) configured, so client certificates are never requested or validated. (2) No configuration surface for mTLS - the `config.yaml` schema has no fields for CA certificates, certificate verification mode, or CRL/OCSP configuration. (3) No TLS version floor - without an explicit context, the server may accept TLS 1.0/1.1 depending on the underlying framework defaults. (4) No cipher restrictions - default ciphers are used, which may include weak suites. The application uses OAuth for authentication rather than mTLS, meaning there is no mechanism to require, verify, or validate client certificates. For a voting/election system handling authenticated ballot submission, the inability to layer mTLS as a defense-in-depth authentication mechanism is a notable gap. Without mTLS, any process that can reach the backend port can impersonate a legitimate proxy, and service identity is not cryptographically verified on either inbound or outbound connections.

**Remediation:**

Create an explicit `ssl.SSLContext` with proper configuration and provide mTLS configuration options. Step 1: Update configuration schema in `config.yaml` to add mTLS configuration fields (ca_certs, verify_client) and TLS hardening options (tls_min_version, ciphers). Step 2: Implement SSL context creation function `_create_ssl_context()` in `main.py` that: (a) Creates ssl.SSLContext with PROTOCOL_TLS_SERVER, (b) Enforces minimum TLS version 1.2, (c) Loads server certificate chain, (d) Configures strong cipher suites, (e) If verify_client is enabled, loads CA certificates and sets verify_mode to ssl.CERT_REQUIRED to validate client certificates before use. Step 3: Modify `run_standalone()` to use the SSL context instead of passing raw certfile/keyfile paths. Add configuration options: server: ca_certs: ca-chain.pem, verify_client: true. Code example: if getattr(app.cfg.server, 'ca_certs', None): ssl_context.verify_mode = ssl.CERT_REQUIRED; ssl_context.load_verify_locations(cafile=CERTS_DIR / app.cfg.server.ca_certs).

---

#### FINDING-061: TLS Not Enforced and No Certificate Trust Validation for External Services

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Sections | 12.2.2 |
| Files | `v3/server/main.py:87-91`, `v3/server/config.yaml.example:31-33`, `v3/server/main.py:97-117` |
| Source Reports | 12.2.2.md |
| Related | - |

**Description:**

The TLS control exists (certificate paths can be configured) but is never enforced. The conditional check `if app.cfg.server.certfile:` means TLS is silently skipped when the configuration field is empty, allowing the voting application to serve all external endpoints—including authentication, vote submission, and election management—over plain HTTP. Additionally, when TLS is enabled, no validation occurs to ensure the provided certificate is publicly trusted, and no TLS protocol version or cipher suite restrictions are applied. The only configuration template provided references mkcert-generated development certificates that are not publicly trusted. In ASGI mode, TLS configuration is entirely absent from the application. This violates ASVS 12.2.2 requirement that external facing services use publicly trusted TLS certificates.

**Remediation:**

1. Enforce TLS as mandatory by validating that certfile and keyfile are configured before server startup, exit with critical error if missing. 2. Validate certificate files exist at specified paths. 3. Implement ssl.SSLContext with minimum TLS version 1.2 enforcement using ssl.TLSVersion.TLSv1_2. 4. Update config.yaml.example to reference publicly trusted certificates (e.g., Let's Encrypt) instead of mkcert development certificates. 5. Add warnings against using self-signed or development certificates in production. 6. For ASGI mode, document TLS requirements and add validation checks. 7. If proxy architecture is intended, add explicit configuration flag (e.g., behind_proxy: true) and document deployment requirements.

---

#### FINDING-062: Absence of Formal Cryptographic Inventory and Post-Quantum Migration Plan

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 11.1.1, 11.1.2, 11.1.3, 11.1.4 |
| Files | `v3/steve/crypto.py:entire file`, `v3/steve/election.py:entire file`, `v3/schema.sql`, `All files in codebase:N/A` |
| Source Reports | 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.1.4.md |
| Related | - |

**Description:**

The codebase uses six distinct cryptographic primitives (BLAKE2b, Argon2d, HKDF-SHA256, Fernet/AES-128-CBC, HMAC-SHA256, CSPRNG) across multiple files, but no formal cryptographic inventory document exists that catalogs these primitives, their configuration parameters, approved usage contexts, key lifecycle management, or deprecation timelines. ASVS 11.1.1, 11.1.2, 11.1.3, and 11.1.4 explicitly require: (a) a documented policy for management of cryptographic keys and lifecycle, (b) a maintained cryptographic inventory that includes all keys, algorithms, and certificates, (c) cryptographic discovery mechanisms to identify all instances of cryptography, and (d) a documented plan outlining migration to new standards including post-quantum cryptography. Evidence of awareness exists in code comments (e.g., 'still using Fernet now, but will switch soon') but this constitutes a Type B gap: awareness EXISTS but is NOT FORMALIZED. Without a cryptographic inventory, the system cannot systematically respond to algorithm deprecations, PQC migration requirements, compliance audits, incident response, or developer onboarding. The absence of inventory has allowed inconsistencies to persist including: no algorithm registry, no key boundary documentation (where keys can/cannot be used), no data protection mapping (what data can/cannot be protected), no key lifecycle documentation, and algorithm variant mismatches. For an election system protecting ballot secrecy, this represents a significant governance gap that could delay response to cryptographic threats.

**Remediation:**

Create a formal CRYPTO_INVENTORY.md document at the repository root that includes: (1) Complete algorithm catalog with ID, library, version, key size, purpose, status, PQC risk, and justification for each primitive (BLAKE2b, Argon2, HKDF, Fernet, HMAC, CSPRNG); (2) Keys and their boundaries documenting derivation, what data can/cannot be protected, storage locations, and authorized accessors; (3) Usage contexts mapping algorithms to specific code locations and functions; (4) Key lifecycle policies covering generation, storage, access, rotation, and destruction procedures including maximum key lifetime per election state, key destruction procedures post-tallying, and compromise response procedures; (5) Post-quantum cryptography migration plan with risk assessment, timeline (Q2 2026 - complete inventory; Q3 2026 - migrate Argon2d to Argon2id; Q4 2026 - migrate Fernet to XChaCha20-Poly1305; Q1 2027 - implement algorithm versioning; Q2 2027 - evaluate NIST PQC standards (ML-KEM-768, ML-DSA-65); Q4 2027 - proof-of-concept hybrid classical+PQC KDF; 2028+ - production PQC deployment), and breaking change management; (6) Parameter justification for all cryptographic configurations; (7) Compliance mapping to relevant standards (NIST SP 800-57, RFC 9106, ASVS); (8) Review history and scheduled review cadence. Establish quarterly inventory reviews with documented sign-off, annual PQC threat assessments, and immediate reviews upon algorithm deprecation announcements. Implement automated crypto scanning in CI/CD to detect crypto imports outside crypto.py and verify inventory matches actual usage. Add decorator-based crypto registration system to track operations at runtime with a CRYPTO_REGISTRY dictionary. Implement key destruction after tally completion: add archive_and_destroy_keys() method that verifies tally has been exported/signed, destroys election-level keys (SET salt=NULL, opened_key=NULL), and destroys per-voter salts (SET mayvote.salt=NULL). Add key creation timestamp columns to schema: keys_created_at and keys_destroyed_at. Implement schema versioning to enable future cryptographic migrations without breaking changes. Add automated tests to validate that the inventory document matches the actual code implementation.

---

#### FINDING-063: Absence of Cryptographic Abstraction Layer Prevents Algorithm Agility

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 11.2.2 |
| Files | `v3/steve/crypto.py:62`, `v3/steve/crypto.py:69`, `v3/steve/crypto.py:53`, `v3/steve/crypto.py:77`, `v3/steve/crypto.py:38` |
| Source Reports | 11.2.2.md |
| Related | - |

**Description:**

All cryptographic algorithms are directly instantiated without any abstraction, configuration, or strategy pattern. The application lacks a cryptographic provider layer that would enable algorithm substitution without code changes. All algorithms including Fernet (AES-128-CBC+HMAC), HKDF-SHA256, Argon2, and BLAKE2b are hardcoded directly in crypto.py without any mechanism to reconfigure, upgrade, or swap them. This makes swapping algorithms require code modifications, prevents configuration-driven algorithm selection, and blocks migration to post-quantum cryptography without a complete rewrite.

**Remediation:**

Introduce a crypto provider abstraction with configuration-driven algorithm selection. Implement a CryptoProvider class with algorithm registry (ENCRYPTION_REGISTRY) that maps algorithm names to implementation classes. Create a CryptoConfig dataclass to load algorithm choices from YAML configuration. Implement version-aware encryption/decryption methods that can handle multiple algorithm implementations. Add methods like _extract_version() and _get_encryptor_for_version() to support backward compatibility during migrations. This enables algorithm substitution without code changes and provides a path for post-quantum cryptography adoption.

---

#### FINDING-064: Unbounded Database Connection Creation Without Pooling, Limits, or Documented Recovery

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 13.1.2, 13.2.6 |
| Files | `v3/steve/election.py:42-48`, `v3/server/config.yaml.example` |
| Source Reports | 13.1.2.md, 13.2.6.md |
| Related | - |

**Description:**

The Election class opens a new, independent SQLite database connection for every operation via open_database(). There is no connection pool, no maximum connection limit, no timeout configuration, and no documented behavior for when the database becomes unavailable or connections are exhausted. Class-level methods each independently open new connections, meaning concurrent API requests create unbounded parallel connections. Under concurrent load, each inbound request opens at least one new SQLite connection. SQLite uses file-level locking; under write contention, connections queue on the lock with no configured timeout. Concurrent read-heavy operations (listing elections) exhaust file descriptors. No fallback or circuit-breaker exists—the application will produce unhandled exceptions (e.g., sqlite3.OperationalError: unable to open database file or database is locked), leading to cascading failures.

**Remediation:**

1. Add connection pool configuration to config.yaml.example with pool_size (10), pool_timeout (5 seconds), max_overflow (5), and documented behavior when pool exhausted (return HTTP 503 with Retry-After header). 2. Implement a connection pool or singleton pattern in election.py using threading.Lock and queue.Queue with maxsize=MAX_CONNECTIONS that raises ServiceUnavailable after POOL_TIMEOUT. 3. Document fallback behavior when limits are reached.

---

#### FINDING-065: No Concurrency Limits on Memory-Intensive Argon2 Operations Enabling Resource Exhaustion

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 13.1.2, 15.1.3, 15.2.2 |
| Files | `v3/steve/crypto.py:88-98`, `v3/steve/election.py:230-243` |
| Source Reports | 13.1.2.md, 15.1.3.md, 15.2.2.md |
| Related | - |

**Description:**

The application uses Argon2 key derivation with significant resource requirements (64MB memory, ~200-500ms CPU time per invocation) in multiple web request paths without any documentation identifying these operations as resource-intensive, documented defenses against availability loss, or documented strategies to avoid response times exceeding consumer timeouts. This directly violates ASVS 15.1.3. The application uses Quart (async framework) but calls synchronous CPU-bound Argon2 operations directly within the async event loop without offloading to a thread pool, blocking the entire event loop during cryptographic operations. Resource impact scenarios: (1) Vote submission (add_vote): 1× Argon2 per request — 10 concurrent submissions = 640MB peak memory + CPU saturation, (2) Ballot status (has_voted_upon): N × Argon2 where N = number of issues — 20 issues = ~10 seconds response time likely exceeding client timeout, (3) Tally operation (tally_issue): O(N) where N = eligible voters — 100 voters = ~50s, 1000 voters = ~500s with no documented timeout or processing strategy. During the 500ms Argon2 execution, the entire async event loop is blocked and no other requests (including health checks) can be served. There is no documentation of expected execution time, no guidance on maximum supported election sizes, no documented timeout or processing strategy, and no documented mitigation for event loop blocking.

**Remediation:**

1. Create an operations/architecture document that: (a) Identifies each resource-intensive operation with its CPU/memory profile (Vote Submission: 1× Argon2 = 64MB RAM + ~500ms CPU; Ballot Status: N × Argon2 where N = issues; Tally: N × Argon2 where N = eligible voters), (b) Documents maximum concurrent requests the server can handle based on Argon2 memory, (c) Specifies recommended reverse proxy timeout settings (client timeout ≥ 2s for vote submission, N × 0.5s for ballot status), (d) Describes recommended deployment configuration (worker count, memory limits), (e) Documents expected execution times for various voter counts in tally operations. 2. Implement asyncio.run_in_executor() for all Argon2-calling paths using a bounded ThreadPoolExecutor (e.g., max_workers=4 to limit concurrent operations: 4 concurrent × 64MB = 256MB Argon2 budget). Convert synchronous methods like add_vote() to async versions (add_vote_async()) that offload CPU-bound operations. 3. Document the thread pool size as the concurrency control mechanism: 'Argon2 operations are offloaded to a bounded thread pool (max_workers=4). This limits peak memory to 256MB and prevents event loop blocking. Excess requests queue at the executor.' 4. Implement rate limiting at the web layer using quart_rate_limiter (e.g., 5 votes per minute per user). 5. Add maximum issue count check (e.g., MAX_ISSUES_PER_CHECK = 100) in has_voted_upon(). 6. For tally operations: document as CLI-only, add logging of expected resource consumption based on voter count, implement progress callback mechanism, consider running in separate process with CPU affinity. 7. Document operational planning guidance: 'For elections > 200 voters, schedule tallying during low-usage windows. Maximum supported: tested up to N voters.'

---

#### FINDING-066: Absence of Critical Secrets Inventory Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-1059 |
| ASVS Sections | 13.1.4 |
| Files | `v3/server/config.yaml.example:1-22`, `v3/steve/crypto.py:13-77`, `v3/steve/election.py:82-94, 143-151`, `v3/server/main.py:38-49` |
| Source Reports | 13.1.4.md |
| Related | FINDING-151, FINDING-190 |

**Description:**

The application employs at least 8 distinct categories of cryptographic secrets that are critical to election integrity, vote confidentiality, and voter anonymity. No documentation exists—either within the configuration template, inline code documentation, or a standalone security document—that enumerates these secrets, describes their purpose, classifies their sensitivity level, or specifies access control requirements. Secrets include: TLS Certificate/Key, OAuth Client Secrets, Election Salt, Opened Key, Per-voter Salts, Vote Tokens, Fernet Encryption Keys, and Database File. Operations staff cannot properly protect secrets they don't know exist, and incident response cannot systematically identify and rotate compromised secrets without an inventory.

**Remediation:**

Create SECURITY.md in repository root with comprehensive secrets inventory including: Infrastructure Secrets (TLS Private Key, TLS Certificate, OAuth Client Secret, Database File) and Cryptographic Secrets (Election Salt, Opened Key, Per-Voter Salt, Vote Tokens, Fernet Encryption Keys). For each secret, document: storage location, access requirements, criticality level, and purpose. Include configuration management guidance specifying that secrets MUST NOT be stored in config.yaml and must be provided via environment variables or secure filesystem with restricted permissions. Create access control matrix defining which roles can access which secrets.

---

#### FINDING-067: No Secret Rotation Schedule or Rotation Capability

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-320 |
| ASVS Sections | 13.1.4 |
| Files | `v3/steve/crypto.py:68-77`, `v3/steve/election.py:82-94, 143-151, 282-295` |
| Source Reports | 13.1.4.md |
| Related | FINDING-069 |

**Description:**

No rotation schedule is defined for any secret in the application. More critically, the cryptographic architecture structurally prevents rotation for election-bound secrets: once an election is opened, its salt, opened_key, per-voter salts, and derived vote tokens are permanently fixed. There is no key versioning, no re-encryption mechanism, and no documented procedure for rotating even infrastructure secrets (TLS certificates, OAuth credentials). The HKDF info parameter is a fixed constant (b'xchacha20_key') with no version indicator, making rotation impossible. If any election-scoped secret is compromised, there is no recovery path without closing the election.

**Remediation:**

Document rotation schedule and constraints in SECURITY.md with rotation frequencies for infrastructure secrets (TLS Certificate: Annual or 30 days before expiry, OAuth Client Secret: Annual or on compromise) and explicit documentation that election-scoped secrets cannot be rotated (bound to election lifecycle). Create rotation procedures for TLS certificate renewal and OAuth secret rotation. Add key versioning support to crypto.py by modifying _b64_vote_key() to accept version parameter and update info parameter to include version (e.g., f'vote_key_v{version}'.encode()). Store key version in database alongside votes to enable future rotation capability. Implement decrypt() function that supports multiple key versions for backward compatibility during rotation periods.

---

#### FINDING-068: No Secrets Management Solution for Backend Cryptographic Material

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 13.3.1, 13.3.4 |
| Files | `v3/steve/election.py:75-88`, `v3/steve/election.py:258-274`, `v3/server/main.py:77-78`, `v3/server/config.yaml.example:28-29` |
| Source Reports | 13.3.1.md, 13.3.4.md |
| Related | - |

**Description:**

ASVS 13.3.1 (L2) requires a secrets management solution (e.g., key vault) to securely create, store, control access to, and destroy backend secrets. The application has no integration with any secrets management system. All cryptographic key material is stored directly in SQLite or referenced by plain file paths. Affected secrets include: opened_key (election master key) stored as raw bytes in SQLite metadata table, per-voter salts stored as raw bytes in SQLite mayvote table, TLS private key referenced by file path in config.yaml, and OAuth integration secrets presumably in config.yaml or environment variables. Any compromise of the SQLite database file exposes all cryptographic material needed to decrypt every vote in every election. No access controls, audit trail, or monitoring exist around secret retrieval.

**Remediation:**

Add a post-tally key destruction step with a destroy_key_material() method that: asserts the election is closed, begins a database transaction, destroys the election master key, destroys per-voter salts, destroys vote tokens and ciphertexts, commits the transaction, executes VACUUM to force SQLite to reclaim space and overwrite deleted pages, and logs the key material destruction event. This should be called after tallying is complete and results are finalized. Add a purge_crypto() method and integrate it into the post-tally lifecycle. Add an 'archived' state to the election lifecycle to track when cryptographic material has been destroyed.

---

#### FINDING-069: Master Election Key (opened_key) Stored in Application Database Co-located with Encrypted Votes

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | CWE-320 |
| ASVS Sections | 13.3.3 |
| Files | `v3/steve/election.py:67-84`, `v3/steve/election.py:118-131`, `v3/steve/election.py:222-236`, `v3/steve/election.py:257-299`, `v3/steve/election.py:238-256` |
| Source Reports | 13.3.3.md |
| Related | FINDING-067 |

**Description:**

The master election key (opened_key) used to derive vote encryption keys is stored directly in the same SQLite database file that contains the encrypted votes and per-voter salts. This violates ASVS 13.3.3's requirement for isolated key storage. An attacker with read access to the steve.db file can extract the opened_key, per-voter salts, and encrypted votes, then reconstruct the complete vote-to-voter mapping. With Argon2 parameters (time_cost=2, memory_cost=64MB), complete de-anonymization of 500 voters × 5 issues takes only 4-8 minutes. All three components needed for de-anonymization (opened_key, salt, ciphertext) reside in a single security boundary with no external secret required.

**Remediation:**

Store the opened_key in an external secrets manager (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, or cloud KMS) requiring a separate compromise vector. At minimum, split the key derivation so that one component comes from outside the database. Option A: Use vault/KMS to store the key and only store a reference in the database. Option B: XOR opened_key with a master key from an environment variable (STEVE_MASTER_KEY) before database storage. Implement vault client integration in the open() function and retrieve keys from vault in _all_metadata() rather than from the database.

---

#### FINDING-070: Absence of Formal Sensitive Data Classification and Protection Levels

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 14.1.1 |
| Files | `v3/steve/election.py:146-157`, `v3/steve/election.py:163`, `v3/steve/persondb.py:38`, `v3/server/pages.py:57`, `v3/server/pages.py:603`, `v3/schema.sql` |
| Source Reports | 14.1.1.md |
| Related | - |

**Description:**

The system processes at least six distinct categories of sensitive data (election cryptographic salt/opened_key, per-voter salts, vote content, vote tokens, voter PII, election metadata), each requiring different protection levels, but none are formally classified. Ad-hoc protections exist (salt exclusion in specific functions, vote encryption) but there is no systematic framework to ensure consistent handling across all code paths. Current protections are convention-based, comment-driven, and function-specific rather than architecturally enforced. Without formal classification, there is no systematic way to verify that all sensitive data types are consistently protected across all code paths, and the ballot secrecy guarantee cannot be verified as complete.

**Remediation:**

1. Create formal data classification document defining CRITICAL, SENSITIVE, INTERNAL, PUBLIC tiers with handling rules. 2. Implement defense-in-depth filtering at template boundary via sanitize_for_template() function. 3. Update postprocess_election() with classification awareness and verification. 4. Add classification verification tests for get_metadata(), get_issue(), and template sanitization. 5. Implement classification-aware data access layer with automatic field filtering. 6. Add runtime classification validation in data processing functions.

---

#### FINDING-071: Potential Sensitive Data Leakage Through Exception Logging During Vote Processing

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | CWE-532 |
| ASVS Sections | 14.1.2 |
| Files | `v3/server/pages.py:~425-432`, `v3/steve/election.py:~207` |
| Source Reports | 14.1.2.md |
| Related | FINDING-200 |

**Description:**

Exception messages during vote processing are logged without sanitization in the `do_vote_endpoint` function. The code logs exception details using `_LOGGER.error(f'Error adding vote for user[U:{result.uid}] on issue[I:{iid}]: {e}')`. If exceptions occur in `election.add_vote()`, `crypto.create_vote()`, or `crypto.gen_vote_token()`, the exception message may include function arguments such as plaintext vote content (`votestring`), cryptographic vote tokens, or per-voter salts. This violates ballot secrecy and exposes cryptographic material in application logs.

**Remediation:**

Remove exception details from logging. Replace the current logging statement with a sanitized version that logs only non-sensitive metadata: `_LOGGER.error(f'Error adding vote for user on issue[I:{iid}] in election[E:{election.eid}]')`. Never include the exception object `{e}` in logs. For debugging purposes, detailed exceptions should only go to secure debug logs with restricted access, separate from standard application logs.

---

#### FINDING-072: Complete Absence of Cache-Control Headers on All Sensitive Endpoints

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-524 |
| ASVS Sections | 14.1.2, 14.2.2, 14.2.4, 14.2.5, 14.3.2, 14.1.1 |
| Files | `v3/server/pages.py:60`, `v3/server/pages.py:137`, `v3/server/pages.py:220`, `v3/server/pages.py:283`, `v3/server/pages.py:320`, `v3/server/pages.py:343`, `v3/server/pages.py:530`, `v3/server/pages.py:540`, `v3/server/pages.py:156`, `v3/server/pages.py:240`, `v3/server/pages.py:299`, `v3/server/pages.py:333`, `v3/server/pages.py:353`, `v3/server/pages.py:537`, `v3/server/pages.py:545`, `v3/server/pages.py:223`, `v3/server/pages.py:119`, `v3/server/pages.py:286`, `v3/server/pages.py:238`, `v3/server/pages.py:151`, `v3/server/pages.py:302`, `v3/server/pages.py:328`, `v3/server/pages.py:348` |
| Source Reports | 14.1.2.md, 14.2.2.md, 14.2.4.md, 14.2.5.md, 14.3.2.md, 14.1.1.md |
| Related | FINDING-016 |

**Description:**

Pages that display sensitive election data (voter eligibility, candidate lists, election structure, voting interfaces) are served without any Cache-Control headers or equivalent meta tags. This allows browser back-button, history, and proxy caches to reveal voter participation, election structure, administrative access, and PII. Attack scenarios include shared workstations (next user presses Back), misconfigured proxy caches serving authenticated pages to wrong users, browser forensics extracting cached election data, and mobile device theft allowing access to cached voting pages without authentication. The absence of cache-control headers demonstrates that data displayed on these pages has not been assigned a protection level that would mandate cache prevention.

**Remediation:**

Add an after-request handler to set Cache-Control: no-store on all authenticated responses. Implementation: Add @APP.after_request async def set_cache_control(response) that checks if response is text/html and sets headers: 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0', 'Pragma: no-cache', 'Expires: 0'. Alternatively, create a decorator for sensitive routes that wraps responses with these headers.

---

#### FINDING-073: Election Management Endpoints Lack Ownership Authorization

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.6 |
| Files | `v3/server/pages.py:308`, `v3/server/pages.py:355`, `v3/server/pages.py:361`, `v3/server/pages.py:423`, `v3/server/pages.py:441`, `v3/server/pages.py:457`, `v3/server/pages.py:479`, `v3/server/pages.py:500` |
| Source Reports | 14.2.6.md |
| Related | - |

**Description:**

Election management endpoints require only R.committer authentication but perform no ownership or authorization verification. Any authenticated committer can access /manage/&lt;eid&gt; for ANY election, receiving sensitive election management data (full issue details, election state, owner identity, configuration) that exceeds the minimum required for their voter role. The state-changing endpoints (do-open, do-close, do-add-issue, do-edit-issue, do-delete-issue) are similarly unprotected, meaning unauthorized users can also modify elections.

**Remediation:**

Implement ownership/authz verification on all management endpoints. Add authorization checks to manage_page, do_open_endpoint, do_close_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint, and do_delete_issue_endpoint to verify the authenticated user is the election owner or in the authorized group before exposing management data or allowing state changes. Create a load_election_for_management decorator that verifies md.owner_pid matches result.uid before allowing access.

---

#### FINDING-074: No Data Retention Classification for Any Sensitive Data Category

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 14.2.7 |
| Files | `v3/schema.sql:vote table definition`, `v3/schema.sql:person table definition`, `v3/steve/election.py:180-200`, `v3/steve/election.py:64-78`, `v3/steve/persondb.py:51-64`, `v3/server/pages.py:past_elections feature` |
| Source Reports | 14.2.7.md |
| Related | - |

**Description:**

The system handles multiple categories of sensitive data — encrypted votes, voter PII (names, emails), per-voter cryptographic salts, election keys, and voter-to-issue mappings — but no data retention classification exists. There are no retention period definitions, no expiration timestamps in the schema, and no administrative interfaces or scheduled processes for data lifecycle management. Sensitive data enters, is stored, and remains indefinitely with no exit path.

**Remediation:**

1. Define a data retention classification document mapping each data type to a retention period: Encrypted votes (retain per-policy e.g., 2 years post-close), Election keys (delete after final tally verified), Per-voter salts (delete after final tally verified), Person PII (delete when no active elections reference them), Superseded votes (delete immediately upon re-vote). 2. Add schema support: ALTER TABLE election ADD COLUMN tallied_at INTEGER; ALTER TABLE vote ADD COLUMN created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')). 3. Implement a periodic cleanup process or CLI command.

---

#### FINDING-075: Election Cryptographic Key Material Persisted Indefinitely After Use

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 14.2.7, 11.2.2 |
| Files | `v3/schema.sql:election table definition`, `v3/schema.sql:mayvote table definition`, `v3/steve/election.py:64-78`, `v3/steve/election.py:80-90`, `v3/steve/election.py:217-255`, `v3/steve/election.py:50-60` |
| Source Reports | 14.2.7.md, 11.2.2.md |
| Related | - |

**Description:**

When an election is opened, a 16-byte salt and 32-byte opened_key are stored in the election table. The opened_key is derived from the election definition and used to generate vote_tokens, which in turn derive per-vote encryption keys. After an election is closed and tallied, these cryptographic values remain in the database forever. There is no mechanism to purge them after they are no longer needed. The combination of election.opened_key + election.salt + per-voter mayvote.salt values enables decryption of all votes in an election. After tallying is complete, these keys serve no operational purpose, but their continued presence means that a future database compromise would allow retroactive decryption of votes from all past elections, violating the system's ballot secrecy goal.

**Remediation:**

Add algorithm version fields to all tables storing cryptographic material. For the vote table, add 'crypto_version INTEGER NOT NULL DEFAULT 1' to track which encryption algorithm was used. For election and mayvote tables, add crypto_version fields to track KDF and hashing algorithm versions. Relax fixed-length CHECK constraints to allow variable-length outputs (e.g., 'CHECK (salt IS NULL OR length(salt) >= 16)' instead of '= 16'). This enables phased migration where new data uses new algorithms while old data can still be processed with legacy algorithms based on the version field.

---

#### FINDING-076: No Documentation Classifying Third-Party Component Risk Levels

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.1.4 |
| Files | `v3/steve/crypto.py:25-28`, `v3/steve/election.py:22-24`, `v3/steve/election.py:146-156`, `v3/steve/election.py:216`, `v3/steve/election.py:259`, `v3/steve/election.py:310`, `v3/server/main.py:37` |
| Source Reports | 15.1.4.md |
| Related | - |

**Description:**

No documentation exists identifying, classifying, or highlighting third-party libraries based on their risk profile. ASVS 15.1.4 specifically requires documentation that flags 'risky components' — libraries that are poorly maintained, unsupported, at end-of-life, or have a history of significant vulnerabilities. The application depends on at least five third-party packages with characteristics warranting explicit risk documentation: asfpy and asfquart (ASF-internal libraries without broad public security review processes), easydict (small convenience library with minimal maintenance activity and narrow contributor base, used to wrap security-sensitive data including election metadata with salt and opened_key), and argon2-cffi low-level API (bypasses higher-level safety defaults). The easydict library converts dict keys to object attributes which could mask key collisions or unexpected attribute access patterns. Without documented risk assessment, vulnerability response timeframes cannot be differentiated by component risk level, and there is no documented update cadence for risky vs. standard components.

**Remediation:**

Create a dependency risk assessment document (e.g., DEPENDENCIES.md or integrate into SBOM) that classifies each third-party component with: (1) Risk Level (Critical/High/Medium/Low), (2) Justification (maintenance status, security review process, contributor base, CVE history), (3) Mitigations (version pinning, monitoring strategy, alternative evaluation timeline), (4) Review Cadence (Critical: weekly, High: monthly, Medium/Low: quarterly). Document vulnerability response timeframes per component risk level (e.g., Critical CVE in risky component: Patch within 24 hours, High CVE in risky component: Patch within 72 hours). Classify components: Dangerous Functionality (cryptography, argon2-cffi) - Critical risk due to cryptographic operations; Risky Components (asfquart, asfpy - internal ASF libraries without broad security review; easydict - minimal maintenance, narrow contributor base, used for security-sensitive data). Consider replacing easydict with Python standard library alternatives such as dataclasses (Python 3.7+) or typing.NamedTuple to eliminate dependency on minimally-maintained external library for security-sensitive data structures.

---

#### FINDING-077: cryptography.hazmat and argon2.low_level API Usage Not Documented as Dangerous Functionality

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.1.5 |
| Files | `v3/steve/crypto.py:23`, `v3/steve/crypto.py:25`, `v3/steve/crypto.py:26`, `v3/steve/crypto.py:62`, `v3/steve/crypto.py:92-103` |
| Source Reports | 15.1.5.md |
| Related | - |

**Description:**

The codebase uses two explicitly dangerous low-level cryptographic APIs without formal documentation: cryptography.hazmat module (explicitly named 'hazardous materials' by maintainers with warnings that misuse can lead to severe vulnerabilities) and argon2.low_level module (bypasses high-level safety features including parameter validation, automatic encoding, and type selection). The cryptography library's own documentation states: 'This is a Hazardous Materials module. You should ONLY use it if you're 100% absolutely sure that you know what you're doing.' The code contains only brief inline comments but no formal documentation that: (1) Inventories all hazmat/low-level crypto usage, (2) Explains why high-level APIs were insufficient, (3) Documents the security review status of these usages, (4) Identifies the specific risks of each operation. ASVS 15.1.5 requires application documentation to highlight parts where 'dangerous functionality' is being used. This is particularly critical as these APIs are the foundation for vote encryption/decryption and election integrity.

**Remediation:**

Create a SECURITY.md or architecture document section that inventories dangerous functionality: (1) Document cryptography.hazmat (HKDF-SHA256 in _b64_vote_key): Purpose - Used for key stretching of vote tokens. Justification - Low-level API required because Fernet needs specific key format. Risk - Incorrect parameter selection could weaken encryption keys. Parameters - SHA256, 32-byte output, salt from vote_token, info='xchacha20_key' (note: should match actual algorithm). (2) Document argon2.low_level (Argon2 hashing in _hash): Purpose - Used for opened_key generation and vote tokens. Justification - Low-level API required for raw byte output (high-level returns encoded string). Risk - Incorrect parameter tuning could weaken brute-force resistance. Parameters - time_cost=2, memory_cost=64MB, parallelism=4, Type=D (note: should be Type.ID per RFC 9106). (3) Include security review status and date of last cryptographic review. (4) Document that these modules require specialized cryptographic expertise for any modifications.

---

#### FINDING-078: Vote Decryption/Tallying Functionality Lacks Process Isolation from Web Attack Surface

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Sections | 15.2.5, 11.7.2 |
| Files | `v3/steve/election.py:56`, `v3/steve/election.py:284-349`, `v3/steve/crypto.py:82-87` |
| Source Reports | 15.2.5.md, 11.7.2.md |
| Related | - |

**Description:**

The tally_issue() method, which decrypts all encrypted votes for a given issue, resides in the same Election class and runs in the same process as web-facing request handlers. The opened_key (the master key material that, combined with per-voter salts, can decrypt every vote) is loaded into the web server's process memory during tallying. There is no process isolation, privilege separation, sandboxing, or network isolation. A vulnerability in any web handler (e.g., SSRF, template injection, deserialization flaw) could allow an attacker to invoke tally_issue() or access opened_key in process memory, compromising all vote secrecy. Additionally, the __getattr__ proxy in the Election class exposes all database cursors defined in queries.yaml to any code holding an Election instance, completely bypassing the state-machine protections and allowing direct access to cursors like c_delete_election, c_open, c_close, and c_add_vote without state checks. ASVS 15.2.5 requires additional protections around dangerous functionality such as sandboxing, encapsulation, or containerization.

**Remediation:**

Implement process-level separation for tallying operations. Option A (recommended for L3 compliance): Create a separate tallying service that runs as a separate process/container: 1. Create isolated_tally() function using multiprocessing.Process. 2. Tally process should drop capabilities after opening database (e.g., using prctl on Linux). 3. Destroy key material when subprocess exits using try/finally. 4. Communicate results via IPC (pipe/queue) rather than shared memory. 5. Run tally service in separate container with minimal permissions. Option B (minimum): Restrict Election class API surface: 1. Remove __getattr__ proxy entirely and define explicit private properties for needed cursors, OR use __getattr__ with an allowlist (_ALLOWED_ATTRS frozenset) that explicitly lists each allowed cursor and raises AttributeError for non-permitted attributes. 2. Create a separate TallyElection subclass for privileged operations that is only instantiable from CLI/privileged context. 3. Document that tally operations must never be exposed via web endpoints.

---

#### FINDING-079: Authorization Failures Not Logged at Multiple Endpoints

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2, L3 |
| CWE | - |
| ASVS Sections | 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3 |
| Files | `v3/server/pages.py:250`, `v3/server/pages.py:294-299`, `v3/server/pages.py:356-366`, `v3/server/pages.py:274-279`, `v3/server/pages.py:241-247`, `v3/server/pages.py:274-354`, `v3/server/pages.py:308`, `v3/server/pages.py:547`, `v3/server/pages.py:607-611`, `v3/server/pages.py:494-499`, `v3/server/pages.py:589-625`, `v3/server/pages.py:246-251`, `v3/server/pages.py:610-614` |
| Source Reports | 16.1.1.md, 16.2.1.md, 16.3.1.md, 16.3.2.md, 16.3.3.md |
| Related | - |

**Description:**

Multiple endpoints perform authorization checks (PersonDB lookup, mayvote eligibility verification, document access control) but silently deny access by returning 404 responses without creating any log entry. Authorization failures are high-signal security events indicating potential attacks or misconfigurations. Affected endpoints include vote_on_page() for voter eligibility checks, serve_doc() for document access authorization, and admin_page() for admin access control. This prevents detection of unauthorized access attempts, privilege escalation probing, reconnaissance attacks, and provides no visibility for security incident investigation or pattern detection.

**Remediation:**

Add _LOGGER.warning() calls before all authorization failure responses to log user ID, requested resource, IP address (from quart.request.remote_addr), and reason for denial. Example for vote_on_page: _LOGGER.warning(f'AUTHZ_DENIED: User[U:{result.uid}] attempted to access election[E:{election.eid}] without voter eligibility. source_ip={quart.request.remote_addr}'). Example for serve_doc: _LOGGER.warning(f'AUTHZ_DENIED: User[U:{result.uid}] attempted to access document for issue[I:{iid}] (file: {docname}) without eligibility. source_ip={quart.request.remote_addr}'). Consider implementing rate limiting detection to escalate log level to ERROR with 'POSSIBLE_ATTACK' prefix when failure_count_5min >= 10.

---

#### FINDING-080: No Authentication Event Logging Framework

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.1 |
| Files | `v3/server/pages.py:63-92`, `v3/server/main.py:36-48` |
| Source Reports | 16.3.1.md |
| Related | - |

**Description:**

The application uses @asfquart.auth.require decorators for OAuth-based authentication across 15+ endpoints but never logs the outcome of authentication operations. There is no @APP.before_request handler, no @APP.after_request handler, and no error handler for 401/403 responses. When the OAuth flow completes (success or failure), the application does not record this event. In an election system, this makes it impossible to detect unauthorized access attempts, creates no forensic trail for security incident investigation, prevents verification that only authorized individuals accessed the system during an election, and represents compliance failure for election auditing requirements.

**Remediation:**

Add before_request handler to log authentication outcomes for all requests to protected endpoints. Add error handlers for 401 and 403 responses to log authentication rejections and authorization failures. Include metadata such as user ID, IP address (quart.request.remote_addr), user agent, request path, and authentication method in all authentication log entries. Example: @app.before_request async def log_authentication() to capture successful authentications, and @app.errorhandler(401) and @app.errorhandler(403) to capture failures with _LOGGER.warning() calls.

---

#### FINDING-081: Input Validation and Business Logic Bypass Attempts Not Logged

| Attribute | Value |
|-----------|-------|
| Severity | 🟠 High |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS Sections | 16.3.3 |
| Files | `v3/server/pages.py:420-422`, `v3/server/pages.py:413-415`, `v3/server/pages.py:107-111` |
| Source Reports | 16.3.3.md |
| Related | - |

**Description:**

ASVS 16.3.3 specifically requires logging of attempts to bypass security controls, such as input validation, business logic, and anti-automation. The application performs input validation and business logic checks but does not log when these checks fail. This includes invalid issue IDs in votes, empty vote submissions, invalid date formats, and election state machine violations (enforced by assert statements). This makes automated attacks, fuzzing attempts, and manipulation attempts invisible to security monitoring. Attackers can probe the system without generating any alerts.

**Remediation:**

Add _LOGGER.warning() calls for all input validation failures with context about the invalid input. Log user ID, election/issue ID, validation type that failed, and the invalid value (sanitized). Implement rate limiting on validation failures to prevent fuzzing attacks. Add SIEM rules to alert on high volumes of validation failures. Example: _LOGGER.warning('INPUT_VALIDATION_FAILED: User[U:%s] submitted vote with invalid issue[I:%s] in election[E:%s]. valid_issues=%s', result.uid, iid, election.eid, list(issue_dict.keys()))

#### FINDING-082: Election State Violation Attempts Not Logged (Assert-Based Enforcement)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 16.3.3, 16.5.3 |
| **Files** | `v3/steve/election.py:57`, `v3/steve/election.py:61`, `v3/steve/election.py:77`, `v3/steve/election.py:82`, `v3/steve/election.py:128`, `v3/steve/election.py:135`, `v3/steve/election.py:137`, `v3/steve/election.py:196`, `v3/steve/election.py:197`, `v3/steve/election.py:215`, `v3/steve/election.py:216`, `v3/steve/election.py:228`, `v3/steve/election.py:248`, `v3/steve/election.py:257`, `v3/steve/election.py:268` |
| **Source Reports** | `16.3.3.md`, `16.5.3.md` |
| **Related** | - |

**Description:**

The Election class enforces business logic rules about which operations are valid in each election state (editable, open, closed) using Python assert statements. These assertions produce no log output when they fail, are disabled by Python's -O optimization flag, and raise generic AssertionError exceptions with no security context. Attempts to bypass these business logic controls (e.g., voting on closed elections, modifying opened elections, adding issues to closed elections) are invisible to security monitoring. Multiple methods use assert for security-critical state checks including delete(), open(), close(), add_salts(), add_issue(), edit_issue(), delete_issue(), and add_voter().

**Remediation:**

Replace all assert statements used for security/business logic with explicit state validation that includes logging. Create a _require_state() helper method that logs state violations before raising exceptions. Example: def _require_state(self, required_state, operation): current = self.get_state(); if current != required_state: _LOGGER.warning('STATE_VIOLATION: election[E:%s] operation=%s current_state=%s required_state=%s', self.eid, operation, current, required_state); raise ElectionBadState(...). Apply to all state-dependent methods. Add enhanced exception handlers in pages.py to log business logic violations with user context.

---

#### FINDING-083: No Log Immutability or Write-Protection Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.4.2, 16.4.3 |
| **Files** | `v3/server/main.py:52-59`, `v3/server/main.py:84-91` |
| **Source Reports** | `16.4.2.md`, `16.4.3.md` |
| **Related** | - |

**Description:**

logging.basicConfig() is called without a filename parameter, directing all log output to sys.stderr. There is no configuration for file-based logging with restricted permissions, append-only or write-once log storage, remote/centralized log forwarding (e.g., syslog, SIEM), cryptographic integrity verification of log entries, or log rotation with retention guarantees. An attacker (or malicious administrator) with process-level or filesystem access can redirect stderr to /dev/null (silencing all audit logs), modify or delete log files if stderr is redirected to a file by a process manager, tamper with forensic evidence of vote manipulation, or undermine the entire auditing chain that the election system's security model depends upon.

**Remediation:**

Configure a remote log handler in addition to local output. At minimum, add a SysLogHandler targeting a separate log aggregation server using TCP for reliable delivery. Implement structured format for SIEM ingestion. For production election systems, consider: (1) TLS-encrypted syslog (RFC 5425) to prevent log interception in transit, (2) SIEM integration (Splunk HEC, Elasticsearch, etc.) via dedicated handlers, (3) Write-once storage (S3 with Object Lock, immutable log volumes), (4) Log signing to detect tampering of archived logs.

---

#### FINDING-084: Missing Vote Content Validation - Invalid Votes Stored Without Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 16.5.3 |
| **Files** | `v3/steve/election.py:260`, `v3/server/pages.py:437` |
| **Source Reports** | `16.5.3.md` |
| **Related** | - |

**Description:**

The add_vote() method contains a TODO comment where vote content validation should occur but has no implementation. Any arbitrary string is accepted, encrypted, and stored as a vote regardless of the issue's vote type (yna or stv). This is a fail-open condition where the validation step is absent, and the transaction (vote storage) proceeds unconditionally. Invalid votes corrupt election tallying results. For YNA: non-standard vote strings may be counted or cause tally errors. For STV: malformed ranking data could crash the STV algorithm or produce incorrect seat allocations.

**Remediation:**

Implement vote content validation in the add_vote() method. Validate votestring against the issue type by retrieving the issue, loading its vtype module, and calling a validate(votestring, kv) function. Each vtype module should implement validation logic (e.g., vtypes/yna.py validates that votestring is in ('y', 'n', 'a'); vtypes/stv.py validates ranking format and candidate labels). Raise InvalidVote(iid, votestring) exception if validation fails. Log validation failures with _LOGGER.warning() including user ID and issue ID.

---

#### FINDING-085: CLI Tally Tool Lacks Top-Level Exception Handler

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 16.5.4 |
| **Files** | `v3/server/bin/tally.py:172-185`, `v3/server/bin/tally.py:125-126` |
| **Source Reports** | `16.5.4.md` |
| **Related** | - |

**Description:**

The CLI tally tool, which processes election results and is likely run as a scheduled job or manual administrative task, lacks any top-level exception handling. The __main__ block invokes main() without any try/except wrapper, and errors within tally_election() are printed to stdout rather than logged. This means tallying errors during election processing are lost if stderr is not captured by the deployment environment, and error details critical for audit trails are not recorded in structured log format. This violates ASVS 16.5.4 requirement for a last resort error handler.

**Remediation:**

Wrap the main() call in a try/except block with structured logging. Catch ElectionNotFound, ElectionBadState, and general Exception separately with appropriate exit codes. Log all errors using _LOGGER with appropriate severity levels. Example: try: main(args.spy_on_open_elections, args.election_id, args.issue_id, args.db_path, args.output); except steve.election.ElectionNotFound as e: _LOGGER.error('Election not found: %s', e); sys.exit(2); except Exception: _LOGGER.critical('Unexpected error during tally', exc_info=True); sys.exit(99). Also fix tally_election() to use _LOGGER.error() instead of print().

---

#### FINDING-086: add_vote Crashes on Missing Voter Eligibility Record Instead of Failing Securely

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 16.5.2 |
| **Files** | `v3/steve/election.py:207-218` |
| **Source Reports** | `16.5.2.md` |
| **Related** | - |

**Description:**

The add_vote method retrieves voter eligibility records from the database but does not check for null results. When a voter attempts to vote on an issue they're not eligible for, the database query returns None, and the subsequent access to mayvote.salt raises an AttributeError instead of a proper authorization failure. This results in insecure authorization check failure, polluted security audit trails with implementation errors instead of authorization failure events, and could mask attacks where users attempt to vote on unauthorized issues. This violates ASVS 16.5.2 requirement for graceful degradation on external resource failure.

**Remediation:**

Add null check after q_get_mayvote.first_row() call. If the result is None, log a warning about authorization failure and raise a custom VoterNotEligible exception with proper context (pid, iid). Example: mayvote = self.q_get_mayvote.first_row(pid, iid); if not mayvote: _LOGGER.warning(f'AUTHZ_DENIED: User[U:{pid}] attempted to vote on issue[I:{iid}] without eligibility'); raise VoterNotEligible(pid, iid). This ensures authorization failures are handled explicitly and recorded correctly in audit logs.

---

#### FINDING-087: Election Close Operation Not Atomic — No State Guard in SQL

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-362 |
| **ASVS Sections** | 15.4.1, 15.4.2, 15.4.3 |
| **Files** | `v3/steve/election.py:121-127`, `v3/steve/election.py:108-113`, `v3/steve/election.py:121-128`, `v3/server/pages.py:482`, `v3/server/pages.py:378` |
| **Source Reports** | `15.4.1.md`, `15.4.2.md`, `15.4.3.md` |
| **Related** | FINDING-023, FINDING-024 |

**Description:**

The election close operation performs a state check and state update as separate database operations without transactional protection or atomic state verification in the UPDATE statement. This creates a race condition where multiple close requests can execute concurrently, and more critically, allows votes to be submitted during the close operation. The c_close SQL likely does not include WHERE clause checking current state (e.g., WHERE closed IS NULL OR closed = 0), meaning it doesn't atomically verify the election was actually open before closing.

**Remediation:**

Use an atomic UPDATE with a state-checking WHERE clause (UPDATE election SET closed=1 WHERE eid=? AND salt IS NOT NULL AND opened_key IS NOT NULL AND (closed IS NULL OR closed = 0)) and verify rowcount == 1 after execution. Raise ElectionBadState exception if the update affects 0 rows, indicating the election was not in the expected state. Wrap in BEGIN IMMEDIATE transaction.

---

#### FINDING-088: Election Delete — State Assertion Before Transaction Creates Race Window (TOCTOU)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-367 |
| **ASVS Sections** | 15.4.2 |
| **Files** | `v3/steve/election.py:48-65` |
| **Source Reports** | `15.4.2.md` |
| **Related** | FINDING-025 |

**Description:**

The delete() function asserts that the election is editable before beginning a transaction to delete the election and its related data. This state check occurs outside the transaction boundary, allowing a concurrent request to open the election after the check passes but before the transaction begins, resulting in deletion of an active election. Between assert self.is_editable() passing and BEGIN TRANSACTION executing, a concurrent request could open the election via open(). The delete then proceeds on an election that is now open, destroying an active election with salts and voter data.

**Remediation:**

Move the state check inside the transaction boundary. Use BEGIN IMMEDIATE before checking state, then verify the election is editable using _all_metadata(self.S_EDITABLE) within the transaction. This ensures the state check and deletion operations are atomic. Include proper exception handling with ROLLBACK on failure.

---

#### FINDING-089: Synchronous Blocking Database I/O in Async Event Loop Without Thread Pool

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 15.4.4 |
| **Files** | `v3/steve/election.py:38-43`, `v3/server/pages.py:181`, `v3/server/pages.py:399-432`, `v3/server/pages.py:144-172` |
| **Source Reports** | `15.4.4.md` |
| **Related** | - |

**Description:**

Election opening performs CPU-intensive Argon2 key derivation and holds a database write lock during an unbounded iteration over all voter-issue combinations. The entire operation executes synchronously in the async event loop, blocking all concurrent requests for potentially 1-5+ seconds depending on election size and Argon2 parameters. The add_salts() transaction holds SQLite's file-level write lock for the entire iteration over potentially hundreds of voter-issue combinations, blocking even separate database connections from writing. Argon2 key derivation is deliberately CPU-intensive; running it synchronously in the event loop blocks all async task scheduling for its full duration. Combined, these create a multi-second window where the application is completely unresponsive.

**Remediation:**

Wrap all synchronous Election method calls in asyncio.to_thread() to offload them to a thread pool. Example: e = await asyncio.to_thread(steve.election.Election, DB_FNAME, eid). Alternatively, adopt an async SQLite driver such as aiosqlite for native async database operations. Configure thread pool size via asyncio.get_event_loop().set_default_executor(ThreadPoolExecutor(max_workers=N)) to match expected concurrency.

---

#### FINDING-090: No Application-Level Memory Protection for Sensitive Cryptographic Material

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 11.7.1 |
| **Files** | `v3/steve/crypto.py:60-71`, `v3/steve/crypto.py:74-79`, `v3/steve/crypto.py:82-87`, `v3/steve/crypto.py:40-50`, `v3/steve/election.py:262-320`, `v3/steve/election.py:247-260`, `v3/server/bin/tally.py:103-145` |
| **Source Reports** | `11.7.1.md` |
| **Related** | - |

**Description:**

The application handles highly sensitive cryptographic material (encryption keys, plaintext votes, voter tokens) but implements no memory protection mechanisms. Python's immutable bytes and str objects cannot be overwritten, and no memory locking or zeroing is performed. Specific concerns include: (1) Immutable bytes for keys persist until garbage collected with no guaranteed zeroing, (2) Immutable str for plaintext votes cannot be zeroed, (3) No mlock() means sensitive memory pages can be swapped to disk, (4) Bulk accumulation during tally where the entire election's decrypted votes exist in memory simultaneously. A memory dump during vote submission or tallying could recover plaintext votes, cryptographic keys, and voter-to-vote mappings.

**Remediation:**

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

# For tallying, process and aggregate incrementally rather than accumulating all plaintext:
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

### 3.3 Medium

#### FINDING-091: Stored XSS via Flash Messages Containing Unencoded User Input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 1.1.1, 1.1.2, 1.2.1 |
| **Files** | `v3/server/templates/flashes.ezt:1-6`&lt;br&gt;`v3/server/pages.py:413, 426, 447, 455, 504, 508, 518, 533, 535, 537, 598` |
| **Source Reports** | 1.1.1.md, 1.1.2.md, 1.2.1.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-113, FINDING-114 |

**Description:**

Flash messages are constructed by interpolating user-controlled values (election titles, issue titles, issue IDs extracted from form field names) directly into message strings using Python f-strings without HTML encoding. These messages are stored in the session and rendered in flashes.ezt without the `[format "html"]` directive. The `iid` in `do_vote_endpoint` is extracted from form field names (`vote-<iid>`), making it directly controllable by the requester. XSS executes on the page redirect after a state-changing action. Primarily a self-XSS risk for the attacker's own session, but could be exploited if combined with CSRF.

**Remediation:**

Either encode at the template level by changing `[flashes.message]` to `[format "html"][flashes.message][end]`, or encode when constructing flash messages using `html.escape()`. Example: `await flash_success(f'Created election: {html.escape(form.title)}')`, `await flash_danger(f'Invalid issue ID: {html.escape(iid)}')`, `await flash_success(f'Issue "{html.escape(form.title)}" has been added.')`

---

#### FINDING-092: Missing Upper-Bound Range Validation on STV `seats` Integer Parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 1.4.2 |
| **Files** | `v3/server/bin/create-election.py:60-61`&lt;br&gt;`v3/steve/election.py:174`&lt;br&gt;`v3/steve/vtypes/stv.py:65` |
| **Source Reports** | 1.4.2.md |
| **Related** | - |

**Description:**

The STV election type accepts a `seats` parameter that determines how many candidates should be elected. While the CLI import tool validates that `seats` is a positive integer, there is no upper-bound validation anywhere in the codebase. The core API function `election.add_issue()` performs no validation on the `kv` dictionary contents at all, creating a defense-in-depth gap. This allows extreme values (e.g., INT32_MAX: 2147483647) to pass validation, get stored in the database, and be passed to `stv_tool.run_stv()` during tallying. Depending on the STV algorithm's implementation, this could exhaust memory, produce logically incorrect election results if seats exceeds the number of candidates, or cause integer overflow if the underlying STV tool uses C-based numeric processing.

**Remediation:**

Add range validation at multiple layers for defense-in-depth: (1) In `election.py:add_issue()` - API layer validation to check seats is positive integer, seats <= 100 (reasonable upper bound), and seats <= len(labelmap). (2) In `stv.py:tally()` - validate before algorithm execution. (3) In `create-election.py:validate_issue()` - add upper bound check. Full code examples provided in source report.

---

#### FINDING-093: Database Connection Resource Leak in Class Methods

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 1.4.3 |
| **Files** | `v3/steve/election.py:393-408, 414-423, 425-436, 438-447, 449-456` |
| **Source Reports** | 1.4.3.md |
| **Related** | - |

**Description:**

Every Election instance created via __init__ opens a SQLite database connection. The only code paths that close this connection are delete() and _disappeared() - specific to election deletion and missing election detection. Normal operations (creating an Election to read metadata, check vote status, add a vote, or tally results) never close the connection. The class provides no close(), __del__, __enter__/__exit__, or other standard resource release mechanism. Each web request that instantiates an Election object leaks one database connection for the duration of the request (at minimum) and potentially longer if reference cycles exist. Over many requests, this accumulates leaked file descriptors, SQLite locks preventing concurrent access, and memory overhead from buffered connection state. Under high load, this leads to resource exhaustion and application failure.

**Remediation:**

Add explicit connection cleanup using try/finally blocks or implement context manager support. Example: `@classmethod def open_to_pid(cls, db_fname, pid): db = cls.open_database(db_fname); try: db.q_open_to_me.perform(pid); return [row for row in db.q_open_to_me.fetchall()]; finally: db.conn.close()`. Or better, add context manager support to Election/DB class: `@classmethod def open_to_pid(cls, db_fname, pid): with cls.open_database(db_fname) as db: db.q_open_to_me.perform(pid); return [row for row in db.q_open_to_me.fetchall()]`

---

#### FINDING-094: No CSV/Formula Injection Protection Architecture

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 1.2.10 |
| **Files** | `v3/server/pages.py:361-376, 414-433, 474-502`&lt;br&gt;`v3/steve/election.py:197-209, 210-265, 301-307` |
| **Source Reports** | 1.2.10.md |
| **Related** | - |

**Description:**

The application stores user-controllable data (election titles, issue titles, issue descriptions, vote strings) without any sanitization of CSV formula injection characters. No CSV export functionality, CSV-safe utility functions, or formula injection escaping mechanisms exist anywhere in the codebase. The voting system produces tabular data through tally_issue() and get_voters_for_email() that are natural candidates for CSV/spreadsheet export, yet no architectural provision has been made for safe export. If tally results or voter/election data are ever exported to CSV/XLS/XLSX/ODF (a common operational need for voting systems), formula injection payloads stored by authenticated users would execute in the recipient's spreadsheet application. Vote strings are stored without format validation (as noted by TODO in add_vote()), allowing formula characters in vote data.

**Remediation:**

(1) Add a CSV-safe export utility with RFC 4180 compliance and formula character escaping (=, +, -, @, \t, \0) by prefixing with a single quote when they appear as the first character. (2) Add vote string validation in add_vote() per vote type (e.g., YNA accepts only y/n/a; STV accepts only comma-separated valid candidate labels). (3) Add input validation for election/issue titles rejecting or escaping leading formula characters. (4) Document CSV export security requirements in a developer guide to prevent regression when export features are added.

---

#### FINDING-095: Missing Vote String Format Validation (Type B Gap)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-20 |
| **ASVS Sections** | 1.2.7, 1.3.8, 1.3.9, 1.3.3, 2.3.1, 2.3.2, 2.2.1, 2.2.2, 2.2.3, 2.1.2, 2.1.3 |
| **Files** | `v3/steve/election.py:253-268`&lt;br&gt;`v3/server/pages.py:430-445` |
| **Source Reports** | 1.2.7.md, 1.3.8.md, 1.3.9.md, 1.3.3.md, 2.3.1.md, 2.3.2.md, 2.2.1.md, 2.2.2.md, 2.2.3.md, 2.1.2.md, 2.1.3.md |
| **Related** | FINDING-098, FINDING-099 |

**Description:**

The vote submission flow completely skips the validation step that should verify vote content matches the issue's vote type before encryption and storage. The expected sequential steps are: (1) authenticate user, (2) verify election is open, (3) verify voter eligibility, (4) validate vote content, (5) encrypt and store vote. Step 4 is entirely missing, acknowledged by a TODO comment (`### validate VOTESTRING for ISSUE.TYPE voting`) that was never implemented. Raw user input travels directly from HTTP form fields to encrypted storage without any domain validation. Invalid votes (e.g., 'INVALID_VALUE' for YNA issues, malformed rankings for STV issues) are successfully encrypted and stored, only to corrupt election results during tallying. The damage is irreversible once encrypted, and there's no mechanism to distinguish valid from invalid votes without decrypting all of them. This is a Type A gap where the validation step is entirely missing from the business flow. Client-side form controls can be trivially bypassed via direct HTTP requests.

**Remediation:**

Implement the missing validation step in the `add_vote()` method before encryption: (1) Fetch the issue to determine its vote type using `q_get_issue.first_row(iid)`. (2) Load the appropriate vote type module using `vtypes.vtype_module(issue.type)`. (3) Call a new `validate(votestring, kv)` function on the module to verify the vote content is valid for that type. (4) Raise `InvalidVoteString` exception if validation fails. (5) Implement `validate()` functions in each vote type module (vtypes/yna.py, vtypes/stv.py, etc.) that check vote strings against the allowed format and values for that type. For example, YNA should only accept 'yes', 'no', or 'abstain'; STV should verify rankings reference valid candidates and contain no duplicates. Add defense-in-depth validation in `do_vote_endpoint()` handler before calling `add_vote()`. For YNA votes, check votestring in ('y', 'n', 'a'). For STV votes, validate submitted labels exist in issue's labelmap, check for duplicates, ensure non-empty ranking.

---

#### FINDING-096: No SMTP Injection Sanitization Controls for User-Controlled Election Metadata

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-93 |
| **ASVS Sections** | 1.3.11 |
| **Files** | `v3/steve/election.py:501-507, 430-434`&lt;br&gt;`v3/server/pages.py:467-484, 524-544, 534-540, 557-562` |
| **Source Reports** | 1.3.11.md |
| **Related** | - |

**Description:**

The codebase contains email notification functionality via the get_voters_for_email() method in election.py, but no SMTP/IMAP injection sanitization controls are present. User-controlled election metadata (titles, descriptions) flows through the system without any mail-specific encoding or sanitization, creating potential SMTP header injection vulnerabilities. User input from form.title is stored via Election.create() and later retrieved by get_metadata() and get_voters_for_email() for email dispatch. An authenticated user creating an election could inject SMTP headers via the title field using CRLF sequences (%0d%0a), potentially injecting additional headers (Bcc:, Cc:, To:), overriding Content-Type for phishing, or adding arbitrary recipients.

**Remediation:**

Add SMTP-specific sanitization for all user-controlled data before it reaches any email system. Create a new sanitize.py module with sanitize_for_email_header() function that removes CRLF sequences (\r, \n, \x00) that could enable SMTP header injection. Apply this sanitization in Election.create() method before storing the title. Use Python's email.message module for constructing emails rather than string concatenation, as it provides built-in header encoding and injection protection. Apply sanitize_for_email_header() to issue titles and sanitize_for_email_body() to descriptions at the form handler level or within add_issue()/edit_issue() methods. Strip \r, \n, \x00 from issue titles before database storage as these characters are never legitimate in single-line fields. Add input length limits on title and description fields at the web handler level.

---

#### FINDING-097: Missing Path Sanitization/Validation for Document Serving Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 1.3.6 |
| **Files** | `v3/server/pages.py:527-543` |
| **Source Reports** | 1.3.6.md |
| **Related** | - |

**Description:**

The `docname` parameter is user-controllable via the URL and is passed directly to `quart.send_from_directory` without any application-level validation. The developer explicitly recognized this gap with the comment `### verify the propriety of DOCNAME.` but did not implement the control. This violates the ASVS 1.3.6 principle of validating untrusted data against an allowlist of paths and sanitizing dangerous characters before using the data to access a resource. Reliance on a single framework-level protection without defense-in-depth is a risk if a bypass is discovered in `safe_join`. While `safe_join` should block path traversal, null-byte or encoding bypasses in specific framework versions could allow access to unintended files within the DOCSDIR tree.

**Remediation:**

Implement explicit allowlist validation for the `docname` parameter using a regex pattern that only permits safe characters (alphanumeric, hyphens, underscores, dots). Explicitly reject path traversal components like `..` or leading dots. Example implementation:

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

---

#### FINDING-098: No Input Length Limits on User-Supplied Text Fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-20 |
| **ASVS Sections** | 1.3.3 |
| **Files** | `v3/server/pages.py:398, 457, 479`&lt;br&gt;`v3/server/templates/admin.ezt`&lt;br&gt;`v3/server/templates/manage.ezt` |
| **Source Reports** | 1.3.3.md |
| **Related** | FINDING-095, FINDING-099 |

**Description:**

ASVS 1.3.3 specifically requires 'trimming input which is too long.' No server-side length limits exist on any text input field (election titles, issue titles, issue descriptions). No client-side maxlength attributes are set on form inputs. SQLite TEXT columns accept up to 1 billion characters. This allows arbitrarily long inputs to be stored and rendered, causing storage bloat, slow template rendering, and potential denial of service.

**Remediation:**

Implement server-side length limits: MAX_ELECTION_TITLE = 200, MAX_ISSUE_TITLE = 200, MAX_ISSUE_DESCRIPTION = 10000. In all form-handling endpoints (do_create_endpoint, do_add_issue_endpoint, do_edit_issue_endpoint), apply:

```python
title = (form.get('title') or '').strip()[:MAX_TITLE_LEN]
```

Add client-side enforcement in all templates:

```html
<input maxlength="200" ...>
```

Reject empty titles after trimming.

---

#### FINDING-099: STV Vote String Parser Inconsistency Between Submission and Tallying

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-20 |
| **ASVS Sections** | 1.5.3, 15.2.2, 15.3.5 |
| **Files** | `v3/steve/election.py:200-213`&lt;br&gt;`v3/steve/vtypes/stv.py:46-63`&lt;br&gt;`v3/server/pages.py:321` |
| **Source Reports** | 1.5.3.md, 15.2.2.md, 15.3.5.md |
| **Related** | FINDING-095, FINDING-098 |

**Description:**

The add_vote() method accepts vote values from users without validating them against the expected vote type for the issue. The code contains an explicit TODO comment acknowledging this validation requirement, but the validation is not implemented. No validation of votestring length, format, or content against the issue's vote type occurs before passing the data to expensive cryptographic operations (Argon2 computation: 64 MiB memory, 4 CPU threads, ~100ms). This allows: (1) Arbitrary strings to be encrypted and stored as votes regardless of whether they match the issue's voting format (YNA, STV, etc.), (2) Voters to submit arbitrarily large or malformed votestrings that consume disproportionate resources during encryption, storage, and later decryption during tallying, (3) Repeated vote submissions to trigger unbounded Argon2 computation without throttling. A voter could submit a votestring of 10 MiB, which bypasses all vote-type validation, forces Fernet encryption of the full payload, stores the encrypted blob in SQLite, and must decrypt the full blob during tallying. Election integrity is compromised as invalid votes are encrypted and stored, then when tallied by vtypes modules, the behavior is unpredictable — tallying may crash, produce incorrect results, or silently discard/miscount votes.

**Remediation:**

Implement explicit type and format validation in the add_vote method before expensive operations: 1. Implement hard limit on votestring size (e.g., MAX_VOTESTRING_LEN = 4096). 2. Validate that votestring is a string type: `if not isinstance(votestring, str): raise ValueError(f'votestring must be a string, got {type(votestring).__name__}')`. 3. Retrieve the issue and validate it exists before processing: `issue = self.q_get_issue.first_row(iid); if not issue: raise IssueNotFound(iid)`. 4. Use the vtypes module's validate_vote function to ensure the vote format matches the issue type: `m = vtypes.vtype_module(issue.type); if not m.validate_vote(votestring, self.json2kv(issue.kv)): raise ValueError(f'Invalid vote format for {issue.type}: {votestring!r}')`. 5. Consider short-circuit check if identical vote already exists before computing expensive token. 6. Implement rate limiting at the web layer using quart_rate_limiter with conservative limits (e.g., 5 votes per minute per user).

---

#### FINDING-100: Election Date Serialization/Deserialization Inconsistency

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-838 |
| **ASVS Sections** | 1.5.3 |
| **Files** | `v3/server/pages.py:105-127, 489-494`&lt;br&gt;`v3/server/bin/tally.py:79-81` |
| **Source Reports** | 1.5.3.md |
| **Related** | - |

**Description:**

The election date write path uses datetime.fromisoformat() to parse JSON date strings and stores datetime.date objects (serialized as ISO strings like '2024-06-15'), but all read paths use datetime.fromtimestamp() expecting numeric Unix timestamps. This parser inconsistency causes TypeError exceptions when displaying elections whose dates were set via the API, resulting in 500 errors and denial of service for election administration. The tally CLI tool similarly fails when listing elections, preventing tallying operations.

**Remediation:**

Normalize to Unix timestamp at write time to match all read paths. Modify _set_election_date() to convert the parsed datetime to a Unix timestamp using int(dt.timestamp()) before storing. This ensures consistency with the fromtimestamp() calls in postprocess_election() and tally.py:

```python
dt = datetime.fromisoformat(date_str)
timestamp = int(dt.timestamp())
# Store timestamp instead of ISO string
```

---

#### FINDING-101: Document URL Construction/Parsing Inconsistency

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-22 |
| **ASVS Sections** | 1.5.3 |
| **Files** | `v3/server/pages.py:50-57, 454-465` |
| **Source Reports** | 1.5.3.md |
| **Related** | FINDING-039 |

**Description:**

Document URLs are constructed from issue descriptions using regex extraction without URL encoding, while the route handler receives URL-decoded parameters from the ASGI server. This parser inconsistency creates ambiguity for filenames containing percent-encoded sequences, special characters like # or ?, or path traversal sequences. The iid parameter is used directly in path construction (DOCSDIR / iid) without validation. The TODO comment '### verify the propriety of DOCNAME' confirms missing validation. While send_from_directory provides baseline protection for docname, the lack of validation on iid and the encoding inconsistency create potential security risks.

**Remediation:**

Add URL encoding at construction time using urllib.parse.quote() with safe='' to encode all special characters. Add validation at the route handler to verify both iid and docname match expected patterns (alphanumeric, underscore, hyphen, and period only):

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

---

#### FINDING-102: Missing ROLLBACK Handling in Transactional Methods

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.3.3, 16.5.2 |
| **Files** | `v3/steve/election.py:55-70, 126-140` |
| **Source Reports** | 2.3.3.md, 16.5.2.md |
| **Related** | - |

**Description:**

Multiple methods explicitly begin database transactions but fail to include rollback logic in exception handlers. If any operation within the transaction fails (crypto operation, database write, disk full), the transaction is neither committed nor rolled back, leaving the database connection in an undefined state. In add_salts, partial salt assignment means some voters have salts and some don't, breaking the election opening process. In delete, partial deletion could leave orphaned records that violate referential integrity. SQLite's rollback journal may hold a lock, blocking other connections.

**Remediation:**

Add try/except blocks with explicit ROLLBACK logic to all methods using BEGIN TRANSACTION. Ensure that any exception during the transaction triggers a rollback before re-raising. Replace security-critical assert statements with explicit if/raise patterns. Add error logging for all rollback scenarios. Example: try: self.db.conn.execute('BEGIN TRANSACTION'); ...; self.db.conn.commit(); except Exception as e: _LOGGER.error(f'Transaction failed for election[E:{self.eid}]: {type(e).__name__}', exc_info=True); self.db.conn.rollback(); raise

---

#### FINDING-103: Tampering Detection Control Exists But Is Never Invoked Before Sensitive Operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-353 |
| **ASVS Sections** | 2.3.2, 9.1.1, 11.6.2 |
| **Files** | `v3/steve/election.py:316, 236, 252`&lt;br&gt;`v3/server/pages.py:336` |
| **Source Reports** | 2.3.2.md, 9.1.1.md, 11.6.2.md |
| **Related** | - |

**Description:**

The application implements a cryptographic tampering detection mechanism (is_tampered() method) that computes an opened_key hash to detect if election data has been modified after opening. The method's own docstring states it should prevent voting when tampered and prevent tallying if tampered. However, this control is never called in any operational code path. Neither add_vote() (vote submission) nor tally_issue() (tallying) invoke is_tampered(), and the voting page display also doesn't check for tampering. If election data (issues, voters) is tampered with after opening, the system will silently accept votes and produce tallies against corrupted data, rendering the integrity protection mechanism useless. This is a Type B gap where the control exists but is never called.

**Remediation:**

Add tamper checks before every sensitive operation that relies on election data. The most effective approach is to integrate it into `_all_metadata()` or create a wrapper. Option A: Integrate into _all_metadata for open/closed elections by adding a `check_integrity` parameter that calls `is_tampered()` when the election has an `opened_key`. Option B: Add explicit checks at each entry point in pages.py before processing votes or closing elections. Additionally, use constant-time comparison (`hmac.compare_digest()`) for the MAC check instead of Python's `!=` operator to prevent timing side-channels.

---

#### FINDING-104: No Cross-Field Date Consistency Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.1.2, 2.2.3 |
| **Files** | `v3/server/pages.py:79-100, 77-101, 375, 382` |
| **Source Reports** | 2.1.2.md, 2.2.3.md |
| **Related** | - |

**Description:**

The _set_election_date() function validates individual date formats but does not perform cross-field validation to ensure logical consistency between open_at and close_at dates. The application accepts close_at dates that are before open_at dates, or dates in the past, creating logically inconsistent election metadata. This represents failure to validate contextual consistency of the combined data items (open_at + close_at). Administrators can set close_at to a date before open_at, creating logically impossible election configurations that undermine trust in the election process and cause confusing information to be displayed to voters.

**Remediation:**

Add cross-field validation in _set_election_date() that: (1) Retrieves current election metadata, (2) When setting open_at, checks that it is before close_at if close_at exists, (3) When setting close_at, checks that it is after open_at if open_at exists, (4) Returns 400 Bad Request with descriptive error message if validation fails. Also add similar validation in Election.create() and create-election.py CLI tool to prevent invalid date configurations at election creation time.

---

#### FINDING-105: Election Can Be Opened Without Issues or Eligible Voters

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 2.2.3 |
| **Files** | `v3/steve/election.py:72-87`&lt;br&gt;`v3/server/pages.py:530-547` |
| **Source Reports** | 2.2.3.md |
| **Related** | - |

**Description:**

The election.open() method does not verify that the election has at least one issue and at least one eligible voter before transitioning to OPEN state. Since opening an election is an irreversible state transition, this allows administrators to permanently render elections unusable by opening them before they are properly configured. An empty election in OPEN state cannot be returned to EDITABLE state, has no voteable content, and must be abandoned in favor of creating a new election.

**Remediation:**

Add pre-condition checks in election.open() method before allowing state transition. Query for issues associated with the election and raise ValueError if none exist. Query for mayvote entries (eligible voters) and raise ValueError if none exist. This ensures only complete, usable elections can be opened. The checks should occur after the is_editable() assertion but before add_salts() is called.

---

#### FINDING-106: No Business Logic Limits on Resource Creation or Vote Revisions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-770 |
| **ASVS Sections** | 2.1.3, 2.4.1 |
| **Files** | `v3/server/pages.py:466, 522, 473-490, 523-545`&lt;br&gt;`v3/steve/election.py:256` |
| **Source Reports** | 2.1.3.md, 2.4.1.md |
| **Related** | - |

**Description:**

No business logic limits are defined or enforced for resource creation (elections, issues) or vote revisions. The vote storage model uses INSERT for every revision, allowing unbounded database growth. There are no per-user limits on election creation, no per-election limits on issue count, and no limits on vote revision count. This enables resource exhaustion attacks through election creation spam, unbounded issue creation per election, and rapid vote-change cycling. Each election creates cryptographic keys consuming CPU resources for key derivation. The SQLite database has no inherent size limits — unchecked creation leads to disk exhaustion on the server.

**Remediation:**

Define and document business logic limits (e.g., MAX_ELECTIONS_PER_USER=50, MAX_ISSUES_PER_ELECTION=100, MAX_VOTE_REVISIONS_PER_ISSUE=10, MAX_TITLE_LENGTH=200, MAX_DESCRIPTION_LENGTH=5000, MAX_CANDIDATES_PER_STV=50). Implement enforcement checks before allowing resource creation. Add input length validation for title and description fields. For election creation, add per-user election creation quota and check the count of owned elections before allowing creation. For issue creation, enforce maximum issues per election and maximum candidates per STV issue. Return error messages and redirect when limits are reached.

---

#### FINDING-107: Election Creation and State-Change Endpoints Lack Rate Limiting and Timing Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 2.4.1, 2.4.2 |
| **Files** | `v3/server/pages.py:473-490, 463-482, 485-504, 507-523` |
| **Source Reports** | 2.4.1.md, 2.4.2.md |
| **Related** | - |

**Description:**

The election creation endpoint and state-change endpoints (open/close) lack rate limiting, cooldown periods, and timing controls. A compromised PMC member account can create unbounded elections at machine speed, causing database bloat, garbage-data creation, and quota exhaustion. Elections could be rapidly toggled between open and closed states, disrupting active voters mid-ballot. Each election creates cryptographic keys consuming CPU resources. The SQLite database has no inherent size limits — unchecked creation leads to disk exhaustion. The state-change endpoints execute immediately upon GET requests with no timing controls, confirmation steps, or cooldowns, violating HTTP semantics and enabling trivial CSRF exploitation.

**Remediation:**

For election creation: Add per-user election creation quota (e.g., MAX_ELECTIONS_PER_USER=50) and check the count of owned elections before allowing creation. Implement a per-user cooldown period (e.g., 30 seconds) between election creations tracked in session. Add a daily limit (e.g., 5 elections per user per day) enforced via database query. For state-change endpoints: Change endpoints from GET to POST methods. Add owner authorization check to verify metadata.owner_pid matches the requesting user. Implement a cooldown period (e.g., 60 seconds) on state changes per election tracked in session using an 'election_state_{eid}' key. Flash warning messages when cooldown is active or limits are exceeded and redirect appropriately.

---

#### FINDING-108: Missing Global Security Headers Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-693 |
| **ASVS Sections** | 3.2.1 |
| **Files** | `v3/server/main.py:30-43` |
| **Source Reports** | 3.2.1.md |
| **Related** | FINDING-119 |

**Description:**

The application has no after_request handler or middleware to apply security response headers globally. All 21 endpoints in the application serve responses without Content-Security-Policy, X-Content-Type-Options, or other defensive headers. This creates no defense-in-depth layer and allows browsers to MIME-sniff responses. Any response from the application lacks critical security headers, allowing MIME-sniffing attacks and providing no defense-in-depth if any endpoint inadvertently returns user-controlled content.

**Remediation:**

Implement an after_request handler in the create_app function that sets X-Content-Type-Options: nosniff and a default Content-Security-Policy for all responses. The CSP should restrict content sources with directives like default-src 'self', script-src 'self', style-src 'self' 'unsafe-inline', img-src 'self' data:, and frame-ancestors 'none'.

---

#### FINDING-109: API Endpoints Lack Sec-Fetch-* Context Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Sections** | 3.2.1 |
| **Files** | `v3/server/pages.py:376, 383, 390` |
| **Source Reports** | 3.2.1.md |
| **Related** | FINDING-007, FINDING-008, FINDING-009, FINDING-030, FINDING-033, FINDING-034 |

**Description:**

API-style endpoints that accept JSON or form data and return non-HTML responses do not validate Sec-Fetch-Dest or Sec-Fetch-Mode headers to confirm the request originates from the expected context (e.g., fetch from JavaScript, not direct browser navigation). While POST mitigates direct navigation, there is no server-side enforcement that these endpoints are called only via the intended AJAX/fetch context. Without Sec-Fetch-* validation, there is no server-side assurance that API endpoints are accessed only from the application's frontend. Combined with the lack of CSRF tokens, this increases the risk that these endpoints could be triggered from external contexts.

**Remediation:**

Create a require_fetch_context decorator that validates Sec-Fetch-Dest and Sec-Fetch-Mode headers on API endpoints. The decorator should check that sec_fetch_dest is 'empty' or blank and sec_fetch_mode is 'cors', 'same-origin', 'no-cors', or blank. Apply this decorator to all API-style endpoints that return non-HTML responses.

---

#### FINDING-110: Session Cookie Name Missing __Host- or __Secure- Prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS Sections** | 3.3.1, 3.3.3 |
| **Files** | `v3/server/main.py:30-44, 36-38, 44-46`&lt;br&gt;`v3/server/pages.py:70` |
| **Source Reports** | 3.3.1.md, 3.3.3.md |
| **Related** | - |

**Description:**

Quart (and Flask) default the session cookie name to 'session'. ASVS 3.3.1 requires that if the __Host- prefix is not used, the __Secure- prefix must be used. Neither prefix is configured anywhere in the provided application code. The __Secure- prefix instructs browsers to only send the cookie over HTTPS and requires the Secure attribute. The __Host- prefix additionally restricts the cookie to the exact host and root path, preventing subdomain attacks. Without the __Secure- or __Host- prefix, the browser does not enforce prefix-based cookie protections. Combined with the missing Secure attribute, this means no browser-enforced HTTPS-only transmission, potential for subdomain cookie injection attacks, and cookies could be overwritten by a less-secure subdomain.

**Remediation:**

Use __Host- prefix for maximum cookie security. The __Host- prefix requires: Secure attribute, Path=/, and no Domain attribute. Example: app.config['SESSION_COOKIE_NAME'] = '__Host-steve_session'; app.config['SESSION_COOKIE_SECURE'] = True; app.config['SESSION_COOKIE_PATH'] = '/'; Do NOT set SESSION_COOKIE_DOMAIN (required for __Host- prefix). Alternative: Use __Secure- prefix (less restrictive).

---

#### FINDING-111: No Explicit HttpOnly Configuration on Session Cookie

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.3.4 |
| **Files** | `v3/server/main.py:42` |
| **Source Reports** | 3.3.4.md |
| **Related** | - |

**Description:**

The application does not explicitly configure session cookie security attributes (SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SECURE, SESSION_COOKIE_SAMESITE) anywhere in the auditable codebase. The asfquart.construct() call is the sole application factory, and no cookie attribute configuration follows it. While Quart (based on Flask's API) defaults SESSION_COOKIE_HTTPONLY to True, the asfquart wrapper layer is not available for review and could potentially override this default. ASVS 3.3.4 requires verification that HttpOnly is set — this cannot be verified from the provided code. If HttpOnly is not set, a cross-site scripting vulnerability anywhere in the application could be leveraged to steal session tokens via document.cookie.

**Remediation:**

Explicitly configure session cookie security attributes after app construction in main.py: app.config['SESSION_COOKIE_HTTPONLY'] = True; app.config['SESSION_COOKIE_SECURE'] = True; app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'; app.config['SESSION_COOKIE_NAME'] = '__Host-session' (Cookie prefix for additional protection).

---

#### FINDING-112: No Cookie Size Validation Control

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.3.5 |
| **Files** | `v3/server/pages.py:63-94, 73-78, 121-128, 356, 519` |
| **Source Reports** | 3.3.5.md |
| **Related** | - |

**Description:**

The application has no mechanism to validate or enforce the 4096-byte cookie size limit. All session cookie management is delegated to the Quart/asfquart framework with no application-level guard. While the current session payload (uid, fullname, email, flash messages) is likely small enough, there is no defensive control preventing oversized cookies if session data grows (e.g., additional session attributes, accumulated data from framework internals, or future code changes). If the session cookie exceeds 4096 bytes (through future code changes, framework overhead growth, or unforeseen session data accumulation), the browser will silently discard it. The user's session would effectively be invalidated, preventing authentication and use of all protected functionality. This is a denial-of-service condition against individual users.

**Remediation:**

Implement middleware that validates cookie size before the response is sent using @APP.after_request. Check Set-Cookie headers for cookies exceeding 4096 bytes and take corrective action (clear session, log, alert). Add after_request middleware to log warnings when Set-Cookie headers approach 4096 bytes. Document session storage architecture and cap flash message content length to prevent edge cases.

---

#### FINDING-113: Reflected XSS via URL Path Parameters in Error Pages

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.2 |
| **Files** | `v3/server/templates/e_bad_eid.ezt`&lt;br&gt;`v3/server/templates/e_bad_iid.ezt`&lt;br&gt;`v3/server/pages.py:172` |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-114 |

**Description:**

Error templates e_bad_eid.ezt and e_bad_iid.ezt render URL path parameters (eid and iid) directly without HTML escaping. When a user visits an invalid election or issue URL, Quart URL-decodes the path parameter and the load_election decorator assigns it to result.eid or result.iid, which is then rendered as raw HTML in the 404 error page. An attacker can craft URLs containing HTML/JavaScript that, when clicked by authenticated users, execute in their browser session.

**Remediation:**

Apply [format "html"] to error template outputs. In e_bad_eid.ezt: The Election ID ([format "html"][eid][end]) does not exist. In e_bad_iid.ezt: The Issue ID ([format "html"][iid][end]) does not exist. Apply same fix to e_bad_pid.ezt if it exists.

---

#### FINDING-114: Reflected XSS via Flash Messages Containing User-Provided Input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Sections** | 3.2.2 |
| **Files** | `v3/server/pages.py:459, 521, 543, 427, 435, 73-77` |
| **Source Reports** | 3.2.2.md |
| **Related** | FINDING-001, FINDING-002, FINDING-003, FINDING-004, FINDING-022, FINDING-028, FINDING-031, FINDING-091, FINDING-113 |

**Description:**

Multiple flash messages interpolate user-provided input (form.title, iid from form keys) directly into message strings without HTML escaping. Flash messages are stored in the session via quart.flash() and retrieved via get_flashed_messages() in basic_info(), then rendered as raw HTML in templates. For title-based vectors, an admin submitting a form with HTML in the title field will see that HTML executed when the success message is displayed. For iid-based vectors (e.g., in do_vote_endpoint), a crafted form key like 'vote-&lt;img src=x onerror="alert(1)"&gt;' directly injects into the flash message when an invalid issue ID error occurs.

**Remediation:**

Option 1 - Server-side escaping in pages.py: import html; await flash_success(f'Created election: {html.escape(form.title)}'). Option 2 - Template-side escaping: &lt;div class="alert alert-[flashes.category]"&gt;[format "html"][flashes.message][end]&lt;/div&gt;. Option 1 is preferred to ensure all flash messages are safe by default.

---

#### FINDING-115: Shared Utility Functions Declared in Global Scope Without Namespace Isolation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.2.3 |
| **Files** | `v3/server/static/js/steve.js:30-73` |
| **Source Reports** | 3.2.3.md |
| **Related** | - |

**Description:**

The shared utility file steve.js declares three functions at global scope without namespace isolation or strict mode enforcement. These functions are accessible as properties of the window object, making them vulnerable to DOM clobbering attacks where malicious HTML elements with matching id or name attributes could shadow these function references. An authorized committer can inject HTML elements with matching IDs/names through issue descriptions, which are rendered as raw HTML. This can cause denial of service for election management operations by preventing form submissions when the clobbered references are accessed.

**Remediation:**

Wrap steve.js in an IIFE with 'use strict' and expose functions through a namespace object (e.g., SteVe.showModal()). Add type checking with instanceof to verify elements returned by getElementById are of expected types (HTMLElement, HTMLFormElement, HTMLButtonElement, etc.) before using them.

---

#### FINDING-116: Inline Scripts in Management Templates Lack Namespace Isolation and Strict Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.2.3 |
| **Files** | `v3/server/templates/manage.ezt`&lt;br&gt;`v3/server/templates/manage-stv.ezt`&lt;br&gt;`v3/server/templates/admin.ezt` |
| **Source Reports** | 3.2.3.md |
| **Related** | - |

**Description:**

Management templates (manage.ezt, manage-stv.ezt, admin.ezt) contain inline JavaScript that declares multiple functions and variables at global scope without namespace isolation or strict mode. This creates pollution of the global namespace and makes these functions vulnerable to DOM clobbering attacks. The templates render issue descriptions as raw HTML, allowing injection of elements with matching IDs/names. While vote-on.ezt properly wraps its script in an IIFE with 'use strict', the management templates do not use this pattern despite handling equally sensitive operations and rendering the same unsanitized issue descriptions.

**Remediation:**

Wrap all template inline scripts in IIFEs with strict mode, matching the pattern already used in vote-on.ezt. Only expose to HTML onclick handlers via window if needed: window.toggleDescription = toggleDescription; window.openAddIssueModal = openAddIssueModal; etc.

---

#### FINDING-117: No Type or Null Checking on document.getElementById() Results Across All Client-Side JavaScript

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.2.3 |
| **Files** | `v3/server/static/js/steve.js:31, 42, 49`&lt;br&gt;`v3/server/templates/manage.ezt`&lt;br&gt;`v3/server/templates/vote-on.ezt` |
| **Source Reports** | 3.2.3.md |
| **Related** | - |

**Description:**

Throughout the codebase, document.getElementById() is called without subsequent null or type checking. The return value is immediately used with property access (.value, .classList, .innerHTML) without verifying the returned element exists or is of the expected type. This creates vulnerability to DOM clobbering where an injected element of unexpected type could cause silent failures or type errors. Issue descriptions rendered as raw HTML may contain elements with id attributes that collide with IDs used by the application (e.g., id='csrf-token', id='vote-&lt;iid&gt;', id='issueTitle'). If a clobbered element of different type is returned, accessing properties like .value returns undefined rather than the expected string, causing silent data corruption or TypeError.

**Remediation:**

Implement a safe element lookup utility function that performs null and type checking. Example: function safeGetElement(id, expectedType) { const el = document.getElementById(id); if (!el) { console.error(`Element not found: #${id}`); return null; } if (expectedType && !(el instanceof expectedType)) { console.error(`Element #${id} is ${el.constructor.name}, expected ${expectedType.name}`); return null; } return el; }

---

#### FINDING-118: Missing Strict-Transport-Security Header on All Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 3.4.1, 3.7.4, 3.1.1 |
| **Files** | `v3/server/main.py:31-47`&lt;br&gt;`v3/server/pages.py`&lt;br&gt;`v3/server/config.yaml.example`&lt;br&gt;`v3/ARCHITECTURE.md` |
| **Source Reports** | 3.4.1.md, 3.7.4.md, 3.1.1.md |
| **Related** | - |

**Description:**

The application supports TLS configuration but never sets the `Strict-Transport-Security` header. This is a Type A gap — TLS is available but HSTS enforcement does not exist. Even when TLS is configured: (1) No HSTS header is sent to instruct browsers to always use HTTPS. (2) No HTTP→HTTPS redirect is configured. (3) No mechanism ensures the application behaves correctly (warns or blocks) when accessed over plain HTTP. (4) In ASGI mode (`run_asgi()`, line 96), TLS is delegated entirely to the reverse proxy with no application-level verification. Users connecting over HTTP (e.g., first visit, downgrade attack, misconfigured proxy) transmit authentication cookies and session data in plaintext. Election data and voter identity are exposed to network-level attackers.

**Remediation:**

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

---

#### FINDING-119: Complete Absence of X-Content-Type-Options Header

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-693 |
| **ASVS Sections** | 3.4.4 |
| **Files** | `v3/server/main.py:28-43`&lt;br&gt;`v3/server/pages.py:134, 144, 180, 259, 299, 323, 353, 359, 365, 400, 423, 445, 463, 486, 511, 531, 540, 548, 553-562, 565-566, 570-571, 653-654, 92-112` |
| **Source Reports** | 3.4.4.md |
| **Related** | FINDING-108 |

**Description:**

The application does not set the 'X-Content-Type-Options: nosniff' header on any HTTP response. No global middleware, after-request handler, or framework configuration was found that would inject this header. All 21+ routes return responses without this protection. This allows browsers to MIME-sniff responses and interpret content differently than the declared Content-Type, potentially executing attacker-controlled content as active scripts. The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serving user-associated documents presents the highest risk, as documents served as text/plain could be sniffed and executed as text/html containing JavaScript. The /static/&lt;path:filename&gt; endpoint serving CSS/JS has weakened Cross-Origin Read Blocking (CORB) protection. In the context of a voting system, MIME-sniffing XSS could lead to session hijacking or vote manipulation.

**Remediation:**

Primary Fix: Add a global after_request hook in the application factory (main.py create_app() function) that sets the X-Content-Type-Options: nosniff header on every response. Secondary Fix (Defense-in-Depth): Explicitly set the header on manually constructed Response objects in raise_404() function. The after_request hook approach is preferred because it provides single point of enforcement and cannot be forgotten when new routes are added.

---

#### FINDING-120: Missing Referrer-Policy Header on All Application Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 3.4.5 |
| **Files** | `v3/server/main.py:31-47`&lt;br&gt;`v3/server/pages.py:125-602` |
| **Source Reports** | 3.4.5.md |
| **Related** | - |

**Description:**

The application does not set a Referrer-Policy HTTP response header on any responses, nor is there evidence of HTML meta tag configuration in the provided code. This violates ASVS requirement 3.4.5 and exposes sensitive election identifiers, issue IDs, and document names in URL paths to third-party services via the browser's Referer header. When users navigate to sensitive pages (e.g., /vote-on/abc123 or /manage-stv/abc123/issue456), the HTML response is rendered without a Referrer-Policy header. If any page contains links to third-party resources or the user clicks an external link, the browser sends the full URL including the path (election ID, issue ID, document name) in the Referer header to the third party. This allows third-party services to learn internal election identifiers and navigation patterns.

**Remediation:**

Add a global after_request handler that sets Referrer-Policy on all responses. For an election system, 'strict-origin-when-cross-origin' (minimum) or 'no-referrer' (strictest) is recommended: response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'. For maximum protection (recommended for a voting system): response.headers['Referrer-Policy'] = 'no-referrer'. Alternatively, if templates are controlled, a fallback HTML meta tag can be added in the base template: &lt;meta name="referrer" content="strict-origin-when-cross-origin"&gt;

#### FINDING-121: Missing Content-Security-Policy Header with Violation Reporting Directive

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.4.7, 3.1.1 |
| **Files** | `v3/server/main.py:29-40`, `v3/server/pages.py:135-653` |
| **Source Reports** | 3.4.7.md, 3.1.1.md |
| **Related Findings** | - |

**Description:**

The application does not configure a Content-Security-Policy header with a violation reporting directive (report-uri or report-to) anywhere in the codebase. No CSP header is set at the application level, and there is no middleware or after-request hook that would add one with reporting capabilities. This results in: (1) No CSP enforcement - browser applies no restrictions on script sources, style sources, frame ancestors, or other content policies, leaving the application exposed to XSS and content injection attacks; (2) No violation reporting - security team has no visibility into policy violations, cannot detect attack attempts, and cannot identify misconfigured CSP directives; (3) No monitoring baseline - cannot establish a CSP in report-only mode first to test policies before enforcement.

**Remediation:**

In main.py create_app(), add after_request handler:
```python
def create_app():
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)

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
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=()'
        )
        return response

    import pages
    import api
    return app
```

---

#### FINDING-122: Missing Cross-Origin-Opener-Policy Header on All HTML Responses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.4.8 |
| **Files** | `v3/server/main.py:32-47`, `v3/server/pages.py:659`, `v3/server/pages.py:125`, `v3/server/pages.py:133`, `v3/server/pages.py:222`, `v3/server/pages.py:280`, `v3/server/pages.py:320`, `v3/server/pages.py:343`, `v3/server/pages.py:551`, `v3/server/pages.py:559`, `v3/server/pages.py:567`, `v3/server/pages.py:575` |
| **Source Reports** | 3.4.8.md |
| **Related Findings** | - |

**Description:**

The application does not set the Cross-Origin-Opener-Policy (COOP) header on any HTTP response that renders HTML content. This leaves all document-rendering responses vulnerable to cross-origin window handle attacks such as tabnabbing and frame counting. An attacker-controlled page opened from the voting application can navigate the original tab to a phishing page mimicking the voting UI, potentially capturing credentials or manipulating vote submissions. Cross-origin pages can also enumerate browsing contexts to infer voting behavior, undermining the system's anonymity goals. Without COOP, the window.opener property leaks a reference across origins, enabling cross-origin state inspection.

**Remediation:**

Add a global after_request hook in the application factory to set the Cross-Origin-Opener-Policy header on all HTML responses. In v3/server/main.py, inside create_app(), add an after_request handler that checks content type and sets 'Cross-Origin-Opener-Policy: same-origin' for text/html responses. Also update the raise_404 function in v3/server/pages.py to include the header on manual responses. Use same-origin as the default directive. If the application requires popup interactions (e.g., OAuth flows using popups), use same-origin-allow-popups instead. Given the ASF OAuth flow appears to use redirects rather than popups, same-origin is the appropriate choice.

---

#### FINDING-123: JSON Endpoints Lack Explicit Content-Type Validation (Incidental Protection Only)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 3.5.2 |
| **Files** | `v3/server/pages.py:88-108`, `v3/server/pages.py:368-372`, `v3/server/pages.py:374-378` |
| **Source Reports** | 3.5.2.md |
| **Related Findings** | - |

**Description:**

JSON endpoints use 'quart.request.get_json()' without the 'force=True' parameter, which incidentally requires 'Content-Type: application/json'. This Content-Type is not CORS-safelisted, so it forces a preflight check. However, this protection is incidental, not intentional - the code does not explicitly validate the Content-Type header as a security control. This protection is fragile and could be accidentally removed during refactoring (e.g., by adding 'force=True' or adding None checks). The error handling returns unhandled 500 exceptions rather than proper 403/415 responses.

**Remediation:**

Make the Content-Type requirement explicit by adding explicit validation that checks if 'application/json' is in the Content-Type header before processing. Return proper 415 (Unsupported Media Type) error for invalid Content-Type. Add validation that the JSON body is not None and return 400 for invalid JSON. This makes the security control explicit and prevents accidental removal during refactoring.

---

#### FINDING-124: Systemic Absence of Cross-Origin Resource Protection Headers and Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.5.8 |
| **Files** | `v3/server/pages.py:all endpoints` |
| **Source Reports** | 3.5.8.md |
| **Related Findings** | - |

**Description:**

The application has no global mechanism — neither middleware, after_request hook, nor per-endpoint logic — to set Cross-Origin-Resource-Policy response headers or validate Sec-Fetch-* request headers on any response. This is a systemic architectural gap affecting all 15+ authenticated endpoints. ASVS 3.5.8 requires one of these mechanisms; neither is present. No browser-enforced cross-origin resource blocking exists on any authenticated response. Authenticated HTML pages can be iframed by malicious sites (clickjacking vector; no X-Frame-Options visible either). Cross-origin scripts can probe authenticated endpoints for timing/error-based information disclosure. The application relies solely on Same-Origin Policy, which does not prevent resource loading (only reading in some contexts).

**Remediation:**

Implement global @APP.after_request middleware that sets Cross-Origin-Resource-Policy: same-origin on all responses. Add X-Frame-Options: DENY and X-Content-Type-Options: nosniff headers. Create a validate_sec_fetch() utility function that checks Sec-Fetch-Site (reject if not 'same-origin', 'same-site', or 'none') and Sec-Fetch-Mode (reject 'no-cors' for state-changing endpoints). Apply validation as a decorator to sensitive endpoints. Implement Content-Security-Policy with frame-ancestors directive.

---

#### FINDING-125: Complete Absence of External URL Navigation Warning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.7.3 |
| **Files** | `v3/server/pages.py:52-59`, `v3/server/pages.py:349-350` |
| **Source Reports** | 3.7.3.md |
| **Related Findings** | - |

**Description:**

The application has no mechanism whatsoever to warn users before navigating to URLs outside the application's control. There is no interstitial warning page, no client-side JavaScript intercept for external links, and no server-side redirect proxy. The rewrite_description() function injects unescaped HTML into the page, allowing arbitrary HTML including external links to be rendered directly to voters without any warning or cancellation option. An election administrator can create an issue with external links in the description, and voters clicking these links will navigate directly to external URLs with no interstitial warning and no option to cancel. This could be used for phishing attacks that mimic the voting application, potentially capturing credentials or manipulating vote decisions.

**Remediation:**

Implement a three-part solution: (1) Server-side redirect proxy route that validates URLs and shows an interstitial warning page for external domains; (2) Interstitial template with explicit warning text, target domain display, and both 'Continue' and 'Cancel' options; (3) HTML escaping in rewrite_description() to prevent arbitrary HTML injection, and client-side JavaScript to intercept external link clicks and redirect through the warning proxy. The proxy should maintain an ALLOWED_DOMAINS list and automatically pass through same-domain links while showing warnings for all external navigation.

---

#### FINDING-126: Complete Absence of Browser Security Feature Detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 3.7.5 |
| **Files** | `v3/server/static/js/steve.js:1-76` |
| **Source Reports** | 3.7.5.md |
| **Related Findings** | - |

**Description:**

The application's common JavaScript utility file contains zero browser security feature detection. The application implicitly depends on modern browser features (Bootstrap 5 Modal API, ES6 template literals, classList API, const declarations) but never checks whether the browser supports the security features the application relies upon. For a voting system, the browser must support Content Security Policy (CSP), Strict-Transport-Security, SameSite cookie attribute, Secure cookie flag enforcement, and SubtleCrypto/Web Crypto API if any client-side cryptographic operations are used. No feature detection, no user warning, and no access-blocking logic exists anywhere in the provided client-side code. Users accessing the voting application with an outdated browser that does not support CSP Level 2, SameSite cookies, or HSTS preloading would receive the page normally with no warning, have server-sent security headers silently ignored, be vulnerable to attacks (XSS, session hijacking) that the security headers were designed to prevent, and have no indication their session is less secure than expected.

**Remediation:**

Add a browser security feature detection module to steve.js that runs on page load. The module should check for: Content Security Policy support (window.SecurityPolicyViolationEvent), Web Cryptography API (window.crypto.subtle), Fetch API with credentials support (window.fetch), HTTPS enforcement (location.protocol), and SameSite cookie support. If critical features are missing, display a warning message to users and optionally disable form submission buttons to block access. Implement the checkBrowserSecurityFeatures() function that creates a visible alert and disables forms when required security features are not supported. Additionally, add a &lt;noscript&gt; tag warning that JavaScript is required for secure operation, document minimum browser requirements in user-facing documentation, create automated tests to verify browser feature detection warnings, implement server-side User-Agent analysis to warn or redirect users on outdated browsers, and implement telemetry to track browser feature support across the user base.

---

#### FINDING-127: HTML Responses Created Without Explicit Charset in Content-Type

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 4.1.1 |
| **Files** | `v3/server/pages.py:764-766`, `v3/server/pages.py:183`, `v3/server/pages.py:211`, `v3/server/pages.py:222`, `v3/server/pages.py:318`, `v3/server/pages.py:390` |
| **Source Reports** | 4.1.1.md |
| **Related Findings** | - |

**Description:**

The `raise_404` function creates explicit HTML responses without specifying a charset parameter in the Content-Type header. It sets `mimetype='text/html'` which produces `Content-Type: text/html` without `; charset=utf-8`. In Werkzeug 3.0+, the Response class no longer automatically appends a charset when only mimetype is supplied. Without an explicit charset declaration, browsers must guess the character encoding, creating a window for character-encoding-based attacks (e.g., UTF-7 XSS in legacy or misconfigured clients, or multi-byte encoding attacks). The rendered templates contain URL-derived values (eid, iid) making this a plausible vector.

**Remediation:**

Change the `raise_404` function to use `content_type='text/html; charset=utf-8'` instead of `mimetype='text/html'`. Example: 
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

#### FINDING-128: No Application-Wide Content-Type Enforcement Mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 4.1.1 |
| **Files** | `v3/server/pages.py`, `v3/server/main.py`, `v3/server/pages.py:93`, `v3/server/pages.py:679` |
| **Source Reports** | 4.1.1.md |
| **Related Findings** | - |

**Description:**

The application has no centralized mechanism to ensure all HTTP responses include a Content-Type header with an appropriate charset parameter. Content-Type correctness is entirely delegated to individual handler implementations and framework defaults. There is no `@APP.after_request` hook that validates or enforces Content-Type headers with charset across all response types. This creates systemic risks: if framework default behavior changes across versions (as happened with Werkzeug 3.0's charset removal), all responses silently lose charset declarations; new endpoints added by developers may omit Content-Type charset without any safety net; error responses generated by `quart.abort()` inherit framework defaults with no override. The application has 22+ response-generating endpoints with no defense-in-depth for Content-Type enforcement.

**Remediation:**

Add an `after_request` hook to enforce Content-Type charset on all text-based responses. Example: 
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
Add this to main.py create_app() or pages.py module level.

---

#### FINDING-129: Application lacks any mechanism to differentiate transport security handling between browser-facing pages and action/API endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 4.1.2 |
| **Files** | `v3/server/main.py:76-82`, `v3/server/pages.py:all route definitions`, `v3/server/config.yaml.example:24-30` |
| **Source Reports** | 4.1.2.md |
| **Related Findings** | - |

**Description:**

The application does not implement any mechanism to differentiate transport security requirements between user-facing browser endpoints and action/API endpoints. All endpoints are treated identically with respect to HTTP/HTTPS handling, creating a vulnerability where action endpoints may silently accept HTTP requests that get redirected to HTTPS by a reverse proxy, masking plaintext data transmission. Configuration explicitly documents TLS as optional with 'leave these two fields blank for plain HTTP'. When a reverse proxy implements blanket HTTP→HTTPS redirect, action endpoints like /do-vote/&lt;eid&gt; are silently redirected instead of rejected. Vote data, session cookies, and election management commands may be transmitted in plaintext without detection.

**Remediation:**

Implement middleware that enforces HTTPS on action/API endpoints and only redirects on browser-facing GET endpoints. Add before_request middleware to check X-Forwarded-Proto when behind reverse proxy. For browser-facing GET endpoints, redirect to HTTPS with 301. For action/API endpoints (POST, or state-changing GET like /do-*), reject with 403 error and do NOT redirect. Additionally, set HSTS headers (Strict-Transport-Security: max-age=31536000; includeSubDomains) for browser clients.

---

#### FINDING-130: State-changing operations use GET method, compounding transport security risk

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 4.1.2 |
| **Files** | `v3/server/pages.py:/do-open/<eid>`, `v3/server/pages.py:/do-close/<eid>` |
| **Source Reports** | 4.1.2.md |
| **Related Findings** | - |

**Description:**

State-changing operations for opening and closing elections are exposed as GET endpoints rather than POST endpoints. This architectural choice compounds the transport security risk because GET requests are more likely to be logged, cached, and automatically redirected by intermediaries, increasing the attack surface for plaintext credential leakage. Election open/close operations are GET endpoints that are especially prone to being logged by proxies, browsers, and intermediaries. Session cookies and election IDs are exposed in the URL and headers. A blanket HTTP→HTTPS proxy redirect for GET requests may execute the state-changing operation after redirect, but authentication cookies were already sent in plaintext on the initial HTTP request. Session tokens leaked in plaintext allow election administration hijacking.

**Remediation:**

Convert state-changing operations to POST method. Change @APP.get('/do-open/&lt;eid&gt;') to @APP.post('/do-open/&lt;eid&gt;') and @APP.get('/do-close/&lt;eid&gt;') to @APP.post('/do-close/&lt;eid&gt;'). HTTPS enforcement will be handled by the before_request middleware recommended in CONTENT_TYPE-3.

---

#### FINDING-131: No Trusted Proxy Configuration or X-Forwarded-* Header Sanitization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 4.1.3 |
| **Files** | `v3/server/main.py:34-53`, `v3/server/main.py:78-95`, `v3/server/main.py:96-113` |
| **Source Reports** | 4.1.3.md |
| **Related Findings** | - |

**Description:**

The application, designed to run behind a reverse proxy via Hypercorn (ASGI), lacks any configuration or middleware to sanitize, validate, or restrict intermediary-set HTTP headers (e.g., X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host). While the application reads user identity from server-side sessions rather than headers, the underlying Quart framework and OAuth redirect flow may implicitly trust these spoofable headers. This creates risks for OAuth redirect manipulation, audit log integrity compromise, and scheme confusion leading to insecure URL generation.

**Remediation:**

Configure trusted proxy handling at the ASGI server level and/or within the application:

1. Option 1: Configure Hypercorn with --forwarded-allow-ips="127.0.0.1,10.0.0.0/8" to only trust forwarded headers from specific proxy IPs

2. Option 2: Add ProxyFixMiddleware in create_app():
```python
from quart.middleware import ProxyFixMiddleware
app.asgi_app = ProxyFixMiddleware(
    app.asgi_app,
    mode="modern",
    trusted_hops=1,
)
```

3. Option 3: Strip dangerous headers in a before_request handler to remove proxy headers that should only be set by trusted infrastructure (X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host, X-Real-IP, X-User-ID, Forwarded)

---

#### FINDING-132: No Per-Message Digital Signatures on Election Lifecycle Transitions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.1.5 |
| **Files** | `v3/server/pages.py:496-517`, `v3/server/pages.py:520-538`, `v3/steve/election.py:269-282`, `v3/steve/election.py:285-296`, `v3/steve/crypto.py:31-41` |
| **Source Reports** | 4.1.5.md |
| **Related Findings** | - |

**Description:**

Election open and close operations are irreversible state machine transitions performed without per-message digital signatures. These endpoints use GET methods for state-changing operations and rely only on session cookie authentication. Opening an election triggers cryptographic key generation and salt assignment; closing permanently ends voting. There is no cryptographic confirmation of administrator intent, no cryptographic binding in audit logs, and the operations are vulnerable to CSRF attacks via link injection, img tags, or browser prefetching. Authorization checking is also incomplete (marked with '### check authz' comments).

**Remediation:**

Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; to POST methods with signed request bodies. Require confirmation signatures from administrators using Ed25519 or similar. Implement: (1) JSON payload containing action, eid, timestamp, and nonce; (2) Administrator signs payload with private key; (3) Server verifies signature against registered admin public key; (4) Validate timestamp freshness (e.g., within 5 minutes) to prevent replay; (5) Check and consume nonce to prevent replay within time window; (6) Log with signature verification confirmation. Add nonce storage infrastructure (Redis or database) for replay protection.

---

#### FINDING-133: No explicit HTTP request body size limits configured, enabling denial-of-service via overly long HTTP messages

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 4.2.1 |
| **Files** | `v3/server/main.py:31-44`, `v3/server/pages.py:403`, `v3/server/pages.py:96`, `v3/server/pages.py:440`, `v3/server/pages.py:504`, `v3/server/pages.py:531` |
| **Source Reports** | 4.2.1.md |
| **Related Findings** | - |

**Description:**

The Quart application does not set `max_content_length` or configure Hypercorn body size limits. The ASVS 4.2.1 parent section explicitly includes "denial of service via overly long HTTP messages" as an attack vector. Multiple POST endpoints accept unbounded request bodies. An authenticated attacker (any committer) can submit arbitrarily large HTTP request bodies that are fully buffered by the framework before reaching handler code. This can exhaust server memory and cause denial of service during an active election, potentially disrupting voting.

**Remediation:**

Set `app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024` (1 MB) in the `create_app()` function in `main.py`. Additionally, configure Hypercorn limits in the ASGI deployment using a hypercorn.toml configuration file with settings for `h11_max_incomplete_size`, `h2_max_concurrent_streams`, and `h2_max_header_list_size`.

---

#### FINDING-134: State-changing operations as GET requests increase HTTP request smuggling attack surface

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 4.2.1 |
| **Files** | `v3/server/pages.py:453-470`, `v3/server/pages.py:475-492` |
| **Source Reports** | 4.2.1.md |
| **Related Findings** | - |

**Description:**

Two state-changing operations (`/do-open/<eid>` and `/do-close/<eid>`) are implemented as GET requests. In the context of ASVS 4.2.1, this is significant because GET requests have simpler message boundary determination (no body parsing) and are therefore the easiest payloads to smuggle through a misconfigured proxy/server chain. A smuggled GET request requires only a request line and minimal headers, making successful exploitation more likely if any infrastructure component mishandles message boundaries. Additionally, the authorization check stubs (`### check authz`) exist but are NOT CALLED, compounding the smuggling risk by removing the ownership check that would limit impact. If HTTP request smuggling is achievable at the infrastructure level (reverse proxy ↔ Hypercorn), any authenticated committer's session could be hijacked to open or close elections they don't own.

**Remediation:**

Convert state-changing operations to POST with CSRF protection. Change `@APP.get('/do-open/<eid>')` to `@APP.post('/do-open/<eid>')` and `@APP.get('/do-close/<eid>')` to `@APP.post('/do-close/<eid>')`. Implement ownership verification by checking if `md.owner_pid != result.uid` and abort with 403 if unauthorized. Add CSRF token validation using `validate_csrf_token(form.get('csrf_token'))` after parsing the form data.

---

#### FINDING-135: No Application-Level HTTP/2 Connection-Specific Header Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.2.3 |
| **Files** | `v3/server/main.py:33-48`, `v3/server/main.py:43`, `v3/server/main.py:77-78`, `v3/server/main.py:91-110`, `v3/server/pages.py:93`, `v3/server/pages.py:441`, `v3/server/pages.py:499`, `v3/server/pages.py:520` |
| **Source Reports** | 4.2.3.md |
| **Related Findings** | - |

**Description:**

The application runs on Hypercorn, which supports HTTP/2 by default when TLS is enabled (via ALPN negotiation) and can support HTTP/3. There is no application-level middleware, Quart extension, or Hypercorn configuration to: (1) Reject incoming HTTP/2/HTTP/3 requests containing prohibited connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade, TE except for trailers), (2) Prevent connection-specific headers from being included in outgoing HTTP/2/HTTP/3 responses, (3) Validate header integrity during HTTP version conversion (e.g., if deployed behind a reverse proxy that downgrades/upgrades HTTP versions). The application relies entirely on the underlying ASGI server (Hypercorn) for HTTP/2 protocol enforcement, with no application-level middleware, validation, or configuration to explicitly enforce ASVS 4.2.3 requirements. In an HTTP/2-to-HTTP/1.1 downgrade proxy scenario, this could enable request smuggling attacks, allowing attackers to bypass authentication/authorization decorators and reach state-changing endpoints without proper session validation.

**Remediation:**

Add ASGI middleware to validate and strip connection-specific headers for HTTP/2/HTTP/3 requests. Create a HTTP2HeaderValidationMiddleware class that rejects HTTP/2+ requests containing connection-specific header fields per RFC 9113 Section 8.2.2 (transfer-encoding, connection, keep-alive, proxy-connection, upgrade). Register the middleware in main.py by wrapping app.asgi_app. Additionally, add a Quart after_request handler to strip connection-specific headers (Transfer-Encoding, Connection, Keep-Alive, Proxy-Connection, Upgrade) from all responses. Configure Hypercorn explicitly for HTTP version handling and document supported versions. Convert state-changing GET endpoints (/do-open/&lt;eid&gt;, /do-close/&lt;eid&gt;) to POST methods to reduce request smuggling impact. Add integration tests validating that HTTP/2 requests with Transfer-Encoding are rejected.

---

#### FINDING-136: No Application-Level CRLF Validation on HTTP Request Headers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.2.4 |
| **Files** | `v3/server/pages.py:114-628`, `v3/server/main.py:90-107` |
| **Source Reports** | 4.2.4.md |
| **Related Findings** | - |

**Description:**

The application has zero middleware, decorators, or configuration that validates incoming HTTP request headers for CR (\r), LF (\n), or CRLF (\r\n) sequences. ASVS 4.2.4 specifically requires this validation for HTTP/2 and HTTP/3 requests. The application supports HTTP/2 when deployed via Hypercorn but does not add any application-layer header validation. The application relies entirely on the underlying ASGI server (Hypercorn) and framework (Quart/Werkzeug) for protocol-level protection, with no defense-in-depth. This becomes critical when HTTP version conversion occurs at a reverse proxy layer where HTTP/2 requests are converted to HTTP/1.1, potentially allowing CRLF characters that pass HTTP/2 binary framing to become injection vectors after protocol downgrade.

**Remediation:**

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

---

#### FINDING-137: Redirect Responses Constructed with URL Path Parameters Without CRLF Sanitization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.2.4 |
| **Files** | `v3/server/pages.py:303`, `v3/server/pages.py:363`, `v3/server/pages.py:413`, `v3/server/pages.py:416`, `v3/server/pages.py:434`, `v3/server/pages.py:455`, `v3/server/pages.py:477`, `v3/server/pages.py:496`, `v3/server/pages.py:521`, `v3/server/pages.py:547`, `v3/server/pages.py:567` |
| **Source Reports** | 4.2.4.md |
| **Related Findings** | - |

**Description:**

Multiple POST and GET endpoints construct redirect Location headers using URL path parameters (eid, or values derived from form input). While the load_election decorator provides database validation that would reject most injected values, not all redirect paths go through this validation, and the application places no explicit CRLF check on data flowing into response headers. The framework-level protection is version-dependent and not verified. If a future code change introduces a redirect path without database validation, header injection becomes possible, with no defense-in-depth against response splitting.

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

Additionally, add an after_request hook to validate all outgoing headers:

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

#### FINDING-138: Unbounded User Input in Flash Messages Creates Potential for Oversized Cookie Header DoS

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 4.2.5 |
| **Files** | `v3/server/pages.py:385-395`, `v3/server/pages.py:424`, `v3/server/pages.py:485`, `v3/server/pages.py:505`, `v3/server/pages.py:369`, `v3/server/pages.py:410`, `v3/server/pages.py:467`, `v3/server/pages.py:489` |
| **Source Reports** | 4.2.5.md |
| **Related Findings** | - |

**Description:**

Multiple endpoints incorporate unsanitized, unbounded user input into session flash messages via `quart.flash()`. If the session uses cookie-based storage (the default for Quart/Flask frameworks), the resulting `Set-Cookie` response header can exceed the browser's cookie size limit (~4KB) or the server's incoming header size limit (~8-16KB for most ASGI servers). When the browser sends back the oversized cookie on subsequent requests, the server rejects every request before reaching application code, resulting in a persistent DoS for that user's session. The vulnerable code paths include: (1) `do_vote_endpoint` extracting unbounded `iid` from form field names (vote-&lt;arbitrary_data&gt;) and passing to flash_danger, (2) `do_create_endpoint` passing unbounded `form.title` to flash_success, (3) `do_add_issue_endpoint` passing unbounded `form.title` to flash_success, and (4) `do_edit_issue_endpoint` passing unbounded `form.title` to flash_success. Data flows from HTTP POST form field names or body fields through extraction without length checks into quart.flash(), then to session storage and Set-Cookie response headers, ultimately causing the browser to send oversized Cookie headers that the server rejects with persistent 431 errors.

**Remediation:**

Apply length limits at three levels: (1) Truncate user input before including in flash messages using a MAX_FLASH_INPUT_LEN constant (e.g., 200 characters) - truncate iid and title values before passing to flash functions. (2) Enforce maximum request body size via Quart configuration by setting APP.config['MAX_CONTENT_LENGTH'] = 64 * 1024 (64KB max request body). (3) Add server-side input length validation for form fields with constants like MAX_TITLE_LEN = 500 and MAX_DESCRIPTION_LEN = 5000, rejecting requests that exceed these limits with HTTP 400 errors. Example code provided shows truncation: `safe_iid = iid[:MAX_FLASH_INPUT_LEN]` and `title = form.title[:MAX_FLASH_INPUT_LEN]` before flash calls, plus validation: `if len(form.get('title', '')) > MAX_TITLE_LEN: quart.abort(400, 'Title too long')`.

---

#### FINDING-139: No WebSocket Origin Header Validation Infrastructure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 4.4.2 |
| **Files** | `v3/server/main.py:36-51` |
| **Source Reports** | 4.4.2.md |
| **Related Findings** | - |

**Description:**

The application lacks any infrastructure for validating the `Origin` header during WebSocket handshakes. The `create_app()` function, which serves as the sole application configuration entry point, establishes zero WebSocket security controls: (1) No allowed-origins list is defined in application configuration, (2) No `before_websocket` or `before_request` middleware is registered to inspect the `Origin` header, (3) The underlying framework (`asfquart`, built on Quart) does not validate WebSocket Origin headers by default, (4) All WebSocket endpoints defined in `pages` and `api` modules inherit this unprotected configuration. This represents a Type A gap — no control exists at any layer. An attacker can perform Cross-Site WebSocket Hijacking (CSWSH) where an authenticated user visiting a malicious page would have their browser establish a WebSocket connection to the voting application using their existing session cookies, allowing the attacker to submit or modify votes on behalf of the victim, read election state or results in real-time, bypass CSRF protections, and compromise the integrity and confidentiality of the voting process.

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

#### FINDING-140: Complete Absence of File Handling Documentation for Document Serving Feature

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 5.1.1 |
| **Files** | `v3/docs/schema.md`, `v3/ARCHITECTURE.md:18`, `v3/server/pages.py:562-580` |
| **Source Reports** | 5.1.1.md |
| **Related Findings** | - |

**Description:**

The application has an active document-serving feature with two components: (1) A route GET /docs/&lt;iid&gt;/&lt;docname&gt; that serves files from the DOCSDIR / iid directory, and (2) A rewrite_description() function that converts doc:filename tokens in issue descriptions into clickable download links. Neither the schema.md, ARCHITECTURE.md, nor any other provided documentation defines: permitted file types for documents associated with issues, expected file extensions (e.g., .pdf, .txt, .md), maximum file size (including unpacked size for archives), how files are made safe for end-user download and processing (Content-Disposition, Content-Type validation, anti-virus scanning), or behavior when a malicious file is detected. Without documented file handling requirements, developers have no specification to implement or test against. This has directly led to the missing validation in serve_doc(). An attacker who can place files in the docs directory (or exploit any future upload feature) could serve HTML files with embedded JavaScript (stored XSS via Content-Type sniffing), executable files disguised as documents, or excessively large files causing storage exhaustion.

**Remediation:**

Create a file handling specification document and reference it from ARCHITECTURE.md. The specification should define: Permitted file types (PDF, plain text, Markdown), Expected extensions (.pdf, .txt, .md), Maximum file size (10 MB per file, 50 MB per issue), Maximum unpacked size (N/A - archives not accepted), Safety measures (file extension validation against allowlist, explicit Content-Type header based on extension mapping, Content-Disposition: attachment for non-text files, X-Content-Type-Options: nosniff on all responses, rejection of unrecognized extensions with 403), and Malicious file behavior (logging and HTTP 403 for files failing extension validation, MIME type validation for uploads, server logging of denied access attempts with user ID and filename).

---

#### FINDING-141: Issue Description Doc-Link Rewriting Generates Unvalidated File References

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 5.1.1 |
| **Files** | `v3/server/pages.py:52-58` |
| **Source Reports** | 5.1.1.md |
| **Related Findings** | - |

**Description:**

The rewrite_description() function parses issue descriptions and converts doc:filename patterns into HTML anchor tags pointing to /docs/{iid}/{filename}. The filename extracted from the description is not validated against any allowlist of permitted file types or extensions before being embedded in the HTML link. The regex r'doc:([^\s]+)' captures any non-whitespace sequence, meaning filenames like ../../../etc/passwd, evil.html, or payload.exe would be turned into clickable links. While the serve_doc endpoint's send_from_directory provides basic path traversal protection, the absence of documented permitted file types means there is no basis for validation at either the link-generation or file-serving layer. This generates links to file types that should not be served (executables, HTML, etc.) and creates a social engineering vector where attackers with issue-editing privileges can embed links to dangerous file types.

**Remediation:**

Validate the filename in rewrite_description() against the documented allowlist. Define ALLOWED_DOC_EXTENSIONS constant, extract file extension using pathlib.Path().suffix, check extension against allowlist, validate that filename does not contain path separators ('/' or '\'), return placeholder text '[invalid document reference: {filename}]' for invalid references, and only generate &lt;a&gt; tags for validated filenames. Example implementation: extract extension, check against allowlist, validate no path separators, reject invalid references with placeholder text.

---

#### FINDING-142: Files Served to Voters Undergo No Antivirus or Malicious Content Scanning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 5.4.3 |
| **Files** | `v3/server/pages.py:638-658`, `v3/server/pages.py:52`, `v3/server/pages.py:308` |
| **Source Reports** | 5.4.3.md |
| **Related Findings** | - |

**Description:**

The document serving endpoint allows authenticated voters to download files associated with election issues. While the endpoint implements proper authentication and authorization checks, it completely bypasses any antivirus or malicious content scanning. Files are served directly from the filesystem without inspection, creating a potential vector for malware distribution to voters. An election administrator can place a document containing malware in DOCSDIR/&lt;iid&gt;/, reference it in an issue description, and it will be served to voters without detection. In an election system context, compromised voter machines could lead to vote manipulation or credential theft.

**Remediation:**

Integrate antivirus scanning at the point where files are placed into DOCSDIR (upload time) and optionally at serve time. Implement a scan_file() function using ClamAV (clamdscan) that scans files before serving. The function should return True if clean, raise AVScanError if malicious or scan fails. Add the scanning check in the serve_doc handler before calling send_from_directory. Additionally, implement scanning at the point of file ingestion (upload or placement), reject files that fail scanning before they reach the serving directory, and consider periodic background scans of DOCSDIR to catch newly-identified threats. Complete the TODO comment for DOCNAME validation with explicit path validation. Consider adding file type allowlisting for serve_doc.

---

#### FINDING-143: Complete absence of documentation defining authentication defense controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.1.1 |
| **Files** | `v3/TODO.md`, `v3/docs/schema.md`, `v3/server/pages.py`, `v3/server/main.py:33`, `v3/server/main.py:39-43` |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

ASVS 6.1.1 requires application documentation to explicitly define how rate limiting, anti-automation, and adaptive response controls defend against credential stuffing and password brute force, and how they prevent malicious account lockout. A thorough review of all provided documentation and code reveals no documentation whatsoever addressing these concerns. The application delegates authentication to Apache OAuth (oauth.apache.org) but provides no documentation explaining what brute force protections the OAuth provider implements, whether there are retry limits on the OAuth callback flow, how the application would detect or respond to credential stuffing, or how malicious account lockout is prevented at the identity provider level.

**Remediation:**

Create an authentication security document (e.g., v3/docs/authentication-security.md) that addresses: 1) Authentication flow and OAuth provider's brute force protections, 2) Rate limiting policies for login attempts, vote submission, and API endpoints including implementation details, 3) Anti-automation controls such as CAPTCHA/challenge requirements and bot detection mechanisms, 4) Adaptive response policies describing actions taken after N failed attempts and escalation procedures, 5) Account lockout prevention including lockout policy, anti-lockout measures, and election-specific protections against voter lockout during active elections, 6) Configuration details including where settings are configured, how to modify thresholds, and monitoring/alerting for attack detection.

---

#### FINDING-144: No rate limiting or throttling on vote submission and state-changing endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.1.1 |
| **Files** | `v3/server/pages.py:367`, `v3/server/pages.py:408`, `v3/server/pages.py:429`, `v3/server/pages.py:448` |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

The vote submission and election state-change endpoints have no rate limiting or throttling controls, and no documentation exists describing how such controls should be configured. An authenticated attacker (any committer) could submit rapid automated requests causing database contention in SQLite (single-writer model) or abuse election state changes. The do_vote_endpoint(), do_create_endpoint(), do_open_endpoint(), and do_close_endpoint() functions process requests immediately without any rate limiting checks or anti-automation controls. State-changing GET requests are particularly concerning as they combine the absence of CSRF protection with the absence of rate limiting, making automated abuse trivial.

**Remediation:**

1) Implement rate limiting on sensitive endpoints using a library like quart_rate_limiter (e.g., @rate_limit(1, timedelta(seconds=5)) for vote submission to allow 1 vote per 5 seconds), 2) Document the rate limiting configuration in the authentication security document referenced in Finding AUTH_RATE_LIMIT-001, 3) Add similar rate limiting to election state-change endpoints (e.g., @rate_limit(5, timedelta(minutes=1)) to allow 5 state changes per minute), 4) Convert state-changing GET endpoints to POST with CSRF protection as acknowledged in TODO.md.

---

#### FINDING-145: No Throttling on Vote Submission Endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 6.3.1 |
| **Files** | `v3/server/pages.py:290-323`, `v3/steve/election.py:265` |
| **Source Reports** | 6.3.1.md |
| **Related Findings** | - |

**Description:**

The vote submission endpoint (POST /do-vote/&lt;eid&gt;) has no throttling mechanism. An authenticated attacker or compromised account could: (1) Submit rapid automated vote changes to create timing side-channels, (2) Flood the endpoint to cause resource exhaustion as each vote triggers expensive cryptographic operations (crypto.gen_vote_token() + crypto.create_vote() with Argon2 key derivation and Fernet encryption), (3) Abuse the 'last vote wins' behavior for race-condition vote manipulation. The add_vote() method in election.py performs multiple cryptographic operations per call without any throttling. No rate limiting, submission cooldown, or duplicate detection exists at the HTTP layer.

**Remediation:**

Add endpoint-specific rate limiting for the vote submission endpoint using @rate_limit decorator (e.g., max 5 vote submissions per minute per user). Implement submission cooldown check: track last vote timestamp per user per election and enforce minimum 10-second wait between submissions. Add duplicate detection at the HTTP layer to prevent rapid resubmission of identical votes.

---

#### FINDING-146: No Rate Limiting on Resource Identifier Endpoints — Brute Force Enumeration Unprotected

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 6.6.3 |
| **Files** | `v3/server/pages.py:161`, `v3/server/pages.py:180`, `v3/server/pages.py:217`, `v3/server/pages.py:306`, `v3/server/pages.py:362`, `v3/server/pages.py:418`, `v3/server/pages.py:436`, `v3/server/pages.py:536` |
| **Source Reports** | 6.6.3.md |
| **Related Findings** | - |

**Description:**

The application lacks any rate limiting mechanism on election and issue identifier lookup endpoints. Despite requiring authentication via ASF OAuth for all sensitive endpoints, no brute-force protection exists anywhere in the codebase. The load_election and load_election_issue decorators perform direct database lookups without tracking failed attempts, implementing delays, or enforcing request limits. An authenticated attacker can send unlimited rapid requests to endpoints like /manage/&lt;eid&gt; with sequential or random EID guesses, using the 404/200 response codes as an oracle to discover valid identifiers. Combined with the 40-bit entropy issue (ASVS-663-SEV-001), systematic enumeration becomes tractable. ASVS 6.6.3 explicitly requires rate limiting as a defense against brute force of out-of-band codes.

**Remediation:**

Implement rate limiting on election/issue lookup endpoints to prevent brute force enumeration attacks. Two recommended approaches: Option 1: Use quart-rate-limiter library with @rate_limit(10, timedelta(minutes=1)) decorator (10 requests/minute per IP). Option 2: Implement custom tracking with exponential backoff including is_rate_limited() check, record_failed_lookup() tracking, and 429 responses for rate-limited requests. Additionally, complete the missing authorization checks marked with '### check authz' comments to prevent unauthorized access to discovered elections.

---

#### FINDING-147: State-Changing Operations via GET Bypass Session CSRF Protections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 7.2.1, 7.5.3, 7.6.2 |
| **Files** | `v3/server/pages.py:448`, `v3/server/pages.py:468`, `v3/server/pages.py:84`, `v3/server/pages.py:437-453`, `v3/server/pages.py:456-472` |
| **Source Reports** | 7.2.1.md, 7.5.3.md, 7.6.2.md |
| **Related Findings** | - |

**Description:**

Two critical state-changing operations (opening and closing elections) use GET methods. While session tokens are verified on the backend via @asfquart.auth.require({R.committer}), GET requests are inherently more vulnerable to cross-site request forgery because they can be triggered by image tags, link prefetching, or redirects without user interaction. Combined with the placeholder CSRF token (basic.csrf_token = 'placeholder' at line 84), a verified session can be abused through external trigger mechanisms. An attacker can trick an authenticated user into opening or closing an election without their knowledge. This is particularly dangerous with automatic session creation (ASVS-762-MED-001) where third-party content can trigger both session creation and state changes in a single redirect chain.

**Remediation:**

Change /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; to POST methods. Replace the placeholder CSRF token with a cryptographically secure token using secrets.token_urlsafe(32). Store the token in the session and validate it on POST requests. Ensure all state-changing operations use POST methods with CSRF protection. Update templates to use forms with CSRF tokens instead of direct links.

---

#### FINDING-148: Absence of Session Management Risk Analysis and Policy Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.1.1 |
| **Files** | `v3/docs/schema.md`, `v3/ARCHITECTURE.md` |
| **Source Reports** | 7.1.1.md |
| **Related Findings** | - |

**Description:**

ASVS 7.1.1 explicitly requires documentation stating session inactivity timeout value, absolute maximum session lifetime, justification for these values in combination with other controls, and justification for any deviations from NIST SP 800-63B. The project's only documentation file (v3/docs/schema.md) covers database schema in detail but contains no mention of session management policies, session token storage mechanism, session timeout values, SSO interaction considerations, NIST SP 800-63B analysis or deviation justification, or risk analysis for session handling decisions. A risk analysis with documented security decisions related to session handling must be conducted as a prerequisite to implementation and testing.

**Remediation:**

Create a session-management.md document (or equivalent section in existing docs) containing: (1) Session timeout values with justification (recommend 15-minute inactivity timeout and 12-hour absolute lifetime), (2) NIST SP 800-63B compliance section documenting AAL level, re-authentication requirements, and any deviations with justification, (3) SSO interaction documentation covering how SSO session lifetime interacts with application session lifetime and session revocation on SSO logout, (4) Risk analysis documenting threats (unattended workstation, stolen session token) and corresponding mitigations (inactivity timeout, absolute lifetime, HTTPS-only cookies), (5) Justification for timeout values based on voting system sensitivity and operational requirements.

---

#### FINDING-149: Complete Absence of Concurrent Session Limit Policy and Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.1.2 |
| **Files** | `v3/server/pages.py:70-87`, `v3/server/pages.py:547-560`, `v3/server/main.py:39-41` |
| **Source Reports** | 7.1.2.md |
| **Related Findings** | - |

**Description:**

The application has no documented policy, configuration, or code to define or enforce how many concurrent (parallel) sessions are permitted for a single user account. For a voting/election management system where session integrity directly impacts the trustworthiness of votes and administrative actions, this is a significant gap. Missing controls include: (1) No session count tracking—no database table, in-memory store, or external service tracks how many sessions exist per uid, (2) No session limit constant/configuration—no MAX_SESSIONS or equivalent defined, (3) No enforcement action—no code path to revoke oldest sessions, deny new login, or notify the user, (4) No session listing endpoint—users cannot view their active sessions, (5) No session revocation endpoint—users cannot terminate other active sessions, (6) No documentation—no policy defines intended concurrent session behavior.

**Remediation:**

1. Document the policy defining: (a) Maximum concurrent sessions per account (e.g., 3 for regular users, 1 during active voting), (b) Behavior when the limit is reached (e.g., terminate oldest session, or deny new login), (c) Any role-specific limits. 2. Implement session tracking using a server-side session registry that tracks active sessions per user with timestamps, including methods to register_session, get_active_sessions, and revoke_session. 3. Integrate into authentication flow—check session count at login and at basic_info(). 4. Add session management UI—populate the existing /settings page with session listing and revocation controls.

---

#### FINDING-150: Session Creation Without User Consent or Explicit Action

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 7.6.2 |
| **Files** | `v3/server/main.py:37-40`, `v3/server/pages.py:136-165` |
| **Source Reports** | 7.6.2.md |
| **Related Findings** | - |

**Description:**

The application does not enforce explicit user consent or action before creating new application sessions. When a user's application session expires but their IdP session remains active, visiting any protected endpoint triggers an automatic redirect chain that silently re-establishes an application session without user interaction. The OAuth integration lacks prompt parameters (prompt=login or prompt=consent) and does not implement an interstitial login page, allowing passive authentication where sessions are created without the subscriber's explicit awareness or consent. ASVS 7.6.2 requires that creation of a session requires either the user's consent or an explicit action. This violates NIST SP 800-63C guidance and makes application session timeout policies ineffective. Combined with state-changing GET endpoints, third-party content can trigger both session creation and state changes in a single redirect chain.

**Remediation:**

1. Add 'prompt=login' or 'prompt=consent' to the OAuth initiation URL in main.py to force explicit user interaction at the IdP. 2. Implement an interstitial login page with a 'Sign In' button instead of auto-redirecting to the IdP when @asfquart.auth.require detects no session. 3. Add 'max_age' parameter to limit how recently the user must have authenticated at the IdP (e.g., max_age=300 for 5 minutes). 4. Convert /do-open/&lt;eid&gt; and /do-close/&lt;eid&gt; from GET to POST to prevent link-triggered state changes.

#### FINDING-151: No Formal Authorization Policy Document Defining Access Rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-1059 |
| **ASVS Sections** | 8.1.1, 8.1.2, 8.1.3 |
| **Files** | `v3/ARCHITECTURE.md`, `v3/docs/schema.md`, `v3/server/pages.py:101`, `v3/server/pages.py:167`, `v3/server/pages.py:194`, `v3/server/pages.py:290`, `v3/server/pages.py:335`, `v3/server/pages.py:349`, `v3/server/pages.py:363`, `v3/server/pages.py:378`, `v3/server/pages.py:394`, `v3/server/pages.py:413` |
| **Source Reports** | 8.1.1.md, 8.1.2.md, 8.1.3.md |
| **Related** | FINDING-066, FINDING-190 |

**Description:**

The application lacks a formal authorization policy document that defines function-level, data-specific, and field-level access rules. The existing documentation provides only minimal coverage, and critical authorization rules are explicitly marked as incomplete ('TBD'). ARCHITECTURE.md contains only a single sentence on authorization. schema.md describes the authz field as 'TBD'. There are 10+ unresolved authorization placeholders (### check authz) in pages.py. ASVS 8.1.2 specifically requires that authorization documentation defines rules for field-level access restrictions based on consumer permissions and resource attributes. ASVS 8.1.3 requires documentation that explicitly defines the environmental and contextual attributes used for security decisions. This absence of comprehensive documentation has directly led to the implementation gaps identified in the other findings. Without documented authorization rules, developers cannot implement consistent access controls, testers cannot verify authorization enforcement, administrators cannot audit compliance, and security reviewers cannot assess completeness.

**Remediation:**

Create a formal authorization policy document (e.g., AUTHORIZATION.md) that includes: (1) Role definitions with sources and descriptions (anonymous, authenticated, committer, pmc_member, election_owner, authz_group), (2) Function-level access rules mapping endpoints to required roles and resource checks, (3) Data-specific rules for election management, voting, and tallying, (4) Field-level access matrix showing which roles can read/write which fields based on election state, (5) Decision-making factors including user role, resource ownership, group membership, voter eligibility, election state, and tamper status, (6) Environmental and contextual attributes used (or explicitly NOT used) in authorization decisions, (7) State transition authorization rules. Include an authorization matrix mapping roles to permitted functions and document all consumer-resource permission relationships.

---

#### FINDING-152: Authorization Tier Inconsistency: Lower Privilege Required for Management Than Creation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-269 |
| **ASVS Sections** | 8.3.1 |
| **Files** | `v3/server/pages.py:423`, `v3/server/pages.py:445`, `v3/server/pages.py:465`, `v3/server/pages.py:483`, `v3/server/pages.py:507`, `v3/server/pages.py:530` |
| **Source Reports** | 8.3.1.md |
| **Related** | |

**Description:**

The application has an inverted authorization model where creating an election requires higher privileges (R.pmc_member) than performing all subsequent management operations (R.committer). This means users who lack sufficient privileges to create elections can nonetheless fully manage, modify, open, close, and delete issues from any existing election. Every management endpoint includes a comment acknowledging this issue: '### need general solution'. The authorization model is inverted: creation of elections (a lower-impact, reversible operation that simply initializes a new election) requires higher privilege than opening/closing elections and modifying issues (higher-impact, irreversible operations that affect election integrity and voter participation). A committer who should only have voter-level access can perform all administrative operations on any election.

**Remediation:**

Align management endpoint authorization with creation by requiring R.pmc_member role for all management operations. Add ownership checks using the load_election_owned decorator to all management endpoints: do_add_issue_endpoint, do_edit_issue_endpoint, do_delete_issue_endpoint, do_open_endpoint, do_close_endpoint, do_set_open_at_endpoint, do_set_close_at_endpoint, manage_page, and manage_stv_page. Consider implementing a more granular role-based access control system that distinguishes between election creators, election administrators, voters, and system administrators.

---

#### FINDING-153: _set_election_date Modifies Election Properties Without Object-Level Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-639 |
| **ASVS Sections** | 8.2.3 |
| **Files** | `v3/server/pages.py:99-122`, `v3/steve/election.py:117`, `v3/steve/election.py:119` |
| **Source Reports** | 8.2.3.md |
| **Related** | FINDING-010, FINDING-051, FINDING-053 |

**Description:**

The _set_election_date helper function modifies election properties (open_at, close_at) without performing object-level authorization checks, relying only on the broken load_election decorator that contains an unimplemented '### check authz' placeholder. Any committer can modify the advisory open/close dates on any election, causing confusion for eligible voters and election owners. While the prevent_open_close_update trigger prevents changes after closing, dates can be freely modified while the election is editable or open. This is a direct modification of object properties (open_at, close_at) without authorization, violating ASVS 8.2.3's requirement for field-level access restrictions.

**Remediation:**

This is resolved by the same load_election decorator fix described in AUTHZ-001. Additionally, _set_election_date should verify the election is in the editable state before allowing date modifications. Add explicit state check: if not election.is_editable(): quart.abort(403, 'Cannot modify dates on a non-editable election'). This ensures field-level write access is properly restricted based on both ownership and resource state.

---

#### FINDING-154: Election time-based validity constraints (open_at/close_at) are stored but never enforced during vote acceptance or state computation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Sections** | 9.2.1 |
| **Files** | `v3/steve/election.py:306-318`, `v3/steve/election.py:211-222`, `v3/steve/election.py:367`, `v3/steve/election.py:371`, `v3/server/pages.py:590-600`, `v3/server/pages.py:402-412` |
| **Source Reports** | 9.2.1.md |
| **Related** | |

**Description:**

The election system stores open_at and close_at timestamp fields in the database and displays them to users in the UI, creating an expectation that voting is only permitted within the specified time window. However, these time constraints are never validated when accepting votes or computing election state. The _compute_state() method only checks the manual closed flag and the presence of cryptographic keys, ignoring the time-based validity fields entirely. This allows votes to be accepted after the displayed deadline, undermining election integrity and creating false expectations of enforcement.

**Remediation:**

Option 1: Enforce time constraints in _compute_state() by adding time-based checks that compare current time against open_at and close_at fields, returning S_CLOSED if close_at has passed or S_EDITABLE if open_at has not yet arrived. Option 2: Add explicit time checks in add_vote() that raise ElectionBadState if the current time is outside the valid voting window defined by open_at and close_at. Consider implementing automated election close via background task for defense-in-depth.

---

#### FINDING-155: Missing OIDC Audience Restriction Control

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-346 |
| **ASVS Sections** | 10.1.1, 10.3.1 |
| **Files** | `v3/server/main.py:36-43` |
| **Source Reports** | 10.1.1.md, 10.3.1.md |
| **Related** | |

**Description:**

The application explicitly overrides the framework's default OIDC configuration to use a plain OAuth flow against oauth.apache.org. By disabling OIDC, the application loses the standardized ID Token 'aud' (audience) claim verification that ensures tokens issued by the authorization server are intended exclusively for this specific client. Without audience-restricted tokens, there is no verifiable mechanism at the application layer to confirm that: (1) The access token obtained was issued specifically for the STeVe application (and not a different OAuth client registered with the same AS), and (2) Token confusion attacks (where a token issued for one relying party is replayed against another) are prevented. The developer comment '### is this really needed right now?' indicates uncertainty about whether this OIDC override is still necessary, suggesting this may be a transitional configuration that was never revisited.

**Remediation:**

Re-enable OIDC and validate the ID Token's 'aud' claim. Remove the OAUTH_URL_INIT and OAUTH_URL_CALLBACK overrides to use OIDC defaults. Configure OIDC_CLIENT_ID for audience validation and set OIDC_VALIDATE_AUDIENCE to True in the app configuration. Example:

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

---

#### FINDING-156: Unverified Session Transport May Expose Tokens to Browser

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-522 |
| **ASVS Sections** | 10.1.1 |
| **Files** | `v3/server/pages.py:65-95` |
| **Source Reports** | 10.1.1.md |
| **Related** | |

**Description:**

The application reads session data via asfquart.session.read() in every authenticated handler. Quart's default session implementation stores all session data in a client-side signed cookie (itsdangerous-signed, base64-encoded). If the asfquart.session follows Quart's default and the framework stores the OAuth access token or refresh token in the session, these tokens would be: (1) Serialized into the session cookie sent to the browser with every HTTP response, (2) Readable by any JavaScript on the page (if the cookie lacks HttpOnly), and (3) Sent by the browser with every subsequent request to the domain. The application code extracts only uid, fullname, and email from the session, but the entire session dictionary (including any tokens the framework may have stored) travels through the browser via the cookie. There is no visible configuration ensuring server-side session storage, session cookie attributes (HttpOnly, Secure, SameSite=Lax), or token exclusion from the session cookie payload.

**Remediation:**

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

Additionally, audit the asfquart framework to confirm tokens are stored server-side only and session cookies contain only a session identifier.

---

#### FINDING-157: OAuth Authorization Flow Lacks PKCE (Proof Key for Code Exchange)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.1.2, 10.2.1, 10.4.6 |
| **Files** | `v3/server/main.py:35-38`, `v3/server/main.py:38-42` |
| **Source Reports** | 10.1.2.md, 10.2.1.md, 10.4.6.md |
| **Related** | |

**Description:**

The application explicitly overrides the framework's OAuth URL templates. The authorization URL (OAUTH_URL_INIT) includes only 'state' and 'redirect_uri' — there are no 'code_challenge' or 'code_challenge_method' parameters. The token exchange URL (OAUTH_URL_CALLBACK) includes only 'code' — there is no 'code_verifier' parameter. ASVS 10.1.2 specifically requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', are used to cryptographically bind the authorization code to the specific transaction. Without PKCE: An attacker who intercepts an authorization code (via referrer headers, browser history, open redirector, or log exposure) can exchange it at the token endpoint since no proof of the original requestor is required. The 'state' parameter alone prevents cross-site request forgery on the OAuth flow but does not prevent authorization code injection by an attacker who obtains a valid code through other means.

**Remediation:**

1. Implement PKCE parameter generation function that creates cryptographically random code_verifier (43-128 characters) and S256 code_challenge per RFC 7636. 2. Update OAuth URL templates to include code_challenge and code_challenge_method=S256 in OAUTH_URL_INIT, and code_verifier in OAUTH_URL_CALLBACK. 3. Integrate PKCE into OAuth flow by storing code_verifier in server-side session during authorization request and retrieving it for token exchange. 4. Verify asfquart framework compatibility and extend if needed to handle PKCE parameters. 5. Coordinate with oauth.apache.org administrators to ensure PKCE is enforced, code_challenge is required, code_challenge_method=plain is rejected, and code_verifier validation is required on token requests. 6. Implement automated tests to verify code_challenge presence in authorization URLs, code_verifier in token requests, and rejection of requests without proper PKCE parameters.

---

#### FINDING-158: OAuth State Parameter Security Properties Unverifiable — Framework Delegation Without Audit Visibility

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.1.2, 10.5.1 |
| **Files** | `v3/server/main.py:35-38`, `v3/server/pages.py:89` |
| **Source Reports** | 10.1.2.md, 10.5.1.md |
| **Related** | |

**Description:**

ASVS 10.1.2 requires that the 'state' parameter is: (1) Not guessable — generated with a cryptographically secure random number generator, (2) Specific to the transaction — unique per authorization request, (3) Securely bound to the client and user agent session — stored server-side and validated on callback. The 'state=%s' placeholder in the URL template confirms the framework is expected to populate this value. However: The OAuth callback handler is not present in any of the provided source files. It is entirely within the 'asfquart' framework, which is not available for audit. The state generation logic is not visible — we cannot verify entropy source, length, or uniqueness. The state validation logic is not visible — we cannot verify that the callback checks the state against the session-stored value before accepting the authorization code. The session binding mechanism is opaque — 'asfquart.session.read()' is used but its security properties (server-side vs. client-side, tamper-resistance) cannot be assessed. The 'basic.csrf_token = placeholder' on line 89 of pages.py demonstrates that session-bound cryptographic tokens are not yet implemented for form CSRF protection. This pattern of deferred security controls raises concern about whether the analogous OAuth state parameter handling in the framework is robust.

**Remediation:**

1. Obtain and audit the 'asfquart' framework source code — specifically the OAuth callback handler, state generation, and state validation logic.
2. Verify that 'state' is generated using secrets.token_urlsafe(32) or equivalent:
   import secrets
   state = secrets.token_urlsafe(32)
3. Verify that 'state' is stored in a server-side session before the redirect:
   session['oauth_state'] = state
4. Verify that the callback handler rejects requests where the returned 'state' does not match the session-stored value:
   if request.args.get('state') != session.get('oauth_state'):
       abort(403, 'Invalid state parameter')
   session.pop('oauth_state')  # Consume the state
5. Document the framework's OAuth security properties as part of the application's security architecture.

---

#### FINDING-159: OAuth authorization request does not specify required scopes, relying on server defaults

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3, L2 |
| **CWE** | |
| **ASVS Sections** | 10.2.3, 10.3.2, 10.4.11, 10.7.2 |
| **Files** | `v3/server/main.py:38-41`, `v3/server/pages.py:85-91`, `v3/server/main.py:37-41` |
| **Source Reports** | 10.2.3.md, 10.3.2.md, 10.4.11.md, 10.7.2.md |
| **Related** | |

**Description:**

The OAuth authorization request URL template includes only `state` and `redirect_uri` parameters. It does not include a `scope` parameter (e.g., `openid`, `profile`, `email`), nor a `client_id` parameter in the visible URL template. Without scopes, the authorization server at `oauth.apache.org` cannot present the user with information about what data or permissions the STeVe application is requesting. ASVS 10.7.2 requires that the consent prompt presents 'the nature of the requested authorizations (typically based on scope).' By omitting scopes entirely, the authorization server cannot fulfill this requirement regardless of its own implementation quality. Users cannot make informed consent decisions about personal data sharing (uid, name, email). The authorization server's consent screen cannot distinguish between minimal authentication and the full profile data the application actually consumes.

**Remediation:**

**Option 1 — Direct URL Template Modification:**

```python
# Determine the minimal scopes needed by this application
REQUIRED_SCOPES = 'openid uid email'  # Adjust to match oauth.apache.org's scope vocabulary

asfquart.generics.OAUTH_URL_INIT = (
    f'https://oauth.apache.org/auth?state=%s&redirect_uri=%s&scope={REQUIRED_SCOPES}'
)
```

**Option 2 — Framework Configuration (if supported):**

```python
app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
app.config['OAUTH_SCOPES'] = 'openid uid email'  # Framework-specific configuration
```

**Additional Steps:**

1. Document the rationale for each requested scope
2. Map scopes to specific session fields consumed by the application
3. Coordinate with `oauth.apache.org` administrators to confirm available scopes
4. Verify that the minimal scope set still provides all required functionality
5. Validate returned scopes in the token response to confirm the AS only granted what was requested

---

#### FINDING-160: User Identity Derived from Opaque `uid` Session Field Without Verifiable `iss`+`sub` Claim Origin

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 10.3.3 |
| **Files** | `v3/server/pages.py:89-98`, `v3/server/pages.py:157`, `v3/server/pages.py:274`, `v3/server/pages.py:329`, `v3/server/pages.py:438`, `v3/server/pages.py:475`, `v3/server/pages.py:496`, `v3/server/pages.py:514`, `v3/server/pages.py:626`, `v3/server/main.py:38-42` |
| **Source Reports** | 10.3.3.md |
| **Related** | |

**Description:**

The application derives user identity from a session field `uid` without verifiable proof that this identifier originates from non-reassignable OAuth token claims (`iss` + `sub`). All authorization decisions throughout the application depend on this single `uid` field, which is populated by the opaque `asfquart` framework during OAuth token exchange. The `uid` field from the session is used as the sole user identifier for every authorization decision in the system, including vote eligibility and vote submission. The application code has no mechanism to verify that this `uid` was derived from the non-reassignable combination of `iss` (issuer) and `sub` (subject) claims from the OAuth token response. If the `asfquart` framework populates `uid` from a reassignable claim (such as `preferred_username`, `email`, or a custom attribute), a user who inherits a recycled identifier could gain access to another user's election permissions, votes, and administrative privileges. While Apache's infrastructure does not currently recycle committer UIDs, the application architecture itself provides no defense-in-depth against this class of identity confusion. The entire authorization chain depends on the external framework making the correct claim selection—a trust assumption that is neither documented nor verified.

**Remediation:**

The application should explicitly verify that user identity is derived from `iss` + `sub` claims, or at minimum document and validate this at the application layer. Implement verification in the `basic_info()` function to: 1) Extract `iss` and `sub` claims from the session, 2) Validate the expected issuer (https://oauth.apache.org), 3) Use the iss+sub combination as the canonical identity, 4) Map this to uid via a verified lookup. If the `asfquart` framework cannot be modified to expose `iss` and `sub` in the session, audit the framework's token-to-session mapping to confirm that `uid` is derived from the `sub` claim (or equivalent non-reassignable identifier) and the issuer is validated during token exchange. Immediate actions: Audit the `asfquart` framework to verify that the `uid` session field is derived from non-reassignable token claims. Short-term: Expose `iss` and `sub` in the session for application-level validation and add issuer validation check in `basic_info()`. Long-term: Document the identity model explicitly, mapping uid to LDAP uid to OAuth sub claim.

---

#### FINDING-161: Missing Authentication Recentness Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 10.3.4 |
| **Files** | `v3/server/main.py:37-43`, `v3/server/pages.py:85-95`, `v3/server/pages.py:443-482`, `v3/server/pages.py:507-525`, `v3/server/pages.py:528-544`, `v3/server/pages.py:485-504` |
| **Source Reports** | 10.3.4.md |
| **Related** | |

**Description:**

The application explicitly disables OIDC and uses plain OAuth, thereby removing the standard mechanism (auth_time claim) for verifying authentication recentness. The session object contains only uid, fullname, and email — no authentication timestamp is stored or checked. Sensitive operations (voting, opening/closing elections) proceed without verifying when the user last authenticated. In a voting system, stale sessions can be exploited to cast votes on behalf of another user without requiring recent authentication. This undermines vote integrity — the core security property of the system.

**Remediation:**

1. Store auth_time in session during OAuth callback: Record int(time.time()) when session is established. 2. Implement a require_recent_auth() helper function that checks if (time.time() - auth_time) exceeds the maximum age threshold. 3. Apply recentness checks before sensitive operations, particularly voting (MAX_AUTH_AGE_VOTING = 3600 seconds). 4. Redirect users to re-authenticate if auth_time check fails. Example code provided in the report shows implementation in session creation and a decorator pattern for enforcement.

---

#### FINDING-162: Missing Authentication Method and Strength Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 10.3.4 |
| **Files** | `v3/server/pages.py:443-482`, `v3/server/pages.py:507-525`, `v3/server/pages.py:528-544`, `v3/server/pages.py:485-504` |
| **Source Reports** | 10.3.4.md |
| **Related** | |

**Description:**

The application has operations of varying sensitivity (viewing elections, voting, managing elections, creating elections) but performs no verification of authentication method or strength. The framework distinguishes R.committer from R.pmc_member roles but these are authorization checks on group membership — not authentication quality. There is no verification that the user authenticated with an appropriate method (e.g., MFA for administrative operations). Administrative operations on elections (open, close, create, delete issues) can be performed with any authentication method, including potentially weak ones. For a voting system, this means election integrity relies entirely on the initial authentication quality, which is neither verified nor enforced by the resource server.

**Remediation:**

1. If using OIDC (recommended), capture and verify acr (Authentication Context Class Reference) and amr (Authentication Methods References) claims during session creation. 2. Implement a require_auth_strength() function that verifies actual_acr matches required_acr for the operation sensitivity level. 3. For administrative operations (election management), require MFA methods in amr claim (e.g., 'mfa', 'otp', 'hwk'). 4. Return HTTP 403 with descriptive error if authentication strength is insufficient. 5. Long-term: Evaluate OIDC adoption to gain standard acr/amr/auth_time claims from the identity provider.

---

#### FINDING-163: No Visible Client Authentication for OAuth Token Exchange

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-306 |
| **ASVS Sections** | 10.4.10 |
| **Files** | `v3/server/main.py:38-41` |
| **Source Reports** | 10.4.10.md |
| **Related** | FINDING-044 |

**Description:**

This server-side web application (Quart/Python) is inherently capable of maintaining credential confidentiality and should operate as a confidential OAuth client per RFC 6749 §2.1. ASVS 10.4.10 requires that confidential clients authenticate themselves to the authorization server during backchannel requests such as token exchange. The audit reveals no visible client authentication mechanism in the codebase. The only OAuth configuration present consists of two URL templates pointing to `oauth.apache.org`. Critical authentication elements are missing: (1) No `client_secret` configuration — No client credentials visible in the code or configuration, (2) No client certificate for mTLS — While server TLS certificates are configured, no mutual TLS client authentication is set up, (3) No `private_key_jwt` configuration — No JWT assertion signing keys configured, (4) Framework opacity — The `asfquart` package handles the actual HTTP request to the token endpoint, but its internals cannot be verified without source code access. Additionally, the token URL format uses query parameters (`token?code=%s`) rather than the RFC 6749 §4.1.3 recommended POST body approach, potentially exposing authorization codes in server logs.

**Remediation:**

**Immediate Actions:** (1) Verify current configuration — Obtain and review the `asfquart` framework source code and any external configuration files (e.g., `APP.cfg`) to determine if client authentication is already configured but not visible in the audited files. (2) Confirm client registration — Verify with Apache Infrastructure that the STeVe application is registered as a confidential client at `oauth.apache.org` and determine the configured authentication method. **Implementation Options (choose one based on AS capabilities):** Option 1: Client Secret (Minimum Acceptable) - Add explicit client authentication configuration with `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` from environment variables, and `OAUTH_CLIENT_AUTH_METHOD = 'client_secret_post'`. Option 2: Private Key JWT (Recommended per ASVS) - Configure `OAUTH_CLIENT_AUTH_METHOD = 'private_key_jwt'`, `OAUTH_SIGNING_KEY_PATH`, and `OAUTH_SIGNING_ALG = 'RS256'`. Option 3: Mutual TLS (RFC 8705) - Configure `OAUTH_CLIENT_AUTH_METHOD = 'tls_client_auth'` with client certificate and key paths. **Token Exchange Protocol Fix:** Ensure the authorization code is transmitted via POST body parameters rather than query parameters by using `OAUTH_TOKEN_ENDPOINT` with `OAUTH_TOKEN_METHOD = 'POST'`. **Verification Steps:** (1) Enable debug logging for OAuth token exchange requests, (2) Confirm client authentication parameters are included in token requests, (3) Test that token exchange fails when client credentials are invalid, (4) Document the authentication method in security configuration documentation.

---

#### FINDING-164: OAuth Client Authorization Request Does Not Explicitly Specify response_mode, Relying Entirely on External AS Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 10.4.12 |
| **Files** | `v3/server/main.py:39-43` |
| **Source Reports** | 10.4.12.md |
| **Related** | |

**Description:**

The authorization URL template omits `response_mode` (and `response_type`). While `asfquart` may add parameters internally, the visible configuration shows no defense-in-depth from the client side. ASVS 10.4.12 requires that the AS only allow the `response_mode` appropriate for the client, and suggests PAR or JAR as enforcement mechanisms — neither is used. Without explicit `response_mode=query` in the authorization request, an attacker who can manipulate the authorization request (e.g., via open redirect or parameter injection) could append `response_mode=fragment`, causing the authorization code to be returned in the URL fragment. Fragment-based responses are not sent to the server and can be intercepted by client-side scripts or leaked via the Referer header. The comment `# Avoid OIDC` (line 38) suggests this is a deliberate departure from OIDC defaults, which may also remove OIDC-specific `response_mode` protections.

**Remediation:**

Option 1 — Explicitly specify `response_mode` and `response_type` in the authorization request: `asfquart.generics.OAUTH_URL_INIT = ('https://oauth.apache.org/auth?response_type=code&response_mode=query&state=%s&redirect_uri=%s')`. Option 2 — Use Pushed Authorization Requests (PAR) per RFC 9126, where the authorization request parameters are sent server-to-server. Option 3 — Use JWT-Secured Authorization Request (JAR) per RFC 9101, where authorization parameters are signed by the client.

---

#### FINDING-165: OAuth Client Confidentiality Classification Cannot Be Verified — No Client Type Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | |
| **ASVS Sections** | 10.4.16 |
| **Files** | `v3/server/main.py:35-51` |
| **Source Reports** | 10.4.16.md |
| **Related** | |

**Description:**

ASVS 10.4.16 first requires verification that the client is confidential. A confidential client must demonstrate the ability to maintain credential confidentiality by authenticating with the authorization server using credentials that are not exposed to end users. The application is a server-side Quart application, which architecturally should be a confidential client. However, no explicit client credential configuration or client type enforcement is visible in the codebase. No explicit client credential configuration (client_id/client_secret) is visible, no client registration metadata shows token_endpoint_auth_method is set to a confidential method, and the token endpoint URL passes only the authorization code, which mirrors a public client pattern where the client cannot authenticate itself.

**Remediation:**

- Explicitly register the client as a confidential client with the authorization server (oauth.apache.org).
- Configure the application with the appropriate client credentials and authentication method.
- Document the client type classification in application security documentation.
- Add configuration validation to ensure confidential client credentials are present and properly secured.

---

#### FINDING-166: No Visible Session/Token Absolute Expiration Enforcement in OAuth Client

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.4.8 |
| **Files** | `v3/server/main.py:36-48`, `v3/server/pages.py:60-90` |
| **Source Reports** | 10.4.8.md |
| **Related** | |

**Description:**

The application lacks visible enforcement of absolute session or token expiration at the client level. While the application delegates authentication to an external OAuth Authorization Server (oauth.apache.org), there is no application-level mechanism to ensure sessions derived from OAuth tokens respect absolute expiration boundaries. The asfquart.construct() call includes no session lifetime configuration, and basic_info() performs no timestamp-based session validation. If asfquart does not internally enforce absolute session expiration, sessions derived from OAuth tokens could persist indefinitely. Even if the AS properly expires refresh tokens (per ASVS 10.4.8), the client session may outlive the intended token lifetime. Long-lived sessions increase the window for session hijacking, particularly for a voting application where temporal bounds on voting windows are security-critical.

**Remediation:**

Step 1: Configure explicit session absolute expiration in the application by setting PERMANENT_SESSION_LIFETIME to datetime.timedelta(hours=8) and configuring SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, and SESSION_COOKIE_SAMESITE in app.config. Step 2: Store the authentication timestamp in the session (created_at field) and validate it in basic_info() function, checking if age exceeds MAX_SESSION_AGE (8 hours) and invalidating the session if expired. Step 3: Ensure the OAuth callback handler stores the creation timestamp using time.time() when writing session data.

---

#### FINDING-167: No User-Facing Session or Token Revocation Mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.4.9 |
| **Files** | `v3/server/pages.py:582-597`, `v3/server/pages.py:entire application scope`, `v3/server/main.py:39-42` |
| **Source Reports** | 10.4.9.md |
| **Related** | |

**Description:**

A comprehensive review of all 21 routes defined in pages.py reveals no logout endpoint, no session revocation mechanism, and no integration with the Authorization Server's token revocation endpoint (RFC 7009). Users who authenticate via OAuth have no way to invalidate their session or trigger revocation of any tokens held by the application. The /profile and /settings pages exist but contain no session management functionality. An attacker who obtains a valid session cookie (e.g., via XSS, network interception, or physical access) can use it indefinitely. The legitimate user visiting /profile or /settings will find no 'Log out' or 'Revoke sessions' option.

**Remediation:**

1. Add Logout Endpoint: Create a /logout route that clears local session and revokes tokens at the Authorization Server using RFC 7009 Token Revocation endpoint (https://oauth.apache.org/revoke). 2. Add Session Management UI: Enhance the /settings page to display active sessions with revocation capability per session. 3. Update Configuration: Add OAUTH_URL_REVOKE configuration in main.py pointing to the AS revocation endpoint. 4. Add Logout Links: Include logout links in navigation on all authenticated pages. 5. Implement session listing with 'last accessed' timestamps to help users identify suspicious sessions.

---

#### FINDING-168: No Technical Enforcement of Identifier Immutability

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.5.2 |
| **Files** | `v3/server/pages.py:77-88`, `v3/server/bin/asf-load-ldap.py:55-59` |
| **Source Reports** | 10.5.2.md |
| **Related** | |

**Description:**

The application uses s['uid'] from the session as the sole user identifier for all security decisions. While Apache LDAP UIDs are operationally stable (not reassigned), there is no technical enforcement in this codebase that the 'uid' originates from a claim that is contractually non-reassignable (like OIDC 'sub'). The 'uid' is populated by the asfquart framework during the OAuth callback, drawing from whatever the Apache OAuth provider returns. There is no technical enforcement that: (1) The 'uid' originates from a claim that is contractually non-reassignable, (2) The 'uid' has not been modified between the identity provider and the session, (3) The 'uid' is bound to a single identity provider (no 'iss' + 'sub' compound key). If the identity provider changes, or if the system is deployed in a different context, user identity confusion could occur.

**Remediation:**

Use a compound identifier ('iss' + 'sub') or validate that the identifier source guarantees non-reassignment. Example: Use 'sub' claim from ID Token qualified by issuer to ensure uniqueness even across federated IdPs: basic.update(uid=s['sub'], issuer=s['iss'], name=s['fullname'], email=s['email']). This ensures uniqueness even across federated identity providers and provides technical enforcement of identifier immutability.

---

#### FINDING-169: No Authorization Server Issuer Validation Mechanism Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.5.3 |
| **Files** | `main.py:37-42`, `pages.py:83-89` |
| **Source Reports** | 10.5.3.md |
| **Related** | |

**Description:**

The application configures OAuth endpoints via hardcoded URL strings but defines no expected issuer URL and implements no mechanism to validate that authorization server metadata or token responses originate from the expected issuer. The comment 'Avoid OIDC' indicates a deliberate bypass of OIDC discovery, which also bypasses the metadata issuer validation this requirement mandates. If an attacker can perform a DNS hijack or man-in-the-middle on the connection to oauth.apache.org, or if the asfquart framework were to support metadata discovery in the future, a rogue authorization server could impersonate the legitimate AS by including 'issuer': 'https://oauth.apache.org' in its metadata. Without issuer validation, the client would accept the metadata and redirect users to the attacker's authorization endpoint, allowing identity forgery and vote manipulation.

**Remediation:**

Configure an expected issuer URL and validate it against authorization server metadata and token responses. Implement: 1) Define EXPECTED_ISSUER constant as 'https://oauth.apache.org', 2) Configure asfquart framework to validate issuer if supported, 3) Add middleware to validate iss claim in session/tokens before processing, rejecting sessions from unexpected issuers, 4) If migrating to OIDC discovery, implement metadata fetching with exact issuer match validation comparing metadata['issuer'] to expected_issuer before accepting any metadata.

---

#### FINDING-170: Missing Explicit `response_type=code` Parameter in OAuth Authorization URL

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.6.1 |
| **Files** | `v3/server/main.py:36-41` |
| **Source Reports** | 10.6.1.md |
| **Related** | |

**Description:**

The OAuth authorization URL template does not include the required `response_type=code` parameter. Per RFC 6749 §4.1.1, `response_type` is a REQUIRED parameter in authorization requests. While the callback URL pattern (`code=%s`) implies the code flow is expected, the authorization request itself does not enforce this. Without an explicit `response_type=code` parameter, the RP relies entirely on the external OP's default behavior, which is not guaranteed by the OAuth specification. If the OP defaults to or supports `response_type=token`, access tokens could be returned in the URL fragment, leading to token leakage vectors including browser history exposure, referrer header leakage, JavaScript access by third-party scripts, and server logs. This directly contradicts ASVS 10.6.1's prohibition of `token` (implicit flow).

**Remediation:**

Explicitly include `response_type=code` in the authorization URL template:

```python
asfquart.generics.OAUTH_URL_INIT = (
    'https://oauth.apache.org/auth?response_type=code&state=%s&redirect_uri=%s'
)
```

Additional recommendations:
1. Verify whether the `asfquart` framework adds `response_type` internally and document this behavior
2. Consider adding PKCE parameters (`code_challenge`, `code_challenge_method`) to prevent authorization code interception attacks
3. Implement defense-in-depth by validating that the callback contains a `code` parameter and not token parameters
4. Re-evaluate whether the intentional bypass of OIDC (comment: `# Avoid OIDC`) is justified given the standardized security properties OIDC provides

---

#### FINDING-171: Missing Consent Enforcement Parameters in OAuth Authorization Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.7.1 |
| **Files** | `v3/server/main.py:36-42` |
| **Source Reports** | 10.7.1.md |
| **Related** | |

**Description:**

The OAuth authorization URL configuration omits all consent-enforcing parameters and explicitly disables OIDC support. This makes it impossible to verify or guarantee that the external authorization server prompts users for consent on each authorization request. The configuration includes no `prompt`, `consent_prompt`, or `scope` parameters, and explicitly avoids OIDC (which provides standardized consent mechanisms). When users are redirected to the AS for authorization, the AS receives no instruction to prompt for consent and may silently issue tokens for returning users without displaying a consent screen. For a voting system, silent re-authorization without explicit consent could enable scenarios where a user's browser is redirected through the OAuth flow and obtains a valid session without the user's awareness.

**Remediation:**

Switch to OIDC or add consent parameters if the AS supports them in plain OAuth. Specifically: (1) Use OIDC with explicit consent prompting by adding `response_type=code`, `scope=openid profile email`, and `prompt=consent` parameters to the OAuth authorization URL; (2) If OIDC adoption is not feasible, coordinate with the `oauth.apache.org` operators to confirm that consent is always prompted for the STeVe client registration and document this as a compensating control; (3) Add `scope` parameter to the authorization URL so the consent screen can show users what permissions are being requested; (4) In the OAuth callback handler, log whether the authorization was freshly consented vs. silently completed for audit trail purposes.

---

#### FINDING-172: Deliberate OIDC Avoidance Eliminates Standardized Consent and Identity Claims

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.7.2 |
| **Files** | `v3/server/main.py:35-36`, `v3/server/main.py:37-41` |
| **Source Reports** | 10.7.2.md |
| **Related** | |

**Description:**

The application deliberately overrides the framework's default OAuth/OIDC URLs to 'avoid OIDC,' replacing them with a custom ASF OAuth endpoint. OIDC provides standardized consent mechanisms including well-defined scopes (`openid`, `profile`, `email`), standardized claims, and the `prompt=consent` parameter that gives the authorization server explicit signals to display consent screens with structured claim information. By bypassing OIDC in favor of a custom OAuth flow, the application loses: (1) Standardized `scope` values that map to well-defined user data categories, (2) The `prompt=consent` mechanism to force consent re-display, (3) ID Token claims that document what data was authorized, (4) The client identification via registered `client_id` that the AS presents to users. The authorization server cannot leverage OIDC-standard consent presentation (identity of the application, requested scopes with descriptions, authorization lifetime). Users may be authenticated without any consent prompt, or with a generic prompt that doesn't specify the STeVe application name or data access.

**Remediation:**

Re-evaluate the OIDC bypass decision. If the ASF's OAuth server supports OIDC:

```python
def create_app():
    # Use standard OIDC flow for proper consent management
    # Do NOT override asfquart.generics.OAUTH_URL_INIT
    # Let the framework use its default OIDC endpoints
    
    app = asfquart.construct('steve', app_dir=THIS_DIR, static_folder=None)
    
    # If custom endpoints are needed, ensure OIDC parameters are preserved:
    # asfquart.generics.OAUTH_URL_INIT = (
    #     'https://oauth.apache.org/auth?'
    #     'response_type=code&'
    #     'client_id=steve&'
    #     'scope=openid+profile+email&'
    #     'prompt=consent&'
    #     'state=%s&redirect_uri=%s'
    # )
    
    import pages
    import api
    return app
```

---

#### FINDING-173: Authorization Tiers Not Reflected in OAuth Consent — Election Management Privileges Granted Without Specific Consent

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.7.2 |
| **Files** | `v3/server/pages.py:518`, `v3/server/pages.py:540`, `v3/server/pages.py:561`, `v3/server/pages.py:580`, `v3/server/pages.py:632`, `v3/server/pages.py:476`, `v3/server/main.py:37-39` |
| **Source Reports** | 10.7.2.md |
| **Related** | |

**Description:**

The application enforces a two-tiered authorization model internally: Tier 1 (`R.committer`) for voting, election viewing, and election management, and Tier 2 (`R.pmc_member`) for election creation (higher privilege). However, the OAuth consent flow is identical for all users regardless of their eventual privilege tier. A user who logs in solely to view elections goes through the same consent flow as an election administrator who will create and manage elections affecting other voters. The single OAuth flow means users are never informed during consent that: their ASF membership/group data will determine election management privileges, the application will query LDAP group membership to determine PMC membership, or that authentication grants potential access to election administration functions. Users are not informed that their LDAP group membership determines administrative privileges in the application. A PMC member who logs in is not specifically consented to the elevated election management capabilities. No scope differentiation means the AS consent screen cannot distinguish between basic voter access and full administrative access.

**Remediation:**

Define distinct OAuth scopes or Rich Authorization Request (RAR) details that map to application privilege tiers, and request them contextually:

```python
# Define scope sets for different authorization contexts
SCOPE_VOTER = 'openid profile email steve:vote'
SCOPE_ADMIN = 'openid profile email steve:vote steve:manage'

# When redirecting to admin functions, use elevated scopes
# Or implement step-up consent for management operations
```

If the ASF OAuth server doesn't support custom scopes, implement an application-level consent screen before granting elevated privileges:

```python
@APP.get('/admin')
@asfquart.auth.require({R.committer})
async def admin_page():
    result = await basic_info()
    # Check if user has consented to admin-level access
    s = await asfquart.session.read()
    if not s.get('admin_consent_granted'):
        return quart.redirect('/consent/admin-access')
    # ... proceed with admin page
```

Alternatively, implement explicit authorization lifetime disclosure showing specific privileges being granted (vote vs. manage elections), session duration, and data access (uid, name, email, group membership).

---

#### FINDING-174: Complete Absence of Consent Management Functionality

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 10.7.3 |
| **Files** | `v3/server/pages.py:554-560`, `v3/server/pages.py:563-569` |
| **Source Reports** | 10.7.3.md |
| **Related** | |

**Description:**

The application provides no mechanism for users to review, modify, or revoke OAuth consents granted through the authorization server. While the application integrates with `oauth.apache.org` as an OAuth client, it lacks any consent management interface required by ASVS 10.7.3. Users cannot exercise control over delegated authorization, cannot review what data the application accesses on their behalf, and cannot revoke application access without visiting the authorization server directly.

**Remediation:**

Implement comprehensive consent management functionality:

1. **Implement Consent Review Page** - Create `/consents` endpoint displaying active OAuth grants, scopes, and grant timestamps

2. **Implement Consent Revocation Endpoint** - Create `/revoke-consent` POST endpoint that:
   - Calls the AS token revocation endpoint (RFC 7009)
   - Clears the local session
   - Logs the revocation action

3. **Store Consent Metadata** - At authentication time, store consent metadata including:
   - access_token
   - granted_scopes
   - auth_time (timestamp)
   - authorization_server URL

4. **Add UI Links** - Integrate consent management into existing `/profile` and `/settings` pages

5. **Implement Scope Modification** - Allow users to adjust scope permissions for granted consents

6. **Add Consent History** - Track all grants, modifications, and revocations for audit purposes

---

#### FINDING-175: No TLS/Cipher Configuration for ASGI Deployment Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | |
| **ASVS Sections** | 12.1.2, 12.1.3, 12.3.1, 12.3.3 |
| **Files** | `v3/server/main.py:94-115`, `v3/server/main.py:99-118`, `v3/server/main.py:91-109`, `v3/server/main.py:115-126`, `v3/server/main.py:95-115` |
| **Source Reports** | 12.1.2.md, 12.1.3.md, 12.3.1.md, 12.3.3.md, 12.1.5.md |
| **Related** | |

**Description:**

The ASGI mode creates the application but provides no TLS configuration whatsoever. No Hypercorn configuration file (hypercorn.toml) is provided in the codebase. No --ciphers, --certfile, --keyfile, or --ssl-version command-line guidance is documented. No programmatic SSLContext configuration exists within run_asgi(). Deployments following the documented pattern will either lack TLS entirely or use Hypercorn's permissive defaults. Production deployments using ASGI mode have no secure cipher suite baseline, operators have no reference configuration for cipher suite hardening, and cipher suite selection is left entirely to deployment luck. When deployed behind Hypercorn, TLS must be configured entirely through Hypercorn's own configuration. The application performs no check that TLS is actually active in the ASGI server environment. The Hypercorn invocation shown in the code comments also lacks any TLS flags.

**Remediation:**

Provide a Hypercorn configuration file (hypercorn.toml) with hardened TLS settings including bind address, certfile, keyfile, and ciphers specification using the recommended cipher suite string. Document the required invocation command: 'uv run python -m hypercorn --config hypercorn.toml main:steve_app'. Ensure the configuration enforces TLS 1.2+ and forward-secret cipher suites only. Add startup validation that TLS configuration exists even in ASGI mode and exit with critical error if not configured. Add runtime warnings in ASGI mode to alert operators about TLS configuration requirements. If TLS certificates are configured in config.yaml, warn that ASGI mode won't use them directly and provide example Hypercorn command with TLS flags. If no TLS certificate is configured, warn that TLS must be provided by the reverse proxy or ASGI server. Update code comments to show secure invocation examples with --certfile and --keyfile flags for Hypercorn. Provide Hypercorn configuration documentation with ECH settings including bind address, certfile, keyfile, TLS 1.3 enforcement, and cipher configuration. Add runtime validation in run_asgi() that logs a warning message: 'ASGI mode: Ensure your ASGI server (Hypercorn) is configured with TLS 1.3 and ECH support. See deployment documentation.' Create example hypercorn.toml configuration file with TLS and ECH settings.

---

#### FINDING-176: Example Configuration Lacks Cipher Suite and TLS Version Settings

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | |
| **ASVS Sections** | 12.1.2, 12.1.4 |
| **Files** | `v3/server/config.yaml.example:23-31`, `v3/server/config.yaml.example:28-30`, `v3/server/main.py:103-120` |
| **Source Reports** | 12.1.2.md, 12.1.4.md |
| **Related** | |

**Description:**

The example configuration file is the primary deployment reference, yet it only includes certfile and keyfile settings. It provides no cipher suite configuration options, meaning: (1) The configuration schema doesn't support cipher suite settings; (2) Operators cannot restrict cipher suites via configuration; (3) No secure defaults are documented or enforceable; (4) No tls_version_min or ciphers fields exist. Every deployment based on this template inherits Python/system default cipher suites. No configuration-driven mechanism exists to enforce ASVS 12.1.2 compliance. Operators must modify source code to achieve compliant cipher suite configuration. No OCSP Stapling configuration exists anywhere in the example configuration or documentation. The config.yaml.example contains only certfile and keyfile — there are no fields for OCSP responder URL, stapling file path, or any revocation-related settings.

**Remediation:**

Extend the configuration schema and example to include TLS hardening options: tls_min_version (set to '1.2'), ciphers (set to 'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK'), and prefer_server_ciphers (set to true). Update the configuration parser in main.py to consume these settings when constructing the SSLContext. Add OCSP-related configuration to the example config including ocsp_staple_file path and tls_minimum_version fields. For ASGI deployments, add a Hypercorn configuration template (hypercorn_config.py) with certfile, keyfile, and ciphers configuration. Document that the reverse proxy must be configured with OCSP Stapling, providing nginx.conf example with ssl_stapling on, ssl_stapling_verify on, ssl_trusted_certificate, and resolver directives.

---

#### FINDING-177: No Certificate Revocation Checking for Outbound OAuth Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-295 |
| **ASVS Sections** | 12.1.4, 12.3.2, 12.3.4 |
| **Files** | `v3/server/main.py:44-48`, `v3/server/main.py:38-41`, `v3/server/main.py:42-45` |
| **Source Reports** | 12.1.4.md, 12.3.2.md, 12.3.4.md |
| **Related** | |

**Description:**

The application makes outbound HTTPS connections to the Apache OAuth service for authentication. There is no visible configuration of certificate revocation checking (OCSP or CRL) for these outbound TLS connections. The application code provides no mechanism to: (1) Enforce OCSP checking on the OAuth endpoint's certificate, (2) Provide a CRL distribution point for validation, (3) Configure an SSL context for outbound connections with revocation verification. If the OAuth server's certificate were compromised and revoked, the application could continue to trust and send sensitive authentication tokens to an attacker-controlled endpoint presenting the revoked certificate. An attacker who compromises the OAuth server's private key and performs a MITM attack would not be detected even after the legitimate certificate is revoked, potentially allowing interception of OAuth authorization codes and tokens. While the configured URLs correctly use the https:// scheme, there is no explicit SSL context creation, certificate verification enforcement, or CA trust store configuration anywhere in the application code for these outbound connections.

**Remediation:**

Configure outbound HTTPS connections with certificate revocation verification. Create create_secure_ssl_context() function that creates default SSL context with certifi CA bundle, enables check_hostname and CERT_REQUIRED verify_mode, and sets verify_flags to include VERIFY_CRL_CHECK_LEAF for OCSP checking. Pass this context to asfquart or underlying HTTP client. Example: import ssl, certifi; oauth_ssl_context = ssl.create_default_context(cafile=certifi.where()); oauth_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2; optionally pin to Let's Encrypt / specific CA for oauth.apache.org with oauth_ssl_context.load_verify_locations(cafile='certs/oauth-ca-bundle.pem'); pass to asfquart or configure the HTTP client used for OAuth.

---

#### FINDING-178: TLS Configuration Allows Plain HTTP as Valid Deployment Mode Without Warnings

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-319 |
| **ASVS Sections** | 12.3.4, 12.3.5, 13.3.4 |
| **Files** | `v3/server/config.yaml.example:30-32`, `v3/server/main.py:83-86`, `v3/server/config.yaml.example:28-31`, `v3/server/main.py:79-87` |
| **Source Reports** | 12.3.4.md, 12.3.5.md, 13.3.4.md |
| **Related** | FINDING-014 |

**Description:**

The TLS configuration is entirely optional. The example config explicitly documents that leaving certfile/keyfile blank results in plain HTTP. In main.py, the conditional 'if app.cfg.server.certfile:' means the server silently degrades to unencrypted HTTP without any warning or startup failure. The config comments confirm 'a proxy sits in front of this server' — meaning the proxy-to-application connection is an internal service link that should always be encrypted. If deployed with blank TLS configuration, all internal communication between the reverse proxy and the application server occurs in plaintext, exposing authentication tokens, OAuth credentials, vote data, and session cookies. For an election system processing authentication tokens and votes, running without TLS exposes all traffic (including OAuth tokens and ballot submissions) to network interception. While the comment mentions a proxy typically sits in front, there is no validation that TLS termination actually occurs somewhere in the chain. A misconfigured deployment with blank cert fields and no TLS-terminating proxy would expose all traffic in cleartext.

**Remediation:**

Make TLS mandatory by failing startup if certificates are not configured. Add validation logic: if app.cfg.server.certfile and app.cfg.server.keyfile: configure TLS; else: _LOGGER.critical('TLS is not configured! Set server.certfile and server.keyfile in config.yaml. Refusing to start without TLS.'); sys.exit(1). Update config.yaml.example to remove the 'leave blank for plain HTTP' guidance: # REQUIRED: Specify the .pem files to serve using TLS. # The server will not start without valid TLS configuration. certfile: localhost.apache.org+3.pem, keyfile: localhost.apache.org+3-key.pem. Add startup validation that warns or refuses to start without TLS unless an explicit require_tls: false override is set. Configuration example: server: require_tls: true, certfile: localhost.apache.org+3.pem, keyfile: localhost.apache.org+3-key.pem.

---

#### FINDING-179: Non-Constant-Time Comparison of Cryptographic Key Material in Tamper Detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-208 |
| **ASVS Sections** | 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.2.3, 11.2.4, 11.2.5, 11.3.3, 11.4.2, 11.6.1, 11.6.2, 11.7.1 |
| **Files** | `v3/steve/election.py:335-349`, `v3/steve/election.py:375`, `v3/steve/election.py:362-375`, `v3/steve/election.py:264`, `v3/steve/election.py:381`, `v3/server/bin/tally.py:155` |
| **Source Reports** | 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 11.2.3.md, 11.2.4.md, 11.2.5.md, 11.3.3.md, 11.4.2.md, 11.6.1.md, 11.6.2.md, 11.7.1.md |
| **Related** | FINDING-180 |

**Description:**

The tamper detection mechanism (`is_tampered()` function) compares a recomputed opened_key against the stored value using Python's standard `!=` operator, which short-circuits on the first differing byte. This leaks information about the stored key through timing differences. An attacker who can trigger tamper checks with controlled election data modifications and observe response timing could gradually reconstruct the opened_key value. While currently CLI-only, the method is a public API on the Election class that web handlers could invoke. Per NIST SP 800-57, key material should be protected with constant-time operations during comparison. Python's != operator on bytes objects short-circuits at the first differing byte, creating a timing side-channel. While the Argon2 computation dominates execution time (reducing practical exploitability), an attacker with local access could potentially submit controlled modifications to election data, measure response time differences across multiple tamper checks, and incrementally reconstruct the stored opened_key. The `opened_key` is critical as it's the root from which all vote tokens are derived. Any leakage could help an attacker forge vote tokens or correlate votes to voters. A proper cryptographic inventory would document that all cryptographic comparisons must use constant-time functions to prevent timing side-channels.

**Remediation:**

Replace the non-constant-time comparison (opened_key != md.opened_key) with hmac.compare_digest(opened_key, md.opened_key) to prevent timing oracle attacks. Update the return statement to: return not hmac.compare_digest(opened_key, md.opened_key). Add 'import hmac' at the top of the file. This prevents timing side-channels that could theoretically allow an attacker to deduce bytes of the stored opened_key through repeated attempts and precise timing measurement. This prevents timing side-channel attacks on cryptographic material comparison.

---

#### FINDING-180: Argon2d Variant Used Instead of NIST/OWASP-Recommended Argon2id

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-208 |
| **ASVS Sections** | 11.2.3, 11.2.4, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1, 15.1.4, 15.1.5, 11.7.1, 11.7.2 |
| **Files** | `v3/steve/crypto.py:88`, `v3/steve/crypto.py:31-38`, `v3/steve/crypto.py:43-46`, `v3/steve/crypto.py:130`, `v3/steve/crypto.py:97`, `v3/steve/crypto.py:48`, `v3/steve/crypto.py:55`, `v3/steve/crypto.py:82-92`, `v3/steve/crypto.py:83`, `v3/steve/crypto.py:76-84`, `v3/steve/crypto.py:40-47`, `v3/steve/crypto.py:50-54`, `v3/steve/crypto.py:88-98`, `v3/steve/crypto.py:79-89`, `v3/steve/crypto.py:80` |
| **Source Reports** | 11.2.3.md, 11.2.4.md, 11.3.3.md, 11.4.2.md, 11.4.3.md, 11.4.4.md, 11.6.1.md, 11.6.2.md, 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md, 15.1.4.md, 15.1.5.md, 15.2.5.md, 11.7.1.md, 11.7.2.md |
| **Related** | FINDING-179 |

**Description:**

The production `_hash()` function uses `argon2.low_level.Type.D` (Argon2d), while the benchmark function correctly uses `argon2.low_level.Type.ID` (Argon2id). Argon2d uses data-dependent memory access patterns, making it vulnerable to side-channel attacks (cache-timing, memory bus snooping) that could leak information about the secret input. RFC 9106 Section 4 explicitly recommends Argon2id for general-purpose use because it combines Argon2i's side-channel resistance with Argon2d's GPU resistance. While the `argon2-cffi` library itself is industry-validated, the selected variant does not align with current standards. This inconsistency suggests the variant choice was not a deliberate security decision and demonstrates the need for a cryptographic inventory that would have caught this discrepancy. This affects both the election master key and per-voter tokens, potentially compromising ballot encryption and vote anonymity. In shared hosting or cloud environments, an attacker with co-tenant access could use cache timing attacks to extract data-dependent memory access patterns from Argon2d. The _hash() function is called by gen_opened_key() (tamper detection key) and gen_vote_token() (voter/issue token), both security-critical operations.

**Remediation:**

1. Document the cryptographic migration plan including timeline and risk assessment in SECURITY.md or architecture documentation. 2. Fix the HKDF info parameter to match current usage: use b'fernet_vote_key_v1' instead of b'xchacha20_key' until migration is complete. 3. Change _hash() function to use type=argon2.low_level.Type.ID (Argon2id) instead of Type.D: `type=argon2.low_level.Type.ID`. Better yet, use the high-level API: `from argon2 import PasswordHasher` with `ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)`. 4. Document the future XChaCha20-Poly1305 library dependency in the component risk assessment before adoption. 5. When migrating, update the info parameter to b'xchacha20_key_v1' at the same time as switching encryption algorithms to maintain cryptographic binding. 6. If Argon2d is intentional, document extensively: 'Argon2d is used intentionally because [justification]. This requires deployment in environments without shared memory/cache.' NOTE: Changing the Argon2 type will alter derived keys, making existing encrypted votes unrecoverable. This change must be coordinated with a migration plan for any elections with existing votes.

#### FINDING-181: HKDF Domain Separation Label Mismatches Actual Encryption Algorithm

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-327 |
| **ASVS Sections** | 11.3.3, 11.3.4, 11.3.5, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1 |
| **Files** | `v3/steve/crypto.py:59-70`, `v3/steve/crypto.py:73-78`, `v3/steve/crypto.py:59-69`, `v3/steve/crypto.py:73-76`, `v3/steve/crypto.py:60-71`, `v3/steve/crypto.py:74-79`, `v3/steve/crypto.py:82-87`, `v3/steve/crypto.py:52-57`, `v3/steve/crypto.py:53`, `v3/steve/crypto.py:53-62` |
| **Source Reports** | 11.3.3.md, 11.3.4.md, 11.3.5.md, 11.6.1.md, 11.6.2.md, 11.1.1.md, 11.1.2.md, 11.1.3.md, 11.2.1.md |
| **Related** | - |

**Description:**

The HKDF info parameter, which provides cryptographic domain separation per NIST SP 800-56C / RFC 5869, identifies the derived key as 'xchacha20_key' while the actual encryption uses Fernet (AES-128-CBC + HMAC-SHA256). This violates the principle of accurate domain separation in key derivation and creates a latent key reuse vulnerability. If XChaCha20-Poly1305 is later added alongside Fernet (as the comment suggests), both would derive keys with info=b'xchacha20_key', meaning the same key material feeds two different algorithms — a key reuse violation per NIST SP 800-57 §5.2. The mismatch between code labels and actual behavior makes cryptographic inventory inaccurate, directly contradicting ASVS 11.1.1's requirement for accurate key documentation. This creates two problems: (1) Inventory Falsification: Any automated or manual inventory reading the info field would incorrectly record XChaCha20-Poly1305 as the encryption algorithm; (2) Unsafe Algorithm Migration: When the planned migration to XChaCha20-Poly1305 occurs, if the same info value is retained, the derived keys will be identical to the current Fernet keys, eliminating cryptographic domain separation between old and new algorithms. The HKDF `info` parameter provides cryptographic domain separation to ensure keys derived for different purposes are cryptographically independent. Using b'xchacha20_key' when the actual cipher is Fernet creates future collision risk if XChaCha20-Poly1305 is later added (as comments suggest) with the same info label, and causes audit confusion by self-documenting an algorithm that is not in use.

**Remediation:**

Change the HKDF info parameter from b'xchacha20_key' to b'fernet_vote_key_v1' (or b'steve_fernet_vote_key_v1') to accurately reflect the actual encryption algorithm in use. Add version suffix to support future algorithm migrations. Update comment from '32-byte key for XChaCha20-Poly1305' to '32 bytes: 16-byte signing key + 16-byte AES-128 key (Fernet spec)'. Document algorithm migration strategy before switching from Fernet to XChaCha20-Poly1305. When migrating to XChaCha20-Poly1305, use a distinct info value like b'xchacha20_vote_key_v2' to maintain proper domain separation. CRITICAL NOTE: Changing the info parameter changes all derived keys and requires coordinated migration similar to the Argon2 type change. Existing encrypted votes will become undecryptable. This change requires a coordinated migration: (1) For new elections: will automatically use corrected HKDF after deployment; (2) For open elections: existing votes cannot be decrypted; must implement dual-algorithm support or complete tallying before upgrade; (3) For closed elections: historical data remains valid. Document this in the cryptographic inventory with version tracking and algorithm migration history.

---

#### FINDING-182: Cryptographic Decryption Errors Propagate Without Secure Handling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 11.2.5 |
| **Files** | `v3/steve/crypto.py:75`, `v3/steve/election.py:290`, `v3/steve/election.py:250` |
| **Source Reports** | 11.2.5.md |
| **Related** | - |

**Description:**

Cryptographic operations in crypto.py (encryption, decryption, key derivation) do not have exception handling and allow raw exceptions (cryptography.fernet.InvalidToken, argon2.exceptions.*, ValueError) to propagate through election.py to the transport layer. This can lead to: (1) Information disclosure via stack traces revealing encryption library, algorithm choices (Fernet), and internal architecture to attackers; (2) Availability issues where a single corrupted ciphertext prevents tallying of an entire election with no graceful degradation. While Fernet's encrypt-then-MAC design prevents padding oracle attacks specifically, the broader fail-secure principle is violated.

**Remediation:**

Add a dedicated crypto error class in crypto.py (CryptoError) that wraps all internal crypto exceptions to prevent leaking implementation details to callers. Wrap decrypt_votestring() and create_vote() in try-except blocks that catch cryptography.fernet.InvalidToken and other exceptions, log internally at DEBUG level, and raise sanitized CryptoError. Handle decryption failures gracefully in tally_issue by catching CryptoError, logging the error with a hash of the vote_token for audit purposes, and continuing to tally other votes rather than failing the entire election.

---

#### FINDING-183: Election and Issue IDs Generated with Insufficient Entropy (40 bits vs. 128-bit minimum)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L1 |
| **CWE** | - |
| **ASVS Sections** | 11.5.1, 7.2.3 |
| **Files** | `v3/steve/crypto.py:118`, `v3/schema.sql:61`, `v3/schema.sql:104`, `v3/steve/election.py:370`, `v3/steve/election.py:195` |
| **Source Reports** | 11.5.1.md, 7.2.3.md |
| **Related** | - |

**Description:**

create_id() generates reference tokens (election IDs eid, issue IDs iid) with only 40 bits of entropy (5 bytes × 8 = 40 bits). ASVS 7.2.3 mandates a minimum of 128 bits for reference tokens. While these are resource identifiers rather than session tokens directly, they function as security-critical reference tokens within authenticated sessions. The insufficient entropy becomes a security issue due to three compounding factors: (1) Authorization is systematically incomplete with '### check authz' comments and no actual enforcement, (2) IDs are exposed in URLs like /manage/&lt;eid&gt;, /do-vote/&lt;eid&gt;, /do-open/&lt;eid&gt;, (3) Brute-force feasibility—40 bits = ~1.1 trillion possible values. An authenticated attacker can enumerate valid election IDs systematically. Without authorization checks, discovering a valid eid grants full access.

**Remediation:**

Increase ID entropy to at least 128 bits (16 bytes → 32 hex characters). Update crypto.py create_id() to use secrets.token_hex(16). Update schema.sql CHECK constraints for both eid and iid to enforce length(eid) = 32 and length(iid) = 32 with corresponding GLOB patterns for 32 hex characters. Create database migration script for existing installations. Add rate limiting on election/issue lookup endpoints as defense-in-depth.

---

#### FINDING-184: Argon2 Parameters Adopted from Passlib Defaults Without Application-Specific Tuning

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 11.4.4 |
| **Files** | `v3/steve/crypto.py:78` |
| **Source Reports** | 11.4.4.md |
| **Related** | - |

**Description:**

The Argon2 parameters are explicitly annotated as 'Passlib default' with no evidence of application-specific tuning. ASVS 11.4.4 requires parameters that 'balance security and performance to prevent brute-force attacks.' The parallelism of 4 is higher than OWASP's recommended configurations which use p=1. There is no documented tuning rationale, and while a benchmark_argon2() function exists for parameter tuning, the production parameters still use untuned defaults. The untuned defaults are not inherently weak for this use case (high-entropy inputs), but they represent a process gap — the ASVS requirement expects deliberate parameter selection based on the application's performance budget and threat model.

**Remediation:**

1. Run the existing benchmark_argon2() on the production hardware. 2. Select parameters that target 100-500ms computation time per derivation. 3. Document the tuning rationale alongside the parameters, including hardware description, target computation time, benchmark date, and references to OWASP Password Storage Cheat Sheet and RFC 9106 Section 4. Consider reducing parallelism from 4 to 1 to match OWASP recommendations and increasing time_cost to maintain security level.

---

#### FINDING-185: External OAuth Service Dependency Hardcoded and Undocumented in Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.1.1 |
| **Files** | `v3/server/main.py:37-40`, `v3/server/config.yaml.example:entire file` |
| **Source Reports** | 13.1.1.md |
| **Related** | - |

**Description:**

The application has a hard runtime dependency on oauth.apache.org for authentication, but this external service is not documented in the configuration file. The OAuth endpoints are hardcoded in source code rather than externalized as configuration parameters. This prevents operators from performing accurate network security planning and violates ASVS 13.1.1 requirement to document external services which the application relies upon.

**Remediation:**

Add OAuth configuration to config.yaml.example documenting auth_url, token_url, and redirect_uri construction. Update main.py to use configuration values instead of hardcoded URLs. Example:

```yaml
oauth:
    auth_url: "https://oauth.apache.org/auth"
    token_url: "https://oauth.apache.org/token"
```

Update main.py:
```python
asfquart.generics.OAUTH_URL_INIT = f'{app.cfg.oauth.auth_url}?state=%s&redirect_uri=%s'
asfquart.generics.OAUTH_URL_CALLBACK = f'{app.cfg.oauth.token_url}?code=%s'
```

---

#### FINDING-186: Absence of Comprehensive Communication Architecture Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.1.1 |
| **Files** | `v3/server/config.yaml.example:entire file`, `v3/server/main.py:38`, `v3/server/main.py:40` |
| **Source Reports** | 13.1.1.md |
| **Related** | - |

**Description:**

ASVS 13.1.1 at Level 2 requires all communication needs to be documented. The current config.yaml.example provides incomplete coverage of the application's communication architecture. Only 3 out of 8 communication channels are documented (inbound HTTP/HTTPS, TLS configuration, SQLite database). Missing documentation includes: OAuth endpoints (outbound), LDAP backend, CLI tallying tools inter-process communication, and OAuth callbacks (inbound).

**Remediation:**

Add comprehensive communication architecture documentation section to config.yaml.example that includes:
- INBOUND: HTTPS on configured port, OAuth callback from oauth.apache.org
- OUTBOUND: HTTPS to oauth.apache.org (authentication), LDAPS to LDAP server (authorization)
- LOCAL: SQLite database file, CLI tools database access
- USER-CONTROLLABLE DESTINATIONS: Document that application does not connect to user-specified URLs

Include complete configuration sections for oauth, ldap, and server.base_url settings.

---

#### FINDING-187: Debug Logging Level Enabled by Default in Both Run Modes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.1, 13.4.2, 15.2.3, 13.4.6 |
| **Files** | `v3/server/main.py:50`, `v3/server/main.py:91`, `v3/server/config.yaml.example:entire file` |
| **Source Reports** | 13.1.1.md, 13.4.2.md, 15.2.3.md, 13.4.6.md |
| **Related** | - |

**Description:**

The run_asgi() function (lines 85-96 in main.py) is the production code path triggered when the module is imported by Hypercorn. It unconditionally sets logging.DEBUG level on both basicConfig and the application logger (_LOGGER.setLevel(logging.DEBUG) on line 96). This causes all application-level debug messages including cryptographic operations, database queries, and election state transitions to be written to production logs. While current debug messages in election.py are relatively benign, the DEBUG level setting means any future debug logging added anywhere in the application will automatically be exposed in production, creating a latent information disclosure risk characteristic of development configuration that was not hardened for production. ASVS 15.2.3 requires production environments to not expose extraneous functionality such as development functionality.

**Remediation:**

Set production logging to INFO level in run_asgi(): 1. Change logging.basicConfig level to logging.INFO. 2. Use environment variable override for log level configuration to allow operational flexibility without hardcoding DEBUG in production code. Example implementation: `log_level = os.environ.get('STEVE_LOG_LEVEL', 'INFO').upper()` and `_LOGGER.setLevel(getattr(logging, log_level, logging.INFO))`. 3. Document in deployment guide that DEBUG logging should only be enabled temporarily for troubleshooting and never left enabled in production. 4. Consider implementing separate log levels for different components (web server, crypto operations, database) for more granular control.

---

#### FINDING-188: No Web Server Concurrency Limits Configured or Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.2 |
| **Files** | `v3/server/config.yaml.example`, `v3/server/main.py:50-88`, `v3/server/main.py:91-108` |
| **Source Reports** | 13.1.2.md |
| **Related** | - |

**Description:**

The server configuration and startup code define no maximum concurrent connections, worker limits, request queue sizes, or keepalive timeouts. The config.yaml.example only specifies port and TLS settings. Neither standalone nor ASGI mode documents or configures concurrency boundaries. Without documented and configured connection limits, the application relies entirely on the default behavior of asfquart/Hypercorn, which may accept thousands of concurrent connections. Combined with the database and Argon2 resource issues above, this creates a multiplier effect for resource exhaustion. Operations teams have no documented guidance on capacity planning or expected failure modes.

**Remediation:**

1. Add server concurrency configuration to config.yaml.example: max_connections (100), workers (2), keepalive_timeout (30 seconds), request_timeout (60 seconds), and documented behavior when max_connections reached (new connections receive 503). 2. For Hypercorn ASGI deployment, document and provide a hypercorn.toml configuration file with bind, workers (2), backlog (100), and graceful_timeout (10) settings.

---

#### FINDING-189: No OAuth Service Connection Limits or Failure Handling Documented

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.1.2, 13.1.3, 13.2.6 |
| **Files** | `v3/server/main.py:35-38`, `v3/server/main.py:32-37`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.1.2.md, 13.1.3.md, 13.2.6.md |
| **Related** | - |

**Description:**

The application integrates with an external OAuth service (oauth.apache.org) for authentication. There is no documented or configured connection limit, timeout, retry policy, or fallback behavior for when the OAuth service is unreachable or slow. The URLs are hardcoded with no resilience configuration. If oauth.apache.org becomes slow or unresponsive, authentication requests will hang indefinitely (no timeout configured), consuming server resources (connections, worker threads). A slowloris-style attack against the OAuth provider or DNS manipulation could cause cascading failure in the voting application. No documentation exists for operators on how to detect or respond to OAuth service degradation.

**Remediation:**

Document OAuth service dependencies and limits in configuration: base_url (https://oauth.apache.org), connect_timeout (5 seconds), read_timeout (10 seconds), max_retries (2), circuit_breaker_threshold (5 failures before opening circuit), fallback behavior (display 'Authentication service unavailable' page), and recovery mechanism (auto-retry after 30 seconds). Configure the HTTP client used by asfquart.generics to apply these parameters.

---

#### FINDING-190: Configuration Template Lacks Secret Management Guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-1059 |
| **ASVS Sections** | 13.1.4 |
| **Files** | `v3/server/config.yaml.example:1-22` |
| **Source Reports** | 13.1.4.md |
| **Related** | FINDING-066, FINDING-151 |

**Description:**

The configuration template (config.yaml.example) is the primary operational reference for deploying the application. It contains no guidance about which values are security-sensitive, how secrets should be injected (e.g., environment variable overrides via asfquart), or what file permissions should be applied. The domain context indicates the application supports environment variable integration via asfquart, but this capability is completely undocumented in the template. There is no indication that keyfile contains a private key requiring restricted permissions, no mention of additional secrets (OAuth credentials) that exist outside this file, no documentation on using environment variables to override sensitive values, no guidance on what file permissions config.yaml itself should have in production, no warning that db: steve.db references a file containing election cryptographic keys, and no .gitignore reference to prevent committing production values.

**Remediation:**

Replace config.yaml.example with comprehensive security guidance including: security checklist before deployment, secrets management section warning against storing secrets directly in config.yaml in production, documentation of supported environment variables (STEVE_PORT, STEVE_CERTFILE, STEVE_KEYFILE, STEVE_DB, STEVE_OAUTH_SECRET), inline security comments for each configuration value indicating sensitivity level and required file permissions (0600 for keyfile and database, 0644 for certfile), deployment checklist with file permission commands, and reference to SECURITY.md for complete secrets management procedures. Create/update .gitignore to include config.yaml, *.db, certs/*.pem, .env files, and backup files. Create configuration validation script (validate_config.py) that checks file permissions, .gitignore entries, and required environment variables before deployment.

---

#### FINDING-191: Database Access Lacks Authentication and Permission Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.2.1 |
| **Files** | `v3/steve/election.py:40`, `v3/steve/election.py:46`, `v3/steve/election.py:365`, `v3/steve/election.py:381`, `v3/steve/election.py:390`, `v3/steve/election.py:402`, `v3/steve/election.py:412` |
| **Source Reports** | 13.2.1.md |
| **Related** | - |

**Description:**

The database stores high-value cryptographic material: `opened_key` (Argon2 hash enabling vote token derivation), per-voter `salt` values (enabling vote decryption when combined with opened_key), and encrypted vote ciphertext. While SQLite is an in-process library without native authentication, ASVS 13.2.1 requires data layer access to be authenticated. No compensating controls exist — the code does not verify file ownership, permissions, or employ database-level encryption (e.g., SQLCipher). Any process running as the same user can open the database and extract `opened_key` and `salt` values, which are sufficient to derive vote tokens and decrypt all votes.

**Remediation:**

Add file permission verification in `open_database()` to ensure the database file has restrictive permissions (0o600 or stricter). Verify file ownership and reject overly permissive modes. Set restrictive permissions on newly created databases. Additionally, consider SQLCipher or application-level database encryption for the `opened_key` and `salt` columns.

---

#### FINDING-192: OAuth Backend Communication Lacks Visible Authentication Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.2.1 |
| **Files** | `v3/server/main.py:39-43`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.2.1.md |
| **Related** | - |

**Description:**

The application performs a backend-to-backend HTTP call to `oauth.apache.org/token` during the OAuth token exchange, which requires OAuth client credentials (`client_id` and `client_secret`). However, `config.yaml.example` contains zero credential-related configuration — no OAuth settings, no environment variable references, no vault integration examples. The `asfquart` framework presumably manages OAuth client secrets, but this is opaque from the application's perspective. Without visible credential management configuration, it is impossible to verify that OAuth client secrets are not hardcoded, can be rotated without code changes, use distinct credentials per environment, or follow ASVS 13.2.1 requirements (not unchanging shared passwords).

**Remediation:**

Update `config.yaml.example` to document the expected secret management pattern with environment variable references (e.g., `${STEVE_OAUTH_CLIENT_ID}`, `${STEVE_OAUTH_CLIENT_SECRET}`). Add documentation indicating credentials MUST be provided via environment variables or secrets vault and should not be placed directly in configuration files. In application code, verify credential source at startup and warn if secrets appear to be literal values rather than environment variable references.

---

#### FINDING-193: All Database Connections Use Uniform Read-Write Privileges Without Least-Privilege Separation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.2.2 |
| **Files** | `v3/steve/election.py:45` |
| **Source Reports** | 13.2.2.md |
| **Related** | - |

**Description:**

All database operations, regardless of whether they require read or write access, use the same connection type with full read-write privileges. There is no mechanism to open read-only database connections for operations that only query data. Read-only operations (listing elections, checking vote status, retrieving metadata, tallying) hold connections capable of writing to the database. If any code path is compromised (e.g., through a future bug in the web layer), the existing connection has full write access even when the intended operation is read-only. The `__getattr__` proxy means any code with an `Election` reference can invoke any database cursor, including `c_delete_election`, `c_delete_issues`, etc. Class method connections are not explicitly closed, extending the window where overprivileged connections exist.

**Remediation:**

Implement separate read-only and read-write database connection methods. Modify `open_database()` to accept a `readonly` parameter. For SQLite, use URI mode with `?mode=ro` or execute `PRAGMA query_only = ON` after connection for read-only access. Apply `readonly=True` to class methods: `open_to_pid()`, `owned_elections()`, `upcoming_to_pid()`, `list_closed_election_ids()`, and instance methods: `tally_issue()`, `has_voted_upon()`, `get_metadata()`. Explicitly close database connections in class methods using try/finally blocks. Review and restrict the `__getattr__` proxy scope to prevent unintended database operations through attribute access.

---

#### FINDING-194: Missing External Communications Allowlist

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.2.4, 13.2.5 |
| **Files** | `v3/server/config.yaml.example:entire file`, `v3/server/main.py:43-46` |
| **Source Reports** | 13.2.4.md, 13.2.5.md |
| **Related** | - |

**Description:**

The application configuration (config.yaml.example) defines no allowlist of permitted external resources. The application communicates with at least one external service (oauth.apache.org), and the domain context indicates LDAP and potentially email services are also used. No centralized, configurable allowlist exists to define and restrict these communications. No single auditable location documents all permitted external communications. If any code path makes outbound requests based on user-controlled data, there is no enforcement mechanism to prevent SSRF or unauthorized data exfiltration. New external integrations can be added without updating a central policy. Deployment hardening cannot reference an application-defined list for firewall rules.

**Remediation:**

Add an external communications allowlist to the application configuration with sections for oauth, ldap, and other external resources including host, port, protocol, and purpose. Implement an enforcement wrapper (OutboundAllowlist class) for outbound connections that validates URLs against the configured allowlist and raises PermissionError for unauthorized destinations. Add 'allowed_outbound_hosts' and 'allowed_file_paths' entries. Enforce these allowlists at application startup by validating all configured outbound endpoints against the host allowlist and all file paths (db, certfile, keyfile) against the allowed directories.

---

#### FINDING-195: OAuth Redirect URI Not Validated Against Allowlist

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.2.4 |
| **Files** | `v3/server/main.py:43-46` |
| **Source Reports** | 13.2.4.md |
| **Related** | - |

**Description:**

The OAuth redirect_uri parameter in OAUTH_URL_INIT is constructed using string formatting (%s), and the value that populates this parameter comes from the asfquart framework (not visible in provided code). If the redirect_uri is derived from request-controlled data (e.g., the Host header) without validation against an allowlist of permitted callback URLs, this could allow an attacker to redirect OAuth callbacks to an attacker-controlled server, capturing authorization codes. This enables OAuth authorization code theft and potential account takeover, particularly impactful for election administrators.

**Remediation:**

Define an explicit allowlist for permitted OAuth redirect URIs in the configuration file (oauth.allowed_redirect_uris). Validate the redirect URI against the allowlist and use a hardcoded value from the allowlist rather than deriving it from request context. Ensure redirect_uri is URL-encoded properly using urllib.parse.quote.

---

#### FINDING-196: No Backend Connection Configuration for Any External or Internal Service

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-1188 |
| **ASVS Sections** | 13.2.6 |
| **Files** | `v3/server/config.yaml.example:1-5`, `v3/steve/election.py:39`, `v3/steve/election.py:458`, `v3/steve/election.py:470`, `v3/steve/election.py:484`, `v3/steve/election.py:496`, `v3/steve/election.py:436` |
| **Source Reports** | 13.2.6.md |
| **Related** | - |

**Description:**

The application's configuration file (config.yaml.example) serves as the sole documented configuration surface. It defines only server port, TLS certificate paths, and database path. There is zero configuration for any connection management parameter required by ASVS 13.2.6. The application connects to at least two backend services: SQLite Database via asfpy.db.DB() throughout election.py and Apache OAuth Provider via https://oauth.apache.org/ in main.py. Neither service has documented or configurable connection management parameters. Operators attempting to configure production connection behavior have no documented mechanism for timeouts, connection pools, retry strategies, or max connection limits.

**Remediation:**

Add a backend connection configuration section to config.yaml.example with database settings (busy_timeout, max_connections, journal_mode) and OAuth settings (connect_timeout, read_timeout, max_retries, retry_backoff_factor, pool_connections, pool_maxsize). Update application initialization in main.py create_app() to read and apply these settings to both database connections and OAuth HTTP client configuration.

---

#### FINDING-197: State-Checking Operations Unnecessarily Retrieve Full Secret Material

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.3.2 |
| **Files** | `v3/steve/election.py:125`, `v3/steve/election.py:329`, `v3/steve/election.py:318`, `v3/steve/election.py:322`, `v3/steve/election.py:326`, `v3/steve/election.py:135`, `v3/steve/election.py:78` |
| **Source Reports** | 13.3.2.md |
| **Related** | - |

**Description:**

The `_all_metadata()` method retrieves complete election metadata including cryptographic secrets (`salt` and `opened_key`) for every call, even when the calling code only needs to check state or retrieve non-sensitive metadata. Six different methods call `_all_metadata()` when they only need NULL/NOT-NULL checks or non-secret fields. The `opened_key` (master election secret enabling vote decryption) is loaded into memory during every state check, metadata request, and election data gathering — operations that have no need for the actual key values. `_compute_state()` only checks for NULL/NOT-NULL status but receives actual secret bytes. State checks occur on nearly every request path (election display, voting eligibility, metadata), broadening the window where secrets reside in process memory. If any exception handler, debugger, or future logging change captures local variables, `md.salt` and `md.opened_key` would be exposed.

**Remediation:**

Create a separate state-only query and method that returns only the information needed for state computation. Add a new query `q_state_info` that returns only `closed`, `has_salt` (boolean check), and `has_key` (boolean check) without retrieving actual secret values. Implement `_get_state_info()` method to use this query and refactor `get_state()` to use `_compute_state_from_flags()` that works with boolean flags instead of actual secret data.

---

#### FINDING-198: Unrestricted Database Cursor Proxy Bypasses Secret-Filtering Controls

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.3.2 |
| **Files** | `v3/steve/election.py:44` |
| **Source Reports** | 13.3.2.md |
| **Related** | - |

**Description:**

The `Election` class implements `__getattr__()` to proxy database cursor access, which allows any code with an `Election` instance to bypass the intentional secret-filtering in `get_metadata()` by directly accessing `q_metadata` cursor. The developer intentionally created `get_metadata()` to filter `salt` and `opened_key` from public access, but the `__getattr__` proxy makes the underlying secret-returning cursor equally accessible. Any module that imports and uses the `Election` class (API handlers, page handlers, CLI tools) can directly access `q_metadata` and retrieve full secrets without going through the filtering method. This creates false confidence that secrets are protected by the `get_metadata()` abstraction.

**Remediation:**

Restrict the `__getattr__` proxy to only expose safe cursors using an allowlist approach. Create a `_SAFE_PROXIED_ATTRS` frozenset containing only non-secret-accessing cursor names and raise `AttributeError` for any other attribute access. Alternatively, create private methods like `_get_opened_key()` that explicitly retrieve secret material and require conscious method calls rather than allowing direct cursor access.

---

#### FINDING-199: No Secret Management System Integration for Application Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-256 |
| **ASVS Sections** | 13.3.3 |
| **Files** | `v3/server/config.yaml.example:entire file`, `v3/server/main.py:41` |
| **Source Reports** | 13.3.3.md |
| **Related** | - |

**Description:**

The application manages OAuth client secrets, database encryption keys, LDAP credentials, and Fernet encryption keys, but the configuration system shows no integration with any secret management solution (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, SOPS, etc.). The example configuration template (config.yaml.example) contains no placeholder patterns for environment variable substitution (e.g., ${ENV_VAR}) or vault references. While asfquart may support environment variable overrides at the framework level, no documentation or configuration patterns demonstrate secure secret injection for any of the identified secret categories. This means secrets are likely stored in plaintext in the configuration file or passed directly as environment variables without centralized management, rotation support, or access auditing.

**Remediation:**

Integrate a secret management system and document the pattern. Update config.yaml to use vault references (e.g., vault://secret/steve/tls#certfile, vault://secret/steve/db#key) or environment variable placeholders (e.g., env://STEVE_OAUTH_SECRET). At minimum, document environment variable usage for all secrets with clear provisioning instructions. Implement vault client initialization in main.py during app construction to resolve vault references before configuration is used. Provide deployment documentation (deployment/secrets.md) detailing secret provisioning procedures.

---

#### FINDING-200: Key Material Exposed in Python Exception Tracebacks and Debug Logging

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-532 |
| **ASVS Sections** | 13.3.3 |
| **Files** | `v3/steve/crypto.py:38-80`, `v3/steve/election.py:222-236`, `v3/steve/election.py:257-299`, `v3/steve/election.py:238-256`, `v3/server/main.py:57`, `v3/server/main.py:97`, `v3/steve/election.py:80-81` |
| **Source Reports** | 13.3.3.md |
| **Related** | FINDING-071 |

**Description:**

Key material (opened_key, vote_token, b64key, plaintext votestring) is passed as plain function parameters and stored in local variables without exception wrapping. If any exception occurs during cryptographic operations, Python's default exception handling will include all function arguments and local variables in the traceback. Both server entry points (run_standalone, run_asgi) default to DEBUG logging level, which would write these tracebacks to logs. The crypto.py module has no exception wrapping around cryptographic operations. Commented-out print statements for SALT and KEY in election.py (lines 80-81) demonstrate historical key material logging during development, creating risk of re-enabling during debugging. Log aggregation systems, monitoring tools, or log file access could expose this material.

**Remediation:**

1. Wrap cryptographic operations in exception handlers that sanitize key material. Use 'raise ... from None' to suppress original tracebacks that contain key material. Log only exception type and issue ID, not full tracebacks. Add finally blocks to clear local key references (set to None). 2. Set production logging to INFO or WARNING level. Make DEBUG logging opt-in via environment variable (STEVE_LOG_LEVEL) rather than the default. 3. Remove all commented-out key printing statements (lines 80-81 in election.py) entirely from the codebase to prevent accidental re-enabling.

---

#### FINDING-201: Per-Voter Cryptographic Salts Never Expire or Rotate

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.3.4 |
| **Files** | `v3/steve/election.py:134-154`, `v3/steve/crypto.py:35-37` |
| **Source Reports** | 13.3.4.md |
| **Related** | - |

**Description:**

Per-voter cryptographic salts in the mayvote table are generated once when an election is opened and never expire or rotate. While per-voter salts are critical for vote anonymity (preventing cross-voter correlation), there is no mechanism for the salts to have a defined maximum lifetime or be securely zeroed after use. Combined with the indefinite persistence of the election master key, the complete key derivation chain (opened_key → vote_token → vote_key) remains reconstructable from database contents alone, without any time-bound protection.

**Remediation:**

Integrate salt destruction into the purge_crypto() method from the secret destruction finding. Additionally, add a created_at timestamp to the mayvote salt records to enable age-based expiration policies. This allows tracking of salt age and enforcement of maximum lifetime policies.

---

#### FINDING-202: No Explicit HTTP TRACE Method Blocking at Application or Server Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.4.4 |
| **Files** | `v3/server/main.py:33-45`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.4.4.md |
| **Related** | - |

**Description:**

The application relies entirely on Quart's implicit behavior (returning 405 for methods not registered on any route) to prevent TRACE handling. There is no explicit, defense-in-depth control: (1) No application middleware exists to reject TRACE requests before route dispatch. (2) No server configuration (config.yaml.example) includes HTTP method restrictions. (3) No reverse proxy configuration is included in the codebase, despite the comment stating 'Typical usage is that a proxy sits in front of this server.' The proxy configuration, which would be the primary defense point, is not provided or templated. (4) No ASGI middleware is registered that would block TRACE before it reaches routing logic. While Quart's default behavior provides implicit protection (no route explicitly accepts TRACE), this is fragile: A catch-all error handler or routing change could inadvertently respond to TRACE; the pages and api modules (imported but not provided for review) could register routes accepting all methods; without the reverse proxy config, there's no verifiable TRACE blocking at the infrastructure tier.

**Remediation:**

Add explicit TRACE blocking middleware to the application and provide production proxy configuration. In main.py, after app creation, add a before_request hook to abort with 405 if request.method == 'TRACE'. Additionally, provide a production reverse proxy configuration template (nginx.conf.example or Apache httpd config) that blocks TRACE and TRACK methods at the proxy level using appropriate directives (e.g., 'if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }' for nginx or 'TraceEnable Off' for Apache). Add integration tests to verify TRACE returns 405 across all endpoints. Document the expected production deployment architecture including proxy TRACE blocking in a deployment guide.

---

#### FINDING-203: Production ASGI Deployment Path Enables DEBUG-Level Logging

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.4.5 |
| **Files** | `v3/server/main.py:95-99`, `v3/server/main.py:104`, `v3/steve/election.py:46`, `v3/steve/election.py:189`, `v3/steve/election.py:403` |
| **Source Reports** | 13.4.5.md |
| **Related** | - |

**Description:**

The production deployment entry point `run_asgi()` configures the logging system with DEBUG-level verbosity, which causes extensive operational details to be logged in production environments. This violates the ASVS principle that 'Production configurations should be hardened to avoid disclosing unnecessary data.' Production logs capture DEBUG-level output from all application and library modules, including internal operation details (election IDs, retry behavior, database interactions) and verbose library logging (asyncio, HTTP handling, TLS) that may expose connection details, timing information, or internal state.

**Remediation:**

Change production log level to WARNING in `run_asgi()` and set application logger to INFO. Make log level configurable through `config.yaml` with a `log_level` setting. Example: `logging.basicConfig(level=logging.WARNING, ...)` and `_LOGGER.setLevel(logging.INFO)`. Add configuration: `server: { log_level: WARNING }` in config.yaml template.

---

#### FINDING-204: No Production Configuration Controls for Endpoint Exposure and Debug Mode

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 13.4.5 |
| **Files** | `v3/server/config.yaml.example:1-12`, `v3/server/main.py:33-43`, `v3/server/main.py:88-107` |
| **Source Reports** | 13.4.5.md |
| **Related** | - |

**Description:**

The production configuration template provides no mechanism to explicitly control debug mode, log levels, or endpoint exposure. This prevents operators from verifying production hardening through configuration review and provides no defense-in-depth mechanism to disable debug features. The configuration file lacks settings to: (1) explicitly disable debug mode, (2) control log verbosity, (3) disable framework-provided endpoints, and (4) enable/disable monitoring endpoints. Production deployments cannot be audited for proper hardening through configuration review alone, and it is unclear which endpoints the `asfquart` framework registers by default beyond the explicitly imported `pages` and `api` modules.

**Remediation:**

Add production hardening settings to `config.yaml.example`: `debug: false`, `log_level: WARNING`, and `enable_health_endpoint: false`. Enforce these settings in `create_app()` by checking `app.cfg.server.get('debug', False)` and setting `app.debug = False` and `app.config['TESTING'] = False` when debug is disabled. Provide documented endpoint inventory and exposure controls.

---

#### FINDING-205: Hypercorn Server Header Exposes Backend Component Identity and Version

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.4.6 |
| **Files** | `v3/server/main.py:32-42`, `v3/server/main.py:82-103`, `v3/server/config.yaml.example:entire file` |
| **Source Reports** | 13.4.6.md |
| **Related** | - |

**Description:**

The application uses Hypercorn as its production ASGI server. Hypercorn, by default, sends a `Server` response header on every HTTP response (e.g., `server: hypercorn-h11` or `server: hypercorn-h2`), which directly discloses the server software name and transport protocol version to any client. Neither the application startup code nor the configuration template includes any mechanism to suppress or override this header. An attacker can fingerprint the backend technology stack without any application interaction. This enables targeted attacks against known Hypercorn vulnerabilities and reduces attacker reconnaissance effort.

**Remediation:**

Option A (recommended): Create a `hypercorn.toml` configuration with `include_server_header = false` and launch with `hypercorn --config hypercorn.toml main:steve_app`. Option B: Add after-request middleware in `create_app()` to strip Server and X-Powered-By headers using `@app.after_request` decorator. Option C: Add `suppress_server_header: true` to config.yaml and apply during app creation.

---

#### FINDING-206: Sensitive Data Files Co-Located in Application Directory Without File-Extension Serving Restrictions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.4.7 |
| **Files** | `v3/server/config.yaml.example:34`, `v3/server/main.py:28` |
| **Source Reports** | 13.4.7.md |
| **Related** | - |

**Description:**

The SQLite database (steve.db), configuration file (config.yaml), query definitions (queries.yaml), TLS private key (*.pem), and Python source files (.py) all reside within or directly adjacent to the application directory tree. While static_folder=None prevents the Quart framework from serving these files, the documented deployment model uses a reverse proxy, and no proxy configuration is provided or enforced to restrict served file types. If the reverse proxy is misconfigured or a new route handler is added that inadvertently serves file contents, an attacker could obtain the SQLite database containing all election data, encrypted votes, cryptographic salts, and opened_keys enabling offline decryption of all votes; TLS private keys enabling man-in-the-middle attacks; application source code enabling targeted vulnerability discovery; and Git history potentially containing committed secrets.

**Remediation:**

1. Move sensitive data files outside the application directory tree: Use absolute paths outside web root for database (e.g., /var/lib/steve/steve.db) and certificates (e.g., /etc/steve/certs). 2. Add application-level middleware to restrict response content types to allowed types (text/html, application/json, text/css, application/javascript) and log/block unexpected content types. 3. Provide and document required reverse proxy configuration with rules to block access to sensitive file extensions (.db, .sqlite, .yaml, .yml, .py, .pyc, .pem, .key, .git, .env, .cfg, .ini, .log), hidden files/directories, and only proxy defined API/page routes.

---

#### FINDING-207: No Documented or Enforced Production Web Tier Hardening for File-Type Restrictions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Sections** | 13.4.7 |
| **Files** | `v3/server/main.py`, `v3/server/config.yaml.example` |
| **Source Reports** | 13.4.7.md |
| **Related** | - |

**Description:**

The config.yaml.example references a reverse proxy deployment model ('a proxy sits in front of this server'), but the codebase contains no reverse proxy configuration templates, deployment hardening documentation, or automated configuration validation to ensure file extension restrictions are applied in production. ASVS 13.4.7 Level 3 requires verification that the web tier (not just the application framework) restricts served file types. Without enforceable proxy configuration, this requirement cannot be verified as satisfied. Neither the standalone mode nor ASGI/Hypercorn mode configures file-extension restrictions at the ASGI server level. Without documented and enforced web tier configuration, deployments may omit file-extension restrictions entirely, new team members or automated deployments may expose the application directly without a properly configured proxy, and the ASVS 13.4.7 requirement cannot be verified as consistently met across deployments.

**Remediation:**

1. Include a production reverse proxy configuration template in the repository (v3/deploy/ directory with nginx.conf.example, deployment-checklist.md, and hardening.md). 2. Add a startup check that verifies the application is not directly exposed by warning if running on ports 80/443. 3. Add ASGI middleware to reject requests for common sensitive extensions (.db, .sqlite, .yaml, .yml, .py, .pyc, .pem, .key, .env, .cfg, .ini, .log, .git, .bak, .swp, .old) with logging and 404 responses.

---

#### FINDING-208: Debug Logging of Unclassified Form Data to Standard Output

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Sections** | 14.1.1, 14.1.2, 14.2.4 |
| **Files** | `v3/server/pages.py:487`, `v3/server/pages.py:507`, `v3/server/pages.py:509`, `v3/server/pages.py:533` |
| **Source Reports** | 14.1.1.md, 14.1.2.md, 14.2.4.md |
| **Related** | - |

**Description:**

Debug print() statements in do_add_issue_endpoint() and do_edit_issue_endpoint() dump all form fields (including issue titles, descriptions containing confidential candidate information, and any future form fields) to stdout with uncontrolled retention. This data flows to container logs, log aggregation systems (ELK, Splunk, CloudWatch) with extended retention, and is accessible to operations teams who should not see election content. The presence of print() statements demonstrates that form data has not been assigned a protection level with handling rules.

**Remediation:**

1. Immediate: Remove all debug print() statements from do_add_issue_endpoint() and do_edit_issue_endpoint(). 2. Short-term: Implement structured logging with SensitiveFieldFilter that removes sensitive fields from log records. 3. Long-term: Add data classification to logging policy with is_loggable() method that determines if a field can be logged based on its classification (CRITICAL/SENSITIVE: never log, INTERNAL: log field name only, PUBLIC: log freely).

---

#### FINDING-209: Voter-Issue Timing Correlation Recorded in Application Logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-203 |
| **ASVS Sections** | 14.1.2, 14.2.4 |
| **Files** | `v3/server/pages.py:~427-429`, `v3/server/pages.py:425`, `v3/server/pages.py:426`, `v3/server/pages.py:427`, `v3/steve/election.py:~207`, `v3/schema.sql:N/A` |
| **Source Reports** | 14.1.2.md, 14.2.4.md |
| **Related** | - |

**Description:**

Per-issue vote logging in `do_vote_endpoint` creates a timing side channel that enables voter-vote correlation. The code logs each individual vote submission with `_LOGGER.info(f'User[U:{result.uid}] voted on issue[I:{iid}] in election[E:{election.eid}]')` inside the vote processing loop. Combined with the `vote` table's auto-incrementing `vid` column, this enables correlation between voter identity and votes through timing analysis. An attacker with access to both application logs and the database can map log timestamps to `vid` ranges to narrow down which vote tokens belong to which voters, undermining the cryptographic separation designed to protect ballot secrecy.

**Remediation:**

Replace per-issue vote logging with aggregated ballot submission logging. Before the vote processing loop, count the number of votes with `vote_count = len(votes)`. Remove the logging statement from inside the loop. After the loop completes successfully, log a single aggregated entry: `_LOGGER.info(f'User[U:{result.uid}] submitted ballot for election[E:{election.eid}] ({vote_count} issue(s))')`. This maintains audit capability while preventing timing correlation attacks.

---

#### FINDING-210: Authorization-Protected Documents Served via send_from_directory Without Cache Prevention

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Sections** | 14.2.2, 14.2.5 |
| **Files** | `v3/server/pages.py:555-565`, `v3/server/pages.py:557` |
| **Source Reports** | 14.2.2.md, 14.2.5.md |
| **Related** | - |

**Description:**

The /docs/&lt;iid&gt;/&lt;docname&gt; endpoint serves election documents after verifying voter eligibility via the mayvote table. However, quart.send_from_directory() uses framework defaults which typically set Cache-Control: public or include max-age based on SEND_FILE_MAX_AGE_DEFAULT config. This actively encourages intermediate caches to store authorization-protected documents. Election documents containing ballot details, candidate information, or voting instructions could be served from cache to unauthorized users, bypassing the authorization check.

**Remediation:**

Override cache headers on the response from send_from_directory() before returning. After calling send_from_directory, set response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private', response.headers['Pragma'] = 'no-cache', and response.headers['Expires'] = '0' before returning the response object. Additionally, validate the docname parameter to prevent path traversal and enforce allowed content types.

#### FINDING-211: External Image Loaded on All Pages Leaks Voter Activity Metadata to Third-Party Server

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.3 |
| **Files** | `v3/server/templates/header.ezt:22` |
| **Source Reports** | 14.2.3.md |
| **Related Findings** | - |

**Description:**

The application's navigation header includes an external image resource loaded from `https://www.apache.org/foundation/press/kit/feather.svg`. This image is automatically fetched by the browser on every page load, including sensitive voting pages. The HTTP request to apache.org transmits voter metadata outside the application's control, creating an externally-observable record of voting activity. The request transmits voter IP address, User-Agent header, Referer header (potentially including election ID), and precise timestamp of page access. Apache.org's web server logs record correlations between voter network identity, voting system origin, specific election being accessed, and precise timing. This creates an external record of voting activity that violates ballot secrecy principles and ASVS 14.2.3 requirements that sensitive data not be sent to untrusted parties.

**Remediation:**

**Immediate Fix (Priority 1):** Download and host the Apache feather logo locally. Download the image to static assets directory using `curl -o v3/server/static/img/feather.svg https://www.apache.org/foundation/press/kit/feather.svg`. Update `header.ezt` to use local path: `<img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top">`. **Defense-in-Depth (Priority 2):** Add a `Referrer-Policy` header at the application level using middleware: `response.headers['Referrer-Policy'] = 'same-origin'`. Optionally add CSP to prevent future external resource inclusion: `response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"`.

---

#### FINDING-212: Missing Vote Content Validation Before Encryption

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.4 |
| **Files** | `v3/steve/election.py:221` |
| **Source Reports** | 14.2.4.md |
| **Related Findings** | - |

**Description:**

Arbitrary strings are accepted as vote content and encrypted without validation against the issue's vote type. Invalid votes cannot be detected until decryption during tallying, when correction is impossible. The add_vote() function contains a comment '### validate VOTESTRING for ISSUE.TYPE voting' but no actual implementation. Invalid vote content (e.g., 'xyz' for a YNA vote, or 'a,a,a,b' with duplicates for STV) would either produce incorrect tallies or cause tally-time errors. Since votes are encrypted, invalid content cannot be detected until the offline tallying process when the election is closed.

**Remediation:**

Implement vote validation in add_vote() before encryption: issue = self.q_get_issue.first_row(iid); m = vtypes.vtype_module(issue.type); if not m.validate(votestring, self.json2kv(issue.kv)): raise ValueError(f'Invalid vote format for {issue.type} issue'). This ensures data integrity verification at the point of collection.

---

#### FINDING-213: Voting Page Returns All Issues Instead of Per-Issue Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.6 |
| **Files** | `v3/server/pages.py:244-270` |
| **Source Reports** | 14.2.6.md |
| **Related Findings** | - |

**Description:**

The voting page performs a coarse-grained eligibility check (does the voter have ANY mayvote entries for this election?) but then returns ALL issues for the election, including issues the voter is not authorized to vote on. The mayvote table is designed for per-issue authorization, but the voting interface ignores this granularity. In elections where different voter groups are authorized for different issues, a voter authorized for even one issue sees all issues and their full descriptions, including STV candidate lists.

**Remediation:**

Filter list_issues() results in vote_on_page() to return only issues the voter is authorized for based on their mayvote entries. Query q_find_issues to get authorized issue IDs (iids), then filter all_issues to only include those matching the authorized set before rendering to the template.

---

#### FINDING-214: List Query Methods Return Raw Database Rows Without Field Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.6 |
| **Files** | `v3/steve/election.py:410`, `v3/steve/election.py:432`, `v3/server/pages.py:137`, `v3/server/pages.py:275` |
| **Source Reports** | 14.2.6.md |
| **Related Findings** | - |

**Description:**

The get_metadata() method implements explicit field filtering to exclude cryptographic material (salt, opened_key). However, the list-query methods (open_to_pid(), upcoming_to_pid()) return raw database rows without code-level field filtering. While owned_elections() has a defensive comment noting this concern, the other methods lack equivalent protections. These raw results are passed through postprocess_election() and directly into template contexts without any sensitive field stripping. If queries return election salt or opened_key columns, this cryptographic material enters the template rendering context, creating a defense-in-depth gap.

**Remediation:**

Add consistent field filtering to list query methods. Implement a _safe_election_row() method that strips sensitive fields (salt, opened_key) and apply it to open_to_pid(), upcoming_to_pid(), and owned_elections() to ensure defense-in-depth consistency with get_metadata(). This ensures cryptographic material is explicitly excluded at the code level rather than relying on template rendering behavior.

---

#### FINDING-215: Superseded Votes Retained Indefinitely as Unnecessary Data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.7 |
| **Files** | `v3/schema.sql:vote table definition`, `v3/steve/election.py:204-215`, `v3/steve/election.py:217-255` |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | - |

**Description:**

When a voter re-votes on an issue, the system creates a new vote row with the same vote_token but a new auto-incrementing vid. Only the most recent vote is used during tallying (q_recent_vote). The superseded votes serve no purpose but remain in the database indefinitely. For a system whose core goal is ballot secrecy, retaining the history of vote changes for each vote_token provides an unnecessary information channel — particularly the count of re-votes per token and their ordering. A voter who changes their vote 5 times will have 5 encrypted vote rows in the database. An attacker with database access can observe that a specific vote_token voted 5 times and potentially correlate timing of row insertions (via vid ordering) with other events.

**Remediation:**

Modify add_vote() to delete previous votes before inserting new one. Add query to queries.yaml: c_delete_prior_votes: DELETE FROM vote WHERE vote_token = ?. Execute within transaction: self.c_delete_prior_votes.perform(vote_token) before self.c_add_vote.perform(vote_token, ciphertext).

---

#### FINDING-216: Person PII (Name, Email) Has No Practical Deletion Path

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.7 |
| **Files** | `v3/steve/persondb.py:51-64`, `v3/schema.sql:mayvote foreign key constraints`, `v3/steve/persondb.py:30-40` |
| **Source Reports** | 14.2.7.md |
| **Related Findings** | - |

**Description:**

The person table stores PII (name, email) for all voters ever registered. While a delete_person() method exists, referential integrity constraints from the mayvote table prevent deletion of any person who has been associated with any election. The code comment explicitly acknowledges this limitation with no resolution. Voter PII accumulates without any lifecycle management. For a voting system that may serve many elections over years, this creates an ever-growing store of personal data with no ability to honor data subject deletion requests or comply with data minimization principles.

**Remediation:**

Implement anonymization as an alternative to blocked deletion. Add anonymize_person() method that replaces name and email with anonymized values while keeping the PID reference intact for mayvote/vote integrity. Add query: c_anonymize_person: UPDATE person SET name = ?, email = ? WHERE pid = ?.

---

#### FINDING-217: Documents Served Without Metadata Stripping or User Consent

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 14.2.8 |
| **Files** | `v3/server/pages.py:582-597`, `v3/server/pages.py:60-68` |
| **Source Reports** | 14.2.8.md |
| **Related Findings** | - |

**Description:**

The application serves documents to authorized voters through the serve_doc() endpoint without removing embedded metadata. Election administrators place supporting documents in DOCSDIR/&lt;iid&gt;/ which are then served via /docs/&lt;iid&gt;/&lt;docname&gt; using quart.send_from_directory(). The raw files are returned with all embedded metadata intact, including potentially sensitive information such as author names, organization details, creation/modification timestamps, revision history, software version information, GPS coordinates, embedded comments, or tracked changes. No metadata stripping occurs at any stage (neither at ingestion nor at serving time), and no user consent mechanism exists for metadata retention. This violates ASVS 14.2.8 which requires either removal of sensitive metadata from user-submitted files or explicit user consent for its retention.

**Remediation:**

Implement metadata stripping for all documents either at ingestion time (preferred) or at serving time. Option A: Strip metadata at serving time using tools like exiftool, python-pdfkit, or Pillow before returning files. Option B (preferred): Strip metadata at upload/ingestion time in the CLI tool or upload handler that places documents, processing files once during ingestion. Additionally: (1) Add Content-Disposition: attachment headers to serve_doc() responses to force download rather than inline rendering; (2) Validate the docname parameter to prevent path traversal (address the TODO comment '### verify the propriety of DOCNAME'); (3) Document metadata policy - if some metadata is intentionally retained for transparency, document this decision and add user consent mechanisms where appropriate.

---

#### FINDING-218: Sensitive Voter Identity Data Stored in Session (Likely Cookie-Backed)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 14.3.3 |
| **Files** | `v3/server/pages.py:62-80`, `v3/server/pages.py:107-113` |
| **Source Reports** | 14.3.3.md |
| **Related Findings** | - |

**Description:**

The application stores sensitive voter identity data (PII) directly in the session object, which in Quart's default configuration is implemented as a client-side signed cookie. The session contains uid (voter identifier), fullname (voter full name), and email (voter email address). Additionally, flash messages stored in the session may contain election-specific data such as issue IDs and election titles, potentially revealing voter-to-issue mappings. The session cookie is base64-encoded and signed but not encrypted, making it readable by anyone with access to browser DevTools, file system, or via XSS if HttpOnly flag is not set. ASVS 14.3.3 allows session tokens in cookies but not sensitive data - a session token should be an opaque identifier, not a container for user PII.

**Remediation:**

Option 1 (Recommended): Configure a server-side session backend (Redis, filesystem, sqlalchemy, or memcached) so only an opaque session ID is stored in the browser cookie. Set SESSION_TYPE='redis', SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True, and SESSION_COOKIE_SAMESITE='Lax'. Option 2: Store only the session identifier (UID) in the cookie and look up user details server-side on each request from the PersonDB. Option 3: If cookie-based sessions must be used with full data, encrypt the cookie contents using an encrypted serializer. All options should include security flags: HttpOnly=True, Secure=True, SameSite=Lax.

---

#### FINDING-219: Dependency Confusion Risk for ASF-Namespaced Internal Package asfquart

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.2.4 |
| **Files** | `v3/server/main.py:32-38` |
| **Source Reports** | 15.2.4.md |
| **Related Findings** | - |

**Description:**

The asfquart package is an ASF-internal web framework wrapper that provides critical security infrastructure including OAuth integration, authentication, and application construction. This package presents an elevated dependency confusion risk. If asfquart is distributed via an internal ASF package repository and the name is not defensively registered on PyPI, an attacker could register asfquart on PyPI with a higher version number. If pip or uv is configured with --extra-index-url (adding internal repo alongside PyPI), the public malicious package could be preferred due to version precedence. The malicious package would execute during import, with full access to the OAuth configuration, authentication flow, and application construction. No configuration restricting the package index source was provided for audit. A malicious asfquart package could intercept OAuth tokens, modify authentication flows, exfiltrate voter data, and manipulate election results. This is the foundational framework of the application, making it the highest-value target for a supply chain attack.

**Remediation:**

1. Configure uv workspace sources to restrict asfquart to internal repository using explicit index mapping in pyproject.toml: `[[tool.uv.index]] name = "asf-internal" url = "https://internal.apache.org/pypi/simple" explicit = true` and `[tool.uv.sources] asfquart = { index = "asf-internal" }`. 2. Defensively register the asfquart package name on PyPI (even as an empty placeholder with a README explaining it's internal-only) to prevent name squatting. 3. Configure uv or pip to use --index-url exclusively for ASF packages, preventing fallback to public PyPI. 4. Document the expected repository source for all internal packages in DEPENDENCIES.md. 5. Implement hash pinning for asfquart in lock file to detect tampering.

---

#### FINDING-220: No SBOM Documenting Transitive Dependency Tree

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.2.4 |
| **Files** | `Project root:N/A` |
| **Source Reports** | 15.2.4.md |
| **Related Findings** | - |

**Description:**

The application's direct dependencies pull in significant transitive dependency chains. None of these transitive dependencies are documented in the provided audit materials. Direct dependencies like cryptography, argon2-cffi, asfquart, asfpy, and easydict have extensive transitive dependencies including cffi, pycparser, quart, hypercorn, h11, h2, wsproto, priority, hpack, PyYAML, requests, ldap3, and others. Without an SBOM: (1) Vulnerabilities in transitive dependencies cannot be tracked, (2) The full attack surface of the application is unknown, (3) Compliance with ASVS 15.2.4's requirement to verify 'all of their transitive dependencies' cannot be satisfied, (4) A compromised or vulnerable transitive dependency would go undetected, (5) Transitive dependencies can introduce vulnerabilities, be compromised to inject malicious code during installation, and create hidden attack vectors not visible in direct dependency audits.

**Remediation:**

1. Generate and maintain an SBOM using CycloneDX format: `cyclonedx-py environment -o sbom.json --format json` or using syft: `syft dir:./v3 -o cyclonedx-json > sbom.json`. 2. Integrate SBOM generation into CI/CD pipeline to automatically regenerate on dependency changes. 3. Store SBOM artifacts with each release for audit trail. 4. Implement automated vulnerability scanning against the SBOM using tools like grype: `grype sbom:sbom.json`. 5. Review transitive dependency changes during dependency updates to identify new attack surface. 6. Document process for evaluating transitive dependency security in DEPENDENCY-POLICY.md.

---

#### FINDING-221: Development Benchmark Function Present in Production Crypto Module

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 15.2.3 |
| **Files** | `v3/steve/crypto.py:26`, `v3/steve/crypto.py:129-158`, `v3/steve/crypto.py:160-162` |
| **Source Reports** | 15.2.3.md |
| **Related Findings** | - |

**Description:**

The crypto.py module contains a benchmark_argon2() function (lines 129-158) that is development/test code exposed in the production module. This function executes 8 CPU/memory-intensive Argon2 operations with up to 128MB memory each, creating a denial-of-service vector if reachable through any server-side codepath. The function uses hardcoded test salts and print() statements that write to stdout/logs, potentially exposing Argon2 tuning parameters and timing information. Additionally, the benchmark uses argon2.Type.ID while production uses argon2.Type.D, indicating it is purely development tooling that doesn't represent production behavior. ASVS 15.2.3 requires that production environments only include functionality required for the application to function and do not expose extraneous functionality such as test code.

**Remediation:**

Move the benchmark to a separate development-only script excluded from production deployment: 1. Create tools/benchmark_argon2.py with appropriate header indicating it is NOT for production deployment. 2. Remove benchmark_argon2() function (lines 129-158) from crypto.py. 3. Remove the if __name__ == '__main__' block (lines 160-162) from crypto.py. 4. Remove `import time` (line 26) from crypto.py if unused elsewhere. 5. Update deployment documentation to exclude tools/ directory from production packages. 6. Add comment in crypto.py indicating benchmark was moved to tools/ for development use only.

---

#### FINDING-222: Web Server Log Timestamps Use Local Time Without Timezone, Year, or Seconds

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.2, 16.2.4 |
| **Files** | `v3/server/main.py:23`, `v3/server/main.py:55-59`, `v3/server/main.py:85-91`, `v3/server/main.py:20`, `v3/server/main.py:51-56`, `v3/server/pages.py:101`, `v3/server/pages.py:371`, `v3/server/pages.py:374`, `v3/server/pages.py:394-395`, `v3/server/pages.py:415`, `v3/server/pages.py:428`, `v3/server/pages.py:451`, `v3/server/pages.py:472-473`, `v3/server/pages.py:489-490` |
| **Source Reports** | 16.2.2.md, 16.2.4.md |
| **Related Findings** | - |

**Description:**

The web server logging configuration uses DATE_FORMAT = '%m/%d %H:%M' which lacks: (1) timezone offset (%z or %Z) required by ASVS 16.2.2, (2) UTC enforcement (defaults to time.localtime()), (3) year (%Y) needed for cross-year correlation, and (4) seconds (%S) for proper event ordering. During DST transitions, timestamps become ambiguous—the same wall-clock time occurs twice, making it impossible to distinguish legitimate operations from unauthorized actions occurring in the duplicate time window. This prevents reliable log correlation across time periods, rapid event sequences, and distributed systems. All security events in pages.py (election creation, opening, closing, vote submission, issue management) are affected.

**Remediation:**

Change DATE_FORMAT to '%Y-%m-%dT%H:%M:%SZ' for ISO 8601 UTC format. Create a custom formatter with formatter.converter = time.gmtime to enforce UTC timestamps. Configure the root logger with this formatter instead of using basicConfig with datefmt only. Example: formatter = logging.Formatter(fmt='[{asctime}|{levelname}|{name}] {message}', datefmt='%Y-%m-%dT%H:%M:%SZ', style='{'); formatter.converter = time.gmtime. Apply to both run_standalone() and run_asgi() configurations.

---

#### FINDING-223: Unsynchronized Logging Configuration Between Web Server and Tally CLI Components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.2, 16.2.4 |
| **Files** | `v3/server/main.py:23`, `v3/server/main.py:55-59`, `v3/server/main.py:85-91`, `v3/server/main.py:51-56`, `v3/server/bin/tally.py:145`, `v3/server/bin/tally.py:148`, `v3/steve/election.py:186`, `v3/steve/election.py:197`, `v3/steve/election.py:381` |
| **Source Reports** | 16.2.2.md, 16.2.4.md |
| **Related Findings** | - |

**Description:**

The web server (main.py) and tally CLI (tally.py) use completely different logging configurations with incompatible formats. Web server uses '[{asctime}|{levelname}|{name}] {message}' with '%m/%d %H:%M' timestamps in local time, while tally CLI uses Python's default format '%(levelname)s:%(name)s:%(message)s' with no timestamps at all. The same election.py module produces different log formats depending on which entry point calls it, making SIEM correlation impossible and violating ASVS 16.2.2 requirement that 'time sources for all logging components are synchronized'. This format divergence creates a correlation gap at the most critical phase of the election lifecycle.

**Remediation:**

Create a shared logging configuration module (e.g., v3/steve/log_config.py) with a configure_logging() function that sets consistent format, date format, style, and UTC converter. Import and call this function from both main.py and tally.py entry points. Example shared config: LOG_FORMAT = '[{asctime}|{levelname}|{name}] {message}', LOG_DATEFMT = '%Y-%m-%dT%H:%M:%SZ', formatter.converter = time.gmtime. This ensures unified log processing across all components.

---

#### FINDING-224: Source IP Address Missing From All Web Security Log Entries

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.1, 16.3.1 |
| **Files** | `v3/server/pages.py:116`, `v3/server/pages.py:438`, `v3/server/pages.py:468`, `v3/server/pages.py:490`, `v3/server/pages.py:505`, `v3/server/pages.py:529`, `v3/server/pages.py:547`, `v3/server/pages.py:565`, `v3/server/pages.py:410-443`, `v3/server/pages.py:455-473`, `v3/server/pages.py:476-493`, `v3/server/pages.py:495-509`, `v3/server/pages.py:511-532`, `v3/server/pages.py:534-555`, `v3/server/pages.py:557-575`, `v3/server/pages.py:475`, `v3/server/pages.py:498`, `v3/server/pages.py:513` |
| **Source Reports** | 16.2.1.md, 16.3.1.md |
| **Related Findings** | - |

**Description:**

ASVS 16.2.1 requires 'where' metadata for detailed investigation. For web applications, the source IP address is essential context that is completely absent from all security log entries. Every state-changing operation logs user identity and action details, but never records the IP address from which the request originated. Without source IP addresses, security teams cannot detect compromised accounts (votes/actions from unexpected geolocations), correlate multi-account attacks (single attacker using multiple compromised accounts), investigate incidents (determine which requests were malicious), enforce rate limiting (IP-based abuse prevention), or meet compliance requirements (election security standards often require IP address logging).

**Remediation:**

Create a centralized security logging helper function that captures source IP address from quart.request.remote_addr, request ID from X-Request-ID header, and User-Agent for device fingerprinting. Example: async def log_security_event(action: str, details: str, level: int = logging.INFO) -> None: source_ip = quart.request.remote_addr or 'unknown'; request_id = quart.request.headers.get('X-Request-ID', 'none'); user_agent = quart.request.headers.get('User-Agent', 'unknown')[:100]; _LOGGER.log(level, f'[ip:{source_ip}] [req:{request_id}] User[U:{result.uid}] action={action} {details} user_agent="{user_agent}"'). Refactor all endpoint logging to use this helper. For enhanced security, consider migrating to structured JSON logging using structlog.

---

#### FINDING-225: Log Injection via Unsanitized User-Controlled Input in Election Title and Form Fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Section(s)** | 16.1.1, 16.3.3, 16.4.1 |
| **Files** | `v3/server/pages.py:455`, `v3/server/pages.py:101`, `v3/server/pages.py:517`, `v3/server/pages.py:542`, `v3/server/pages.py:459`, `v3/server/pages.py:429-431` |
| **Source Reports** | 16.1.1.md, 16.3.3.md, 16.4.1.md |
| **Related Findings** | FINDING-227, FINDING-228 |

**Description:**

User-controlled input from form submissions (election titles, issue titles, descriptions, date strings) is directly interpolated into log messages using f-strings without encoding newlines or other log control characters. An attacker can inject fake log entries by including newline characters in form fields, undermining log integrity for forensic analysis. This allows attackers to forge log entries to cover tracks or frame other users, causes log analysis tools to misparse injected entries, and undermines trust in the entire logging infrastructure. The vulnerability affects election creation, issue management, and date configuration endpoints.

**Remediation:**

Implement a sanitize_for_log() utility function that removes or replaces control characters (newlines, tabs, carriage returns, and other characters in the range \x00-\x1f) with spaces or escaped representations, and truncates excessively long values to prevent log flooding. Apply this function to all user-controlled values before log interpolation. Example: def sanitize_for_log(value: str) -> str: if value is None: return 'None'; return re.sub(r'[\r\n\t\x00-\x1f\x7f-\x9f]', ' ', str(value))[:256]. Then use: _LOGGER.info(f'User[U:{result.uid}] created election[E:{election.eid}]; title: "{sanitize_for_log(form.title)}"'). Apply to all log statements with user input.

---

#### FINDING-226: Exception Details in Error Logs May Expose Sensitive Data

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-209 |
| **ASVS Section(s)** | 16.1.1, 16.2.5 |
| **Files** | `v3/server/pages.py:419`, `v3/server/pages.py:399-403`, `v3/server/bin/tally.py:124`, `v3/server/bin/tally.py:115-118` |
| **Source Reports** | 16.1.1.md, 16.2.5.md |
| **Related Findings** | FINDING-020, FINDING-021 |

**Description:**

Exception objects are directly interpolated into log messages using {e}. During vote processing, exceptions from cryptographic operations or database layer could expose sensitive internal state including cryptographic parameters (key material, salts, vote tokens), SQL queries with parameter values, or partial vote data (violating ballot secrecy). Logs containing sensitive data become a high-value target for attackers. This affects vote submission error handling in pages.py and tally error handling in tally.py where exceptions are logged without sanitization.

**Remediation:**

Log only the exception type name (type(e).__name__) at ERROR level for production logs, and use a separate DEBUG-level log entry with exc_info=True for detailed exception information that should only be enabled in development environments. Example: _LOGGER.error(f'Vote processing failed for user[U:{result.uid}] on issue[I:{iid}]: {type(e).__name__}'); _LOGGER.debug(f'Vote error details (issue[I:{iid}]): {e}', exc_info=True). For tally errors: _LOGGER.error(f'Tally failed for issue[I:{issue.iid}]: {type(e).__name__} (details suppressed to protect vote data)')

---

#### FINDING-227: Debug print() Statements Output Raw Form Data to Unprotected stdout

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Section(s)** | 16.1.1, 16.2.3, 16.2.4, 16.2.5, 16.4.1, 16.4.2 |
| **Files** | `v3/server/pages.py:508`, `v3/server/pages.py:537`, `v3/server/pages.py:493`, `v3/server/pages.py:516`, `v3/server/pages.py:489`, `v3/server/pages.py:513`, `v3/server/pages.py:510`, `v3/server/pages.py:531`, `v3/server/pages.py:482`, `v3/server/pages.py:499`, `v3/server/pages.py:447`, `v3/server/pages.py:467` |
| **Source Reports** | 16.1.1.md, 16.2.3.md, 16.2.4.md, 16.2.5.md, 16.4.1.md, 16.4.2.md |
| **Related Findings** | FINDING-225, FINDING-228 |

**Description:**

Production code contains print('FORM:', form) statements in issue management endpoints (do_add_issue_endpoint and do_edit_issue_endpoint) that dump raw request form data to stdout. This bypasses the logging framework entirely, has no log level classification, no timestamp, and intermingles with structured logs in ASGI deployments. Form data (issue titles, descriptions, potentially election configuration) is written to an unstructured, unprotected output stream accessible to anyone who can read captured logs. These print() statements cannot be suppressed by adjusting log levels—they always execute. In ASGI deployments (Hypercorn), stdout is captured alongside structured log output, making injected lines appear alongside legitimate entries.

**Remediation:**

Remove all print('FORM:', form) statements entirely from production code. If debugging is needed, replace with appropriate structured logging that logs only metadata about the action, not form contents: _LOGGER.debug(f'Issue form submitted for election[E:{election.eid}]'). Establish a policy to replace all print() calls with _LOGGER calls at appropriate levels. This ensures form data is only logged when DEBUG level is explicitly enabled and flows through the protected logging framework.

---

#### FINDING-228: Log Injection via URL Path Parameters in Election Constructor

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS Section(s)** | 16.4.1 |
| **Files** | `v3/steve/election.py:40`, `v3/server/main.py:57` |
| **Source Reports** | 16.4.1.md |
| **Related Findings** | FINDING-225, FINDING-227 |

**Description:**

The Election constructor logs the eid parameter before validating it against the database, allowing log injection through 11 different endpoints that use the @load_election decorator. The injection occurs at DEBUG level which is enabled in production configurations. Any authenticated committer can inject arbitrary log entries across multiple endpoints before the election ID is validated. The eid parameter is user-controlled from URL paths and is logged with f-string interpolation without sanitization. Affected endpoints include /manage/&lt;eid&gt;, /vote-on/&lt;eid&gt;, /do-open/&lt;eid&gt;, /do-close/&lt;eid&gt;, and all issue management endpoints.

**Remediation:**

Option 1 (Preferred): Move log statement after validation. Only log after self.q_check_election confirms the eid exists in the database. Option 2: Sanitize before logging using re.sub(r'[\r\n\x00-\x1f\x7f-\x9f]', '', str(eid))[:64] to remove control characters and limit length. Additionally, reduce production log level from DEBUG to INFO in main.py to reduce attack surface.

---

#### FINDING-229: No Documented Log Inventory or Centralized Log Destination Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.3 |
| **Files** | `v3/server/main.py:58-63`, `v3/server/main.py:92-97`, `v3/server/bin/tally.py:157` |
| **Source Reports** | 16.2.3.md |
| **Related Findings** | - |

**Description:**

The application lacks a documented log inventory and uses only default logging destinations across all execution modes. No persistent log storage or centralized log destination is configured. All three execution contexts (standalone, ASGI, CLI) configure logging.basicConfig() without persistent handlers. Without a log inventory, it is impossible to verify that logs are only going to approved destinations per ASVS 16.2.3. The three different logging configurations across execution modes mean logs may end up in different places depending on how the application is run, with no documentation of which destinations are approved.

**Remediation:**

Create a formal log inventory document specifying approved log destinations. Centralize logging configuration using logging.config.dictConfig() with explicit handlers (console, audit_file, remote_syslog). Configure at minimum a RotatingFileHandler for persistent audit logs with restricted permissions (0o640). Use same configuration across standalone, ASGI, and CLI modes. Add linting rules or code review checks to prevent print() in production modules.

---

#### FINDING-230: Multi-Issue Vote Submission Lacks Atomicity; Partial Failure Creates Inconsistent State

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.2, 16.5.3 |
| **Files** | `v3/server/pages.py:349-378`, `v3/server/pages.py:425-444` |
| **Source Reports** | 16.5.2.md, 16.5.3.md |
| **Related Findings** | - |

**Description:**

The vote submission endpoint processes multiple issue votes in a loop, with each vote committed individually. If a failure occurs mid-loop (database lock, crypto failure, disk full), votes processed before the failure are permanently recorded while subsequent votes are lost. The voter receives only a generic error message and cannot determine which votes were successfully recorded. This creates an election integrity violation where partial vote recording without voter awareness could alter election outcomes. This violates ASVS 16.5.2 (graceful degradation) and 16.5.3 (secure failure) requirements.

**Remediation:**

Implement atomic batch vote submission by wrapping all vote operations in a single database transaction. Add a new add_votes_batch() method in election.py that uses BEGIN TRANSACTION/COMMIT/ROLLBACK to ensure all votes succeed or none are committed. Validate all votes before committing any, and provide clear feedback to users about whether the entire batch succeeded or failed. Log transaction start, commit, and rollback events with user context.

---

#### FINDING-231: Election State-Change Operations Lack Error Handling and Recovery

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.5.2 |
| **Files** | `v3/server/pages.py:399`, `v3/server/pages.py:419`, `v3/steve/election.py:70` |
| **Source Reports** | 16.5.2.md |
| **Related Findings** | - |

**Description:**

The election opening and closing endpoints lack error handling for external resource access failures. The multi-step election.open() operation can fail partway through, leaving the election in an inconsistent state with no rollback mechanism. Database and cryptographic operation failures are not caught, and no audit trail is created for failures. If PersonDB.open() fails, unhandled exceptions occur with no audit trail. If failure occurs after add_salts() but before c_open.perform(), the election has salts applied but remains 'editable', creating an inconsistent state.

**Remediation:**

Wrap PersonDB.open() and election.open() calls in try/except blocks with proper error logging and user-friendly error messages. Make election.open() atomic by wrapping the entire multi-step process (salts + state change) in a single database transaction with rollback on failure. Add audit logging for all failure scenarios with _LOGGER.error() including user context, election ID, and operation that failed.

---

#### FINDING-232: No X-Frame-Options or frame-ancestors CSP Directive — Clickjacking Unmitigated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.1.1 |
| **Files** | `v3/server/pages.py:203`, `v3/server/pages.py:315`, `v3/server/pages.py:448`, `v3/server/pages.py:468` |
| **Source Reports** | 3.1.1.md |
| **Related Findings** | - |

**Description:**

No route handler or application-level middleware sets `X-Frame-Options` or a `Content-Security-Policy` `frame-ancestors` directive. This is a Type A gap. All 18+ HTML-rendering endpoints can be embedded in attacker-controlled iframes. Entry points affected include all HTML endpoints, but most critical are state-changing pages that could be clickjacked: `/vote-on/<eid>` (voting form, line 203), `/manage/<eid>` (election management, line 315), `/do-open/<eid>` (election opening, line 448, GET request — doubly vulnerable), `/do-close/<eid>` (election closing, line 468, GET request). Since `/do-open/<eid>` and `/do-close/<eid>` are GET requests that perform state changes, a simple iframe load (without even requiring a click on a form button) could open or close an election. An attacker can trick an authenticated election administrator into opening/closing elections or submitting votes by framing the application page and overlaying deceptive UI elements.

**Remediation:**

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

---

#### FINDING-233: No Browser Security Feature Documentation or Degradation Behavior

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.1.1 |
| **Files** | `v3/server/main.py:32-42` |
| **Source Reports** | 3.1.1.md |
| **Related Findings** | - |

**Description:**

ASVS 3.1.1 explicitly requires that application documentation states: (1) Expected security features browsers must support (HTTPS, HSTS, CSP, etc.). (2) How the application behaves when features are unavailable (warning, blocking, graceful degradation). Neither the application code nor any referenced configuration contains such documentation. Specifically: No `SECURITY.md`, security section in README, or inline documentation of browser requirements. No runtime checks for browser security feature support. No warning mechanism for users on non-conforming browsers. No `@app.before_request` handler that validates request security properties. Without documented browser security requirements, deployment teams cannot verify that the application is served with appropriate security headers. Operations teams have no guidance on required proxy/CDN security configurations. Users are not warned when their browser lacks required security features.

**Remediation:**

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

---

#### FINDING-234: Externally Hosted SVG Image Without SRI or Documented Security Decision

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | `v3/server/templates/header.ezt:18` |
| **Source Reports** | 3.6.1.md |
| **Related Findings** | - |

**Description:**

The Apache feather logo is loaded at runtime from an external domain (www.apache.org). This resource is not versioned (the URL has no version identifier, meaning content can change), has no SRI integrity attribute (the integrity attribute is not supported on &lt;img&gt; elements), and has no documented security decision justifying this external dependency. ASVS 3.6.1 requires that when SRI is not possible, there should be a documented security decision to justify this for each resource. While SVG loaded via &lt;img&gt; is sandboxed (no script execution), a compromised resource could still be used for phishing (visual replacement) or tracking. If the external host is compromised or the resource is modified, the application would display attacker-controlled visual content to all users. In a voting application, this could undermine trust or be used for social engineering.

**Remediation:**

Self-host the SVG image alongside other static assets. In fetch-thirdparty.sh, add: FEATHER_URL="https://www.apache.org/foundation/press/kit/feather.svg"; echo "Fetching: ${FEATHER_URL}"; curl -q --fail "${FEATHER_URL}" --output "${STATIC_DIR}/img/feather.svg". In header.ezt, change to: &lt;img src="/static/img/feather.svg" alt="Logo" width="30" height="30" class="d-inline-block align-text-top"&gt;

---

#### FINDING-235: Missing SRI for Self-Hosted Third-Party Library (bootstrap-icons.css)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | `v3/server/templates/header.ezt:10`, `v3/server/bin/fetch-thirdparty.sh:70-74` |
| **Source Reports** | 3.6.1.md |
| **Related Findings** | - |

**Description:**

The SRI defense-in-depth pattern is applied to bootstrap.min.css and bootstrap.bundle.min.js but explicitly skipped for bootstrap-icons.css. This third-party CSS file controls @font-face declarations for web fonts. If tampered with after deployment, it could: (1) Redirect font loading to an attacker-controlled origin, (2) Inject CSS-based data exfiltration (e.g., attribute selectors with background URLs), (3) Modify visual rendering to mislead voters. The inconsistency creates a false confidence that third-party resources are integrity-protected when a significant gap exists. An attacker who can modify server-side files or intercept during deployment could alter bootstrap-icons.css without detection, while other Bootstrap files would trigger integrity failures. This creates a targeted attack vector through the weakest link.

**Remediation:**

Add SRI hash generation and template integration. In fetch-thirdparty.sh, after extracting bootstrap-icons.css: echo "bootstrap-icons.css:"; echo -n "sha384-" ; openssl dgst -sha384 -binary "${STATIC_DIR}/css/bootstrap-icons.css" | openssl base64 -A ; echo "". In header.ezt: &lt;link href="/static/css/bootstrap-icons.css" rel="stylesheet" integrity="sha384-GENERATED_HASH_HERE"&gt;

---

#### FINDING-236: Build Script Downloads Third-Party Assets Without Pre-Download Integrity Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | `v3/server/bin/fetch-thirdparty.sh:47`, `v3/server/bin/fetch-thirdparty.sh:60-62`, `v3/server/bin/fetch-thirdparty.sh:67`, `v3/server/bin/fetch-thirdparty.sh:82`, `v3/server/bin/fetch-thirdparty.sh:92` |
| **Source Reports** | 3.6.1.md |
| **Related Findings** | - |

**Description:**

The build script generates SRI hashes from the downloaded content rather than verifying downloads against known-good hashes. This means: (1) curl does not use --fail flag (HTTP errors silently produce non-library content), (2) No pre-defined SHA-256/SHA-384 checksums are checked before extraction, (3) No GPG signature verification of release packages, (4) The generated SRI hash will match whatever was downloaded, including compromised content. If a supply chain attack targets the download (e.g., compromised GitHub release, DNS hijacking), the SRI mechanism would be rendered ineffective because the integrity hash would be computed from the malicious payload. A supply chain compromise during the build process would result in malicious JavaScript/CSS being served to all voters, with SRI hashes that appear valid. The existing SRI provides zero protection against this attack vector.

**Remediation:**

Add known-good hash verification before extraction. Define expected hashes from official release notes (e.g., EXPECTED_BS_SHA256="a4a04c..." from https://github.com/twbs/bootstrap/releases). Download with curl -q --fail --location "${B_URL}" --output "${ZIPFILE}". Verify: ACTUAL_HASH=$(sha256sum "${ZIPFILE}" | cut -d' ' -f1); if [ "${ACTUAL_HASH}" != "${EXPECTED_BS_SHA256}" ]; then echo "ERROR: Bootstrap download integrity check failed!"; echo "Expected: ${EXPECTED_BS_SHA256}"; echo "Got: ${ACTUAL_HASH}"; rm -f "${ZIPFILE}"; exit 1; fi. Only then extract the files.

---

#### FINDING-237: TLS Certificates Loaded Without Integrity Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 6.7.1 |
| **Files** | `v3/server/main.py:37`, `v3/server/main.py:85-90` |
| **Source Reports** | 6.7.1.md |
| **Related Findings** | - |

**Description:**

The TLS certificate and private key files — which protect the OAuth authentication channel — are loaded directly from the filesystem without any integrity verification. There is no hash comparison, fingerprint validation, or signature check to ensure certificates have not been tampered with. An attacker with write access to the `server/certs/` directory could substitute a rogue certificate and key, enabling man-in-the-middle interception of the OAuth authentication flow. The certificates are explicitly added to the `extra_files` watch set, meaning the server will automatically reload when certificate files change on disk, which amplifies the risk — a certificate swap triggers immediate adoption without manual restart.

**Remediation:**

Implement certificate integrity verification before loading TLS certificates by validating against known fingerprints stored separately from the certificate files. Enforce restrictive file permissions (0o400 for key, 0o444 for cert) at startup. Store certificate fingerprints in a separate, integrity-protected configuration. Consider removing certificates from extra_files to prevent automatic reload on modification. Example implementation:

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

---

#### FINDING-238: Certificate File Paths Accept Unvalidated Configuration Input

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 6.7.1 |
| **Files** | `v3/server/main.py:85`, `v3/server/main.py:86` |
| **Source Reports** | 6.7.1.md |
| **Related Findings** | - |

**Description:**

Certificate and key file paths are constructed by joining `CERTS_DIR` with values from `config.yaml` without validating that the resulting paths remain within the intended `certs/` directory. The `pathlib.Path` `/` operator does not sanitize path traversal sequences. An attacker who can modify `config.yaml` (but not necessarily the code or certs directory) could redirect certificate loading to an arbitrary filesystem path, causing the server to use an attacker-controlled certificate. While config file modification requires some prior access, defense-in-depth demands path validation.

**Remediation:**

Add path containment validation for certificate configuration values to prevent directory traversal. Example implementation:

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

---

#### FINDING-239: Cryptographic Key Material Not Cleared From Memory After Use

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 11.7.2 |
| **Files** | `v3/steve/crypto.py:65`, `v3/steve/crypto.py:73`, `v3/steve/crypto.py:51`, `v3/steve/election.py:224`, `v3/steve/election.py:238` |
| **Source Reports** | 11.7.2.md |
| **Related Findings** | - |

**Description:**

Per-voter encryption keys, the election opened_key, and derived key material remain in process memory beyond their operational need. During tallying, key material for every voter/issue pair accumulates across loop iterations. No cleanup mechanism exists for sensitive cryptographic material after use. The vulnerable functions include create_vote(), decrypt_votestring(), _b64_vote_key(), add_vote(), and tally_issue(). Memory disclosure vulnerabilities (e.g., via /proc/&lt;pid&gt;/mem, heap inspection, or swap) would expose these keys, allowing decryption of any intercepted ciphertexts. The opened_key (election master key) remaining in the md variable is particularly critical as it enables derivation of all vote tokens.

**Remediation:**

While Python doesn't natively support secure memory erasure for immutable types, use bytearray for mutable key storage and explicit zeroing. Implement a _secure_zero() function using ctypes.memset for critical material. Wrap key operations in try/finally blocks to ensure cleanup. Consider using ctypes-based wrappers or compiled-language crypto modules for the most sensitive operations to achieve better memory control.

---

#### FINDING-240: Unbounded Synchronous Vote Processing Loop Amplifies Event Loop Starvation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS Section(s)** | 15.4.4 |
| **Files** | `v3/server/pages.py:399-432`, `v3/steve/election.py:231-244` |
| **Source Reports** | 15.4.4.md |
| **Related Findings** | - |

**Description:**

Vote submission loops over all issues synchronously, performing database reads, PBKDF key derivation, encryption, and database writes for each issue without yielding to the event loop. For elections with many issues, this creates extended blocking proportional to the number of issues, with redundant state checks amplifying the problem. Each add_vote() call includes key derivation (PBKDF), which is deliberately slow. This multiplied across N issues creates significant starvation. Multiple voters submitting simultaneously will serialize completely, with each voter's full submission blocking all others. Additionally, _all_metadata(self.S_OPEN) is re-queried on every iteration, performing redundant state checks that add unnecessary blocking time. For an election with 20 issues, approximately 100 synchronous blocking operations occur in a single request.

**Remediation:**

Offload each blocking add_vote() call to thread pool using await asyncio.to_thread(election.add_vote, result.uid, iid, votestring) within the vote processing loop. Alternatively, create a bulk add_votes_bulk() method that caches the metadata query and wraps all inserts in a single transaction to reduce per-vote overhead and redundant state checks.

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Implementation Files | ASVS Coverage |
|------------|-------------------|----------|---------------------|---------------|
| PSC-001 | 100% parameterized SQL queries using ? placeholders | All database queries in queries.yaml consistently use parameter binding via asfpy.db wrapper, preventing SQL injection | `v3/queries.yaml`, `v3/steve/election.py`, `v3/steve/persondb.py` | 1.2.4 |
| PSC-002 | Data stored in canonical (raw) form without pre-encoding | All database writes store raw data, satisfying ASVS 1.1.1 requirement for single decoding | `v3/queries.yaml` | 1.1.1 |
| PSC-003 | Single URL decoding by Quart framework | Framework performs canonicalization exactly once, no double-decoding in application code | `v3/server/pages.py` | 1.1.1 |
| PSC-004 | LDAP filter hardcoded with no user input | LDAP filter is constant 'uid=*', not user-derived, preventing LDAP injection | `v3/server/bin/asf-load-ldap.py:52, 62` | 1.2.6 |
| PSC-005 | send_from_directory for file serving | Framework-provided protection against path traversal attacks | `v3/server/pages.py:572, 575` | 5.3.2 |
| PSC-006 | JSON serialization/deserialization handled correctly | KV data stored as JSON text, parsed once without double-encoding | `v3/steve/election.py` | 1.5.2 |
| PSC-007 | Python's arbitrary precision integers | Eliminates traditional integer overflow/underflow vulnerabilities in arithmetic operations | `v3/steve/crypto.py`, `v3/steve/election.py`, `v3/server/pages.py` | 1.4.2 |
| PSC-008 | Hardcoded cryptographic parameters | All Argon2 and HKDF parameters are constants, preventing user-controlled integer manipulation at cryptographic boundary | `v3/steve/crypto.py:22, 31, 58, 59, 82-88, 94, 119` | 1.4.2 |
| PSC-009 | Language choice provides inherent memory safety | Python runtime eliminates buffer overflows, dangling pointers, stack smashing, and string corruption at language level | All `.py` files | 1.4.1 |
| PSC-010 | Zero OS command execution surface | No imports or usage of os.system(), subprocess, or other command execution primitives | All `.py` files | 1.2.5 |
| PSC-011 | Static regex patterns | Single hardcoded regex pattern r'doc:([^\s]+)' with no user input in pattern construction | `v3/server/pages.py:43` | 1.3.12 |
| PSC-012 | Client-side HTML escaping for dynamic DOM | JavaScript escapeHtml() function provides defense-in-depth for client-side rendering | `v3/server/templates/vote-on.ezt` | 1.2.1 |
| PSC-013 | Subresource Integrity (SRI) on CDN resources | integrity= attributes on CSS/JS prevents tampered CDN delivery | `v3/server/templates/header.ezt`, `v3/server/templates/footer.ezt` | 3.6.1 |
| PSC-014 | LDAPS encrypted connection | Uses ldaps:// for encrypted LDAP communication | `v3/server/bin/asf-load-ldap.py:46` | 12.3.1 |
| PSC-015 | Cryptographic vote anonymization | Per-voter salts and vote tokens decouple identity from votes | `v3/steve/election.py` | 14.1.1 |
| PSC-016 | State machine enforcement | Assert-based state checks prevent invalid operations (is_editable(), is_open(), is_closed()) | `v3/steve/election.py` | 2.3.1 |
| PSC-017 | Authentication on all sensitive endpoints | All data-modifying endpoints require authentication via @asfquart.auth.require | `v3/server/pages.py` | 8.2.1 |
| PSC-018 | Minimal Regex Usage | Only one regex pattern exists with O(n) time complexity and no catastrophic backtracking possible | `v3/server/pages.py:42-49` | 1.3.12 |
| PSC-019 | No eval() usage | Zero occurrences of eval(), exec(), compile(), pickle deserialization, or subprocess calls across all files | All files | 1.3.2 |
| PSC-020 | Safe template engine (EZT) | EZT supports only substitution, iteration, conditionals — no code execution capability, inherently prevents SSTI | All `*.ezt` template files | 1.3.7 |
| PSC-021 | No outbound HTTP client usage | The application imports no HTTP client libraries; no web endpoints construct or fetch external URLs based on user input | N/A | 1.3.6 |
| PSC-022 | Exclusive Use of Safe JSON Deserialization | Uses json.loads()/json.dumps() exclusively for structured data serialization | `v3/steve/election.py:301, 305` | 1.5.2 |
| PSC-023 | Database Type Safety with STRICT Mode | SQLite tables use STRICT mode with explicit type constraints, preventing type confusion | `schema.md` | 1.5.2 |
| PSC-024 | Proper state check via _all_metadata(required_state) | Used correctly in add_vote(), tally_issue(), and has_voted_upon() methods with exception-based enforcement | `v3/steve/election.py:160-177, 286, 305, 363` | 2.3.1 |
| PSC-025 | Election state derivation from database fields | State computed from actual column values in _compute_state() method | `v3/steve/election.py:424-437, 389` | 2.3.1 |
| PSC-026 | Cryptographic ID generation prevents enumeration | Uses crypto.create_id() for issue and election IDs with 10-character hex random values and CHECK constraints | `v3/steve/election.py:209-214, 453-458`; `v3/schema.sql:10, 98` | 7.2.2 |
| PSC-027 | Integrity loop on ID collision | While loop with IntegrityError catch handles concurrent ID creation safely | `v3/steve/election.py:209-214, 453-458, 222-228` | 7.2.2 |
| PSC-028 | Transactional operations for multi-step modifications | BEGIN TRANSACTION / COMMIT used in state-modifying operations | `v3/steve/election.py:delete(), add_salts(), 56, 132` | 2.3.3 |
| PSC-029 | Tamper detection via opened_key cryptographic binding | is_tampered() method detects post-opening modifications by recomputing opened_key from current data | `v3/steve/election.py:387-405, 351, 404-421` | 9.1.1 |
| PSC-030 | Voter eligibility enforcement via mayvote table | Database-level check using q_get_mayvote.first_row(pid, iid) before accepting votes | `v3/steve/election.py:add_vote(), 264, 265` | 8.2.2 |
| PSC-031 | Re-voting support via MAX(vid) ordering | Vote table with AUTOINCREMENT vid ensures latest vote counted while preserving history | `v3/schema.sql` | 2.3.2 |
| PSC-032 | Per-voter cryptographic salts | Each voter/issue pair has a unique salt for vote token generation and encryption key derivation | `v3/steve/election.py:121` | 11.5.1 |
| PSC-033 | Schema-level constraints | CHECK constraints, STRICT mode, foreign keys with ON DELETE RESTRICT provide defense-in-depth | `v3/schema.sql:140-154, 94` | 2.3.1 |
| PSC-034 | Vote shuffling before tallying | crypto.shuffle(votes) prevents database-order leakage | Multiple files | 14.1.1 |
| PSC-035 | Referential integrity via foreign keys | Schema defines FOREIGN KEY constraints with ON DELETE RESTRICT, preventing orphaned records | `v3/schema.sql` | 2.3.3 |
| PSC-036 | Election state immutability | prevent_open_close_update trigger prevents modification of advisory timestamps after election closure | `v3/schema.sql` | 2.3.1 |
| PSC-037 | Sensitive Data Exclusion | get_metadata() and get_issue() explicitly exclude salt and opened_key from returned data | `v3/steve/election.py` | 14.2.6 |
| PSC-038 | STV Candidate Randomization | random.shuffle(issue.candidates) prevents ballot-order bias in STV ballots | `v3/server/pages.py:302`; `v3/steve/election.py` | 2.1.1 |
| PSC-039 | Elevated privilege for election creation | POST /do-create-election requires R.pmc_member, a higher privilege level than general committer access | `v3/server/pages.py:473-490, 388` | 8.2.1 |
| PSC-040 | Structured logging of sensitive operations | All state-changing operations log the user ID, action, and target resource | `v3/server/pages.py:426-592` | 16.2.1 |
| PSC-041 | Safe YAML parsing | Uses yaml.safe_load() preventing arbitrary object deserialization | `v3/server/bin/create-election.py:74` | 1.5.2 |
| PSC-042 | Redirect after POST (PRG pattern) | All POST handlers redirect with code=303, preventing form resubmission | `v3/server/pages.py:430-431` | 3.5.1 |
| PSC-043 | TLS support | Certificate and keyfile loading for HTTPS | `v3/server/main.py:70-72` | 12.1.1 |
| PSC-044 | IIFE namespace isolation with 'use strict' | vote-on.ezt script wrapped in (function() { 'use strict'; ... })() providing proper namespace isolation | `v3/server/templates/vote-on.ezt` | 3.2.3 |
| PSC-045 | const/let variable declarations | Modern variable declarations prevent accidental global creation | `v3/server/static/js/steve.js`, multiple template files | 3.2.3 |
| PSC-046 | Secure Default: No CORS Headers | Application does not import any CORS library, no CORS middleware configured | `v3/server/main.py:44`; `v3/server/pages.py` | 3.4.2 |
| PSC-047 | Session token not exposed in response bodies | Only session data (uid, name, email) is extracted and passed to templates | `pages.py:73-82` | 7.2.3 |
| PSC-048 | OAuth over HTTPS | OAuth endpoints hardcoded to https://oauth.apache.org/..., ensuring token exchange is encrypted | `v3/server/main.py:35-38` | 10.1.1 |
| PSC-049 | POST method used for most state-changing operations | 7 of 9 state-changing endpoints correctly use @APP.post() decorator | `v3/server/pages.py:373, 379, 393, 517, 572, 597, 617` | 3.5.3 |
| PSC-050 | JSON Content-Type for date-setting endpoints triggers CORS preflight | /do-set-open_at/&lt;eid&gt; and /do-set-close_at/&lt;eid&gt; accept application/json | `v3/server/pages.py` | 3.5.2 |
| PSC-051 | Single-origin application architecture | All application components served from the same hostname | `v3/ARCHITECTURE.md` | 3.5.4 |
| PSC-052 | No postMessage usage | Application avoids postMessage entirely, using same-origin form submissions | Multiple JavaScript files | 3.5.5 |
| PSC-053 | No JSONP functionality | No callback/jsonp query parameter handling, no wrapping of JSON in function calls | `v3/server/pages.py` | 3.5.6 |
| PSC-054 | HTML-First Response Architecture | All data-serving routes use server-side EZT templating to produce text/html responses | `v3/server/pages.py` | 3.5.7 |
| PSC-055 | Modern client-side technology stack | Uses Bootstrap 5.3.1, Bootstrap Icons 1.13.1, SortableJS 1.15.7 with version pinning | `v3/server/bin/fetch-thirdparty.sh` | 3.7.1 |
| PSC-056 | Self-hosted dependencies | All third-party assets are self-hosted, reducing CDN risks | `v3/server/bin/fetch-thirdparty.sh` | 3.7.1 |
| PSC-057 | All redirects use absolute paths | Every quart.redirect() call uses a path starting with / | `v3/server/pages.py` | 3.7.2 |
| PSC-058 | Database validation before redirect | Dynamic redirect components validated via database lookup through decorators | `v3/server/pages.py` | 3.7.2 |
| PSC-059 | Framework-delegated HTTP parsing | All request body parsing uses Quart's built-in request.form and request.get_json() | `v3/server/pages.py` | 4.2.2 |
| PSC-060 | Strong cryptographic primitives | Argon2 (Type D, 64MB memory), HKDF-SHA256, Fernet encryption, secrets module | `v3/steve/crypto.py` | 11.2.3 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Status | Title | Related Findings |
|---------|--------|-------|------------------|
| 1.1.1 | **Fail** | Encoding and Sanitization Architecture | FINDING-001, FINDING-002, FINDING-003, FINDING-091 |
| 1.1.2 | **Fail** | Encoding and Sanitization Architecture | FINDING-001, FINDING-002, FINDING-003, FINDING-091 |
| 1.2.1 | **Fail** | Output Encoding for HTTP Response Context | FINDING-001, FINDING-002, FINDING-003, FINDING-091 |
| 1.2.2 | **Fail** | Injection Prevention - Dynamic URL Building with Untrusted Data | FINDING-003 |
| 1.2.3 | **Fail** | JavaScript/JSON Injection Prevention | FINDING-002 |
| 1.2.4 | **Pass** | Injection Prevention - Parameterized Queries | PSC-001 |
| 1.2.5 | **Pass** | OS Command Injection Prevention | PSC-010 |
| 1.2.6 | **Pass** | LDAP Injection Prevention | PSC-004 |
| 1.2.7 | **Fail** | XPath Injection Prevention / Injection Prevention | FINDING-095 |
| 1.2.8 | **N/A** | LaTeX Processor Security Configuration | — |
| 1.2.9 | **Partial** | Injection Prevention - Encoding and Sanitization | FINDING-003 |
| 1.2.10 | **Fail** | CSV and Formula Injection Protection | FINDING-094 |
| 1.3.1 | **Fail** | HTML input from WYSIWYG sanitization | FINDING-003, FINDING-004 |
| 1.3.2 | **Pass** | Avoid eval() and dynamic code execution | PSC-019 |
| 1.3.3 | **Fail** | Data sanitization before dangerous contexts | FINDING-002, FINDING-095, FINDING-098 |
| 1.3.4 | **Fail** | SVG scriptable content validation | FINDING-003, FINDING-004 |
| 1.3.5 | **Fail** | Template language content sanitization | FINDING-001, FINDING-002, FINDING-003, FINDING-022 |
| 1.3.6 | **Partial** | SSRF protection | PSC-021, FINDING-097 |
| 1.3.7 | **Fail** | Template injection protection | FINDING-002, FINDING-022, PSC-020 |
| 1.3.8 | **Partial** | JNDI query sanitization | FINDING-095 |
| 1.3.9 | **N/A** | Memcache injection sanitization | — |
| 1.3.10 | **Fail** | Format string sanitization | FINDING-002, FINDING-003, FINDING-004, FINDING-022 |
| 1.3.11 | **Fail** | SMTP/IMAP injection sanitization | FINDING-096 |
| 1.3.12 | **Pass** | ReDoS prevention | PSC-011, PSC-018 |
| 1.4.1 | **Pass** | Memory Safety Analysis | PSC-009 |
| 1.4.2 | **Partial** | Integer Overflow Prevention | PSC-007, PSC-008, FINDING-092 |
| 1.4.3 | **Fail** | Dynamic Resource Release | FINDING-093 |
| 1.5.1 | **Pass** | XML parser restrictive configuration | — |
| 1.5.2 | **Pass** | Safe deserialization | PSC-006, PSC-022, PSC-023, PSC-041 |
| 1.5.3 | **Fail** | Parser consistency | FINDING-099, FINDING-100, FINDING-101 |
| 2.1.1 | **Pass** | Validation and Business Logic Documentation | PSC-038 |
| 2.1.2 | **Fail** | Combined data item consistency validation | FINDING-005, FINDING-095, FINDING-104 |
| 2.1.3 | **Fail** | Validation and Business Logic Documentation | FINDING-005, FINDING-038, FINDING-095, FINDING-106 |
| 2.2.1 | **Fail** | Input Validation | FINDING-095 |
| 2.2.2 | **Fail** | Input Validation at Trusted Service Layer | FINDING-095 |
| 2.2.3 | **Fail** | Reasonable data combinations verification | FINDING-095, FINDING-104, FINDING-105 |
| 2.3.1 | **Fail** | Business Logic Sequential Flow Enforcement | FINDING-005, FINDING-095, PSC-016, PSC-024, PSC-025, PSC-033, PSC-036 |
| 2.3.2 | **Fail** | Business Logic Limits Implementation | FINDING-005, FINDING-095, FINDING-103, PSC-031 |
| 2.3.3 | **Fail** | Transaction Atomicity | FINDING-023, FINDING-024, FINDING-102, PSC-028, PSC-035 |
| 2.3.4 | **Fail** | Business Logic Level Locking | FINDING-005, FINDING-023, FINDING-024, FINDING-025 |
| 2.3.5 | **Fail** | Multi-user Approval for High-Value Operations | FINDING-006, FINDING-007, FINDING-026 |
| 2.4.1 | **Fail** | Anti-Automation Controls | FINDING-027, FINDING-106, FINDING-107 |
| 2.4.2 | **Fail** | Realistic Human Timing | FINDING-027, FINDING-107 |
| 3.1.1 | **Fail** | Web Frontend Security Documentation | FINDING-118, FINDING-121, FINDING-232, FINDING-233 |
| 3.2.1 | **Fail** | Unintended Content Interpretation | FINDING-028, FINDING-108, FINDING-109 |
| 3.2.2 | **Fail** | Unintended Content Interpretation | FINDING-002, FINDING-003, FINDING-031, FINDING-113, FINDING-114 |
| 3.2.3 | **Fail** | DOM Clobbering Prevention | FINDING-115, FINDING-116, FINDING-117 |
| 3.3.1 | **Fail** | Cookie Setup | FINDING-029, FINDING-110 |
| 3.3.2 | **Fail** | Cookie SameSite Attribute | FINDING-007, FINDING-030 |
| 3.3.3 | **Fail** | Cookie __Host- Prefix Requirement | FINDING-110 |
| 3.3.4 | **Partial** | Cookie Setup | FINDING-111 |
| 3.3.5 | **Fail** | Cookie Setup | FINDING-112 |
| 3.4.1 | **Fail** | Strict Transport Security | FINDING-118 |
| 3.4.2 | **Pass** | CORS Configuration | PSC-046 |
| 3.4.3 | **Fail** | Content-Security-Policy Response Header | FINDING-032, FINDING-121 |
| 3.4.4 | **Fail** | X-Content-Type-Options | FINDING-119 |
| 3.4.5 | **Fail** | Referrer Policy | FINDING-120 |
| 3.4.6 | **Fail** | frame-ancestors directive | FINDING-032 |
| 3.4.7 | **Fail** | CSP Violation Reporting | FINDING-121 |
| 3.4.8 | **Fail** | Cross-Origin-Opener-Policy Header | FINDING-122 |
| 3.5.1 | **Fail** | CSRF Protection for Sensitive Functionality | FINDING-007, FINDING-008, FINDING-009, FINDING-033, PSC-042 |
| 3.5.2 | **Fail** | CORS Preflight Bypass Prevention | FINDING-009, FINDING-034, FINDING-123, PSC-050 |
| 3.5.3 | **Fail** | HTTP Method Appropriateness | FINDING-007, FINDING-009, PSC-049 |
| 3.5.4 | **Fail** | Browser Origin Separation via Hostname | FINDING-034, PSC-051 |
| 3.5.5 | **N/A** | postMessage Interface Origin Validation | PSC-052 |
| 3.5.6 | **Pass** | JSONP / XSSI Prevention | PSC-053 |
| 3.5.7 | **Pass** | Authorized Data in Script Resources Prevention | PSC-054 |
| 3.5.8 | **Fail** | Authenticated Resource Cross-Origin Loading Protection | FINDING-035, FINDING-036, FINDING-124 |
| 3.6.1 | **Partial** | External Resource Integrity | PSC-013, FINDING-234, FINDING-235, FINDING-236 |
| 3.7.1 | **Pass** | Client-Side Technology Security | PSC-055, PSC-056 |
| 3.7.2 | **Pass** | Automatic Redirect Allowlist Validation | PSC-057, PSC-058 |
| 3.7.3 | **Fail** | External URL Navigation Warning | FINDING-125 |
| 3.7.4 | **Fail** | HSTS Preload List | FINDING-118 |
| 3.7.5 | **Fail** | Browser Security Feature Detection | FINDING-126 |
| 4.1.1 | **Fail** | Content-Type Header Validation | FINDING-127, FINDING-128 |
| 4.1.2 | **Fail** | API and Web Service | FINDING-129, FINDING-130 |
| 4.1.3 | **Fail** | Proxy Header Protection | FINDING-131 |
| 4.1.4 | **Fail** | HTTP Method Restriction | FINDING-007, FINDING-009 |
| 4.1.5 | **Fail** | Per-Message Digital Signatures | FINDING-037, FINDING-132 |
| 4.2.1 | **Partial** | HTTP Message Structure Validation | FINDING-133, FINDING-134 |
| 4.2.2 | **Pass** | HTTP Message Structure Validation | PSC-059 |
| 4.2.3 | **Fail** | HTTP/2 Connection-Specific Header Validation | FINDING-135 |
| 4.2.4 | **Fail** | HTTP Message Structure Validation | FINDING-136, FINDING-137 |
| 4.2.5 | **Fail** | Overly Long URI/Header Prevention | FINDING-138 |
| 4.3.1 | **N/A** | GraphQL DoS prevention | — |
| 4.3.2 | **N/A** | GraphQL Introspection Queries | — |
| 4.4.1 | **Partial** | WebSocket over TLS | FINDING-014 |
| 4.4.2 | **Fail** | WebSocket Origin Header Validation | FINDING-139 |
| 4.4.3 | **N/A** | WebSocket Session Management | — |
| 4.4.4 | **N/A** | WebSocket Session Management Token Validation | — |
| 5.1.1 | **Fail** | File Handling Documentation | FINDING-038, FINDING-140, FINDING-141 |
| 5.2.1 | **N/A** | File Upload Size Limits | — |
| 5.2.2 | **Partial** | File Upload and Content Validation | FINDING-038 |
| 5.2.3 | **N/A** | Compressed File Validation | — |
| 5.2.4 | **N/A** | File Size Quota Per User | — |
| 5.2.5 | **N/A** | Compressed File Symlink Validation | — |
| 5.2.6 | **N/A** | Image Pixel Size Validation | — |
| 5.3.1 | **Partial** | Prevention of Server-Side Execution | FINDING-038 |
| 5.3.2 | **Fail** | File Path Security | FINDING-039, PSC-005 |
| 5.3.3 | **N/A** | Server-Side File Processing Path Validation | — |
| 5.4.1 | **Fail** | File Download Filename Validation | FINDING-038 |
| 5.4.2 | **N/A** | File Name Encoding/Sanitization | — |
| 5.4.3 | **Fail** | File Download - Antivirus Scanning | FINDING-142 |
| 6.1.1 | **Fail** | Authentication Documentation | FINDING-040, FINDING-143, FINDING-144 |
| 6.1.2 | **N/A** | — | — |
| 6.1.3 | **Fail** | Multiple Authentication Pathways Documentation | — |
| 6.2.1–6.2.12 | **N/A** | Password authentication requirements | — |
| 6.3.1 | **Fail** | Brute Force and Credential Stuffing Prevention | FINDING-040, FINDING-145 |
| 6.3.2 | **Pass** | Default User Accounts | — |
| 6.3.3 | **Fail** | Multi-Factor Authentication Requirements | — |
| 6.3.4 | **Fail** | Consistent security controls across authentication pathways | — |
| 6.3.5 | **Fail** | Suspicious Authentication Notification | — |
| 6.3.6 | **Pass** | Email not used as authentication mechanism | — |
| 6.3.7 | **Fail** | Notification after credential updates | — |
| 6.3.8 | **Partial** | User Enumeration Protection | — |
| 6.4.1–6.4.3 | **N/A** | Credential storage requirements | — |
| 6.4.4 | **Fail** | Authentication Factor Lifecycle | — |
| 6.4.5 | **Fail** | Authentication Factor Recovery | — |
| 6.4.6 | **N/A** | Admin Password Reset | — |
| 6.5.1 | **N/A** | General MFA requirements | — |
| 6.5.2 | **Partial** | Lookup Secret Storage | — |
| 6.5.3 | **Pass** | Cryptographically Secure RNG | — |
| 6.5.4–6.5.5 | **N/A** | Lookup secret entropy | — |
| 6.5.6 | **Fail** | Authentication Factor Revocation | — |
| 6.5.7 | **N/A** | — | — |
| 6.5.8 | **N/A** | TOTP Time Source Verification | — |
| 6.6.1 | **N/A** | Out-of-Band authentication | — |
| 6.6.2 | **Fail** | Out-of-Band authentication | — |
| 6.6.3 | **Fail** | Code-based OOB brute force protection | FINDING-146 |
| 6.6.4 | **N/A** | — | — |
| 6.7.1 | **Fail** | Cryptographic authentication mechanism | FINDING-237, FINDING-238 |
| 6.7.2 | **N/A** | Challenge Nonce Length | — |
| 6.8.1 | **Partial** | Identity Provider Namespace Verification | — |
| 6.8.2 | **Fail** | Digital signature validation on assertions | — |
| 6.8.3 | **N/A** | — | — |
| 6.8.4 | **Fail** | Authentication strength verification from IdP | — |
| 7.1.1 | **Fail** | Session timeout documentation | FINDING-041, FINDING-148 |
| 7.1.2 | **Fail** | Concurrent Session Limits | FINDING-149 |
| 7.1.3 | **Fail** | Federated Identity session management | FINDING-041, FINDING-042, FINDING-044 |
| 7.2.1 | **Partial** | Fundamental Session Management Security | FINDING-147 |
| 7.2.2 | **Pass** | Dynamic Token Generation | PSC-026, PSC-027 |
| 7.2.3 | **Partial** | Fundamental Session Management Security | FINDING-183, PSC-047 |
| 7.2.4 | **Fail** | Session Token Regeneration | FINDING-042, FINDING-043, FINDING-044 |
| 7.3.1 | **Fail** | Inactivity timeout enforcement | FINDING-041, FINDING-042 |
| 7.3.2 | **Fail** | Absolute Maximum Session Lifetime | FINDING-041 |
| 7.4.1 | **Fail** | Session Termination on Logout | FINDING-042 |
| 7.4.2 | **Fail** | Session Termination on account deletion | FINDING-045 |
| 7.4.3 | **Fail** | Session Termination after factor changes | FINDING-046 |
| 7.4.4 | **Pass** | Logout Functionality Visibility | — |
| 7.4.5 | **Fail** | Administrator session termination | FINDING-047 |
| 7.5.1 | **Pass** | Re-authentication for Sensitive Account Modifications | — |
| 7.5.2 | **Fail** | View and Terminate Active Sessions | FINDING-048 |
| 7.5.3 | **Fail** | Re-authentication Before Highly Sensitive Operations | FINDING-044, FINDING-147 |
| 7.6.1 | **Fail** | Federated Re-authentication | FINDING-041, FINDING-042, FINDING-044 |
| 7.6.2 | **Fail** | Session creation requires user consent | FINDING-147, FINDING-150 |
| 8.1.1 | **Fail** | Authorization Documentation | FINDING-006, FINDING-049, FINDING-151 |
| 8.1.2 | **Fail** | Field-Level Authorization Documentation | FINDING-005, FINDING-006, FINDING-049, FINDING-050, FINDING-151 |
| 8.1.3 | **Fail** | Environmental/Contextual Authorization | FINDING-005, FINDING-050, FINDING-151 |
| 8.1.4 | **Fail** | Authorization Decision-Making Documentation | FINDING-005, FINDING-006, FINDING-007, FINDING-049 |
| 8.2.1 | **Pass** | Function-Level Access Control | PSC-017, PSC-039 |
| 8.2.2 | **Fail** | Data-Specific Access Control (IDOR/BOLA) | FINDING-006, FINDING-010, FINDING-049, PSC-030 |
| 8.2.3 | **Fail** | Field-Level Access Control (BOPLA) | FINDING-006, FINDING-051, FINDING-153 |
| 8.2.4 | **Fail** | Adaptive Security Controls | — |
| 8.3.1 | **Fail** | Operation Level Authorization | FINDING-006, FINDING-007, FINDING-152 |
| 8.3.2 | **Fail** | Immediate Application of Authorization Changes | FINDING-007, FINDING-049 |
| 8.3.3 | **Fail** | Subject-Based Permission Enforcement | FINDING-006, FINDING-010, FINDING-049 |
| 8.4.1 | **Fail** | Multi-Tenant Cross-Tenant Control | FINDING-006, FINDING-010, FINDING-049 |
| 8.4.2 | **Fail** | Administrative Interface Multi-Layer Security | — |
| 9.1.1 | **Fail** | Self-Contained Token Integrity Validation | FINDING-103 |
| 9.1.2 | **Pass** | Algorithm Allowlist | — |
| 9.1.3 | **N/A** | Key Material from Trusted Sources | — |
| 9.2.1 | **Partial** | Time-based validity verification | FINDING-154 |
| 9.2.2 | **N/A** | Token Type and Purpose Validation | — |
| 9.2.3 | **N/A** | Token Audience Validation | — |
| 9.2.4 | **Pass** | Token Audience Restriction | — |
| 10.1.1 | **Partial** | Token Distribution Restriction | FINDING-155, FINDING-156 |
| 10.1.2 | **Fail** | OAuth Authorization Flow Transaction Binding | FINDING-157, FINDING-158 |
| 10.2.1 | **Fail** | CSRF Protection in Authorization Code Flow | FINDING-008, FINDING-157, FINDING-158 |
| 10.2.2 | **N/A** | Defense Against Mix-Up Attacks | — |
| 10.2.3 | **Fail** | Required Scopes Only | FINDING-159 |
| 10.3.1 | **Fail** | OAuth Resource Server Audience Validation | FINDING-155 |
| 10.3.2 | **Fail** | Delegated Authorization Claims Enforcement | FINDING-011, FINDING-012, FINDING-159 |
| 10.3.3 | **Fail** | User Identity from Access Tokens | FINDING-160 |
| 10.3.4 | **Fail** | Authentication Strength Verification | FINDING-161, FINDING-162 |
| 10.3.5 | **Fail** | Sender-Constrained Access Tokens | FINDING-052 |
| 10.4.1 | **N/A** | Redirect URI Validation | — |
| 10.4.2–10.4.5 | **N/A** | Authorization Server requirements | — |
| 10.4.6 | **Fail** | PKCE for Authorization Code Flow | FINDING-157 |
| 10.4.7 | **N/A** | Dynamic Client Registration Security | — |
| 10.4.8 | **Fail** | Refresh Token Absolute Expiration | FINDING-166 |
| 10.4.9 | **Fail** | Token Revocation | FINDING-167 |
| 10.4.10 | **Fail** | Client Authentication for Backchannel Requests | FINDING-163 |
| 10.4.11 | **Fail** | Required Scopes Assignment | FINDING-011, FINDING-012, FINDING-159 |
| 10.4.12 | **Partial** | Response Mode Validation | FINDING-164 |
| 10.4.13 | **Fail** | PAR Requirement | FINDING-053 |
| 10.4.14 | **Fail** | Sender-Constrained Access Tokens | FINDING-052 |
| 10.4.15 | **Fail** | Server-Side Client Authorization Parameter Integrity | FINDING-053 |
| 10.4.16 | **Fail** | Client Authentication with Public-Key Cryptography | FINDING-054, FINDING-165 |
| 10.5.1 | **Fail** | ID Token Replay Attack Mitigation via Nonce | FINDING-158 |
| 10.5.2 | **Fail** | Unique User Identification from ID Token | FINDING-055, FINDING-168 |
| 10.5.3 | **Fail** | Authorization Server Issuer Validation | FINDING-169 |
| 10.5.4 | **Fail** | ID Token Audience Validation | FINDING-056 |
| 10.5.5 | **N/A** | OIDC Back-Channel Logout Security | — |
| 10.6.1 | **Partial** | OpenID Provider Response Mode Restrictions | FINDING-170 |
| 10.6.2 | **Fail** | Denial of Service through Forced Logout | FINDING-042 |
| 10.7.1 | **Partial** | User Consent for Authorization Requests | FINDING-171 |
| 10.7.2 | **Fail** | Clear Consent Information | FINDING-159, FINDING-172, FINDING-173 |
| 10.7.3 | **Fail** | Review, Modify, and Revoke Consents | FINDING-174 |
| 11.1.1 | **Fail** | Cryptographic Key Management Policy | FINDING-062, FINDING-179 |
| 11.1.2 | **Fail** | Cryptographic Inventory and Documentation | FINDING-062, FINDING-179, FINDING-180, FINDING-181 |
| 11.1.3 | **Fail** | Discovery Mechanisms | FINDING-062, FINDING-179, FINDING-180, FINDING-181 |
| 11.1.4 | **Fail** | PQC Migration Plan | FINDING-062 |
| 11.2.1 | **Partial** | Secure Cryptography Implementation | FINDING-179, FINDING-180, FINDING-181 |
| 11.2.2 | **Fail** | Crypto Agility | FINDING-063, FINDING-075 |
| 11.2.3 | **Partial** | Minimum 128-bit Security | FINDING-180, PSC-060 |
| 11.2.4 | **Fail** | Constant-Time Cryptographic Operations | FINDING-179, FINDING-180 |
| 11.2.5 | **Partial** | Cryptographic modules fail securely | FINDING-182 |
| 11.3.1 | **Pass** | Insecure Block Modes and Weak Padding | — |
| 11.3.2 | **Fail** | Approved Ciphers and Modes | FINDING-015 |
| 11.3.3 | **Partial** | Authenticated Encryption | FINDING-015, FINDING-179, FINDING-180, FINDING-181 |
| 11.3.4 | **Partial** | Nonce and IV Uniqueness | FINDING-181 |
| 11.3.5 | **Partial** | Encrypt-then-MAC Mode | FINDING-181 |
| 11.4.1 | **Pass** | Hash Function Usage | — |
| 11.4.2 | **Fail** | Password Storage with Approved KDF | FINDING-180 |
| 11.4.3 | **Partial** | Hashing and Hash-based Functions | FINDING-180, FINDING-184 |
| 11.4.4 | **Partial** | Hashing and Hash-based Functions | FINDING-180, FINDING-184 |
| 11.5.1 | **Partial** | Random Values | FINDING-183, PSC-032 |
| 11.5.2 | **Pass** | Random number generation under demand | — |
| 11.6.1 | **Partial** | Approved Cryptographic Algorithms | FINDING-179, FINDING-180, FINDING-181 |
| 11.6.2 | **Partial** | Key Exchange and Secure Parameters | FINDING-103, FINDING-179, FINDING-180, FINDING-181 |
| 11.7.1 | **Fail** | Full Memory Encryption | FINDING-090, FINDING-179, FINDING-180 |
| 11.7.2 | **Partial** | Data Minimization and Immediate Encryption | FINDING-078, FINDING-180, FINDING-239 |
| 12.1.1 | **Fail** | Secure Communication | FINDING-013, PSC-043 |
| 12.1.2 | **Fail** | Cipher Suite Configuration | FINDING-057, FINDING-175, FINDING-176 |
| 12.1.3 | **Fail** | mTLS Client Certificate Validation | FINDING-060, FINDING-175 |
| 12.1.4 | **Fail** | Certificate Revocation (OCSP Stapling) | FINDING-058, FINDING-176, FINDING-177 |
| 12.1.5 | **Fail** | Encrypted Client Hello (ECH) Support | FINDING-059 |
| 12.2.1 | **Fail** | HTTPS Communication with External Services | FINDING-014 |
| 12.2.2 | **Fail** | Publicly Trusted TLS Certificates | FINDING-061 |
| 12.3.1 | **Fail** | Encrypted Protocol Enforcement | FINDING-013, FINDING-014, FINDING-057, FINDING-175, PSC-014 |
| 12.3.2 | **Fail** | TLS Certificate Validation | FINDING-177 |
| 12.3.3 | **Fail** | HTTP-based Services | FINDING-014, FINDING-057, FINDING-175 |
| 12.3.4 | **Fail** | Trusted Certificates | FINDING-060, FINDING-177, FINDING-178 |
| 12.3.5 | **Fail** | Strong Authentication | FINDING-060, FINDING-178 |
| 13.1.1 | **Fail** | Communication Needs Documentation | FINDING-185, FINDING-186, FINDING-187 |
| 13.1.2 | **Fail** | Service Connection Limits | FINDING-064, FINDING-188, FINDING-189 |
| 13.1.3 | **Fail** | Resource Management Documentation | FINDING-189 |
| 13.1.4 | **Fail** | Secrets Documentation and Rotation | FINDING-066, FINDING-067, FINDING-190 |
| 13.2.1 | **Partial** | Backend Communication Configuration | FINDING-191, FINDING-192 |
| 13.2.2 | **Fail** | Backend Communication Configuration | FINDING-005, FINDING-193 |
| 13.2.3 | **Pass** | No Default Credentials | — |
| 13.2.4 | **Fail** | Backend Communication Configuration | FINDING-194, FINDING-195 |
| 13.2.5 | **Fail** | Backend Communication Configuration | FINDING-194 |
| 13.2.6 | **Fail** | Backend Communication Configuration | FINDING-064, FINDING-189, FINDING-196 |
| 13.3.1 | **Fail** | Secrets Management Solution | FINDING-068, FINDING-199 |
| 13.3.2 | **Partial** | Least Privilege Access to Secrets | FINDING-197, FINDING-198 |
| 13.3.3 | **Fail** | Isolated Security Module | FINDING-069, FINDING-199, FINDING-200 |
| 13.3.4 | **Fail** | Secret Expiration and Rotation | FINDING-068, FINDING-178, FINDING-201 |
| 13.4.1 | **Partial** | Source Control Metadata Exclusion | — |
| 13.4.2 | **Fail** | Unintended Information Leakage | FINDING-187 |
| 13.4.3 | **Pass** | Directory Listings | — |
| 13.4.4 | **Fail** | HTTP TRACE Method Blocking | FINDING-202 |
| 13.4.5 | **Fail** | Documentation and Monitoring Endpoints | FINDING-203, FINDING-204 |
| 13.4.6 | **Fail** | Backend Component Version Disclosure | FINDING-187, FINDING-205 |
| 13.4.7 | **Partial** | File Extension Restrictions | FINDING-206, FINDING-207 |
| 14.1.1 | **Fail** | Data Protection Documentation | FINDING-007, FINDING-070, FINDING-208, PSC-015 |
| 14.1.2 | **Fail** | Data Protection Documentation | FINDING-006, FINDING-071, FINDING-072, FINDING-208, FINDING-209 |
| 14.2.1 | **Pass** | Sensitive Data in URLs | — |
| 14.2.2 | **Fail** | Server Component Cache Prevention | FINDING-072, FINDING-210 |
| 14.2.3 | **Fail** | Sensitive Data Not Sent to Untrusted Parties | FINDING-211 |
| 14.2.4 | **Fail** | Controls around sensitive data | FINDING-006, FINDING-007, FINDING-072, FINDING-208, FINDING-209, FINDING-212 |
| 14.2.5 | **Fail** | Cache Control and Web Cache Deception | FINDING-072, FINDING-210 |
| 14.2.6 | **Fail** | Minimum Sensitive Data Return | FINDING-073, FINDING-213, FINDING-214, PSC-037 |
| 14.2.7 | **Fail** | Data Retention Classification | FINDING-074, FINDING-075, FINDING-215, FINDING-216 |
| 14.2.8 | **Fail** | Metadata Removal | FINDING-217 |
| 14.3.1 | **Fail** | Authenticated Data Clearing | FINDING-016 |
| 14.3.2 | **Fail** | Cache-Control Header for Sensitive Data | FINDING-072 |
| 14.3.3 | **Partial** | Browser Storage of Sensitive Data | FINDING-218 |
| 15.1.1 | **Fail** | Risk-Based Remediation Timeframes | FINDING-017 |
| 15.1.2 | **Fail** | SBOM and Third-Party Library Inventory | FINDING-017, FINDING-220 |
| 15.1.3 | **Fail** | Resource-Intensive Functionality Documentation | FINDING-065 |
| 15.1.4 | **Fail** | Risky Third-Party Components Documentation | FINDING-076, FINDING-180 |
| 15.1.5 | **Fail** | Dangerous Functionality Documentation | FINDING-005, FINDING-077, FINDING-180 |
| 15.2.1 | **Fail** | Component Update and Remediation | FINDING-017 |
| 15.2.2 | **Fail** | Resource-Demanding Functionality DoS Defenses | FINDING-065, FINDING-099 |
| 15.2.3 | **Partial** | Production Environment Functionality | FINDING-187, FINDING-221 |
| 15.2.4 | **Fail** | Third-Party Component Repository Verification | FINDING-219, FINDING-220 |
| 15.2.5 | **Fail** | Additional Protections for Dangerous Functionality | FINDING-078 |
| 15.3.1 | **Fail** | Data Minimization in API/Data Responses | — |
| 15.3.2 | **Pass** | External URL Redirect Following | — |
| 15.3.3 | **Partial** | Mass Assignment Protection | — |
| 15.3.4 | **Fail** | IP Address Handling in Proxied Environments | — |
| 15.3.5 | **Fail** | Type Safety and Strict Equality | FINDING-099 |
| 15.3.6 | **Partial** | Prototype Pollution Prevention | — |
| 15.3.7 | **Partial** | HTTP Parameter Pollution Defense | — |
| 15.4.1 | **Fail** | Safe Concurrency | FINDING-005, FINDING-023, FINDING-024, FINDING-025, FINDING-087 |
| 15.4.2 | **Fail** | TOCTOU Prevention | FINDING-023, FINDING-024, FINDING-025, FINDING-087, FINDING-088 |
| 15.4.3 | **Fail** | Safe Concurrency | FINDING-005, FINDING-024, FINDING-025, FINDING-087 |
| 15.4.4 | **Fail** | Resource Allocation and Thread Starvation | FINDING-089, FINDING-240 |
| 16.1.1 | **Fail** | Security Logging Documentation | FINDING-018, FINDING-019, FINDING-079, FINDING-225, FINDING-226, FINDING-227 |
| 16.2.1 | **Fail** | Log Entry Metadata Completeness | FINDING-018, FINDING-019, FINDING-079, FINDING-224, PSC-040 |
| 16.2.2 | **Fail** | Time Source Synchronization and UTC Timestamps | FINDING-019, FINDING-222, FINDING-223 |
| 16.2.3 | **Fail** | Log Destination Documentation | FINDING-018, FINDING-227, FINDING-229 |
| 16.2.4 | **Fail** | Log Format and Correlation | FINDING-018, FINDING-222, FINDING-223, FINDING-227 |
| 16.2.5 | **Partial** | Sensitive Data Logging Protection | FINDING-226, FINDING-227 |
| 16.3.1 | **Fail** | Authentication Operation Logging | FINDING-019, FINDING-080, FINDING-224 |
| 16.3.2 | **Fail** | Failed Authorization Logging | FINDING-019, FINDING-079 |
| 16.3.3 | **Fail** | Security events and bypass attempts logging | FINDING-018, FINDING-019, FINDING-081, FINDING-082, FINDING-225 |
| 16.4.1 | **Fail** | Prevent Log Injection | FINDING-225, FINDING-227, FINDING-228 |
| 16.4.2 | **Fail** | Log Protection | FINDING-083, FINDING-227 |
| 16.4.3 | **Fail** | Secure Transmission to Separate System | FINDING-083 |
| 16.5.1 | **Fail** | Generic Error Messages | FINDING-020, FINDING-021 |
| 16.5.2 | **Fail** | Graceful Degradation on External Resource Failure | FINDING-086, FINDING-102, FINDING-230, FINDING-231 |
| 16.5.3 | **Fail** | Graceful and Secure Failure Analysis | FINDING-082, FINDING-084, FINDING-230 |
| 16.5.4 | **Fail** | Last Resort Exception Handler | FINDING-085 |
| 17.1.1–17.3.2 | **N/A** | WebRTC requirements | — |

---

# 6. Cross-Reference Matrix

## Findings → ASVS Requirements

| Finding ID | ASVS Requirements |
|------------|-------------------|
| FINDING-001 | 1.1.1, 1.1.2, 1.2.1, 1.3.4, 1.3.5 |
| FINDING-002 | 1.1.1, 1.1.2, 1.2.1, 1.2.3, 1.3.10, 1.3.5, 1.3.7, 1.3.3, 3.2.2 |
| FINDING-003 | 1.3.1, 1.3.4, 1.3.5, 1.3.10, 1.1.1, 1.1.2, 1.2.1, 1.2.2, 1.2.9, 3.2.2 |
| FINDING-004 | 1.3.1, 1.3.4, 1.3.5, 1.3.10 |
| FINDING-005 | 2.3.1, 2.3.2, 2.3.4, 2.1.2, 2.1.3, 8.1.2, 8.1.3, 8.1.4, 13.2.2, 15.1.5, 15.4.1, 15.4.3 |
| FINDING-006 | 2.3.2, 2.3.5, 2.1.2, 2.1.3, 4.4.3, 7.2.1, 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.2.3, 8.3.1, 8.3.3, 8.4.1, 14.1.2, 14.2.4 |
| FINDING-007 | 2.3.2, 2.3.5, 2.1.2, 2.1.3, 3.3.2, 4.1.4, 4.4.3, 8.1.4, 8.3.1, 8.3.2, 10.2.1, 14.1.1, 14.1.2, 14.2.4 |
| FINDING-008 | 3.5.1, 10.2.1 |
| FINDING-009 | 3.5.1, 3.5.2, 3.5.3 |
| FINDING-010 | 8.2.2, 8.3.3, 8.4.1 |
| FINDING-011 | 10.3.2, 10.4.11 |
| FINDING-012 | 10.3.2, 10.4.11 |
| FINDING-013 | 12.1.1, 12.3.1 |
| FINDING-014 | 12.2.1, 12.3.1, 12.3.3, 4.4.1 |
| FINDING-015 | 11.3.2 |
| FINDING-016 | 14.3.1 |
| FINDING-017 | 15.1.1, 15.1.2, 15.2.1 |
| FINDING-018 | 16.1.1, 16.2.1, 16.2.3, 16.2.4, 16.3.3 |
| FINDING-019 | 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3, 16.2.2 |
| FINDING-020 | 16.5.1 |
| FINDING-021 | 16.5.1 |
| FINDING-022 | 1.3.10, 1.3.5, 1.3.7, 1.3.3 |
| FINDING-023 | 2.3.3, 2.3.4, 15.4.1, 15.4.2 |
| FINDING-024 | 2.3.3, 2.3.4, 15.4.1, 15.4.2, 15.4.3 |
| FINDING-025 | 2.3.4, 15.4.1, 15.4.2, 15.4.3 |
| FINDING-026 | 2.3.5 |
| FINDING-027 | 2.4.1, 2.4.2 |
| FINDING-028 | 3.2.1 |
| FINDING-029 | 3.3.1 |
| FINDING-030 | 3.3.2 |
| FINDING-031 | 3.2.2 |
| FINDING-032 | 3.4.6, 3.4.3 |
| FINDING-033 | 3.5.1 |
| FINDING-034 | 3.5.2, 3.5.4 |
| FINDING-035 | 3.5.8 |
| FINDING-036 | 3.5.8 |
| FINDING-037 | 4.1.5 |
| FINDING-038 | 5.1.1, 5.2.2, 5.3.1, 5.4.1, 2.1.3 |
| FINDING-039 | 5.3.2 |
| FINDING-040 | 6.3.1 |
| FINDING-041 | 7.1.1, 7.3.1, 7.3.2, 7.1.3, 7.6.1 |
| FINDING-042 | 7.1.3, 7.2.4, 7.3.1, 7.4.1, 7.6.1, 10.6.2 |
| FINDING-043 | 7.2.4 |
| FINDING-044 | 7.1.3, 7.2.4, 7.5.3, 7.6.1 |
| FINDING-045 | 7.4.2 |
| FINDING-046 | 7.4.3 |
| FINDING-047 | 7.4.5 |
| FINDING-048 | 7.5.2 |
| FINDING-049 | 8.1.1, 8.1.2, 8.1.4, 8.2.2, 8.3.2, 8.3.3, 8.4.1 |
| FINDING-050 | 8.1.2, 8.1.3 |
| FINDING-051 | 8.2.3 |
| FINDING-052 | 10.3.5, 10.4.14 |
| FINDING-053 | 10.4.13, 10.4.15 |
| FINDING-054 | 10.4.16 |
| FINDING-055 | 10.5.2 |
| FINDING-056 | 10.5.4 |
| FINDING-057 | 12.1.2, 12.3.1, 12.3.3, 12.3.4 |
| FINDING-058 | 12.1.4 |
| FINDING-059 | 12.1.5 |
| FINDING-060 | 12.1.3, 12.3.4, 12.3.5 |
| FINDING-061 | 12.2.2 |
| FINDING-062 | 11.1.1, 11.1.2, 11.1.3, 11.1.4 |
| FINDING-063 | 11.2.2 |
| FINDING-064 | 13.1.2, 13.2.6 |
| FINDING-065 | 13.1.2, 15.1.3, 15.2.2 |
| FINDING-066 | 13.1.4 |
| FINDING-067 | 13.1.4 |
| FINDING-068 | 13.3.1, 13.3.4 |
| FINDING-069 | 13.3.3 |
| FINDING-070 | 14.1.1 |
| FINDING-071 | 14.1.2 |
| FINDING-072 | 14.1.2, 14.2.2, 14.2.4, 14.2.5, 14.3.2, 14.1.1 |
| FINDING-073 | 14.2.6 |
| FINDING-074 | 14.2.7 |
| FINDING-075 | 14.2.7, 11.2.2 |
| FINDING-076 | 15.1.4 |
| FINDING-077 | 15.1.5 |
| FINDING-078 | 15.2.5, 11.7.2 |
| FINDING-079 | 16.1.1, 16.2.1, 16.3.1, 16.3.2, 16.3.3 |
| FINDING-080 | 16.3.1 |
| FINDING-081 | 16.3.3 |
| FINDING-082 | 16.3.3, 16.5.3 |
| FINDING-083 | 16.4.2, 16.4.3 |
| FINDING-084 | 16.5.3 |
| FINDING-085 | 16.5.4 |
| FINDING-086 | 16.5.2 |
| FINDING-087 | 15.4.1, 15.4.2, 15.4.3 |
| FINDING-088 | 15.4.2 |
| FINDING-089 | 15.4.4 |
| FINDING-090 | 11.7.1 |
| FINDING-091 | 1.1.1, 1.1.2, 1.2.1 |
| FINDING-092 | 1.4.2 |
| FINDING-093 | 1.4.3 |
| FINDING-094 | 1.2.10 |
| FINDING-095 | 1.2.7, 1.3.8, 1.3.9, 1.3.3, 2.3.1, 2.3.2, 2.2.1, 2.2.2, 2.2.3, 2.1.2, 2.1.3 |
| FINDING-096 | 1.3.11 |
| FINDING-097 | 1.3.6 |
| FINDING-098 | 1.3.3 |
| FINDING-099 | 1.5.3, 15.2.2, 15.3.5 |
| FINDING-100 | 1.5.3 |
| FINDING-101 | 1.5.3 |
| FINDING-102 | 2.3.3, 16.5.2 |
| FINDING-103 | 2.3.2, 9.1.1, 11.6.2 |
| FINDING-104 | 2.1.2, 2.2.3 |
| FINDING-105 | 2.2.3 |
| FINDING-106 | 2.1.3, 2.4.1 |
| FINDING-107 | 2.4.1, 2.4.2 |
| FINDING-108 | 3.2.1 |
| FINDING-109 | 3.2.1 |
| FINDING-110 | 3.3.1, 3.3.3 |
| FINDING-111 | 3.3.4 |
| FINDING-112 | 3.3.5 |
| FINDING-113 | 3.2.2 |
| FINDING-114 | 3.2.2 |
| FINDING-115 | 3.2.3 |
| FINDING-116 | 3.2.3 |
| FINDING-117 | 3.2.3 |
| FINDING-118 | 3.4.1, 3.7.4, 3.1.1 |
| FINDING-119 | 3.4.4 |
| FINDING-120 | 3.4.5 |
| FINDING-121 | 3.4.7, 3.1.1 |
| FINDING-122 | 3.4.8 |
| FINDING-123 | 3.5.2 |
| FINDING-124 | 3.5.8 |
| FINDING-125 | 3.7.3 |
| FINDING-126 | 3.7.5 |
| FINDING-127 | 4.1.1 |
| FINDING-128 | 4.1.1 |
| FINDING-129 | 4.1.2 |
| FINDING-130 | 4.1.2 |
| FINDING-131 | 4.1.3 |
| FINDING-132 | 4.1.5 |
| FINDING-133 | 4.2.1 |
| FINDING-134 | 4.2.1 |
| FINDING-135 | 4.2.3 |
| FINDING-136 | 4.2.4 |
| FINDING-137 | 4.2.4 |
| FINDING-138 | 4.2.5 |
| FINDING-139 | 4.4.2 |
| FINDING-140 | 5.1.1 |
| FINDING-141 | 5.1.1 |
| FINDING-142 | 5.4.3 |
| FINDING-143 | 6.1.1 |
| FINDING-144 | 6.1.1 |
| FINDING-145 | 6.3.1 |
| FINDING-146 | 6.6.3 |
| FINDING-147 | 7.2.1, 7.5.3, 7.6.2 |
| FINDING-148 | 7.1.1 |
| FINDING-149 | 7.1.2 |
| FINDING-150 | 7.6.2 |
| FINDING-151 | 8.1.1, 8.1.2, 8.1.3 |
| FINDING-152 | 8.3.1 |
| FINDING-153 | 8.2.3 |
| FINDING-154 | 9.2.1 |
| FINDING-155 | 10.1.1, 10.3.1 |
| FINDING-156 | 10.1.1 |
| FINDING-157 | 10.1.2, 10.2.1, 10.4.6 |
| FINDING-158 | 10.1.2, 10.5.1 |
| FINDING-159 | 10.2.3, 10.3.2, 10.4.11, 10.7.2 |
| FINDING-160 | 10.3.3 |
| FINDING-161 | 10.3.4 |
| FINDING-162 | 10.3.4 |
| FINDING-163 | 10.4.10 |
| FINDING-164 | 10.4.12 |
| FINDING-165 | 10.4.16 |
| FINDING-166 | 10.4.8 |
| FINDING-167 | 10.4.9 |
| FINDING-168 | 10.5.2 |
| FINDING-169 | 10.5.3 |
| FINDING-170 | 10.6.1 |
| FINDING-171 | 10.7.1 |
| FINDING-172 | 10.7.2 |
| FINDING-173 | 10.7.2 |
| FINDING-174 | 10.7.3 |
| FINDING-175 | 12.1.2, 12.1.3, 12.3.1, 12.3.3 |
| FINDING-176 | 12.1.2, 12.1.4 |
| FINDING-177 | 12.1.4, 12.3.2, 12.3.4 |
| FINDING-178 | 12.3.4, 12.3.5, 13.3.4 |
| FINDING-179 | 11.1.1, 11.1.2, 11.1.3, 11.2.1, 11.2.3, 11.2.4, 11.2.5, 11.3.3, 11.4.2, 11.6.1, 11.6.2, 11.7.1 |
| FINDING-180 | 11.2.3, 11.2.4, 11.3.3, 11.4.2, 11.4.3, 11.4.4, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1, 15.1.4, 15.1.5, 11.7.1, 11.7.2 |
| FINDING-181 | 11.3.3, 11.3.4, 11.3.5, 11.6.1, 11.6.2, 11.1.1, 11.1.2, 11.1.3, 11.2.1 |
| FINDING-182 | 11.2.5 |
| FINDING-183 | 11.5.1, 7.2.3 |
| FINDING-184 | 11.4.4 |
| FINDING-185 | 13.1.1 |
| FINDING-186 | 13.1.1 |
| FINDING-187 | 13.1.1, 13.4.2, 15.2.3, 13.4.6 |
| FINDING-188 | 13.1.2 |
| FINDING-189 | 13.1.2, 13.1.3, 13.2.6 |
| FINDING-190 | 13.1.4 |
| FINDING-191 | 13.2.1 |
| FINDING-192 | 13.2.1 |
| FINDING-193 | 13.2.2 |
| FINDING-194 | 13.2.4, 13.2.5 |
| FINDING-195 | 13.2.4 |
| FINDING-196 | 13.2.6 |
| FINDING-197 | 13.3.2 |
| FINDING-198 | 13.3.2 |
| FINDING-199 | 13.3.1, 13.3.3 |
| FINDING-200 | 13.3.3 |
| FINDING-201 | 13.3.4 |
| FINDING-202 | 13.4.4 |
| FINDING-203 | 13.4.5 |
| FINDING-204 | 13.4.5 |
| FINDING-205 | 13.4.6 |
| FINDING-206 | 13.4.7 |
| FINDING-207 | 13.4.7 |
| FINDING-208 | 14.1.1, 14.1.2, 14.2.4 |
| FINDING-209 | 14.1.2, 14.2.4 |
| FINDING-210 | 14.2.2, 14.2.5 |
| FINDING-211 | 14.2.3 |
| FINDING-212 | 14.2.4 |
| FINDING-213 | 14.2.6 |
| FINDING-214 | 14.2.6 |
| FINDING-215 | 14.2.7 |
| FINDING-216 | 14.2.7 |
| FINDING-217 | 14.2.8 |
| FINDING-218 | 14.3.3 |
| FINDING-219 | 15.2.4 |
| FINDING-220 | 15.2.4 |
| FINDING-221 | 15.2.3 |
| FINDING-222 | 16.2.2, 16.2.4 |
| FINDING-223 | 16.2.2, 16.2.4 |
| FINDING-224 | 16.2.1, 16.3.1 |
| FINDING-225 | 16.1.1, 16.3.3, 16.4.1 |
| FINDING-226 | 16.1.1, 16.2.5 |
| FINDING-227 | 16.1.1, 16.2.3, 16.2.4, 16.2.5, 16.4.1, 16.4.2 |
| FINDING-228 | 16.4.1 |
| FINDING-229 | 16.2.3 |
| FINDING-230 | 16.5.2, 16.5.3 |
| FINDING-231 | 16.5.2 |
| FINDING-232 | 3.1.1 |
| FINDING-233 | 3.1.1 |
| FINDING-234 | 3.6.1 |
| FINDING-235 | 3.6.1 |
| FINDING-236 | 3.6.1 |
| FINDING-237 | 6.7.1 |
| FINDING-238 | 6.7.1 |
| FINDING-239 | 11.7.2 |
| FINDING-240 | 15.4.4 |

## ASVS Requirements → Findings/Controls

| ASVS ID | Findings | Positive Controls |
|---------|----------|-------------------|
| 1.1.1 | FINDING-001, FINDING-002, FINDING-003, FINDING-091 | PSC-002, PSC-003 |
| 1.1.2 | FINDING-001, FINDING-002, FINDING-003, FINDING-091 | PSC-002, PSC-003 |
| 1.2.1 | FINDING-001, FINDING-002, FINDING-003, FINDING-091 | PSC-012 |
| 1.2.4 | — | PSC-001 |
| 1.2.5 | — | PSC-010 |
| 1.2.6 | — | PSC-004 |
| 1.3.2 | — | PSC-019 |
| 1.3.6 | FINDING-097 | PSC-021 |
| 1.3.7 | FINDING-002, FINDING-022 | PSC-020 |
| 1.3.12 | — | PSC-011, PSC-018 |
| 1.4.1 | — | PSC-009 |
| 1.4.2 | FINDING-092 | PSC-007, PSC-008 |
| 1.5.2 | — | PSC-006, PSC-022, PSC-023, PSC-041 |
| 2.3.1 | FINDING-005, FINDING-095 | PSC-016, PSC-024, PSC-025, PSC-033, PSC-036 |
| 2.3.3 | FINDING-023, FINDING-024, FINDING-102 | PSC-028, PSC-035 |
| 3.4.2 | — | PSC-046 |
| 3.5.1 | FINDING-007, FINDING-008, FINDING-009, FINDING-033 | PSC-042 |
| 3.5.2 | FINDING-009, FINDING-034, FINDING-123 | PSC-050 |
| 3.5.3 | FINDING-007, FINDING-009 | PSC-049 |
| 3.5.4 | FINDING-034 | PSC-051 |
| 3.5.5 | — | PSC-052 |
| 3.5.6 | — | PSC-053 |
| 3.5.7 | — | PSC-054 |
| 3.6.1 | FINDING-234, FINDING-235, FINDING-236 | PSC-013 |
| 3.7.1 | — | PSC-055, PSC-056 |
| 3.7.2 | — | PSC-057, PSC-058 |
| 4.2.2 | — | PSC-059 |
| 5.3.2 | FINDING-039 | PSC-005 |
| 7.2.2 | — | PSC-026, PSC-027 |
| 7.2.3 | FINDING-183 | PSC-047 |
| 8.2.1 | — | PSC-017, PSC-039 |
| 8.2.2 | FINDING-006, FINDING-010, FINDING-049 | PSC-030 |
| 9.1.1 | FINDING-103 | PSC-029 |
| 10.1.1 | FINDING-155, FINDING-156 | PSC-048 |
| 11.2.3 | FINDING-180 | PSC-060 |
| 11.5.1 | FINDING-183 | PSC-032 |
| 12.1.1 | FINDING-013 | PSC-043 |
| 12.3.1 | FINDING-013, FINDING-014, FINDING-057, FINDING-175 | PSC-014 |
| 14.1.1 | FINDING-007, FINDING-070, FINDING-208 | PSC-015, PSC-034 |
| 14.2.6 | FINDING-073, FINDING-213, FINDING-214 | PSC-037 |
| 16.2.1 | FINDING-018, FINDING-019, FINDING-079, FINDING-224 | PSC-040 |

---

**End of Report**

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 47 |
| L2 | 182 | 146 |
| L3 | 92 | 121 |

**Total consolidated findings: 240**


### Reports Not Included in Consolidation

1 per-section report(s) could not be automatically extracted into this consolidated report. 
Findings from these sections are available in the original per-section reports:

| Section | Per-Section Report |
|---------|-------------------|
| 16.3.4 | [ASVS/reports/steve/v3/d0aa7e9/logging_and_monitoring/16.3.4.md](https://github.com/apache/tooling-agents/blob/main/ASVS/reports/steve/v3/d0aa7e9/logging_and_monitoring/16.3.4.md) |

*End of Consolidated Security Audit Report*