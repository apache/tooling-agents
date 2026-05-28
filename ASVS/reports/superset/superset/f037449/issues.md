# Security Issues

*16 actionable finding(s). 5 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---

## Issue: FINDING-001 - SSH Tunnel Credentials Returned Unmasked in Database Read Endpoints

**Labels:** bug, security, priority:high

**Description:**

### Summary
SSH tunnel credentials (passwords, private keys, and passphrases) are exposed in plaintext through database read API endpoints (`get_connection()` and `get()`) to any authenticated user with Database read permission.

### Details
In `superset/databases/api.py`, the `get_connection()` and `get()` endpoints return SSH tunnel data via `database.ssh_tunnel.data` without applying `mask_password_info()`. While write endpoints (`post()` and `put()`) correctly mask these credentials, read endpoints do not, creating an inconsistent security posture.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS:** 15.3.1 (Level 1)

Any authenticated user with Database read permission can retrieve unmasked SSH tunnel credentials, which could be used to compromise the underlying infrastructure.

### Remediation
Apply `mask_password_info()` to SSH tunnel data in both `get_connection()` and `get()` endpoints in `superset/databases/api.py`, consistent with the masking already applied in `post()` and `put()`.

### Acceptance Criteria
- [ ] `mask_password_info()` applied to SSH tunnel data in `get_connection()` endpoint
- [ ] `mask_password_info()` applied to SSH tunnel data in `get()` endpoint
- [ ] Test added verifying credentials are masked in read responses
- [ ] Test added verifying write endpoints continue to mask credentials

### References
- Related findings: FINDING-003, FINDING-004, FINDING-010, FINDING-015
- Source: 15.3.1.md

### Priority
**High** - Credentials exposed to unauthorized users

---

## Issue: FINDING-002 - Encryption engine not explicitly set to AES-GCM; defaults to unauthenticated AES-CBC

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The encryption adapter defaults to AES-CBC without authenticated encryption, allowing potential bit-flipping attacks on encrypted credentials stored in the database.

### Details
`SQLAlchemyUtilsAdapter.create()` in `superset/utils/encrypt.py` does not specify an engine parameter, causing sqlalchemy-utils to default to `AesEngine` (AES-CBC). An attacker with database write access could perform bit-flipping attacks on AES-CBC ciphertext to silently modify encrypted credentials (database passwords, SSH tunnel credentials, OAuth2 tokens) without detection.

**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)  
**ASVS:** 11.3.2 (Level 1)

**Affected files:**
- `superset/utils/encrypt.py`
- `superset/models/core.py`
- `superset/databases/ssh_tunnel/models.py`

### Remediation
Explicitly specify `engine=AesGcmEngine` when creating `EncryptedType` instances in `SQLAlchemyUtilsAdapter.create()` and in `SecretsMigrator._re_encrypt_row()`. Run a data migration via `SecretsMigrator` to re-encrypt existing data under the new authenticated encryption mode.

### Acceptance Criteria
- [ ] `AesGcmEngine` explicitly specified in `SQLAlchemyUtilsAdapter.create()`
- [ ] `AesGcmEngine` explicitly specified in `SecretsMigrator._re_encrypt_row()`
- [ ] Data migration script created to re-encrypt existing credentials
- [ ] Test added verifying AES-GCM is used for new encrypted fields
- [ ] Test added verifying tamper detection works

### References
- Source: 11.3.2.md

### Priority
**Medium** - Requires database write access to exploit

---

## Issue: FINDING-003 - SSH Tunnel Data Appended Outside Schema Serialization

**Labels:** bug, security, priority:medium

**Description:**

### Summary
SSH tunnel data is returned via the raw `.data` property, bypassing Marshmallow schema serialization and potentially exposing internal model fields beyond the declared API contract.

### Details
In `get_connection()` and `get()` endpoints in `superset/databases/api.py`, SSH tunnel data is appended to responses using the raw `.data` property instead of proper schema serialization. This returns all SSH tunnel model attributes without field projection, potentially exposing internal fields (IDs, foreign keys, audit columns) that should not be part of the public API contract.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS:** 15.3.1 (Level 1)

### Remediation
Create a dedicated Marshmallow schema (`SSHTunnelResponseSchema`) for SSH tunnel responses that:
- Declares only allowed public fields
- Always masks credentials
- Replaces the raw `.data` property access

### Acceptance Criteria
- [ ] `SSHTunnelResponseSchema` created with explicit field declarations
- [ ] Schema includes credential masking
- [ ] `get_connection()` endpoint uses new schema
- [ ] `get()` endpoint uses new schema
- [ ] Test added verifying only declared fields are returned
- [ ] Test added verifying internal fields are not exposed

### References
- Related findings: FINDING-001, FINDING-004, FINDING-010, FINDING-015
- Source: 15.3.1.md

### Priority
**Medium** - Information disclosure of internal model structure

---

## Issue: FINDING-004 - Schema bypass via `to_dict()` in `get_updated_since` endpoint

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The `get_updated_since` endpoint bypasses declared schema field projections by using `to_dict()`, potentially exposing all Query model fields instead of only the 27 declared fields.

### Details
The `get_updated_since` endpoint in `superset/queries/api.py` uses `q.to_dict()` to serialize Query objects, bypassing the declared `list_model_schema` (QuerySchema) and `list_columns` field projections. This returns all Query model fields rather than only the 27 fields declared in `list_columns`, potentially including internal tracking state, template parameters, extra JSON configuration, and foreign key references.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS:** 15.3.1 (Level 1)

### Remediation
Replace `[q.to_dict() for q in queries]` with `self.list_model_schema.dump(queries, many=True)` to honor the declared field contract.

### Acceptance Criteria
- [ ] `to_dict()` replaced with `self.list_model_schema.dump()` in `get_updated_since`
- [ ] Test added verifying only declared fields are returned
- [ ] Test added verifying internal fields are not exposed
- [ ] Backward compatibility verified for existing API consumers

### References
- Related findings: FINDING-001, FINDING-003, FINDING-010, FINDING-015
- Source: 15.3.1.md

### Priority
**Medium** - Information disclosure of internal query metadata

---

## Issue: FINDING-005 - Ownership check bypass in UpdateChartCommand via query_context_generation flag

**Labels:** bug, security, priority:medium

**Description:**

### Summary
Non-owner users can modify chart `query_context` by setting `query_context_generation=true`, bypassing ownership validation intended only for report workers.

### Details
The `UpdateChartCommand.validate()` method in `superset/commands/chart/update.py` skips the `security_manager.raise_for_ownership()` check when the update contains only `query_context` and `query_context_generation=True`. This bypass is designed for report workers but lacks verification that the caller is actually a report worker or service account.

**ASVS:** 2.3.1 (Level 1)

**Attack path:**
1. Authenticated user with chart read access (not owner)
2. PUT `/api/v1/chart/{id}` with `{"query_context": "...", "query_context_generation": true}`
3. Ownership check skipped
4. Chart's query_context modified by non-owner

The query_context defines default query parameters used for report generation and chart rendering.

### Remediation
Verify caller has report worker permission or is an owner in the query_context_generation bypass path:

```python
if not is_query_context_update(self._properties):
    try:
        security_manager.raise_for_ownership(self._model)
else:
    try:
        if not security_manager.can_access("can_write", "ReportSchedule") and not security_manager.is_owner(self._model):
            raise ChartForbiddenError()
    except SupersetSecurityException as ex:
        raise ChartForbiddenError() from ex
```

### Acceptance Criteria
- [ ] Ownership or report worker check added to query_context bypass path
- [ ] Test added verifying non-owners cannot update query_context
- [ ] Test added verifying report workers can update query_context
- [ ] Test added verifying owners can update query_context

### References
- Source: 2.3.1.md

### Priority
**Medium** - Requires authentication and chart read access

---

## Issue: FINDING-006 - Chart Update Command Bypasses Ownership Check for Query Context Updates Without Role Restriction

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The `is_query_context_update()` function allows any authenticated user with read access to modify a chart's `query_context` without ownership validation, constituting both function-level access control bypass and broken object level authorization.

### Details
The `is_query_context_update()` function in `superset/commands/chart/update.py` (lines 54-56) allows any authenticated user with read access to a chart (via datasource permission) to modify its `query_context` and `query_context_generation` fields without ownership validation. The ownership check (`security_manager.raise_for_ownership()`) is entirely skipped when the PUT payload contains only these two fields.

**CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)  
**ASVS:** 8.2.1, 8.2.2 (Level 1)

A Gamma user with datasource access to a chart's underlying dataset can write to chart objects they do not own, modifying what data is displayed to other users.

### Remediation
Restrict the ownership bypass to service accounts or internal callers by:
- Checking for a specific role or internal flag
- Adding a dedicated permission check such as `can_write_query_context`
- Verifying the caller is a report worker before skipping ownership validation
- Implementing a separate data-level authorization check for the specific chart object

### Acceptance Criteria
- [ ] Role or permission check added before ownership bypass
- [ ] Test added verifying Gamma users cannot bypass ownership
- [ ] Test added verifying authorized service accounts can update query_context
- [ ] Test added verifying owners can update query_context
- [ ] Documentation updated explaining authorized callers

### References
- Source: 8.2.1.md, 8.2.2.md

### Priority
**Medium** - Authorization bypass requiring authentication

---

## Issue: FINDING-007 - Missing HTML attribute encoding for URL in Dashboard.dashboard_link

**Labels:** bug, security, priority:low

**Description:**

### Summary
User-controlled Dashboard slug is inserted unescaped into HTML href attribute, enabling potential stored XSS in FAB admin list views.

### Details
In `superset/models/dashboard.py`, the `dashboard_link()` method inserts user-controlled `Dashboard.slug` unescaped into an HTML href attribute. An Alpha-role user (untrusted) can set the slug value; if an Admin visits the legacy FAB list view, session theft or privilege escalation is possible.

**CWE:** CWE-79 (Cross-site Scripting)  
**ASVS:** 1.2.1 (Level 1)

### Remediation
Apply `escape()` to `self.url` in `dashboard_link()` to match the pattern established in `SqlaTable.link`:

```python
from markupsafe import escape
# In dashboard_link():
url = escape(self.url)
```

### Acceptance Criteria
- [ ] `escape()` applied to URL in `dashboard_link()`
- [ ] Test added with XSS payload in slug
- [ ] Test verifies escaped output in rendered HTML
- [ ] Similar patterns reviewed in codebase

### References
- Related findings: FINDING-008, FINDING-009, FINDING-012, FINDING-013, FINDING-019
- Source: 1.2.1.md

### Priority
**Low** - Requires Admin to visit legacy view; limited scope

---

## Issue: FINDING-008 - Missing HTML encoding in Slice.icons property

**Labels:** bug, security, priority:low

**Description:**

### Summary
Database-stored datasource name is inserted unescaped into HTML title attribute in the `Slice.icons` property.

### Details
In `superset/models/slice.py`, the `icons` property inserts datasource name and edit URL into HTML title attributes without escaping. An Alpha-role user who can configure dataset names could inject HTML, though exploitability is very limited and rendering context in user-facing views has not been confirmed.

**CWE:** CWE-79 (Cross-site Scripting)  
**ASVS:** 1.2.1 (Level 1)

### Remediation
Apply `escape()` to `self.datasource` and `self.datasource_edit_url` before insertion into HTML attributes:

```python
from markupsafe import escape
# In icons property:
datasource = escape(self.datasource)
url = escape(self.datasource_edit_url)
```

### Acceptance Criteria
- [ ] `escape()` applied to datasource name in `icons` property
- [ ] `escape()` applied to datasource URL in `icons` property
- [ ] Test added with HTML injection in datasource name
- [ ] Test verifies escaped output

### References
- Related findings: FINDING-007, FINDING-009, FINDING-012, FINDING-013, FINDING-019
- Source: 1.2.1.md

### Priority
**Low** - Very limited exploitability; rendering context unclear

---

## Issue: FINDING-009 - Email error template interpolates unsanitized text into HTML context

**Labels:** bug, security, priority:low

**Description:**

### Summary
Report execution error messages are interpolated into HTML email body without sanitization, while normal content properly applies `nh3.clean()`.

### Details
In `superset/reports/notifications/email.py`, the `_error_template()` function interpolates error messages into HTML email body without `nh3` sanitization, while the normal content path applies `nh3.clean()`. An authenticated user with report/chart creation privileges can trigger database errors containing controlled content (e.g., crafted table names), resulting in HTML injection in notification emails sent to all configured recipients.

**CWE:** CWE-79 (Cross-site Scripting)  
**ASVS:** 1.2.1 (Level 1)

### Remediation
Apply `nh3.clean(text, tags=set(), attributes={})` to the error text before interpolation, matching the security posture of the normal content path:

```python
import nh3

def _error_template(self, text: str) -> str:
    safe_text = nh3.clean(text, tags=set(), attributes={})
    return f"<html><body>{safe_text}</body></html>"
```

### Acceptance Criteria
- [ ] `nh3.clean()` applied to error text in `_error_template()`
- [ ] Test added with HTML injection in error message
- [ ] Test verifies sanitized output in email body
- [ ] Consistency verified with normal content path sanitization

### References
- Related findings: FINDING-007, FINDING-008, FINDING-012, FINDING-013, FINDING-019
- Source: 1.2.1.md

### Priority
**Low** - Limited to email context; modern clients block scripts

---

## Issue: FINDING-010 - `registration_hash` exposed in user registration list endpoint

**Labels:** bug, security, priority:low

**Description:**

### Summary
The user registration API exposes `registration_hash` values, which function as bearer tokens for account activation, creating secondary exposure risk through caches and logs.

### Details
The `UserRegistrationsRestAPI` class in `superset/security/api.py` explicitly includes `registration_hash` in `list_columns`. This hash functions as a bearer token for account activation without email verification. Its exposure in API responses creates secondary exposure risk through response caches, proxy logs, and observability pipelines.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS:** 15.3.1 (Level 1)

### Remediation
Remove `registration_hash` from `list_columns` in `UserRegistrationsRestAPI`. If needed for admin approval flows, provide it only on a dedicated single-item endpoint with audit logging.

### Acceptance Criteria
- [ ] `registration_hash` removed from `list_columns`
- [ ] Alternative admin approval mechanism implemented if needed
- [ ] Test added verifying hash not exposed in list endpoint
- [ ] Audit logging added if hash provided via dedicated endpoint

### References
- Related findings: FINDING-001, FINDING-003, FINDING-004, FINDING-015
- Source: 15.3.1.md

### Priority
**Low** - Requires admin access; secondary exposure risk

---

## Issue: FINDING-011 - Inconsistent JSON validation documentation between ChartPostSchema and ChartPutSchema

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `query_context` field has JSON validation in `ChartPostSchema` but not in `ChartPutSchema`, creating inconsistent validation rules and potential for invalid JSON storage.

### Details
In `superset/charts/schemas.py`, the `query_context` field has a `validate_json` validator in `ChartPostSchema` but not in `ChartPutSchema`. This inconsistency makes it unclear whether `query_context` is expected to be valid JSON on updates. Invalid JSON stored in the database could cause parse errors on subsequent reads and potential chart rendering failures.

**ASVS:** 2.1.1 (Level 1)

An authenticated user with chart write access can store invalid JSON, affecting availability.

### Remediation
Add `validate_json` to `ChartPutSchema` to maintain consistency:

```python
query_context = fields.String(
    metadata={"description": query_context_description},
    allow_none=True,
    validate=utils.validate_json,
)
```

### Acceptance Criteria
- [ ] `validate_json` added to `query_context` in `ChartPutSchema`
- [ ] Test added verifying invalid JSON rejected on PUT
- [ ] Test added verifying valid JSON accepted on PUT
- [ ] Consistency verified between POST and PUT validation

### References
- Source: 2.1.1.md

### Priority
**Low** - Availability impact; requires write access

---

## Issue: FINDING-012 - Error text inserted into email HTML without HTML escaping in `_error_template()`

**Labels:** bug, security, priority:low

**Description:**

### Summary
Exception messages flow into email HTML without sanitization while normal content is properly sanitized with `nh3.clean()`, creating an inconsistent security posture.

### Details
In `superset/reports/notifications/email.py` (lines 82-91), exception messages flow through `self._content.text` to `_error_template(text=...)` where raw string interpolation occurs into HTML body without sanitization. The same class properly sanitizes `self._content.description` with `nh3.clean()` but does NOT sanitize `self._content.text`.

**CWE:** CWE-79 (Cross-site Scripting)  
**ASVS:** 3.2.2 (Level 1)

An authenticated user who can create reports/alerts referencing content that triggers errors containing attacker-controlled strings (e.g., SQL query error messages) can inject HTML into email bodies. Modern email clients block script execution, limiting impact to phishing via injected HTML content.

### Remediation
Apply `nh3.clean(text, tags=set())` to sanitize error text before HTML interpolation:

```python
import nh3

def _error_template(self, text: str) -> str:
    safe_text = nh3.clean(text, tags=set())
    # Use safe_text in HTML interpolation
```

### Acceptance Criteria
- [ ] `nh3.clean()` applied to error text before HTML interpolation
- [ ] Test added with HTML injection in error message
- [ ] Test verifies sanitized output
- [ ] Pattern aligned with existing `description` sanitization

### References
- Related findings: FINDING-007, FINDING-008, FINDING-009, FINDING-013, FINDING-019
- Source: 3.2.2.md

### Priority
**Low** - Email context; limited to phishing impact

---

## Issue: FINDING-013 - Dashboard slug inserted into href attribute without HTML escaping in `dashboard_link()`

**Labels:** bug, security, priority:low

**Description:**

### Summary
User-provided dashboard slug is inserted into href attribute without HTML escaping and wrapped in `Markup()`, bypassing autoescaping and enabling potential stored XSS.

### Details
In `superset/models/dashboard.py` (lines 163-165), user-provided `slug` flows through `self.url` into f-string interpolation within `href=""` attribute, then wrapped in `Markup()` (bypassing autoescaping) and rendered in Flask-AppBuilder list views. The code applies `markupsafe.escape()` to the title but NOT to the URL component.

**CWE:** CWE-79 (Cross-site Scripting)  
**ASVS:** 3.2.2 (Level 1)

An authenticated user with dashboard creation/edit permissions (Alpha role or higher) can set a malicious slug. If API-layer slug validation is bypassed, stored XSS in Flask-AppBuilder admin list views via attribute injection is possible (e.g., slug containing `"onmouseover=alert(1) x="`).

### Remediation
Apply `markupsafe.escape()` to URL values interpolated into `href` attributes:

```python
from markupsafe import escape

url = escape(self.url)
# Use url in f-string
```

This provides defense-in-depth against slug validation bypass.

### Acceptance Criteria
- [ ] `escape()` applied to URL in `dashboard_link()`
- [ ] Test added with attribute injection payload in slug
- [ ] Test verifies escaped output
- [ ] Defense-in-depth verified against validation bypass

### References
- Related findings: FINDING-007, FINDING-008, FINDING-009, FINDING-012, FINDING-019
- Source: 3.2.2.md

### Priority
**Low** - Requires validation bypass; limited by CSP

---

## Issue: FINDING-014 - No explicit Content-Type or custom header enforcement visible for CSRF-exempt endpoints

**Labels:** bug, security, priority:low

**Description:**

### Summary
CSRF-exempt endpoints rely on CORS preflight for protection but lack explicit Content-Type validation or custom header requirements to guarantee preflight occurs.

### Details
The application (per `superset/config.py` lines 244-252) relies on CORS preflight to prevent unauthorized cross-origin requests to CSRF-exempt endpoints. For this reliance to be effective, requests must trigger CORS preflight by using:
- Non-safelisted Content-Type (not application/x-www-form-urlencoded, multipart/form-data, or text/plain)
- Non-safelisted header
- Non-simple method

There is no visible server-side Content-Type validation or requirement for a custom header on CSRF-exempt endpoints.

**ASVS:** 3.5.2 (Level 1)

The primary control (`SESSION_COOKIE_SAMESITE = "Lax"`) effectively prevents exploitation in modern browsers, making this a defense-in-depth issue.

### Remediation
For endpoints claiming CORS preflight protection, add explicit validation:

**Option 1:** Validate Content-Type on CSRF-exempt endpoints using a decorator ensuring `application/json` or other non-safelisted type.

**Option 2:** Require a custom header (e.g., `X-Requested-With`) which definitively triggers preflight.

### Acceptance Criteria
- [ ] Content-Type validation or custom header requirement added
- [ ] Test added verifying simple requests without proper headers are rejected
- [ ] Test added verifying proper requests with correct headers succeed
- [ ] Documentation updated explaining CSRF protection strategy

### References
- Source: 3.5.2.md

### Priority
**Low** - Primary SameSite control is effective; defense-in-depth issue

---

## Issue: FINDING-015 - Registration activation hash exposed in admin API without masking

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `UserRegistrationsRestAPI` exposes `registration_hash` activation tokens in admin API responses, allowing token exposure via logs, caches, and compromised admin sessions.

### Details
The `UserRegistrationsRestAPI` in `superset/security/api.py` exposes `registration_hash` in `list_columns`, making activation tokens visible in admin API responses. An attacker with access to API response data (via proxy logs, response caches, browser history, or admin session compromise) could use the registration hash to activate pending user accounts at `/register/activation/<hash>`, bypassing the intended email delivery channel.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS:** 6.4.1 (Level 1)

While admin-only, credential/secret material must be masked regardless of caller privilege per project policy.

### Remediation
Remove `registration_hash` from `UserRegistrationsRestAPI.list_columns` or mask the value. Provide a dedicated 'resend activation email' admin action instead of exposing the raw hash.

### Acceptance Criteria
- [ ] `registration_hash` removed from `list_columns` or masked
- [ ] Alternative 'resend activation email' action implemented
- [ ] Test added verifying hash not exposed in API responses
- [ ] Audit logging added for activation actions

### References
- Related findings: FINDING-001, FINDING-003, FINDING-004, FINDING-010
- Source: 6.4.1.md

### Priority
**Low** - Admin-only; secondary exposure risk

---

## Issue: FINDING-016 - Async query JWT tokens lack `exp` claim — no inherent expiration

**Labels:** bug, security, priority:low

**Description:**

### Summary
Async query JWT tokens are created without an `exp` (expiration) claim, giving them unlimited cryptographic validity and allowing indefinite access if stolen.

### Details
In `superset/async_events/async_query_manager.py`, async query JWT tokens are created without an `exp` claim. PyJWT only checks expiration if the claim is present, so these tokens have unlimited cryptographic validity. An attacker with a stolen async query cookie can access the user's async event channel indefinitely.

**CWE:** CWE-613 (Insufficient Session Expiration)  
**ASVS:** 9.2.1 (Level 1)

Impact is limited to async query event metadata (job status, result URLs) rather than direct data access. Exploitation requires obtaining the cookie value via a secondary vulnerability.

### Remediation
Add an `exp` claim to async query JWT tokens with a configurable TTL:

```python
# Add configuration
GLOBAL_ASYNC_QUERIES_JWT_EXPIRY_SECONDS = 3600  # default 1 hour

# In token creation:
payload = {
    "channel": channel_id,
    "exp": datetime.utcnow() + timedelta(seconds=config["GLOBAL_ASYNC_QUERIES_JWT_EXPIRY_SECONDS"])
}
```

PyJWT automatically validates `exp` during `jwt.decode()` when the claim is present.

### Acceptance Criteria
- [ ] `exp` claim added to async query JWT token creation
- [ ] Configuration option added for TTL
- [ ] Test added verifying token expires after TTL
- [ ] Test added verifying expired tokens are rejected
- [ ] Documentation updated explaining token lifetime

### References
- Source: 9.2.1.md

### Priority
**Low** - Requires cookie theft; limited to event metadata access