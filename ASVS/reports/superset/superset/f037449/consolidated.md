# Security Audit Consolidated Report — apache/superset/superset

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | f037449 |
| Date | May 28, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 21 |
| Actionable Issues | 16 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 16 actionable items.*

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 5 |
| Low | 10 |
| Info | 5 |

### ASVS Level Coverage

This audit assessed the repository against ASVS Level 1 requirements across 15 security domains including authentication controls, authorization enforcement, input validation, sensitive data exposure, cryptographic controls, and browser security controls. All 21 findings map to L1 verification requirements, confirming broad coverage of the baseline assurance level.

### Top 5 Risks

1. **SSH Tunnel Credentials Returned Unmasked in Database Read Endpoints** [High] — Database API endpoints return SSH tunnel passwords and private keys in plaintext within JSON responses, enabling credential harvesting by any user with database read permissions.
2. **Encryption engine not explicitly set to AES-GCM; defaults to unauthenticated AES-CBC** [Medium] — The encrypted_field_factory does not enforce authenticated encryption, leaving stored secrets vulnerable to padding oracle or ciphertext manipulation attacks.
3. **SSH Tunnel Data Appended Outside Schema Serialization** [Medium] — SSH tunnel connection details are manually appended to API responses after Marshmallow schema serialization, bypassing field-level filtering and potentially exposing sensitive attributes.
4. **Schema bypass via `to_dict()` in `get_updated_since` endpoint** [Medium] — The endpoint serializes model objects using `to_dict()` instead of the Marshmallow schema, leaking fields that should be filtered from API responses.
5. **Ownership check bypass in UpdateChartCommand via query_context_generation flag** [Medium] — The chart update command skips ownership validation when the update is flagged as a query context generation operation, allowing unauthorized users to modify chart objects.

### Positive Controls Observed

- **OAuth2/OIDC hardening**: Superset acts exclusively as an OAuth Client with no Authorization Server surface. Authorization Code flow with PKCE is the only supported grant type; PKCE code_verifiers are cleaned from the key-value store after use; state JWTs expire after 5 minutes; refresh token rotation is supported with distributed locking to prevent race conditions.
- **TLS enforcement**: Python runtime `ssl.create_default_context()` enforces TLS 1.2+ minimum for all outbound client connections (redis-py, requests). WSS enforcement is delegated to the reverse proxy layer with JWT-authenticated channels as defense-in-depth.
- **Input validation**: All chart API endpoints enforce server-side validation via Marshmallow schemas (ChartPostSchema, ChartPutSchema, ChartDataQueryObjectSchema) before business logic execution.
- **Browser security — CSP**: All inline scripts in the SPA template include nonce attributes enabling strict Content Security Policy enforcement at the infrastructure layer. Jinja2 autoescaping is enabled for standard template expressions.
- **Browser security — HTML sanitization**: The codebase standardizes on nh3 (Rust-based) for HTML sanitization across all layers, including multi-pass entity decoding with iteration limits, explicit `&amp;`-only restore after sanitization, and `df.to_html(escape=True)` for tabular email content. SVG content is sanitized by stripping scripts, event handlers, iframes, objects, and embeds.
- **Browser security — output encoding**: Consistent `escape()` + `Markup()` pattern is used for text content in model link helpers. The MCP service uses `nh3.clean()` with an empty tag set to ensure complete HTML stripping.
- **Cookie security**: SESSION_COOKIE_HTTPONLY defaults to True; SESSION_COOKIE_SAMESITE defaults to Lax; configuration knobs exist for Secure flag delegation to infrastructure/proxy layers.
- **CORS hardening**: Fixed origin allowlist (only two map tile server origins by default); no wildcard `Access-Control-Allow-Origin: *`; `supports_credentials` defaults to False; CSP `connect-src` directive aligns with CORS origins.
- **CSRF protection**: WTF_CSRF_ENABLED is True globally; dedicated `/api/v1/security/csrf_token/` endpoint (authentication-gated) for SPA use; only 6 specific endpoints are exempt (API data fetching, SAML callbacks); embedded view validates `request.referrer` against a configured allowlist.
- **Security headers**: Flask-Talisman enabled by default with configurable HSTS support; OVERRIDE_HTTP_HEADERS mechanism available for header injection; no hardcoded HSTS-undermining values present.
- **Redirect URI safety**: Configurable `DATABASE_OAUTH2_REDIRECT_URI` is not dynamically controlled by user input.

---

## 3. Findings

### 3.2 High

#### FINDING-001: SSH Tunnel Credentials Returned Unmasked in Database Read Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | superset/databases/api.py |
| **Source Reports** | 15.3.1.md |
| **Related** | FINDING-003, FINDING-004, FINDING-010, FINDING-015 |

**Description:**

In `get_connection()` and `get()` endpoints, SSH tunnel data is returned via `database.ssh_tunnel.data` without applying `mask_password_info()`. Write endpoints (post/put) correctly mask credentials, but read endpoints do not. This exposes SSH tunnel passwords, private keys, and private key passphrases to any authenticated user with Database read permission.

**Remediation:**

Apply `mask_password_info()` to SSH tunnel data in both `get_connection()` and `get()` endpoints in `superset/databases/api.py`, consistent with the masking already applied in `post()` and `put()`.

---

### 3.3 Medium

#### FINDING-002: Encryption engine not explicitly set to AES-GCM; defaults to unauthenticated AES-CBC

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 11.3.2 |
| **File(s)** | superset/utils/encrypt.py, superset/models/core.py, superset/databases/ssh_tunnel/models.py |
| **Source Report(s)** | 11.3.2.md |
| **Related** | None |

**Description:**

SQLAlchemyUtilsAdapter.create() does not specify an engine parameter, causing sqlalchemy-utils to default to AesEngine (AES-CBC without authenticated encryption). An attacker with database write access could perform bit-flipping on AES-CBC ciphertext to silently modify encrypted credentials (database passwords, SSH tunnel credentials, OAuth2 tokens) without detection.

**Remediation:**

Explicitly specify engine=AesGcmEngine when creating EncryptedType instances in SQLAlchemyUtilsAdapter.create() and in SecretsMigrator._re_encrypt_row(). Run a data migration via SecretsMigrator to re-encrypt existing data under the new mode.

---

#### FINDING-003: SSH Tunnel Data Appended Outside Schema Serialization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 15.3.1 |
| **File(s)** | superset/databases/api.py |
| **Source Report(s)** | 15.3.1.md |
| **Related** | FINDING-001, FINDING-004, FINDING-010, FINDING-015 |

**Description:**

In `get_connection()` and `get()` endpoints, SSH tunnel data is appended to the response via the raw `.data` property, bypassing Marshmallow schema serialization. This returns all SSH tunnel model attributes without field projection, potentially exposing internal fields (IDs, foreign keys, audit columns) beyond the declared API contract.

**Remediation:**

Create a dedicated Marshmallow schema (SSHTunnelResponseSchema) for SSH tunnel responses that declares allowed fields and always masks credentials, replacing the raw `.data` property access.

---

#### FINDING-004: Schema bypass via `to_dict()` in `get_updated_since` endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 15.3.1 |
| **File(s)** | superset/queries/api.py |
| **Source Report(s)** | 15.3.1.md |
| **Related** | FINDING-001, FINDING-003, FINDING-010, FINDING-015 |

**Description:**

The `get_updated_since` endpoint in `superset/queries/api.py` uses `q.to_dict()` to serialize Query objects, bypassing the declared `list_model_schema` (QuerySchema) and `list_columns` field projections. This returns all Query model fields rather than only the 27 fields declared in `list_columns`, potentially including internal tracking state, template parameters, extra JSON configuration, and foreign key references.

**Remediation:**

Replace `[q.to_dict() for q in queries]` with `self.list_model_schema.dump(queries, many=True)` to honor the declared field contract.

---

#### FINDING-005: Ownership check bypass in UpdateChartCommand via query_context_generation flag

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 2.3.1 |
| **File(s)** | superset/commands/chart/update.py |
| **Source Report(s)** | 2.3.1.md |
| **Related** | None |

**Description:**

The `UpdateChartCommand.validate()` method skips the `security_manager.raise_for_ownership()` check when the update contains only `query_context` and `query_context_generation=True`. This is designed for report workers but there is no verification that the caller is actually a report worker or service account. Any authenticated user who can access the chart (via ChartFilter) can update the chart's `query_context` without being an owner. Data flow: Authenticated user → PUT /api/v1/chart/{id} with {"query_context": "...", "query_context_generation": true} → UpdateChartCommand.validate() → ownership check skipped → ChartDAO.update() modifies chart. Attacker capability required: Authenticated user with chart read access (Gamma with dataset access, Alpha, or custom role) who is NOT an owner of the target chart. Impact on success: Non-owner can modify the stored `query_context` of any chart they can access. The query_context defines default query parameters used for report generation and chart rendering. Exploitability: Requires authentication and access to the chart via ChartFilter; straightforward exploitation via API

**Remediation:**

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

---

#### FINDING-006: Chart Update Command Bypasses Ownership Check for Query Context Updates Without Role Restriction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Section(s)** | 8.2.1, 8.2.2 |
| **File(s)** | superset/commands/chart/update.py |
| **Source Report(s)** | 8.2.1.md, 8.2.2.md |
| **Related** | None |

**Description:**

The `is_query_context_update()` function in `superset/commands/chart/update.py` (lines 54-56) allows any authenticated user with read access to a chart (via datasource permission) to modify its `query_context` and `query_context_generation` fields without ownership validation. The ownership check (`security_manager.raise_for_ownership()`) is entirely skipped when the PUT payload contains only these two fields. This constitutes both a function-level access control bypass (ASVS 8.2.1) and a broken object level authorization vulnerability (ASVS 8.2.2), as a Gamma user with datasource access to a chart's underlying dataset can write to chart objects they do not own. The ChartFilter allows read access, `is_query_context_update()` returns True, and the ownership check is skipped, enabling non-owners to modify what data is displayed to other users.

**Remediation:**

Restrict the ownership bypass to service accounts or internal callers by checking for a specific role or internal flag. Add a dedicated permission check such as `can_write_query_context` or verify the caller is a report worker before skipping ownership validation. Alternatively, implement a separate data-level authorization check that verifies the caller has write permission to the specific chart object even for query context updates.

### 3.4 Low

#### FINDING-007: Missing HTML attribute encoding for URL in Dashboard.dashboard_link

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | superset/models/dashboard.py |
| **Source Report(s)** | 1.2.1.md |
| **Related Finding(s)** | FINDING-008, FINDING-009, FINDING-012, FINDING-013, FINDING-019 |

**Description:**

User-controlled Dashboard.slug is inserted unescaped into HTML href attribute in dashboard_link(), enabling stored XSS in FAB admin list views. Alpha-role user (untrusted) can set slug value; if Admin visits legacy FAB list view, session theft or privilege escalation is possible.

**Remediation:**

Apply escape() to self.url in dashboard_link() to match the pattern established in SqlaTable.link.

---

#### FINDING-008: Missing HTML encoding in Slice.icons property

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | superset/models/slice.py |
| **Source Report(s)** | 1.2.1.md |
| **Related Finding(s)** | FINDING-007, FINDING-009, FINDING-012, FINDING-013, FINDING-019 |

**Description:**

Database-stored datasource name is inserted unescaped into HTML title attribute in Slice.icons property. Alpha-role user who can configure dataset names could inject HTML. Very limited exploitability — rendering context in user-facing views not confirmed.

**Remediation:**

Apply escape() to self.datasource and self.datasource_edit_url before insertion into HTML attributes.

---

#### FINDING-009: Email error template interpolates unsanitized text into HTML context

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | superset/reports/notifications/email.py |
| **Source Report(s)** | 1.2.1.md |
| **Related Finding(s)** | FINDING-007, FINDING-008, FINDING-012, FINDING-013, FINDING-019 |

**Description:**

Report execution error messages are interpolated into HTML email body without nh3 sanitization in _error_template(), while the normal content path applies nh3.clean(). Authenticated user with report/chart creation privileges can trigger database errors containing controlled content (e.g., crafted table names), resulting in HTML injection in notification emails sent to all configured recipients.

**Remediation:**

Apply nh3.clean(text, tags=set(), attributes={}) to the error text before interpolation, matching the security posture of the normal content path.

---

#### FINDING-010: `registration_hash` exposed in user registration list endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 15.3.1 |
| **File(s)** | superset/security/api.py |
| **Source Report(s)** | 15.3.1.md |
| **Related Finding(s)** | FINDING-001, FINDING-003, FINDING-004, FINDING-015 |

**Description:**

The `UserRegistrationsRestAPI` class explicitly includes `registration_hash` in `list_columns`. This hash functions as a bearer token for account activation without email verification. Per the credential/token carve-out, its exposure in API responses creates secondary exposure risk through response caches, proxy logs, and observability pipelines.

**Remediation:**

Remove `registration_hash` from `list_columns` in `UserRegistrationsRestAPI`. If needed for admin approval flows, provide it only on a dedicated single-item endpoint with audit logging.

---

#### FINDING-011: Inconsistent JSON validation documentation between ChartPostSchema and ChartPutSchema

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.1.1 |
| **File(s)** | superset/charts/schemas.py |
| **Source Report(s)** | 2.1.1.md |
| **Related Finding(s)** | - |

**Description:**

The `query_context` field has a `validate_json` validator in `ChartPostSchema` but not in `ChartPutSchema`, creating an inconsistency in documented validation rules. This makes it unclear whether `query_context` is expected to be valid JSON. Data flow: User input → API layer → ChartPutSchema deserialization → stored without JSON format validation. Attacker capability required: Authenticated user with chart write access. Impact on success: Invalid JSON stored in database, causing parse errors on subsequent reads, potential chart rendering failure (availability). Exploitability: Trivial in default deployment for any user with write access

**Remediation:**

In ChartPutSchema, add validate_json to maintain consistency: query_context = fields.String(metadata={"description": query_context_description}, allow_none=True, validate=utils.validate_json,)

---

#### FINDING-012: Error text inserted into email HTML without HTML escaping in `_error_template()`

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 3.2.2 |
| **File(s)** | superset/reports/notifications/email.py:82-91 |
| **Source Report(s)** | 3.2.2.md |
| **Related Finding(s)** | FINDING-007, FINDING-008, FINDING-009, FINDING-013, FINDING-019 |

**Description:**

Exception message (potentially containing user input from failed SQL/chart) flows through `self._content.text` to `_error_template(text=...)` where it undergoes raw string interpolation into HTML body without sanitization. The same class properly sanitizes `self._content.description` with `nh3.clean()` (line ~100) but does NOT sanitize `self._content.text` before HTML interpolation. This inconsistency creates a gap. Attacker capability required: Authenticated user who can create a report/alert referencing content that triggers an error containing attacker-controlled strings (e.g., SQL query that produces an error message including the query text, or a chart name containing HTML). Impact: HTML injection in email bodies sent to report recipients. Modern email clients block script execution, limiting impact to phishing via injected HTML content (fake links, misleading content).

**Remediation:**

Apply `nh3.clean(text, tags=set())` to sanitize error text before HTML interpolation in `_error_template()`. Import nh3 and replace the text parameter usage with `safe_text = nh3.clean(text, tags=set())` before string interpolation. This aligns with the existing pattern used for `description` sanitization in the same class.

---

#### FINDING-013: Dashboard slug inserted into href attribute without HTML escaping in `dashboard_link()`

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 3.2.2 |
| **File(s)** | superset/models/dashboard.py:163-165 |
| **Source Report(s)** | 3.2.2.md |
| **Related Finding(s)** | FINDING-007, FINDING-008, FINDING-009, FINDING-012, FINDING-019 |

**Description:**

User-provided `slug` (String(255) column) flows through `self.url` property into f-string interpolation within `href=""` attribute, then wrapped in `Markup()` (bypassing autoescaping) and rendered in Flask-AppBuilder list view via `@renders` decorator. The code applies `markupsafe.escape()` to the title but NOT to the URL component (Gap type: Type B — escape control EXISTS but NOT CALLED for the URL component). Attacker capability required: Authenticated user with dashboard creation/edit permissions (Alpha role or higher) who can set a dashboard slug. The slug is typically validated at the API layer to be URL-safe, but the model-level code does not enforce this. Impact: If API-layer slug validation is bypassed, stored XSS in Flask-AppBuilder admin list views via attribute injection (e.g., slug containing `"onmouseover=alert(1) x="`). Impact limited by CSP at reverse proxy and the fact that FAB admin views are typically restricted to admin users.

**Remediation:**

Apply `markupsafe.escape()` to URL values interpolated into `href` attributes when constructing `Markup` objects. Modify the code to: `url = escape(self.url)` then use `url` in the f-string. This provides defense-in-depth against slug validation bypass.

---

#### FINDING-014: No explicit Content-Type or custom header enforcement visible for CSRF-exempt endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.5.2 |
| **File(s)** | superset/config.py:244-252 |
| **Source Report(s)** | 3.5.2.md |
| **Related Finding(s)** | - |

**Description:**

The domain context states "The CORS preflight mechanism is used to prevent unauthorized cross-origin requests to sensitive endpoints." For this reliance to be effective, requests to CSRF-exempt endpoints MUST trigger CORS preflight. A request triggers preflight only when it uses a non-safelisted Content-Type (not application/x-www-form-urlencoded, multipart/form-data, or text/plain), a non-safelisted header, or a non-simple method. From the code provided, there is no visible server-side Content-Type validation or requirement for a custom non-safelisted header on CSRF-exempt endpoints. While Flask API endpoints typically parse JSON bodies (which would fail gracefully if form data is sent), there is no guarantee that all exempt endpoints reject non-JSON content types at the server level. The primary control (SESSION_COOKIE_SAMESITE = "Lax") effectively prevents exploitation in modern browsers because cross-site POST requests don't include session cookies. This makes the finding low-severity — the CORS preflight reliance is a secondary control, and the primary SameSite control is independently effective.

**Remediation:**

For endpoints that the application claims are protected by CORS preflight, add explicit Content-Type validation middleware or require a custom header. Option 1: Validate Content-Type on CSRF-exempt endpoints using a decorator that ensures request uses Content-Type that triggers CORS preflight (e.g., application/json). Option 2: Require a custom header (e.g., X-Requested-With) which is simpler and definitively triggers preflight.

---

#### FINDING-015: Registration activation hash exposed in admin API without masking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 6.4.1 |
| **File(s)** | superset/security/api.py |
| **Source Report(s)** | 6.4.1.md |
| **Related Finding(s)** | FINDING-001, FINDING-003, FINDING-004, FINDING-010 |

**Description:**

The `UserRegistrationsRestAPI` exposes `registration_hash` in `list_columns`, making activation tokens visible in admin API responses. An attacker with access to API response data (via proxy logs, response caches, browser history, or admin session compromise) could use the registration hash to activate pending user accounts at `/register/activation/<hash>`, bypassing the intended email delivery channel. While admin-only, credential/secret material must be masked regardless of caller privilege per project policy.

**Remediation:**

Remove `registration_hash` from `UserRegistrationsRestAPI.list_columns` or mask the value. Provide a dedicated 'resend activation email' admin action instead of exposing the raw hash.

---

#### FINDING-016: Async query JWT tokens lack `exp` claim — no inherent expiration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 9.2.1 |
| **File(s)** | superset/async_events/async_query_manager.py |
| **Source Report(s)** | 9.2.1.md |
| **Related Finding(s)** | - |

**Description:**

Async query JWT tokens are created without an `exp` claim. PyJWT only checks expiration if the claim is present, so these tokens have unlimited cryptographic validity. An attacker with a stolen async query cookie can access the user's async event channel indefinitely. Impact is limited to async query event metadata (job status, result URLs) rather than direct data access. Requires obtaining the cookie value via secondary vulnerability.

**Remediation:**

Add an `exp` claim to async query JWT tokens with a configurable TTL (e.g., `GLOBAL_ASYNC_QUERIES_JWT_EXPIRY_SECONDS`, default 3600). PyJWT automatically validates `exp` during `jwt.decode()` when the claim is present — no changes needed to the verification side.

### 3.5 Informational

#### FINDING-017: Missing URL encoding for table_name in SqlaTable.sql_url

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS Section(s)** | 1.2.2 |
| **File(s)** | superset/connectors/sqla/models.py |
| **Source Report(s)** | 1.2.2.md |
| **Related** | None |

**Description:**

DOWNGRADED from Low: table_name is concatenated into URL query parameter without URL encoding, causing URL malformation if table_name contains & or #. No direct security impact identified — URL malformation issue with no exploitable attack scenario. Does not enable protocol injection.

**Remediation:**

Apply urllib.parse.quote() to table_name in SqlaTable.sql_url for correctness.

---

#### FINDING-018: row_limit field lacks upper bound validation

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | superset/charts/schemas.py |
| **Source Report(s)** | 2.2.1.md |
| **Related** | None |

**Description:**

DOWNGRADED from Low to Informational. The `row_limit` field in `ChartDataQueryObjectSchema` validates only a minimum of 0 but has no maximum. However, config-level `ROW_LIMIT` and database timeouts cap actual execution downstream, reducing this to a schema-completeness gap rather than a demonstrable attack path. Data flow: User input (chart query) → ChartDataQueryObjectSchema → query execution → potentially unbounded result set. Attacker capability required: Authenticated user with chart/explore access. Impact on success: Excessive database load and memory consumption on Superset server; potential denial of service. Exploitability: Requires authentication; downstream database timeouts and config-level `ROW_LIMIT` may cap actual execution

**Remediation:**

Add a maximum value (e.g., from config["SQL_MAX_ROW"]) to the schema-level validation for `row_limit` to provide early feedback.

---

#### FINDING-019: `icons` property constructs HTML with unescaped interpolated values

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 3.2.2 |
| **File(s)** | superset/models/slice.py:195-204 |
| **Source Report(s)** | 3.2.2.md |
| **Related** | FINDING-007, FINDING-008, FINDING-009, FINDING-012, FINDING-013 |

**Description:**

The `icons` property in `superset/models/slice.py` interpolates `self.datasource` (SqlaTable object string representation) and `self.datasource_edit_url` into HTML without escaping. However, this property returns a plain `str` (not `Markup`), lacks the `@renders` decorator, and does not appear to be used in the modern React-based UI. In Jinja2 templates with autoescaping enabled, this string would be escaped on output. Classification: Informational — legacy code pattern with no demonstrated render path in current UI. The lack of `@renders` decorator and `Markup` return type means Flask-AppBuilder does not use it for automatic column rendering.

**Remediation:**

Consider deprecating this legacy property as part of the long-term migration away from Flask-AppBuilder HTML-constructing model properties toward API-only serialization with proper schema-based output encoding.

---

#### FINDING-020: CSRF-exempt endpoint list lacks documented justification for alternative protections

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 3.5.1 |
| **File(s)** | superset/config.py:244-252 |
| **Source Report(s)** | 3.5.1.md |
| **Related** | None |

**Description:**

Six endpoints are exempt from Flask-WTF CSRF token validation. The application relies on SESSION_COOKIE_SAMESITE = "Lax" (which prevents cross-site POST cookies from being sent) and CORS preflight (for JSON content-type endpoints) as alternative protections. This combination is effective in modern browsers. However: 1. The code lacks inline documentation explaining WHY each endpoint is exempt and WHICH alternative mechanism protects it. 2. For the SAML ACS endpoint (flask_appbuilder.security.views.acs), the exemption is correct because IdP-signed assertions provide authentication. 3. SameSite=Lax provides the effective protection, making this a documentation gap rather than a vulnerability.

**Remediation:**

Add inline comments documenting the rationale and alternative protection mechanism for each CSRF-exempt endpoint:

```python
WTF_CSRF_EXEMPT_LIST = [
    # Protected by: SameSite=Lax cookies + JSON Content-Type (triggers CORS preflight)
    "superset.charts.data.api.data",
    "superset.dashboards.api.cache_dashboard_screenshot",
    "superset.views.core.explore_json",
    "superset.views.core.log",
    "superset.views.datasource.views.samples",
    # Protected by: SAML assertion signature validation (cross-origin POST required by protocol)
    "flask_appbuilder.security.views.acs",
]
```

---

#### FINDING-021: Guest Tokens (Self-Contained JWTs) Lack Explicit Revocation Mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 7.4.1 |
| **File(s)** | superset/security/manager.py |
| **Source Report(s)** | 7.4.1.md |
| **Related** | None |

**Description:**

Guest tokens (self-contained JWTs with 5-minute expiry) have no server-side revocation mechanism. Feature is disabled by default, tokens are read-only with RLS, and 5-minute expiry limits exposure. DOWNGRADED from Low to Informational per hardening_vs_vulnerability_classification.md: no concrete demonstrable attack scenario with meaningful impact in default deployment posture.

**Remediation:**

For deployments requiring immediate revocation capability, implement a token ID (jti claim) blacklist backed by the existing cache infrastructure.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Oauth2 Oidc Flows | Superset acts exclusively as an OAuth Client; no Authorization Server implementation exists | Audit confirmation | — |
| Oauth2 Oidc Flows | Configurable redirect URI (DATABASE_OAUTH2_REDIRECT_URI) not dynamically controlled by user input | Audit confirmation | — |
| Oauth2 Oidc Flows | PKCE code_verifier properly cleaned up from key-value store after use | Audit confirmation | — |
| Oauth2 Oidc Flows | OAuth2 state JWT has 5-minute expiration limiting replay window | Audit confirmation | — |
| Oauth2 Oidc Flows | Superset exclusively uses Authorization Code flow with PKCE; no deprecated Implicit or ROPC flows | Audit confirmation | — |
| Oauth2 Oidc Flows | Client-side support for refresh token rotation from external AS | Audit confirmation | — |
| Oauth2 Oidc Flows | Distributed lock prevents concurrent refresh token races | Audit confirmation | — |
| Tls And Transport Security | Python runtime ssl.create_default_context() enforces TLS 1.2+ minimum for all client connections (redis-py, requests) | source: Dropped finding ASVS-1211-INFO-001 | — |
| Tls And Transport Security | WSS enforcement delegated to reverse proxy/infrastructure layer; application provides JWT-authenticated channels with HTTP-only secure cookies as defense-in-depth | Architecture observation from report | — |
| Input Validation | Server-side validation enforced at trusted service layer | All chart API endpoints use Marshmallow schemas (ChartPostSchema, ChartPutSchema, ChartDataQueryObjectSchema) for server-side validation before business logic execution | superset/charts/schemas.py |
| Browser Security Controls | CSP nonce generation | All inline scripts in SPA template include nonce attributes enabling strict CSP enforcement at infrastructure layer | superset/templates/superset/spa.html:48, superset/templates/superset/spa.html:79, superset/templates/superset/spa.html:118 |
| Browser Security Controls | SVG content sanitization | sanitize_svg_content() function strips scripts, event handlers, iframes, objects, and embeds from SVG content before inline rendering | superset/utils/core.py:283 |
| Browser Security Controls | HTML sanitization in email notifications | Uses nh3.clean() with explicit tag/attribute allowlists before rendering descriptions in email bodies | superset/reports/notifications/email.py |
| Browser Security Controls | Complete HTML tag stripping in MCP sanitization | nh3.clean() with empty tag set ensures text content cannot be rendered as HTML | superset/mcp_service/utils/sanitization.py |
| Browser Security Controls | Consistent sanitization library choice | Codebase standardizes on nh3 (Rust-based) for HTML sanitization across all layers | — |
| Browser Security Controls | Defense-in-depth HTML stripping | _strip_html_tags() implements multi-pass entity decoding with iteration limit, nh3 tag stripping, and selective entity restoration | superset/mcp_service/utils/sanitization.py |
| Browser Security Controls | Consistent `escape()` + `Markup()` pattern for text content | Both `dashboard_link()` and `slice_link` demonstrate the correct pattern of escaping user-controlled text content before wrapping in `Markup` | superset/models/dashboard.py:163-165, superset/models/slice.py |
| Browser Security Controls | nh3-based HTML sanitization throughout codebase | Consistent use of `nh3.clean()` for HTML sanitization across multiple layers: MCP service sanitization strips ALL tags (`tags=set()`), email notifications allow only safe formatting tags, markdown rendering allows only safe structure tags with restricted attributes | superset/utils/sanitization.py, superset/reports/notifications/email.py:100, superset/reports/notifications/email.py:108, superset/utils/core.py |
| Browser Security Controls | Multi-layer entity decoding defense | `_strip_html_tags()` iteratively decodes HTML entities before passing to nh3, preventing bypass via nested encoding (e.g., `&amp;lt;script&amp;gt;`) | superset/utils/sanitization.py |
| Browser Security Controls | Explicit `&amp;`-only restore after sanitization | After nh3 sanitization, only `&amp;` → `&` is restored (not full `html.unescape()`), explicitly documented as preventing re-introduction of angle brackets | superset/utils/sanitization.py |
| Browser Security Controls | Pandas `escape=True` for table rendering | In email.py, `df.to_html(escape=True)` ensures cell values are HTML-escaped before structural sanitization with nh3 | superset/reports/notifications/email.py:108 |
| Browser Security Controls | Jinja2 autoescaping enabled | Standard `{{ }}` expressions are auto-escaped in spa.html template | superset/templates/spa.html |
| Browser Security Controls | CSP infrastructure integration with nonce | The SPA template uses `nonce` attributes on all inline scripts demonstrating proper integration with infrastructure-layer CSP | superset/templates/spa.html |
| Cookie And Header Security | SESSION_COOKIE_HTTPONLY | Default True prevents JS access | superset/config.py:1048 |
| Cookie And Header Security | SESSION_COOKIE_SECURE | Default False - operator/proxy sets for production | superset/config.py:1049 |
| Cookie And Header Security | SESSION_COOKIE_SAMESITE | Default Lax - CSRF defense | superset/config.py:1050 |
| Cookie And Header Security | TALISMAN_CONFIG session_cookie_secure | Default False - delegated to infrastructure | superset/config.py:1028 |
| Cookie And Header Security | GLOBAL_ASYNC_QUERIES_JWT_COOKIE_SECURE | Default False - feature flag gated, infrastructure delegated | superset/config.py:1074 |
| Cookie And Header Security | GLOBAL_ASYNC_QUERIES_JWT_COOKIE_SAMESITE | Default None (browsers apply Lax) | superset/config.py:1075 |
| Cookie And Header Security | Layered CSRF Defense | SESSION_COOKIE_SAMESITE, Flask-WTF CSRF tokens, CORS preflight, @protect() authentication | — |
| Cookie And Header Security | Infrastructure Delegation Model | Configuration knobs exist for both application and infrastructure layers, allowing operators to configure cookie security at either level | — |
| Cookie And Header Security | Flask-Talisman enabled by default | TALISMAN_ENABLED = True in superset/config.py | superset/config.py:982 |
| Cookie And Header Security | TALISMAN_CONFIG provides configurable security headers including HSTS | TALISMAN_CONFIG configuration point available for HSTS addition | superset/config.py:986 |
| Cookie And Header Security | force_https delegated to proxy layer | force_https = False in TALISMAN_CONFIG - does not interfere with proxy HTTPS redirect | superset/config.py:1028 |
| Cookie And Header Security | OVERRIDE_HTTP_HEADERS mechanism for header injection | Empty dict allows adding HSTS via configuration | superset/config.py:817 |
| Cookie And Header Security | No hardcoded HSTS undermining values | Application does not set Strict-Transport-Security: max-age=0 or similar values | — |
| Cookie And Header Security | Fixed origin allowlist | CORS_OPTIONS uses a hardcoded list of trusted origins rather than reflecting the request Origin header | superset/config.py:556, superset/config.py:557 |
| Cookie And Header Security | No wildcard CORS | Access-Control-Allow-Origin: * is not used in the default configuration | superset/config.py:557 |
| Cookie And Header Security | No credentials by default | supports_credentials is not set (defaults to False), meaning cross-origin requests from allowed origins cannot include authentication cookies | superset/config.py:557 |
| Cookie And Header Security | Minimal surface | Only two map tile server origins are allowed by default: https://tile.openstreetmap.org and https://tile.osm.ch | superset/config.py:557 |
| Cookie And Header Security | ENABLE_CORS configuration | Default True - CORS enabled with explicit configuration | superset/config.py:556 |
| Cookie And Header Security | Flask-CORS integration | Applies CORS_OPTIONS to Flask app | superset/initialization.py |
| Cookie And Header Security | CSP connect-src directive | Restricts frontend fetch targets, aligns with CORS origins list | superset/config.py:1003 |
| Cookie And Header Security | CSRF enabled globally | WTF_CSRF_ENABLED = True ensures all endpoints are CSRF-protected unless explicitly exempted | superset/config.py:241 |
| Cookie And Header Security | Explicit CSRF token API | The /api/v1/security/csrf_token/ endpoint (authentication-gated) provides tokens for SPA form submissions | superset/security/api.py:97 |
| Cookie And Header Security | Embedded view referrer validation | The embedded dashboard view validates request.referrer against a configured allowlist using same_origin() from flask_wtf | superset/embedded/view.py:56 |
| Cookie And Header Security | @protect() on security endpoints | All security API methods (csrf_token, guest_token, role list) require authentication via FAB's @protect() decorator | superset/security/api.py |
| Cookie And Header Security | Limited exempt list | Only 6 specific endpoints are exempt, and they serve legitimate purposes (API data fetching, SAML callbacks) | superset/config.py:244-252 |
| Cookie And Header Security | WTF_CSRF_TIME_LIMIT | 1 week token lifetime | superset/config.py:930 |
| Cookie And Header Security | Referrer allowlist | Domain-based access control for embedded views | superset/embedded/view.py:53-58 |
| Cookie And Header Security | Restrictive CORS origin allowlist | Only two specific trusted origins are permitted, dramatically reducing the attack surface | superset/config.py:557 |
| Cookie And Header Security | JSON-based APIs | Flask-AppBuilder API classes typically parse request.json, which means endpoints will fail gracefully (with errors) if sent form-encoded data instead of JSON | — |
| Cookie And Header Security | Content-Type: application/json (implicit) | Most API endpoints parse JSON (implicitly triggers preflight) | — |
| Cookie And Header Security | POST for guest_token | superset/security/api.py:~L118 | superset/security/api.py:118 |
| Cookie And Header Security | GET for csrf_token | superset/security/api.py:~L97 | superset/security/api.py:97 |
| Cookie And Header Security | GET for role list | superset/security/api.py:~L181 | superset/security/api.py:181 |
| Cookie And Header Security | GET for embedded view | superset/embedded/view.py:~L36 | superset/embedded/view.py:36 |
| Cookie And Header Security | REST conventions | Flask-AppBuilder API classes enforce method-action mapping | — |
| Cookie And Header Security | Correct method assignment | Guest token creation (state-changing) uses POST; data retrieval (CSRF token, roles) uses GET | — |
| Cookie And Header Security | Flask-AppBuilder enforcement | The FAB API class framework enforces REST conventions where CRUD operations map to appropriate HTTP methods (POST=create, GET=read, PUT=update, DELETE=delete) | — |
| Cookie And Header Security | @expose with explicit methods | Route declarations explicitly specify allowed methods, preventing method confusion | — |
| Cookie And Header Security | No state-changing GET endpoints | None of the audited endpoints perform state-changing operations via GET requests | — |
| Authentication Controls | Application-level rate limiting available via AUTH_RATE_LIMITED config with primary defense delegated to infrastructure | Promoted from dropped finding ASVS-611-INFO-001 | — |
| Authentication Controls | Password complexity validation available via FAB AUTH_PASSWORD_COMPLEXITY_VALIDATOR configuration | source: Dropped finding ASVS-624-LOW-001 | — |
| Session Management | Application performs session token verification using backend service | All session verification handled by trusted backend (Flask-AppBuilder) | — |
| Session Management | Application uses dynamically generated session tokens, not static API secrets | Session management delegated to Flask-AppBuilder with dynamic token generation | — |
| Session Management | New session token generated on user authentication and current session terminated | Session lifecycle managed by Flask-AppBuilder per authentication flow | — |
| Session Management | Flask-Login user_loader performs per-request is_active validation, providing functional session termination when users are disabled | Session lifecycle (including invalidation) delegated to Flask-AppBuilder per flask_appbuilder_security_controls.md; FAB's per-request is_active check provides effective termination and is the documented primary control | — |
| Authorization Enforcement | Authorization documentation exists and defines rules for function-level and data-specific access | Section 8.1.1 passed review | — |
| Authorization Enforcement | Authorization rules are enforced at trusted service layer without client-side manipulation | Section 8.3.1 passed review - server-side enforcement confirmed | — |
| Token Validation | JWT tokens are validated using digital signatures before accepting token contents | ASVS 9.1.1 passed - signature verification implemented | — |
| Token Validation | Only allowlisted algorithms are used for JWT token creation and verification | ASVS 9.1.2 passed - algorithm allowlist enforced | — |
| Token Validation | Key material for token validation comes from trusted pre-configured sources | ASVS 9.1.3 passed - trusted key sources validated | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Partial** | See FINDING-007, FINDING-008, FINDING-009 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-017 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Pass** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Partial** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-011 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-018 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Fail** | See FINDING-005 |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Pass** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Partial** | See FINDING-012, FINDING-013, FINDING-019 |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Pass** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **Pass** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** | See FINDING-020 |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Partial** | See FINDING-014 |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Pass** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Pass** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **Pass** |  |
| 6.2.2 | Verify that users can change their password. | **Pass** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **Pass** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **Pass** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Partial** | See FINDING-015 |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Partial** | See FINDING-021 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Fail** | See FINDING-006 |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Fail** | See FINDING-006 |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Partial** | See FINDING-016 |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** |  |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** |  |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** |  |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** |  |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Fail** | See FINDING-002 |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Pass** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Pass** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Pass** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Fail** | See FINDING-001, FINDING-003, FINDING-004, FINDING-010 |

**Summary Statistics:**
- **Pass**: 43 requirements (61.4%)
- **Partial**: 10 requirements (14.3%)
- **N/A**: 12 requirements (17.1%)
- **Fail**: 5 requirements (7.1%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | High | 15.3.1 | FINDING-003, FINDING-004, FINDING-010, FINDING-015 | superset/databases/api.py |
| FINDING-002 | Medium | 11.3.2 | — | superset/utils/encrypt.py, superset/models/core.py, superset/databases/ssh_tunnel/models.py |
| FINDING-003 | Medium | 15.3.1 | FINDING-001, FINDING-004, FINDING-010, FINDING-015 | superset/databases/api.py |
| FINDING-004 | Medium | 15.3.1 | FINDING-001, FINDING-003, FINDING-010, FINDING-015 | superset/queries/api.py |
| FINDING-005 | Medium | 2.3.1 | — | superset/commands/chart/update.py |
| FINDING-006 | Medium | 8.2.1, 8.2.2 | — | superset/commands/chart/update.py |
| FINDING-007 | Low | 1.2.1 | FINDING-008, FINDING-009, FINDING-012, FINDING-013, FINDING-019 | superset/models/dashboard.py |
| FINDING-008 | Low | 1.2.1 | FINDING-007, FINDING-009, FINDING-012, FINDING-013, FINDING-019 | superset/models/slice.py |
| FINDING-009 | Low | 1.2.1 | FINDING-007, FINDING-008, FINDING-012, FINDING-013, FINDING-019 | superset/reports/notifications/email.py |
| FINDING-010 | Low | 15.3.1 | FINDING-001, FINDING-003, FINDING-004, FINDING-015 | superset/security/api.py |
| FINDING-011 | Low | 2.1.1 | — | superset/charts/schemas.py |
| FINDING-012 | Low | 3.2.2 | FINDING-007, FINDING-008, FINDING-009, FINDING-013, FINDING-019 | superset/reports/notifications/email.py |
| FINDING-013 | Low | 3.2.2 | FINDING-007, FINDING-008, FINDING-009, FINDING-012, FINDING-019 | superset/models/dashboard.py |
| FINDING-014 | Low | 3.5.2 | — | superset/config.py |
| FINDING-015 | Low | 6.4.1 | FINDING-001, FINDING-003, FINDING-004, FINDING-010 | superset/security/api.py |
| FINDING-016 | Low | 9.2.1 | — | superset/async_events/async_query_manager.py |
| FINDING-017 | Informational | 1.2.2 | — | superset/connectors/sqla/models.py |
| FINDING-018 | Informational | 2.2.1 | — | superset/charts/schemas.py |
| FINDING-019 | Informational | 3.2.2 | FINDING-007, FINDING-008, FINDING-009, FINDING-012, FINDING-013 | superset/models/slice.py |
| FINDING-020 | Informational | 3.5.1 | — | superset/config.py |
| FINDING-021 | Informational | 7.4.1 | — | superset/security/manager.py |

**Total Unique Findings**: 21 (0 Critical, 1 High, 5 Medium, 10 Low, 5 Info)

*16 of 21 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 16 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 21 |

**Total consolidated findings: 21**

*End of Consolidated Security Audit Report*