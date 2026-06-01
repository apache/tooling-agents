# Security Audit Consolidated Report — apache/superset/superset

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset |
| ASVS Level | L3 |
| Severity Threshold | None (all findings included) |
| Commit | a621520 |
| Date | Jun 01, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 345 |
| Total Findings | 62 |
| Actionable Issues | 54 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 54 actionable items.*

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 1 |
| Medium | 12 |
| Low | 41 |
| Info | 8 |

### ASVS Level Coverage

This audit evaluated the repository against ASVS Level 3 requirements across 16 security domains including input validation, authentication, session management, cryptography, and browser security controls. Findings span all three ASVS levels, with the majority of medium-severity issues concentrated at L2 requirements related to token security, transport configuration, and cryptographic defaults.

### Top 5 Risks

1. **SQL Injection via Unescaped `url_param` Return Values from `request.args`** [High] — The `url_param` Jinja function returns user-controlled query string values directly into SQL template contexts without escaping, enabling SQL injection when used in ad-hoc SQL queries.
2. **Default JWT Secrets and Cryptographic Keys Shipped in Source Code Without Runtime Validation** [Medium] — Production deployments that do not override default SECRET_KEY and JWT secret values operate with publicly known cryptographic material, allowing token forgery and session hijacking.
3. **CSV/File Upload Stores Formula-Prefixed Values Without Sanitization, Enabling Formula Injection on Subsequent Export** [Medium] — Uploaded CSV data containing formula-prefixed cells is stored as-is and later exported without sanitization, enabling formula injection attacks against users who open exported files in spreadsheet applications.
4. **MCP Authentication Error Reveals System Configuration to Unauthenticated Users** [Medium] — Authentication failures in the MCP resource server return detailed error messages exposing internal system configuration details to unauthenticated callers.
5. **`random_key()` Function Defaults to 64 Bits of Entropy, Below 128-Bit Minimum** [Medium] — The utility function used for generating random identifiers defaults to 64 bits of entropy, falling below the ASVS-mandated 128-bit minimum for security-sensitive tokens.

### Positive Controls Observed

- **SVG upload restricted to admin role** — SVG file uploads are limited to the admin trust boundary, preventing untrusted users from injecting malicious SVG content.
- **Database schema names sourced from operator-controlled infrastructure** — Schema names originate from operator-controlled database infrastructure, limiting injection surface to trusted actors.
- **Layered CSRF defense** — Multiple protection layers including CSRF tokens (primary), SameSite=Lax cookies (secondary), and restrictive CORS origins (tertiary).
- **CSP with nonces and strict-dynamic** — Talisman configuration uses `strict-dynamic` with nonces, providing robust protection against script injection and XSSI attacks.
- **Guest token isolation for embedded contexts** — Embedded dashboards use separate JWTs with scoped permissions and short TTL (300 seconds) rather than sharing the main session cookie.
- **Fail-closed behavior in async command pattern** — If `run()` is called without prior `validate()`, an AttributeError raises preventing execution in `CreateAsyncChartDataJobCommand`.
- **Access check in temporary cache creation** — `CreateFilterStateCommand.create()` performs access check via `check_access(resource_id)`, mitigating immediate impact of missing `validate()` call.
- **Local asset hosting by default** — `STATIC_ASSETS_PREFIX` defaults to empty string, serving all assets from the same origin and eliminating the need for SRI in default deployments.
- **Security headers delegated to deployment infrastructure** — HSTS, CSP, X-Content-Type-Options, Referrer-Policy, and frame-ancestors enforcement delegated to reverse proxy with Talisman providing defense-in-depth.
- **Anti-automation and rate limiting delegated to deployment infrastructure** — Rate limiting explicitly delegated to API gateway, reverse proxy, or WAF layer per documented architecture.
- **Minimal CORS configuration** — CORS origin list only includes map tile services needed by the frontend visualization layer, far more restrictive than typical applications.
- **SameSite cookie policy (Lax)** — `SESSION_COOKIE_SAMESITE = 'Lax'` prevents authenticated resources from being loadable cross-origin via embedded elements.
- **CSP object-src: 'none'** — Unconditionally blocks all `<object>`, `<embed>`, and `<applet>` elements in both production and development configurations.
- **Modern framework (React) with no deprecated plugin technologies** — No NSAPI, Flash, Shockwave, ActiveX, Silverlight, NACL, or Java applet references present.
- **HTML_SANITIZATION enabled** — Markdown content is sanitized by default, limiting injection of deceptive or malicious content into dashboards.
- **Authentication redirects delegated to Flask-AppBuilder** — Login/logout redirect validation handled by Flask-AppBuilder's security manager with `next` parameter validation.
- **Safe text rendering practices** — Application uses safe rendering functions like `createTextNode`/`textContent` preventing DOM-based XSS.
- **DOM clobbering protections** — Explicit variable declarations, type checking, and namespace isolation implemented.
- **CORS Access-Control-Allow-Origin properly validated** — Origin header validated against allowlist or fixed value used.
- **No JSONP callback parameter handling** — All API responses use standard JSON with proper content-type without callback wrapping.

---

## 3. Findings

### 3.2 High

#### FINDING-001: SQL Injection via Unescaped `url_param` Return Values from `request.args`

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | CWE-89 |
| **ASVS Sections** | 1.1.1, 1.1.2, 1.2.4, 1.3.3, 1.3.7, 1.5.3 |
| **Files** | superset/jinja_context.py |
| **Source Reports** | 1.1.1.md, 1.1.2.md, 1.2.4.md, 1.3.3.md, 1.3.7.md, 1.5.3.md |
| **Related** | FINDING-002 |

**Description:**

The `url_param()` function in `superset/jinja_context.py` has inconsistent input escaping. When values are sourced from `request.args` (URL query parameters), the function returns the raw, unescaped value, completely bypassing the dialect-specific SQL escaping (`String().literal_processor()`) that is applied to values obtained from `form_data["url_params"]`. This violates both ASVS 1.1.1 (canonical form processing before further use) and 1.1.2 (output encoding as final step). The data flow is: Browser URL query string → Flask request.args → url_param() early return (no escaping) → Jinja template string substitution → raw SQL string → database cursor execution. Attacker: Gamma role user with access to view a dashboard/chart using url_param() in its virtual dataset SQL.

**Remediation:**

Apply dialect-specific SQL escaping to ALL return paths in `url_param()`, regardless of input source. The escaping must be applied as the final step immediately before returning the value that will be interpolated into SQL, ensuring consistency across all code paths.

---

### 3.3 Medium

#### FINDING-002: Documented Unsafe Pattern in `get_filters` Docstring Encourages SQL Injection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-89 |
| **ASVS Sections** | 1.2.4 |
| **Files** | superset/jinja_context.py |
| **Source Reports** | 1.2.4.md |
| **Related Findings** | FINDING-001 |

**Description:**

The get_filters() docstring in `superset/jinja_context.py` documents a replace("'", "''") escaping pattern that is incomplete and unsafe. This pattern does not handle backslash escaping, Unicode sequences, or charset-specific SQL injection vectors. Non-admin users controlling filter values on dashboards using this documented pattern can achieve SQL injection.

**Remediation:**

Update documentation to remove the unsafe replace pattern and recommend the where_in filter or proper parameterization. Include clear warnings against manual SQL escaping.

---

#### FINDING-003: CSV/File Upload Stores Formula-Prefixed Values Without Sanitization, Enabling Formula Injection on Subsequent Export

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-1236 |
| **ASVS Sections** | 1.2.10 |
| **Files** | superset/commands/database/uploaders/csv_reader.py, superset/commands/database/uploaders/base.py, superset/commands/database/uploaders/columnar_reader.py |
| **Source Reports** | 1.2.10.md |
| **Related Findings** | |

**Description:**

When users upload CSV files, the application uses pd.read_csv() without formula sanitization. The data flow is: User-uploaded CSV file → pd.read_csv() (no formula sanitization) → pandas DataFrame → df_to_sql() → database table → later queried by chart → exported as CSV → opened in spreadsheet application → formula execution. Cells starting with =, +, -, @, \t, or \0 are stored verbatim and will be interpreted as formulas when another user exports and opens the data in a spreadsheet application. Attacker: Authenticated user with CSV upload permission. Victim: another user who exports and opens the data.

**Remediation:**

Apply formula escaping at the export layer: prefix cells starting with =, +, -, @, \t, \0 with a single quote when exporting to CSV or spreadsheet formats. Follow RFC 4180 sections 2.6 and 2.7 for CSV escaping.

---

#### FINDING-004: No Application-Level File Size Check Before Processing in Columnar Upload

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-400 |
| **ASVS Sections** | 5.2.1 |
| **Files** | superset/commands/database/uploaders/columnar_reader.py, superset/commands/database/uploaders/base.py |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | FINDING-012, FINDING-030, FINDING-045 |

**Description:**

The ColumnarReader._yield_files() and file_to_dataframe() methods process uploaded files without any size validation before reading content into memory. The UploadCommand.validate() method checks database/schema permissions but does not validate file size. A large parquet file or ZIP containing large parquet files will be read entirely into BytesIO buffers and then into pandas DataFrames without bounds.

**Remediation:**

Add file size validation in UploadCommand.validate() or at the reader level, checking against a configurable UPLOAD_MAX_FILE_SIZE_BYTES before processing begins.

---

#### FINDING-005: MCP Authentication Error Reveals System Configuration to Unauthenticated Users

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-209 |
| **ASVS Sections** | 6.3.4, 6.3.8 |
| **Files** | superset/mcp_service/auth.py |
| **Source Reports** | 6.3.4.md, 6.3.8.md |
| **Related Findings** | FINDING-046 |

**Description:**

The `get_user_from_request()` function in `superset/mcp_service/auth.py` raises a ValueError containing detailed configuration diagnostics (MCP_AUTH_ENABLED value, whether JWT keys are configured, API key prefix format, whether MCP_DEV_USERNAME is set) that propagates to unauthenticated MCP clients. This enables configuration fingerprinting by remote unauthenticated attackers and violates both authentication pathway consistency (6.3.4) and user enumeration prevention (6.3.8) requirements.

**Remediation:**

Replace the detailed ValueError with a generic message for the client ('Authentication required. No valid credentials provided.' or 'Authentication failed.'), while preserving detailed diagnostics server-side via logger.warning() or logger.debug(). Ensure consistent error responses across all authentication pathways.

---

#### FINDING-006: Guest Token RLS Rules Cannot Be Revoked or Updated Before Expiration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-613 |
| **ASVS Sections** | 8.3.2 |
| **Files** | superset/security/manager.py, superset/connectors/sqla/models.py |
| **Source Reports** | 8.3.2.md |
| **Related Findings** | FINDING-035, FINDING-036 |

**Description:**

Guest tokens embed RLS rules directly in the JWT payload at issuance time. When RLS rules are modified on the server, outstanding guest tokens continue to enforce stale RLS rules until natural expiration. There is no token revocation mechanism, no server-side re-validation of RLS rules against current configuration, and no alerting when a guest user performs actions under stale authorization rules. ASVS 8.3.2 requires mitigating controls for self-contained tokens.

**Remediation:**

Implement server-side RLS rule validation for guest tokens: compare token-embedded rules against current server state on each request, with audit logging on drift detection. Alternatively, add an rls_version claim to guest tokens validated against a server-side counter, or implement short-lived tokens with refresh to reduce the staleness window.

---

#### FINDING-007: MCP Resource Server Audience Validation Is Conditional and Not Enforced by Default

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-287 |
| **ASVS Sections** | 10.3.1, 9.2.3 |
| **Files** | superset/mcp_service/jwt_verifier.py |
| **Source Reports** | 10.3.1.md, 9.2.3.md |
| **Related Findings** | |

**Description:**

The MCP resource server's audience validation is conditional on configuration (`if self.audience:`). When `self.audience` is None/empty, audience validation is skipped entirely, allowing tokens intended for other services sharing the same IdP to be accepted. A stolen or misdirected token from another service could grant access to MCP tools. Data Flow: External JWT token → DetailedJWTVerifier.load_access_token() → `if self.audience:` guard → audience validation SKIPPED when self.audience is not configured → token accepted for any audience → user context established → tool execution.

**Remediation:**

The verifier should either require audience configuration or reject tokens that don't match a configured audience. At minimum, log a warning during initialization when audience is not set. Consider failing closed when MCP_AUTH_ENABLED is True but no audience is configured.

---

#### FINDING-008: Token Scope Claims Not Enforced in Per-Tool Authorization Decisions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-863 |
| **ASVS Sections** | 10.3.2 |
| **Files** | superset/mcp_service/auth.py, superset/mcp_service/jwt_verifier.py |
| **Source Reports** | 10.3.2.md |
| **Related Findings** | FINDING-031, FINDING-032 |

**Description:**

The MCP resource server validates token scopes at entry (minimum gate) but does not enforce them in per-tool authorization decisions. Token scopes are available in the AccessToken ContextVar but check_tool_permission() only consults database RBAC roles. A token with limited scopes (e.g., mcp:read) can perform write operations if the mapped user has broader database permissions, violating the OAuth principle of enforcing the intersection of user permissions and token scope.

**Remediation:**

Incorporate the access token's scopes into the authorization decision in check_tool_permission(). The authorization should be the intersection of the token's granted scopes and the user's database permissions. Map tool methods (read/write/delete) to required scopes.

---

#### FINDING-009: `random_key()` function defaults to 64 bits of entropy, below 128-bit minimum

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-331 |
| **ASVS Sections** | 11.2.3, 11.5.1 |
| **Files** | superset/key_value/utils.py |
| **Source Reports** | 11.2.3.md, 11.5.1.md |
| **Related Findings** | |

**Description:**

The `random_key` function in `superset/key_value/utils.py` defaults to 8 bytes (64 bits) of entropy via `secrets.token_urlsafe(8)`. This is below the 128-bit minimum required by ASVS 11.2.3 and 11.5.1. The function is used for key-value store entries including PKCE code verifiers (RFC 7636 recommends minimum 256 bits). With 64 bits of entropy, the birthday bound is ~2^32. For PKCE verifier lookups, guessing a valid key grants access to the stored code verifier, potentially compromising OAuth2 flows. While online brute-force is infeasible over a network (~2^63 requests), the default does not meet the stated minimum security requirement.

**Remediation:**

Change `nbytes` default from 8 to 16 (128 bits) in `superset/key_value/utils.py`: `def random_key(nbytes: int = 16) -> str`. Add a minimum bytes validation to prevent callers from requesting less than 16 bytes for security-sensitive keys.

---

#### FINDING-010: SMTP outbound connections default to disabled server certificate authentication

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-295 |
| **ASVS Sections** | 12.3.1, 12.3.2 |
| **Files** | superset/config.py |
| **Source Reports** | 12.3.1.md, 12.3.2.md |
| **Related Findings** | FINDING-038 |

**Description:**

SMTP_SSL_SERVER_AUTH defaults to False in superset/config.py. When an operator configures a remote SMTP server, STARTTLS upgrades the connection but the server certificate is not validated, allowing network-positioned attackers to MITM email traffic containing alert/report data. This violates both encrypted transport requirements (12.3.1) and certificate validation requirements (12.3.2).

**Remediation:**

Change the default to SMTP_SSL_SERVER_AUTH = True. If backward compatibility is needed, raise a ConfigurationError when STARTTLS is enabled with a remote host and SMTP_SSL_SERVER_AUTH is False. Alternatively, add a startup warning when SMTP_STARTTLS = True and SMTP_SSL_SERVER_AUTH = False with a remote SMTP host.

---

#### FINDING-011: Default JWT Secrets and Cryptographic Keys Shipped in Source Code Without Runtime Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-1188 |
| **ASVS Sections** | 13.2.3, 13.3.4 |
| **Files** | superset/config.py, superset/constants.py |
| **Source Reports** | 13.2.3.md, 13.3.4.md |
| **Related Findings** | |

**Description:**

The application ships publicly-known default values for SECRET_KEY, GUEST_TOKEN_JWT_SECRET, and GLOBAL_ASYNC_QUERIES_JWT_SECRET with no runtime validation preventing their use. An unauthenticated attacker knowing these defaults can forge guest tokens, async query JWTs, or Flask sessions if operators fail to override them.

**Remediation:**

Add startup validation that blocks the application from starting or disables affected features when security-sensitive secrets retain their default placeholder values.

---

#### FINDING-012: Unbounded Query Amplification via `time_compare` and `deck_slices` Lists

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-400 |
| **ASVS Sections** | 15.2.2 |
| **Files** | superset/viz.py |
| **Source Reports** | 15.2.2.md |
| **Related Findings** | FINDING-004, FINDING-030, FINDING-045 |

**Description:**

User-controlled `form_data["time_compare"]` list / `form_data["deck_slices"]` list → unbounded iteration → multiple database queries per iteration → resource exhaustion. A single HTTP request with 50 time_compare entries triggers 50+ database queries. Combined with deck_slices (each slice potentially having its own time_compare), amplification can be multiplicative.

**Remediation:**

Add configurable upper bound on `time_compare` list length (suggest default 10) and `deck_slices` list length (suggest default 10). Validate list lengths before iteration.

---

#### FINDING-013: MCP Service JWT Authentication Successful Events Not Logged

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-778 |
| **ASVS Sections** | 16.3.1 |
| **Files** | superset/mcp_service/jwt_verifier.py |
| **Source Reports** | 16.3.1.md |
| **Related Findings** | FINDING-050, FINDING-052 |

**Description:**

Authentication failure events are logged at WARNING level via `_auth_error_handler`, but successful JWT authentication generates no log entry. An attacker using a stolen JWT token to access the MCP service would generate no authentication audit trail. Incident response teams cannot correlate access patterns, detect credential theft, or establish timelines for successful MCP service access.

**Remediation:**

Add structured logging on successful authentication in the `authenticate` method, including relevant metadata (client_id, scopes, authentication method).

### 3.4 Low

#### FINDING-014: Missing URL Protocol Validation on `external_url` Fields

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS Section(s) | 1.2.2 |
| Files | superset/charts/schemas.py, superset/dashboards/schemas.py |
| Source Reports | 1.2.2.md |
| Related Findings | FINDING-017 |

**Description:**

The `external_url` field in chart and dashboard schemas accepts any string with no URL protocol validation. If the frontend renders it as a clickable link, a javascript: or data: protocol URL could execute JavaScript in another user's browser (XSS). Requires Alpha role or custom role with chart/dashboard write access.

**Remediation:**

Add a Marshmallow validator that rejects non-http/https protocols on external_url fields. Ensure only safe URL protocols (http, https) are permitted and reject javascript:, data:, vbscript:, and other dangerous schemes.

---

#### FINDING-015: Email Subject Field Not Sanitized for CRLF Injection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-93 |
| ASVS Section(s) | 1.3.11 |
| Files | superset/utils/core.py |
| Source Reports | 1.3.11.md |
| Related Findings | |

**Description:**

In superset/utils/core.py, the send_email_smtp function assigns the subject parameter directly to msg['Subject'] without CRLF sanitization. Data flow: Report/alert name → subject parameter → msg['Subject'] → SMTP transmission. Attacker capability required: Authenticated user with permission to create reports/alerts (typically Alpha role or above). Impact: Email header injection allowing BCC injection, reply-to modification, or content-type manipulation.

**Remediation:**

Strip or replace \r and \n characters from the subject parameter before setting it as a MIME header: subject = subject.replace('\r', '').replace('\n', ' ').strip()

---

#### FINDING-016: Missing ZIP safety check in columnar file upload reader

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-409 |
| ASVS Section(s) | 1.3.3, 5.2.3, 5.3.3 |
| Files | superset/commands/database/uploaders/columnar_reader.py |
| Source Reports | 1.3.3.md, 5.2.3.md, 5.3.3.md |
| Related Findings | |

**Description:**

File: superset/commands/database/uploaders/columnar_reader.py, method _yield_files. Unlike the importer code path which calls check_is_safe_zip(), the columnar reader does not validate ZIP file safety (decompression ratio, entry count, total uncompressed size). Attacker capability: Authenticated user with file upload permission (non-admin Alpha/Gamma with upload grants). Impact: Memory exhaustion DoS via ZIP bomb.

**Remediation:**

Add check_is_safe_zip(zip_file) call before processing ZIP entries in columnar_reader.py, mirroring the pattern in importers/v1/utils.py. Implement decompression safety checks including total uncompressed size and file count limits before reading ZIP entries.

---

#### FINDING-017: User-supplied CSS stored and rendered without sanitization

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-79 |
| ASVS Section(s) | 1.3.5 |
| Files | superset/dashboards/schemas.py |
| Source Reports | 1.3.5.md |
| Related Findings | FINDING-014 |

**Description:**

File: superset/dashboards/schemas.py, DashboardPostSchema and DashboardPutSchema. The css field accepts arbitrary CSS content without sanitization. Attacker capability: Authenticated user with dashboard write permission (Alpha role or custom role with dashboard edit grants). Impact: CSS-based data exfiltration via attribute selectors + url() backgrounds, UI manipulation via CSS overlays, external resource loading via @import. Mitigated by deployment-layer CSP policies blocking external resource loading from CSS.

**Remediation:**

Apply CSS sanitization using a property/function allowlist or CSS sanitization library to strip url(), @import, expression() and other dangerous CSS constructs before storing dashboard CSS.

---

#### FINDING-018: Unescaped schema name used in regex substitution pattern

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-1333 |
| ASVS Section(s) | 1.3.12 |
| Files | superset/db_engine_specs/base.py |
| Source Reports | 1.3.12.md |
| Related Findings | |

**Description:**

File: superset/db_engine_specs/base.py, functions get_table_names() and get_view_names(). Schema name from database metadata is inserted unescaped into regex pattern via f-string. If a schema name contains regex metacharacters, the regex could exhibit catastrophic backtracking. Exploitability is low due to database identifier restrictions and requirement for elevated permissions to create schemas.

**Remediation:**

Apply re.escape() to the schema name before interpolation: escaped_schema = re.escape(schema); tables = {re.sub(f'^{escaped_schema}\\.', '', table) for table in tables}

---

#### FINDING-019: SQL dialect fallback from base to MySQL may produce different parse results

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-436 |
| ASVS Section(s) | 1.5.3 |
| Files | superset/sql/parse.py |
| Source Reports | 1.5.3.md |
| Related Findings | |

**Description:**

In superset/sql/parse.py, when SQL parsing fails with the base dialect and the script contains backticks, the parser falls back to MySQL dialect. This may produce different table extraction or mutation detection results than the actual target database's SQL parser, potentially affecting access control decisions for databases with unrecognized engine types.

**Remediation:**

Log the dialect fallback at WARNING level to enable security monitoring. Consider raising an error instead of silently falling back, or documenting the known limitation for unrecognized database types.

---

#### FINDING-020: CreateTemporaryCacheCommand.run() bypasses validate() invocation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-573 |
| ASVS Section(s) | 2.2.1 |
| Files | superset/commands/temporary_cache/create.py |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-021 |

**Description:**

The `BaseCommand` contract establishes that `run()` should call `validate()` before execution. However, `CreateTemporaryCacheCommand.run()` directly calls `self.create()` without invoking `self.validate()`. While `validate()` is currently a no-op, this pattern creates a gap where future validation logic added to `validate()` would be silently bypassed. Immediate impact is mitigated because `CreateFilterStateCommand.create()` performs its own access check via `check_access(resource_id)`.

**Remediation:**

Add `self.validate()` call in `run()` to align with the established BaseCommand contract.

---

#### FINDING-021: CreateAsyncChartDataJobCommand does not follow BaseCommand pattern, separating validate() from run() without enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-573 |
| ASVS Section(s) | 2.2.1 |
| Files | superset/commands/chart/data/create_async_job_command.py |
| Source Reports | 2.2.1.md |
| Related Findings | FINDING-020 |

**Description:**

This command class does not extend `BaseCommand` and has a different interface where `validate()` takes external parameters, `run()` takes different parameters, and `run()` does not call `validate()`. The caller must enforce ordering. If `run()` is called without prior `validate()`, an `AttributeError` on `_async_channel_id` will raise — this is fail-closed behavior.

**Remediation:**

Refactor to extend BaseCommand or add a guard in `run()` that verifies initialization state.

---

#### FINDING-022: BaseDAO.list() Has No Upper Bound on page_size

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-770 |
| ASVS Section(s) | 2.3.2 |
| Files | superset/daos/base.py |
| Source Reports | 2.3.2.md |
| Related Findings | |

**Description:**

BaseDAO.list() enforces a minimum page_size of 1 via `max(page_size, 1)` but has no upper bound. An authenticated user could pass an extremely large page_size forcing the database to prepare and transfer a large result set. Impact is limited DoS (resource exhaustion), not data exposure or privilege escalation. Base filters limit query universe to accessible records.

**Remediation:**

Enforce a configurable maximum page_size at the DAO layer: `page_size = min(max(page_size, 1), MAX_PAGE_SIZE)`

---

#### FINDING-023: CSRF-Exempt Endpoints Lack Explicit Content-Type or Custom Header Enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-352 |
| ASVS Section(s) | 3.5.2 |
| Files | superset/config.py |
| Source Reports | 3.5.2.md |
| Related Findings | |

**Description:**

Six sensitive endpoints are exempt from CSRF token validation. While the application does NOT primarily rely on CORS preflight for protection (it uses CSRF tokens + SameSite=Lax cookies), these exempt endpoints have no visible enforcement of a Content-Type that would trigger preflight (e.g., application/json) or a custom header. The SameSite=Lax cookie setting provides the primary defense but for legacy browsers without SameSite support, or if the endpoint also accepts GET requests, the protection may not hold.

**Remediation:**

For CSRF-exempt endpoints that perform state-changing operations, require a Content-Type of application/json (which triggers CORS preflight) or mandate a custom request header (e.g., X-Requested-With) that is not CORS-safelisted.

---

#### FINDING-024: No Sec-Fetch-* Header Validation or Cross-Origin-Resource-Policy Header for Authenticated Resources

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Section(s) | 3.5.8 |
| Files | superset/config.py |
| Source Reports | 3.5.8.md |
| Related Findings | |

**Description:**

The application does not validate Sec-Fetch-* headers or set Cross-Origin-Resource-Policy headers on authenticated resource endpoints. Browser cross-origin requests to Flask endpoints serving authenticated resources (chart data, thumbnails, CSV exports) return responses without CORP headers or Sec-Fetch-* validation, potentially allowing resources to be loaded cross-origin. However, the impact is limited because the SESSION_COOKIE_SAMESITE = 'Lax' cookie policy prevents cookie transmission on cross-origin subresource requests, so authenticated resources cannot actually be loaded cross-origin in practice.

**Remediation:**

For Level 3 compliance, add a Cross-Origin-Resource-Policy: same-origin response header to authenticated resource endpoints. This can be configured in DEFAULT_HTTP_HEADERS: DEFAULT_HTTP_HEADERS: dict[str, Any] = { "Cross-Origin-Resource-Policy": "same-origin" }. Alternatively, implement Sec-Fetch-* validation middleware that checks the Sec-Fetch-Site header on authenticated endpoints and aborts with 403 if the value is not same-origin, same-site, or none.

---

#### FINDING-025: No Configurable Redirect Allowlist Mechanism Visible in Application Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | |
| ASVS Section(s) | 3.7.2 |
| Files | superset/config.py |
| Source Reports | 3.7.2.md |
| Related Findings | |

**Description:**

No redirect allowlist configuration exists in config.py. The following settings can direct users to external URLs without allowlist validation: LOGO_TARGET_PATH (can specify full URL), TRACKING_URL_TRANSFORMER (used to translate internal Hadoop job tracker URL into a proxied one), and WEBDRIVER_BASEURL_USER_FRIENDLY (base URL for email report hyperlinks). Configuration values (admin-set) or application logic can redirect user responses to potentially untrusted domains without visible allowlist validation. For admin-configured values (LOGO_TARGET_PATH, etc.), requires admin access (out of scope per trust model). For any user-controllable redirect paths (not visible in provided code), would require authenticated user access. Open redirect could be used for phishing or credential theft by redirecting users to attacker-controlled lookalike pages.

**Remediation:**

Add a redirect allowlist configuration option and validation utility:

```python
# In config.py
ALLOWED_REDIRECT_DOMAINS: list[str] = []  # Empty = same-origin only

# In a utility module
from urllib.parse import urlparse

def is_safe_redirect(url: str) -> bool:
    """Validate redirect URL against allowlist."""
    if not url:
        return False
    parsed = urlparse(url)
    if not parsed.netloc:
        return True  # Relative URL, safe
    allowed = current_app.config.get("ALLOWED_REDIRECT_DOMAINS", [])
    return parsed.netloc in allowed
```

Note: The actual redirect-handling code is not present in the provided files. This finding is based on the absence of a configurable allowlist mechanism. Authentication-related redirects are handled by Flask-AppBuilder.

---

#### FINDING-026: External Redirect Warning Limited to Alert/Report Email Links

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Section(s) | 3.7.3 |
| Files | superset/config.py |
| Source Reports | 3.7.3.md |
| Related Findings | |

**Description:**

Alert/report email contains external link → link rewritten to pass through redirect warning page → user sees notification → user can choose to proceed or cancel. However, other navigation paths (dashboard links to external URLs, markdown content links, SQL Lab result links) may not implement the same warning mechanism. Users may be navigated to external URLs without explicit confirmation, potentially enabling social engineering attacks via compromised dashboard content.

**Remediation:**

Implement a general-purpose external navigation interceptor in the React frontend:

```javascript
// In a navigation utility
function navigateExternal(url: string, applicationOrigin: string) {
  const parsed = new URL(url, window.location.origin);
  if (parsed.origin !== applicationOrigin) {
    // Show confirmation modal
    showExternalNavigationWarning(url, () => {
      window.open(url, '_blank', 'noopener,noreferrer');
    });
  } else {
    window.location.href = url;
  }
}
```

---

#### FINDING-027: No Browser Security Feature Detection or User Warning Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Section(s) | 3.7.5 |
| Files | superset/config.py, superset/templates/superset/macros.html |
| Source Reports | 3.7.5.md |
| Related Findings | |

**Description:**

The application configures security features that depend on modern browser support (CSP Level 2 with 'strict-dynamic', nonces, SameSite cookies) but implements no mechanism to detect whether the user's browser supports these features, and provides no warning or access blocking for unsupported browsers. While the React 18 frontend framework requires ES6+ features that are only available in browsers already supporting CSP Level 2 and SameSite cookies, the application lacks an explicit, documented, and user-facing communication about minimum browser requirements.

**Remediation:**

Add client-side browser feature detection to warn users of unsupported browsers. Implement a JavaScript check in the React application bootstrap (e.g., src/setup/setupApp.ts) that validates support for SecurityPolicyViolationEvent and other modern browser features. Display a banner or block access with a message like 'Your browser may not support required security features. Please update to a supported browser version.' Additionally, add a documented minimum browser requirements page accessible before the main application loads.

---

#### FINDING-028: Raw JSON String Return Without Explicit Content-Type in Api.query()

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-116 |
| ASVS Section(s) | 4.1.1 |
| Files | superset/views/api.py |
| Source Reports | 4.1.1.md |
| Related Findings | |

**Description:**

The `Api.query()` method returns a raw `json.dumps()` string without using `self.json_response()`, potentially serving JSON with Flask's default `text/html` Content-Type. The `@api` decorator may not explicitly set Content-Type. The sibling methods `query_form_data` and `time_range` correctly use `self.json_response()`.

**Remediation:**

Replace `return json.dumps(payload_json, default=json.json_int_dttm_ser, ignore_nan=True)` with `return self.json_response(payload_json)` to ensure consistent Content-Type header generation.

---

#### FINDING-029: User-provided Input Used in HTTP Headers Without Explicit Sanitization

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-113 |
| ASVS Section(s) | 4.2.4 |
| Files | superset/charts/data/api.py, superset/databases/api.py, superset/datasets/api.py |
| Source Reports | 4.2.4.md |
| Related Findings | |

**Description:**

User-provided filename in Content-Disposition header (charts/data/api.py) and user-controlled query parameter used as cookie name (databases/api.py, datasets/api.py) lack explicit sanitization. Werkzeug v2.2+ rejects CRLF but malformed header syntax remains possible. Impact is self-affecting only for authenticated users.

**Remediation:**

Apply secure_filename() to user-provided filenames consistently. Validate token parameter with regex (alphanumeric, max 128 chars) before use as cookie name.

---

#### FINDING-030: Unbounded Cookie Name Length from User Input Could Cause Downstream Request Rejection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-400 |
| ASVS Section(s) | 4.2.5 |
| Files | superset/databases/api.py, superset/datasets/api.py |
| Source Reports | 4.2.5.md |
| Related Findings | FINDING-004, FINDING-012, FINDING-045 |

**Description:**

The `token` query parameter in databases/api.py and datasets/api.py export endpoints is used as a cookie name without length or character validation. An oversized token could cause persistent 431 errors for the targeted user until cookie expiry (600s). Requires authenticated access.

**Remediation:**

Add length (max 128) and character validation (alphanumeric + dash/underscore) for the token query parameter before use as cookie name.

---

#### FINDING-031: RLS Rule Creation/Update Commands Do Not Validate Caller's Access to Referenced Tables

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-863 |
| ASVS Section(s) | 8.2.2 |
| Files | superset/commands/security/create.py, superset/commands/security/update.py |
| Source Reports | 8.2.2.md |
| Related Findings | FINDING-008, FINDING-032 |

**Description:**

The `CreateRLSRuleCommand` and `UpdateRLSRuleCommand` validate that referenced table IDs exist in the database but do not verify that the authenticated user has access to those specific tables. While the RLS API endpoints are protected by `@protect()` (requiring "Row Level Security" write permission), a user with this permission could reference tables they don't have datasource/schema/database access to.

**Remediation:**

Add `security_manager.can_access_datasource(datasource=table)` check for each referenced table in both `CreateRLSRuleCommand.validate()` and `UpdateRLSRuleCommand.validate()`.

---

#### FINDING-032: REST API Explore View Lacks Per-User Field-Level Filtering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-863 |
| ASVS Section(s) | 8.2.3 |
| Files | superset/connectors/sqla/models.py |
| Source Reports | 8.2.3.md |
| Related Findings | FINDING-008, FINDING-031 |

**Description:**

The `BaseDatasource.data` property returns all fields (including `sql`, `params`, `perm`) uniformly to any user with datasource access, without per-user field-level filtering. The MCP service implements comprehensive field-level permissions via `SENSITIVE_FIELDS`/`SENSITIVE_FIELD_PERMISSIONS` but this filtering is not applied in the REST API explore view path.

**Remediation:**

Apply the MCP service's field-level filtering pattern (`permissions_utils.py`) to the REST API explore data path, gating sensitive dataset fields (`sql`, `extra`, `params`) behind specific permissions.

---

#### FINDING-033: User Identification Uses Potentially Reassignable Claims Without Issuer Context Binding

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-290 |
| ASVS Section(s) | 10.3.3 |
| Files | superset/mcp_service/auth.py |
| Source Reports | 10.3.3.md |
| Related Findings | |

**Description:**

The MCP resource server resolves users from JWT claims without incorporating the issuer into the user lookup key. In multi-issuer deployments, an attacker controlling a second trusted issuer could authenticate as a legitimate user if email/username collides across issuers. The issuer (iss) claim is validated at the JWT level but NOT incorporated into the user identification key in the database lookup.

**Remediation:**

For multi-issuer deployments, incorporate the issuer into the user lookup to prevent cross-issuer collision. Document that single-issuer deployments are safe, and multi-issuer deployments must use a resolver that returns iss+sub or similar compound key.

---

#### FINDING-034: MCP JWT verifier algorithm enforcement is conditional on configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-757 |
| ASVS Section(s) | 9.1.2 |
| Files | superset/mcp_service/jwt_verifier.py |
| Source Reports | 9.1.2.md |
| Related Findings | |

**Description:**

MCP JWT verifier algorithm enforcement is conditional on configuration. When self.algorithm is not configured, the algorithm check is skipped entirely. DOWNGRADED from Medium: exploitation requires operator misconfiguration (operator is a trusted party per profile) combined with specific key material conditions, and authlib mitigates many algorithm confusion vectors via key-type checks.

**Remediation:**

Enforce that self.algorithm is always set during initialization, or add a hard-fail when no algorithm is configured. Alternatively, define a static allowlist of permitted algorithms.

---

#### FINDING-035: Async query JWT tokens issued without expiration claim

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS Section(s) | 9.2.1 |
| Files | superset/async_events/async_query_manager.py |
| Source Reports | 9.2.1.md |
| Related Findings | FINDING-006, FINDING-036 |

**Description:**

Async query JWT tokens are issued without an exp claim, meaning they remain cryptographically valid indefinitely. Impact is limited: the cookie is httponly, the channel ID is a random UUID, and the data accessible is limited to the user's own async query results. The token is implicitly invalidated when the Flask session changes.

**Remediation:**

Add an exp claim to the token (e.g., matching session timeout). PyJWT's decode() automatically validates exp when present, so no changes needed on the verification side.

---

#### FINDING-036: MCP JWT verifier accepts tokens without expiration claim

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS Section(s) | 9.2.1 |
| Files | superset/mcp_service/jwt_verifier.py |
| Source Reports | 9.2.1.md |
| Related Findings | FINDING-006, FINDING-035 |

**Description:**

The MCP JWT verifier conditionally checks exp (if exp and exp < time.time()), meaning tokens without an exp claim are accepted without time boundary. Exploitation requires the IdP to issue tokens without exp (misconfiguration) AND token compromise.

**Remediation:**

Require the exp claim to be present: reject tokens where claims.get('exp') returns None.

---

#### FINDING-037: MD5 Used for UUID Namespace Generation (Legacy Path)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-328 |
| ASVS Section(s) | 11.4.1 |
| Files | superset/key_value/utils.py |
| Source Reports | 11.4.1.md |
| Related Findings | |

**Description:**

The `_uuid_namespace_from_md5` function in `superset/key_value/utils.py` uses MD5 for UUID namespace generation as a legacy fallback path. While SHA-256 alternative exists and is the recommended primary path, the MD5 path remains available when `HASH_ALGORITHM = 'md5'` or via `HASH_ALGORITHM_FALLBACKS`. Practical exploitation requires a targeted MD5 collision attack which is computationally expensive. Mitigating factors include SHA-256 as primary algorithm and developer awareness (`# noqa: S324`).

**Remediation:**

Deprecate the MD5 fallback path with a deprecation warning and document a timeline for removal from HASH_ALGORITHM_FALLBACKS support.

---

#### FINDING-038: SSH tunnel connections do not enforce host key verification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-295 |
| ASVS Section(s) | 12.3.1 |
| Files | superset/extensions/ssh.py |
| Source Reports | 12.3.1.md |
| Related Findings | FINDING-010 |

**Description:**

The create_tunnel method in superset/extensions/ssh.py does not pass an ssh_host_key parameter to sshtunnel.open_tunnel, causing the library to use AutoAddPolicy and accept any SSH server key. A network-positioned attacker could MITM the SSH tunnel. Exploitation requires the SSH_TUNNELING feature flag to be enabled and an admin to have configured a tunnel.

**Remediation:**

Add an optional host_key field to the SSH tunnel model and pass it to open_tunnel. Log a warning when tunnels are created without host key verification.

---

#### FINDING-039: Swagger/OpenAPI Documentation UI Enabled by Default in All Environments

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-215 |
| ASVS Section(s) | 13.4.5, 13.4.2 |
| Files | superset/config.py |
| Source Reports | 13.4.5.md, 13.4.2.md |
| Related Findings | |

**Description:**

FAB_API_SWAGGER_UI = True unconditionally. Requires authentication (@protect() decorator). DOWNGRADED from Low: no concrete attack scenario with meaningful impact — authenticated users viewing API docs for endpoints they already have access to is reconnaissance convenience, not exploitation per severity/remediation policy.

**Remediation:**

Disable Swagger UI by default or restrict to non-production environments: FAB_API_SWAGGER_UI = utils.parse_boolean_string(os.environ.get('SUPERSET_FAB_API_SWAGGER_UI', 'false'))

---

#### FINDING-040: Unauthenticated Endpoint Exposes Detailed Backend Version Information Including Git SHA

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-200 |
| ASVS Section(s) | 13.4.5, 13.4.6 |
| Files | superset/views/health.py, superset/config.py |
| Source Reports | 13.4.5.md, 13.4.6.md |
| Related Findings | FINDING-048, FINDING-060 |

**Description:**

The /version endpoint returns comprehensive version information including version string, Git SHA (8 chars), and branch name without authentication. Enables precise fingerprinting and CVE correlation.

**Remediation:**

Require authentication on /version endpoint, or reduce response to major.minor version only, or add EXPOSE_VERSION_INFO configuration flag defaulting to False.

---

#### FINDING-041: Temporary Cache Entries Created Without Explicit TTL

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | |
| ASVS Section(s) | 14.2.2, 14.2.4, 14.2.7 |
| Files | superset/commands/dashboard/filter_state/create.py, superset/commands/explore/form_data/create.py |
| Source Reports | 14.2.2.md, 14.2.4.md, 14.2.7.md |
| Related Findings | |

**Description:**

The application's cache subsystems show inconsistent implementation of TTL (time-to-live) controls. The QueryCacheManager implements explicit timeout passing, establishing a code convention for TTL enforcement. However, filter state and form data subsystems call cache.set() without explicit timeout parameter, relying entirely on backend default configuration which may be indefinite. This means sensitive filter state and explore form data may persist in the cache backend indefinitely if default timeout is 0/None, violating data retention requirements.

**Remediation:**

Pass explicit timeout values to cache.set() calls in CreateFilterStateCommand.create() and CreateFormDataCommand.run(), using configuration values with sensible defaults (e.g., 86400 seconds). This enforces maximum retention regardless of default configuration and aligns with the pattern established by QueryCacheManager.

---

#### FINDING-042: Expired Entry Cleanup Only Triggered Opportunistically

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | |
| ASVS Section(s) | 14.2.7 |
| Files | superset/extensions/metastore_cache.py, superset/daos/key_value.py |
| Source Reports | 14.2.7.md |
| Related Findings | |

**Description:**

Expired KeyValueEntry records remain in the database after their expires_on date if no new add() operations trigger cleanup. The delete_expired_entries() method is only called within SupersetMetastoreCache.add(), not on a schedule. This means outdated sensitive data may remain stored longer than intended, violating automatic deletion requirements for data retention.

**Remediation:**

Ensure scheduled cleanup tasks cover metastore cache entries, or add periodic cleanup independent of write operations. Implement a background task or cron job that regularly invokes delete_expired_entries() to guarantee timely removal of expired sensitive data.

---

#### FINDING-043: DatabaseSSHTunnel Schema Includes Credential Fields Without Output-Specific Exclusion

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | CWE-212 |
| ASVS Section(s) | 14.2.6 |
| Files | superset/databases/schemas.py |
| Source Reports | 14.2.6.md |
| Related Findings | |

**Description:**

The DatabaseSSHTunnel schema includes password, private_key, and private_key_password fields without load_only=True annotation. If used for response serialization without pre-masking, SSH tunnel credentials could be returned in API responses. Even for admin-only endpoints, credentials in responses are subject to secondary exposure via logs, caches, and observability tools. Per profile: credential masking required regardless of caller privilege.

**Remediation:**

Use marshmallow's load_only=True for credential fields (password, private_key, private_key_password) or create separate input/output schemas. This ensures credentials are only accepted on input and never serialized in API responses, reducing exposure via logs, caches, and observability tools.

#### FINDING-044: File Upload Processing Does Not Strip Metadata from Uploaded Files

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L3 |
| CWE | - |
| ASVS Section(s) | 14.2.8 |
| Files | superset/databases/schemas.py |
| Source Reports | 14.2.8.md |
| Related | - |

**Description:**

File upload pipeline validates extension only; no metadata stripping step exists for Excel files which may contain PII (author, organization, last modified by). While pandas DataFrame extraction typically ignores file-level metadata, the original file may be stored temporarily with metadata intact. This violates the requirement to remove sensitive information from metadata of user-submitted files unless storage is consented to by the user.

**Remediation:**

Add a metadata stripping step using openpyxl for Excel files before processing. This should remove document properties (author, organization, last modified by, etc.) from uploaded files to prevent unintended PII storage. Consider implementing this for all supported file formats that can contain metadata.

---

#### FINDING-045: Prophet Forecast Periods Field Lacks Upper Bound, Enabling Resource-Intensive Computation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-400 |
| ASVS Section(s) | 15.2.2 |
| Files | superset/charts/schemas.py |
| Source Reports | 15.2.2.md |
| Related | FINDING-004, FINDING-012, FINDING-030 |

**Description:**

User-supplied integer → `ChartDataProphetOptionsSchema.periods` → Prophet forecasting library → unbounded computation. Large period values (e.g., 10,000,000) force the Prophet library to generate an equally large forecast dataframe.

**Remediation:**

Add Range(max=10000) or configurable upper bound via app.config["MAX_PROPHET_PERIODS"] to the periods field validation.

---

#### FINDING-046: Stacktrace Exposed to Clients in Visualization Error Responses

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-209 |
| ASVS Section(s) | 15.2.3 |
| Files | superset/viz.py |
| Source Reports | 15.2.3.md |
| Related | FINDING-005 |

**Description:**

In superset/viz.py BaseViz.get_df_payload(), stacktraces are unconditionally included in error responses to authenticated clients without checking the SHOW_STACKTRACE configuration flag that is applied elsewhere in the codebase. This exposes internal file paths, library versions, code structure, and database driver details.

**Remediation:**

Gate stacktrace inclusion behind current_app.debug or current_app.config.get("SHOW_STACKTRACE") check, matching the pattern used in superset/utils/core.py.

---

#### FINDING-047: Dynamic Method Dispatch on User-Controlled Input Without Whitelist

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2, L3 |
| CWE | CWE-470 |
| ASVS Section(s) | 15.2.5, 15.3.5 |
| Files | superset/viz.py |
| Source Reports | 15.2.5.md, 15.3.5.md |
| Related | - |

**Description:**

User-controlled `form_data["resample_method"]` is passed to `getattr()` on a pandas Resampler object without whitelist validation. While practical impact is limited (target object has safe no-argument methods), this is inconsistent with the pattern used by `apply_rolling()` which validates `rolling_type` against a known set.

**Remediation:**

Add ALLOWED_RESAMPLE_METHODS whitelist and validate before getattr() call, matching the pattern already used by apply_rolling() for rolling_type.

---

#### FINDING-048: DashboardDatasetSchema Exposes Internal SQL Definitions and Operational Metadata to Guest Users

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-200 |
| ASVS Section(s) | 15.3.1 |
| Files | superset/dashboards/schemas.py |
| Source Reports | 15.3.1.md |
| Related | FINDING-040, FINDING-060 |

**Description:**

The `DashboardDatasetSchema.post_dump()` removes only `owners` and `database` for guest users but leaves `sql`, `select_star`, `perm`, `edit_url`, `fetch_values_predicate`, `template_params` exposed. Guest users (untrusted per threat model) receive internal SQL definitions, permission strings, and internal URL paths that could aid reconnaissance.

**Remediation:**

Extend the guest user post_dump filter to also remove sql, select_star, perm, edit_url, fetch_values_predicate, and template_params fields.

---

#### FINDING-049: Explore View Form Data Merging Without Schema Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-915 |
| ASVS Section(s) | 15.3.3 |
| Files | superset/views/utils.py |
| Source Reports | 15.3.3.md |
| Related | FINDING-061 |

**Description:**

The explore view's `get_form_data` merges parameters from multiple sources (JSON body, form body, query string) using dict.update() without Marshmallow schema validation. The REJECTED_FORM_DATA_KEYS denylist blocks known-dangerous keys but is less robust than the allowlist approach used by REST API endpoints.

**Remediation:**

Replace the REJECTED_FORM_DATA_KEYS denylist with a schema-based allowlist (Marshmallow schema with Meta: unknown = EXCLUDE) for the explore view form_data path.

---

#### FINDING-050: Authentication failure logs in jwt_verifier.py lack request context metadata (who/where)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-778 |
| ASVS Section(s) | 16.2.1 |
| Files | superset/mcp_service/jwt_verifier.py |
| Source Reports | 16.2.1.md |
| Related | FINDING-013, FINDING-052 |

**Description:**

Authentication failure events are logged at WARNING level with only the generic failure reason. The log entry does not explicitly include request metadata (source IP, request path, correlation ID) that would be needed for forensic investigation. While Python's logging formatter CAN inject some of this data (e.g., via request-scoped context), the application code does not ensure it. For the `logs` database table entries, the schema includes user_id, action, dttm, path — but JWT authentication failures in the MCP service go to Python logging, not the database table.

**Remediation:**

Include client IP address and request path in the `_auth_error_handler` WARNING log to support forensic investigation of authentication attacks against the MCP endpoint.

---

#### FINDING-051: Log pruning uses timezone-naive datetime.now() instead of UTC-aware datetime

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-187 |
| ASVS Section(s) | 16.2.2 |
| Files | superset/commands/logs/prune.py |
| Source Reports | 16.2.2.md |
| Related | - |

**Description:**

The datetime.now() call returns the current local time as a timezone-naive datetime object. If Log.dttm stores UTC timestamps (as recommended by the domain context: "Timestamps are server-generated (UTC recommended)"), and the server's local timezone is not UTC, this comparison will be incorrect by the offset amount. On a UTC+5 server, this would delete logs that are 5 hours younger than intended, effectively reducing retention by 5 hours.

**Remediation:**

Replace datetime.now() with datetime.now(tz=timezone.utc) to ensure log retention operates correctly regardless of server timezone configuration.

---

#### FINDING-052: Error Sanitization Utility Does Not Log Security-Relevant Bypass Indicators Before Redaction

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-778 |
| ASVS Section(s) | 16.3.3 |
| Files | superset/mcp_service/utils/error_sanitization.py |
| Source Reports | 16.3.3.md |
| Related | FINDING-013, FINDING-050 |

**Description:**

The `_sanitize_validation_error` function redacts sensitive information from error responses but does not log the original unsanitized error server-side. If the calling code does not log the original exception before calling this sanitization function, evidence of input validation bypass attempts (SQL injection probes, schema discovery) would be lost.

**Remediation:**

Add optional server-side logging within the sanitization function, or ensure callers log the original exception before sanitizing.

---

#### FINDING-053: DEBUG-Level Logs Include Attacker-Controlled JWT Claim Values Without Encoding

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-117 |
| ASVS Section(s) | 16.4.1 |
| Files | superset/mcp_service/jwt_verifier.py |
| Source Reports | 16.4.1.md |
| Related | - |

**Description:**

JWT claim values (algorithm from header, issuer, audience, client_id) are logged at DEBUG level using Python's `%s` formatting without sanitization of control characters. An attacker can craft a JWT with claims containing newlines to inject fake log entries. The `token_alg` value is logged before signature verification (fully attacker-controlled). Impact limited to DEBUG level which is typically disabled in production.

**Remediation:**

Create a `_sanitize_for_log()` helper that replaces newlines and control characters, and apply it to all JWT claim values logged at DEBUG level. Alternatively, configure structured JSON logging for the MCP service.

---

#### FINDING-054: JWT verifier catch-all does not explicitly handle network-related exceptions from JWKS endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-755 |
| ASVS Section(s) | 16.5.2 |
| Files | superset/mcp_service/jwt_verifier.py |
| Source Reports | 16.5.2.md |
| Related | - |

**Description:**

When the JWKS endpoint is unreachable, network exceptions (`ConnectionError`, `TimeoutError`, `OSError`) are not explicitly caught by the application's error handling. These would propagate to Starlette's default handler, resulting in HTTP 500 instead of a clean 401 response. Authentication still fails closed (not fail-open), but the error response is degraded. DOWNGRADED from Low: authentication remains fail-closed; impact is limited to HTTP 500 vs 401 response code during JWKS outages.

**Remediation:**

Broaden the exception handling to include network-related errors, or add `Exception` as a catch-all with appropriate logging.

### 3.5 Informational

#### FINDING-055: Embedded Superset Shares Origin Unless Explicitly Deployed Separately

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.5.4 |
| **Files** | superset/config.py:1556-1575 |
| **Source Reports** | 3.5.4.md |
| **Related** | None |

**Description:**

Superset supports an embedded mode (EMBEDDED_SUPERSET feature flag) where dashboards can be embedded in third-party applications via iframes. The application uses guest tokens (JWTs with scoped permissions) for authentication in embedded contexts, which provides logical separation. However, the codebase does not enforce that embedded instances run on separate hostnames from the main application — this is a deployment decision. From a same-origin policy perspective, if the embedded Superset iframe shares the same hostname as the parent application, the same-origin policy doesn't provide isolation between them. The guest token mechanism provides application-level isolation but not browser-level origin isolation. If same-hostname deployment is used, cookie scope and DOM access are shared between the main application and embedded contexts, potentially allowing JavaScript in one context to interfere with the other.

**Remediation:**

Deployment documentation should mandate that embedded Superset instances are served from a different hostname than the parent application. The GUEST_TOKEN_JWT_AUDIENCE configuration supports this pattern. In deployment configuration, use separate subdomain for embedding: GUEST_TOKEN_JWT_AUDIENCE = "https://embedded.superset.example.com". Create deployment guidance mandating that EMBEDDED_SUPERSET instances use a distinct hostname from the main Superset application to leverage browser-native origin isolation.

---

#### FINDING-056: CDN-Hosted Assets via STATIC_ASSETS_PREFIX Lack SRI Enforcement Mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.6.1 |
| **Files** | superset/config.py:1117 |
| **Source Reports** | 3.6.1.md |
| **Related** | None |

**Description:**

When STATIC_ASSETS_PREFIX is configured to point to an external CDN, the application does not generate or enforce Subresource Integrity (SRI) attributes on script and link tags. This means that if a CDN is compromised or a network-level MITM attack occurs between users and the CDN, arbitrary JavaScript could be injected into all user sessions without integrity verification.

**Remediation:**

When STATIC_ASSETS_PREFIX points to an external CDN, the build pipeline should generate an integrity manifest and templates should include integrity attributes. Example: &lt;script src="{{ assets_prefix }}/static/assets/main.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous" nonce="{{ get_nonce() }}"&gt;&lt;/script&gt;. The project should document that SRI is required when using CDN-hosted assets, or provide a configuration option to define integrity hashes.

---

#### FINDING-057: HSTS Preload Is a Deployment Infrastructure Concern — N/A for Application Code

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L3 |
| **CWE** | N/A |
| **ASVS Section(s)** | 3.7.4 |
| **Files** | N/A |
| **Source Reports** | 3.7.4.md |
| **Related** | None |

**Description:**

This requirement is not applicable to the application code audit. HSTS preload list submission is a deployment-layer concern that depends on the specific domain under which Superset is deployed. The application cannot know its production TLD at build time. Per the project's documented architecture, HSTS header injection (including the `preload` directive) is delegated to the reverse proxy/load balancer layer. The application exposes the `TALISMAN_CONFIG` with `force_https: False` as a development convenience, with the expectation that production deployments configure HSTS at the infrastructure layer. The HSTS preload list is maintained at https://hstspreload.org/ and requires: 1. A valid HTTPS deployment (TLS termination = deployment concern), 2. An `includeSubDomains` directive (header injection = deployment concern), 3. A `max-age` ≥ 1 year (header injection = deployment concern), 4. Manual submission of the domain by the deployment operator. None of these steps can be performed by the application code itself.

**Remediation:**

HSTS preload list submission is a deployment infrastructure concern that must be handled by operators at the deployment layer. Ensure production deployments configure HSTS headers at the reverse proxy/load balancer layer with appropriate `max-age`, `includeSubDomains`, and `preload` directives, then submit the domain to https://hstspreload.org/.

---

#### FINDING-058: MCP JWT verifier does not validate token type claim

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-345 |
| **ASVS Section(s)** | 9.2.2 |
| **Files** | superset/mcp_service/jwt_verifier.py |
| **Source Reports** | 9.2.2.md |
| **Related** | FINDING-059 |

**Description:**

MCP JWT verifier does not validate token type (typ header or token_use claim). DOWNGRADED from Low to Informational: no concrete attack scenario exists — modern IdPs use different signing keys or audience values for different token types, and scope requirements (required_scopes) provide implicit type differentiation. This is a hardening observation.

**Remediation:**

Add token type validation checking for standard claims (token_use, typ) that differentiate access tokens from ID tokens or refresh tokens.

---

#### FINDING-059: Missing explicit audience claim in tokens signed with shared SECRET_KEY

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-345 |
| **ASVS Section(s)** | 9.2.4 |
| **Files** | superset/utils/oauth2.py, superset/async_events/async_query_manager.py |
| **Source Reports** | 9.2.4.md |
| **Related** | FINDING-058 |

**Description:**

Internally-issued JWTs (OAuth2 state, async query) lack explicit aud claims. DOWNGRADED from Low to Informational: no concrete exploit path exists — async query tokens use a separate signing key (GLOBAL_ASYNC_QUERIES_JWT_SECRET), and OAuth2 state tokens are validated via Marshmallow schema requiring Superset-specific fields, preventing practical cross-type confusion.

**Remediation:**

Add explicit aud claims to internally-issued JWTs and validate on decode for defense-in-depth.

---

#### FINDING-060: DeckContour Returns Complete Raw Data Object in `_originalData` Property

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | superset/viz.py |
| **Source Reports** | 15.3.1.md |
| **Related** | FINDING-040, FINDING-048 |

**Description:**

DeckContour.get_properties() includes all original row data in `_originalData` field. DOWNGRADED: User already has authorized datasource access; no concrete attack scenario with meaningful impact beyond the data minimization principle violation. Other DeckGL visualizations (DeckScatter, DeckGrid, DeckHex) selectively include only needed properties.

**Remediation:**

Remove `_originalData` from DeckContour.get_properties() since tooltip columns are already added selectively.

---

#### FINDING-061: Unrestricted form_data Consumption in BaseViz Without Field-Level Allowlisting

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-915 |
| **ASVS Section(s)** | 15.3.3 |
| **Files** | superset/viz.py |
| **Source Reports** | 15.3.3.md |
| **Related** | FINDING-049 |

**Description:**

BaseViz accepts form_data dict without per-viz-type allowlisting. DOWNGRADED: Marshmallow schemas at the API layer provide primary mass-assignment protection, sanitize_clause() handles SQL fields, and this is deprecated code (deprecated_in="3.0"). No concrete bypass of upstream schema validation demonstrated.

**Remediation:**

Consider defining explicit allowed form_data keys per visualization type as defense-in-depth, rejecting unrecognized keys at the viz layer.

---

#### FINDING-062: Explicit Multi-Source Parameter Merging in Explore View

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-235 |
| **ASVS Section(s)** | 15.3.7 |
| **Files** | superset/views/utils.py |
| **Source Reports** | 15.3.7.md |
| **Related** | None |

**Description:**

The explore view merges form_data from three sources (JSON body, form body, query string) with query string taking precedence. DOWNGRADED: This is the intentional mechanism for Superset's explore URL sharing feature. Merging follows deterministic precedence, Flask prevents duplicate key ambiguity within each source, and RBAC/RLS still apply to the resulting query. No privilege escalation demonstrated.

**Remediation:**

Consider adding debug logging when override occurs between sources for auditability.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Input Validation And Injection | SVG upload restricted to admin role (trusted boundary) | source: Dropped finding ASVS-121-LOW-001 | — |
| Input Validation And Injection | Database schema names sourced from operator-controlled infrastructure within trust boundary | Schema names originate from operator-controlled database infrastructure (trusted per deployment_infrastructure_delegated.md); finding confirms no data access bypass or code execution is achievable | — |
| Input Validation And Injection | SVG sanitization scoped to admin-provided content only, with documented trust assumption in docstring | Dropped finding ASVS-134-LOW-001 - function docstring documents 'Assumes admin-provided content' and SVG content is admin-only | — |
| Business Logic Validation | CreateFilterStateCommand.create() performs access check via check_access(resource_id) | Mitigates immediate impact of missing validate() call in CreateTemporaryCacheCommand | superset/commands/temporary_cache/create.py |
| Business Logic Validation | Fail-closed behavior via AttributeError on _async_channel_id | If run() is called without prior validate(), an AttributeError will raise preventing execution | superset/commands/chart/data/create_async_job_command.py |
| Business Logic Validation | Anti-automation and rate limiting explicitly delegated to deployment infrastructure (API gateway, reverse proxy, WAF layer) | source: Report confirmation of deployment_infrastructure_delegated.md | — |
| Browser Security Controls | Security headers delegated to deployment infrastructure (HSTS, CSP, X-Content-Type-Options, Referrer-Policy, frame-ancestors/X-Frame-Options) | Documented architecture delegates header enforcement to reverse proxy with Talisman providing defense-in-depth | — |
| Browser Security Controls | Existing CSP/CORS/Content-Type controls provide mitigation for unintended content interpretation | Application layer mitigation for Sec-Fetch-* header concerns | — |
| Browser Security Controls | Cookie prefix policy delegated to deployment infrastructure based on TLS posture | Infrastructure handles __Host-/__Secure- prefix enforcement according to TLS configuration | — |
| Browser Security Controls | Safe text rendering practices implemented | ASVS 3.2.2 verification passed - application uses safe rendering functions like createTextNode/textContent | — |
| Browser Security Controls | DOM clobbering protections in place | ASVS 3.2.3 verification passed - explicit variable declarations, type checking, namespace isolation implemented | — |
| Browser Security Controls | Secure cookie attributes properly configured | ASVS 3.3.1 verification passed - cookies use Secure attribute with appropriate prefixes | — |
| Browser Security Controls | Cookie size limits enforced | ASVS 3.3.5 verification passed - cookies stay within 4096 byte limit | — |
| Browser Security Controls | CORS Access-Control-Allow-Origin properly validated | ASVS 3.4.2 verification passed - Origin header validated against allowlist or fixed value used | — |
| Browser Security Controls | Security documentation defines required browser security features | ASVS 3.1.1 verification passed - documentation states expected HTTPS, HSTS, CSP, and HTTP security mechanisms | — |
| Browser Security Controls | CSP reporting endpoint is deployment-specific; configuration override mechanism available for operators | Profile: deployment_infrastructure_delegated.md | — |
| Browser Security Controls | COOP header delegated to reverse proxy; operator can add via OVERRIDE_HTTP_HEADERS config | Profile: deployment_infrastructure_delegated.md | — |
| Browser Security Controls | Guest token isolation for embedded contexts | Embedded dashboards use separate JWTs with scoped permissions rather than sharing the main session cookie | superset/config.py:1556-1575 |
| Browser Security Controls | JWT audience validation for embedded mode | GUEST_TOKEN_JWT_AUDIENCE configuration allows deployment to enforce audience-based token validation | superset/config.py:1556-1575 |
| Browser Security Controls | AppRootMiddleware path isolation | Supports path-based separation and deploying Superset under a specific path prefix, enabling reverse-proxy-based hostname routing | superset/app.py:173-192 |
| Browser Security Controls | Layered CSRF defense | Multiple layers of cross-origin protection: CSRF tokens (primary), SameSite=Lax cookies (secondary), and restrictive CORS origins (tertiary) | — |
| Browser Security Controls | CSP with nonces and strict-dynamic | Talisman configuration uses 'strict-dynamic' with nonces, which is the modern best-practice approach to script execution control and provides robust protection against XSSI attacks | superset/config.py:1423-1456, superset/templates/superset/macros.html |
| Browser Security Controls | Minimal CORS configuration | CORS origin list only includes map tile services that the frontend visualization layer needs to access, far more restrictive than many applications | superset/config.py:CORS_OPTIONS |
| Browser Security Controls | CSP object-src restriction | Talisman config prevents plugin-based cross-origin attacks | superset/config.py:TALISMAN_CONFIG |
| Browser Security Controls | Domain context acknowledgment | Project explicitly identifies postMessage validation as a frontend requirement | — |
| Browser Security Controls | No JSONP callback parameter handling | All provided files show no callback parameter handling for JSONP | All provided files |
| Browser Security Controls | Standard CORS for cross-origin | Flask-CORS used with restrictive origin list instead of JSONP for cross-origin resource access | superset/config.py:ENABLE_CORS, superset/config.py:CORS_OPTIONS |
| Browser Security Controls | Standard JSON responses | API responses use standard JSON (application/json) without callback wrapping | All API endpoints |
| Browser Security Controls | Guest token isolation for embedded dashboards | Purpose-built guest tokens with scoped permissions and short TTL (300 seconds) for embedded architecture | — |
| Browser Security Controls | Static file serving without dynamic data injection | SupersetApp.send_static_file only serves files from the static directory without dynamic content injection | superset/app.py:SupersetApp.send_static_file |
| Browser Security Controls | Hot-update handler returns empty 204 responses | The hot-update handler returns empty 204 responses for missing files, preventing data leakage | superset/app.py:SupersetApp.send_static_file |
| Browser Security Controls | CSP nonce mechanism for inline scripts | The macros.html template provides a get_nonce() macro for CSP nonce injection, ensuring only explicitly authorized inline scripts execute | superset/templates/superset/macros.html:get_nonce() |
| Browser Security Controls | JSON API responses use proper content-type | API endpoints return application/json content-type, which browsers won't execute as script even if included via script src | — |
| Browser Security Controls | SameSite cookie policy (Lax) | SESSION_COOKIE_SAMESITE = 'Lax' effectively prevents authenticated resources from being loadable cross-origin via <img>, <script>, <link>, or fetch() since the session cookie won't be included | superset/config.py:SESSION_COOKIE_SAMESITE |
| Browser Security Controls | CORS origin restriction | CORS_OPTIONS limits allowed origins to tile server domains only, preventing programmatic cross-origin access | superset/config.py:CORS_OPTIONS |
| Browser Security Controls | CSP script-src strict-dynamic | Prevents cross-origin script injection | superset/config.py:TALISMAN_CONFIG |
| Browser Security Controls | CSP object-src none | Blocks plugin-based embedding | superset/config.py:TALISMAN_CONFIG |
| Browser Security Controls | Embedded mode uses separate auth | Guest tokens via X-GuestToken header (not cookies) are used for embedded dashboards, providing intentional cross-origin access without relying on cookie behavior | — |
| Browser Security Controls | CSP nonce generation | The macros.html template provides nonce generation for inline scripts, supporting the strict-dynamic CSP policy. This prevents XSS even if content injection occurs | superset/templates/superset/macros.html |
| Browser Security Controls | Local asset hosting by default | STATIC_ASSETS_PREFIX is set to empty string by default, meaning all JavaScript, CSS, and font assets are served from the same origin, eliminating the need for SRI in default deployment | superset/config.py:1117 |
| Browser Security Controls | Restricted external resource domains | THEME_FONT_URL_ALLOWED_DOMAINS limits external font loading to well-known, trusted CDNs (Google Fonts, Adobe Fonts) | superset/config.py |
| Browser Security Controls | Font URLs limited by count and domain | THEME_FONTS_MAX_URLS = 15 and HTTPS-only enforcement on font URLs prevent abuse of the font loading mechanism | superset/config.py |
| Browser Security Controls | Modern framework (React) | Domain context - no deprecated technologies used | — |
| Browser Security Controls | No plugin references | All provided files - no NSAPI, Flash, Shockwave, ActiveX, Silverlight, NACL, or Java applet references | — |
| Browser Security Controls | CSP object-src: 'none' in both TALISMAN_CONFIG and TALISMAN_DEV_CONFIG | Unconditionally blocks all <object>, <embed>, and <applet> elements, providing browser-enforced prevention of deprecated plugin technologies | superset/config.py |
| Browser Security Controls | VIZ_TYPE_DENYLIST configuration | Provides operators a mechanism to block specific visualization types if any were to use deprecated technologies | — |
| Browser Security Controls | Authentication redirects delegated to Flask-AppBuilder | Login/logout redirect validation is handled by Flask-AppBuilder's security manager, which includes `next` parameter validation | — |
| Browser Security Controls | ALERT_REPORTS_ENABLE_LINK_REDIRECT | External links in alert/report emails are rewritten to go through a warning page, providing controlled navigation for that specific flow | superset/config.py |
| Browser Security Controls | Admin-only external URL configuration | Settings like `LOGO_TARGET_PATH` that could point to external URLs are admin-only configuration, which falls within the admin trust boundary | superset/config.py |
| Browser Security Controls | HTML_SANITIZATION = True - Markdown content is sanitized | Markdown content is sanitized, limiting the ability to inject deceptive external links into dashboard content | superset/config.py |
| Browser Security Controls | Configurable behavior - Warning page mechanism is configurable | The warning page mechanism is configurable, allowing deployment operators to enable/disable based on their security requirements | superset/config.py |
| Browser Security Controls | Talisman integration available | Flask-Talisman is configured and could set HSTS headers if `force_https` were enabled, providing operators a mechanism for development/testing | superset/config.py |
| Browser Security Controls | Clear architectural delegation | The project documents that HSTS is a deployment-layer responsibility, which is appropriate for an application that can be deployed under any domain | — |
| Browser Security Controls | Defense-in-depth Talisman configuration | Even though CSP is primarily delegated to the reverse proxy, the application includes Talisman configuration as a secondary layer | superset/config.py:1423-1456 |
| Browser Security Controls | Graceful CSP degradation | The use of 'strict-dynamic' alongside 'self' means browsers not supporting Level 2 fall back to the 'self' directive rather than failing open with no policy | superset/config.py:1423-1456 |
| Browser Security Controls | React 18 framework choice | The technology stack decision to use React 18 (which requires ES6+, dropped IE11) acts as an implicit gate ensuring only browsers with modern security feature support can load the application | — |
| Http Security | Internal service communication (Celery, Redis) operates within operator-trusted infrastructure boundary | source: Dropped finding ASVS-415-INFO-001 | — |
| File Handling | File types centrally enumerated in UploadFileType StrEnum with RBAC permissions per type | Promoted from dropped finding ASVS-511-LOW-001 | — |
| File Handling | Implicit content validation via pyarrow parser rejects non-parquet content regardless of extension | Promoted from dropped finding ASVS-522-LOW-001 | — |
| File Handling | Schema-level upload restrictions and RBAC permissions limit upload scope; database storage limits delegated to operator | Promoted from dropped finding ASVS-524-LOW-001 | — |
| File Handling | In-memory-only ZIP extraction (BytesIO) eliminates symlink traversal by design | Files are read into BytesIO memory buffers, never extracted to filesystem. Symlink traversal is physically impossible in the current architecture. | — |
| File Handling | Upload-to-database architecture (files parsed into DataFrames, never stored/served as files) eliminates malicious content serving by design | source: Dropped finding ASVS-543-LOW-001 | — |
| Authentication | FAB auth rate limiting applied to auth blueprint POST methods via AUTH_RATE_LIMITED config | Implements ASVS 6.1.1 and 6.3.1 anti-automation controls | — |
| Authentication | Login failure audit logging via _log_audit_event(UserLoginFailed) | Supports detection of credential stuffing and brute force attacks per ASVS 6.1.1 | — |
| Authentication | FAB resetmypassword view requires current password for password changes | Password reset flows delegated to Flask-AppBuilder, satisfies ASVS 6.2.3 | — |
| Authentication | Comprehensive audit logging of login/logout/failure events via _log_audit_event() for operator-side detection | Provides audit trail for suspicious authentication attempts (ASVS 6.3.5 partial implementation) | — |
| Authentication | Credential changes require Admin role (trusted) | Referenced in admin_role_trusted.md, supports ASVS 6.3.7 security model | — |
| Authentication | FAB-delegated flows for credential management | Referenced in flask_appbuilder_security_controls.md, centralizes authentication security | — |
| Authentication | No untrusted principal can trigger credential changes | Noted in dropped finding rationale for ASVS 6.3.7 | — |
| Authentication | Password reset flow delegated to Flask-AppBuilder with email-token-based reset | source: Report positive pattern | — |
| Authentication | Admin role is fully trusted with deployment-equivalent privileges; admin password-setting capability is by design | source: Dropped finding ASVS-646-INFO-001 | — |
| Authentication | MCP_USER_RESOLVER is configurable, allowing deployments to implement IdP-namespaced resolution | Promoted from dropped finding ASVS-681-INFO-001 | — |
| Authentication | Claims preserved in AccessToken.claims dict enabling custom MCP_USER_RESOLVER to validate acr/amr/auth_time per deployment policy | Promoted from dropped finding ASVS-684-LOW-001 | — |
| Session Management | Session lifecycle configuration delegated to Flask-AppBuilder and deployment operator | Promoted from dropped finding ASVS-711-INFO-001 | — |
| Session Management | Concurrent session policy delegated to Flask-AppBuilder | Session lifecycle (concurrent-session policy) explicitly delegated to Flask-AppBuilder per flask_appbuilder_security_controls.md | — |
| Session Management | Federated identity session coordination delegated to Flask-AppBuilder | OAuth/OIDC/SAML provider integration (protocol-level enforcement) delegated to Flask-AppBuilder per flask_appbuilder_security_controls.md | — |
| Session Management | Default configuration uses self-contained tokens (signed cookies), not reference tokens | Noted in dropped finding ASVS-723-INFO-001 | — |
| Session Management | Session lifecycle delegated to FAB per flask_appbuilder_security_controls.md | Referenced in filter reasoning for dropped finding | — |
| Session Management | Session expiration configuration delegated to Flask-AppBuilder and deployment operator | source: Dropped finding ASVS-731-LOW-001 | — |
| Session Management | Session lifetime enforcement delegated to Flask-AppBuilder and deployment operator | source: Dropped finding ASVS-732-LOW-001 | — |
| Session Management | Guest tokens have 5-minute absolute expiry with resource scoping and embedded RLS rules | source: Dropped finding ASVS-741-LOW-001 | — |
| Session Management | Session invalidation delegated to Flask-AppBuilder | Promoted from dropped finding ASVS-742-MED-001 | — |
| Session Management | Session termination on credential change delegated to Flask-AppBuilder | source: Dropped finding ASVS-743-MED-001 | — |
| Session Management | Logout visible by default; DISABLE_EMBEDDED_SUPERSET_LOGOUT defaults to False | source: Dropped finding ASVS-744-LOW-001 | — |
| Session Management | Session management infrastructure delegated to Flask-AppBuilder | Dropped finding ASVS-745-MED-001 | — |
| Session Management | Re-authentication flows delegated to Flask-AppBuilder; user modification API restricted to trusted admin role | source: Dropped finding ASVS-751-MED-001 | — |
| Session Management | Session management UI/capability delegated to Flask-AppBuilder | source: Dropped finding ASVS-752-MED-001 | — |
| Session Management | Admin role trusted; admin operations protected by RBAC and CSRF per documented design decision | Dropped finding ASVS-753-LOW-001 | — |
| Session Management | Session lifecycle and federated session coordination delegated to Flask-AppBuilder OAuth/SAML managers | Dropped finding ASVS-761-LOW-001 | — |
| Authorization And Rbac | Authorization rules comprehensively defined through programmatic constants (ADMIN_ONLY_VIEW_MENUS, ALPHA_ONLY_VIEW_MENUS, OBJECT_SPEC_PERMISSIONS, role sync definitions) | Promoted from dropped finding ASVS-811-LOW-001 | — |
| Authorization And Rbac | Field-level access controls implemented via SENSITIVE_FIELDS, SENSITIVE_FIELD_PERMISSIONS, credential masking, and REST API schema projections | Implemented and enforced throughout the application | — |
| Authorization And Rbac | Environmental/contextual access controls delegated to deployment infrastructure (WAF, reverse proxy, identity provider) | Dropped finding ASVS-813-INFO-001 | — |
| Authorization And Rbac | Contextual access decisions delegated to external infrastructure (WAF, identity provider conditional access policies) | source: Dropped finding ASVS-814-INFO-001 | — |
| Authorization And Rbac | MCP service implements comprehensive field-level permissions via SENSITIVE_FIELDS/SENSITIVE_FIELD_PERMISSIONS | permissions_utils.py | permissions_utils.py |
| Authorization And Rbac | Adaptive security controls delegated to external infrastructure; MCP_USER_RESOLVER extension point available for deployers | Dropped finding ASVS-824-INFO-001 | — |
| Authorization And Rbac | RLS rules rely on route-level decorator plus DAO base_filters for ownership scoping; absence of raise_for_access is by design | Dropped finding ASVS-841-LOW-001 | — |
| Authorization And Rbac | Admin role is fully trusted; additional verification layers for admin access are delegated to IDP/deployment infrastructure | Dropped finding ASVS-842-MED-001 | — |
| Token Security | Database OAuth2 endpoint configuration is admin-only, placing mix-up attack prerequisites inside the trust boundary | Promoted from dropped finding ASVS-1022-INFO-001 | — |
| Token Security | Token replay prevention relies on expiration and network-level TLS, delegated to deployment operator | Dropped finding ASVS-1035-LOW-001 | — |
| Token Security | MCP key sources use pre-configured operator settings (MCP_JWKS_URI/MCP_JWT_PUBLIC_KEY/MCP_JWT_SECRET); authlib does not honor attacker-supplied jku/x5u/jwk headers without explicit configuration | Promoted from dropped finding ASVS-913-INFO-001 | — |
| Token Security | Async query tokens use a separate signing key (GLOBAL_ASYNC_QUERIES_JWT_SECRET) | Prevents cross-type token confusion with OAuth2 state tokens | superset/async_events/async_query_manager.py |
| Token Security | OAuth2 state tokens validated via Marshmallow schema requiring Superset-specific fields | Prevents practical cross-type confusion attacks | superset/utils/oauth2.py |
| Cryptography | SecretsMigrator supports key rotation with idempotency and transaction safety | Demonstrates key lifecycle management capabilities | — |
| Cryptography | GUEST_TOKEN_JWT_SECRET separated from SECRET_KEY demonstrating key separation awareness | Key separation best practice implemented | — |
| Cryptography | discover_encrypted_fields() provides programmatic cryptographic discovery across FAB and Superset metadata registries | Automated cryptographic inventory discovery mechanism | — |
| Cryptography | SQLALCHEMY_ENCRYPTED_FIELD_TYPE_ADAPTER provides pluggable encryption adapter extension point | Crypto agility design pattern for encryption adapters | — |
| Cryptography | HASH_ALGORITHM + HASH_ALGORITHM_FALLBACKS demonstrates crypto agility pattern for hashing | Configurable and upgradeable hash algorithm implementation | — |
| Cryptography | SHA-256 is the primary hash algorithm for UUID namespace generation | Approved hash function used as default | superset/key_value/utils.py |
| Cryptography | Developer awareness of MD5 security implications | Code includes security awareness comment (# noqa: S324) | superset/key_value/utils.py |
| Cryptography | SSH tunnel configuration is an Admin-only operation within the trusted boundary; key selection is the trusted admin's responsibility | Public key cryptography key selection delegated to trusted administrators | — |
| Cryptography | Memory encryption is an infrastructure-layer responsibility delegated to the deployment operator; not implementable at the Python application layer | In-use data cryptography acknowledged as deployment-layer concern | — |
| Cryptography | Process-level memory protection (core dump prevention, ptrace restrictions) is delegated to deployment operator's OS/container configuration | Data minimization and memory protection documented as deployment-layer concern | — |
| Tls And Transport Security | All internal service configuration knobs accept TLS-enabled protocol variants (rediss://, https://, wss://, sslmode=verify-full) | source: Dropped finding ASVS-1233-INFO-001 | — |
| Tls And Transport Security | Redis SSL cert_reqs defaults to 'required' ensuring certificate validation when SSL is enabled | CACHE_REDIS_SSL_CERT_REQS defaults to 'required' when SSL enabled | — |
| Tls And Transport Security | Redis client certificate configuration knobs (CERTFILE/KEYFILE) available for operator-managed mTLS | source: Dropped finding ASVS-1235-INFO-001 | — |
| Service Communication | Operator-controlled infrastructure configuration and documentation is delegated to deployment operator | Dropped finding ASVS-1311-LOW-001 | — |
| Service Communication | Connection pool tuning for backend services delegated to deployment operator via SQLALCHEMY_ENGINE_OPTIONS and per-service config | source: Dropped finding ASVS-1312-LOW-001 | — |
| Service Communication | Application provides comprehensive timeout and retry configuration hooks (SUPERSET_CLIENT_RETRY_*, SSH_TUNNEL_TIMEOUT_SEC, SQLLAB_TIMEOUT, DISTRIBUTED_LOCK_DEFAULT_TTL) for operator tuning | Promoted from dropped finding ASVS-1313-LOW-001 | — |
| Service Communication | SecretsMigrator provides idempotent secret rotation capability; secret lifecycle management delegated to operator | Dropped finding ASVS-1314-LOW-001 | — |
| Service Communication | SQLALCHEMY_CUSTOM_PASSWORD_STORE hook enables dynamic credential retrieval from external secret managers | source: Dropped finding ASVS-1321-MED-001 | — |
| Service Communication | Network security including TLS cert verification delegated to deployment operator | source: Dropped finding ASVS-1321-LOW-001 | — |
| Service Communication | Application supports independent credential configuration per service tier (cache, coordination, broker) enabling operator-managed least privilege | Dropped finding ASVS-1322-LOW-001 - Application supports separate configs per service tier (CACHE_CONFIG, DATA_CACHE_CONFIG, DISTRIBUTED_COORDINATION_CONFIG) | — |
| Service Communication | Admin role is trusted; database and import operations are admin-only privileges by design | source: Dropped finding ASVS-1324-MED-001 | — |
| Service Communication | Network-level SSRF prevention (firewall rules, network isolation) delegated to deployment operator | source: Dropped finding ASVS-1324-MED-002 | — |
| Service Communication | Outbound connection targets are operator-configured; network-layer allowlisting delegated to deployment infrastructure | All outbound connections are to operator-controlled infrastructure or require Admin-level configuration (trusted per admin_role_trusted.md). Network security delegated to deployment operator per deployment_infrastructure_delegated.md | — |
| Service Communication | Application exposes SQLALCHEMY_ENGINE_OPTIONS and per-service configuration for operator-managed connection pooling | Promoted from dropped finding ASVS-1326-LOW-001 | — |
| Service Communication | Application provides AbstractEncryptedFieldAdapter extension point and SQLALCHEMY_CUSTOM_PASSWORD_STORE hook for operator-managed secret store integration | source: Dropped finding ASVS-1331-MED-001 | — |
| Service Communication | SECRET_KEY loadable from environment variable (SUPERSET_SECRET_KEY), enabling injection from external secret management systems | source: Dropped finding ASVS-1331-MED-001 | — |
| Service Communication | In-process code (extensions, plugins, security managers) operates within a single trust boundary by documented design decision | Documented Design Decisions indicate extensions run in-process with full application privilege by design | — |
| Service Communication | SQLALCHEMY_ENCRYPTED_FIELD_TYPE_ADAPTER configuration allows operators to substitute HSM/vault-backed encryption adapters without code changes | Dropped finding ASVS-1333-MED-001 | — |
| Service Communication | SecretsMigrator provides idempotent key rotation tooling for operator use | Dropped finding ASVS-1334-MED-001 | — |
| Data Protection And Privacy | QueryCacheManager implements explicit timeout passing, establishing a code convention for TTL enforcement | Observed in cache subsystem implementation | superset/common/utils/query_cache_manager.py |
| Data Protection And Privacy | Cache access gated by authentication and RLS filters applied before caching; cache key isolation per user session | Security control preventing sensitive data leakage across user contexts | — |
| Data Protection And Privacy | Session lifecycle (establishment, expiration, invalidation) delegated to Flask-AppBuilder | Framework-level management of authenticated data clearing | — |
| Data Protection And Privacy | Cache-Control and anti-caching headers managed by reverse proxy/deployment infrastructure | Documented in deployment_infrastructure_delegated.md | — |
| Third Party Dependencies | Third-party dependency lifecycle governed by ASF security process | Documented in third_party_dependency_policy.md and referenced in dropped finding ASVS-1524-INFO-001 | — |
| Third Party Dependencies | Rate limiting and IP-based security decisions delegated to deployment infrastructure (ingress/WAF layer) | Report confirms no IP-based security logic in application code | — |
| Third Party Dependencies | Python's object model is structurally immune to prototype pollution attacks | Report confirms N/A for Python backend code | — |
| Third Party Dependencies | Deployment environment filesystem access is within operator trust boundary | source: Dropped finding ASVS-1542-LOW-001 | — |
| Third Party Dependencies | Marshmallow schemas at the API layer provide primary mass-assignment protection | Mentioned in finding ASVS-1533-LOW-002 description | — |
| Third Party Dependencies | sanitize_clause() handles SQL fields | Mentioned in finding ASVS-1533-LOW-002 description | superset/viz.py |
| Third Party Dependencies | REJECTED_FORM_DATA_KEYS denylist blocks known-dangerous keys | Mentioned in finding ASVS-1533-LOW-001 description | superset/views/utils.py |
| Logging And Monitoring | LogPruneCommand is an operator-only scheduled task; database access controls protect log integrity. | Dropped finding ASVS-1642-INFO-001 | — |
| Logging And Monitoring | SIEM integration and log forwarding are operator-configured; application provides structured logs suitable for external consumption. | Promoted from dropped finding ASVS-1643-LOW-001 | — |
| Logging And Monitoring | Framework last-resort error handlers (Starlette ServerErrorMiddleware, Flask error handlers) catch all unhandled exceptions, log them server-side, and prevent process termination | Dropped finding ASVS-1654-INFO-001 | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | **Fail** | See FINDING-001 |
| 1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | **Fail** | See FINDING-001 |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-014 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Fail** | See FINDING-001, FINDING-002 |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Pass** |  |
| 1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | **N/A** |  |
| 1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | **N/A** |  |
| 1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | **N/A** |  |
| 1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | **N/A** |  |
| 1.2.10 | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | **Fail** | See FINDING-003 |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | **Partial** | See FINDING-001, FINDING-016 |
| 1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | **N/A** |  |
| 1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | **Partial** | See FINDING-017 |
| 1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | **Pass** |  |
| 1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | **Partial** | See FINDING-001 |
| 1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | **N/A** |  |
| 1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | **N/A** |  |
| 1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | **Pass** |  |
| 1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | **Partial** | See FINDING-015 |
| 1.3.12 | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | **Partial** | See FINDING-018 |
| 1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | **N/A** |  |
| 1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | **N/A** |  |
| 1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | **N/A** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| 1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | **Pass** |  |
| 1.5.3 | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | **Fail** | See FINDING-001, FINDING-019 |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | **Pass** |  |
| 2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-020, FINDING-021 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.2.3 | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| 2.3.2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | **Partial** | See FINDING-022 |
| 2.3.3 | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | **Pass** |  |
| 2.3.4 | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | **Pass** |  |
| 2.3.5 | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | **N/A** |  |
| 2.4.1 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | **Pass** |  |
| 2.4.2 | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | **N/A** |  |
| **V3: Web Frontend Security** | | | |
| 3.1.1 | Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access). | **Pass** |  |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.2.3 | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Pass** |  |
| 3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **N/A** |  |
| 3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | **N/A** |  |
| 3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | **N/A** |  |
| 3.3.5 | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | **Pass** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | **N/A** |  |
| 3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | **N/A** |  |
| 3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | **N/A** |  |
| 3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | **N/A** |  |
| 3.4.7 | Verify that the Content-Security-Policy header field specifies a location to report violations. | **N/A** |  |
| 3.4.8 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Partial** | See FINDING-023 |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| 3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | **Partial** | See FINDING-055 |
| 3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | **N/A** |  |
| 3.5.6 | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.7 | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.8 | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | **Partial** | See FINDING-024 |
| 3.6.1 | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | **Partial** | See FINDING-056 |
| 3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | **Pass** |  |
| 3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | **Partial** | See FINDING-025 |
| 3.7.3 | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | **Partial** | See FINDING-026 |
| 3.7.4 | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | **N/A** | See FINDING-057 |
| 3.7.5 | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | **Partial** | See FINDING-027 |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Partial** | See FINDING-028 |
| 4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | **Pass** |  |
| 4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | **Pass** |  |
| 4.1.4 | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | **Pass** |  |
| 4.1.5 | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | **N/A** |  |
| 4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | **Pass** |  |
| 4.2.2 | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | **Pass** |  |
| 4.2.3 | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | **Pass** |  |
| 4.2.4 | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | **Partial** | See FINDING-029 |
| 4.2.5 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status. | **Partial** | See FINDING-030 |
| 4.3.1 | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | **N/A** |  |
| 4.3.2 | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | **N/A** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| 4.4.2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | **N/A** |  |
| 4.4.3 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | **N/A** |  |
| 4.4.4 | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.1.1 | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | **N/A** |  |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Fail** | See FINDING-004 |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Pass** |  |
| 5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | **Fail** | See FINDING-016 |
| 5.2.4 | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | **N/A** |  |
| 5.2.5 | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | **Pass** |  |
| 5.2.6 | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** |  |
| 5.3.3 | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | **Fail** | See FINDING-016 |
| 5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | **N/A** |  |
| 5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | **N/A** |  |
| 5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** |  |
| 6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | **N/A** |  |
| 6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | **N/A** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **Pass** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **N/A** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.2.9 | Verify that passwords of at least 64 characters are permitted. | **Pass** |  |
| 6.2.10 | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | **Pass** |  |
| 6.2.11 | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | **N/A** |  |
| 6.2.12 | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | **N/A** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.3.3 | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | **N/A** |  |
| 6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | **Fail** | See FINDING-005 |
| 6.3.5 | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | **N/A** |  |
| 6.3.6 | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | **Pass** |  |
| 6.3.7 | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | **N/A** |  |
| 6.3.8 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | **Partial** | See FINDING-005 |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| 6.4.3 | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | **N/A** |  |
| 6.4.4 | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | **N/A** |  |
| 6.4.5 | Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary. | **N/A** |  |
| 6.4.6 | Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password. | **N/A** |  |
| 6.5.1 | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | **Pass** |  |
| 6.5.2 | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more. | **N/A** |  |
| 6.5.3 | Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values. | **N/A** |  |
| 6.5.4 | Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient). | **N/A** |  |
| 6.5.5 | Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds. | **N/A** |  |
| 6.5.6 | Verify that any authentication factor (including physical devices) can be revoked in case of theft or other loss. | **N/A** |  |
| 6.5.7 | Verify that biometric authentication mechanisms are only used as secondary factors together with either something you have or something you know. | **N/A** |  |
| 6.5.8 | Verify that time-based one-time passwords (TOTPs) are checked based on a time source from a trusted service and not from an untrusted or client provided time. | **N/A** |  |
| 6.6.1 | Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options. | **N/A** |  |
| 6.6.2 | Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one. | **N/A** |  |
| 6.6.3 | Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy. | **N/A** |  |
| 6.6.4 | Verify that, where push notifications are used for multi-factor authentication, rate limiting is used to prevent push bombing attacks. Number matching may also mitigate this risk. | **N/A** |  |
| 6.7.1 | Verify that the certificates used to verify cryptographic authentication assertions are stored in a way protects them from modification. | **N/A** |  |
| 6.7.2 | Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic device. | **N/A** |  |
| 6.8.1 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | **Pass** |  |
| 6.8.2 | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | **Pass** |  |
| 6.8.3 | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | **N/A** |  |
| 6.8.4 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | **N/A** |  |
| **V7: Session Management** | | | |
| 7.1.1 | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | **N/A** |  |
| 7.1.2 | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | **N/A** |  |
| 7.1.3 | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | **N/A** |  |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.3.1 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | **N/A** |  |
| 7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | **N/A** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **N/A** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** |  |
| 7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | **N/A** |  |
| 7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | **Pass** |  |
| 7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | **N/A** |  |
| 7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | **N/A** |  |
| 7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | **N/A** |  |
| 7.5.3 | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | **N/A** |  |
| 7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | **N/A** |  |
| 7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | **Pass** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | **Pass** |  |
| 8.1.3 | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | **N/A** |  |
| 8.1.4 | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | **N/A** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Partial** | See FINDING-031 |
| 8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | **Partial** | See FINDING-032 |
| 8.2.4 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | **N/A** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| 8.3.2 | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | **Partial** | See FINDING-006 |
| 8.3.3 | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | **Pass** |  |
| 8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | **Pass** |  |
| 8.4.2 | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | **N/A** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Partial** | See FINDING-034 |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Partial** | See FINDING-035, FINDING-036 |
| 9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | **Partial** | See FINDING-058 |
| 9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | **Partial** | See FINDING-007 |
| 9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | **Partial** | See FINDING-059 |
| **V10: OAuth and OIDC** | | | |
| 10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | **Pass** |  |
| 10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | **Pass** |  |
| 10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | **Pass** |  |
| 10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | **Pass** |  |
| 10.2.3 | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | **Pass** |  |
| 10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | **Partial** | See FINDING-007 |
| 10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | **Partial** | See FINDING-008 |
| 10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | **Partial** | See FINDING-033 |
| 10.3.4 | Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively. | **N/A** |  |
| 10.3.5 | Verify that the resource server prevents the use of stolen access tokens or replay of access tokens (from unauthorized parties) by requiring sender-constrained access tokens, either Mutual TLS for OAuth 2 or OAuth 2 Demonstration of Proof of Possession (DPoP). | **N/A** |  |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** |  |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** |  |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** |  |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** |  |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** |  |
| 10.4.6 | Verify that, if the code grant is used, the authorization server mitigates authorization code interception attacks by requiring proof key for code exchange (PKCE). For authorization requests, the authorization server must require a valid 'code_challenge' value and must not accept a 'code_challenge_method' value of 'plain'. For a token request, it must require validation of the 'code_verifier' parameter. | **N/A** |  |
| 10.4.7 | Verify that if the authorization server supports unauthenticated dynamic client registration, it mitigates the risk of malicious client applications. It must validate client metadata such as any registered URIs, ensure the user's consent, and warn the user before processing an authorization request with an untrusted client application. | **N/A** |  |
| 10.4.8 | Verify that refresh tokens have an absolute expiration, including if sliding refresh token expiration is applied. | **N/A** |  |
| 10.4.9 | Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens. | **N/A** |  |
| 10.4.10 | Verify that confidential client is authenticated for client-to-authorized server backchannel requests such as token requests, pushed authorization requests (PAR), and token revocation requests. | **N/A** |  |
| 10.4.11 | Verify that the authorization server configuration only assigns the required scopes to the OAuth client. | **N/A** |  |
| 10.4.12 | Verify that for a given client, the authorization server only allows the 'response_mode' value that this client needs to use. For example, by having the authorization server validate this value against the expected values or by using pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | **N/A** |  |
| 10.4.13 | Verify that grant type 'code' is always used together with pushed authorization requests (PAR). | **N/A** |  |
| 10.4.14 | Verify that the authorization server issues only sender-constrained (Proof-of-Possession) access tokens, either with certificate-bound access tokens using mutual TLS (mTLS) or DPoP-bound access tokens (Demonstration of Proof of Possession). | **N/A** |  |
| 10.4.15 | Verify that, for a server-side client (which is not executed on the end-user device), the authorization server ensures that the 'authorization_details' parameter value is from the client backend and that the user has not tampered with it. For example, by requiring the usage of pushed authorization request (PAR) or JWT-secured Authorization Request (JAR). | **N/A** |  |
| 10.4.16 | Verify that the client is confidential and the authorization server requires the use of strong client authentication methods (based on public-key cryptography and resistant to replay attacks), such as mutual TLS ('tls_client_auth', 'self_signed_tls_client_auth') or private key JWT ('private_key_jwt'). | **N/A** |  |
| 10.5.1 | Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server). | **N/A** |  |
| 10.5.2 | Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider). | **N/A** |  |
| 10.5.3 | Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client. | **N/A** |  |
| 10.5.4 | Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client. | **N/A** |  |
| 10.5.5 | Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes). | **N/A** |  |
| 10.6.1 | Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used. | **N/A** |  |
| 10.6.2 | Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'. | **N/A** |  |
| 10.7.1 | Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent. | **N/A** |  |
| 10.7.2 | Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations. | **N/A** |  |
| 10.7.3 | Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.1.1 | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | **N/A** |  |
| 11.1.2 | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | **Pass** |  |
| 11.1.3 | Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations. | **N/A** |  |
| 11.1.4 | Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats. | **Pass** |  |
| 11.2.1 | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | **Pass** |  |
| 11.2.2 | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | **N/A** |  |
| 11.2.3 | Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security. | **Partial** | See FINDING-009 |
| 11.2.4 | Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information. | **Pass** |  |
| 11.2.5 | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks. | **Pass** |  |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Pass** |  |
| 11.3.3 | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm. | **Pass** |  |
| 11.3.4 | Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used. | **Pass** |  |
| 11.3.5 | Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode. | **Pass** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Partial** | See FINDING-037 |
| 11.4.2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | **Pass** |  |
| 11.4.3 | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | **Pass** |  |
| 11.4.4 | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | **Pass** |  |
| 11.5.1 | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | **Fail** | See FINDING-009 |
| 11.5.2 | Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand. | **Pass** |  |
| 11.6.1 | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | **N/A** |  |
| 11.6.2 | Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks. | **N/A** |  |
| 11.7.1 | Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes. | **N/A** |  |
| 11.7.2 | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | **N/A** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | **N/A** |  |
| 12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | **N/A** |  |
| 12.1.4 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | **N/A** |  |
| 12.1.5 | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| 12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | **Fail** | See FINDING-010, FINDING-038 |
| 12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | **Fail** | See FINDING-010 |
| 12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | **N/A** |  |
| 12.3.5 | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | **N/A** |  |
| 13.1.2 | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | **N/A** |  |
| 13.1.3 | Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | **N/A** |  |
| 13.1.4 | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | **N/A** |  |
| 13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | **N/A** |  |
| 13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | **N/A** |  |
| 13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | **Fail** | See FINDING-011 |
| 13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | **N/A** |  |
| 13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | **N/A** |  |
| 13.2.6 | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | **N/A** |  |
| 13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | **N/A** |  |
| 13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | **N/A** |  |
| 13.3.3 | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | **N/A** |  |
| 13.3.4 | Verify that secrets are configured to expire and be rotated based on the application's documentation. | **Partial** | See FINDING-011 |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| 13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | **Pass** | See FINDING-039 |
| 13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | **Pass** |  |
| 13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | **Pass** |  |
| 13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | **Fail** | See FINDING-039, FINDING-040 |
| 13.4.6 | Verify that the application does not expose detailed version information of backend components. | **Fail** | See FINDING-040 |
| 13.4.7 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | **Pass** |  |
| 14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | **Pass** |  |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | **Partial** | See FINDING-041 |
| 14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | **Pass** |  |
| 14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | **Partial** | See FINDING-041 |
| 14.2.5 | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | **Partial** |  |
| 14.2.6 | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | **Partial** | See FINDING-043 |
| 14.2.7 | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | **Partial** | See FINDING-041, FINDING-042 |
| 14.2.8 | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | **Partial** | See FINDING-044 |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| 14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | **N/A** |  |
| 14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Pass** |  |
| 15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | **Pass** |  |
| 15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | **Pass** |  |
| 15.1.4 | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | **Pass** |  |
| 15.1.5 | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | **Pass** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Pass** |  |
| 15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | **Fail** | See FINDING-012, FINDING-045 |
| 15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | **Fail** | See FINDING-046 |
| 15.2.4 | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | **Pass** |  |
| 15.2.5 | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | **Fail** | See FINDING-047 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Fail** | See FINDING-048, FINDING-060 |
| 15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | **N/A** |  |
| 15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | **Partial** | See FINDING-049, FINDING-061 |
| 15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | **N/A** |  |
| 15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | **Fail** | See FINDING-047 |
| 15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | **N/A** |  |
| 15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | **Partial** | See FINDING-062 |
| 15.4.1 | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | **Pass** |  |
| 15.4.2 | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it. | **N/A** |  |
| 15.4.3 | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | **Pass** |  |
| 15.4.4 | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | **Pass** |  |
| **V16: Security Logging and Error Handling** | | | |
| 16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | **Pass** |  |
| 16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | **Partial** | See FINDING-050 |
| 16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | **Partial** | See FINDING-051 |
| 16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | **Pass** |  |
| 16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | **Pass** |  |
| 16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | **Pass** |  |
| 16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | **Partial** | See FINDING-013 |
| 16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | **Pass** |  |
| 16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | **Partial** | See FINDING-052 |
| 16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | **Pass** |  |
| 16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | **Partial** | See FINDING-053 |
| 16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | **Pass** |  |
| 16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | **Partial** |  |
| 16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | **Pass** |  |
| 16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | **Partial** | See FINDING-054 |
| 16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | **Pass** |  |
| 16.5.4 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | **Pass** |  |
| **V17: WebRTC** | | | |
| 17.1.1 | Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses. | **N/A** |  |
| 17.1.2 | Verify that the Traversal Using Relays around NAT (TURN) service is not susceptible to resource exhaustion when legitimate users attempt to open a large number of ports on the TURN server. | **N/A** |  |
| 17.2.1 | Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys. | **N/A** |  |
| 17.2.2 | Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP). | **N/A** |  |
| 17.2.3 | Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams. | **N/A** |  |
| 17.2.4 | Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets. | **N/A** |  |
| 17.2.5 | Verify that the media server is able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | **N/A** |  |
| 17.2.6 | Verify that the media server is not susceptible to the "ClientHello" Race Condition vulnerability in Datagram Transport Layer Security (DTLS) by checking if the media server is publicly known to be vulnerable or by performing the race condition test. | **N/A** |  |
| 17.2.7 | Verify that any audio or video recording mechanisms associated with the media server are able to continue processing incoming media traffic during a flood of Secure Real-time Transport Protocol (SRTP) packets from legitimate users. | **N/A** |  |
| 17.2.8 | Verify that the Datagram Transport Layer Security (DTLS) certificate is checked against the Session Description Protocol (SDP) fingerprint attribute, terminating the media stream if the check fails, to ensure the authenticity of the media stream. | **N/A** |  |
| 17.3.1 | Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level. | **N/A** |  |
| 17.3.2 | Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 110 requirements (31.9%)
- **Partial**: 48 requirements (13.9%)
- **N/A**: 167 requirements (48.4%)
- **Fail**: 20 requirements (5.8%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | High | 1.1.1, 1.1.2, 1.2.4, 1.3.3, 1.3.7, 1.5.3 | FINDING-002 | superset/jinja_context.py |
| FINDING-002 | Medium | 1.2.4 | FINDING-001 | superset/jinja_context.py |
| FINDING-003 | Medium | 1.2.10 | — | superset/commands/database/uploaders/csv_reader.py, superset/commands/database/uploaders/base.py, superset/commands/database/uploaders/columnar_reader.py |
| FINDING-004 | Medium | 5.2.1 | FINDING-012, FINDING-030, FINDING-045 | superset/commands/database/uploaders/columnar_reader.py, superset/commands/database/uploaders/base.py |
| FINDING-005 | Medium | 6.3.4, 6.3.8 | FINDING-046 | superset/mcp_service/auth.py |
| FINDING-006 | Medium | 8.3.2 | FINDING-035, FINDING-036 | superset/security/manager.py, superset/connectors/sqla/models.py |
| FINDING-007 | Medium | 10.3.1, 9.2.3 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-008 | Medium | 10.3.2 | FINDING-031, FINDING-032 | superset/mcp_service/auth.py, superset/mcp_service/jwt_verifier.py |
| FINDING-009 | Medium | 11.2.3, 11.5.1 | — | superset/key_value/utils.py |
| FINDING-010 | Medium | 12.3.1, 12.3.2 | FINDING-038 | superset/config.py |
| FINDING-011 | Medium | 13.2.3, 13.3.4 | — | superset/config.py, superset/constants.py |
| FINDING-012 | Medium | 15.2.2 | FINDING-004, FINDING-030, FINDING-045 | superset/viz.py |
| FINDING-013 | Medium | 16.3.1 | FINDING-050, FINDING-052 | superset/mcp_service/jwt_verifier.py |
| FINDING-014 | Low | 1.2.2 | FINDING-017 | superset/charts/schemas.py, superset/dashboards/schemas.py |
| FINDING-015 | Low | 1.3.11 | — | superset/utils/core.py |
| FINDING-016 | Low | 1.3.3, 5.2.3, 5.3.3 | — | superset/commands/database/uploaders/columnar_reader.py |
| FINDING-017 | Low | 1.3.5 | FINDING-014 | superset/dashboards/schemas.py |
| FINDING-018 | Low | 1.3.12 | — | superset/db_engine_specs/base.py |
| FINDING-019 | Low | 1.5.3 | — | superset/sql/parse.py |
| FINDING-020 | Low | 2.2.1 | FINDING-021 | superset/commands/temporary_cache/create.py |
| FINDING-021 | Low | 2.2.1 | FINDING-020 | superset/commands/chart/data/create_async_job_command.py |
| FINDING-022 | Low | 2.3.2 | — | superset/daos/base.py |
| FINDING-023 | Low | 3.5.2 | — | superset/config.py |
| FINDING-024 | Low | 3.5.8 | — | superset/config.py |
| FINDING-025 | Low | 3.7.2 | — | superset/config.py |
| FINDING-026 | Low | 3.7.3 | — | superset/config.py |
| FINDING-027 | Low | 3.7.5 | — | superset/config.py, superset/templates/superset/macros.html |
| FINDING-028 | Low | 4.1.1 | — | superset/views/api.py |
| FINDING-029 | Low | 4.2.4 | — | superset/charts/data/api.py, superset/databases/api.py, superset/datasets/api.py |
| FINDING-030 | Low | 4.2.5 | FINDING-004, FINDING-012, FINDING-045 | superset/databases/api.py, superset/datasets/api.py |
| FINDING-031 | Low | 8.2.2 | FINDING-008, FINDING-032 | superset/commands/security/create.py, superset/commands/security/update.py |
| FINDING-032 | Low | 8.2.3 | FINDING-008, FINDING-031 | superset/connectors/sqla/models.py |
| FINDING-033 | Low | 10.3.3 | — | superset/mcp_service/auth.py |
| FINDING-034 | Low | 9.1.2 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-035 | Low | 9.2.1 | FINDING-006, FINDING-036 | superset/async_events/async_query_manager.py |
| FINDING-036 | Low | 9.2.1 | FINDING-006, FINDING-035 | superset/mcp_service/jwt_verifier.py |
| FINDING-037 | Low | 11.4.1 | — | superset/key_value/utils.py |
| FINDING-038 | Low | 12.3.1 | FINDING-010 | superset/extensions/ssh.py |
| FINDING-039 | Low | 13.4.5, 13.4.2 | — | superset/config.py |
| FINDING-040 | Low | 13.4.5, 13.4.6 | FINDING-048, FINDING-060 | superset/views/health.py, superset/config.py |
| FINDING-041 | Low | 14.2.2, 14.2.4, 14.2.7 | — | superset/commands/dashboard/filter_state/create.py, superset/commands/explore/form_data/create.py |
| FINDING-042 | Low | 14.2.7 | — | superset/extensions/metastore_cache.py, superset/daos/key_value.py |
| FINDING-043 | Low | 14.2.6 | — | superset/databases/schemas.py |
| FINDING-044 | Low | 14.2.8 | — | superset/databases/schemas.py |
| FINDING-045 | Low | 15.2.2 | FINDING-004, FINDING-012, FINDING-030 | superset/charts/schemas.py |
| FINDING-046 | Low | 15.2.3 | FINDING-005 | superset/viz.py |
| FINDING-047 | Low | 15.2.5, 15.3.5 | — | superset/viz.py |
| FINDING-048 | Low | 15.3.1 | FINDING-040, FINDING-060 | superset/dashboards/schemas.py |
| FINDING-049 | Low | 15.3.3 | FINDING-061 | superset/views/utils.py |
| FINDING-050 | Low | 16.2.1 | FINDING-013, FINDING-052 | superset/mcp_service/jwt_verifier.py |
| FINDING-051 | Low | 16.2.2 | — | superset/commands/logs/prune.py |
| FINDING-052 | Low | 16.3.3 | FINDING-013, FINDING-050 | superset/mcp_service/utils/error_sanitization.py |
| FINDING-053 | Low | 16.4.1 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-054 | Low | 16.5.2 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-055 | Informational | 3.5.4 | — | superset/config.py |
| FINDING-056 | Informational | 3.6.1 | — | superset/config.py |
| FINDING-057 | Informational | 3.7.4 | — | — |
| FINDING-058 | Informational | 9.2.2 | FINDING-059 | superset/mcp_service/jwt_verifier.py |
| FINDING-059 | Informational | 9.2.4 | FINDING-058 | superset/utils/oauth2.py, superset/async_events/async_query_manager.py |
| FINDING-060 | Informational | 15.3.1 | FINDING-040, FINDING-048 | superset/viz.py |
| FINDING-061 | Informational | 15.3.3 | FINDING-049 | superset/viz.py |
| FINDING-062 | Informational | 15.3.7 | — | superset/views/utils.py |

**Total Unique Findings**: 62 (0 Critical, 1 High, 12 Medium, 41 Low, 8 Info)

*54 of 62 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 54 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 15 |
| L2 | 183 | 34 |
| L3 | 92 | 22 |

**Total consolidated findings: 62**

*End of Consolidated Security Audit Report*