# Security Issues

*54 actionable finding(s). 8 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

## Issue: FINDING-001 - SQL Injection via Unescaped `url_param` Return Values from `request.args`
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `url_param()` function in `superset/jinja_context.py` has inconsistent input escaping. When values are sourced from `request.args` (URL query parameters), the function returns the raw, unescaped value, completely bypassing the dialect-specific SQL escaping that is applied to values obtained from `form_data["url_params"]`. This enables SQL injection attacks by Gamma role users with access to dashboards/charts using url_param() in virtual dataset SQL.

### Details
- **CWE:** CWE-89 (SQL Injection)
- **ASVS Sections:** 1.1.1, 1.1.2, 1.2.4, 1.3.3, 1.3.7, 1.5.3
- **ASVS Levels:** L1, L2, L3
- **Affected Files:** `superset/jinja_context.py`
- **Data Flow:** Browser URL query string → Flask request.args → url_param() early return (no escaping) → Jinja template string substitution → raw SQL string → database cursor execution
- **Attacker Profile:** Gamma role user with access to view a dashboard/chart using url_param() in its virtual dataset SQL

This violates both ASVS 1.1.1 (canonical form processing before further use) and 1.1.2 (output encoding as final step).

### Remediation
Apply dialect-specific SQL escaping to ALL return paths in `url_param()`, regardless of input source. The escaping must be applied as the final step immediately before returning the value that will be interpolated into SQL, ensuring consistency across all code paths.

### Acceptance Criteria
- [ ] Dialect-specific SQL escaping applied to all return paths in url_param()
- [ ] Escaping applied as final step before value interpolation
- [ ] Test added covering request.args input path
- [ ] Test added verifying SQL injection prevention

### References
- Related: FINDING-002
- Source Reports: 1.1.1.md, 1.1.2.md, 1.2.4.md, 1.3.3.md, 1.3.7.md, 1.5.3.md

### Priority
**High** - Active SQL injection vulnerability exploitable by authenticated users

---

## Issue: FINDING-002 - Documented Unsafe Pattern in `get_filters` Docstring Encourages SQL Injection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The get_filters() docstring in `superset/jinja_context.py` documents a replace("'", "''") escaping pattern that is incomplete and unsafe. This pattern does not handle backslash escaping, Unicode sequences, or charset-specific SQL injection vectors, enabling SQL injection by non-admin users controlling filter values on dashboards.

### Details
- **CWE:** CWE-89 (SQL Injection)
- **ASVS Sections:** 1.2.4
- **ASVS Levels:** L1
- **Affected Files:** `superset/jinja_context.py`
- **Attacker Profile:** Non-admin users controlling filter values on dashboards using this documented pattern

### Remediation
Update documentation to remove the unsafe replace pattern and recommend the where_in filter or proper parameterization. Include clear warnings against manual SQL escaping.

### Acceptance Criteria
- [ ] Unsafe replace pattern removed from docstring
- [ ] Safe alternatives documented (where_in filter, parameterization)
- [ ] Warning added against manual SQL escaping
- [ ] Documentation review completed

### References
- Related: FINDING-001
- Source Reports: 1.2.4.md

### Priority
**Medium** - Documentation issue encouraging unsafe practices

---

## Issue: FINDING-003 - CSV/File Upload Stores Formula-Prefixed Values Without Sanitization, Enabling Formula Injection on Subsequent Export
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When users upload CSV files, the application uses pd.read_csv() without formula sanitization. Cells starting with =, +, -, @, \t, or \0 are stored verbatim and will be interpreted as formulas when another user exports and opens the data in a spreadsheet application.

### Details
- **CWE:** CWE-1236 (CSV Injection)
- **ASVS Sections:** 1.2.10
- **ASVS Levels:** L3
- **Affected Files:** `superset/commands/database/uploaders/csv_reader.py`, `superset/commands/database/uploaders/base.py`, `superset/commands/database/uploaders/columnar_reader.py`
- **Data Flow:** User-uploaded CSV file → pd.read_csv() (no formula sanitization) → pandas DataFrame → df_to_sql() → database table → later queried by chart → exported as CSV → opened in spreadsheet application → formula execution
- **Attacker Profile:** Authenticated user with CSV upload permission
- **Victim Profile:** Another user who exports and opens the data

### Remediation
Apply formula escaping at the export layer: prefix cells starting with =, +, -, @, \t, \0 with a single quote when exporting to CSV or spreadsheet formats. Follow RFC 4180 sections 2.6 and 2.7 for CSV escaping.

### Acceptance Criteria
- [ ] Formula escaping implemented at export layer
- [ ] All dangerous formula prefixes handled (=, +, -, @, \t, \0)
- [ ] Test added with malicious CSV upload and subsequent export
- [ ] RFC 4180 compliance verified

### References
- Source Reports: 1.2.10.md

### Priority
**Medium** - Requires two-step attack (upload + victim export)

---

## Issue: FINDING-004 - No Application-Level File Size Check Before Processing in Columnar Upload
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ColumnarReader._yield_files() and file_to_dataframe() methods process uploaded files without any size validation before reading content into memory. A large parquet file or ZIP containing large parquet files will be read entirely into BytesIO buffers and then into pandas DataFrames without bounds.

### Details
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **ASVS Sections:** 5.2.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/commands/database/uploaders/columnar_reader.py`, `superset/commands/database/uploaders/base.py`

The UploadCommand.validate() method checks database/schema permissions but does not validate file size.

### Remediation
Add file size validation in UploadCommand.validate() or at the reader level, checking against a configurable UPLOAD_MAX_FILE_SIZE_BYTES before processing begins.

### Acceptance Criteria
- [ ] File size validation added before processing
- [ ] Configurable UPLOAD_MAX_FILE_SIZE_BYTES setting implemented
- [ ] Test added with oversized file
- [ ] Appropriate error message returned to user

### References
- Related: FINDING-012, FINDING-030, FINDING-045
- Source Reports: 5.2.1.md

### Priority
**Medium** - DoS risk requiring authenticated access

---

## Issue: FINDING-005 - MCP Authentication Error Reveals System Configuration to Unauthenticated Users
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `get_user_from_request()` function in `superset/mcp_service/auth.py` raises a ValueError containing detailed configuration diagnostics (MCP_AUTH_ENABLED value, whether JWT keys are configured, API key prefix format, whether MCP_DEV_USERNAME is set) that propagates to unauthenticated MCP clients. This enables configuration fingerprinting by remote unauthenticated attackers.

### Details
- **CWE:** CWE-209 (Information Exposure Through an Error Message)
- **ASVS Sections:** 6.3.4, 6.3.8
- **ASVS Levels:** L2, L3
- **Affected Files:** `superset/mcp_service/auth.py`

This violates both authentication pathway consistency (6.3.4) and user enumeration prevention (6.3.8) requirements.

### Remediation
Replace the detailed ValueError with a generic message for the client ('Authentication required. No valid credentials provided.' or 'Authentication failed.'), while preserving detailed diagnostics server-side via logger.warning() or logger.debug(). Ensure consistent error responses across all authentication pathways.

### Acceptance Criteria
- [ ] Generic error messages returned to clients
- [ ] Detailed diagnostics logged server-side only
- [ ] Consistent error responses across all auth pathways
- [ ] Test verifying no configuration leakage in error responses

### References
- Related: FINDING-046
- Source Reports: 6.3.4.md, 6.3.8.md

### Priority
**Medium** - Information disclosure enabling reconnaissance

---

## Issue: FINDING-006 - Guest Token RLS Rules Cannot Be Revoked or Updated Before Expiration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Guest tokens embed RLS rules directly in the JWT payload at issuance time. When RLS rules are modified on the server, outstanding guest tokens continue to enforce stale RLS rules until natural expiration. There is no token revocation mechanism, no server-side re-validation of RLS rules against current configuration, and no alerting when a guest user performs actions under stale authorization rules.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS Sections:** 8.3.2
- **ASVS Levels:** L3
- **Affected Files:** `superset/security/manager.py`, `superset/connectors/sqla/models.py`

ASVS 8.3.2 requires mitigating controls for self-contained tokens.

### Remediation
Implement server-side RLS rule validation for guest tokens: compare token-embedded rules against current server state on each request, with audit logging on drift detection. Alternatively, add an rls_version claim to guest tokens validated against a server-side counter, or implement short-lived tokens with refresh to reduce the staleness window.

### Acceptance Criteria
- [ ] Server-side RLS rule validation implemented for guest tokens
- [ ] Audit logging added for rule drift detection
- [ ] Test added verifying stale rule detection
- [ ] Documentation updated with new behavior

### References
- Related: FINDING-035, FINDING-036
- Source Reports: 8.3.2.md

### Priority
**Medium** - Authorization bypass via stale embedded rules

---

## Issue: FINDING-007 - MCP Resource Server Audience Validation Is Conditional and Not Enforced by Default
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The MCP resource server's audience validation is conditional on configuration (`if self.audience:`). When `self.audience` is None/empty, audience validation is skipped entirely, allowing tokens intended for other services sharing the same IdP to be accepted. A stolen or misdirected token from another service could grant access to MCP tools.

### Details
- **CWE:** CWE-287 (Improper Authentication)
- **ASVS Sections:** 10.3.1, 9.2.3
- **ASVS Levels:** L2
- **Affected Files:** `superset/mcp_service/jwt_verifier.py`
- **Data Flow:** External JWT token → DetailedJWTVerifier.load_access_token() → `if self.audience:` guard → audience validation SKIPPED when self.audience is not configured → token accepted for any audience → user context established → tool execution

### Remediation
The verifier should either require audience configuration or reject tokens that don't match a configured audience. At minimum, log a warning during initialization when audience is not set. Consider failing closed when MCP_AUTH_ENABLED is True but no audience is configured.

### Acceptance Criteria
- [ ] Audience validation enforced or configuration required
- [ ] Warning logged when audience not configured
- [ ] Test added verifying audience enforcement
- [ ] Documentation updated with configuration requirements

### References
- Source Reports: 10.3.1.md, 9.2.3.md

### Priority
**Medium** - Authentication bypass in multi-service deployments

---

## Issue: FINDING-008 - Token Scope Claims Not Enforced in Per-Tool Authorization Decisions
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The MCP resource server validates token scopes at entry (minimum gate) but does not enforce them in per-tool authorization decisions. Token scopes are available in the AccessToken ContextVar but check_tool_permission() only consults database RBAC roles. A token with limited scopes (e.g., mcp:read) can perform write operations if the mapped user has broader database permissions.

### Details
- **CWE:** CWE-863 (Incorrect Authorization)
- **ASVS Sections:** 10.3.2
- **ASVS Levels:** L2
- **Affected Files:** `superset/mcp_service/auth.py`, `superset/mcp_service/jwt_verifier.py`

This violates the OAuth principle of enforcing the intersection of user permissions and token scope.

### Remediation
Incorporate the access token's scopes into the authorization decision in check_tool_permission(). The authorization should be the intersection of the token's granted scopes and the user's database permissions. Map tool methods (read/write/delete) to required scopes.

### Acceptance Criteria
- [ ] Token scopes incorporated into authorization decisions
- [ ] Intersection logic implemented (token scopes AND user permissions)
- [ ] Tool method to scope mapping defined
- [ ] Test added verifying scope enforcement

### References
- Related: FINDING-031, FINDING-032
- Source Reports: 10.3.2.md

### Priority
**Medium** - Authorization bypass via insufficient scope enforcement

---

## Issue: FINDING-009 - `random_key()` function defaults to 64 bits of entropy, below 128-bit minimum
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `random_key` function in `superset/key_value/utils.py` defaults to 8 bytes (64 bits) of entropy via `secrets.token_urlsafe(8)`. This is below the 128-bit minimum required by ASVS 11.2.3 and 11.5.1. The function is used for key-value store entries including PKCE code verifiers (RFC 7636 recommends minimum 256 bits).

### Details
- **CWE:** CWE-331 (Insufficient Entropy)
- **ASVS Sections:** 11.2.3, 11.5.1
- **ASVS Levels:** L2, L3
- **Affected Files:** `superset/key_value/utils.py`

With 64 bits of entropy, the birthday bound is ~2^32. For PKCE verifier lookups, guessing a valid key grants access to the stored code verifier, potentially compromising OAuth2 flows.

### Remediation
Change `nbytes` default from 8 to 16 (128 bits) in `superset/key_value/utils.py`: `def random_key(nbytes: int = 16) -> str`. Add a minimum bytes validation to prevent callers from requesting less than 16 bytes for security-sensitive keys.

### Acceptance Criteria
- [ ] Default nbytes changed to 16 (128 bits)
- [ ] Minimum bytes validation added
- [ ] Test added verifying minimum entropy enforcement
- [ ] Existing key generation calls reviewed for compatibility

### References
- Source Reports: 11.2.3.md, 11.5.1.md

### Priority
**Medium** - Insufficient entropy for security-sensitive keys

---

## Issue: FINDING-010 - SMTP outbound connections default to disabled server certificate authentication
**Labels:** bug, security, priority:medium
**Description:**
### Summary
SMTP_SSL_SERVER_AUTH defaults to False in superset/config.py. When an operator configures a remote SMTP server, STARTTLS upgrades the connection but the server certificate is not validated, allowing network-positioned attackers to MITM email traffic containing alert/report data.

### Details
- **CWE:** CWE-295 (Improper Certificate Validation)
- **ASVS Sections:** 12.3.1, 12.3.2
- **ASVS Levels:** L2
- **Affected Files:** `superset/config.py`

This violates both encrypted transport requirements (12.3.1) and certificate validation requirements (12.3.2).

### Remediation
Change the default to SMTP_SSL_SERVER_AUTH = True. If backward compatibility is needed, raise a ConfigurationError when STARTTLS is enabled with a remote host and SMTP_SSL_SERVER_AUTH is False. Alternatively, add a startup warning when SMTP_STARTTLS = True and SMTP_SSL_SERVER_AUTH = False with a remote SMTP host.

### Acceptance Criteria
- [ ] Default changed to SMTP_SSL_SERVER_AUTH = True
- [ ] Configuration validation added for unsafe combinations
- [ ] Test added verifying certificate validation
- [ ] Migration guide provided for existing deployments

### References
- Related: FINDING-038
- Source Reports: 12.3.1.md, 12.3.2.md

### Priority
**Medium** - MITM vulnerability requiring network position

---

## Issue: FINDING-011 - Default JWT Secrets and Cryptographic Keys Shipped in Source Code Without Runtime Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application ships publicly-known default values for SECRET_KEY, GUEST_TOKEN_JWT_SECRET, and GLOBAL_ASYNC_QUERIES_JWT_SECRET with no runtime validation preventing their use. An unauthenticated attacker knowing these defaults can forge guest tokens, async query JWTs, or Flask sessions if operators fail to override them.

### Details
- **CWE:** CWE-1188 (Insecure Default Initialization of Resource)
- **ASVS Sections:** 13.2.3, 13.3.4
- **ASVS Levels:** L2, L3
- **Affected Files:** `superset/config.py`, `superset/constants.py`

### Remediation
Add startup validation that blocks the application from starting or disables affected features when security-sensitive secrets retain their default placeholder values.

### Acceptance Criteria
- [ ] Startup validation added for default secrets
- [ ] Application blocks startup with default secrets in production
- [ ] Clear error message provided to operators
- [ ] Documentation updated with secret generation instructions

### References
- Source Reports: 13.2.3.md, 13.3.4.md

### Priority
**Medium** - Cryptographic bypass via default secrets

---

## Issue: FINDING-012 - Unbounded Query Amplification via `time_compare` and `deck_slices` Lists
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-controlled `form_data["time_compare"]` list / `form_data["deck_slices"]` list → unbounded iteration → multiple database queries per iteration → resource exhaustion. A single HTTP request with 50 time_compare entries triggers 50+ database queries. Combined with deck_slices (each slice potentially having its own time_compare), amplification can be multiplicative.

### Details
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **ASVS Sections:** 15.2.2
- **ASVS Levels:** L2
- **Affected Files:** `superset/viz.py`

### Remediation
Add configurable upper bound on `time_compare` list length (suggest default 10) and `deck_slices` list length (suggest default 10). Validate list lengths before iteration.

### Acceptance Criteria
- [ ] Configurable upper bounds added for time_compare and deck_slices
- [ ] List length validation implemented before iteration
- [ ] Test added with oversized lists
- [ ] Appropriate error message returned to user

### References
- Related: FINDING-004, FINDING-030, FINDING-045
- Source Reports: 15.2.2.md

### Priority
**Medium** - DoS risk via query amplification

---

## Issue: FINDING-013 - MCP Service JWT Authentication Successful Events Not Logged
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Authentication failure events are logged at WARNING level via `_auth_error_handler`, but successful JWT authentication generates no log entry. An attacker using a stolen JWT token to access the MCP service would generate no authentication audit trail. Incident response teams cannot correlate access patterns, detect credential theft, or establish timelines for successful MCP service access.

### Details
- **CWE:** CWE-778 (Insufficient Logging)
- **ASVS Sections:** 16.3.1
- **ASVS Levels:** L2
- **Affected Files:** `superset/mcp_service/jwt_verifier.py`

### Remediation
Add structured logging on successful authentication in the `authenticate` method, including relevant metadata (client_id, scopes, authentication method).

### Acceptance Criteria
- [ ] Successful authentication logging added
- [ ] Structured log format implemented with relevant metadata
- [ ] Test added verifying log generation
- [ ] Log retention policy documented

### References
- Related: FINDING-050, FINDING-052
- Source Reports: 16.3.1.md

### Priority
**Medium** - Insufficient audit trail for security events

---

## Issue: FINDING-014 - Missing URL Protocol Validation on `external_url` Fields
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `external_url` field in chart and dashboard schemas accepts any string with no URL protocol validation. If the frontend renders it as a clickable link, a javascript: or data: protocol URL could execute JavaScript in another user's browser (XSS). Requires Alpha role or custom role with chart/dashboard write access.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS Sections:** 1.2.2
- **ASVS Levels:** L1
- **Affected Files:** `superset/charts/schemas.py`, `superset/dashboards/schemas.py`

### Remediation
Add a Marshmallow validator that rejects non-http/https protocols on external_url fields. Ensure only safe URL protocols (http, https) are permitted and reject javascript:, data:, vbscript:, and other dangerous schemes.

### Acceptance Criteria
- [ ] URL protocol validator added to external_url fields
- [ ] Only http/https protocols permitted
- [ ] Test added with dangerous protocols (javascript:, data:)
- [ ] Frontend rendering reviewed for XSS prevention

### References
- Related: FINDING-017
- Source Reports: 1.2.2.md

### Priority
**Low** - Requires elevated permissions and frontend rendering

---

## Issue: FINDING-015 - Email Subject Field Not Sanitized for CRLF Injection
**Labels:** bug, security, priority:low
**Description:**
### Summary
In superset/utils/core.py, the send_email_smtp function assigns the subject parameter directly to msg['Subject'] without CRLF sanitization. Data flow: Report/alert name → subject parameter → msg['Subject'] → SMTP transmission. Attacker capability required: Authenticated user with permission to create reports/alerts (typically Alpha role or above). Impact: Email header injection allowing BCC injection, reply-to modification, or content-type manipulation.

### Details
- **CWE:** CWE-93 (CRLF Injection)
- **ASVS Sections:** 1.3.11
- **ASVS Levels:** L2
- **Affected Files:** `superset/utils/core.py`

### Remediation
Strip or replace \r and \n characters from the subject parameter before setting it as a MIME header: subject = subject.replace('\r', '').replace('\n', ' ').strip()

### Acceptance Criteria
- [ ] CRLF sanitization added to subject parameter
- [ ] Test added with CRLF characters in subject
- [ ] Email header integrity verified
- [ ] Similar fields reviewed for CRLF injection

### References
- Source Reports: 1.3.11.md

### Priority
**Low** - Requires elevated permissions, limited impact

---

## Issue: FINDING-016 - Missing ZIP safety check in columnar file upload reader
**Labels:** bug, security, priority:low
**Description:**
### Summary
File: superset/commands/database/uploaders/columnar_reader.py, method _yield_files. Unlike the importer code path which calls check_is_safe_zip(), the columnar reader does not validate ZIP file safety (decompression ratio, entry count, total uncompressed size). Attacker capability: Authenticated user with file upload permission (non-admin Alpha/Gamma with upload grants). Impact: Memory exhaustion DoS via ZIP bomb.

### Details
- **CWE:** CWE-409 (Improper Handling of Highly Compressed Data)
- **ASVS Sections:** 1.3.3, 5.2.3, 5.3.3
- **ASVS Levels:** L2, L3
- **Affected Files:** `superset/commands/database/uploaders/columnar_reader.py`

### Remediation
Add check_is_safe_zip(zip_file) call before processing ZIP entries in columnar_reader.py, mirroring the pattern in importers/v1/utils.py. Implement decompression safety checks including total uncompressed size and file count limits before reading ZIP entries.

### Acceptance Criteria
- [ ] check_is_safe_zip() call added to columnar reader
- [ ] Decompression safety checks implemented
- [ ] Test added with ZIP bomb
- [ ] Appropriate error message returned to user

### References
- Source Reports: 1.3.3.md, 5.2.3.md, 5.3.3.md

### Priority
**Low** - DoS risk requiring authenticated access

---

## Issue: FINDING-017 - User-supplied CSS stored and rendered without sanitization
**Labels:** bug, security, priority:low
**Description:**
### Summary
File: superset/dashboards/schemas.py, DashboardPostSchema and DashboardPutSchema. The css field accepts arbitrary CSS content without sanitization. Attacker capability: Authenticated user with dashboard write permission (Alpha role or custom role with dashboard edit grants). Impact: CSS-based data exfiltration via attribute selectors + url() backgrounds, UI manipulation via CSS overlays, external resource loading via @import. Mitigated by deployment-layer CSP policies blocking external resource loading from CSS.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS Sections:** 1.3.5
- **ASVS Levels:** L2
- **Affected Files:** `superset/dashboards/schemas.py`

### Remediation
Apply CSS sanitization using a property/function allowlist or CSS sanitization library to strip url(), @import, expression() and other dangerous CSS constructs before storing dashboard CSS.

### Acceptance Criteria
- [ ] CSS sanitization implemented with allowlist approach
- [ ] Dangerous CSS constructs removed (url(), @import, expression())
- [ ] Test added with malicious CSS
- [ ] CSP policies reviewed for defense-in-depth

### References
- Related: FINDING-014
- Source Reports: 1.3.5.md

### Priority
**Low** - Requires elevated permissions, mitigated by CSP

---

## Issue: FINDING-018 - Unescaped schema name used in regex substitution pattern
**Labels:** bug, security, priority:low
**Description:**
### Summary
File: superset/db_engine_specs/base.py, functions get_table_names() and get_view_names(). Schema name from database metadata is inserted unescaped into regex pattern via f-string. If a schema name contains regex metacharacters, the regex could exhibit catastrophic backtracking. Exploitability is low due to database identifier restrictions and requirement for elevated permissions to create schemas.

### Details
- **CWE:** CWE-1333 (Inefficient Regular Expression Complexity)
- **ASVS Sections:** 1.3.12
- **ASVS Levels:** L3
- **Affected Files:** `superset/db_engine_specs/base.py`

### Remediation
Apply re.escape() to the schema name before interpolation: escaped_schema = re.escape(schema); tables = {re.sub(f'^{escaped_schema}\\.', '', table) for table in tables}

### Acceptance Criteria
- [ ] re.escape() applied to schema name before regex interpolation
- [ ] Test added with regex metacharacters in schema name
- [ ] Performance impact verified
- [ ] Similar patterns reviewed

### References
- Source Reports: 1.3.12.md

### Priority
**Low** - Requires elevated permissions, limited exploitability

---

## Issue: FINDING-019 - SQL dialect fallback from base to MySQL may produce different parse results
**Labels:** bug, security, priority:low
**Description:**
### Summary
In superset/sql/parse.py, when SQL parsing fails with the base dialect and the script contains backticks, the parser falls back to MySQL dialect. This may produce different table extraction or mutation detection results than the actual target database's SQL parser, potentially affecting access control decisions for databases with unrecognized engine types.

### Details
- **CWE:** CWE-436 (Interpretation Conflict)
- **ASVS Sections:** 1.5.3
- **ASVS Levels:** L3
- **Affected Files:** `superset/sql/parse.py`

### Remediation
Log the dialect fallback at WARNING level to enable security monitoring. Consider raising an error instead of silently falling back, or documenting the known limitation for unrecognized database types.

### Acceptance Criteria
- [ ] Dialect fallback logged at WARNING level
- [ ] Documentation added for known limitation
- [ ] Test added verifying fallback behavior
- [ ] Consider error-on-fallback option

### References
- Source Reports: 1.5.3.md

### Priority
**Low** - Edge case affecting unrecognized database types

---

## Issue: FINDING-020 - CreateTemporaryCacheCommand.run() bypasses validate() invocation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `BaseCommand` contract establishes that `run()` should call `validate()` before execution. However, `CreateTemporaryCacheCommand.run()` directly calls `self.create()` without invoking `self.validate()`. While `validate()` is currently a no-op, this pattern creates a gap where future validation logic added to `validate()` would be silently bypassed.

### Details
- **CWE:** CWE-573 (Improper Following of Specification by Caller)
- **ASVS Sections:** 2.2.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/commands/temporary_cache/create.py`

Immediate impact is mitigated because `CreateFilterStateCommand.create()` performs its own access check via `check_access(resource_id)`.

### Remediation
Add `self.validate()` call in `run()` to align with the established BaseCommand contract.

### Acceptance Criteria
- [ ] self.validate() call added to run() method
- [ ] Test added verifying validate() is called
- [ ] Similar command classes reviewed
- [ ] BaseCommand contract documented

### References
- Related: FINDING-021
- Source Reports: 2.2.1.md

### Priority
**Low** - Pattern violation with mitigated current impact

---

## Issue: FINDING-021 - CreateAsyncChartDataJobCommand does not follow BaseCommand pattern, separating validate() from run() without enforcement
**Labels:** bug, security, priority:low
**Description:**
### Summary
This command class does not extend `BaseCommand` and has a different interface where `validate()` takes external parameters, `run()` takes different parameters, and `run()` does not call `validate()`. The caller must enforce ordering. If `run()` is called without prior `validate()`, an `AttributeError` on `_async_channel_id` will raise — this is fail-closed behavior.

### Details
- **CWE:** CWE-573 (Improper Following of Specification by Caller)
- **ASVS Sections:** 2.2.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/commands/chart/data/create_async_job_command.py`

### Remediation
Refactor to extend BaseCommand or add a guard in `run()` that verifies initialization state.

### Acceptance Criteria
- [ ] Command refactored to extend BaseCommand or add state guard
- [ ] Test added verifying proper initialization
- [ ] Documentation added for command interface
- [ ] Similar command classes reviewed

### References
- Related: FINDING-020
- Source Reports: 2.2.1.md

### Priority
**Low** - Pattern violation with fail-closed behavior

---

## Issue: FINDING-022 - BaseDAO.list() Has No Upper Bound on page_size
**Labels:** bug, security, priority:low
**Description:**
### Summary
BaseDAO.list() enforces a minimum page_size of 1 via `max(page_size, 1)` but has no upper bound. An authenticated user could pass an extremely large page_size forcing the database to prepare and transfer a large result set. Impact is limited DoS (resource exhaustion), not data exposure or privilege escalation. Base filters limit query universe to accessible records.

### Details
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **ASVS Sections:** 2.3.2
- **ASVS Levels:** L2
- **Affected Files:** `superset/daos/base.py`

### Remediation
Enforce a configurable maximum page_size at the DAO layer: `page_size = min(max(page_size, 1), MAX_PAGE_SIZE)`

### Acceptance Criteria
- [ ] Configurable MAX_PAGE_SIZE implemented
- [ ] Upper bound enforced in BaseDAO.list()
- [ ] Test added with oversized page_size
- [ ] Default MAX_PAGE_SIZE value documented

### References
- Source Reports: 2.3.2.md

### Priority
**Low** - DoS risk requiring authenticated access

---

## Issue: FINDING-023 - CSRF-Exempt Endpoints Lack Explicit Content-Type or Custom Header Enforcement
**Labels:** bug, security, priority:low
**Description:**
### Summary
Six sensitive endpoints are exempt from CSRF token validation. While the application does NOT primarily rely on CORS preflight for protection (it uses CSRF tokens + SameSite=Lax cookies), these exempt endpoints have no visible enforcement of a Content-Type that would trigger preflight (e.g., application/json) or a custom header. The SameSite=Lax cookie setting provides the primary defense but for legacy browsers without SameSite support, or if the endpoint also accepts GET requests, the protection may not hold.

### Details
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **ASVS Sections:** 3.5.2
- **ASVS Levels:** L1
- **Affected Files:** `superset/config.py`

### Remediation
For CSRF-exempt endpoints that perform state-changing operations, require a Content-Type of application/json (which triggers CORS preflight) or mandate a custom request header (e.g., X-Requested-With) that is not CORS-safelisted.

### Acceptance Criteria
- [ ] Content-Type or custom header requirement added to CSRF-exempt endpoints
- [ ] Test added verifying header enforcement
- [ ] Documentation updated with CSRF protection strategy
- [ ] Legacy browser support documented

### References
- Source Reports: 3.5.2.md

### Priority
**Low** - Defense-in-depth for legacy browsers

---

## Issue: FINDING-024 - No Sec-Fetch-* Header Validation or Cross-Origin-Resource-Policy Header for Authenticated Resources
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application does not validate Sec-Fetch-* headers or set Cross-Origin-Resource-Policy headers on authenticated resource endpoints. Browser cross-origin requests to Flask endpoints serving authenticated resources (chart data, thumbnails, CSV exports) return responses without CORP headers or Sec-Fetch-* validation. However, the impact is limited because the SESSION_COOKIE_SAMESITE = 'Lax' cookie policy prevents cookie transmission on cross-origin subresource requests.

### Details
- **ASVS Sections:** 3.5.8
- **ASVS Levels:** L3
- **Affected Files:** `superset/config.py` (lines 1423-1456)

### Remediation
For Level 3 compliance, add a Cross-Origin-Resource-Policy: same-origin response header to authenticated resource endpoints. This can be configured in DEFAULT_HTTP_HEADERS: DEFAULT_HTTP_HEADERS: dict[str, Any] = { "Cross-Origin-Resource-Policy": "same-origin" }. Alternatively, implement Sec-Fetch-* validation middleware that checks the Sec-Fetch-Site header on authenticated endpoints and aborts with 403 if the value is not same-origin, same-site, or none.

### Acceptance Criteria
- [ ] Cross-Origin-Resource-Policy header added to authenticated endpoints
- [ ] Sec-Fetch-* validation implemented (alternative approach)
- [ ] Test added verifying CORP enforcement
- [ ] Browser compatibility documented

### References
- Source Reports: 3.5.8.md

### Priority
**Low** - Defense-in-depth, mitigated by SameSite cookies

---

## Issue: FINDING-025 - No Configurable Redirect Allowlist Mechanism Visible in Application Configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
No redirect allowlist configuration exists in config.py. The following settings can direct users to external URLs without allowlist validation: LOGO_TARGET_PATH (can specify full URL), TRACKING_URL_TRANSFORMER (used to translate internal Hadoop job tracker URL into a proxied one), and WEBDRIVER_BASEURL_USER_FRIENDLY (base URL for email report hyperlinks). Configuration values (admin-set) or application logic can redirect user responses to potentially untrusted domains without visible allowlist validation.

### Details
- **ASVS Sections:** 3.7.2
- **ASVS Levels:** L2
- **Affected Files:** `superset/config.py`

For admin-configured values (LOGO_TARGET_PATH, etc.), requires admin access (out of scope per trust model). For any user-controllable redirect paths (not visible in provided code), would require authenticated user access. Open redirect could be used for phishing or credential theft by redirecting users to attacker-controlled lookalike pages.

### Remediation
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

### Acceptance Criteria
- [ ] ALLOWED_REDIRECT_DOMAINS configuration added
- [ ] is_safe_redirect() utility implemented
- [ ] Redirect validation applied to relevant code paths
- [ ] Test added with external redirect attempts
- [ ] Documentation added for redirect allowlist configuration

### References
- Source Reports: 3.7.2.md

### Priority
**Low** - Requires admin configuration or user-controllable redirect paths

---

## Issue: FINDING-026 - External Redirect Warning Limited to Alert/Report Email Links
**Labels:** bug, security, priority:low
**Description:**
### Summary
Alert/report email contains external link → link rewritten to pass through redirect warning page → user sees notification → user can choose to proceed or cancel. However, other navigation paths (dashboard links to external URLs, markdown content links, SQL Lab result links) may not implement the same warning mechanism. Users may be navigated to external URLs without explicit confirmation, potentially enabling social engineering attacks via compromised dashboard content.

### Details
- **ASVS Sections:** 3.7.3
- **ASVS Levels:** L3
- **Affected Files:** `superset/config.py` (line 1392)

### Remediation
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

### Acceptance Criteria
- [ ] External navigation interceptor implemented in frontend
- [ ] Warning modal added for external URLs
- [ ] All navigation paths reviewed and updated
- [ ] Test added verifying warning display
- [ ] User confirmation required before external navigation

### References
- Source Reports: 3.7.3.md

### Priority
**Low** - Defense-in-depth against social engineering

---

## Issue: FINDING-027 - No Browser Security Feature Detection or User Warning Mechanism
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application configures security features that depend on modern browser support (CSP Level 2 with 'strict-dynamic', nonces, SameSite cookies) but implements no mechanism to detect whether the user's browser supports these features, and provides no warning or access blocking for unsupported browsers. While the React 18 frontend framework requires ES6+ features that are only available in browsers already supporting CSP Level 2 and SameSite cookies, the application lacks an explicit, documented, and user-facing communication about minimum browser requirements.

### Details
- **ASVS Sections:** 3.7.5
- **ASVS Levels:** L3
- **Affected Files:** `superset/config.py` (lines 1423-1456), `superset/templates/superset/macros.html`

### Remediation
Add client-side browser feature detection to warn users of unsupported browsers. Implement a JavaScript check in the React application bootstrap (e.g., src/setup/setupApp.ts) that validates support for SecurityPolicyViolationEvent and other modern browser features. Display a banner or block access with a message like 'Your browser may not support required security features. Please update to a supported browser version.' Additionally, add a documented minimum browser requirements page accessible before the main application loads.

### Acceptance Criteria
- [ ] Browser feature detection implemented in frontend bootstrap
- [ ] Warning banner or access block added for unsupported browsers
- [ ] Minimum browser requirements documented
- [ ] Test added with legacy browser user agents
- [ ] Browser support policy documented

### References
- Source Reports: 3.7.5.md

### Priority
**Low** - Defense-in-depth, React 18 already requires modern browsers

---

## Issue: FINDING-028 - Raw JSON String Return Without Explicit Content-Type in Api.query()
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `Api.query()` method returns a raw `json.dumps()` string without using `self.json_response()`, potentially serving JSON with Flask's default `text/html` Content-Type. The `@api` decorator may not explicitly set Content-Type. The sibling methods `query_form_data` and `time_range` correctly use `self.json_response()`.

### Details
- **CWE:** CWE-116 (Improper Encoding or Escaping of Output)
- **ASVS Sections:** 4.1.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/views/api.py`

### Remediation
Replace `return json.dumps(payload_json, default=json.json_int_dttm_ser, ignore_nan=True)` with `return self.json_response(payload_json)` to ensure consistent Content-Type header generation.

### Acceptance Criteria
- [ ] Api.query() refactored to use self.json_response()
- [ ] Test added verifying Content-Type header
- [ ] Similar patterns reviewed in codebase
- [ ] Response encoding verified

### References
- Source Reports: 4.1.1.md

### Priority
**Low** - Inconsistent Content-Type header

---

## Issue: FINDING-029 - User-provided Input Used in HTTP Headers Without Explicit Sanitization
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-provided filename in Content-Disposition header (charts/data/api.py) and user-controlled query parameter used as cookie name (databases/api.py, datasets/api.py) lack explicit sanitization. Werkzeug v2.2+ rejects CRLF but malformed header syntax remains possible. Impact is self-affecting only for authenticated users.

### Details
- **CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **ASVS Sections:** 4.2.4
- **ASVS Levels:** L3
- **Affected Files:** `superset/charts/data/api.py`, `superset/databases/api.py`, `superset/datasets/api.py`

### Remediation
Apply secure_filename() to user-provided filenames consistently. Validate token parameter with regex (alphanumeric, max 128 chars) before use as cookie name.

### Acceptance Criteria
- [ ] secure_filename() applied to user-provided filenames
- [ ] Token parameter validation added (regex, length)
- [ ] Test added with malicious input
- [ ] Header syntax validation verified

### References
- Source Reports: 4.2.4.md

### Priority
**Low** - Mitigated by Werkzeug, self-affecting only

---

## Issue: FINDING-030 - Unbounded Cookie Name Length from User Input Could Cause Downstream Request Rejection
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `token` query parameter in databases/api.py and datasets/api.py export endpoints is used as a cookie name without length or character validation. An oversized token could cause persistent 431 errors for the targeted user until cookie expiry (600s). Requires authenticated access.

### Details
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **ASVS Sections:** 4.2.5
- **ASVS Levels:** L3
- **Affected Files:** `superset/databases/api.py`, `superset/datasets/api.py`

### Remediation
Add length (max 128) and character validation (alphanumeric + dash/underscore) for the token query parameter before use as cookie name.

### Acceptance Criteria
- [ ] Token length validation added (max 128 chars)
- [ ] Token character validation added (alphanumeric + dash/underscore)
- [ ] Test added with oversized token
- [ ] Appropriate error message returned to user

### References
- Related: FINDING-004, FINDING-012, FINDING-045
- Source Reports: 4.2.5.md

### Priority
**Low** - Self-affecting DoS requiring authenticated access

---

## Issue: FINDING-031 - RLS Rule Creation/Update Commands Do Not Validate Caller's Access to Referenced Tables
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `CreateRLSRuleCommand` and `UpdateRLSRuleCommand` validate that referenced table IDs exist in the database but do not verify that the authenticated user has access to those specific tables. While the RLS API endpoints are protected by `@protect()` (requiring "Row Level Security" write permission), a user with this permission could reference tables they don't have datasource/schema/database access to.

### Details
- **CWE:** CWE-863 (Incorrect Authorization)
- **ASVS Sections:** 8.2.2
- **ASVS Levels:** L1
- **Affected Files:** `superset/commands/security/create.py`, `superset/commands/security/update.py`

### Remediation
Add `security_manager.can_access_datasource(datasource=table)` check for each referenced table in both `CreateRLSRuleCommand.validate()` and `UpdateRLSRuleCommand.validate()`.

### Acceptance Criteria
- [ ] Datasource access check added to CreateRLSRuleCommand.validate()
- [ ] Datasource access check added to UpdateRLSRuleCommand.validate()
- [ ] Test added verifying access enforcement
- [ ] Appropriate error message returned for unauthorized access

### References
- Related: FINDING-008, FINDING-032
- Source Reports: 8.2.2.md

### Priority
**Low** - Requires elevated RLS permission

---

## Issue: FINDING-032 - REST API Explore View Lacks Per-User Field-Level Filtering
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `BaseDatasource.data` property returns all fields (including `sql`, `params`, `perm`) uniformly to any user with datasource access, without per-user field-level filtering. The MCP service implements comprehensive field-level permissions via `SENSITIVE_FIELDS`/`SENSITIVE_FIELD_PERMISSIONS` but this filtering is not applied in the REST API explore view path.

### Details
- **CWE:** CWE-863 (Incorrect Authorization)
- **ASVS Sections:** 8.2.3
- **ASVS Levels:** L2
- **Affected Files:** `superset/connectors/sqla/models.py`

### Remediation
Apply the MCP service's field-level filtering pattern (`permissions_utils.py`) to the REST API explore data path, gating sensitive dataset fields (`sql`, `extra`, `params`) behind specific permissions.

### Acceptance Criteria
- [ ] Field-level filtering applied to REST API explore view
- [ ] Sensitive fields gated behind specific permissions
- [ ] Test added verifying field-level access control
- [ ] MCP service pattern reused or abstracted

### References
- Related: FINDING-008, FINDING-031
- Source Reports: 8.2.3.md

### Priority
**Low** - Information disclosure to authorized users

---

## Issue: FINDING-033 - User Identification Uses Potentially Reassignable Claims Without Issuer Context Binding
**Labels:** bug, security, priority:low
**Description:**
### Summary
The MCP resource server resolves users from JWT claims without incorporating the issuer into the user lookup key. In multi-issuer deployments, an attacker controlling a second trusted issuer could authenticate as a legitimate user if email/username collides across issuers. The issuer (iss) claim is validated at the JWT level but NOT incorporated into the user identification key in the database lookup.

### Details
- **CWE:** CWE-290 (Authentication Bypass by Spoofing)
- **ASVS Sections:** 10.3.3
- **ASVS Levels:** L2
- **Affected Files:** `superset/mcp_service/auth.py`

### Remediation
For multi-issuer deployments, incorporate the issuer into the user lookup to prevent cross-issuer collision. Document that single-issuer deployments are safe, and multi-issuer deployments must use a resolver that returns iss+sub or similar compound key.

### Acceptance Criteria
- [ ] Issuer incorporated into user lookup for multi-issuer deployments
- [ ] Documentation added for single vs multi-issuer deployments
- [ ] Test added verifying cross-issuer collision prevention
- [ ] Configuration guidance provided

### References
- Source Reports: 10.3.3.md

### Priority
**Low** - Only affects multi-issuer deployments

---

## Issue: FINDING-034 - MCP JWT verifier algorithm enforcement is conditional on configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
MCP JWT verifier algorithm enforcement is conditional on configuration. When self.algorithm is not configured, the algorithm check is skipped entirely. DOWNGRADED from Medium: exploitation requires operator misconfiguration (operator is a trusted party per profile) combined with specific key material conditions, and authlib mitigates many algorithm confusion vectors via key-type checks.

### Details
- **CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **ASVS Sections:** 9.1.2
- **ASVS Levels:** L1
- **Affected Files:** `superset/mcp_service/jwt_verifier.py`

### Remediation
Enforce that self.algorithm is always set during initialization, or add a hard-fail when no algorithm is configured. Alternatively, define a static allowlist of permitted algorithms.

### Acceptance Criteria
- [ ] Algorithm configuration enforced during initialization
- [ ] Hard-fail added when algorithm not configured
- [ ] Static algorithm allowlist considered
- [ ] Test added verifying algorithm enforcement

### References
- Source Reports: 9.1.2.md

### Priority
**Low** - Requires operator misconfiguration

---

## Issue: FINDING-035 - Async query JWT tokens issued without expiration claim
**Labels:** bug, security, priority:low
**Description:**
### Summary
Async query JWT tokens are issued without an exp claim, meaning they remain cryptographically valid indefinitely. Impact is limited: the cookie is httponly, the channel ID is a random UUID, and the data accessible is limited to the user's own async query results. The token is implicitly invalidated when the Flask session changes.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS Sections:** 9.2.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/async_events/async_query_manager.py`

### Remediation
Add an exp claim to the token (e.g., matching session timeout). PyJWT's decode() automatically validates exp when present, so no changes needed on the verification side.

### Acceptance Criteria
- [ ] exp claim added to async query JWT tokens
- [ ] Expiration time aligned with session timeout
- [ ] Test added verifying token expiration
- [ ] Token lifecycle documented

### References
- Related: FINDING-006, FINDING-036
- Source Reports: 9.2.1.md

### Priority
**Low** - Limited impact due to httponly cookie and channel ID

---

## Issue: FINDING-036 - MCP JWT verifier accepts tokens without expiration claim
**Labels:** bug, security, priority:low
**Description:**
### Summary
The MCP JWT verifier conditionally checks exp (if exp and exp < time.time()), meaning tokens without an exp claim are accepted without time boundary. Exploitation requires the IdP to issue tokens without exp (misconfiguration) AND token compromise.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS Sections:** 9.2.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/mcp_service/jwt_verifier.py`

### Remediation
Require the exp claim to be present: reject tokens where claims.get('exp') returns None.

### Acceptance Criteria
- [ ] exp claim presence enforced in JWT verifier
- [ ] Tokens without exp claim rejected
- [ ] Test added verifying exp claim requirement
- [ ] Appropriate error message returned

### References
- Related: FINDING-006, FINDING-035
- Source Reports: 9.2.1.md

### Priority
**Low** - Requires IdP misconfiguration and token compromise

---

## Issue: FINDING-037 - MD5 Used for UUID Namespace Generation (Legacy Path)
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `_uuid_namespace_from_md5` function in `superset/key_value/utils.py` uses MD5 for UUID namespace generation as a legacy fallback path. While SHA-256 alternative exists and is the recommended primary path, the MD5 path remains available when `HASH_ALGORITHM = 'md5'` or via `HASH_ALGORITHM_FALLBACKS`. Practical exploitation requires a targeted MD5 collision attack which is computationally expensive.

### Details
- **CWE:** CWE-328 (Use of Weak Hash)
- **ASVS Sections:** 11.4.1
- **ASVS Levels:** L1
- **Affected Files:** `superset/key_value/utils.py`

Mitigating factors include SHA-256 as primary algorithm and developer awareness (`# noqa: S324`).

### Remediation
Deprecate the MD5 fallback path with a deprecation warning and document a timeline for removal from HASH_ALGORITHM_FALLBACKS support.

### Acceptance Criteria
- [ ] Deprecation warning added for MD5 fallback path
- [ ] Removal timeline documented
- [ ] SHA-256 promoted as only supported algorithm
- [ ] Migration guide provided for existing deployments

### References
- Source Reports: 11.4.1.md

### Priority
**Low** - Legacy path with SHA-256 primary alternative

---

## Issue: FINDING-038 - SSH tunnel connections do not enforce host key verification
**Labels:** bug, security, priority:low
**Description:**
### Summary
The create_tunnel method in superset/extensions/ssh.py does not pass an ssh_host_key parameter to sshtunnel.open_tunnel, causing the library to use AutoAddPolicy and accept any SSH server key. A network-positioned attacker could MITM the SSH tunnel. Exploitation requires the SSH_TUNNELING feature flag to be enabled and an admin to have configured a tunnel.

### Details
- **CWE:** CWE-295 (Improper Certificate Validation)
- **ASVS Sections:** 12.3.1
- **ASVS Levels:** L2
- **Affected Files:** `superset/extensions/ssh.py`

### Remediation
Add an optional host_key field to the SSH tunnel model and pass it to open_tunnel. Log a warning when tunnels are created without host key verification.

### Acceptance Criteria
- [ ] host_key field added to SSH tunnel model
- [ ] host_key passed to open_tunnel when configured
- [ ] Warning logged when host key verification disabled
- [ ] Test added verifying host key enforcement
- [ ] Documentation updated with security guidance

### References
- Related: FINDING-010
- Source Reports: 12.3.1.md

### Priority
**Low** - Requires SSH_TUNNELING feature flag and admin configuration

---

## Issue: FINDING-039 - Swagger/OpenAPI Documentation UI Enabled by Default in All Environments
**Labels:** bug, security, priority:low
**Description:**
### Summary
FAB_API_SWAGGER_UI = True unconditionally. Requires authentication (@protect() decorator). DOWNGRADED from Low: no concrete attack scenario with meaningful impact — authenticated users viewing API docs for endpoints they already have access to is reconnaissance convenience, not exploitation per severity/remediation policy.

### Details
- **CWE:** CWE-215 (Information Exposure Through Debug Information)
- **ASVS Sections:** 13.4.5, 13.4.2
- **ASVS Levels:** L2
- **Affected Files:** `superset/config.py`

### Remediation
Disable Swagger UI by default or restrict to non-production environments: FAB_API_SWAGGER_UI = utils.parse_boolean_string(os.environ.get('SUPERSET_FAB_API_SWAGGER_UI', 'false'))

### Acceptance Criteria
- [ ] Swagger UI disabled by default
- [ ] Environment variable configuration added
- [ ] Test added verifying Swagger UI access control
- [ ] Documentation updated with configuration guidance

### References
- Source Reports: 13.4.5.md, 13.4.2.md

### Priority
**Low** - Requires authentication, limited impact

---

## Issue: FINDING-040 - Unauthenticated Endpoint Exposes Detailed Backend Version Information Including Git SHA
**Labels:** bug, security, priority:low
**Description:**
### Summary
The /version endpoint returns comprehensive version information including version string, Git SHA (8 chars), and branch name without authentication. Enables precise fingerprinting and CVE correlation.

### Details
- **CWE:** CWE-200 (Information Exposure)
- **ASVS Sections:** 13.4.5, 13.4.6
- **ASVS Levels:** L2, L3
- **Affected Files:** `superset/views/health.py`, `superset/config.py`

### Remediation
Require authentication on /version endpoint, or reduce response to major.minor version only, or add EXPOSE_VERSION_INFO configuration flag defaulting to False.

### Acceptance Criteria
- [ ] Authentication required on /version endpoint OR
- [ ] Version response reduced to major.minor only OR
- [ ] EXPOSE_VERSION_INFO configuration flag added (default False)
- [ ] Test added verifying version information exposure
- [ ] Documentation updated with security guidance

### References
- Related: FINDING-048, FINDING-060
- Source Reports: 13.4.5.md, 13.4.6.md

### Priority
**Low** - Information disclosure enabling reconnaissance

---
## Issue: FINDING-041 - Temporary Cache Entries Created Without Explicit TTL
**Labels:** bug, security, priority:low
**Description:**
### Summary
Filter state and explore form data subsystems call `cache.set()` without explicit timeout parameters, relying entirely on backend default configuration which may be indefinite. This violates data retention requirements and creates inconsistent TTL enforcement across the application.

### Details
The application's cache subsystems show inconsistent implementation of TTL (time-to-live) controls:
- **QueryCacheManager** implements explicit timeout passing, establishing a code convention for TTL enforcement
- **Filter state subsystem** (`superset/commands/dashboard/filter_state/create.py`) calls `cache.set()` without explicit timeout parameter
- **Form data subsystem** (`superset/commands/explore/form_data/create.py`) calls `cache.set()` without explicit timeout parameter

If the backend default timeout is 0/None, sensitive filter state and explore form data may persist in the cache backend indefinitely.

**Related ASVS Requirements:** 14.2.2, 14.2.4, 14.2.7 (L2/L3)

### Remediation
Pass explicit timeout values to `cache.set()` calls in:
1. `CreateFilterStateCommand.create()`
2. `CreateFormDataCommand.run()`

Use configuration values with sensible defaults (e.g., 86400 seconds). This enforces maximum retention regardless of default configuration and aligns with the pattern established by QueryCacheManager.

### Acceptance Criteria
- [ ] Fixed - Explicit timeout parameters added to all cache.set() calls in filter state creation
- [ ] Fixed - Explicit timeout parameters added to all cache.set() calls in form data creation
- [ ] Test added - Verify timeout values are passed correctly
- [ ] Test added - Verify entries expire as configured

### References
- CWE: N/A
- Files: `superset/commands/dashboard/filter_state/create.py`, `superset/commands/explore/form_data/create.py`

### Priority
**Low** - Data retention policy violation, but requires specific backend misconfiguration to manifest

---
## Issue: FINDING-042 - Expired Entry Cleanup Only Triggered Opportunistically
**Labels:** bug, security, priority:low
**Description:**
### Summary
Expired KeyValueEntry records remain in the database after their `expires_on` date if no new `add()` operations trigger cleanup. The `delete_expired_entries()` method is only called within `SupersetMetastoreCache.add()`, not on a schedule, violating automatic deletion requirements for data retention.

### Details
The metastore cache implementation in `superset/extensions/metastore_cache.py` only performs cleanup of expired entries during write operations:
- `delete_expired_entries()` is called in `SupersetMetastoreCache.add()`
- No scheduled or background cleanup mechanism exists
- Expired sensitive data may remain stored longer than intended if write operations are infrequent

**Related ASVS Requirements:** 14.2.7 (L3)

### Remediation
Implement one of the following approaches:
1. Add a scheduled cleanup task (cron job or Celery beat task) that regularly invokes `delete_expired_entries()`
2. Hook into existing scheduled maintenance tasks to include metastore cache cleanup
3. Add periodic cleanup independent of write operations

Ensure timely removal of expired sensitive data regardless of application write patterns.

### Acceptance Criteria
- [ ] Fixed - Scheduled cleanup mechanism implemented
- [ ] Fixed - Cleanup runs independently of write operations
- [ ] Test added - Verify expired entries are removed within acceptable timeframe
- [ ] Test added - Verify cleanup runs even when no writes occur

### References
- CWE: N/A
- Files: `superset/extensions/metastore_cache.py`, `superset/daos/key_value.py`

### Priority
**Low** - Expired data retention, but entries do eventually expire; impact depends on write frequency

---
## Issue: FINDING-043 - DatabaseSSHTunnel Schema Includes Credential Fields Without Output-Specific Exclusion
**Labels:** bug, security, priority:low
**Description:**
### Summary
The DatabaseSSHTunnel schema includes `password`, `private_key`, and `private_key_password` fields without `load_only=True` annotation. If used for response serialization without pre-masking, SSH tunnel credentials could be returned in API responses and exposed via logs, caches, and observability tools.

### Details
In `superset/databases/schemas.py`, the DatabaseSSHTunnel schema defines credential fields without output protection:
- `password`, `private_key`, `private_key_password` lack `load_only=True`
- If schema is used for serialization, credentials may appear in responses
- Even for admin-only endpoints, credentials in responses are subject to secondary exposure via:
  - Application logs
  - HTTP caches
  - Observability/monitoring tools
  - Browser developer tools

**Related ASVS Requirements:** 14.2.6 (L3)  
**CWE:** CWE-212 (Improper Removal of Sensitive Information Before Storage or Transfer)

### Remediation
Implement one of the following approaches:
1. Add `load_only=True` to credential fields (`password`, `private_key`, `private_key_password`)
2. Create separate input/output schemas with credentials only in input schema
3. Use marshmallow's `@post_dump` decorator to explicitly mask credential fields

This ensures credentials are only accepted on input and never serialized in API responses.

### Acceptance Criteria
- [ ] Fixed - Credential fields marked as load_only or removed from output schema
- [ ] Test added - Verify credentials never appear in serialized responses
- [ ] Test added - Verify credentials can still be accepted on input
- [ ] Documentation updated - Schema usage patterns documented

### References
- CWE: CWE-212
- Files: `superset/databases/schemas.py`

### Priority
**Low** - Requires admin access and specific usage pattern, but violates defense-in-depth principles

---
## Issue: FINDING-044 - File Upload Processing Does Not Strip Metadata from Uploaded Files
**Labels:** bug, security, priority:low
**Description:**
### Summary
File upload pipeline validates extension only; no metadata stripping step exists for Excel files which may contain PII (author, organization, last modified by). While pandas DataFrame extraction typically ignores file-level metadata, the original file may be stored temporarily with metadata intact.

### Details
The file upload processing in `superset/databases/schemas.py` does not strip metadata from uploaded files:
- Excel files can contain document properties (author, organization, last modified by, etc.)
- Current implementation only validates file extension
- pandas DataFrame extraction ignores metadata, but original file may be stored temporarily
- Violates requirement to remove sensitive information from metadata unless storage is consented to

**Related ASVS Requirements:** 14.2.8 (L3)

### Remediation
Add a metadata stripping step for uploaded files:
1. Use `openpyxl` to remove document properties from Excel files before processing
2. Strip properties: author, organization, last modified by, created, modified dates
3. Consider implementing for all supported file formats that can contain metadata (CSV comments, etc.)
4. Apply stripping before any temporary storage or processing

Example implementation:
```python
from openpyxl import load_workbook

def strip_excel_metadata(file_path):
    wb = load_workbook(file_path)
    wb.properties.creator = ""
    wb.properties.lastModifiedBy = ""
    wb.properties.company = ""
    wb.save(file_path)
```

### Acceptance Criteria
- [ ] Fixed - Metadata stripping implemented for Excel files
- [ ] Fixed - Stripping occurs before any storage or processing
- [ ] Test added - Verify metadata is removed from uploaded files
- [ ] Test added - Verify data extraction still works correctly
- [ ] Documentation updated - Supported file formats and metadata handling documented

### References
- CWE: N/A
- Files: `superset/databases/schemas.py`

### Priority
**Low** - Requires file upload access; metadata exposure is unintended but limited in scope

---
## Issue: FINDING-045 - Prophet Forecast Periods Field Lacks Upper Bound, Enabling Resource-Intensive Computation
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-supplied `periods` parameter in Prophet forecasting is unbounded, allowing attackers to request extremely large forecast periods (e.g., 10,000,000) that force resource-intensive computation and potential denial of service.

### Details
Data flow: User-supplied integer → `ChartDataProphetOptionsSchema.periods` → Prophet forecasting library → unbounded computation

In `superset/charts/schemas.py`, the `periods` field lacks validation:
- No maximum value constraint
- Large period values force Prophet to generate equally large forecast dataframes
- Can consume excessive CPU, memory, and time
- No configuration-based limit available

**Related ASVS Requirements:** 15.2.2 (L2)  
**CWE:** CWE-400 (Uncontrolled Resource Consumption)

**Related Findings:** FINDING-004, FINDING-012, FINDING-030 (resource exhaustion pattern)

### Remediation
Add validation to the `periods` field in `ChartDataProphetOptionsSchema`:

```python
periods = fields.Integer(
    validate=Range(min=1, max=10000),  # or use config
    description="Number of periods to forecast"
)
```

Or use configurable limit:
```python
periods = fields.Integer(
    validate=Range(min=1, max=lambda: current_app.config.get("MAX_PROPHET_PERIODS", 10000)),
    description="Number of periods to forecast"
)
```

### Acceptance Criteria
- [ ] Fixed - Maximum value constraint added to periods field
- [ ] Fixed - Configuration option added for MAX_PROPHET_PERIODS
- [ ] Test added - Verify requests exceeding limit are rejected with 400
- [ ] Test added - Verify valid periods still work correctly
- [ ] Documentation updated - Limits documented for API consumers

### References
- CWE: CWE-400
- Files: `superset/charts/schemas.py`

### Priority
**Low** - Requires authenticated access; resource limits may exist at infrastructure level

---
## Issue: FINDING-046 - Stacktrace Exposed to Clients in Visualization Error Responses
**Labels:** bug, security, priority:low
**Description:**
### Summary
Stacktraces are unconditionally included in visualization error responses to authenticated clients without checking the `SHOW_STACKTRACE` configuration flag. This exposes internal file paths, library versions, code structure, and database driver details that aid reconnaissance.

### Details
In `superset/viz.py`, the `BaseViz.get_df_payload()` method includes stacktraces in error responses without configuration checks:
- Stacktraces exposed regardless of `SHOW_STACKTRACE` config setting
- Other parts of codebase (e.g., `superset/utils/core.py`) properly gate stacktrace inclusion
- Exposed information includes:
  - Internal file paths
  - Library versions
  - Code structure and method names
  - Database driver details
  - SQL query structure

**Related ASVS Requirements:** 15.2.3 (L2)  
**CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)

**Related Findings:** FINDING-005 (information disclosure pattern)

### Remediation
Gate stacktrace inclusion behind configuration check, matching the pattern used elsewhere:

```python
error_obj = {
    "error": str(error),
    "query": query_context.query,
}

if current_app.debug or current_app.config.get("SHOW_STACKTRACE"):
    error_obj["stacktrace"] = utils.get_stacktrace()

return error_obj
```

### Acceptance Criteria
- [ ] Fixed - Stacktrace inclusion gated behind SHOW_STACKTRACE config
- [ ] Fixed - Consistent with error handling in other modules
- [ ] Test added - Verify stacktrace hidden when SHOW_STACKTRACE=False
- [ ] Test added - Verify stacktrace shown when SHOW_STACKTRACE=True
- [ ] Test added - Verify stacktrace shown in debug mode

### References
- CWE: CWE-209
- Files: `superset/viz.py`

### Priority
**Low** - Requires authenticated access; information disclosure aids but doesn't directly enable attacks

---
## Issue: FINDING-047 - Dynamic Method Dispatch on User-Controlled Input Without Whitelist
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-controlled `resample_method` parameter is passed to `getattr()` on a pandas Resampler object without whitelist validation. While practical impact is limited, this is inconsistent with the safer pattern used by `apply_rolling()` which validates `rolling_type` against a known set.

### Details
In `superset/viz.py`, the resample method handling lacks input validation:
- `form_data["resample_method"]` passed directly to `getattr()`
- No whitelist of allowed method names
- Inconsistent with `apply_rolling()` which validates `rolling_type` against `ALLOWED_ROLLING_TYPES`
- While target object (pandas Resampler) has safe no-argument methods, this violates secure coding principles

**Related ASVS Requirements:** 15.2.5, 15.3.5 (L2/L3)  
**CWE:** CWE-470 (Use of Externally-Controlled Input to Select Classes or Code)

### Remediation
Add whitelist validation matching the pattern used by `apply_rolling()`:

```python
ALLOWED_RESAMPLE_METHODS = {
    "mean", "sum", "min", "max", "median", 
    "std", "var", "first", "last", "count"
}

def apply_resample(self, df, resample_rule, resample_method):
    if resample_method not in ALLOWED_RESAMPLE_METHODS:
        raise QueryObjectValidationError(
            f"Invalid resample method: {resample_method}"
        )
    resampler = df.resample(resample_rule)
    return getattr(resampler, resample_method)()
```

### Acceptance Criteria
- [ ] Fixed - ALLOWED_RESAMPLE_METHODS whitelist defined
- [ ] Fixed - Validation added before getattr() call
- [ ] Test added - Verify whitelisted methods work correctly
- [ ] Test added - Verify non-whitelisted methods are rejected
- [ ] Documentation updated - Supported resample methods documented

### References
- CWE: CWE-470
- Files: `superset/viz.py`

### Priority
**Low** - Limited practical impact due to safe target object, but violates secure coding principles

---
## Issue: FINDING-048 - DashboardDatasetSchema Exposes Internal SQL Definitions and Operational Metadata to Guest Users
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `DashboardDatasetSchema.post_dump()` removes only `owners` and `database` fields for guest users but leaves `sql`, `select_star`, `perm`, `edit_url`, `fetch_values_predicate`, and `template_params` exposed. Guest users receive internal SQL definitions, permission strings, and internal URL paths that could aid reconnaissance.

### Details
In `superset/dashboards/schemas.py`, the guest user filtering is incomplete:
- Current filtering removes: `owners`, `database`
- Still exposed to guest users:
  - `sql` - Internal SQL query definitions
  - `select_star` - SELECT * query templates
  - `perm` - Permission strings revealing internal structure
  - `edit_url` - Internal URL paths
  - `fetch_values_predicate` - Query predicates
  - `template_params` - Template parameters

Guest users are considered untrusted per the threat model, and this information aids reconnaissance for privilege escalation attacks.

**Related ASVS Requirements:** 15.3.1 (L1)  
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Related Findings:** FINDING-040, FINDING-060 (information disclosure to untrusted users)

### Remediation
Extend the guest user `post_dump` filter to remove additional sensitive fields:

```python
if is_guest:
    for key in [
        "owners", "database", "sql", "select_star", 
        "perm", "edit_url", "fetch_values_predicate", 
        "template_params"
    ]:
        data.pop(key, None)
```

### Acceptance Criteria
- [ ] Fixed - Extended field removal for guest users
- [ ] Fixed - All internal operational metadata removed
- [ ] Test added - Verify guest users receive filtered response
- [ ] Test added - Verify non-guest users receive complete response
- [ ] Test added - Verify dashboards still function for guest users

### References
- CWE: CWE-200
- Files: `superset/dashboards/schemas.py`

### Priority
**Low** - Information disclosure to guest users; aids reconnaissance but doesn't directly enable attacks

---
## Issue: FINDING-049 - Explore View Form Data Merging Without Schema Validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The explore view's `get_form_data` merges parameters from multiple sources (JSON body, form body, query string) using `dict.update()` without Marshmallow schema validation. The `REJECTED_FORM_DATA_KEYS` denylist blocks known-dangerous keys but is less robust than the allowlist approach used by REST API endpoints.

### Details
In `superset/views/utils.py`, the form data merging uses a denylist approach:
- Parameters merged from JSON body, form body, and query string
- Uses `dict.update()` without schema validation
- `REJECTED_FORM_DATA_KEYS` denylist blocks known-dangerous keys
- REST API endpoints use allowlist (Marshmallow schema with `Meta: unknown = EXCLUDE`)
- Denylist approach is less secure: unknown dangerous keys may bypass filtering

**Related ASVS Requirements:** 15.3.3 (L2)  
**CWE:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)

**Related Findings:** FINDING-061 (mass assignment pattern)

### Remediation
Replace the `REJECTED_FORM_DATA_KEYS` denylist with a schema-based allowlist:

```python
from marshmallow import Schema, fields, EXCLUDE

class ExploreFormDataSchema(Schema):
    class Meta:
        unknown = EXCLUDE  # Reject unknown fields
    
    datasource = fields.String()
    viz_type = fields.String()
    # ... define all allowed fields
    
def get_form_data(request):
    schema = ExploreFormDataSchema()
    # Merge sources
    combined_data = {}
    combined_data.update(request.args)
    combined_data.update(request.form)
    # Validate and filter
    return schema.load(combined_data)
```

### Acceptance Criteria
- [ ] Fixed - Marshmallow schema defined for explore form_data
- [ ] Fixed - Schema configured with unknown = EXCLUDE
- [ ] Fixed - Denylist approach replaced with allowlist
- [ ] Test added - Verify allowed fields are accepted
- [ ] Test added - Verify unknown fields are rejected
- [ ] Test added - Verify dangerous keys are blocked

### References
- CWE: CWE-915
- Files: `superset/views/utils.py`

### Priority
**Low** - Denylist currently blocks known dangerous keys; risk is future bypass via unknown keys

---
## Issue: FINDING-050 - Authentication failure logs in jwt_verifier.py lack request context metadata (who/where)
**Labels:** bug, security, priority:low
**Description:**
### Summary
Authentication failure events in the MCP service are logged at WARNING level with only the generic failure reason. The log entry does not explicitly include request metadata (source IP, request path, correlation ID) needed for forensic investigation of authentication attacks.

### Details
In `superset/mcp_service/jwt_verifier.py`, the `_auth_error_handler` logs authentication failures:
- Only includes generic failure reason
- Missing request context: source IP, request path, correlation ID
- While Python's logging formatter CAN inject some data, the application code doesn't ensure it
- Database `logs` table has user_id, action, dttm, path fields, but JWT failures go to Python logging only
- Insufficient for forensic investigation of authentication attacks

**Related ASVS Requirements:** 16.2.1 (L2)  
**CWE:** CWE-778 (Insufficient Logging)

**Related Findings:** FINDING-013, FINDING-052 (insufficient logging pattern)

### Remediation
Include request context in authentication failure logs:

```python
def _auth_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.warning(
        "JWT authentication failed: %s | IP: %s | Path: %s | User-Agent: %s",
        str(exc),
        request.client.host if request.client else "unknown",
        request.url.path,
        request.headers.get("user-agent", "unknown")
    )
    return JSONResponse(
        status_code=401,
        content={"detail": "Authentication failed"}
    )
```

### Acceptance Criteria
- [ ] Fixed - Source IP included in authentication failure logs
- [ ] Fixed - Request path included in authentication failure logs
- [ ] Fixed - User-Agent included in authentication failure logs
- [ ] Test added - Verify log format includes all required fields
- [ ] Test added - Verify logs support forensic investigation scenarios
- [ ] Documentation updated - Log format documented for security monitoring

### References
- CWE: CWE-778
- Files: `superset/mcp_service/jwt_verifier.py`

### Priority
**Low** - Impacts forensic investigation capability but doesn't directly affect security controls

---
## Issue: FINDING-051 - Log pruning uses timezone-naive datetime.now() instead of UTC-aware datetime
**Labels:** bug, priority:low
**Description:**
### Summary
The log pruning command uses `datetime.now()` which returns timezone-naive local time. If `Log.dttm` stores UTC timestamps (as recommended), and the server's local timezone is not UTC, the retention comparison will be incorrect by the timezone offset amount.

### Details
In `superset/commands/logs/prune.py`, the log pruning logic has a timezone mismatch:
- Uses `datetime.now()` which returns timezone-naive local time
- If `Log.dttm` stores UTC timestamps (recommended practice)
- And server timezone is not UTC
- Then comparison is incorrect by the offset amount

Example impact: On a UTC+5 server, logs would be deleted 5 hours earlier than intended, effectively reducing retention by 5 hours.

**Related ASVS Requirements:** 16.2.2 (L2)  
**CWE:** CWE-187 (Partial String Comparison)

### Remediation
Replace `datetime.now()` with UTC-aware datetime:

```python
from datetime import datetime, timezone

def run(self) -> None:
    retention_days = config["SUPERSET_LOG_RETENTION_DAYS"]
    cutoff_date = datetime.now(tz=timezone.utc) - timedelta(days=retention_days)
    
    LogDAO.prune_logs(cutoff_date)
```

### Acceptance Criteria
- [ ] Fixed - datetime.now(tz=timezone.utc) used for cutoff calculation
- [ ] Fixed - Consistent timezone handling throughout log management
- [ ] Test added - Verify retention operates correctly with UTC timestamps
- [ ] Test added - Verify behavior independent of server timezone
- [ ] Test added - Verify edge cases around daylight saving time transitions

### References
- CWE: CWE-187
- Files: `superset/commands/logs/prune.py`

### Priority
**Low** - Only affects installations where server timezone differs from log storage timezone

---
## Issue: FINDING-052 - Error Sanitization Utility Does Not Log Security-Relevant Bypass Indicators Before Redaction
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `_sanitize_validation_error` function redacts sensitive information from error responses but does not log the original unsanitized error server-side. If calling code doesn't log before sanitization, evidence of input validation bypass attempts (SQL injection probes, schema discovery) would be lost.

### Details
In `superset/mcp_service/utils/error_sanitization.py`, the sanitization function:
- Redacts sensitive information from errors before returning to client (correct)
- Does not log the original unsanitized error server-side
- Relies on calling code to log before sanitization
- If calling code doesn't log, security-relevant indicators are lost:
  - SQL injection probe attempts
  - Schema discovery attempts
  - Input validation bypass patterns

**Related ASVS Requirements:** 16.3.3 (L2)  
**CWE:** CWE-778 (Insufficient Logging)

**Related Findings:** FINDING-013, FINDING-050 (insufficient logging pattern)

### Remediation
Add optional server-side logging within the sanitization function:

```python
def _sanitize_validation_error(
    error: ValidationError,
    log_original: bool = True
) -> dict[str, Any]:
    """Sanitize validation errors before returning to client.
    
    Args:
        error: The validation error to sanitize
        log_original: Whether to log the original error server-side
    """
    if log_original:
        logger.info(
            "Validation error (unsanitized): %s",
            error.messages,
            extra={"error_type": "validation", "original_error": str(error)}
        )
    
    # Existing sanitization logic
    return sanitized_error
```

Or ensure all callers log before sanitizing:
```python
try:
    # validation logic
except ValidationError as e:
    logger.info("Validation error: %s", e.messages)
    return _sanitize_validation_error(e)
```

### Acceptance Criteria
- [ ] Fixed - Original errors logged server-side before sanitization
- [ ] Fixed - Logs include sufficient detail for security analysis
- [ ] Test added - Verify original errors are logged
- [ ] Test added - Verify sanitized errors still returned to client
- [ ] Documentation updated - Logging requirements documented for error handlers

### References
- CWE: CWE-778
- Files: `superset/mcp_service/utils/error_sanitization.py`

### Priority
**Low** - Impacts detection capability but doesn't directly affect security controls

---
## Issue: FINDING-053 - DEBUG-Level Logs Include Attacker-Controlled JWT Claim Values Without Encoding
**Labels:** bug, security, priority:low
**Description:**
### Summary
JWT claim values (algorithm, issuer, audience, client_id) are logged at DEBUG level using Python's `%s` formatting without sanitization of control characters. An attacker can craft a JWT with claims containing newlines to inject fake log entries. Impact limited to DEBUG level which is typically disabled in production.

### Details
In `superset/mcp_service/jwt_verifier.py`, JWT claims are logged without sanitization:
- `token_alg` logged before signature verification (fully attacker-controlled)
- Issuer, audience, client_id logged at DEBUG level
- Uses Python `%s` formatting without control character sanitization
- Attacker can inject newlines to create fake log entries

Example attack:
```
{"alg": "HS256\n[INFO] Fake log entry injected by attacker"}
```

Impact limited: DEBUG level typically disabled in production.

**Related ASVS Requirements:** 16.4.1 (L2)  
**CWE:** CWE-117 (Improper Output Neutralization for Logs)

### Remediation
Create sanitization helper and apply to all JWT claim values logged:

```python
def _sanitize_for_log(value: str) -> str:
    """Remove control characters from log values."""
    if not isinstance(value, str):
        return str(value)
    # Remove newlines, carriage returns, and other control chars
    return value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

# Usage
logger.debug(
    "JWT validation - Algorithm: %s, Issuer: %s",
    _sanitize_for_log(token_alg),
    _sanitize_for_log(issuer)
)
```

Or configure structured JSON logging for the MCP service to automatically handle encoding.

### Acceptance Criteria
- [ ] Fixed - Sanitization helper implemented
- [ ] Fixed - Applied to all JWT claim values in DEBUG logs
- [ ] Fixed - Control characters properly escaped
- [ ] Test added - Verify newlines cannot inject fake log entries
- [ ] Test added - Verify legitimate values still logged correctly
- [ ] Consider - Structured JSON logging for MCP service

### References
- CWE: CWE-117
- Files: `superset/mcp_service/jwt_verifier.py`

### Priority
**Low** - Only affects DEBUG level logging, typically disabled in production

---
## Issue: FINDING-054 - JWT verifier catch-all does not explicitly handle network-related exceptions from JWKS endpoint
**Labels:** bug, priority:low
**Description:**
### Summary
When the JWKS endpoint is unreachable, network exceptions (`ConnectionError`, `TimeoutError`, `OSError`) are not explicitly caught by the application's error handling. These propagate to Starlette's default handler, resulting in HTTP 500 instead of a clean 401 response. Authentication still fails closed (not fail-open), but the error response is degraded.

### Details
In `superset/mcp_service/jwt_verifier.py`, the exception handling doesn't cover network errors:
- JWT library raises network exceptions when JWKS endpoint is unreachable
- `ConnectionError`, `TimeoutError`, `OSError` not explicitly caught
- These propagate to Starlette's default handler
- Results in HTTP 500 instead of HTTP 401
- Authentication remains fail-closed (secure)
- But error response and logging are degraded

Impact: Authentication security is not compromised (fails closed), but operational monitoring and client error handling are affected.

**Related ASVS Requirements:** 16.5.2 (L2)  
**CWE:** CWE-755 (Improper Handling of Exceptional Conditions)

### Remediation
Broaden exception handling to include network-related errors:

```python
try:
    # JWT verification logic
except jwt.InvalidTokenError as e:
    # Existing handling
    logger.warning("JWT validation failed: %s", str(e))
    raise
except (ConnectionError, TimeoutError, OSError) as e:
    # Network errors accessing JWKS endpoint
    logger.error(
        "Failed to access JWKS endpoint: %s | %s",
        jwks_url,
        str(e)
    )
    raise jwt.InvalidTokenError("Unable to verify token: JWKS endpoint unreachable")
except Exception as e:
    # Catch-all for unexpected errors
    logger.error("Unexpected error during JWT verification: %s", str(e))
    raise jwt.InvalidTokenError("Token verification failed")
```

### Acceptance Criteria
- [ ] Fixed - Network exceptions explicitly caught and handled
- [ ] Fixed - HTTP 401 returned for JWKS endpoint failures
- [ ] Fixed - Appropriate error logging for network failures
- [ ] Test added - Verify behavior when JWKS endpoint is unreachable
- [ ] Test added - Verify HTTP 401 response (not 500)
- [ ] Test added - Verify authentication still fails closed

### References
- CWE: CWE-755
- Files: `superset/mcp_service/jwt_verifier.py`

### Priority
**Low** - Authentication remains secure (fail-closed); impact limited to error response quality during JWKS outages