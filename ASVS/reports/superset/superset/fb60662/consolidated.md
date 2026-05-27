# Security Audit Consolidated Report — apache/superset/superset

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | fb60662 |
| Date | May 27, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 46 |
| Actionable Issues | 45 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 45 actionable items.*

## Executive Summary

### Severity Distribution


| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High     | 0 | 0.0% |
| Medium   | 17 | 38.6% |
| Low      | 26 | 59.1% |
| Info     | 1 | 2.3% |

### ASVS Level Coverage

This audit assessed 23 security domains against OWASP ASVS Level 1 requirements. Coverage spans authentication controls, authorization enforcement, input validation, session management, cryptographic implementation, API data minimization, file upload security, and additional domains. A total of 70 source reports were consolidated into 46 unique findings.

### Top 5 Risks

1. **SSH Tunnel Credentials Returned Without Masking (Critical)** — GET endpoints on the database API return SSH tunnel credentials (private keys, passwords) in plaintext, exposing secrets to any user with read access to database connection objects. This violates ASVS 15.3.1 (API data minimization).

2. **Query Endpoint Bypasses Field Restrictions (Critical)** — The `get_updated_since` endpoint in the queries API uses `to_dict()` serialization that bypasses the configured `list_columns` restrictions, potentially exposing sensitive query metadata including connection strings and internal identifiers.

3. **AES-CBC Mode Without Authenticated Encryption (FINDING-004, Medium)** — The encrypted field implementation uses AES-CBC without an HMAC or authenticated encryption mode (e.g., AES-GCM), leaving stored secrets vulnerable to padding oracle attacks and ciphertext manipulation.

4. **Authentication Rate Limiting Not Active by Default (FINDING-012, Medium)** — No rate limiting is applied to authentication endpoints in the default configuration, leaving the application vulnerable to credential stuffing and brute-force attacks without operator intervention.

5. **Async Query JWT Tokens Have No Expiration Claim (FINDING-019, Medium)** — JWT tokens issued for async query result retrieval lack an `exp` claim, meaning compromised tokens remain valid indefinitely and cannot be time-bounded without manual revocation.

### Positive Controls Observed

The audit identified 40 positive security controls that demonstrate mature security practices across the codebase:

- **OAuth2 Authorization Security** — The implementation uses Authorization Code flow exclusively with PKCE (S256), signed JWT state parameters with 5-minute expiry for CSRF protection, single-use code verifiers, and client-side refresh token rotation with distributed locking. Failed refresh attempts force re-authentication.

- **TLS Transport Security** — TLS termination and protocol enforcement are properly delegated to deployment infrastructure. Redis SSL connections enforce certificate validation. WebSocket transport is opt-in with TLS delegated to infrastructure.

- **Source Control Metadata Protection** — Flask's route-based architecture and Werkzeug's path traversal protections inherently prevent access to `.git` directories and other source control metadata.

- **Input Validation Architecture** — Server-side validation is enforced through Marshmallow schemas across all REST API endpoints, independent of any client-side validation.

- **File Upload Security** — Import endpoints validate ZIP content via `is_zipfile()`, process all content in memory without filesystem writes to untrusted paths, and apply `check_is_safe_zip()` in extension loading paths. Extension management is restricted to administrator access.

- **Authorization Enforcement** — Authorization rules are documented and enforced at the trusted service layer, with function-level and data-specific access controls.

- **Password Management** — Password handling follows ASVS best practices: no restrictive composition rules, no truncation or transformation, paste functionality permitted, and change operations require current password verification.

- **Default Credentials** — No auto-created default user accounts exist; all user provisioning is delegated to the deployment operator.

---


> **Note:** 2 Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

## 3.3 Medium

#### FINDING-003: SSH Tunnel `server_address` Lacks Hostname Format Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-918 |
| ASVS sections | 1.2.5 |
| Files | superset/databases/ssh_tunnel/models.py, superset/commands/database/test_connection.py |
| Source Reports | 1.2.5.md |
| Related | - |

**Description:**

The `server_address` field in the SSH tunnel model accepts arbitrary text without hostname or IP address format validation. While the current implementation uses the paramiko-based `sshtunnel` library (which does not spawn shell commands), this represents a defense-in-depth gap against future implementation changes and enables SSRF attacks to arbitrary internal hosts.

**Remediation:**

Add hostname/IP format validation and optional allowlist/denylist for SSH tunnel `server_address` to prevent SSRF and establish defense-in-depth against future implementation changes.

---

#### FINDING-004: AES-CBC Mode Used Without Authenticated Encryption

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-327 |
| ASVS sections | 11.3.1, 11.3.2 |
| Files | superset/utils/encrypt.py, superset/models/core.py, superset/databases/ssh_tunnel/models.py |
| Source Reports | 11.3.1.md, 11.3.2.md |
| Related | FINDING-025 |

**Description:**

The `sqlalchemy_utils.EncryptedType` with default `AesEngine` implements AES-256-CBC, which does not provide authenticated encryption (AEAD). All database credentials, SSH private keys, OAuth2 tokens, and server certificates are encrypted with this non-authenticated mode. ASVS 11.3.1 prohibits insecure block modes and requires authenticated encryption. ASVS 11.3.2 requires only approved ciphers and modes such as AES with GCM. Attacker capability required: Database-level read/write access. Exploitability: Low in default deployment — no interactive decryption oracle is exposed to external attackers; exploitation requires direct database access. The lack of authenticated encryption is primarily a defense-in-depth concern.

**Remediation:**

Configure the encryption adapter to explicitly use AesGcmEngine which provides authenticated encryption. Modify SQLAlchemyUtilsAdapter.create() to specify engine=AesGcmEngine as the default. Migration to AES-GCM requires re-encrypting all existing data using the SecretsMigrator pattern already present in the codebase.

---

#### FINDING-005: Registration Hash Token Exposed in User Registrations API

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-200 |
| ASVS sections | 15.3.1 |
| Files | superset/security/api.py |
| Source Reports | 15.3.1.md |
| Related | |

**Description:**

The UserRegistrationsRestAPI class includes registration_hash in its list_columns configuration. This token is used for email verification during user registration and should not be exposed in API list responses, as it allows bypassing the email verification step. While this endpoint likely requires administrator permissions, the token serves no legitimate purpose in list responses and violates the principle of least privilege.

**Remediation:**

Remove registration_hash from the list_columns configuration in UserRegistrationsRestAPI.

---

#### FINDING-006: Missing upper bound validation on `row_limit` enabling potential resource exhaustion

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-770 |
| ASVS sections | 2.2.1 |
| Files | superset/charts/schemas.py |
| Source Reports | 2.2.1.md |
| Related | - |

**Description:**

The row_limit field in ChartDataQueryObjectSchema validates only for min=0 with no upper bound. An authenticated user could set row_limit to an extremely large value (e.g., 2^31-1), causing the database to attempt returning billions of rows and the application to buffer them in memory, leading to denial of service.

**Remediation:**

Add an upper bound validation that references the application configuration, e.g., Range(min=0, max=100000) or reference config['SQL_MAX_ROW'].

---

#### FINDING-007: Legacy database URI validator missing unsafe connection check

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS sections | 2.2.1 |
| Files | superset/views/database/validators.py |
| Source Reports | 2.2.1.md |
| Related | FINDING-029, FINDING-030, FINDING-031 |

**Description:**

The legacy views/database/validators.py sqlalchemy_uri_validator does not call check_sqlalchemy_uri() which is present in the REST API validator in databases/schemas.py. This could allow bypass of the PREVENT_UNSAFE_DB_CONNECTIONS safeguard if the legacy view is still accessible, potentially allowing filesystem access through SQLite URIs. Requires Admin user with database creation permissions through legacy UI.

**Remediation:**

Add check_sqlalchemy_uri() call to views/database/validators.py or deprecate the legacy validator if the view is no longer in use.

---

#### FINDING-008: WORKING State Guard Skipped for REPORT Type in SUCCESS State

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-362 |
| ASVS sections | 2.3.1 |
| Files | superset/commands/report/execute.py |
| Source Reports | 2.3.1.md |
| Related | - |

**Description:**

The report execution state machine implements a WORKING state guard to prevent concurrent execution. This guard is correctly applied in ReportNotTriggeredErrorState.next() for all report types, and in ReportSuccessState.next() for ALERT types. However, for REPORT types in SUCCESS state, the WORKING state is never set before self.send() is called, creating a window for concurrent execution and duplicate notifications. Impact includes duplicate notifications and resource waste.

**Remediation:**

Add `self.update_report_schedule_and_log(ReportState.WORKING)` for the REPORT type path in ReportSuccessState.next() before calling self.send(), matching the pattern in ReportNotTriggeredErrorState.next().

---

#### FINDING-009: Error State Recovery in ReportSuccessState Lacks Finally Block for State Transition

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-755 |
| ASVS sections | 2.3.1 |
| Files | superset/commands/report/execute.py |
| Source Reports | 2.3.1.md |
| Related | - |

**Description:**

When an exception occurs during alert processing in ReportSuccessState.next(), the code attempts to send an error notification and update the state to ERROR. However, if send_error() itself raises an exception (e.g., all notification channels fail), the state update to ERROR is never reached. The report remains in WORKING state indefinitely until the working_timeout expires. This pattern is correctly handled with a finally block in ReportNotTriggeredErrorState.next().

**Remediation:**

Wrap send_error() in a try/except and use a finally block to ensure update_report_schedule_and_log(ReportState.ERROR) is always called, matching the pattern in ReportNotTriggeredErrorState.next().

---

#### FINDING-010: Streaming CSV Response Uses Non-Standard Charset Specification

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-116 |
| ASVS sections | 4.1.1 |
| Files | superset/charts/data/api.py |
| Source Reports | 4.1.1.md |
| Related | FINDING-024, FINDING-033 |

**Description:**

The streaming CSV export functionality embeds the charset parameter directly in the `mimetype` argument to Flask's `Response` constructor, which is non-standard API usage that can result in malformed Content-Type headers depending on the Werkzeug version. In Werkzeug 2.x this results in doubled charset parameters; behavior is version-dependent.

**Remediation:**

Change `mimetype=f"text/csv; charset={encoding}"` to `content_type=f"text/csv; charset={encoding}"` in `_create_streaming_csv_response`, or create a StreamingCsvResponse class following the CsvResponse pattern.

---

#### FINDING-011: No file size limit on import endpoint ZIP processing

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-400 |
| ASVS sections | 5.2.1 |
| Files | superset/importexport/api.py |
| Source Reports | 5.2.1.md |
| Related | FINDING-034 |

**Description:**

The import endpoint at `superset/importexport/api.py` processes uploaded ZIP files without enforcing size limits before decompression. An authenticated user with import permissions could upload a decompression bomb or very large ZIP that exhausts memory.

**Remediation:**

Add explicit file size validation before processing the upload, and individual entry size limits when extracting ZIP contents. Configure MAX_CONTENT_LENGTH and add application-level validation.

---

#### FINDING-012: Authentication Rate Limiting Is Not Active by Default

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-307 |
| ASVS sections | 6.3.1 |
| Files | superset/security/manager.py |
| Source Reports | 6.3.1.md |
| Related | - |

**Description:**

The authentication rate limiting is gated by `self.is_auth_limited`, which reads `AUTH_RATE_LIMITED` from Flask-AppBuilder's configuration. In Flask-AppBuilder, `AUTH_RATE_LIMITED` defaults to `False`. This means that in a default Superset deployment without explicit configuration, the login endpoint has no rate limiting, allowing attackers to perform credential stuffing and password brute force attacks.

**Remediation:**

Enable rate limiting by default in Superset's default configuration: AUTH_RATE_LIMITED = True, AUTH_RATE_LIMIT = "5 per 40 second". Additionally, consider applying rate limiting unconditionally in register_views().

---

#### FINDING-013: No Protection Against Malicious Account Lockout via Deliberate Failed Logins

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-645 |
| ASVS sections | 6.3.1 |
| Files | superset/security/manager.py |
| Source Reports | 6.3.1.md |
| Related | - |

**Description:**

Flask-AppBuilder's `SecurityManager` provides `AUTH_MAX_LOGIN_ATTEMPTS` which locks accounts after N failed attempts by incrementing `fail_login_count`. However, there is no mechanism to prevent an attacker from deliberately locking legitimate user accounts by sending failed login attempts with known usernames. Without protections such as temporary lockout with automatic unlock, CAPTCHA challenges, or IP-based rate limiting before account lockout triggers, an attacker who knows valid usernames can perform a denial-of-service attack by locking all accounts.

**Remediation:**

Implement rate limiting that takes precedence over account lockout, so that excessive failed attempts from a single IP are blocked before triggering lockout. Additionally, implement automatic account unlock after a configurable cooldown (e.g., AUTH_LOCKOUT_DURATION_SECONDS = 900).

---

#### FINDING-014: No password minimum length enforcement in SupersetSecurityManager

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-521 |
| ASVS sections | 6.2.1 |
| Files | superset/security/manager.py |
| Source Reports | 6.2.1.md |
| Related | FINDING-015 |

**Description:**

The `SupersetSecurityManager` extends Flask-AppBuilder's `SecurityManager` but does not implement or override any password length validation. There is no `validate_password()` method, no minimum length configuration enforcement, and no password policy checking visible in the security manager layer that Superset controls. When DB authentication with self-registration is enabled, a user could register with a trivially short password.

**Remediation:**

Implement validate_password() override in SupersetSecurityManager enforcing a minimum 8-character length. Set AUTH_MIN_PASSWORD_LENGTH = 8 in the default Superset configuration.

---

#### FINDING-015: No common password blocklist check during registration or password change

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-521 |
| ASVS sections | 6.2.4 |
| Files | superset/security/manager.py |
| Source Reports | 6.2.4.md |
| Related | FINDING-014 |

**Description:**

The `SupersetSecurityManager` does not implement any common password checking. There is no blocklist, no integration with a common password dictionary, and no `validate_password()` override that would reject commonly used passwords during registration or password change. Users can set well-known passwords like "password123" that are trivially guessable via credential stuffing attacks.

**Remediation:**

Integrate a common password blocklist (at least top 3000 passwords) into a validate_password() override in SupersetSecurityManager. Consider integration with Have I Been Pwned API (k-anonymity model) for compromised password detection.

---

#### FINDING-016: No mechanism to expire initial passwords or force change on first use

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-262 |
| ASVS sections | 6.4.1 |
| Files | superset/security/manager.py |
| Source Reports | 6.4.1.md |
| Related | - |

**Description:**

The SupersetSecurityManager and SupersetUserApi extend Flask-AppBuilder's base security implementations. The provided code does not implement secure random password generation for admin-created accounts, does not mark initial passwords for expiration, does not enforce password change on first login, and does not implement activation codes with short-lived expiration. Admin creates user via API/UI → FAB UserApi sets password → No expiration or force-change-on-first-login logic applied.

**Remediation:**

Add initial password lifecycle management: implement a password_must_change flag on user accounts created by administrators, with login middleware that forces password change before allowing other operations. Generate secure random initial passwords and set configurable expiration (e.g., 24 hours).

---

#### FINDING-017: No explicit session regeneration on user authentication in security manager

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-384 |
| ASVS sections | 7.2.4 |
| Files | superset/security/manager.py |
| Source Reports | 7.2.4.md |
| Related | - |

**Description:**

The `on_user_login()` method in `superset/security/manager.py` performs only audit logging without triggering session regeneration. If Flask-Login's `login_user()` or the auth view does not call `session.regenerate()` or `session.clear()` before login, the old session token remains valid, enabling potential session fixation attacks.

**Remediation:**

Add `session.clear()` or equivalent session regeneration call in `on_user_login()` before populating the new session, or verify that the upstream `SupersetAuthView` handles this.

---

#### FINDING-018: No active session termination when user account is disabled or deleted

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS sections | 7.4.2 |
| Files | superset/security/manager.py |
| Source Reports | 7.4.2.md |
| Related | FINDING-019, FINDING-038, FINDING-045 |

**Description:**

The `post_update` and `post_delete` handlers in `superset/security/manager.py` (`SupersetUserApi` class) perform only audit logging without terminating the disabled/deleted user's active sessions. The user retains access until Flask-Login's passive `is_active` check triggers on their next request, creating a window for continued access.

**Remediation:**

Implement a `_terminate_user_sessions()` method that clears all server-side session data for a user when their account is disabled or deleted, and call it from `post_update` (when `active` becomes False) and `post_delete`.

---

#### FINDING-019: Async Query JWT Tokens Have No Expiration Claim

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS sections | 9.2.1 |
| Files | superset/async_events/async_query_manager.py |
| Source Reports | 9.2.1.md |
| Related | FINDING-018, FINDING-038, FINDING-045 |

**Description:**

JWT tokens created by the async query manager contain only `channel` and `sub` claims with no `exp`, `nbf`, or `iat`. Tokens are decoded without requiring expiration, meaning captured tokens can be replayed indefinitely to access async query event channels.

**Remediation:**

Add `exp` and `iat` claims to tokens created in `validate_session()` and enforce `options={"require": ["exp"]}` at decode time.

### 3.4 Low

#### FINDING-020: Cost Estimation Path Bypasses RLS, Disallowed Function/Table Checks, and DML Validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.2.4 |
| Affected File(s) | superset/commands/sql_lab/estimate.py |
| Source Report(s) | 1.2.4.md |
| Related Finding(s) | - |

**Description:**

The cost estimation path (`estimate.py`) does not apply RLS, disallowed function/table checks, or DML validation that are applied in the main execution path (`executor.py`). While EXPLAIN-based estimation doesn't typically expose actual data, row count estimates can confirm data existence behind RLS rules, and disallowed functions/DML statements could be estimated without permission checks.

**Remediation:**

Normalize security controls on estimate.py path: add RLS application, disallowed function/table checks, and DML validation to match the main execution path.

---

#### FINDING-021: Dynamic Function Dispatch via `getattr` with User-Controlled Operation Name in Post-Processing

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.3.2 |
| Affected File(s) | superset/common/query_object.py |
| Source Report(s) | 1.3.2.md |
| Related Finding(s) | - |

**Description:**

Post-processing uses `getattr(pandas_postprocessing, operation)` with a user-controlled operation name, relying on `hasattr` as an implicit allowlist. While the module namespace constrains available functions and no known function provides code execution, an explicit allowlist would be more robust against future module additions or unexpected kwargs causing DoS.

**Remediation:**

Replace `hasattr` check with an explicit `frozenset` allowlist of permitted operation names.

---

#### FINDING-022: User-provided filename not sanitized in Content-Disposition header

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.2.1 |
| Affected File(s) | superset/charts/data/api.py |
| Source Report(s) | 1.2.1.md |
| Related Finding(s) | - |

**Description:**

The user-provided filename is directly interpolated into the `Content-Disposition` header. Characters like `"` could break the header structure. While modern Werkzeug prevents CRLF injection, an unsanitized filename could cause browsers to save files with misleading names.

**Remediation:**

Apply `secure_filename()` to user-provided filenames in `_create_streaming_csv_response` regardless of source.

---

#### FINDING-023: native_filters parameter not URL-encoded in dashboard permalink redirect

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 1.2.2 |
| Affected File(s) | superset/views/core.py |
| Source Report(s) | 1.2.2.md |
| Related Finding(s) | - |

**Description:**

The `native_filters` parameter value is concatenated into the redirect URL without URL encoding, while other parameters are properly encoded via `parse.urlencode()`. An attacker-created permalink could inject additional URL parameters into the redirect destination, potentially modifying dashboard filter state displayed to the victim. Requires authenticated user to create malicious permalink and authenticated victim to access it.

**Remediation:**

Always URL-encode parameter values in dashboard_permalink, or validate that native_filters contains no URL-structure-breaking characters (`&`, `#`, `?`).

---

#### FINDING-024: Chart screenshot/thumbnail endpoints served without X-Content-Type-Options: nosniff or Content-Disposition header

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-116 |
| ASVS Section(s) | 3.2.1 |
| Affected File(s) | superset/charts/api.py |
| Source Report(s) | 3.2.1.md |
| Related Finding(s) | FINDING-010, FINDING-033 |

**Description:**

Chart screenshots served without Content-Disposition header or X-Content-Type-Options: nosniff. While the image/png MIME type prevents HTML execution in modern browsers, defense-in-depth would add X-Content-Type-Options: nosniff to prevent MIME sniffing. Requires authenticated user and separate cache poisoning vulnerability for exploitation.

**Remediation:**

Add X-Content-Type-Options: nosniff header via application middleware or per-endpoint response header.

---

#### FINDING-025: No Explicit Cipher Mode Validation or Enforcement

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-327 |
| ASVS Section(s) | 11.3.2 |
| Affected File(s) | superset/utils/encrypt.py |
| Source Report(s) | 11.3.2.md |
| Related Finding(s) | FINDING-004 |

**Description:**

The EncryptedFieldFactory accepts any adapter class from configuration without validating that it uses an approved cipher mode. There is no runtime assertion or startup check that verifies the configured encryption meets minimum security standards (e.g., AEAD mode). Misconfiguration could silently downgrade encryption to weaker modes without detection.

**Remediation:**

Add a startup validation that verifies the encryption adapter uses an approved AEAD mode, failing fast with a clear error message if not.

---

#### FINDING-026: UUID3 (MD5-based) Used for Cache Key Generation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-328 |
| ASVS Section(s) | 11.4.1 |
| Affected File(s) | superset/extensions/metastore_cache.py |
| Source Report(s) | 11.4.1.md |
| Related Finding(s) | - |

**Description:**

uuid3 internally uses MD5 to hash the namespace+name into a deterministic UUID. ASVS 11.4.1 states disallowed hash functions such as MD5 must not be used for any cryptographic purpose. The usage here is for deterministic key derivation (mapping cache key strings to UUIDs for database lookup), not for security-critical cryptographic operations. A collision would cause cache data corruption but has no direct confidentiality or authentication impact.

**Remediation:**

Replace uuid3 with uuid5 (SHA-1 based) for improved compliance, or use a custom approach with SHA-256 for full compliance with modern hash requirements.

---

#### FINDING-027: Extension Loading System Has No Mechanism to Reject Outdated or Vulnerable Extensions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-1104 |
| ASVS Section(s) | 15.2.1 |
| Affected File(s) | superset/extensions/discovery.py, superset/extensions/utils.py |
| Source Report(s) | 15.2.1.md |
| Related Finding(s) | FINDING-028, FINDING-046 |

**Description:**

The extension discovery and loading pipeline loads all valid .supx files and local extension directories without any check against a vulnerability database, version allowlist, or maximum age threshold. Once an extension has a valid manifest and passes ZIP safety checks, it is loaded and its arbitrary Python code is executed regardless of its version or known vulnerability status. Requires admin/filesystem access to exploit.

**Remediation:**

Add a version/vulnerability check gate in the extension loading pipeline, including an EXTENSION_BLOCKLIST configuration and maximum age checks.

---

#### FINDING-028: No Dependency Version Auditing for Extension-Declared Dependencies

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-1104 |
| ASVS Section(s) | 15.2.1 |
| Affected File(s) | superset/extensions/utils.py |
| Source Report(s) | 15.2.1.md |
| Related Finding(s) | FINDING-027, FINDING-046 |

**Description:**

The manifest's dependencies field is exposed through build_extension_data() but is never validated against known-vulnerable versions or checked for update compliance. Dependencies declared by extensions could reference outdated or vulnerable packages.

**Remediation:**

Implement dependency auditing during extension loading that checks manifest.dependencies against a vulnerability database (e.g., OSV, GitHub Advisory Database).

---

#### FINDING-029: Post-processing operation options schemas exist but are documented as not enforced

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.1.1 |
| Affected File(s) | superset/charts/schemas.py |
| Source Report(s) | 2.1.1.md |
| Related Finding(s) | FINDING-007, FINDING-030, FINDING-031 |

**Description:**

The codebase defines detailed per-operation option schemas (e.g., ChartDataAggregateOptionsSchema, ChartDataRollingOptionsSchema, ChartDataPivotOptionsSchema) with specific validators for each field, but these schemas are documented as not connected to the actual validation pipeline. The options field is accepted as Dict() without structure validation and passed to pandas postprocessing functions.

**Remediation:**

Update to Marshmallow 3+ or use a custom @validates_schema validator that dispatches to the appropriate options schema based on the operation value.

---

#### FINDING-030: `ChartPutSchema` missing JSON validation on `query_context` field

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Affected File(s) | superset/charts/schemas.py |
| Source Report(s) | 2.2.1.md |
| Related Finding(s) | FINDING-007, FINDING-029, FINDING-031 |

**Description:**

The ChartPutSchema accepts query_context as a plain String without validate=utils.validate_json, while ChartPostSchema correctly applies this validator. This allows storage of malformed JSON that causes errors when the chart is rendered.

**Remediation:**

Add validate=utils.validate_json to ChartPutSchema.query_context field to match ChartPostSchema behavior.

---

#### FINDING-031: `external_url` fields lack URL format validation across multiple schemas

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Affected File(s) | superset/charts/schemas.py, superset/dashboards/schemas.py, superset/databases/schemas.py, superset/datasets/schemas.py |
| Source Report(s) | 2.2.1.md |
| Related Finding(s) | FINDING-007, FINDING-029, FINDING-030 |

**Description:**

The `external_url` field appears in multiple Post and Put schemas without any URL format validation. While administrative in nature, storing arbitrary strings as URLs could lead to issues if rendered as hyperlinks without output encoding.

**Remediation:**

Add URL validation with validate=URL(schemes={'http', 'https'}, require_tld=True) to external_url fields.

---

#### FINDING-032: Embedded View Performs State-Changing login_user() on GET Without Anti-Forgery Token

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-352 |
| ASVS Section(s) | 3.5.1 |
| Affected File(s) | superset/embedded/view.py |
| Source Report(s) | 3.5.1.md |
| Related Finding(s) | - |

**Description:**

The embedded view performs login_user(AnonymousUserMixin(), force=True) on a GET request, protected only by referrer validation. The referrer-based origin check via same_origin() provides anti-forgery protection but is weaker than CSRF tokens. Practical impact is mitigated by SameSite cookie policies in modern browsers.

**Remediation:**

For defense-in-depth, consider adding Sec-Fetch-Dest header validation to confirm the request originates from an iframe navigation.

---

#### FINDING-033: JSON Helper Functions Missing Charset Parameter

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-116 |
| ASVS Section(s) | 4.1.1 |
| Affected File(s) | superset/views/base.py |
| Source Report(s) | 4.1.1.md |
| Related Finding(s) | FINDING-010, FINDING-024 |

**Description:**

Generic JSON response helper functions return `application/json` responses without the `charset=utf-8` parameter. While RFC 8259 mandates UTF-8 for JSON (making the parameter technically optional), ASVS 4.1.1 recommends charset on all text-based responses for defense-in-depth.

**Remediation:**

Update `json_success` and `BaseSupersetView.json_response` to include `charset=utf-8` in Content-Type, consistent with the pattern already used in `_send_chart_response`.

---

#### FINDING-034: Extension ZIP per-entry size limits unclear

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-400 |
| ASVS Section(s) | 5.2.1 |
| Affected File(s) | superset/extensions/utils.py |
| Source Report(s) | 5.2.1.md |
| Related Finding(s) | FINDING-011 |

**Description:**

In `superset/extensions/utils.py`, `get_bundle_files_from_zip` calls `check_is_safe_zip` but reads all file contents into memory without visible per-entry size limits. Only administrators with write access to EXTENSIONS_PATH can trigger this path.

**Remediation:**

Verify that check_is_safe_zip implementation checks total decompressed size and per-entry ratios.

---

#### FINDING-035: No filename extension validation on import endpoint

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-434 |
| ASVS Section(s) | 5.2.2 |
| Affected File(s) | superset/importexport/api.py |
| Source Report(s) | 5.2.2.md |
| Related Finding(s) | - |

**Description:**

The import endpoint at `superset/importexport/api.py` validates file content via `is_zipfile()` but does not check the uploaded filename extension. Content validation is the stronger control and is properly applied; this is a defense-in-depth gap.

**Remediation:**

Add extension validation alongside the existing content validation to verify uploaded files have .zip or .json extensions.

---

#### FINDING-036: Missing check_is_safe_zip in import API path

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS Section(s) | 5.3.2 |
| Affected File(s) | superset/importexport/api.py |
| Source Report(s) | 5.3.2.md |
| Related Finding(s) | FINDING-037 |

**Description:**

DOWNGRADED from Medium: The import endpoint does not visibly call `check_is_safe_zip` before extracting ZIP entries. However, no filesystem write operations use these paths — all content is processed in memory and stored in the database — and downstream processing uses prefix-based startswith() routing only. Practical impact is limited to potential confusion in file routing.

**Remediation:**

Ensure `get_contents_from_bundle` calls `check_is_safe_zip` before extracting entries, or add the check at the API level.

---

#### FINDING-037: Permissive BACKEND_REGEX in extension loading

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-22 |
| ASVS Section(s) | 5.3.2 |
| Affected File(s) | superset/extensions/utils.py |
| Source Report(s) | 5.3.2.md |
| Related Finding(s) | FINDING-036 |

**Description:**

The `BACKEND_REGEX` pattern uses `(.+)` which could match path traversal sequences. Mitigated by `check_is_safe_zip()` being called before extraction and the captured path only being used for in-memory module name generation. Requires administrator access to EXTENSIONS_PATH.

**Remediation:**

Tighten the regex to reject path traversal characters: `^backend/src/((?:[a-zA-Z0-9_]+/)*[a-zA-Z0-9_]+\.py)$`

---

#### FINDING-038: Async query JWT token issued without expiration claim

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS Section(s) | 7.4.1 |
| Affected File(s) | superset/async_events/async_query_manager.py |
| Source Report(s) | 7.4.1.md |
| Related Finding(s) | FINDING-018, FINDING-019, FINDING-045 |

**Description:**

The async query JWT in `superset/async_events/async_query_manager.py` (lines 152-162) is generated without an `exp` claim. On logout, the Flask session is cleared but the JWT cookie remains valid indefinitely. Exploitability is low due to httponly flag and separate Flask-Login authentication requirement on API endpoints.

**Remediation:**

Add an `exp` claim (e.g., 24 hours) to the async query JWT payload to ensure it cannot be used indefinitely after session termination.

---

#### FINDING-039: MCP Tools Without Permission Metadata Default to Allowed

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.2.1 |
| Affected File(s) | superset/mcp_service/auth.py |
| Source Report(s) | 8.2.1.md |
| Related Finding(s) | - |

**Description:**

In `superset/mcp_service/auth.py`, the `check_tool_permission` function defaults to allowing access when a tool function lacks the `CLASS_PERMISSION_ATTR`. Data flow: Tool registration (missing @tool decorator metadata) → `check_tool_permission` → `return True` → tool executes without RBAC check. Attacker capability required: Authenticated user (must pass MCP authentication via JWT, API key, or configured dev user). Impact on success: Access to MCP tools that were not explicitly RBAC-gated (limited to tools missing permission metadata). Exploitability: Requires that a tool is registered without proper permission metadata. If all tools are properly decorated, this is unexploitable. This is a defense-in-depth gap rather than an immediately exploitable vulnerability.

**Remediation:**

```python
class_permission_name = getattr(func, CLASS_PERMISSION_ATTR, None)
if not class_permission_name:
    # Fail closed: require explicit permission configuration
    logger.warning(
        "Tool %s has no permission metadata; denying access (fail-closed)",
        func.__name__,
    )
    return False
```

---

#### FINDING-040: MCP Admin Role Check Hardcoded Instead of Using Configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.2.1 |
| Affected File(s) | superset/mcp_service/utils/permissions_utils.py |
| Source Report(s) | 8.2.1.md |
| Related Finding(s) | - |

**Description:**

In `superset/mcp_service/utils/permissions_utils.py`, the `user_has_permission` function checks admin status using hardcoded role names rather than the configurable `AUTH_ROLE_ADMIN` setting. The function checks if role.name is in ("Admin", "admin") instead of using the configured admin role name. Attacker capability required: Requires non-standard deployment configuration where `AUTH_ROLE_ADMIN` is set to something other than "Admin". Impact on success: Admin users may not bypass field-level restrictions in MCP tools (denial of service to admins, not a privilege escalation).

**Remediation:**

```python
from superset import security_manager

if hasattr(user, "roles"):
    admin_role_name = current_app.config.get("AUTH_ROLE_ADMIN", "Admin")
    for role in user.roles:
        if role.name == admin_role_name:
            return True
```

---

#### FINDING-041: Utility Function `get_datasource_by_id` Returns Data Without Access Verification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 8.2.2 |
| Affected File(s) | superset/commands/utils.py |
| Source Report(s) | 8.2.2.md |
| Related Finding(s) | - |

**Description:**

The `get_datasource_by_id` function in `commands/utils.py` retrieves a datasource solely by ID without performing access checks. Authorization is expected to be enforced by the calling command. Data flow: User-controlled `datasource_id` → `DatasourceDAO.get_datasource()` → returns datasource object without access check → relies on caller to verify access. Attacker capability required: Authenticated user who calls a command that uses this function without proper access validation upstream. Impact on success: Could access datasource metadata (BOLA) if the calling command doesn't enforce access checks. Severity rationale: This is a Type B gap (control exists elsewhere but not called at this entry point). However, this is a utility function within the command layer — it's designed to be used by commands that independently enforce authorization. Without evidence that any command uses this without subsequent access checks, this is a defense-in-depth observation rated Low.

**Remediation:**

Consider adding an optional access check parameter:
```python
def get_datasource_by_id(
    datasource_id: int, datasource_type: str, check_access: bool = True
) -> BaseDatasource:
    try:
        datasource = DatasourceDAO.get_datasource(
            DatasourceType(datasource_type), datasource_id
        )
    except DatasourceNotFound as ex:
        raise DatasourceNotFoundValidationError() from ex
    if check_access:
        datasource.raise_for_access()
    return datasource
```

---

#### FINDING-042: Conditional Algorithm Check in MCP JWT Verifier May Allow Signature Bypass

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-347 |
| ASVS Section(s) | 9.1.1, 9.1.2 |
| Affected File(s) | superset/mcp_service/jwt_verifier.py |
| Source Report(s) | 9.1.1.md, 9.1.2.md |
| Related Finding(s) | - |

**Description:**

The conditional guard `if self.algorithm` in the MCP JWT verifier skips both signature validation (9.1.1) and algorithm allowlist enforcement (9.1.2) when self.algorithm is falsy. While production JWT configuration in profile documents includes algorithm (RS256/HS256), making exploitation require deployer misconfiguration, the code should defensively reject tokens when no algorithm is configured rather than silently passing validation. This affects both signature integrity verification and algorithm allowlist enforcement.

**Remediation:**

Remove the `if self.algorithm` guard and either require algorithm configuration at initialization or reject tokens when no expected algorithm is configured. Define an explicit allowlist constant and always enforce it.

---

#### FINDING-043: No Explicit 'None' Algorithm Rejection in MCP Verifier

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-757 |
| ASVS Section(s) | 9.1.2 |
| Affected File(s) | superset/mcp_service/jwt_verifier.py |
| Source Report(s) | 9.1.2.md |
| Related Finding(s) | - |

**Description:**

The MCP JWT verifier does not explicitly reject tokens with `alg: "none"`. While authlib typically rejects "none" when a verification key is provided, ASVS 9.1.2 requires explicit exclusion of the 'None' algorithm from any allowlist.

**Remediation:**

Add an explicit check before the algorithm comparison to reject tokens with `alg: "none"` regardless of configuration state.

---

#### FINDING-044: MCP Verifier Key Source Depends on Uninspectable Base Class

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-295 |
| ASVS Section(s) | 9.1.3 |
| Affected File(s) | superset/mcp_service/jwt_verifier.py |
| Source Report(s) | 9.1.3.md |
| Related Finding(s) | - |

**Description:**

The MCP JWT verifier passes the full token to `_get_verification_key(token)` without stripping potentially dangerous headers (jku, x5u, jwk). While the base class likely uses pre-configured JWKS sources, there is no explicit validation preventing token headers from influencing key resolution.

**Remediation:**

Add explicit validation to reject or strip untrusted key source headers (jku, x5u, jwk) from the token before calling _get_verification_key().

---

#### FINDING-045: MCP JWT Verifier Accepts Tokens Without Expiration Claim

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-613 |
| ASVS Section(s) | 9.2.1 |
| Affected File(s) | superset/mcp_service/jwt_verifier.py |
| Source Report(s) | 9.2.1.md |
| Related Finding(s) | FINDING-018, FINDING-019, FINDING-038 |

**Description:**

The MCP JWT verifier's Step 4 uses `if exp and exp < time.time()` which only checks expiration IF the claim is present. Tokens without an `exp` claim are accepted without any time-based restriction. The profile documents exp as an expected claim, but code does not enforce its presence.

**Remediation:**

Change the expiration check to require the `exp` claim: reject tokens where `claims.get("exp")` is None.

### 3.5 Informational

#### FINDING-046: No Reference to Documented Remediation Timeframes in Extension Loading System

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1104 |
| **ASVS Section(s)** | 15.1.1 |
| **Files** | superset/extensions/utils.py, superset/extensions/discovery.py |
| **Source Reports** | 15.1.1.md |
| **Related** | FINDING-027, FINDING-028 |

**Description:**

The extension loading system processes third-party .supx extension bundles containing arbitrary Python code, but contains no reference to, enforcement of, or link to documented vulnerability remediation timeframes. ASVS 15.1.1 is a documentation requirement asking whether the project defines risk-based remediation timeframes for third-party components. No such documented timeframes were found in the provided code or project documentation.

**Remediation:**

Document risk-based remediation timeframes in the project's security policy (e.g., SECURITY.md) covering Critical (48h), High (7d), Medium (30d), Low (90d) vulnerabilities and general dependency updates (quarterly).

---

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Oauth2 Authorization Security | OAuth2 state parameter uses signed JWT with 5-minute expiry (CSRF protection) | Audit positive pattern | — |
| Oauth2 Authorization Security | PKCE (RFC 7636) with S256 method used for all OAuth2 authorization code flows | Audit positive pattern | — |
| Oauth2 Authorization Security | PKCE code_verifier deleted from KV store after single use, preventing replay | Audit positive pattern | — |
| Oauth2 Authorization Security | OAuth2 state JWT expiration set to 5 minutes, limiting authorization flow window | Audit positive pattern | — |
| Oauth2 Authorization Security | Superset exclusively uses Authorization Code flow with PKCE; no Implicit or ROPC flows | Audit positive pattern | — |
| Oauth2 Authorization Security | Client-side refresh token rotation support with distributed locking to prevent race conditions | Audit positive pattern | — |
| Oauth2 Authorization Security | Failed refresh attempts trigger token deletion, forcing re-authentication | Audit positive pattern | — |
| Tls Transport Security | TLS termination and protocol version enforcement delegated to deployment infrastructure (load balancer/reverse proxy) | Application delegates TLS configuration to infrastructure layer; source: Dropped finding ASVS-1211-LOW-001 | — |
| Tls Transport Security | HTTPS enforcement and secure cookie flags are deployer-configured via superset_config.py overrides, consistent with TLS delegation to infrastructure | Configuration allows deployers to enforce HTTPS and secure cookie settings; source: Dropped finding ASVS-1221-MED-001 | — |
| Tls Transport Security | Redis SSL cert validation set to 'required' when SSL is enabled; all TLS settings overridable by deployer via superset_config.py | Redis connections enforce certificate validation when SSL is enabled; source: Dropped finding ASVS-1222-LOW-001 | — |
| Tls Transport Security | WebSocket transport is opt-in (default is 'polling'), and TLS for WebSocket connections is delegated to deployment infrastructure alongside all other TLS termination | WebSocket security delegated to infrastructure layer, not enabled by default; source: Dropped finding ASVS-441-MED-001 | — |
| Source Control Metadata Exposure | Flask route-based architecture inherently prevents serving source control metadata from project root; unmatched paths return 404 | Dropped finding ASVS-1341-LOW-001 | — |
| Source Control Metadata Exposure | Werkzeug path traversal protection and static folder isolation prevent access to files outside configured static directory | Dropped finding ASVS-1341-LOW-002 | — |
| Sensitive Data In Transit | No sensitive data transmitted in URL or query string parameters | ASVS 14.2.1 audit passed - sensitive data properly confined to HTTP message body and header fields | — |
| Sensitive Data In Transit | Server-side state storage architecture reduces client-side data persistence requirements; sensitive state stored in backend key-value store with opaque key references | ASVS 14.3.1 audit - identified during review | — |
| Api Data Minimization | Write endpoints (post() and put()) correctly use mask_password_info() function to redact sensitive fields | Database API write endpoints apply credential masking | superset/databases/api.py |
| Api Data Minimization | Standard list endpoints use list_columns configuration for field-level access control | Schema-based serialization approach exists with list_model_schema.dump() | superset/queries/api.py |
| Input Validation | Server-side validation enforced through Marshmallow schemas in REST API layer | All REST API endpoints use Marshmallow schemas for input validation at the service layer, independent of client-side checks | superset/charts/schemas.py, superset/dashboards/schemas.py, superset/databases/schemas.py, superset/datasets/schemas.py |
| Business Logic Flow Control | WORKING state guard correctly implemented in ReportNotTriggeredErrorState.next() for all report types | ReportNotTriggeredErrorState.next() sets WORKING state before processing | superset/commands/report/execute.py |
| Business Logic Flow Control | WORKING state guard correctly implemented for ALERT types in ReportSuccessState.next() | ReportSuccessState.next() sets WORKING state for ALERT types before processing | superset/commands/report/execute.py |
| Business Logic Flow Control | Finally block pattern correctly implemented in ReportNotTriggeredErrorState.next() for error recovery | ReportNotTriggeredErrorState.next() uses finally block to ensure state transition to ERROR | superset/commands/report/execute.py |
| Browser Security Controls | Cookie security settings (SESSION_COOKIE_SECURE, etc.) are configurable via superset_config.py override mechanism, delegated to deployment operator | Configuration allows operators to set secure cookie attributes per deployment requirements | — |
| Browser Security Controls | HTTPS enforcement and HSTS delegated to deployment infrastructure; Flask-Talisman available for operators who want application-level enforcement | Transport security handled at infrastructure layer with optional application-level support via Flask-Talisman | — |
| Browser Security Controls | CORS Access-Control-Allow-Origin header properly validated against trusted origins | ASVS section 3.4.2 marked as Pass | — |
| File Upload Security | Content validation via is_zipfile() | Import endpoint properly validates file content | superset/importexport/api.py |
| File Upload Security | check_is_safe_zip() called before extraction in extension loading | Protects against path traversal in extension ZIP files | superset/extensions/utils.py |
| File Upload Security | No filesystem write operations using untrusted paths | All content processed in memory and stored in database | superset/importexport/api.py |
| File Upload Security | Prefix-based startswith() routing for downstream processing | Limits impact of malformed paths in import processing | superset/importexport/api.py |
| File Upload Security | Administrator access required for EXTENSIONS_PATH | Limits exposure of extension loading vulnerabilities to privileged users | superset/extensions/utils.py |
| Authentication Controls | MCP RateLimitMiddleware with documented configuration (default/user/expensive tiers) | Documented rate limiting implementation present in security documentation | — |
| Authentication Controls | Audit logging of authentication events documented in SECURITY.md | Authentication event logging documented for monitoring and incident response | — |
| Password Management | Password change functionality is available to users | ASVS 6.2.2 marked as Pass | — |
| Password Management | Password change requires current and new password | ASVS 6.2.3 marked as Pass | — |
| Password Management | No restrictive character composition rules enforced on passwords | ASVS 6.2.5 marked as Pass | — |
| Password Management | Password input fields use type=password for masking | ASVS 6.2.6 marked as Pass | — |
| Password Management | Paste functionality and password managers are permitted | ASVS 6.2.7 marked as Pass | — |
| Password Management | Passwords are verified exactly as received without truncation or transformation | ASVS 6.2.8 marked as Pass | — |
| Default Credentials | No auto-created default user accounts; user provisioning delegated to deployment operator | Dropped finding ASVS-632-LOW-001 | — |
| Authorization Enforcement | Authorization documentation exists and defines function-level and data-specific access rules | 8.1.1 marked as Pass | — |
| Authorization Enforcement | Authorization rules enforced at trusted service layer | 8.3.1 marked as Pass | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Partial** | See FINDING-022 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-023 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** | |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Partial** | See FINDING-020 |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Partial** | See FINDING-003 |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** | |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Partial** | See FINDING-021 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** | |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-029 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-006, FINDING-007, FINDING-030, FINDING-031 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** | |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Fail** | See FINDING-008, FINDING-009 |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Partial** | See FINDING-024 |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** | |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** | |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** | |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** | |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Partial** | See FINDING-032 |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Pass** | |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** | |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Partial** | See FINDING-010, FINDING-033 |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** | |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Fail** | See FINDING-011, FINDING-034 |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Partial** | See FINDING-035 |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** | |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Partial** | See FINDING-036, FINDING-037 |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** | |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **Partial** | See FINDING-014 |
| 6.2.2 | Verify that users can change their password. | **Pass** | |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **Pass** | |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **Partial** | See FINDING-015 |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** | |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **Pass** | |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** | |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** | |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Partial** | See FINDING-012, FINDING-013 |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** | |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Partial** | See FINDING-016 |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** | |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** | |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** | |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** | |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Fail** | See FINDING-017 |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Partial** | See FINDING-038 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Fail** | See FINDING-018 |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** | |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Partial** | See FINDING-039, FINDING-040 |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Partial** | See FINDING-041 |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** | |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Partial** | See FINDING-042 |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Partial** | See FINDING-042, FINDING-043 |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Partial** | See FINDING-044 |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Fail** | See FINDING-019, FINDING-045 |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** | |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** | |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** | |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** | |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** | |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Fail** | See FINDING-004 |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Fail** | See FINDING-004, FINDING-025 |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Partial** | See FINDING-026 |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** | |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** | |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** | |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** | |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** | |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** | |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Fail** | See FINDING-046 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Fail** | See FINDING-027, FINDING-028 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Fail** | See FINDING-005 |

**Summary Statistics:**
- **Pass**: 24 requirements (34.3%)
- **Partial**: 23 requirements (32.9%)
- **N/A**: 13 requirements (18.6%)
- **Fail**: 10 requirements (14.3%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-003 | Medium | 1.2.5 | — | superset/databases/ssh_tunnel/models.py, superset/commands/database/test_connection.py |
| FINDING-004 | Medium | 11.3.1, 11.3.2 | FINDING-025 | superset/utils/encrypt.py, superset/models/core.py, superset/databases/ssh_tunnel/models.py |
| FINDING-005 | Medium | 15.3.1 | | superset/security/api.py |
| FINDING-006 | Medium | 2.2.1 | — | superset/charts/schemas.py |
| FINDING-007 | Medium | 2.2.1 | FINDING-029, FINDING-030, FINDING-031 | superset/views/database/validators.py |
| FINDING-008 | Medium | 2.3.1 | — | superset/commands/report/execute.py |
| FINDING-009 | Medium | 2.3.1 | — | superset/commands/report/execute.py |
| FINDING-010 | Medium | 4.1.1 | FINDING-024, FINDING-033 | superset/charts/data/api.py |
| FINDING-011 | Medium | 5.2.1 | FINDING-034 | superset/importexport/api.py |
| FINDING-012 | Medium | 6.3.1 | — | superset/security/manager.py |
| FINDING-013 | Medium | 6.3.1 | — | superset/security/manager.py |
| FINDING-014 | Medium | 6.2.1 | FINDING-015 | superset/security/manager.py |
| FINDING-015 | Medium | 6.2.4 | FINDING-014 | superset/security/manager.py |
| FINDING-016 | Medium | 6.4.1 | — | superset/security/manager.py |
| FINDING-017 | Medium | 7.2.4 | — | superset/security/manager.py |
| FINDING-018 | Medium | 7.4.2 | FINDING-019, FINDING-038, FINDING-045 | superset/security/manager.py |
| FINDING-019 | Medium | 9.2.1 | FINDING-018, FINDING-038, FINDING-045 | superset/async_events/async_query_manager.py |
| FINDING-020 | Low | 1.2.4 | — | superset/commands/sql_lab/estimate.py |
| FINDING-021 | Low | 1.3.2 | — | superset/common/query_object.py |
| FINDING-022 | Low | 1.2.1 | — | superset/charts/data/api.py |
| FINDING-023 | Low | 1.2.2 | — | superset/views/core.py |
| FINDING-024 | Low | 3.2.1 | FINDING-010, FINDING-033 | superset/charts/api.py |
| FINDING-025 | Low | 11.3.2 | FINDING-004 | superset/utils/encrypt.py |
| FINDING-026 | Low | 11.4.1 | — | superset/extensions/metastore_cache.py |
| FINDING-027 | Low | 15.2.1 | FINDING-028, FINDING-046 | superset/extensions/discovery.py, superset/extensions/utils.py |
| FINDING-028 | Low | 15.2.1 | FINDING-027, FINDING-046 | superset/extensions/utils.py |
| FINDING-029 | Low | 2.1.1 | FINDING-007, FINDING-030, FINDING-031 | superset/charts/schemas.py |
| FINDING-030 | Low | 2.2.1 | FINDING-007, FINDING-029, FINDING-031 | superset/charts/schemas.py |
| FINDING-031 | Low | 2.2.1 | FINDING-007, FINDING-029, FINDING-030 | superset/charts/schemas.py, superset/dashboards/schemas.py, superset/databases/schemas.py, superset/datasets/schemas.py |
| FINDING-032 | Low | 3.5.1 | — | superset/embedded/view.py |
| FINDING-033 | Low | 4.1.1 | FINDING-010, FINDING-024 | superset/views/base.py |
| FINDING-034 | Low | 5.2.1 | FINDING-011 | superset/extensions/utils.py |
| FINDING-035 | Low | 5.2.2 | — | superset/importexport/api.py |
| FINDING-036 | Low | 5.3.2 | FINDING-037 | superset/importexport/api.py |
| FINDING-037 | Low | 5.3.2 | FINDING-036 | superset/extensions/utils.py |
| FINDING-038 | Low | 7.4.1 | FINDING-018, FINDING-019, FINDING-045 | superset/async_events/async_query_manager.py |
| FINDING-039 | Low | 8.2.1 | — | superset/mcp_service/auth.py |
| FINDING-040 | Low | 8.2.1 | — | superset/mcp_service/utils/permissions_utils.py |
| FINDING-041 | Low | 8.2.2 | — | superset/commands/utils.py |
| FINDING-042 | Low | 9.1.1, 9.1.2 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-043 | Low | 9.1.2 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-044 | Low | 9.1.3 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-045 | Low | 9.2.1 | FINDING-018, FINDING-019, FINDING-038 | superset/mcp_service/jwt_verifier.py |
| FINDING-046 | Informational | 15.1.1 | FINDING-027, FINDING-028 | superset/extensions/utils.py, superset/extensions/discovery.py |

**Total Unique Findings**: 46 (2 Critical, 0 High, 17 Medium, 26 Low, 1 Info)

*45 of 46 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 45 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 46 |

**Total consolidated findings: 46**

*End of Consolidated Security Audit Report*