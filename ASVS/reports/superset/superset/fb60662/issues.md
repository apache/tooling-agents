# Security Issues

*45 actionable finding(s). 1 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-003 - SSH Tunnel `server_address` Lacks Hostname Format Validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `server_address` field in the SSH tunnel model accepts arbitrary text without hostname or IP address format validation, enabling SSRF attacks to arbitrary internal hosts.

### Details
While the current implementation uses the paramiko-based `sshtunnel` library (which does not spawn shell commands), this represents a defense-in-depth gap against future implementation changes. Violates ASVS 1.2.5 (L1) and CWE-918 (SSRF).

**Affected Files:**
- `superset/databases/ssh_tunnel/models.py`
- `superset/commands/database/test_connection.py`

### Remediation
Add hostname/IP format validation and optional allowlist/denylist for SSH tunnel `server_address` to prevent SSRF and establish defense-in-depth against future implementation changes.

### Acceptance Criteria
- [ ] Hostname/IP format validation added to `server_address` field
- [ ] Optional allowlist/denylist configuration implemented
- [ ] Test added for valid hostname formats
- [ ] Test added rejecting invalid hostnames
- [ ] Test added for SSRF prevention

### References
- ASVS 1.2.5
- CWE-918

### Priority
Medium

---
## Issue: FINDING-004 - AES-CBC Mode Used Without Authenticated Encryption
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `sqlalchemy_utils.EncryptedType` with default `AesEngine` implements AES-256-CBC, which does not provide authenticated encryption (AEAD). All database credentials, SSH private keys, OAuth2 tokens, and server certificates are encrypted with this non-authenticated mode.

### Details
ASVS 11.3.1 prohibits insecure block modes and requires authenticated encryption. ASVS 11.3.2 requires only approved ciphers and modes such as AES with GCM. Exploitability is low in default deployment—no interactive decryption oracle is exposed to external attackers; exploitation requires direct database access. The lack of authenticated encryption is primarily a defense-in-depth concern. Violates CWE-327.

**Affected Files:**
- `superset/utils/encrypt.py`
- `superset/models/core.py`
- `superset/databases/ssh_tunnel/models.py`

**Related Findings:** FINDING-025

### Remediation
Configure the encryption adapter to explicitly use `AesGcmEngine` which provides authenticated encryption. Modify `SQLAlchemyUtilsAdapter.create()` to specify `engine=AesGcmEngine` as the default. Migration to AES-GCM requires re-encrypting all existing data using the `SecretsMigrator` pattern already present in the codebase.

### Acceptance Criteria
- [ ] `AesGcmEngine` configured as default encryption engine
- [ ] Migration script created for re-encrypting existing data
- [ ] Test added verifying authenticated encryption is used
- [ ] Documentation updated with migration instructions

### References
- ASVS 11.3.1, 11.3.2
- CWE-327

### Priority
Medium

---
## Issue: FINDING-005 - Registration Hash Token Exposed in User Registrations API
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `UserRegistrationsRestAPI` class includes `registration_hash` in its `list_columns` configuration, exposing the email verification token that can be used to bypass email verification.

### Details
This token is used for email verification during user registration and should not be exposed in API list responses. While this endpoint likely requires administrator permissions, the token serves no legitimate purpose in list responses and violates the principle of least privilege. Violates ASVS 15.3.1 (L1) and CWE-200.

**Affected Files:**
- `superset/security/api.py`

**Related Findings:** FINDING-001, FINDING-002

### Remediation
Remove `registration_hash` from the `list_columns` configuration in `UserRegistrationsRestAPI`.

### Acceptance Criteria
- [ ] `registration_hash` removed from `list_columns`
- [ ] Test added verifying token is not in list response
- [ ] Test added verifying token is still available for verification flow

### References
- ASVS 15.3.1
- CWE-200

### Priority
Medium

---
## Issue: FINDING-006 - Missing upper bound validation on `row_limit` enabling potential resource exhaustion
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `row_limit` field in `ChartDataQueryObjectSchema` validates only for `min=0` with no upper bound. An authenticated user could set `row_limit` to an extremely large value causing denial of service.

### Details
An authenticated user could set `row_limit` to an extremely large value (e.g., 2^31-1), causing the database to attempt returning billions of rows and the application to buffer them in memory, leading to denial of service. Violates ASVS 2.2.1 (L1) and CWE-770 (Allocation of Resources Without Limits).

**Affected Files:**
- `superset/charts/schemas.py`

### Remediation
Add an upper bound validation that references the application configuration, e.g., `Range(min=0, max=100000)` or reference `config['SQL_MAX_ROW']`.

### Acceptance Criteria
- [ ] Upper bound validation added to `row_limit` field
- [ ] Configuration option added for maximum row limit
- [ ] Test added verifying limit enforcement
- [ ] Test added rejecting excessive values

### References
- ASVS 2.2.1
- CWE-770

### Priority
Medium

---
## Issue: FINDING-007 - Legacy database URI validator missing unsafe connection check
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The legacy `views/database/validators.py` `sqlalchemy_uri_validator` does not call `check_sqlalchemy_uri()` which is present in the REST API validator, potentially allowing bypass of the `PREVENT_UNSAFE_DB_CONNECTIONS` safeguard.

### Details
This could allow filesystem access through SQLite URIs if the legacy view is still accessible. Requires Admin user with database creation permissions through legacy UI. Violates ASVS 2.2.1 (L1) and CWE-20.

**Affected Files:**
- `superset/views/database/validators.py`

**Related Findings:** FINDING-029, FINDING-030, FINDING-031

### Remediation
Add `check_sqlalchemy_uri()` call to `views/database/validators.py` or deprecate the legacy validator if the view is no longer in use.

### Acceptance Criteria
- [ ] `check_sqlalchemy_uri()` added to legacy validator OR
- [ ] Legacy validator deprecated with migration path documented
- [ ] Test added verifying unsafe URIs are rejected
- [ ] Test added for SQLite URI blocking

### References
- ASVS 2.2.1
- CWE-20

### Priority
Medium

---
## Issue: FINDING-008 - WORKING State Guard Skipped for REPORT Type in SUCCESS State
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The report execution state machine implements a WORKING state guard to prevent concurrent execution, but for REPORT types in SUCCESS state, the WORKING state is never set before `self.send()` is called, creating a window for concurrent execution.

### Details
This guard is correctly applied in `ReportNotTriggeredErrorState.next()` for all report types, and in `ReportSuccessState.next()` for ALERT types. However, for REPORT types in SUCCESS state, concurrent execution can occur, leading to duplicate notifications and resource waste. Violates ASVS 2.3.1 (L1) and CWE-362 (Race Condition).

**Affected Files:**
- `superset/commands/report/execute.py`

### Remediation
Add `self.update_report_schedule_and_log(ReportState.WORKING)` for the REPORT type path in `ReportSuccessState.next()` before calling `self.send()`, matching the pattern in `ReportNotTriggeredErrorState.next()`.

### Acceptance Criteria
- [ ] WORKING state set before `self.send()` for REPORT type
- [ ] Test added verifying concurrent execution prevention
- [ ] Test added verifying no duplicate notifications

### References
- ASVS 2.3.1
- CWE-362

### Priority
Medium

---
## Issue: FINDING-009 - Error State Recovery in ReportSuccessState Lacks Finally Block for State Transition
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When an exception occurs during alert processing in `ReportSuccessState.next()`, if `send_error()` itself raises an exception, the state update to ERROR is never reached, leaving the report in WORKING state indefinitely.

### Details
The report remains in WORKING state until the `working_timeout` expires. This pattern is correctly handled with a finally block in `ReportNotTriggeredErrorState.next()`. Violates ASVS 2.3.1 (L1) and CWE-755 (Improper Handling of Exceptional Conditions).

**Affected Files:**
- `superset/commands/report/execute.py`

### Remediation
Wrap `send_error()` in a try/except and use a finally block to ensure `update_report_schedule_and_log(ReportState.ERROR)` is always called, matching the pattern in `ReportNotTriggeredErrorState.next()`.

### Acceptance Criteria
- [ ] Finally block added to ensure ERROR state transition
- [ ] Test added verifying state transition on `send_error()` failure
- [ ] Test added verifying no stuck WORKING states

### References
- ASVS 2.3.1
- CWE-755

### Priority
Medium

---
## Issue: FINDING-010 - Streaming CSV Response Uses Non-Standard Charset Specification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The streaming CSV export functionality embeds the charset parameter directly in the `mimetype` argument to Flask's `Response` constructor, which is non-standard API usage that can result in malformed Content-Type headers.

### Details
In Werkzeug 2.x this results in doubled charset parameters; behavior is version-dependent. Violates ASVS 4.1.1 (L1) and CWE-116 (Improper Encoding or Escaping of Output).

**Affected Files:**
- `superset/charts/data/api.py`

**Related Findings:** FINDING-024, FINDING-033

### Remediation
Change `mimetype=f"text/csv; charset={encoding}"` to `content_type=f"text/csv; charset={encoding}"` in `_create_streaming_csv_response`, or create a `StreamingCsvResponse` class following the `CsvResponse` pattern.

### Acceptance Criteria
- [ ] Charset specification corrected to use `content_type` parameter
- [ ] Test added verifying correct Content-Type header
- [ ] Test added across multiple Werkzeug versions

### References
- ASVS 4.1.1
- CWE-116

### Priority
Medium

---
## Issue: FINDING-011 - No file size limit on import endpoint ZIP processing
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The import endpoint at `superset/importexport/api.py` processes uploaded ZIP files without enforcing size limits before decompression. An authenticated user with import permissions could upload a decompression bomb or very large ZIP that exhausts memory.

### Details
Violates ASVS 5.2.1 (L1) and CWE-400 (Uncontrolled Resource Consumption).

**Affected Files:**
- `superset/importexport/api.py`

**Related Findings:** FINDING-034

### Remediation
Add explicit file size validation before processing the upload, and individual entry size limits when extracting ZIP contents. Configure `MAX_CONTENT_LENGTH` and add application-level validation.

### Acceptance Criteria
- [ ] File size validation added before ZIP processing
- [ ] Individual entry size limits implemented
- [ ] `MAX_CONTENT_LENGTH` configured
- [ ] Test added for decompression bomb detection
- [ ] Test added rejecting oversized uploads

### References
- ASVS 5.2.1
- CWE-400

### Priority
Medium

---
## Issue: FINDING-012 - Authentication Rate Limiting Is Not Active by Default
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The authentication rate limiting is gated by `self.is_auth_limited`, which reads `AUTH_RATE_LIMITED` from Flask-AppBuilder's configuration. In Flask-AppBuilder, `AUTH_RATE_LIMITED` defaults to `False`, meaning that in a default Superset deployment, the login endpoint has no rate limiting.

### Details
This allows attackers to perform credential stuffing and password brute force attacks without restriction. Violates ASVS 6.3.1 (L1) and CWE-307 (Improper Restriction of Excessive Authentication Attempts).

**Affected Files:**
- `superset/security/manager.py`

### Remediation
Enable rate limiting by default in Superset's default configuration: `AUTH_RATE_LIMITED = True`, `AUTH_RATE_LIMIT = "5 per 40 second"`. Additionally, consider applying rate limiting unconditionally in `register_views()`.

### Acceptance Criteria
- [ ] `AUTH_RATE_LIMITED = True` set in default configuration
- [ ] `AUTH_RATE_LIMIT` configured with appropriate threshold
- [ ] Test added verifying rate limiting is active
- [ ] Test added verifying brute force protection

### References
- ASVS 6.3.1
- CWE-307

### Priority
Medium

---
## Issue: FINDING-013 - No Protection Against Malicious Account Lockout via Deliberate Failed Logins
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Flask-AppBuilder's `SecurityManager` provides `AUTH_MAX_LOGIN_ATTEMPTS` which locks accounts after N failed attempts, but there is no mechanism to prevent an attacker from deliberately locking legitimate user accounts by sending failed login attempts with known usernames.

### Details
Without protections such as temporary lockout with automatic unlock, CAPTCHA challenges, or IP-based rate limiting before account lockout triggers, an attacker who knows valid usernames can perform a denial-of-service attack by locking all accounts. Violates ASVS 6.3.1 (L1) and CWE-645 (Overly Restrictive Account Lockout Mechanism).

**Affected Files:**
- `superset/security/manager.py`

### Remediation
Implement rate limiting that takes precedence over account lockout, so that excessive failed attempts from a single IP are blocked before triggering lockout. Additionally, implement automatic account unlock after a configurable cooldown (e.g., `AUTH_LOCKOUT_DURATION_SECONDS = 900`).

### Acceptance Criteria
- [ ] IP-based rate limiting implemented before account lockout
- [ ] Automatic account unlock mechanism added
- [ ] Configuration option added for lockout duration
- [ ] Test added verifying malicious lockout prevention
- [ ] Test added verifying automatic unlock

### References
- ASVS 6.3.1
- CWE-645

### Priority
Medium

---
## Issue: FINDING-014 - No password minimum length enforcement in SupersetSecurityManager
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `SupersetSecurityManager` extends Flask-AppBuilder's `SecurityManager` but does not implement or override any password length validation. When DB authentication with self-registration is enabled, a user could register with a trivially short password.

### Details
There is no `validate_password()` method, no minimum length configuration enforcement, and no password policy checking visible in the security manager layer that Superset controls. Violates ASVS 6.2.1 (L1) and CWE-521 (Weak Password Requirements).

**Affected Files:**
- `superset/security/manager.py`

**Related Findings:** FINDING-015

### Remediation
Implement `validate_password()` override in `SupersetSecurityManager` enforcing a minimum 8-character length. Set `AUTH_MIN_PASSWORD_LENGTH = 8` in the default Superset configuration.

### Acceptance Criteria
- [ ] `validate_password()` method implemented
- [ ] Minimum 8-character length enforced
- [ ] `AUTH_MIN_PASSWORD_LENGTH` configuration added
- [ ] Test added verifying short passwords are rejected
- [ ] Test added for registration and password change flows

### References
- ASVS 6.2.1
- CWE-521

### Priority
Medium

---
## Issue: FINDING-015 - No common password blocklist check during registration or password change
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `SupersetSecurityManager` does not implement any common password checking. Users can set well-known passwords like "password123" that are trivially guessable via credential stuffing attacks.

### Details
There is no blocklist, no integration with a common password dictionary, and no `validate_password()` override that would reject commonly used passwords during registration or password change. Violates ASVS 6.2.4 (L1) and CWE-521 (Weak Password Requirements).

**Affected Files:**
- `superset/security/manager.py`

**Related Findings:** FINDING-014

### Remediation
Integrate a common password blocklist (at least top 3000 passwords) into a `validate_password()` override in `SupersetSecurityManager`. Consider integration with Have I Been Pwned API (k-anonymity model) for compromised password detection.

### Acceptance Criteria
- [ ] Common password blocklist integrated (minimum 3000 passwords)
- [ ] `validate_password()` checks against blocklist
- [ ] Test added verifying common passwords are rejected
- [ ] Optional: HIBP API integration implemented

### References
- ASVS 6.2.4
- CWE-521

### Priority
Medium

---
## Issue: FINDING-016 - No mechanism to expire initial passwords or force change on first use
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `SupersetSecurityManager` and `SupersetUserApi` extend Flask-AppBuilder's base security implementations but do not implement secure random password generation for admin-created accounts, do not mark initial passwords for expiration, and do not enforce password change on first login.

### Details
Admin creates user via API/UI → FAB UserApi sets password → No expiration or force-change-on-first-login logic applied. Violates ASVS 6.4.1 (L1) and CWE-262 (Not Using Password Aging).

**Affected Files:**
- `superset/security/manager.py`

### Remediation
Add initial password lifecycle management: implement a `password_must_change` flag on user accounts created by administrators, with login middleware that forces password change before allowing other operations. Generate secure random initial passwords and set configurable expiration (e.g., 24 hours).

### Acceptance Criteria
- [ ] `password_must_change` flag added to user model
- [ ] Login middleware enforces password change
- [ ] Secure random initial password generation implemented
- [ ] Configurable expiration for initial passwords
- [ ] Test added verifying forced password change
- [ ] Test added verifying password expiration

### References
- ASVS 6.4.1
- CWE-262

### Priority
Medium

---
## Issue: FINDING-017 - No explicit session regeneration on user authentication in security manager
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `on_user_login()` method in `superset/security/manager.py` performs only audit logging without triggering session regeneration. If Flask-Login's `login_user()` or the auth view does not call `session.regenerate()` or `session.clear()` before login, the old session token remains valid, enabling potential session fixation attacks.

### Details
Violates ASVS 7.2.4 (L1) and CWE-384 (Session Fixation).

**Affected Files:**
- `superset/security/manager.py`

### Remediation
Add `session.clear()` or equivalent session regeneration call in `on_user_login()` before populating the new session, or verify that the upstream `SupersetAuthView` handles this.

### Acceptance Criteria
- [ ] Session regeneration added to `on_user_login()`
- [ ] Verification that upstream auth view handles regeneration OR
- [ ] Explicit regeneration implemented
- [ ] Test added verifying session token changes on login
- [ ] Test added for session fixation prevention

### References
- ASVS 7.2.4
- CWE-384

### Priority
Medium

---
## Issue: FINDING-018 - No active session termination when user account is disabled or deleted
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `post_update` and `post_delete` handlers in `superset/security/manager.py` (`SupersetUserApi` class) perform only audit logging without terminating the disabled/deleted user's active sessions. The user retains access until Flask-Login's passive `is_active` check triggers on their next request.

### Details
This creates a window for continued access after account disablement or deletion. Violates ASVS 7.4.2 (L1) and CWE-613 (Insufficient Session Expiration).

**Affected Files:**
- `superset/security/manager.py`

**Related Findings:** FINDING-019, FINDING-038, FINDING-045

### Remediation
Implement a `_terminate_user_sessions()` method that clears all server-side session data for a user when their account is disabled or deleted, and call it from `post_update` (when `active` becomes False) and `post_delete`.

### Acceptance Criteria
- [ ] `_terminate_user_sessions()` method implemented
- [ ] Method called from `post_update` when account disabled
- [ ] Method called from `post_delete`
- [ ] Test added verifying immediate session termination
- [ ] Test added verifying disabled user cannot access system

### References
- ASVS 7.4.2
- CWE-613

### Priority
Medium

---
## Issue: FINDING-019 - Async Query JWT Tokens Have No Expiration Claim
**Labels:** bug, security, priority:medium
**Description:**
### Summary
JWT tokens created by the async query manager contain only `channel` and `sub` claims with no `exp`, `nbf`, or `iat`. Tokens are decoded without requiring expiration, meaning captured tokens can be replayed indefinitely to access async query event channels.

### Details
Violates ASVS 9.2.1 (L1) and CWE-613 (Insufficient Session Expiration).

**Affected Files:**
- `superset/async_events/async_query_manager.py`

**Related Findings:** FINDING-018, FINDING-038, FINDING-045

### Remediation
Add `exp` and `iat` claims to tokens created in `validate_session()` and enforce `options={"require": ["exp"]}` at decode time.

### Acceptance Criteria
- [ ] `exp` claim added to JWT tokens
- [ ] `iat` claim added to JWT tokens
- [ ] Token decode enforces expiration requirement
- [ ] Test added verifying expired tokens are rejected
- [ ] Test added verifying token replay prevention

### References
- ASVS 9.2.1
- CWE-613

### Priority
Medium

---
## Issue: FINDING-020 - Cost Estimation Path Bypasses RLS, Disallowed Function/Table Checks, and DML Validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The cost estimation path (`estimate.py`) does not apply RLS, disallowed function/table checks, or DML validation that are applied in the main execution path (`executor.py`). While EXPLAIN-based estimation doesn't typically expose actual data, row count estimates can confirm data existence behind RLS rules.

### Details
Disallowed functions/DML statements could be estimated without permission checks. Violates ASVS 1.2.4 (L1).

**Affected Files:**
- `superset/commands/sql_lab/estimate.py`

### Remediation
Normalize security controls on `estimate.py` path: add RLS application, disallowed function/table checks, and DML validation to match the main execution path.

### Acceptance Criteria
- [ ] RLS applied to cost estimation path
- [ ] Disallowed function/table checks added
- [ ] DML validation added
- [ ] Test added verifying RLS enforcement
- [ ] Test added verifying disallowed function rejection

### References
- ASVS 1.2.4

### Priority
Low

---
## Issue: FINDING-021 - Dynamic Function Dispatch via `getattr` with User-Controlled Operation Name in Post-Processing
**Labels:** bug, security, priority:low
**Description:**
### Summary
Post-processing uses `getattr(pandas_postprocessing, operation)` with a user-controlled operation name, relying on `hasattr` as an implicit allowlist. While the module namespace constrains available functions and no known function provides code execution, an explicit allowlist would be more robust.

### Details
An explicit allowlist would protect against future module additions or unexpected kwargs causing DoS. Violates ASVS 1.3.2 (L1).

**Affected Files:**
- `superset/common/query_object.py`

### Remediation
Replace `hasattr` check with an explicit `frozenset` allowlist of permitted operation names.

### Acceptance Criteria
- [ ] Explicit allowlist implemented using `frozenset`
- [ ] All current valid operations included in allowlist
- [ ] Test added verifying allowed operations work
- [ ] Test added rejecting operations not in allowlist

### References
- ASVS 1.3.2

### Priority
Low

---
## Issue: FINDING-022 - User-provided filename not sanitized in Content-Disposition header
**Labels:** bug, security, priority:low
**Description:**
### Summary
The user-provided filename is directly interpolated into the `Content-Disposition` header. Characters like `"` could break the header structure. While modern Werkzeug prevents CRLF injection, an unsanitized filename could cause browsers to save files with misleading names.

### Details
Violates ASVS 1.2.1 (L1).

**Affected Files:**
- `superset/charts/data/api.py`

### Remediation
Apply `secure_filename()` to user-provided filenames in `_create_streaming_csv_response` regardless of source.

### Acceptance Criteria
- [ ] `secure_filename()` applied to all user-provided filenames
- [ ] Test added verifying special characters are sanitized
- [ ] Test added verifying safe filenames are preserved

### References
- ASVS 1.2.1

### Priority
Low

---
## Issue: FINDING-023 - native_filters parameter not URL-encoded in dashboard permalink redirect
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `native_filters` parameter value is concatenated into the redirect URL without URL encoding, while other parameters are properly encoded via `parse.urlencode()`. An attacker-created permalink could inject additional URL parameters into the redirect destination.

### Details
This could potentially modify dashboard filter state displayed to the victim. Requires authenticated user to create malicious permalink and authenticated victim to access it. Violates ASVS 1.2.2 (L1).

**Affected Files:**
- `superset/views/core.py`

### Remediation
Always URL-encode parameter values in `dashboard_permalink`, or validate that `native_filters` contains no URL-structure-breaking characters (`&`, `#`, `?`).

### Acceptance Criteria
- [ ] URL encoding applied to `native_filters` parameter
- [ ] Test added verifying proper encoding
- [ ] Test added rejecting malformed parameters

### References
- ASVS 1.2.2

### Priority
Low

---
## Issue: FINDING-024 - Chart screenshot/thumbnail endpoints served without X-Content-Type-Options: nosniff or Content-Disposition header
**Labels:** bug, security, priority:low
**Description:**
### Summary
Chart screenshots served without `Content-Disposition` header or `X-Content-Type-Options: nosniff`. While the image/png MIME type prevents HTML execution in modern browsers, defense-in-depth would add `X-Content-Type-Options: nosniff` to prevent MIME sniffing.

### Details
Requires authenticated user and separate cache poisoning vulnerability for exploitation. Violates ASVS 3.2.1 (L1) and CWE-116.

**Affected Files:**
- `superset/charts/api.py`

**Related Findings:** FINDING-010, FINDING-033

### Remediation
Add `X-Content-Type-Options: nosniff` header via application middleware or per-endpoint response header.

### Acceptance Criteria
- [ ] `X-Content-Type-Options: nosniff` header added
- [ ] Test added verifying header presence
- [ ] Applied to all image serving endpoints

### References
- ASVS 3.2.1
- CWE-116

### Priority
Low

---
## Issue: FINDING-025 - No Explicit Cipher Mode Validation or Enforcement
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `EncryptedFieldFactory` accepts any adapter class from configuration without validating that it uses an approved cipher mode. There is no runtime assertion or startup check that verifies the configured encryption meets minimum security standards (e.g., AEAD mode).

### Details
Misconfiguration could silently downgrade encryption to weaker modes without detection. Violates ASVS 11.3.2 (L1) and CWE-327.

**Affected Files:**
- `superset/utils/encrypt.py`

**Related Findings:** FINDING-004

### Remediation
Add a startup validation that verifies the encryption adapter uses an approved AEAD mode, failing fast with a clear error message if not.

### Acceptance Criteria
- [ ] Startup validation added for cipher mode
- [ ] Clear error message on invalid configuration
- [ ] Test added verifying validation works
- [ ] Test added for approved cipher modes

### References
- ASVS 11.3.2
- CWE-327

### Priority
Low

---
## Issue: FINDING-026 - UUID3 (MD5-based) Used for Cache Key Generation
**Labels:** bug, security, priority:low
**Description:**
### Summary
`uuid3` internally uses MD5 to hash the namespace+name into a deterministic UUID. ASVS 11.4.1 states disallowed hash functions such as MD5 must not be used for any cryptographic purpose. The usage here is for deterministic key derivation (mapping cache key strings to UUIDs for database lookup), not for security-critical cryptographic operations.

### Details
A collision would cause cache data corruption but has no direct confidentiality or authentication impact. Violates ASVS 11.4.1 (L1) and CWE-328.

**Affected Files:**
- `superset/extensions/metastore_cache.py`

### Remediation
Replace `uuid3` with `uuid5` (SHA-1 based) for improved compliance, or use a custom approach with SHA-256 for full compliance with modern hash requirements.

### Acceptance Criteria
- [ ] `uuid3` replaced with `uuid5` or SHA-256 approach
- [ ] Test added verifying deterministic key generation
- [ ] Migration path documented for existing cache keys

### References
- ASVS 11.4.1
- CWE-328

### Priority
Low

---
## Issue: FINDING-027 - Extension Loading System Has No Mechanism to Reject Outdated or Vulnerable Extensions
**Labels:** bug, security, priority:low
**Description:**
### Summary
The extension discovery and loading pipeline loads all valid .supx files and local extension directories without any check against a vulnerability database, version allowlist, or maximum age threshold. Once an extension has a valid manifest and passes ZIP safety checks, it is loaded and its arbitrary Python code is executed.

### Details
Requires admin/filesystem access to exploit. Violates ASVS 15.2.1 (L1) and CWE-1104.

**Affected Files:**
- `superset/extensions/discovery.py`
- `superset/extensions/utils.py`

**Related Findings:** FINDING-028, FINDING-046

### Remediation
Add a version/vulnerability check gate in the extension loading pipeline, including an `EXTENSION_BLOCKLIST` configuration and maximum age checks.

### Acceptance Criteria
- [ ] Version/vulnerability check implemented
- [ ] `EXTENSION_BLOCKLIST` configuration added
- [ ] Maximum age check added
- [ ] Test added verifying blocklist enforcement
- [ ] Test added rejecting outdated extensions

### References
- ASVS 15.2.1
- CWE-1104

### Priority
Low

---
## Issue: FINDING-028 - No Dependency Version Auditing for Extension-Declared Dependencies
**Labels:** bug, security, priority:low
**Description:**
### Summary
The manifest's `dependencies` field is exposed through `build_extension_data()` but is never validated against known-vulnerable versions or checked for update compliance. Dependencies declared by extensions could reference outdated or vulnerable packages.

### Details
Violates ASVS 15.2.1 (L1) and CWE-1104.

**Affected Files:**
- `superset/extensions/utils.py`

**Related Findings:** FINDING-027, FINDING-046

### Remediation
Implement dependency auditing during extension loading that checks `manifest.dependencies` against a vulnerability database (e.g., OSV, GitHub Advisory Database).

### Acceptance Criteria
- [ ] Dependency auditing implemented
- [ ] Integration with vulnerability database (OSV or similar)
- [ ] Test added verifying vulnerable dependencies are rejected
- [ ] Warning/error logging for outdated dependencies

### References
- ASVS 15.2.1
- CWE-1104

### Priority
Low

---
## Issue: FINDING-029 - Post-processing operation options schemas exist but are documented as not enforced
**Labels:** bug, security, priority:low
**Description:**
### Summary
The codebase defines detailed per-operation option schemas (e.g., `ChartDataAggregateOptionsSchema`, `ChartDataRollingOptionsSchema`, `ChartDataPivotOptionsSchema`) with specific validators for each field, but these schemas are documented as not connected to the actual validation pipeline.

### Details
The `options` field is accepted as `Dict()` without structure validation and passed to pandas postprocessing functions. Violates ASVS 2.1.1 (L1) and CWE-20.

**Affected Files:**
- `superset/charts/schemas.py`

**Related Findings:** FINDING-007, FINDING-030, FINDING-031

### Remediation
Update to Marshmallow 3+ or use a custom `@validates_schema` validator that dispatches to the appropriate options schema based on the operation value.

### Acceptance Criteria
- [ ] Options schema validation connected to validation pipeline
- [ ] Test added verifying schema validation works
- [ ] Test added rejecting invalid options
- [ ] Documentation updated

### References
- ASVS 2.1.1
- CWE-20

### Priority
Low

---
## Issue: FINDING-030 - `ChartPutSchema` missing JSON validation on `query_context` field
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `ChartPutSchema` accepts `query_context` as a plain String without `validate=utils.validate_json`, while `ChartPostSchema` correctly applies this validator. This allows storage of malformed JSON that causes errors when the chart is rendered.

### Details
Violates ASVS 2.2.1 (L1) and CWE-20.

**Affected Files:**
- `superset/charts/schemas.py`

**Related Findings:** FINDING-007, FINDING-029, FINDING-031

### Remediation
Add `validate=utils.validate_json` to `ChartPutSchema.query_context` field to match `ChartPostSchema` behavior.

### Acceptance Criteria
- [ ] JSON validation added to `ChartPutSchema.query_context`
- [ ] Test added verifying malformed JSON is rejected
- [ ] Test added verifying valid JSON is accepted

### References
- ASVS 2.2.1
- CWE-20

### Priority
Low

---
## Issue: FINDING-031 - `external_url` fields lack URL format validation across multiple schemas
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `external_url` field appears in multiple Post and Put schemas without any URL format validation. While administrative in nature, storing arbitrary strings as URLs could lead to issues if rendered as hyperlinks without output encoding.

### Details
Violates ASVS 2.2.1 (L1) and CWE-20.

**Affected Files:**
- `superset/charts/schemas.py`
- `superset/dashboards/schemas.py`
- `superset/databases/schemas.py`
- `superset/datasets/schemas.py`

**Related Findings:** FINDING-007, FINDING-029, FINDING-030

### Remediation
Add URL validation with `validate=URL(schemes={'http', 'https'}, require_tld=True)` to `external_url` fields.

### Acceptance Criteria
- [ ] URL validation added to all `external_url` fields
- [ ] Test added verifying valid URLs are accepted
- [ ] Test added rejecting invalid URLs
- [ ] Test added for scheme restriction

### References
- ASVS 2.2.1
- CWE-20

### Priority
Low

---
## Issue: FINDING-032 - Embedded View Performs State-Changing login_user() on GET Without Anti-Forgery Token
**Labels:** bug, security, priority:low
**Description:**
### Summary
The embedded view performs `login_user(AnonymousUserMixin(), force=True)` on a GET request, protected only by referrer validation. The referrer-based origin check via `same_origin()` provides anti-forgery protection but is weaker than CSRF tokens.

### Details
Practical impact is mitigated by SameSite cookie policies in modern browsers. Violates ASVS 3.5.1 (L1) and CWE-352.

**Affected Files:**
- `superset/embedded/view.py`

### Remediation
For defense-in-depth, consider adding Sec-Fetch-Dest header validation to confirm the request originates from an iframe navigation.

### Acceptance Criteria
- [ ] Sec-Fetch-Dest header validation added
- [ ] Test added verifying header validation
- [ ] Fallback handling for browsers without Sec-Fetch support

### References
- ASVS 3.5.1
- CWE-352

### Priority
Low

---
## Issue: FINDING-033 - JSON Helper Functions Missing Charset Parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
Generic JSON response helper functions return `application/json` responses without the `charset=utf-8` parameter. While RFC 8259 mandates UTF-8 for JSON (making the parameter technically optional), ASVS 4.1.1 recommends charset on all text-based responses for defense-in-depth.

### Details
Violates ASVS 4.1.1 (L1) and CWE-116.

**Affected Files:**
- `superset/views/base.py`

**Related Findings:** FINDING-010, FINDING-024

### Remediation
Update `json_success` and `BaseSupersetView.json_response` to include `charset=utf-8` in Content-Type, consistent with the pattern already used in `_send_chart_response`.

### Acceptance Criteria
- [ ] `charset=utf-8` added to `json_success`
- [ ] `charset=utf-8` added to `BaseSupersetView.json_response`
- [ ] Test added verifying Content-Type header

### References
- ASVS 4.1.1
- CWE-116

### Priority
Low

---
## Issue: FINDING-034 - Extension ZIP per-entry size limits unclear
**Labels:** bug, security, priority:low
**Description:**
### Summary
In `superset/extensions/utils.py`, `get_bundle_files_from_zip` calls `check_is_safe_zip` but reads all file contents into memory without visible per-entry size limits. Only administrators with write access to EXTENSIONS_PATH can trigger this path.

### Details
Violates ASVS 5.2.1 (L1) and CWE-400.

**Affected Files:**
- `superset/extensions/utils.py`

**Related Findings:** FINDING-011

### Remediation
Verify that `check_is_safe_zip` implementation checks total decompressed size and per-entry ratios.

### Acceptance Criteria
- [ ] `check_is_safe_zip` implementation verified
- [ ] Per-entry size limits documented
- [ ] Test added verifying size limit enforcement

### References
- ASVS 5.2.1
- CWE-400

### Priority
Low

---
## Issue: FINDING-035 - No filename extension validation on import endpoint
**Labels:** bug, security, priority:low
**Description:**
### Summary
The import endpoint at `superset/importexport/api.py` validates file content via `is_zipfile()` but does not check the uploaded filename extension. Content validation is the stronger control and is properly applied; this is a defense-in-depth gap.

### Details
Violates ASVS 5.2.2 (L1) and CWE-434.

**Affected Files:**
- `superset/importexport/api.py`

### Remediation
Add extension validation alongside the existing content validation to verify uploaded files have .zip or .json extensions.

### Acceptance Criteria
- [ ] Extension validation added for .zip and .json
- [ ] Test added verifying valid extensions are accepted
- [ ] Test added rejecting invalid extensions

### References
- ASVS 5.2.2
- CWE-434

### Priority
Low

---
## Issue: FINDING-036 - Missing check_is_safe_zip in import API path
**Labels:** bug, security, priority:low
**Description:**
### Summary
The import endpoint does not visibly call `check_is_safe_zip` before extracting ZIP entries. However, no filesystem write operations use these paths—all content is processed in memory and stored in the database—and downstream processing uses prefix-based `startswith()` routing only. Practical impact is limited to potential confusion in file routing.

### Details
Violates ASVS 5.3.2 (L1) and CWE-22.

**Affected Files:**
- `superset/importexport/api.py`

**Related Findings:** FINDING-037

### Remediation
Ensure `get_contents_from_bundle` calls `check_is_safe_zip` before extracting entries, or add the check at the API level.

### Acceptance Criteria
- [ ] `check_is_safe_zip` added to import path
- [ ] Test added verifying path traversal prevention
- [ ] Test added for ZIP bomb protection

### References
- ASVS 5.3.2
- CWE-22

### Priority
Low

---
## Issue: FINDING-037 - Permissive BACKEND_REGEX in extension loading
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `BACKEND_REGEX` pattern uses `(.+)` which could match path traversal sequences. Mitigated by `check_is_safe_zip()` being called before extraction and the captured path only being used for in-memory module name generation. Requires administrator access to EXTENSIONS_PATH.

### Details
Violates ASVS 5.3.2 (L1) and CWE-22.

**Affected Files:**
- `superset/extensions/utils.py`

**Related Findings:** FINDING-036

### Remediation
Tighten the regex to reject path traversal characters: `^backend/src/((?:[a-zA-Z0-9_]+/)*[a-zA-Z0-9_]+\\.py)$`

### Acceptance Criteria
- [ ] Regex pattern tightened to reject path traversal
- [ ] Test added verifying valid paths are accepted
- [ ] Test added rejecting path traversal attempts

### References
- ASVS 5.3.2
- CWE-22

### Priority
Low

---
## Issue: FINDING-038 - Async query JWT token issued without expiration claim
**Labels:** bug, security, priority:low
**Description:**
### Summary
The async query JWT in `superset/async_events/async_query_manager.py` (lines 152-162) is generated without an `exp` claim. On logout, the Flask session is cleared but the JWT cookie remains valid indefinitely.

### Details
Exploitability is low due to httponly flag and separate Flask-Login authentication requirement on API endpoints. Violates ASVS 7.4.1 (L1) and CWE-613.

**Affected Files:**
- `superset/async_events/async_query_manager.py` (lines 152-162)

**Related Findings:** FINDING-018, FINDING-019, FINDING-045

### Remediation
Add an `exp` claim (e.g., 24 hours) to the async query JWT payload to ensure it cannot be used indefinitely after session termination.

### Acceptance Criteria
- [ ] `exp` claim added to JWT payload
- [ ] Expiration time configurable
- [ ] Test added verifying token expiration
- [ ] Test added verifying expired tokens are rejected

### References
- ASVS 7.4.1
- CWE-613

### Priority
Low

---
## Issue: FINDING-039 - MCP Tools Without Permission Metadata Default to Allowed
**Labels:** bug, security, priority:low
**Description:**
### Summary
In `superset/mcp_service/auth.py`, the `check_tool_permission` function defaults to allowing access when a tool function lacks the `CLASS_PERMISSION_ATTR`. This is a defense-in-depth gap rather than an immediately exploitable vulnerability.

### Details
Data flow: Tool registration (missing @tool decorator metadata) → `check_tool_permission` → `return True` → tool executes without RBAC check. Requires authenticated user. If all tools are properly decorated, this is unexploitable. Violates ASVS 8.2.1 (L1).

**Affected Files:**
- `superset/mcp_service/auth.py`

### Remediation
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

### Acceptance Criteria
- [ ] Fail-closed behavior implemented
- [ ] Warning logged for tools without metadata
- [ ] Test added verifying permission metadata requirement
- [ ] Test added verifying tools without metadata are rejected

### References
- ASVS 8.2.1

### Priority
Low

---
## Issue: FINDING-040 - MCP Admin Role Check Hardcoded Instead of Using Configuration
**Labels:** bug, security, priority:low
**Description:**
### Summary
In `superset/mcp_service/utils/permissions_utils.py`, the `user_has_permission` function checks admin status using hardcoded role names rather than the configurable `AUTH_ROLE_ADMIN` setting. The function checks if `role.name` is in ("Admin", "admin") instead of using the configured admin role name.

### Details
Requires non-standard deployment configuration where `AUTH_ROLE_ADMIN` is set to something other than "Admin". Impact: Admin users may not bypass field-level restrictions in MCP tools (denial of service to admins, not a privilege escalation). Violates ASVS 8.2.1 (L1).

**Affected Files:**
- `superset/mcp_service/utils/permissions_utils.py`

### Remediation
```python
from superset import security_manager

if hasattr(user, "roles"):
    admin_role_name = current_app.config.get("AUTH_ROLE_ADMIN", "Admin")
    for role in user.roles:
        if role.name == admin_role_name:
            return True
```

### Acceptance Criteria
- [ ] Admin role check uses `AUTH_ROLE_ADMIN` configuration
- [ ] Test added verifying custom admin role name works
- [ ] Test added verifying hardcoded names no longer work

### References
- ASVS 8.2.1

### Priority
Low

---
## Issue: FINDING-041 - Utility Function `get_datasource_by_id` Returns Data Without Access Verification
**Labels:** security, priority:low, defense-in-depth
**Description:**
### Summary
The `get_datasource_by_id` utility function in `commands/utils.py` retrieves datasource objects by ID without performing access control checks, relying entirely on calling commands to enforce authorization. This creates a defense-in-depth gap where missing upstream checks could lead to unauthorized datasource access (BOLA).

### Details
**Data Flow:**
- User-controlled `datasource_id` → `DatasourceDAO.get_datasource()` → returns datasource object without access check → relies on caller to verify access

**Attacker Capability Required:**
Authenticated user who calls a command that uses this function without proper access validation upstream.

**Impact:**
Could access datasource metadata if the calling command doesn't enforce access checks.

**Affected Files:**
- `superset/commands/utils.py`

**ASVS Reference:** 8.2.2 (Level L1)

**CWE:** N/A

### Remediation
Add an optional access check parameter to the utility function:

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

### Acceptance Criteria
- [ ] Function enforces access checks by default with opt-out capability
- [ ] All existing callers reviewed to ensure proper authorization
- [ ] Test added verifying access check enforcement
- [ ] Documentation updated to clarify authorization expectations

### References
- Source Report: 8.2.2.md
- Related Domain: authorization_enforcement

### Priority
Low - Defense-in-depth improvement; no evidence of exploitable paths without upstream validation failures.

---
## Issue: FINDING-042 - Conditional Algorithm Check in MCP JWT Verifier May Allow Signature Bypass
**Labels:** security, priority:low, jwt, cryptography
**Description:**
### Summary
The MCP JWT verifier contains a conditional `if self.algorithm` guard that skips both signature validation and algorithm allowlist enforcement when `self.algorithm` is falsy. While production configurations include algorithm specifications, the code should defensively reject tokens when no algorithm is configured rather than silently passing validation.

### Details
**Vulnerability:**
The conditional guard allows bypassing:
1. Signature validation (ASVS 9.1.1)
2. Algorithm allowlist enforcement (ASVS 9.1.2)

**Exploitation Requirements:**
Requires deployer misconfiguration where algorithm is not set in JWT configuration.

**Impact:**
Complete bypass of JWT signature verification and algorithm validation in misconfigured deployments.

**Affected Files:**
- `superset/mcp_service/jwt_verifier.py`

**ASVS Reference:** 9.1.1, 9.1.2 (Level L1)

**CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

### Remediation
Remove the `if self.algorithm` guard and implement one of:
1. Require algorithm configuration at initialization
2. Reject tokens when no expected algorithm is configured

Define an explicit allowlist constant and always enforce it:

```python
ALLOWED_ALGORITHMS = {'RS256', 'HS256'}

if not self.algorithm:
    raise JWTValidationError("JWT algorithm not configured")
if token_algorithm not in ALLOWED_ALGORITHMS:
    raise JWTValidationError(f"Algorithm {token_algorithm} not allowed")
```

### Acceptance Criteria
- [ ] Algorithm validation always executed, never skipped
- [ ] Explicit algorithm allowlist defined and enforced
- [ ] Tokens rejected when algorithm not configured
- [ ] Test added for missing algorithm configuration scenario
- [ ] Test added for disallowed algorithm rejection

### References
- Source Reports: 9.1.1.md, 9.1.2.md
- Related Domain: jwt_token_validation

### Priority
Low - Requires misconfiguration to exploit; production profiles include algorithm specification.

---
## Issue: FINDING-043 - No Explicit 'None' Algorithm Rejection in MCP Verifier
**Labels:** security, priority:low, jwt, cryptography
**Description:**
### Summary
The MCP JWT verifier does not explicitly reject tokens with `alg: "none"`. While the authlib library typically rejects "none" when a verification key is provided, ASVS 9.1.2 requires explicit exclusion of the 'None' algorithm from any allowlist as a defense-in-depth measure.

### Details
**Vulnerability:**
Missing explicit check for the dangerous `alg: "none"` header value, which historically has been exploited to bypass JWT signature verification.

**Current Behavior:**
Relies on authlib's implicit rejection rather than explicit validation.

**Impact:**
Potential signature bypass if library behavior changes or in edge cases where key validation is skipped.

**Affected Files:**
- `superset/mcp_service/jwt_verifier.py`

**ASVS Reference:** 9.1.2 (Level L1)

**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)

### Remediation
Add an explicit check before algorithm comparison:

```python
token_algorithm = token.header.get('alg', '').lower()
if token_algorithm == 'none':
    raise JWTValidationError("Algorithm 'none' is not permitted")
```

### Acceptance Criteria
- [ ] Explicit rejection of `alg: "none"` implemented
- [ ] Check performed regardless of configuration state
- [ ] Test added with token using `alg: "none"`
- [ ] Test verifies rejection with appropriate error message
- [ ] Case-insensitive check covers "none", "None", "NONE"

### References
- Source Report: 9.1.2.md
- Related Domain: jwt_token_validation

### Priority
Low - Defense-in-depth measure; library likely provides protection, but explicit check improves security posture.

---
## Issue: FINDING-044 - MCP Verifier Key Source Depends on Uninspectable Base Class
**Labels:** security, priority:low, jwt, cryptography
**Description:**
### Summary
The MCP JWT verifier passes the full token to `_get_verification_key(token)` without stripping potentially dangerous headers (jku, x5u, jwk). While the base class likely uses pre-configured JWKS sources, there is no explicit validation preventing token headers from influencing key resolution.

### Details
**Vulnerability:**
JWT headers can include claims that specify key sources:
- `jku` (JWK Set URL): Points to external key set
- `x5u` (X.509 URL): Points to external certificate
- `jwk` (JSON Web Key): Embeds key directly in token

If `_get_verification_key()` honors these headers, an attacker could supply their own key and sign tokens with it.

**Current State:**
No explicit validation or stripping of these headers before key resolution.

**Impact:**
Potential for attacker-controlled key source if base class implementation is vulnerable.

**Affected Files:**
- `superset/mcp_service/jwt_verifier.py`

**ASVS Reference:** 9.1.3 (Level L1)

**CWE:** CWE-295 (Improper Certificate Validation)

### Remediation
Add explicit validation to reject or strip untrusted key source headers:

```python
dangerous_headers = {'jku', 'x5u', 'jwk'}
if any(header in token.header for header in dangerous_headers):
    raise JWTValidationError(
        f"Token contains untrusted key source header: "
        f"{dangerous_headers & set(token.header.keys())}"
    )
verification_key = self._get_verification_key(token)
```

### Acceptance Criteria
- [ ] Validation rejects tokens with jku, x5u, or jwk headers
- [ ] Base class key resolution behavior documented
- [ ] Tests added for each dangerous header type
- [ ] Verification that key source is always pre-configured
- [ ] Security documentation updated with key management requirements

### References
- Source Report: 9.1.3.md
- Related Domain: jwt_token_validation

### Priority
Low - Requires base class vulnerability; likely protected by JWKS configuration, but explicit check improves defense-in-depth.

---
## Issue: FINDING-045 - MCP JWT Verifier Accepts Tokens Without Expiration Claim
**Labels:** security, priority:low, jwt, session-management
**Description:**
### Summary
The MCP JWT verifier's expiration check uses `if exp and exp < time.time()` which only validates expiration IF the `exp` claim is present. Tokens without an `exp` claim are accepted without any time-based restriction, allowing potentially infinite token lifetime.

### Details
**Vulnerability:**
The conditional check allows tokens to bypass expiration validation entirely by omitting the `exp` claim.

**Current Code:**
```python
if exp and exp < time.time():
    raise JWTValidationError("Token has expired")
```

**Expected Behavior:**
Profile documents list `exp` as an expected claim, but code does not enforce its presence.

**Impact:**
- Tokens never expire if `exp` claim omitted
- Compromised tokens remain valid indefinitely
- Violates ASVS 9.2.1 requirement for token expiration

**Affected Files:**
- `superset/mcp_service/jwt_verifier.py`

**ASVS Reference:** 9.2.1 (Level L1)

**CWE:** CWE-613 (Insufficient Session Expiration)

### Remediation
Change the expiration check to require the `exp` claim:

```python
exp = claims.get("exp")
if exp is None:
    raise JWTValidationError("Token missing required 'exp' claim")
if exp < time.time():
    raise JWTValidationError("Token has expired")
```

### Acceptance Criteria
- [ ] Tokens without `exp` claim are rejected
- [ ] Expired tokens continue to be rejected
- [ ] Test added for missing `exp` claim
- [ ] Test added for valid `exp` claim (not expired)
- [ ] Test added for expired `exp` claim
- [ ] Token generation ensures `exp` claim always included

### References
- Source Report: 9.2.1.md
- Related Domain: jwt_token_validation
- Related Findings: FINDING-018, FINDING-019, FINDING-038

### Priority
Low - Requires token generation to omit `exp` claim; profile documents expect it, but enforcement gap exists.