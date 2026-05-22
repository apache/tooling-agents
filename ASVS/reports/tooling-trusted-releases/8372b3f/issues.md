# Security Issues

*32 actionable finding(s). 2 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

## Issue: FINDING-001 - MFA Status Tracked But Not Enforced for Application Access
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application captures MFA status from the OAuth provider in UserSession.mfa and has Requirements.mfa_enabled available in the framework, but no route decorator or before_request hook verifies mfa == True. An attacker with stolen ASF credentials where the OAuth provider does not independently enforce MFA gains full application access with single-factor authentication.

### Details
- **CWE:** CWE-308
- **ASVS Sections:** 6.3.3 (Level L2)
- **Affected Files:**
  - `atr/models/sql.py`
  - `atr/blueprints/get.py`
  - `atr/blueprints/post.py`
  - `atr/blueprints/api_auth.py`

### Remediation
Add Requirements.mfa_enabled to route authentication decorators or implement a before_request hook that verifies session.mfa == True for all authenticated routes. Require session.mfa == True before allowing PAT generation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 6.3.3.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-002 - No re-authentication mechanism before sensitive credential operations
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The session validation only checks session validity and LDAP liveness — there is no step-up or fresh authentication mechanism. Sensitive credential endpoints (/tokens/jwt, /tokens, /api/key/add, /api/key/delete, /api/ssh-key/add, /api/ssh-key/delete) are rate-limited (10/hr) but no re-authentication is required. An attacker with a hijacked session can create new persistent authentication credentials (PATs, SSH keys) without proving identity, enabling long-term persistent access even after session compromise is detected.

### Details
- **CWE:** CWE-306
- **ASVS Sections:** 7.5.1 (Level L2)
- **Affected Files:**
  - `atr/sessions.py`

### Remediation
Implement a step-up authentication check for sensitive credential operations. Track authentication freshness in the session model and require the user to have authenticated within the last N minutes before creating PATs, SSH keys, or signing keys. This could leverage the OAuth re-login flow with a prompt=login parameter.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 7.5.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-003 - No user-facing interface to view active sessions or selectively terminate them
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The session store provides bulk termination but no listing or selective termination for users. Users cannot detect or respond to session compromise. If an attacker establishes a parallel session, the legitimate user has no visibility or termination capability. The Store class lacks a list_by_uid method and no user-facing endpoint exposes session management.

### Details
- **ASVS Sections:** 7.5.2 (Level L2)
- **Affected Files:**
  - `atr/sessions.py`

### Remediation
Implement a session management interface: add list_by_uid() to the session store, create a /settings/sessions endpoint that displays active sessions with metadata (created time, last activity), and allow users to terminate individual sessions after re-authentication.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 7.5.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-004 - URL validation using `pydantic.AnyUrl` permits unsafe URL protocols (javascript:, data:)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `to_url_list()` function in `atr/form.py` uses `pydantic.AnyUrl` which accepts any URL scheme including `javascript:` and `data:`. If stored URLs are later rendered as clickable links, this could enable stored XSS. The single-URL types (`URL`, `OptionalURL`) correctly use `pydantic.HttpUrl` but the list variant does not.

### Details
- **CWE:** CWE-79
- **ASVS Sections:** 1.2.2 (Level L1)
- **Affected Files:**
  - `atr/form.py`

### Remediation
Replace `pydantic.AnyUrl` with a custom validator or `pydantic.HttpUrl` to restrict to safe protocols (http, https, mailto).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 1.2.2.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-005 - Key Strength Validation Deferred Until 2026, Allowing Sub-128-bit Keys
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Keys created before April 2026 skip ALL strength validation, including algorithm type, RSA key size, and EC curve size. This allows import of DSA keys, 1024-bit RSA keys, or 160-bit EC keys — all below 128-bit security. The `_check_core_logic` in `signature.py` uses all keys associated with a committee without checking their strength. Severity is Medium because: (1) factoring a 1024-bit RSA key requires significant resources (~$100K+), (2) the attacker must import or find such a key already in the system, (3) it affects verification only for the committee where the key is associated.

### Details
- **CWE:** CWE-326
- **ASVS Sections:** 11.2.3, 11.6.1 (Level L2)
- **Affected Files:**
  - `atr/storage/writers/keys.py`

### Remediation
Add an absolute minimum key strength floor (e.g., reject keys below 2048-bit RSA / 224-bit EC) that applies regardless of creation date, preventing clearly broken keys from entering the system while preserving backward compatibility for 2048-4095 bit keys until 2026. Apply at minimum a reduced set of restrictions immediately (e.g., reject RSA < 2048, reject non-signing algorithms) rather than deferring all validation to 2026.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.2.3.md, 11.6.1.md
- Related Findings: None

### Priority
Medium

---

## Issue: FINDING-006 - Workflow SSH Key TTL (20 minutes) Exceeds ASVS 10-Minute Maximum for Out-of-Band Tokens
**Labels:** bug, security, priority:low
**Description:**
### Summary
Workflow SSH keys generated via OIDC authentication have a 20-minute TTL, exceeding the ASVS 6.5.5 maximum of 10 minutes for out-of-band tokens. The key is project-scoped, user-bound, and revocable, with uploads going through quarantine verification. Exploitation requires compromising the workflow environment during the 20-minute window.

### Details
- **CWE:** CWE-613
- **ASVS Sections:** 6.5.5 (Level L2)
- **Affected Files:**
  - `atr/models/sql.py`
  - `atr/storage/writers/ssh.py`

### Remediation
Reduce TTL to 10 minutes (600 seconds), implement key renewal within workflows for longer operations, or document as risk-accepted deviation with compensating controls (project scoping, quarantine verification, revocation capability).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 6.5.5.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-007 - Absent NIST SP 800-63B deviation justification for 7-day idle timeout
**Labels:** bug, security, priority:low
**Description:**
### Summary
The session inactivity timeout is hardcoded to 7 days (604,800 seconds). NIST SP 800-63B Section 7.2 recommends re-authentication after 30 minutes of inactivity for AAL2 and 12 hours for AAL1. The `asfquart-usage.md` documentation describes the timeout value and enforcement mechanism but does not include justification for this deviation from NIST guidelines.

### Details
- **ASVS Sections:** 7.1.1 (Level L2)
- **Affected Files:**
  - `atr/sessions.py`
  - `atr/docs/asfquart-usage.md`

### Remediation
Add a documented risk assessment section justifying the 7-day idle timeout. Include references to compensating controls: periodic LDAP liveness checks, OAuth delegation, secure cookie attributes, and the nature of the user base (ASF committers with existing identity management).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 7.1.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-008 - Absolute session maximum disabled by default (MAX_SESSION_AGE=0)
**Labels:** bug, security, priority:low
**Description:**
### Summary
When `MAX_SESSION_AGE` defaults to 0, the absolute session lifetime check is effectively disabled. A session that is used within every 7-day window can persist indefinitely without re-authentication. A stolen session token can be reused indefinitely as long as the attacker makes at least one request within the 7-day idle window. No re-authentication is ever forced for long-lived sessions. No documentation justifies why indefinite session lifetime (with activity) is acceptable, nor specifies the deployment-expected value for `MAX_SESSION_AGE`. However, exploitation requires prior session token theft, and the 7-day idle timeout and periodic LDAP liveness checks provide independent mitigation.

### Details
- **ASVS Sections:** 7.1.1, 7.3.2 (Level L2)
- **Affected Files:**
  - `atr/server.py`
  - `atr/sessions.py`

### Remediation
1. Document the expected production value of `MAX_SESSION_AGE` with justification. 2. Consider setting a non-zero default (e.g., 86400 = 24 hours) that deployments can override. 3. Include NIST SP 800-63B deviation justification in session management documentation. 4. Document the risk acceptance for MAX_SESSION_AGE=0 referencing the LDAP liveness checks and idle timeout as compensating controls.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 7.1.1.md, 7.3.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-009 - No documented policy for maximum concurrent sessions per account
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `Store.create()` method creates a new session without checking how many active sessions already exist for the user. No documentation defines how many concurrent sessions are allowed per account, whether there is a maximum, what behavior occurs if resources are exhausted, or the security rationale for allowing unlimited sessions.

### Details
- **ASVS Sections:** 7.1.2 (Level L2)
- **Affected Files:**
  - `atr/sessions.py`

### Remediation
Document the concurrent session policy explicitly stating that unlimited concurrent sessions are permitted by design, with security rationale referencing OAuth delegation, LDAP liveness checks, idle timeout pruning, and administrative revocation capability.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 7.1.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-010 - No JTI replay tracking for GitHub OIDC tokens
**Labels:** bug, security, priority:low
**Description:**
### Summary
ATR validates GitHub OIDC tokens without maintaining a record of previously consumed `jti` values. While the traditional OIDC nonce mechanism does not apply here (ATR does not send an authentication request to GitHub's OIDC provider — the workflow generates the token independently), the `jti` claim exists precisely for replay prevention. Without tracking used `jti` values, a token intercepted within its short validity window could theoretically be replayed.

### Details
- **CWE:** CWE-294
- **ASVS Sections:** 10.5.1 (Level L2)
- **Affected Files:**
  - `atr/models/github.py`

### Remediation
Implement JTI replay tracking with an in-memory dict and expiry-based cleanup to reject previously consumed tokens within their validity window.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 10.5.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-011 - GitHub OIDC token verification does not require `nbf` claim
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `verify_github_oidc()` function specifies `options={"require": ["exp", "iat"]}` but does not include `nbf` in the required claims list. While PyJWT validates `nbf` when present (and GitHub always includes it), the claim is not enforced as mandatory. ASVS 9.2.1 requires that validity time spans present in token data must be verified, and for JWTs, both 'nbf' and 'exp' claims must be verified.

### Details
- **CWE:** CWE-345
- **ASVS Sections:** 9.2.1 (Level L1)
- **Affected Files:**
  - `atr/jwtoken.py`

### Remediation
Add `nbf` to the required claims list: `options={"require": ["exp", "nbf", "iat"]}` to ensure the not-before claim is mandatory and properly enforced during token validation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 9.2.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-012 - CSP `style-src` directive includes `'unsafe-inline'`
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `style-src` directive includes `'unsafe-inline'`, which allows execution of inline `<style>` elements and `style` attributes. While this is common when using CSS frameworks like Bootstrap, it weakens the CSP by allowing CSS injection attacks that could facilitate data exfiltration (e.g., via CSS attribute selectors combined with background-url). CSS injection for data exfiltration only — `script-src` does NOT allow `unsafe-inline`, so JavaScript execution is still blocked. Risk is significantly lower than script-src unsafe-inline.

### Details
- **CWE:** CWE-1021
- **ASVS Sections:** 3.4.3 (Level L2)
- **Affected Files:**
  - `atr/server.py`

### Remediation
Consider migrating to CSP nonces for inline styles or using a separate stylesheet:
```python
# Per-response nonce generation
nonce = secrets.token_urlsafe(16)
f"style-src 'self' 'nonce-{nonce}"
```

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 3.4.3.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-013 - Permitted file types, maximum sizes, and malicious file handling behavior are defined in code but lack consolidated user-facing documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
Configuration constants define permitted types, sizes, and behavior but no externally-facing documentation artifact consolidates these for each upload feature.

### Details
- **CWE:** CWE-1059
- **ASVS Sections:** 5.1.1 (Level L2)
- **Affected Files:**
  - `atr/detection.py`
  - `atr/archives.py`

### Remediation
Create a consolidated document (e.g., in /docs/) specifying permitted archive types, expected content types per extension, maximum sizes, and behavior when malicious content is detected.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 5.1.1.md
- Related Findings: FINDING-016

### Priority
Low

---

## Issue: FINDING-014 - Content/extension validation (`validate_directory`) not called within quarantine promotion path visible in provided code
**Labels:** bug, security, priority:low
**Description:**
### Summary
The quarantine validate() function extracts archives and promotes them without a visible call to detection.validate_directory() between extraction and promotion. Content validation likely occurs in a separate check task but this could not be confirmed from provided files.

### Details
- **CWE:** CWE-434
- **ASVS Sections:** 5.2.2 (Level L1)
- **Affected Files:**
  - `atr/tasks/quarantine.py`

### Remediation
Verify that a separate check task calls detection.validate_directory() on promoted files. If not, add a content validation step either before promotion or as a post-promotion check task.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 5.2.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-015 - Key Lifecycle Not Enforced for Maximum Key Age or Rotation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The code tracks key expiration (`expires` field in `sql.PublicSigningKey`) but there is no evidence of enforcement—keys with past expiration dates are not automatically disabled for verification, and keys without expiration fields persist indefinitely. NIST SP 800-57 recommends cryptoperiods for all key types, and rotation/revocation should be enforced, not merely tracked.

### Details
- **CWE:** CWE-324
- **ASVS Sections:** 11.1.1 (Level L2)
- **Affected Files:**
  - `atr/storage/writers/keys.py`

### Remediation
Add expiration enforcement to signature verification key loading by filtering keys whose `expires` field is in the past before using them for verification.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.1.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-016 - Cryptographic Algorithms Used in Application Not Tracked in Key Inventory
**Labels:** bug, security, priority:low
**Description:**
### Summary
Multiple hash algorithms (SHA-512, SHA3-256, BLAKE3) used across the codebase with no centralized registry linking algorithm → purpose → data classification. The signing key inventory exists in the database, but a comprehensive application-level inventory covering hash algorithms and their purposes is not visible in the audited code.

### Details
- **CWE:** CWE-1059
- **ASVS Sections:** 11.1.2 (Level L2)
- **Affected Files:**
  - `atr/hashes.py`
  - `atr/noisy.py`

### Remediation
Maintain a centralized document or code constant mapping each cryptographic algorithm to its purpose, the data it protects, and the module where it's used.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.1.2.md
- Related Findings: FINDING-013

### Priority
Low

---

## Issue: FINDING-017 - Hash Algorithms Hardcoded Without Abstraction Layer for Reconfiguration
**Labels:** bug, security, priority:low
**Description:**
### Summary
DOWNGRADED from Medium: The finding acknowledges this is 'not directly exploitable' and is an architectural design gap. The algorithms are currently secure and prefixed for identification. Multiple hash algorithms are hardcoded without a configuration or factory pattern, increasing the cost of emergency cryptographic migration.

### Details
- **CWE:** CWE-327
- **ASVS Sections:** 11.2.2 (Level L2)
- **Affected Files:**
  - `atr/hashes.py`

### Remediation
Implement a hash algorithm abstraction layer with configurable defaults to enable algorithm migration without code changes at each call site.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.2.2.md
- Related Findings: FINDING-018

### Priority
Low

---

## Issue: FINDING-018 - Noisy Secrets Protocol Uses Fixed Checksum Algorithm Without Agility
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Noisy Secrets checksum is a fixed protocol specification with hardcoded constants (Q=37, polynomial coefficients 6, 26, 21, 3). This is by design — it's a format specification for token structure validation, not a security-critical hash. The security of PATs comes from the 256-bit payload entropy and bcrypt hashing for storage, not from the checksum.

### Details
- **CWE:** CWE-327
- **ASVS Sections:** 11.2.2 (Level L2)
- **Affected Files:**
  - `atr/noisy.py`

### Remediation
No immediate action required. The checksum serves a structural validation purpose (like a Luhn check) rather than a cryptographic security purpose.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.2.2.md
- Related Findings: FINDING-017

### Priority
Low

---

## Issue: FINDING-019 - Helper script uses insecure PRNG for temporary directories
**Labels:** bug, security, priority:low
**Description:**
### Summary
The gpgsign.sh helper script generates temp directory names using a non-CSPRNG, creating a potential symlink/race attack by a local attacker. Requires local access on the same machine where the user runs the script. The script is a convenience tool downloaded by release managers, not server infrastructure.

### Details
- **CWE:** CWE-330
- **ASVS Sections:** 11.5.1 (Level L2)
- **Affected Files:**
  - `atr/docs/signing-artifacts.md`

### Remediation
Replace the insecure pseudorandom temporary directory generation with `mktemp -d` which uses OS-provided CSPRNG.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 11.5.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-020 - PubSub client does not explicitly enforce TLS 1.2 minimum version and secure SSL context
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `listen()` function in `pubsub.py` creates an `aiohttp.ClientSession` without specifying an explicit SSL context or `TCPConnector` with `util.create_secure_ssl_context()`. While the `PubSubListener.start()` method validates the URL uses HTTPS, and aiohttp's default SSL context will verify certificates via `ssl.create_default_context()`, it does not explicitly enforce TLS 1.2 as the minimum version. The application has a dedicated utility (`util.create_secure_ssl_context()`) that sets `minimum_version = ssl.TLSVersion.TLSv1_2`, but this utility is not used for the PubSub connection, making TLS version enforcement dependent on system-level OpenSSL configuration rather than application-level policy.

### Details
- **CWE:** CWE-757
- **ASVS Sections:** 12.1.1, 12.3.2 (Level L1, L2)
- **Affected Files:**
  - `atr/pubsub.py`

### Remediation
Pass an explicit `TCPConnector` with `util.create_secure_ssl_context()` to the aiohttp ClientSession in `pubsub.py`. This will ensure both TLS 1.2 minimum version enforcement (12.1.1) and explicit certificate validation configuration (12.3.2) are applied consistently with the rest of the application.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 12.1.1.md, 12.3.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-021 - Logging pipeline lacks automated sensitive data redaction filter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The auth logging functions accept arbitrary keyword arguments and serialize them directly to JSON without any automated redaction or blocklist filter. While the API is designed to accept only non-sensitive parameters (event names, user identifiers), there is no technical control preventing accidental logging of sensitive data if a future caller passes credentials.

### Details
- **CWE:** CWE-532
- **ASVS Sections:** 14.2.4, 16.2.5 (Level L2)
- **Affected Files:**
  - `atr/log.py`

### Remediation
Add a keyword blocklist (_SENSITIVE_KEYS) to _auth_log that automatically redacts fields matching sensitive key names before JSON serialization.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 14.2.4.md, 16.2.5.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-022 - Missing `Clear-Site-Data` Header in Visible Session Termination Code
**Labels:** bug, security, priority:low
**Description:**
### Summary
Session termination functions (deleted_or_banned, terminate_current_users_sessions) perform server-side revocation and cookie clearing but do not set a Clear-Site-Data response header to instruct the browser to clear cached data. Exploitation requires physical access to the user's browser after session termination, and the server-side architecture means no valid session would exist — only previously-cached page content could leak.

### Details
- **CWE:** CWE-525
- **ASVS Sections:** 14.3.1 (Level L1)
- **Affected Files:**
  - `atr/sessions.py`

### Remediation
Add Clear-Site-Data: "cache", "cookies", "storage" header to logout/session-termination responses for defense-in-depth.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 14.3.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-023 - Auth audit log entries do not directly include source location (IP address, request path) in the event data
**Labels:** bug, security, priority:low
**Description:**
### Summary
Auth audit log entries include datetime (when), event (what), and request_user_id (who), but 'where' metadata (source IP, request path) is not part of the serialized JSON message. Cross-referencing with request log is needed. Mitigated by structlog contextvars pipeline that may add request_id.

### Details
- **ASVS Sections:** 16.2.1 (Level L2)
- **Affected Files:**
  - `atr/log.py`

### Remediation
Include request context directly in auth log entries by adding request_id and optionally source_ip from context.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.2.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-024 - Performance logger uses local time instead of UTC, with developer TODO acknowledging the issue
**Labels:** bug, security, priority:low
**Description:**
### Summary
The performance logger's MicrosecondsFormatter uses Python's default time.localtime converter, producing timestamps in local timezone without explicit offset. Developer has acknowledged with a TODO comment.

### Details
- **ASVS Sections:** 16.2.2 (Level L2)
- **Affected Files:**
  - `atr/log.py`

### Remediation
Set the formatter's converter to time.gmtime to ensure UTC output.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.2.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-025 - In-memory debug log buffer (BufferingHandler) is an undocumented log destination
**Labels:** bug, security, priority:low
**Description:**
### Summary
The BufferingHandler captures all log messages into an in-memory buffer (100 entries) retrievable via get_recent_logs(). This constitutes an additional log destination not documented in the logging inventory.

### Details
- **ASVS Sections:** 16.2.3 (Level L2)
- **Affected Files:**
  - `atr/log.py`

### Remediation
Document the in-memory buffer in the logging inventory, including conditions for activation, retention, and access control.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.2.3.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-026 - Authorization denial details not logged at point of decision in storage layer
**Labels:** bug, security, priority:low
**Description:**
### Summary
Authorization denial context (which committee/project, which user, what reason) is constructed as an error message in as_*_outcome() methods but not explicitly logged at the storage layer. The gap is about whether denial context (reason, target resource) reaches the audit trail reliably.

### Details
- **ASVS Sections:** 16.3.2 (Level L2)
- **Affected Files:**
  - `atr/storage/__init__.py`

### Remediation
Add explicit authorization failure logging via log.auth_event('authorization_denied', ...) at decision points in Write.as_*_outcome() methods.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.3.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-027 - General logging functions rely on structlog renderer configuration for injection protection
**Labels:** bug, security, priority:low
**Description:**
### Summary
The general _event() logging function does not enforce JSON encoding; protection depends on renderer configuration. Security-critical logs (atr.auth, atr.storage.audit) use explicit json.dumps() and are unaffected. Project has active plan to migrate to t-strings (Python 3.14).

### Details
- **ASVS Sections:** 16.4.1 (Level L2)
- **Affected Files:**
  - `atr/log.py`
  - `atr/loggers.py`

### Remediation
Ensure all persistent log handlers use JSONRenderer() for production deployments. Continue planned migration to t-strings.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.4.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-028 - Internal state information in AccessError messages for 500-status errors
**Labels:** bug, security, priority:low
**Description:**
### Summary
AccessError messages with status=500 contain internal architecture details (e.g., 'No committee found for project - Invalid state', 'User service writes require an ASF UID'). Without confirmed error handler middleware sanitization, these may reach consumers.

### Details
- **ASVS Sections:** 16.5.1 (Level L2)
- **Affected Files:**
  - `atr/storage/__init__.py`

### Remediation
Ensure 500-status AccessError messages use generic text suitable for external consumption, and log the detailed reason internally via log.error().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.5.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-029 - Audit logging uses fire-and-forget pattern — logging failure does not halt operation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The audit() and _auth_log() functions use QueueHandler which returns immediately. There is no mechanism for calling code to detect that audit logging has failed. Security-critical operations could proceed without audit trail if log storage becomes unavailable.

### Details
- **ASVS Sections:** 16.5.3 (Level L2)
- **Affected Files:**
  - `atr/storage/__init__.py`
  - `atr/log.py`
  - `atr/loggers.py`

### Remediation
Consider a synchronous write path for critical audit events or a health check that monitors queue depth.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 16.5.3.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-030 - Vote Casting Endpoint Relies Only on Global Rate Limits
**Labels:** bug, security, priority:low
**Description:**
### Summary
Vote casting endpoint (POST `/vote/<project_key>/<version_key>`) is not included in the sensitive endpoint rate limit tier (10/hr). It falls under global limits only (100/min, 1000/hr per user). An authenticated user could cast up to 100 votes per minute, each generating a receipt email to the project's mailing list. Over an hour, this produces up to 6000 emails.

### Details
- **CWE:** CWE-799
- **ASVS Sections:** 2.4.1 (Level L2)
- **Affected Files:**
  - `atr/post/vote.py`

### Remediation
Add a per-endpoint rate limit to the vote casting endpoint, consistent with other sensitive operations (e.g., 10-30/hr).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 2.4.1.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-031 - Process-wide `os.chdir()` in RAT execution creates thread-safety risk under concurrent load
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `_check_core_logic_execute_rat()` function uses `os.chdir(scan_root)` which modifies process-wide state, creating a race condition when multiple RAT tasks execute concurrently via the thread pool. Under concurrent task execution, RAT checks could execute in the wrong directory, producing incorrect results or failing. This affects availability (failed tasks requiring retry) and potentially integrity (wrong directory scanned). Does not enable RCE or privilege escalation.

### Details
- **CWE:** CWE-362
- **ASVS Sections:** 15.2.2 (Level L2)
- **Affected Files:**
  - `atr/tasks/checks/rat.py`

### Remediation
Replace `os.chdir(scan_root)` + `subprocess.run(...)` with `subprocess.run(..., cwd=scan_root)` in `_check_core_logic_execute_rat()`. This is a one-line fix that eliminates the race condition. The correct pattern already exists in the codebase (`score_qs()` in `sbom.py` uses `cwd=str(full_path.parent)`).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 15.2.2.md
- Related Findings: None

### Priority
Low

---

## Issue: FINDING-032 - Admin session termination has potential delay via LDAP liveness check mechanism
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `revoke_by_uid()` method provides immediate session termination capability for individual users. The LDAP-based path introduces a delay equal to `ACCOUNT_CHECK_INTERVAL` between admin action (disabling account) and session termination. Admin endpoints in blueprint files (not provided) likely expose this capability directly but cannot be verified from audited code.

### Details
- **ASVS Sections:** 7.4.5 (Level L2)
- **Affected Files:**
  - `atr/sessions.py`
  - `atr/server.py`

### Remediation
Ensure an admin endpoint directly calls `Store.revoke_by_uid()` for immediate session termination without requiring LDAP account disable. Verify this exists in admin blueprint code.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source Reports: 7.4.5.md
- Related Findings: None

### Priority
Low