# Security Audit Consolidated Report — apache/tooling-trusted-releases

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/tooling-trusted-releases |
| ASVS Level | L2 |
| Severity Threshold | None (all findings included) |
| Commit | `8372b3f` |
| Date | May 22, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 253 |
| Total Findings | 34 |
| Actionable Issues | 32 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 32 actionable items.*

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 5 |
| Low | 27 |
| Informational | 2 |

The repository presents a **low overall risk posture**. No critical or high severity findings were identified across 253 source reports spanning 26 audit domains. The five medium-severity findings relate to session management enforcement gaps and input validation weaknesses rather than exploitable vulnerabilities in production traffic paths.

### ASVS Level Coverage

This audit was scoped to **ASVS Level 2 (L2)**, which targets applications handling sensitive data and business logic requiring defence-in-depth controls. Findings span both L1 baseline requirements (4 findings) and L2-specific requirements (30 findings), indicating that L1 fundamentals are substantially met while L2 hardening items remain open.

### Top 5 Risks

1. **MFA Not Enforced at Application Layer (FINDING-001)** — The application tracks MFA status from the identity provider but does not gate sensitive operations on MFA completion, leaving step-up authentication decisions entirely to the upstream IdP.

2. **No Re-authentication Before Credential Operations (FINDING-002)** — Sensitive credential management operations (key generation, secret rotation) proceed without requiring the user to re-confirm their identity, increasing the blast radius of a hijacked session.

3. **No User Session Visibility or Selective Termination (FINDING-003)** — Users cannot inspect their active sessions or revoke individual sessions, limiting their ability to respond to suspected compromise.

4. **Unsafe URL Protocols Permitted by Validation (FINDING-004)** — The use of `pydantic.AnyUrl` without protocol restriction allows `javascript:` and `data:` URIs to pass validation, creating a potential stored XSS vector if URLs are rendered in browser contexts.

5. **Deferred Key Strength Validation Allows Weak Keys (FINDING-005)** — Cryptographic key strength enforcement below 128-bit equivalent security is deferred by a TODO-gated check, meaning keys with insufficient strength can currently be registered.

### Positive Controls

The audit identified **50 verified positive controls** across all 26 domains, demonstrating mature security practices in several critical areas:

- **Session Management** — Sessions use CSPRNG-generated reference tokens with 128+ bits of entropy, tokens are regenerated on authentication, and server-side verification is enforced. Logout, account disablement, and credential change all trigger proper session invalidation.
- **Cryptographic Operations** — The project exclusively uses industry-validated libraries (cryptography.io, bcrypt, sequoia-pgp), employs AES-GCM authenticated encryption, and relies on collision-resistant hash functions (SHA-512, SHA3-256, BLAKE3) with no use of MD5 or SHA1 for security purposes.
- **JWT Token Validation** — Algorithm allowlists are enforced, the `none` algorithm is rejected, key material is sourced from pre-configured trusted sources, and `exp`/`aud` claims are validated.
- **File Upload Security** — A full quarantine pipeline is in place with size limits, compressed file bomb detection, antivirus scanning, secure storage isolation, and filename sanitization.
- **Authentication Architecture** — SSH keys are project-scoped and user-bound with revocation capability, anti-automation controls are implemented, no default accounts exist, and authentication strength enforcement is properly delegated to the ASF OAuth identity provider.
- **Input Validation** — SafeType character allowlists proactively exclude format-string-dangerous characters from all validated types used as format arguments, and output encoding is context-aware across HTML, XML, JavaScript, and JSON contexts.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: MFA Status Tracked But Not Enforced for Application Access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-308 |
| **ASVS Section(s)** | 6.3.3 |
| **Files** | atr/models/sql.py, atr/blueprints/get.py, atr/blueprints/post.py, atr/blueprints/api_auth.py |
| **Source Reports** | 6.3.3.md |
| **Related** | None |

**Description:**

The application captures MFA status from the OAuth provider in UserSession.mfa and has Requirements.mfa_enabled available in the framework, but no route decorator or before_request hook verifies mfa == True. An attacker with stolen ASF credentials where the OAuth provider does not independently enforce MFA gains full application access with single-factor authentication.

**Remediation:**

Add Requirements.mfa_enabled to route authentication decorators or implement a before_request hook that verifies session.mfa == True for all authenticated routes. Require session.mfa == True before allowing PAT generation.

---

#### FINDING-002: No re-authentication mechanism before sensitive credential operations

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-306 |
| **ASVS Section(s)** | 7.5.1 |
| **Files** | atr/sessions.py |
| **Source Reports** | 7.5.1.md |
| **Related** | None |

**Description:**

The session validation only checks session validity and LDAP liveness — there is no step-up or fresh authentication mechanism. Sensitive credential endpoints (/tokens/jwt, /tokens, /api/key/add, /api/key/delete, /api/ssh-key/add, /api/ssh-key/delete) are rate-limited (10/hr) but no re-authentication is required. An attacker with a hijacked session can create new persistent authentication credentials (PATs, SSH keys) without proving identity, enabling long-term persistent access even after session compromise is detected.

**Remediation:**

Implement a step-up authentication check for sensitive credential operations. Track authentication freshness in the session model and require the user to have authenticated within the last N minutes before creating PATs, SSH keys, or signing keys. This could leverage the OAuth re-login flow with a prompt=login parameter.

---

#### FINDING-003: No user-facing interface to view active sessions or selectively terminate them

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 7.5.2 |
| **Files** | atr/sessions.py |
| **Source Reports** | 7.5.2.md |
| **Related** | None |

**Description:**

The session store provides bulk termination but no listing or selective termination for users. Users cannot detect or respond to session compromise. If an attacker establishes a parallel session, the legitimate user has no visibility or termination capability. The Store class lacks a list_by_uid method and no user-facing endpoint exposes session management.

**Remediation:**

Implement a session management interface: add list_by_uid() to the session store, create a /settings/sessions endpoint that displays active sessions with metadata (created time, last activity), and allow users to terminate individual sessions after re-authentication.

---

#### FINDING-004: URL validation using `pydantic.AnyUrl` permits unsafe URL protocols (javascript:, data:)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.2 |
| **Files** | atr/form.py |
| **Source Reports** | 1.2.2.md |
| **Related** | None |

**Description:**

The `to_url_list()` function in `atr/form.py` uses `pydantic.AnyUrl` which accepts any URL scheme including `javascript:` and `data:`. If stored URLs are later rendered as clickable links, this could enable stored XSS. The single-URL types (`URL`, `OptionalURL`) correctly use `pydantic.HttpUrl` but the list variant does not.

**Remediation:**

Replace `pydantic.AnyUrl` with a custom validator or `pydantic.HttpUrl` to restrict to safe protocols (http, https, mailto).

---

#### FINDING-005: Key Strength Validation Deferred Until 2026, Allowing Sub-128-bit Keys

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-326 |
| **ASVS Section(s)** | 11.2.3, 11.6.1 |
| **Files** | atr/storage/writers/keys.py |
| **Source Reports** | 11.2.3.md, 11.6.1.md |
| **Related** | None |

**Description:**

Keys created before April 2026 skip ALL strength validation, including algorithm type, RSA key size, and EC curve size. This allows import of DSA keys, 1024-bit RSA keys, or 160-bit EC keys — all below 128-bit security. The `_check_core_logic` in `signature.py` uses all keys associated with a committee without checking their strength. Severity is Medium because: (1) factoring a 1024-bit RSA key requires significant resources (~$100K+), (2) the attacker must import or find such a key already in the system, (3) it affects verification only for the committee where the key is associated.

**Remediation:**

Add an absolute minimum key strength floor (e.g., reject keys below 2048-bit RSA / 224-bit EC) that applies regardless of creation date, preventing clearly broken keys from entering the system while preserving backward compatibility for 2048-4095 bit keys until 2026. Apply at minimum a reduced set of restrictions immediately (e.g., reject RSA < 2048, reject non-signing algorithms) rather than deferring all validation to 2026.

### 3.4 Low

#### FINDING-006: Workflow SSH Key TTL (20 minutes) Exceeds ASVS 10-Minute Maximum for Out-of-Band Tokens

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-613 |
| ASVS sections | 6.5.5 |
| Files | atr/models/sql.py, atr/storage/writers/ssh.py |
| Source Reports | 6.5.5.md |
| Related | - |

**Description:**

Workflow SSH keys generated via OIDC authentication have a 20-minute TTL, exceeding the ASVS 6.5.5 maximum of 10 minutes for out-of-band tokens. The key is project-scoped, user-bound, and revocable, with uploads going through quarantine verification. Exploitation requires compromising the workflow environment during the 20-minute window.

**Remediation:**

Reduce TTL to 10 minutes (600 seconds), implement key renewal within workflows for longer operations, or document as risk-accepted deviation with compensating controls (project scoping, quarantine verification, revocation capability).

---

#### FINDING-007: Absent NIST SP 800-63B deviation justification for 7-day idle timeout

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.1.1 |
| Files | atr/sessions.py, atr/docs/asfquart-usage.md |
| Source Reports | 7.1.1.md |
| Related | - |

**Description:**

The session inactivity timeout is hardcoded to 7 days (604,800 seconds). NIST SP 800-63B Section 7.2 recommends re-authentication after 30 minutes of inactivity for AAL2 and 12 hours for AAL1. The `asfquart-usage.md` documentation describes the timeout value and enforcement mechanism but does not include justification for this deviation from NIST guidelines.

**Remediation:**

Add a documented risk assessment section justifying the 7-day idle timeout. Include references to compensating controls: periodic LDAP liveness checks, OAuth delegation, secure cookie attributes, and the nature of the user base (ASF committers with existing identity management).

---

#### FINDING-008: Absolute session maximum disabled by default (MAX_SESSION_AGE=0)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.1.1, 7.3.2 |
| Files | atr/server.py, atr/sessions.py |
| Source Reports | 7.1.1.md, 7.3.2.md |
| Related | - |

**Description:**

When `MAX_SESSION_AGE` defaults to 0, the absolute session lifetime check is effectively disabled. A session that is used within every 7-day window can persist indefinitely without re-authentication. A stolen session token can be reused indefinitely as long as the attacker makes at least one request within the 7-day idle window. No re-authentication is ever forced for long-lived sessions. No documentation justifies why indefinite session lifetime (with activity) is acceptable, nor specifies the deployment-expected value for `MAX_SESSION_AGE`. However, exploitation requires prior session token theft, and the 7-day idle timeout and periodic LDAP liveness checks provide independent mitigation.

**Remediation:**

1. Document the expected production value of `MAX_SESSION_AGE` with justification. 2. Consider setting a non-zero default (e.g., 86400 = 24 hours) that deployments can override. 3. Include NIST SP 800-63B deviation justification in session management documentation. 4. Document the risk acceptance for MAX_SESSION_AGE=0 referencing the LDAP liveness checks and idle timeout as compensating controls.

---

#### FINDING-009: No documented policy for maximum concurrent sessions per account

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.1.2 |
| Files | atr/sessions.py |
| Source Reports | 7.1.2.md |
| Related | - |

**Description:**

The `Store.create()` method creates a new session without checking how many active sessions already exist for the user. No documentation defines how many concurrent sessions are allowed per account, whether there is a maximum, what behavior occurs if resources are exhausted, or the security rationale for allowing unlimited sessions.

**Remediation:**

Document the concurrent session policy explicitly stating that unlimited concurrent sessions are permitted by design, with security rationale referencing OAuth delegation, LDAP liveness checks, idle timeout pruning, and administrative revocation capability.

---

#### FINDING-010: No JTI replay tracking for GitHub OIDC tokens

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-294 |
| ASVS sections | 10.5.1 |
| Files | atr/models/github.py |
| Source Reports | 10.5.1.md |
| Related | - |

**Description:**

ATR validates GitHub OIDC tokens without maintaining a record of previously consumed `jti` values. While the traditional OIDC nonce mechanism does not apply here (ATR does not send an authentication request to GitHub's OIDC provider — the workflow generates the token independently), the `jti` claim exists precisely for replay prevention. Without tracking used `jti` values, a token intercepted within its short validity window could theoretically be replayed.

**Remediation:**

Implement JTI replay tracking with an in-memory dict and expiry-based cleanup to reject previously consumed tokens within their validity window.

---

#### FINDING-011: GitHub OIDC token verification does not require `nbf` claim

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-345 |
| ASVS sections | 9.2.1 |
| Files | atr/jwtoken.py |
| Source Reports | 9.2.1.md |
| Related | - |

**Description:**

The `verify_github_oidc()` function specifies `options={"require": ["exp", "iat"]}` but does not include `nbf` in the required claims list. While PyJWT validates `nbf` when present (and GitHub always includes it), the claim is not enforced as mandatory. ASVS 9.2.1 requires that validity time spans present in token data must be verified, and for JWTs, both 'nbf' and 'exp' claims must be verified.

**Remediation:**

Add `nbf` to the required claims list: `options={"require": ["exp", "nbf", "iat"]}` to ensure the not-before claim is mandatory and properly enforced during token validation.

---

#### FINDING-012: CSP `style-src` directive includes `'unsafe-inline'`

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-1021 |
| ASVS sections | 3.4.3 |
| Files | atr/server.py |
| Source Reports | 3.4.3.md |
| Related | - |

**Description:**

The `style-src` directive includes `'unsafe-inline'`, which allows execution of inline `<style>` elements and `style` attributes. While this is common when using CSS frameworks like Bootstrap, it weakens the CSP by allowing CSS injection attacks that could facilitate data exfiltration (e.g., via CSS attribute selectors combined with background-url). CSS injection for data exfiltration only — `script-src` does NOT allow `unsafe-inline`, so JavaScript execution is still blocked. Risk is significantly lower than script-src unsafe-inline.

**Remediation:**

Consider migrating to CSP nonces for inline styles or using a separate stylesheet:
```python
# Per-response nonce generation
nonce = secrets.token_urlsafe(16)
f"style-src 'self' 'nonce-{nonce}"
```

---

#### FINDING-013: Permitted file types, maximum sizes, and malicious file handling behavior are defined in code but lack consolidated user-facing documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-1059 |
| ASVS sections | 5.1.1 |
| Files | atr/detection.py, atr/archives.py |
| Source Reports | 5.1.1.md |
| Related | FINDING-016 |

**Description:**

Configuration constants define permitted types, sizes, and behavior but no externally-facing documentation artifact consolidates these for each upload feature.

**Remediation:**

Create a consolidated document (e.g., in /docs/) specifying permitted archive types, expected content types per extension, maximum sizes, and behavior when malicious content is detected.

---

#### FINDING-014: Content/extension validation (`validate_directory`) not called within quarantine promotion path visible in provided code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-434 |
| ASVS sections | 5.2.2 |
| Files | atr/tasks/quarantine.py |
| Source Reports | 5.2.2.md |
| Related | - |

**Description:**

The quarantine validate() function extracts archives and promotes them without a visible call to detection.validate_directory() between extraction and promotion. Content validation likely occurs in a separate check task but this could not be confirmed from provided files.

**Remediation:**

Verify that a separate check task calls detection.validate_directory() on promoted files. If not, add a content validation step either before promotion or as a post-promotion check task.

---

#### FINDING-015: Key Lifecycle Not Enforced for Maximum Key Age or Rotation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-324 |
| ASVS sections | 11.1.1 |
| Files | atr/storage/writers/keys.py |
| Source Reports | 11.1.1.md |
| Related | - |

**Description:**

The code tracks key expiration (`expires` field in `sql.PublicSigningKey`) but there is no evidence of enforcement—keys with past expiration dates are not automatically disabled for verification, and keys without expiration fields persist indefinitely. NIST SP 800-57 recommends cryptoperiods for all key types, and rotation/revocation should be enforced, not merely tracked.

**Remediation:**

Add expiration enforcement to signature verification key loading by filtering keys whose `expires` field is in the past before using them for verification.

---

#### FINDING-016: Cryptographic Algorithms Used in Application Not Tracked in Key Inventory

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-1059 |
| ASVS sections | 11.1.2 |
| Files | atr/hashes.py, atr/noisy.py |
| Source Reports | 11.1.2.md |
| Related | FINDING-013 |

**Description:**

Multiple hash algorithms (SHA-512, SHA3-256, BLAKE3) used across the codebase with no centralized registry linking algorithm → purpose → data classification. The signing key inventory exists in the database, but a comprehensive application-level inventory covering hash algorithms and their purposes is not visible in the audited code.

**Remediation:**

Maintain a centralized document or code constant mapping each cryptographic algorithm to its purpose, the data it protects, and the module where it's used.

---

#### FINDING-017: Hash Algorithms Hardcoded Without Abstraction Layer for Reconfiguration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-327 |
| ASVS sections | 11.2.2 |
| Files | atr/hashes.py |
| Source Reports | 11.2.2.md |
| Related | FINDING-018 |

**Description:**

DOWNGRADED from Medium: The finding acknowledges this is 'not directly exploitable' and is an architectural design gap. The algorithms are currently secure and prefixed for identification. Multiple hash algorithms are hardcoded without a configuration or factory pattern, increasing the cost of emergency cryptographic migration.

**Remediation:**

Implement a hash algorithm abstraction layer with configurable defaults to enable algorithm migration without code changes at each call site.

---

#### FINDING-018: Noisy Secrets Protocol Uses Fixed Checksum Algorithm Without Agility

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-327 |
| ASVS sections | 11.2.2 |
| Files | atr/noisy.py |
| Source Reports | 11.2.2.md |
| Related | FINDING-017 |

**Description:**

The Noisy Secrets checksum is a fixed protocol specification with hardcoded constants (Q=37, polynomial coefficients 6, 26, 21, 3). This is by design — it's a format specification for token structure validation, not a security-critical hash. The security of PATs comes from the 256-bit payload entropy and bcrypt hashing for storage, not from the checksum.

**Remediation:**

No immediate action required. The checksum serves a structural validation purpose (like a Luhn check) rather than a cryptographic security purpose.

---

#### FINDING-019: Helper script uses insecure PRNG for temporary directories

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-330 |
| ASVS sections | 11.5.1 |
| Files | atr/docs/signing-artifacts.md |
| Source Reports | 11.5.1.md |
| Related | - |

**Description:**

The gpgsign.sh helper script generates temp directory names using a non-CSPRNG, creating a potential symlink/race attack by a local attacker. Requires local access on the same machine where the user runs the script. The script is a convenience tool downloaded by release managers, not server infrastructure.

**Remediation:**

Replace the insecure pseudorandom temporary directory generation with `mktemp -d` which uses OS-provided CSPRNG.

---

#### FINDING-020: PubSub client does not explicitly enforce TLS 1.2 minimum version and secure SSL context

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1, L2 |
| CWE | CWE-757 |
| ASVS sections | 12.1.1, 12.3.2 |
| Files | atr/pubsub.py |
| Source Reports | 12.1.1.md, 12.3.2.md |
| Related | - |

**Description:**

The `listen()` function in `pubsub.py` creates an `aiohttp.ClientSession` without specifying an explicit SSL context or `TCPConnector` with `util.create_secure_ssl_context()`. While the `PubSubListener.start()` method validates the URL uses HTTPS, and aiohttp's default SSL context will verify certificates via `ssl.create_default_context()`, it does not explicitly enforce TLS 1.2 as the minimum version. The application has a dedicated utility (`util.create_secure_ssl_context()`) that sets `minimum_version = ssl.TLSVersion.TLSv1_2`, but this utility is not used for the PubSub connection, making TLS version enforcement dependent on system-level OpenSSL configuration rather than application-level policy.

**Remediation:**

Pass an explicit `TCPConnector` with `util.create_secure_ssl_context()` to the aiohttp ClientSession in `pubsub.py`. This will ensure both TLS 1.2 minimum version enforcement (12.1.1) and explicit certificate validation configuration (12.3.2) are applied consistently with the rest of the application.

---

#### FINDING-021: Logging pipeline lacks automated sensitive data redaction filter

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-532 |
| ASVS sections | 14.2.4, 16.2.5 |
| Files | atr/log.py |
| Source Reports | 14.2.4.md, 16.2.5.md |
| Related | - |

**Description:**

The auth logging functions accept arbitrary keyword arguments and serialize them directly to JSON without any automated redaction or blocklist filter. While the API is designed to accept only non-sensitive parameters (event names, user identifiers), there is no technical control preventing accidental logging of sensitive data if a future caller passes credentials.

**Remediation:**

Add a keyword blocklist (_SENSITIVE_KEYS) to _auth_log that automatically redacts fields matching sensitive key names before JSON serialization.

---

#### FINDING-022: Missing `Clear-Site-Data` Header in Visible Session Termination Code

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-525 |
| ASVS sections | 14.3.1 |
| Files | atr/sessions.py |
| Source Reports | 14.3.1.md |
| Related | - |

**Description:**

Session termination functions (deleted_or_banned, terminate_current_users_sessions) perform server-side revocation and cookie clearing but do not set a Clear-Site-Data response header to instruct the browser to clear cached data. Exploitation requires physical access to the user's browser after session termination, and the server-side architecture means no valid session would exist — only previously-cached page content could leak.

**Remediation:**

Add Clear-Site-Data: "cache", "cookies", "storage" header to logout/session-termination responses for defense-in-depth.

---

#### FINDING-023: Auth audit log entries do not directly include source location (IP address, request path) in the event data

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.2.1 |
| Files | atr/log.py |
| Source Reports | 16.2.1.md |
| Related | - |

**Description:**

Auth audit log entries include datetime (when), event (what), and request_user_id (who), but 'where' metadata (source IP, request path) is not part of the serialized JSON message. Cross-referencing with request log is needed. Mitigated by structlog contextvars pipeline that may add request_id.

**Remediation:**

Include request context directly in auth log entries by adding request_id and optionally source_ip from context.

---

#### FINDING-024: Performance logger uses local time instead of UTC, with developer TODO acknowledging the issue

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.2.2 |
| Files | atr/log.py |
| Source Reports | 16.2.2.md |
| Related | - |

**Description:**

The performance logger's MicrosecondsFormatter uses Python's default time.localtime converter, producing timestamps in local timezone without explicit offset. Developer has acknowledged with a TODO comment.

**Remediation:**

Set the formatter's converter to time.gmtime to ensure UTC output.

---

#### FINDING-025: In-memory debug log buffer (BufferingHandler) is an undocumented log destination

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.2.3 |
| Files | atr/log.py |
| Source Reports | 16.2.3.md |
| Related | - |

**Description:**

The BufferingHandler captures all log messages into an in-memory buffer (100 entries) retrievable via get_recent_logs(). This constitutes an additional log destination not documented in the logging inventory.

**Remediation:**

Document the in-memory buffer in the logging inventory, including conditions for activation, retention, and access control.

---

#### FINDING-026: Authorization denial details not logged at point of decision in storage layer

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.3.2 |
| Files | atr/storage/__init__.py |
| Source Reports | 16.3.2.md |
| Related | - |

**Description:**

Authorization denial context (which committee/project, which user, what reason) is constructed as an error message in as_*_outcome() methods but not explicitly logged at the storage layer. The gap is about whether denial context (reason, target resource) reaches the audit trail reliably.

**Remediation:**

Add explicit authorization failure logging via log.auth_event('authorization_denied', ...) at decision points in Write.as_*_outcome() methods.

---

#### FINDING-027: General logging functions rely on structlog renderer configuration for injection protection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.4.1 |
| Files | atr/log.py, atr/loggers.py |
| Source Reports | 16.4.1.md |
| Related | - |

**Description:**

The general _event() logging function does not enforce JSON encoding; protection depends on renderer configuration. Security-critical logs (atr.auth, atr.storage.audit) use explicit json.dumps() and are unaffected. Project has active plan to migrate to t-strings (Python 3.14).

**Remediation:**

Ensure all persistent log handlers use JSONRenderer() for production deployments. Continue planned migration to t-strings.

---

#### FINDING-028: Internal state information in AccessError messages for 500-status errors

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.5.1 |
| Files | atr/storage/__init__.py |
| Source Reports | 16.5.1.md |
| Related | - |

**Description:**

AccessError messages with status=500 contain internal architecture details (e.g., 'No committee found for project - Invalid state', 'User service writes require an ASF UID'). Without confirmed error handler middleware sanitization, these may reach consumers.

**Remediation:**

Ensure 500-status AccessError messages use generic text suitable for external consumption, and log the detailed reason internally via log.error().

---

#### FINDING-029: Audit logging uses fire-and-forget pattern — logging failure does not halt operation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.5.3 |
| Files | atr/storage/__init__.py, atr/log.py, atr/loggers.py |
| Source Reports | 16.5.3.md |
| Related | - |

**Description:**

The audit() and _auth_log() functions use QueueHandler which returns immediately. There is no mechanism for calling code to detect that audit logging has failed. Security-critical operations could proceed without audit trail if log storage becomes unavailable.

**Remediation:**

Consider a synchronous write path for critical audit events or a health check that monitors queue depth.

---

#### FINDING-030: Vote Casting Endpoint Relies Only on Global Rate Limits

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-799 |
| ASVS sections | 2.4.1 |
| Files | atr/post/vote.py |
| Source Reports | 2.4.1.md |
| Related | - |

**Description:**

Vote casting endpoint (POST `/vote/<project_key>/<version_key>`) is not included in the sensitive endpoint rate limit tier (10/hr). It falls under global limits only (100/min, 1000/hr per user). An authenticated user could cast up to 100 votes per minute, each generating a receipt email to the project's mailing list. Over an hour, this produces up to 6000 emails.

**Remediation:**

Add a per-endpoint rate limit to the vote casting endpoint, consistent with other sensitive operations (e.g., 10-30/hr).

---

#### FINDING-031: Process-wide `os.chdir()` in RAT execution creates thread-safety risk under concurrent load

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | CWE-362 |
| ASVS sections | 15.2.2 |
| Files | atr/tasks/checks/rat.py |
| Source Reports | 15.2.2.md |
| Related | - |

**Description:**

The `_check_core_logic_execute_rat()` function uses `os.chdir(scan_root)` which modifies process-wide state, creating a race condition when multiple RAT tasks execute concurrently via the thread pool. Under concurrent task execution, RAT checks could execute in the wrong directory, producing incorrect results or failing. This affects availability (failed tasks requiring retry) and potentially integrity (wrong directory scanned). Does not enable RCE or privilege escalation.

**Remediation:**

Replace `os.chdir(scan_root)` + `subprocess.run(...)` with `subprocess.run(..., cwd=scan_root)` in `_check_core_logic_execute_rat()`. This is a one-line fix that eliminates the race condition. The correct pattern already exists in the codebase (`score_qs()` in `sbom.py` uses `cwd=str(full_path.parent)`).

---

#### FINDING-032: Admin session termination has potential delay via LDAP liveness check mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 7.4.5 |
| Files | atr/sessions.py, atr/server.py |
| Source Reports | 7.4.5.md |
| Related | - |

**Description:**

The `revoke_by_uid()` method provides immediate session termination capability for individual users. The LDAP-based path introduces a delay equal to `ACCOUNT_CHECK_INTERVAL` between admin action (disabling account) and session termination. Admin endpoints in blueprint files (not provided) likely expose this capability directly but cannot be verified from audited code.

**Remediation:**

Ensure an admin endpoint directly calls `Store.revoke_by_uid()` for immediate session termination without requiring LDAP account disable. Verify this exists in admin blueprint code.

### 3.5 Informational

#### FINDING-033: Authorization Cache TTL Documentation Discrepancy

| Attribute | Value |
|-----------|-------|
| Severity | ⚪ Info |
| ASVS Level(s) | L1, L2 |
| CWE | - |
| ASVS sections | 8.1.1, 8.4.1 |
| Files | atr/principal.py, atr/docs/authorization-security.md |
| Source Reports | 8.1.1.md, 8.4.1.md |
| Related | - |

**Description:**

The code implements a 600-second (10-minute) authorization cache TTL in atr/principal.py, while the developer documentation (authorization-security.md) states 300 seconds (5 minutes). This discrepancy means that after LDAP group membership or permission revocation, a user retains cached committee membership and permissions for up to 10 minutes rather than the documented 5 minutes. This affects both general authorization caching and multi-tenant authorization controls.

**Remediation:**

Update either the documentation to reflect 600 seconds or the code to use 300 seconds to eliminate the discrepancy. Consider whether 5 or 10 minutes is the appropriate TTL for the security requirements, then align both code and documentation to that value.

---

#### FINDING-034: Logging inventory documentation is incomplete regarding retention, access control, and full layer coverage

| Attribute | Value |
|-----------|-------|
| Severity | ⚪ Info |
| ASVS Level(s) | L2 |
| CWE | - |
| ASVS sections | 16.1.1 |
| Files | atr/docs/authentication-security.md, atr/log.py, atr/loggers.py, atr/storage/__init__.py |
| Source Reports | 16.1.1.md |
| Related | - |

**Description:**

The documentation does not consolidate into a single inventory specifying retention periods, access controls, full set of log destinations, or how logs are used.

**Remediation:**

Create a consolidated logging inventory document covering all log destinations, their formats, storage locations, retention periods, access controls, and intended consumers.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Authentication Mechanisms | PAT is a system-generated credential (not a user-chosen password); ASVS 6.2.x password field requirements do not apply to non-password credential inputs | Proper scoping of password requirements to user-chosen passwords only | — |
| Authentication Mechanisms | Anti-automation and rate limiting controls are documented and implemented | ASVS 6.1.1 and 6.3.1 both passed | — |
| Authentication Mechanisms | Multiple authentication pathways are documented with consistent security controls | ASVS 6.1.3 passed | — |
| Authentication Mechanisms | Default user accounts are not present or are disabled | ASVS 6.3.2 passed | — |
| Authentication Mechanisms | Project-scoped SSH keys with user binding | Workflow SSH keys are project-scoped and user-bound | atr/models/sql.py, atr/storage/writers/ssh.py |
| Authentication Mechanisms | SSH key revocation capability | SSH keys are revocable | atr/models/sql.py, atr/storage/writers/ssh.py |
| Authentication Mechanisms | Quarantine verification for uploads | Uploads go through quarantine verification | atr/storage/writers/ssh.py |
| Authentication Mechanisms | Authentication strength enforcement delegated to identity provider | Authentication strength enforcement (including MFA policy) is delegated to the ASF OAuth identity provider; ATR treats all authenticated sessions as equally trusted | — |
| Session Management | Session token verification performed on backend | ASVS 7.2.1 | atr/sessions.py |
| Session Management | Dynamic session tokens generated (not static API keys) | ASVS 7.2.2 | atr/sessions.py |
| Session Management | Reference tokens use CSPRNG with 128+ bits entropy | ASVS 7.2.3 | atr/sessions.py |
| Session Management | New session token generated on authentication | ASVS 7.2.4 | atr/sessions.py |
| Session Management | Inactivity timeout enforced (7 days) | ASVS 7.3.1 | atr/sessions.py |
| Session Management | Session invalidated on logout/expiration | ASVS 7.4.1 | atr/sessions.py |
| Session Management | All sessions terminated when account disabled/deleted | ASVS 7.4.2 | atr/sessions.py |
| Session Management | Option to terminate all sessions after authentication factor change | ASVS 7.4.3 | atr/sessions.py |
| Session Management | Visible logout functionality on authenticated pages | ASVS 7.4.4 | application UI |
| Session Management | Federated identity session management documented | ASVS 7.1.3 | documentation |
| Session Management | Federated session lifetime and re-authentication behavior documented | ASVS 7.6.1 | documentation |
| Session Management | Session creation requires user consent/explicit action | ASVS 7.6.2 | OAuth flow |
| Oauth Oidc Integration | HS256 signature verification cryptographically binds JWT to ATR as sole issuer, providing equivalent assurance to explicit iss+sub binding | Promoted from dropped finding ASVS-1033-LOW-001 | — |
| Authorization Access Control | Field-level access managed through Pydantic extra='forbid' and public data model as documented design policy | ASVS 8.1.2 verification - field-level restrictions enforced through schema validation | — |
| Authorization Access Control | Read operations serve only public data by design; authorization enforcement is not required at read permission level transitions | ASVS 8.2.1 verification - function-level access control aligned with public data architecture | — |
| Jwt Token Validation | JWT signature validation is performed using digital signatures | ASVS 9.1.1 passed - tokens are validated for integrity before accepting contents | — |
| Jwt Token Validation | Algorithm allowlist is enforced, 'None' algorithm is not permitted | ASVS 9.1.2 passed - only approved algorithms can be used for token creation and verification | — |
| Jwt Token Validation | Key material is sourced from trusted pre-configured sources | ASVS 9.1.3 passed - token issuer keys are validated against trusted sources, untrusted headers are not accepted | — |
| Jwt Token Validation | Token expiration (exp claim) is validated | ASVS 9.2.1 partial pass - exp and iat claims are required and validated | atr/jwtoken.py |
| Jwt Token Validation | Token type validation is performed | ASVS 9.2.2 passed - service validates tokens are correct type for intended purpose | — |
| Jwt Token Validation | Audience (aud) claim is validated against allowlist | ASVS 9.2.3 passed - service only accepts tokens intended for its use | — |
| Jwt Token Validation | Audience restriction prevents token reuse with unintended audiences | ASVS 9.2.4 passed - tokens contain proper audience restrictions | — |
| Input Validation Sanitization | SafeType character allowlists exclude format-string-dangerous characters ({, }, !, :) from all validated types used as format arguments | Promoted from dropped finding ASVS-1310-LOW-001 | — |
| Output Encoding Xss Prevention | Output encoding for HTTP responses, HTML documents, and XML documents is properly implemented with context-aware encoding | ASVS 1.2.1 passed - no findings related to improper output encoding in HTML/XML contexts | — |
| Output Encoding Xss Prevention | Output encoding and escaping is properly used when dynamically building JavaScript content and JSON | ASVS 1.2.3 passed - no findings related to JavaScript or JSON injection vulnerabilities | — |
| Http Security Headers | X-Content-Type-Options: nosniff set at frontend proxy layer as documented deployment architecture | source: Dropped finding ASVS-321-LOW-001 | — |
| File Upload Quarantine | File size limits enforced to prevent DoS | 5.2.1 marked as Pass | — |
| File Upload Quarantine | Compressed file validation against maximum uncompressed size and file count | 5.2.3 marked as Pass | — |
| File Upload Quarantine | Files stored securely and not executed as server-side code | 5.3.1 marked as Pass | — |
| File Upload Quarantine | File paths use internally generated or trusted data with proper validation | 5.3.2 marked as Pass | — |
| File Upload Quarantine | User-submitted filenames validated with proper Content-Disposition headers | 5.4.1 marked as Pass | — |
| File Upload Quarantine | File names properly encoded/sanitized in responses | 5.4.2 marked as Pass | — |
| File Upload Quarantine | Files from untrusted sources scanned by antivirus | 5.4.3 marked as Pass | — |
| Cryptographic Operations | Industry-validated cryptographic libraries used (cryptography.io, bcrypt, sequoia-pgp) | 11.2.1 Pass status | — |
| Cryptographic Operations | No insecure block modes (ECB) or weak padding schemes detected | 11.3.1 Pass status | — |
| Cryptographic Operations | Approved ciphers and modes used (AES-GCM) | 11.3.2 Pass status | — |
| Cryptographic Operations | Authenticated encryption properly implemented | 11.3.3 Pass status | — |
| Cryptographic Operations | Approved hash functions used (SHA-512, SHA3-256, BLAKE3) with no MD5 or SHA1 for security purposes | 11.4.1 Pass status | — |
| Cryptographic Operations | Password storage uses bcrypt with appropriate cost factor | 11.4.2 Pass status | — |
| Cryptographic Operations | Hash functions for signatures and integrity use collision-resistant algorithms with appropriate bit lengths | 11.4.3 Pass status | — |
| Cryptographic Operations | Key derivation functions properly configured with key stretching | 11.4.4 Pass status | — |
| Tls Transport Security | HTTPS URL validation in PubSubListener.start() method | The PubSubListener.start() method validates the URL uses HTTPS | — |
| Tls Transport Security | Dedicated secure SSL context utility function | Application has util.create_secure_ssl_context() that sets minimum_version = ssl.TLSVersion.TLSv1_2 | — |
| Tls Transport Security | Default certificate verification in aiohttp | aiohttp's default SSL context validates certificates via ssl.create_default_context() | atr/pubsub.py |
| Tls Transport Security | Deployment configuration within trusted boundary | Deployment configuration (including SVN URLs) is within the trusted boundary and managed by trusted operators | — |
| Secrets Management | Secrets file permissions validated at startup via _validate_secrets_permissions (0o400 enforcement) | Startup validation ensures secrets files have restrictive permissions (read-only for owner) | server.py |
| Secrets Management | Secret rotation lifecycle delegated to ASF Infrastructure operations | Operational process exists for secret rotation management | — |
| Deployment Configuration | Backend service credential lifecycle management delegated to ASF Infrastructure | Dropped finding ASVS-1321-LOW-001 | — |
| Deployment Configuration | Service account privilege scoping delegated to deployment environment and external services | Promoted from dropped finding ASVS-1322-INFO-001 | — |
| Sensitive Data Protection | Sensitive data classification documented | 14.1.1 marked as Pass | — |
| Sensitive Data Protection | Protection requirements documented for sensitive data | 14.1.2 marked as Pass | — |
| Sensitive Data Protection | Sensitive data not sent in URL or query strings | 14.2.1 marked as Pass | — |
| Sensitive Data Protection | Sensitive data not cached in server components | 14.2.2 marked as Pass | — |
| Sensitive Data Protection | Sensitive data not sent to untrusted parties | 14.2.3 marked as Pass | — |
| Sensitive Data Protection | Anti-caching headers set for sensitive data | 14.3.2 marked as Pass | — |
| Sensitive Data Protection | Browser storage does not contain sensitive data (except session tokens) | 14.3.3 marked as Pass | — |
| Audit Logging | Security-critical logs use explicit json.dumps() for injection protection | atr.auth and atr.storage.audit loggers explicitly use json.dumps() | atr/log.py, atr/storage/__init__.py |
| Audit Logging | Active plan to migrate to t-strings for improved security | Project has active plan to migrate to t-strings (Python 3.14) | — |
| Audit Logging | Log file permissions managed at deployment/infrastructure layer | Promoted from dropped finding ASVS-1642-LOW-001 | — |
| Audit Logging | Log transmission to separate system handled at infrastructure layer | Promoted from dropped finding ASVS-1643-LOW-001 | — |
| Business Logic Validation | Production safety check ensures sensitive configuration values (including test-mode bypasses) are not misconfigured when env == PRODUCTION | Promoted from dropped finding ASVS-232-LOW-001 | — |
| Svn Integration Security | Outbound connection allowlisting delegated to network/firewall layer in deployment environment | ASVS 13.2.4 - Application-layer allowlist not implemented; security control delegated to infrastructure layer | — |
| Svn Integration Security | Egress allowlisting delegated to network/firewall layer per deployment architecture | ASVS 13.2.5 - Web/application server allowlist not configured; security control delegated to infrastructure layer | — |
| Email Security | Comprehensive SMTP injection protection implemented in mail handling module | Multiple layers of protection: _reject_null_bytes() function prevents null byte injection, _split_address() function rejects CRLF characters, Address object construction validates email format, EmailMessage policy validation enforces RFC compliance | atr/mail.py |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | **Pass** |  |
| 1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | **Pass** |  |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Fail** | See FINDING-004 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Pass** |  |
| 1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | **Pass** |  |
| 1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | **N/A** |  |
| 1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | **N/A** |  |
| 1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | **Pass** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | **Pass** |  |
| 1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | **N/A** |  |
| 1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | **Pass** |  |
| 1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | **Pass** |  |
| 1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | **Pass** |  |
| 1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | **N/A** |  |
| 1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | **N/A** |  |
| 1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | **Pass** |  |
| 1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | **Pass** |  |
| 1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | **Pass** |  |
| 1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | **Pass** |  |
| 1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** |  |
| 1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | **Pass** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | **Pass** |  |
| 2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Pass** |  |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.2.3 | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| 2.3.2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | **Pass** |  |
| 2.3.3 | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | **Pass** |  |
| 2.3.4 | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | **Pass** |  |
| 2.4.1 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | **Partial** | See FINDING-030 |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Pass** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Pass** |  |
| 3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | **Pass** |  |
| 3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | **Pass** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **Pass** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | **Partial** | See FINDING-012 |
| 3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | **Pass** |  |
| 3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | **Pass** |  |
| 3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | **Pass** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Pass** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| 3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | **Pass** |  |
| 3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | **N/A** |  |
| 3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | **Pass** |  |
| 3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | **Pass** |  |
| 4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | **Pass** |  |
| 4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | **Pass** |  |
| 4.3.1 | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | **N/A** |  |
| 4.3.2 | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | **N/A** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| 4.4.2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | **N/A** |  |
| 4.4.3 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | **N/A** |  |
| 4.4.4 | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.1.1 | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | **Partial** | See FINDING-013 |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Pass** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Partial** | See FINDING-014 |
| 5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | **Pass** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** |  |
| 5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | **Pass** |  |
| 5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | **Pass** |  |
| 5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | **Pass** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** |  |
| 6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | **N/A** |  |
| 6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **N/A** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **N/A** |  |
| 6.2.9 | Verify that passwords of at least 64 characters are permitted. | **N/A** |  |
| 6.2.10 | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | **N/A** |  |
| 6.2.11 | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | **N/A** |  |
| 6.2.12 | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | **N/A** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.3.3 | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | **Partial** | See FINDING-001 |
| 6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Pass** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| 6.4.3 | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | **N/A** |  |
| 6.4.4 | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | **N/A** |  |
| 6.5.1 | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | **N/A** |  |
| 6.5.2 | Verify that, when being stored in the application's backend, lookup secrets with less than 112 bits of entropy (19 random alphanumeric characters or 34 random digits) are hashed with an approved password storage hashing algorithm that incorporates a 32-bit random salt. A standard hash function can be used if the secret has 112 bits of entropy or more. | **Pass** |  |
| 6.5.3 | Verify that lookup secrets, out-of-band authentication code, and time-based one-time password seeds, are generated using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG) to avoid predictable values. | **Pass** |  |
| 6.5.4 | Verify that lookup secrets and out-of-band authentication codes have a minimum of 20 bits of entropy (typically 4 random alphanumeric characters or 6 random digits is sufficient). | **Pass** |  |
| 6.5.5 | Verify that out-of-band authentication requests, codes, or tokens, as well as time-based one-time passwords (TOTPs) have a defined lifetime. Out of band requests must have a maximum lifetime of 10 minutes and for TOTP a maximum lifetime of 30 seconds. | **Partial** | See FINDING-006 |
| 6.6.1 | Verify that authentication mechanisms using the Public Switched Telephone Network (PSTN) to deliver One-time Passwords (OTPs) via phone or SMS are offered only when the phone number has previously been validated, alternate stronger methods (such as Time based One-time Passwords) are also offered, and the service provides information on their security risks to users. For L3 applications, phone and SMS must not be available as options. | **N/A** |  |
| 6.6.2 | Verify that out-of-band authentication requests, codes, or tokens are bound to the original authentication request for which they were generated and are not usable for a previous or subsequent one. | **Pass** |  |
| 6.6.3 | Verify that a code based out-of-band authentication mechanism is protected against brute force attacks by using rate limiting. Consider also using a code with at least 64 bits of entropy. | **Pass** |  |
| 6.8.1 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | **Pass** |  |
| 6.8.2 | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | **Pass** |  |
| 6.8.3 | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | **N/A** |  |
| 6.8.4 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | **N/A** |  |
| **V7: Session Management** | | | |
| 7.1.1 | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | **Partial** | See FINDING-007, FINDING-008 |
| 7.1.2 | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | **Partial** | See FINDING-009 |
| 7.1.3 | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | **Pass** |  |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **Pass** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.3.1 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | **Pass** |  |
| 7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | **Partial** | See FINDING-008 |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Pass** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Pass** |  |
| 7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | **Pass** |  |
| 7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | **Pass** |  |
| 7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | **Partial** | See FINDING-032 |
| 7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | **Fail** | See FINDING-002 |
| 7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | **Fail** | See FINDING-003 |
| 7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | **Pass** |  |
| 7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | **Pass** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** | See FINDING-033 |
| 8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** |  |
| 8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | **Pass** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| 8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | **Pass** | See FINDING-033 |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Partial** | See FINDING-011 |
| 9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | **Pass** |  |
| 9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | **Pass** |  |
| 9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | **Pass** |  |
| **V10: OAuth and OIDC** | | | |
| 10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | **Pass** |  |
| 10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | **Pass** |  |
| 10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | **Pass** |  |
| 10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | **Pass** |  |
| 10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | **Pass** |  |
| 10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | **Pass** |  |
| 10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | **Pass** |  |
| 10.3.4 | Verify that, if the resource server requires specific authentication strength, methods, or recentness, it verifies that the presented access token satisfies these constraints. For example, if present, using the OIDC 'acr', 'amr' and 'auth_time' claims respectively. | **Pass** |  |
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
| 10.5.1 | Verify that the client (as the relying party) mitigates ID Token replay attacks. For example, by ensuring that the 'nonce' claim in the ID Token matches the 'nonce' value sent in the authentication request to the OpenID Provider (in OAuth2 refereed to as the authorization request sent to the authorization server). | **Partial** | See FINDING-010 |
| 10.5.2 | Verify that the client uniquely identifies the user from ID Token claims, usually the 'sub' claim, which cannot be reassigned to other users (for the scope of an identity provider). | **Pass** |  |
| 10.5.3 | Verify that the client rejects attempts by a malicious authorization server to impersonate another authorization server through authorization server metadata. The client must reject authorization server metadata if the issuer URL in the authorization server metadata does not exactly match the pre-configured issuer URL expected by the client. | **Pass** |  |
| 10.5.4 | Verify that the client validates that the ID Token is intended to be used for that client (audience) by checking that the 'aud' claim from the token is equal to the 'client_id' value for the client. | **Pass** |  |
| 10.5.5 | Verify that, when using OIDC back-channel logout, the relying party mitigates denial of service through forced logout and cross-JWT confusion in the logout flow. The client must verify that the logout token is correctly typed with a value of 'logout+jwt', contains the 'event' claim with the correct member name, and does not contain a 'nonce' claim. Note that it is also recommended to have a short expiration (e.g., 2 minutes). | **N/A** |  |
| 10.6.1 | Verify that the OpenID Provider only allows values 'code', 'ciba', 'id_token', or 'id_token code' for response mode. Note that 'code' is preferred over 'id_token code' (the OIDC Hybrid flow), and 'token' (any Implicit flow) must not be used. | **N/A** |  |
| 10.6.2 | Verify that the OpenID Provider mitigates denial of service through forced logout. By obtaining explicit confirmation from the end-user or, if present, validating parameters in the logout request (initiated by the relying party), such as the 'id_token_hint'. | **N/A** |  |
| 10.7.1 | Verify that the authorization server ensures that the user consents to each authorization request. If the identity of the client cannot be assured, the authorization server must always explicitly prompt the user for consent. | **N/A** |  |
| 10.7.2 | Verify that when the authorization server prompts for user consent, it presents sufficient and clear information about what is being consented to. When applicable, this should include the nature of the requested authorizations (typically based on scope, resource server, Rich Authorization Requests (RAR) authorization details), the identity of the authorized application, and the lifetime of these authorizations. | **N/A** |  |
| 10.7.3 | Verify that the user can review, modify, and revoke consents which the user has granted through the authorization server. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.1.1 | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | **Partial** | See FINDING-015 |
| 11.1.2 | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | **Partial** | See FINDING-016 |
| 11.2.1 | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | **Pass** |  |
| 11.2.2 | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | **Partial** | See FINDING-017, FINDING-018 |
| 11.2.3 | Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security. | **Partial** | See FINDING-005 |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Pass** |  |
| 11.3.3 | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm. | **Pass** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| 11.4.2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | **Pass** |  |
| 11.4.3 | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | **Pass** |  |
| 11.4.4 | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | **Pass** |  |
| 11.5.1 | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | **Partial** | See FINDING-019 |
| 11.6.1 | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | **Partial** | See FINDING-005 |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Partial** | See FINDING-020 |
| 12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | **Pass** |  |
| 12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Pass** |  |
| 12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | **Pass** |  |
| 12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | **Partial** | See FINDING-020 |
| 12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | **Pass** |  |
| **V13: Configuration** | | | |
| 13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | **Pass** |  |
| 13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | **Pass** |  |
| 13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | **Pass** |  |
| 13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | **Pass** |  |
| 13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | **Pass** |  |
| 13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | **Pass** |  |
| 13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | **Pass** |  |
| 13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | **Pass** |  |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| 13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | **Pass** |  |
| 13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | **Pass** |  |
| 13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | **Pass** |  |
| 13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | **Pass** |  |
| 14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | **Pass** |  |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | **Pass** |  |
| 14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | **Pass** |  |
| 14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | **Partial** | See FINDING-021 |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Partial** | See FINDING-022 |
| 14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | **Pass** |  |
| 14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | **N/A** |  |
| 15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | **Pass** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | **Partial** | See FINDING-031 |
| 15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | **Pass** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |
| 15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | **Pass** |  |
| 15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | **Pass** |  |
| 15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | **N/A** |  |
| 15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | **Pass** |  |
| 15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | **N/A** |  |
| 15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | **Pass** |  |
| **V16: Security Logging and Error Handling** | | | |
| 16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | **Partial** | See FINDING-034 |
| 16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | **Partial** | See FINDING-023 |
| 16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | **Partial** | See FINDING-024 |
| 16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | **Partial** | See FINDING-025 |
| 16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | **Pass** |  |
| 16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | **Partial** | See FINDING-021 |
| 16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | **Pass** |  |
| 16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | **Partial** | See FINDING-026 |
| 16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | **Pass** |  |
| 16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | **Pass** |  |
| 16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | **Partial** | See FINDING-027 |
| 16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | **Partial** |  |
| 16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | **Partial** |  |
| 16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | **Partial** | See FINDING-028 |
| 16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | **Pass** |  |
| 16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | **Partial** | See FINDING-029 |
| **V17: WebRTC** | | | |
| 17.1.1 | Verify that the Traversal Using Relays around NAT (TURN) service only allows access to IP addresses that are not reserved for special purposes (e.g., internal networks, broadcast, loopback). Note that this applies to both IPv4 and IPv6 addresses. | **N/A** |  |
| 17.2.1 | Verify that the key for the Datagram Transport Layer Security (DTLS) certificate is managed and protected based on the documented policy for management of cryptographic keys. | **N/A** |  |
| 17.2.2 | Verify that the media server is configured to use and support approved Datagram Transport Layer Security (DTLS) cipher suites and a secure protection profile for the DTLS Extension for establishing keys for the Secure Real-time Transport Protocol (DTLS-SRTP). | **N/A** |  |
| 17.2.3 | Verify that Secure Real-time Transport Protocol (SRTP) authentication is checked at the media server to prevent Real-time Transport Protocol (RTP) injection attacks from leading to either a Denial of Service condition or audio or video media insertion into media streams. | **N/A** |  |
| 17.2.4 | Verify that the media server is able to continue processing incoming media traffic when encountering malformed Secure Real-time Transport Protocol (SRTP) packets. | **N/A** |  |
| 17.3.1 | Verify that the signaling server is able to continue processing legitimate incoming signaling messages during a flood attack. This should be achieved by implementing rate limiting at the signaling level. | **N/A** |  |
| 17.3.2 | Verify that the signaling server is able to continue processing legitimate signaling messages when encountering malformed signaling message that could cause a denial of service condition. This could include implementing input validation, safely handling integer overflows, preventing buffer overflows, and employing other robust error-handling techniques. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 155 requirements (61.3%)
- **Partial**: 34 requirements (13.4%)
- **N/A**: 61 requirements (24.1%)
- **Fail**: 3 requirements (1.2%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 6.3.3 | — | atr/models/sql.py, atr/blueprints/get.py, atr/blueprints/post.py, atr/blueprints/api_auth.py |
| FINDING-002 | Medium | 7.5.1 | — | atr/sessions.py |
| FINDING-003 | Medium | 7.5.2 | — | atr/sessions.py |
| FINDING-004 | Medium | 1.2.2 | — | atr/form.py |
| FINDING-005 | Medium | 11.2.3, 11.6.1 | — | atr/storage/writers/keys.py |
| FINDING-006 | Low | 6.5.5 | — | atr/models/sql.py, atr/storage/writers/ssh.py |
| FINDING-007 | Low | 7.1.1 | — | atr/sessions.py, atr/docs/asfquart-usage.md |
| FINDING-008 | Low | 7.1.1, 7.3.2 | — | atr/server.py, atr/sessions.py |
| FINDING-009 | Low | 7.1.2 | — | atr/sessions.py |
| FINDING-010 | Low | 10.5.1 | — | atr/models/github.py |
| FINDING-011 | Low | 9.2.1 | — | atr/jwtoken.py |
| FINDING-012 | Low | 3.4.3 | — | atr/server.py |
| FINDING-013 | Low | 5.1.1 | FINDING-016 | atr/detection.py, atr/archives.py |
| FINDING-014 | Low | 5.2.2 | — | atr/tasks/quarantine.py |
| FINDING-015 | Low | 11.1.1 | — | atr/storage/writers/keys.py |
| FINDING-016 | Low | 11.1.2 | FINDING-013 | atr/hashes.py, atr/noisy.py |
| FINDING-017 | Low | 11.2.2 | FINDING-018 | atr/hashes.py |
| FINDING-018 | Low | 11.2.2 | FINDING-017 | atr/noisy.py |
| FINDING-019 | Low | 11.5.1 | — | atr/docs/signing-artifacts.md |
| FINDING-020 | Low | 12.1.1, 12.3.2 | — | atr/pubsub.py |
| FINDING-021 | Low | 14.2.4, 16.2.5 | — | atr/log.py |
| FINDING-022 | Low | 14.3.1 | — | atr/sessions.py |
| FINDING-023 | Low | 16.2.1 | — | atr/log.py |
| FINDING-024 | Low | 16.2.2 | — | atr/log.py |
| FINDING-025 | Low | 16.2.3 | — | atr/log.py |
| FINDING-026 | Low | 16.3.2 | — | atr/storage/__init__.py |
| FINDING-027 | Low | 16.4.1 | — | atr/log.py, atr/loggers.py |
| FINDING-028 | Low | 16.5.1 | — | atr/storage/__init__.py |
| FINDING-029 | Low | 16.5.3 | — | atr/storage/__init__.py, atr/log.py, atr/loggers.py |
| FINDING-030 | Low | 2.4.1 | — | atr/post/vote.py |
| FINDING-031 | Low | 15.2.2 | — | atr/tasks/checks/rat.py |
| FINDING-032 | Low | 7.4.5 | — | atr/sessions.py, atr/server.py |
| FINDING-033 | Informational | 8.1.1, 8.4.1 | — | atr/principal.py, atr/docs/authorization-security.md |
| FINDING-034 | Informational | 16.1.1 | — | atr/docs/authentication-security.md, atr/log.py, atr/loggers.py, atr/storage/__init__.py |

**Total Unique Findings**: 34 (0 Critical, 0 High, 5 Medium, 27 Low, 2 Info)

*32 of 34 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 32 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L2

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 6 |
| L2 | 183 | 30 |

**Total consolidated findings: 34**

*End of Consolidated Security Audit Report*