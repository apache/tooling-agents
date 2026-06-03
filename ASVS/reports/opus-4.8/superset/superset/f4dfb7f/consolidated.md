# Security Audit Consolidated Report — apache/superset/superset

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset |
| ASVS Level | L3 |
| Severity Threshold | none (all findings included) |
| Commit | f4dfb7f |
| Date | Jun 03, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 345 |
| Total Findings | 26 |
| Actionable Issues | 12 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 12 actionable items.*

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0     |
| High     | 1     |
| Medium   | 4     |
| Low      | 7     |
| Info     | 14    |

### ASVS Level Coverage

This audit was conducted against ASVS Level 3 (L3), with scope extending up to L3 across all eighteen security domains, and no severity threshold applied so that all findings — including informational observations — are captured. Coverage spans authentication, authorization, cryptographic controls, input validation, session management, transport security, and audit logging, drawn from 345 source reports.

### Top 5 Risks

1. **Plaintext credentials/tokens persisted to Log.json** [High] — The records path bypasses curation, writing plaintext credentials and tokens to Log.json where they may be exposed (ASVS 16.2.5).
2. **Bypassable regex-based SVG sanitizer** [Medium] — The SVG sanitizer relies on regex and fails to strip `foreignObject` or entity-encoded script vectors, permitting stored XSS (ASVS 1.3.4).
3. **Parquet ZIP upload missing zip-bomb guard** [Medium] — The columnar (Parquet) ZIP upload path never invokes `check_is_safe_zip`, leaving it open to decompression-bomb denial of service (ASVS 2.2.1, 5.2.1, 5.2.3).
4. **Password change without current-password verification** [Medium] — Changing a password does not require re-verifying the current password, enabling account takeover via session hijack or CSRF (ASVS 6.2.3, 6.3.4).
5. **RLS fails open on virtual dataset SQL** [Medium] — Row-level security application on virtual dataset SQL fails open, logging a warning while the query proceeds unfiltered and leaking restricted rows (ASVS 16.3.4, 16.5.3).

### Positive Controls Observed

- **Input validation & sanitization** — Description and table content sanitized with `nh3`; canonical decoding performed once; output encoding applied as the final step; URL and JavaScript/JSON context-aware encoding; parameterized queries/ORM usage; regex metacharacter escaping and ReDoS protection; avoidance of dynamic code execution; mail-system injection protection; `SQLScript.has_unparseable_statement` fails closed.
- **Browser security headers** — Talisman-shipped CSP uses `object-src 'none'` and nonce-based `script-src` with `strict-dynamic`; HSTS/HTTPS enforcement delegated to the edge reverse proxy with operator-overridable knobs.
- **HTTP API security** — Extensions content endpoint is `@protect()`-gated; deployment proxy adds `X-Content-Type-Options: nosniff`; chunk content authored by trusted extension developers.
- **File upload & storage** — File extension/content-type validation; path construction from internally generated/validated data; decompression ignores user-provided path info (`check_is_safe_zip` in import flow); RFC 6266-compliant `Content-Disposition` handling.
- **Federated authentication** — Signed state JWT with 5-minute expiry; confidential client secret gates the token endpoint; single-use PKCE verifier.
- **Session & token authorization** — Short-lived, bounded-`exp` self-contained guest/embedded JWTs validated per request with algorithm/audience pinning; MCP JWT pins algorithm (rejects `none`) and correctly validates audience.
- **Cryptographic controls** — At-rest field encryption via `sqlalchemy_utils EncryptedType`; metastore cache fails toward safer JSON serializer and DB-add fails closed; credentials stored via `encrypted_field_factory` and masked with `PASSWORD_MASK`.
- **Transport security** — TLS used for all client-to-external HTTP connectivity with no insecure fallback (ASVS 12.2.1 Pass).
- **Infrastructure & secrets** — Pluggable field encryption via `SQLALCHEMY_ENCRYPTED_FIELD_TYPE_ADAPTER`; operator-managed signing-secret rotation; Swagger UI gated behind FAB authentication; admin-gated dataset import.
- **Audit logging** — Authentication-event logging delegated to Flask-AppBuilder; structured DB log path is JSON-safe.

---

## 3. Findings

### 3.2 High

#### FINDING-001: Plaintext credentials/tokens persisted to Log.json (curation bypassed on records path)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.2.5 |
| **Files** | superset/utils/log.py |
| **Source Reports** | 16.2.5.md |
| **Related** | - |

**Description:**

User request body/query string (may contain password, JWT/guest tokens, API keys) → collect_request_payload() ingests all form fields, query args, and JSON body → records = [payload] → DBEventLogger.log() → json.dumps(record) → persisted to Log.json in the metadata database. The allow-list redaction (curate_payload / curated_payload_params) is applied only to the curated_payload argument; the records path that DBEventLogger actually persists bypasses curation entirely, with no denylist/masking of credential or token fields. Concrete reachable sink: CurrentUserRestApi.update_me (PUT /api/v1/me/) logs the JSON body including password. This is in scope per the project's credential-masking requirement (admin_role_trusted.md / hardening_vs_vulnerability_classification.md): credential/secret material must be masked, and read/write masking asymmetry is a bug.

**Remediation:**

Apply redaction on the persisted path (make DBEventLogger store the curated/redacted payload, or scrub a denylist of sensitive keys in collect_request_payload() before records are built). Treat Log.json as a classified store and exclude credential/token fields by policy; audit and purge already-captured secrets.

---

### 3.3 Medium

#### FINDING-002: Regex-based SVG sanitizer is bypassable; does not strip foreignObject or entity-encoded script vectors

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.3.4 |
| **File(s)** | superset/utils/core.py, superset/themes/utils.py |
| **Source Report(s)** | 1.3.4.md |
| **Related Finding(s)** | None |

**Description:**

Theme token `brandSpinnerSvg` is routed through a denylist regex sanitizer (`sanitize_svg_content`) that fails to strip `foreignObject`, entity-encoded `javascript:` schemes, and SMIL animation handlers, then stored and rendered as the brand spinner in users' browsers. This is a stored-XSS vector against the browser (the frontend IS the enforcement boundary for XSS/output-encoding per frontend_backend_enforcement_boundary.md). Severity depends on whether a less-privileged role can persist theme tokens; the profile does not document theme-management role restrictions, so the defect remains in scope.

**Remediation:**

Replace regex sanitization with an allowlist SVG sanitizer (e.g., `nh3` with a curated SVG tag/attribute set and `url_schemes=set()`), excluding `script`, `foreignObject`, `use`/`image` with external refs, event/SMIL handlers, and dangerous schemes after entity decoding.

---

#### FINDING-003: Columnar (Parquet) ZIP upload path missing zip-bomb guard (check_is_safe_zip not invoked)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-409 |
| **ASVS Section(s)** | 2.2.1, 5.2.1, 5.2.3 |
| **File(s)** | superset/commands/database/uploaders/columnar_reader.py |
| **Source Report(s)** | 2.2.1.md, 5.2.1.md, 5.2.3.md |
| **Related Finding(s)** | None |

**Description:**

Data flow: Columnar ZIP upload → `ZipFile.namelist()`/`open().read()` reads each member fully → no check of `ZipInfo.file_size` (uncompressed size) and no cap on number of members before decompression → ZIP-bomb / decompression-amplification DoS. Attacker capability required: Authenticated user with columnar upload permission. Impact on success: Memory/CPU exhaustion DoS. A small uploaded ZIP can expand to gigabytes of decompressed Parquet data, and an archive with a very large number of members multiplies allocations. PoC: Upload a `columnar` ZIP whose single Parquet member compresses extremely well, or a ZIP containing thousands of small members; `_yield_files` reads each member's full uncompressed bytes into a `BytesIO` and `file_to_dataframe` concatenates them, driving peak memory far beyond the upload size limit. Note: the import flow already calls `check_is_safe_zip` before reading entries; the gap is specific to the columnar upload ZIP handler (both `/upload/` and `/upload_metadata/`).

**Remediation:**

Before reading members, sum `info.file_size` across `zip_file.infolist()`, enforce a maximum total uncompressed size and a maximum member count, then read. Reuse `superset.utils.core.check_is_safe_zip` here as the import flow does.

---

#### FINDING-004: Password Change Does Not Require Current Password Verification

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-620 |
| **ASVS Section(s)** | 6.2.3, 6.3.4 |
| **File(s)** | superset/views/users/api.py:150-185, superset/views/users/schemas.py:38-51 |
| **Source Report(s)** | 6.2.3.md, 6.3.4.md |
| **Related Finding(s)** | None |

**Description:**

The password change endpoint at `superset/views/users/api.py` in the `CurrentUserRestApi.update_me` method (lines 150-185) and validation schema in `superset/views/users/schemas.py` `CurrentUserPutSchema` (lines 38-51) does not require or verify the user's current password before accepting a password change. Data flow: `request.json["password"]` (attacker-controlled new password) → `CurrentUserPutSchema.load` (validates complexity only) → `setattr(g.user, "password", ...)` + `pre_update` (hash + persist) → missing control: no `current_password` field is required or verified against the stored hash. This is a Superset-specific endpoint that does not reuse FAB's password verification step. An attacker with temporary session access (hijacked/stolen session cookie, shared/unlocked workstation, or token leaked to logs/history) can permanently change the victim's password without knowing the current one, leading to account takeover persistence and lockout. PoC: `PUT /api/v1/me/` with `{"password": "NewControlledPassw0rd!"}` and victim session cookie returns 200 with no current-password challenge.

**Remediation:**

Add a `current_password` field to `CurrentUserPutSchema` and verify it against the stored password hash (e.g., using `security_manager.check_password`) in the `update_me` method before setting the new password. Reject the request if verification fails. Optionally, invalidate other active sessions upon successful password change to neutralize session-riding takeover attempts.

---

#### FINDING-005: RLS application fails open on virtual dataset SQL (logged warning, query proceeds unfiltered)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 16.3.4, 16.5.3 |
| **File(s)** | superset/models/helpers.py |
| **Source Report(s)** | 16.3.4.md, 16.5.3.md |
| **Related Finding(s)** | None |

**Description:**

Virtual dataset SQL → apply_rls throws (parse/dialect error) → exception caught and logged at WARNING → query continues to execute with from_sql unmodified, i.e. without the RLS predicates that failed to apply. The security-control failure is logged (satisfying 16.3.4 logging) but the control fails open rather than secure, producing a potential RLS bypass / data-exposure condition for an authenticated user able to trigger an apply_rls failure.

**Remediation:**

Fail closed: on RLS-application exception, log at ERROR with exc_info=True and abort the query (raise QueryObjectValidationError/SupersetSecurityException) rather than executing unfiltered SQL.

### 3.4 Low

#### FINDING-006: PKCE silently degrades to a non-PKCE token exchange when the code_verifier cannot be retrieved

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 10.1.2 |
| **File(s)** | superset/commands/database/oauth2.py:57-80 |
| **Source Report(s)** | 10.1.2.md |
| **Related Finding(s)** | - |

**Description:**

Location: superset/commands/database/oauth2.py, OAuth2StoreTokenCommand.run(), lines ~57–80. There is no assertion that a code_verifier was found before performing the token exchange; if the tab_id is malformed, the KV entry expired, or it was already consumed, the exchange proceeds with code_verifier=None, losing the PKCE binding for that single exchange. Confidential-client secret still gates the token endpoint, so no direct token theft. Recorded as a hardening/defense-in-depth gap in Superset's own OAuth2 client code (in scope, not delegated).

**Remediation:**

Fail closed when the dance started with PKCE but the verifier is missing. Record in the signed state whether PKCE was initiated, and reject the exchange if the flag is set but no verifier is recoverable: if self._state.get("pkce_initiated") and not code_verifier: raise OAuth2Error("PKCE code_verifier missing or expired; restart authorization.")

---

#### FINDING-007: OAuth2 state is bound to the initiating user (signed user_id) but not to the specific user-agent session

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 10.1.2 |
| **File(s)** | superset/utils/oauth2.py, superset/commands/database/oauth2.py |
| **Source Report(s)** | 10.1.2.md |
| **Related Finding(s)** | - |

**Description:**

Location: superset/utils/oauth2.py:encode_oauth2_state / decode_oauth2_state; consumed in superset/commands/database/oauth2.py:OAuth2StoreTokenCommand. The signed state is unguessable and short-lived (5 minutes) but binds to user_id, not to a per-session cookie-bound nonce. Exploitation requires possession of a still-valid signed state JWT plus a valid authorization code — a narrow, non-default condition. Strong residual controls (signed state, 5-min expiry, single-use verifier, confidential client) limit impact.

**Remediation:**

Add a session-bound, single-use binding to state — store a random nonce in the user's server-side session and include its hash in the signed state; on callback, require the decoded nonce to match the current session and consume it.

---

#### FINDING-008: nbf (not-before) claim not enforced; only exp validated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1, L2, L3 |
| **CWE** | - |
| **ASVS Section(s)** | 9.2.1 |
| **File(s)** | superset/mcp_service/jwt_verifier.py |
| **Source Report(s)** | 9.2.1.md |
| **Related Finding(s)** | - |

**Description:**

token claims → exp validated (required + not in past) → nbf (not-before) claim is never read or enforced. self.jwt.decode() returns claims but .validate() is not invoked, so authlib does not validate nbf automatically. A validly-signed token carrying a future nbf claim is accepted before its intended validity window. Impact is minor because tokens are short-lived and the issuer's documented claim set is iat/exp/aud/sub. This is an unconditional code gap not addressed by any profile section.

**Remediation:**

Enforce nbf symmetrically with exp (allowing small clock skew): check claims.get('nbf') against time.time() + LEEWAY_SECONDS, or call authlib's claims.validate(leeway=...) so nbf/exp are validated together.

---

#### FINDING-009: No explicit token-type / token_use claim validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | - |
| **ASVS Section(s)** | 9.2.2 |
| **File(s)** | superset/mcp_service/jwt_verifier.py |
| **Source Report(s)** | 9.2.2.md |
| **Related Finding(s)** | - |

**Description:**

token claims → audience and scope are validated, but no claim asserting the token is an access token (e.g., typ, token_use) is checked. The verifier relies on audience + scope to scope the token to the service/purpose. An attacker holding a different type of JWT (e.g., an ID token) issued by the same issuer and bearing a matching aud/scope set could cross-use it. Mitigated in practice by audience + scope validation; profile does not address token-type checks.

**Remediation:**

Where the issuer emits multiple token types, validate a type claim explicitly: if self.expected_token_use and claims.get('token_use') != self.expected_token_use: reject.

---

#### FINDING-010: Insecure default for GLOBAL_ASYNC_QUERIES_JWT_SECRET not caught by startup validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2, L3 |
| **CWE** | CWE-798 |
| **ASVS Section(s)** | 11.1.1, 11.6.1, 13.1.4, 13.3.1, 13.3.4 |
| **File(s)** | superset/config.py |
| **Source Report(s)** | 11.1.1.md, 11.6.1.md, 13.1.4.md, 13.3.1.md, 13.3.4.md |
| **Related Finding(s)** | FINDING-011 |

**Description:**

Hardcoded default string used as the HMAC signing key for async-events JWTs. Unlike SECRET_KEY and GUEST_TOKEN_JWT_SECRET (which use CHANGE_ME sentinels that startup validation detects), this key is a plausible-looking literal that CHANGE_ME detection does not catch, so the insecure default silently persists. With GLOBAL_ASYNC_QUERIES=True and the default secret, an attacker computes HS256(payload, "test-secret-change-me") for a victim channel and submits it as the async token to read other users' async query results (cross-user data disclosure). Exploit requires two non-default deployment preconditions: (a) GLOBAL_ASYNC_QUERIES feature flag enabled AND (b) operator leaving the literal default secret. The root cause is a Superset-side asymmetry where the CHANGE_ME sentinel guard is not extended to this secret.

**Remediation:**

Replace the literal default with a CHANGE_ME-style sentinel that startup validation rejects in production (mirroring SECRET_KEY). Extend startup validation to reject any async/guest JWT secret shorter than 32 bytes (256-bit entropy) when the corresponding feature is enabled. Require an explicit value when the feature is enabled (e.g., GLOBAL_ASYNC_QUERIES_JWT_SECRET = os.environ.get("SUPERSET_ASYNC_JWT_SECRET") or CHANGE_ME_SECRET_KEY).

---

#### FINDING-011: GUEST_TOKEN_JWT_SECRET lacks environment-variable sourcing parity and rotation documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-798 |
| **ASVS Section(s)** | 13.1.4 |
| **File(s)** | superset/config.py |
| **Source Report(s)** | 13.1.4.md |
| **Related Finding(s)** | FINDING-010 |

**Description:**

Critical signing secret for embedded guest tokens uses a CHANGE_ME placeholder requiring operator override but, unlike SECRET_KEY, lacks an environment-variable fallback path in this file, and no rotation schedule is associated. Exploitable only if EMBEDDED_SUPERSET is enabled and the placeholder is left unchanged (startup checks typically flag the sentinel).

**Remediation:**

Add env-var sourcing parity with SECRET_KEY, and include all signing secrets in a documented critical-secrets register with rotation cadence.

---

#### FINDING-012: Log injection via unsanitized CR/LF in flat Python-logging sink

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS Section(s)** | 16.4.1 |
| **File(s)** | superset/models/helpers.py |
| **Source Report(s)** | 16.4.1.md |
| **Related Finding(s)** | - |

**Description:**

User-controlled SQL text / schema names / imported object fields → passed as %s arguments to the Python logging module → rendered via flat LOG_FORMAT into console/file/forwarded logs with no CR/LF or control-character neutralization, so newline-bearing input can forge additional log lines. Authenticated user; impact is on log integrity / forensic reliability (the structured DB log path is already JSON-safe).

**Remediation:**

Neutralize control characters before logging user-controlled values (CR/LF escaping helper) or switch the affected sinks to a structured/JSON formatter.

### 3.5 Informational

#### FINDING-013: Report email href URL interpolated without HTML-attribute encoding/scheme validation

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 1.2.1 |
| **Files** | superset/reports/notifications/email.py |
| **Source Reports** | 1.2.1.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational per hardening_vs_vulnerability_classification.md downgrade rule: a real defect (report `url` interpolated into an HTML `href` attribute without attribute-encoding/scheme validation) but with no demonstrable attack scenario — the URL is internally derived and not attacker-reachable in the default deployment, so no concrete PoC exists. The `description` and table content are sanitized with `nh3`, but `self._content.url` is inserted into the `href` attribute without HTML-attribute encoding or scheme validation. Exploitation would require an upstream defect letting an attacker influence the stored report URL — not demonstrated.

**Remediation:**

Encode the URL for HTML-attribute context and validate the scheme before interpolation: `safe_url = escape(sanitize_url(self._content.url))` then use `href="{safe_url}"`.

---

#### FINDING-014: SQL dialect fallback can parse a statement under a different grammar than the executing engine

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-436 |
| **ASVS sections** | 1.5.3 |
| **Files** | superset/sql/parse.py |
| **Source Reports** | 1.5.3.md |
| **Related** | - |

**Description:**

Location: `superset/sql/parse.py`, `SQLStatement._parse` (the backtick → MySQL fallback block). Vulnerable code: `if (dialect is None or dialect == Dialects.DIALECT) and "`" in script:` triggers a fallback to MySQL dialect parser. Data flow: user-submitted SQL (engine="base"/unknown with backticks) → `SQLStatement._parse` selects a *different* grammar (MySQL) than the engine that will execute → table extraction / `is_mutating` / RLS application operate on the MySQL-parsed AST. The parser used for security decisions (table enumeration for access control, RLS predicate application) may differ from the actual execution grammar for the "Other"/base engine path. However: (a) it only triggers for the generic/unknown-engine path, (b) `SQLScript.has_unparseable_statement` fails closed (treats `exp.Command` and non-sqlglot statements as unparseable, forcing strict scoping), and (c) RLS-bypass-via-parser-divergence is explicitly the subject of the project's RLS testing guidance rather than a demonstrated exploit in this code. No concrete attacker scenario reaching meaningful impact is demonstrated in the audited configuration.

**Remediation:**

Where a database has no mapped sqlglot dialect, prefer failing closed (treat as unparseable for table-extraction/RLS purposes) rather than silently switching grammars; or record the fallback as a non-enforceable-scope marker so downstream access control fails closed. Example:
```python
if dialect is None and "`" in script:
    # Generic engine: do not silently adopt MySQL grammar for security analysis.
    raise SupersetParseError(script, engine,
        message="No dialect mapped; cannot reliably extract tables")
```

---

#### FINDING-015: Empty allowed_domains propagated to embedded postMessage origin policy means accept any origin

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 3.5.5 |
| **Files** | superset/embedded/view.py |
| **Source Reports** | 3.5.5.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational per project downgrade-to-Informational policy (hardening_vs_vulnerability_classification.md): real foot-gun but bounded/unclear impact and enforcement point is frontend code not in scope. Per-dashboard `allowed_domains` (DB) → bootstrap payload → frontend postMessage origin check. When `allowed_domains` is empty (default/unconfigured), documented semantics are "any domain is allowed," so the frontend postMessage handler would not constrain message origins. Impact is bounded because authoritative data access control is server-side guest-token validation, not postMessage. postMessage origin validation falls under the frontend-is-the-boundary exception, so the concern is in scope, but the end-to-end behavior cannot be demonstrated from this backend file set.

**Remediation:**

Treat an empty `allowed_domains` as "deny all" rather than "allow all" for postMessage origin validation, or require an explicit opt-in wildcard. At minimum surface a configuration warning when a dashboard is embeddable with no domain restriction, and verify the frontend `window.message` listener checks `event.origin` against `allowed_domains` and discards malformed messages.

---

#### FINDING-016: Content-Type header omits charset on text/* extension chunk responses

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 4.1.1 |
| **Files** | superset/extensions/api.py |
| **Source Reports** | 4.1.1.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational per hardening_vs_vulnerability_classification.md (real defect, no demonstrable attack scenario): `ExtensionsRestApi.content()` serves text-based assets (.js, .css) via `mimetypes.guess_type()` without a `charset` parameter, leaving character-set determination to the browser. The endpoint is @protect()-gated, chunk content is authored by trusted extension developers, and the deployment proxy adds `X-Content-Type-Options: nosniff`. No injection vector or concrete exploit was reproduced. Data flow: Extension chunk filename → mimetypes.guess_type() → Content-Type header. For text-based assets guess_type returns text/javascript / text/css with no charset parameter.

**Remediation:**

Append a charset for text types: after `send_file(...)`, if mimetype startswith 'text/' or in ('application/javascript','image/svg+xml'), set response.headers['Content-Type'] = f'{mimetype}; charset=utf-8'.

---

#### FINDING-017: No user notification after credential/profile updates (L3)

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 6.3.7 |
| **Files** | superset/views/users/api.py, superset/security/manager.py |
| **Source Reports** | 6.3.7.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational per hardening_vs_vulnerability_classification.md downgrade rule (real defect, no direct C/I/A bypass on its own — a detective-control gap). Credential and profile mutations (CurrentUserRestApi.update_me/pre_update, SupersetUserApi.post_update) are logged to the audit trail but the affected user is not notified after a password change (self-service or admin-initiated). PoC: PUT /api/v1/me/ with {"password":"..."} succeeds; the account owner receives no notification. CurrentUserPutSchema does not expose email/username updates, so no email/username-change notification path is required for the self-service endpoint specifically.

**Remediation:**

Send a confirmation notification to the account's email after any credential reset or username/email modification, building on the existing _log_audit_event hook points.

---

#### FINDING-018: Avatar endpoint response-code asymmetry allows numeric user-ID enumeration

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 6.3.8 |
| **Files** | superset/views/users/api.py |
| **Source Reports** | 6.3.8.md |
| **Related** | - |

**Description:**

Data flow: user_id path param → UserDAO.get_by_id (.one()) → 404 when no such user, 204/301 when the user exists. The differing status codes let an authenticated caller distinguish existing user IDs from non-existing ones. Attacker capability: authenticated user (@protect()); enumerates sequential integer user IDs, not usernames or emails. Impact: limited information disclosure (which numeric user IDs exist). Not an authentication challenge, so it does not directly satisfy the 6.3.8 attack model; rated Informational. PoC: authenticated GET /api/v1/user/1/avatar.png → 204/301; GET /api/v1/user/999999/avatar.png → 404.

**Remediation:**

Return a uniform response (e.g., 204 or a default avatar) for both "user not found" and "no avatar" cases so the existence of a user ID cannot be inferred from the status code.

---

#### FINDING-019: Single SECRET_KEY used for session signing, CSRF, and at-rest field encryption (incomplete key separation)

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-320 |
| **ASVS sections** | 11.1.1 |
| **Files** | superset/config.py |
| **Source Reports** | 11.1.1.md |
| **Related** | - |

**Description:**

A single SECRET_KEY is used as key material for (a) Flask session-cookie signing, (b) CSRF token signing, and (c) deriving the symmetric key for EncryptedType columns protecting DB passwords, OAuth tokens, and SSH tunnel credentials, violating key-separation/purpose-binding from NIST SP 800-57. This couples rotation of transient and long-lived secrets and enlarges blast radius if the key leaks. No direct single-step exploit is identified, but the finding describes a real key-separation defect.

**Remediation:**

Derive distinct sub-keys per purpose via an HKDF over SECRET_KEY (separate info contexts for session, field-encryption, csrf), or configure a dedicated encryption key for EncryptedType independent of the Flask session key. Document the key lifecycle and rotation procedure per NIST SP 800-57.

---

#### FINDING-020: Legacy MD5 retained in HASH_ALGORITHM_FALLBACKS for non-cryptographic UUID namespacing

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS sections** | 11.4.1 |
| **Files** | superset/config.py, superset/key_value/shared_entries.py |
| **Source Reports** | 11.4.1.md |
| **Related** | - |

**Description:**

config HASH_ALGORITHM_FALLBACKS -> get_fallback_algorithms() -> get_uuid_namespace_with_algorithm("", "md5") -> uuid3(namespace, key) for key-value lookup. MD5 only derives lookup UUIDs for cache/shared entries; no secret, signature, or integrity decision depends on MD5's collision resistance. A collision would at most cause a cache-key clash already constrained by value codec and resource scoping. No attacker capability is demonstrable: real code uses a weak digest but no cryptographic decision rides on it and secret material is CSPRNG-derived.

**Remediation:**

Once legacy MD5-namespaced entries are migrated, set HASH_ALGORITHM_FALLBACKS = [] to remove the legacy digest entirely.

---

#### FINDING-021: Timezone-naive expiration comparison can delay (or prematurely trigger) purge of cached temporary data

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 14.2.2 |
| **Files** | superset/key_value/models.py |
| **Source Reports** | 14.2.2.md |
| **Related** | - |

**Description:**

DOWNGRADED from Low to Informational per the project's documented downgrade rule (hardening_vs_vulnerability_classification.md): a real defect with no clear attack scenario is recorded as Informational. Location: superset/key_value/models.py, KeyValueEntry.is_expired(), lines 44-45. The comparison `self.expires_on <= datetime.now()` does not normalize timezones. datetime.now() returns a naive local timestamp; expires_on is a naive column whose semantics depend on how it was written. If entries are stored in UTC and the process runs in a non-UTC timezone, the retention boundary is shifted by the UTC offset — sensitive cached state can survive past its intended TTL (or be expired early), defeating the TTL-based retention control. Attacker capability required: None directly exploitable remotely; this is a correctness defect in a retention control. Impact depends on deployment timezone configuration. Impact: Cached temporary data (potentially containing filter/explore state) is retained beyond the documented retention window in non-UTC deployments — a confidentiality/retention weakness, not a direct disclosure to an attacker.

**Remediation:**

Normalize to timezone-aware UTC:
```python
from datetime import datetime, timezone

def is_expired(self) -> bool:
    if self.expires_on is None:
        return False
    expires = self.expires_on
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= datetime.now(timezone.utc)
```
Ensure all writers of expires_on persist UTC consistently, and standardize on timezone-aware UTC throughout the temporary-cache path.

---

#### FINDING-022: CSP allow-lists a third-party telemetry/analytics endpoint (Scarf) for image loads

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 14.2.3 |
| **Files** | superset/config.py |
| **Source Reports** | 14.2.3.md |
| **Related** | - |

**Description:**

Location: superset/config.py, TALISMAN_CONFIG["content_security_policy"]["img-src"]. The browser loads an image beacon from apachesuperset.gateway.scarf.sh, so the third party (Scarf) receives standard request metadata (client IP, User-Agent, and potentially a Referer that may include in-app URLs/IDs). No application sensitive payload (PII, tokens) is intentionally transmitted, but the allow-listing of a tracking endpoint means request metadata leaves the application's control by default. Attacker capability required: None — this is a privacy/data-egress observation, not an exploitable flaw. Impact: Standard request metadata (not application secrets) is observable by a third party unless operators remove the entry / disable telemetry.

**Remediation:**

Document the telemetry egress in the deployment/privacy guidance and provide/honor an opt-out (remove the Scarf entries from img-src and disable the beacon) for deployments with strict data-egress requirements. Ensure no in-app identifiers are leaked via Referer to this origin (set an appropriate Referrer-Policy at the edge).

---

#### FINDING-023: Unsynchronized process-global contribution-processor registry

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 15.4.1 |
| **Files** | superset/extensions/contributions.py |
| **Source Reports** | 15.4.1.md |
| **Related** | - |

**Description:**

Module-level singleton `_contribution_registry` exposes a shared mutable `list` (`_processors`) that is appended to by `register_processor` and iterated by `process_all_contributions` without synchronization. No attacker-reachable concurrent writer exists; registration occurs during single-threaded startup/extension-loading, so no security impact is demonstrable. Recorded as a real-defect-without-exploit-path per the project's downgrade-to-Informational policy.

**Remediation:**

If runtime/concurrent registration is ever introduced, guard mutation and iteration with a lock, or freeze the registry after startup (snapshot the list before iteration).

---

#### FINDING-024: Client source IP not captured in event logs

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.1 |
| **Files** | superset/utils/log.py |
| **Source Reports** | 16.2.1.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational: a real metadata-completeness defect (client IP / X-Forwarded-For is never captured) but with no attacker capability and no direct C/I/A impact, per the project's downgrade-to-Informational policy (hardening_vs_vulnerability_classification.md). Original: request context → collect_request_payload() captures path, form, args, plus user_id/referrer/duration_ms, but the source network identity (client IP) is never recorded, reducing event correlation during investigation.

**Remediation:**

Capture request.headers.get('X-Forwarded-For', request.remote_addr) in collect_request_payload() and add a dedicated indexed ip_address column to the Log model.

---

#### FINDING-025: Stored/emitted timestamps are naive local time without UTC or offset

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.2 |
| **Files** | superset/models/helpers.py, superset/config.py |
| **Source Reports** | 16.2.2.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational: a real correctness/consistency defect (audit/soft-delete columns and console LOG_FORMAT use naive local time, satisfying neither UTC nor explicit offset) but with no attacker capability and no direct C/I/A impact, per the project's downgrade-to-Informational policy (hardening_vs_vulnerability_classification.md). NTP/time-source sync is a deployment concern; the in-scope defect is the missing UTC/offset on stored and emitted timestamps.

**Remediation:**

Use DateTime(timezone=True) with a UTC default for created_on/changed_on/deleted_at, and set console formatter converter = time.gmtime with %z or ISO-8601 offset.

---

#### FINDING-026: Failed authorization attempts not emitted as discrete security events

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Info |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.3.2 |
| **Files** | superset/views/log/api.py |
| **Source Reports** | 16.3.2.md |
| **Related** | - |

**Description:**

DOWNGRADED to Informational: a real observability gap (denied user-activity-access attempts return 403 but are not written as a discrete failed-authorization security event) but the authorization control itself works correctly and there is no direct C/I/A impact; this is a defense-in-depth/observability completeness gap per the project's downgrade-to-Informational policy (hardening_vs_vulnerability_classification.md). FAB @protect()/@has_access plus the generic action log already partially capture the request.

**Remediation:**

Emit a structured security event (event_logger.log_with_context action='authorization_failure.user_activity_access') in the exception path before returning 403.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Input Validation And Sanitization | Sanitization of description and table content with nh3 | The description and table content are sanitized with nh3 | superset/reports/notifications/email.py |
| Input Validation And Sanitization | Canonical decoding performed correctly | Section 1.1.1 passed - input is decoded into canonical form only once before processing | — |
| Input Validation And Sanitization | Output encoding performed as final step | Section 1.1.2 passed - application performs output encoding and escaping appropriately | — |
| Input Validation And Sanitization | URL encoding for dynamic URLs | Section 1.2.2 passed - untrusted data is encoded according to context when building URLs | — |
| Input Validation And Sanitization | JavaScript/JSON output encoding | Section 1.2.3 passed - output encoding used when dynamically building JavaScript content | — |
| Input Validation And Sanitization | Parameterized database queries | Section 1.2.4 passed - application uses parameterized queries and ORMs to prevent injection | — |
| Input Validation And Sanitization | Regular expression metacharacter escaping | Section 1.2.9 passed - special characters in regular expressions are properly escaped | — |
| Input Validation And Sanitization | HTML sanitization for WYSIWYG content | Section 1.3.1 passed - untrusted HTML input is sanitized using secure library | — |
| Input Validation And Sanitization | Format string sanitization | Section 1.3.10 passed - format strings are sanitized before processing | — |
| Input Validation And Sanitization | Mail system injection protection | Section 1.3.11 passed - user input sanitized before passing to mail systems | — |
| Input Validation And Sanitization | ReDoS protection | Section 1.3.12 passed - regular expressions free from exponential backtracking elements | — |
| Input Validation And Sanitization | Dynamic code execution avoidance | Section 1.3.2 passed - application avoids eval() and similar dynamic code execution | — |
| Input Validation And Sanitization | Context-based input sanitization | Section 1.3.3 passed - data sanitized before passing to potentially dangerous contexts | — |
| Input Validation And Sanitization | SQLScript.has_unparseable_statement fails closed | treats exp.Command and non-sqlglot statements as unparseable, forcing strict scoping | superset/sql/parse.py |
| Browser Security Headers | CSP shipped via Talisman uses object-src 'none', nonce-based script-src with 'strict-dynamic'; CSP value is operator-overridable and production enforcement is delegated to the edge proxy. | source: Dropped finding ASVS-343-INFO-001 | — |
| Browser Security Headers | HSTS header emission and HTTPS enforcement delegated to deployment reverse proxy; TALISMAN_CONFIG knob exposed for operators; no hardcoded value blocks edge HSTS enforcement | Report 3.7.4 delegated-control determination | — |
| Http Api Security | Endpoint is @protect()-gated | ExtensionsRestApi.content() endpoint | superset/extensions/api.py |
| Http Api Security | Deployment proxy adds X-Content-Type-Options: nosniff | Security header applied at proxy layer | — |
| Http Api Security | Chunk content is authored by trusted extension developers | Extension content trust model | — |
| File Upload And Storage | File extension and content-type validation implemented for file uploads | 5.2.2 marked as Pass | — |
| File Upload And Storage | File path construction uses internally generated or validated data, preventing path traversal | 5.3.2 marked as Pass | — |
| File Upload And Storage | Server-side file processing ignores user-provided path information during decompression | 5.3.3 marked as Pass - check_is_safe_zip used in import flow | — |
| File Upload And Storage | User-submitted filenames validated and Content-Disposition header properly set for downloads | 5.4.1 marked as Pass | — |
| File Upload And Storage | Filenames in responses are properly encoded/sanitized following RFC 6266 | 5.4.2 marked as Pass | — |
| Password Authentication | Password composition policy is delegated to and configurable via FAB; the password field carries no artificial length/charset cap at the Superset layer. | Dropped finding ASVS-625-INFO-001 | — |
| Federated Authentication | Signed state JWT with 5-minute expiry | superset/utils/oauth2.py encode_oauth2_state / decode_oauth2_state | superset/utils/oauth2.py |
| Federated Authentication | Confidential client secret gates token endpoint | Referenced in ASVS-1012-LOW-001 description | superset/commands/database/oauth2.py |
| Federated Authentication | Single-use PKCE verifier | Referenced in ASVS-1012-LOW-002 description | superset/commands/database/oauth2.py |
| Session Management | Guest/embedded tokens are short-lived self-contained JWTs with mandatory bounded exp (configurable via GUEST_TOKEN_JWT_EXP_SECONDS), validated server-side on every request with algorithm/audience pinning — the documented compensating control for the absence of revocation | Dropped finding ASVS-741-LOW-001 from 7.4.1 audit | — |
| Token Based Authorization | Documented MCP deployment pins the JWT algorithm (HS256/RS256) and rejects 'none'; algorithm checked before key resolution and decode. | source: Dropped finding ASVS-912-LOW-001 | — |
| Token Based Authorization | MCP JWT audience validation is correctly implemented (handles scalar/list forms) and enforced when configured; documented deployment configures the MCP audience. | source: Dropped finding ASVS-923-LOW-001 | — |
| Token Based Authorization | MCP JWT audience validation is operator-enabled and correctly implemented; documented deployment configures the MCP audience to prevent cross-audience reuse. | source: Dropped finding ASVS-924-LOW-001 | — |
| Cryptographic Controls | At-rest field encryption uses the industry-validated sqlalchemy_utils EncryptedType; equality-leakage of the default deterministic engine is accepted as the metadata DB is within the operator trust boundary. | Dropped finding ASVS-1121-LOW-001 | — |
| Cryptographic Controls | Metastore cache fails toward safer serializer (JSON default, warns on Pickle) and DB-add fails closed on error. | Dropped finding ASVS-1125-LOW-001 | — |
| Cryptographic Controls | SSH/database credentials are stored via encrypted_field_factory columns and masked with PASSWORD_MASK on serialization; tamper-protection of ciphertext at rest is delegated to the operator-trusted metadata DB. | Dropped finding ASVS-1133-MED-001 | — |
| Tls And Transport Security | TLS is used for all connectivity between clients and external facing HTTP-based services without fallback to insecure communications | ASVS section 12.2.1 marked as Pass | — |
| Infrastructure And Secrets | Dataset import is admin-gated and the admin is a fully trusted principal; permissive import-URL default is a trusted-operator/operator-config concern, not a vulnerability. | Dropped finding ASVS-1311-LOW-001 | — |
| Infrastructure And Secrets | Connection-pool sizing and at-limit behavior are operator deployment-time decisions configurable via SQLALCHEMY_ENGINE_OPTIONS. | Dropped finding ASVS-1312-LOW-001 | — |
| Infrastructure And Secrets | SMTP/notification credentials are operator-owned deployment configuration; default placeholders are expected to be overridden by the operator. | Dropped finding ASVS-1321-LOW-001 | — |
| Infrastructure And Secrets | Service credentials for operator-configured external relays are deployment-owned; SMTP defaults are placeholders expected to be replaced. | Dropped finding ASVS-1323-LOW-001 | — |
| Infrastructure And Secrets | Dataset-import outbound fetching is gated to the trusted Admin principal; allowlist tightening is operator hardening, not a vulnerability. | Dropped finding ASVS-1324-MED-001 | — |
| Infrastructure And Secrets | SMTP credentials are operator-owned deployment placeholders, externalized by the operator at deploy time. | Dropped finding ASVS-1331-LOW-001 | — |
| Infrastructure And Secrets | In-process field encryption is pluggable via SQLALCHEMY_ENCRYPTED_FIELD_TYPE_ADAPTER; HSM/KMS isolation is a deployment-layer choice within the operator trust boundary. | Promoted from dropped finding ASVS-1333-LOW-001 | — |
| Infrastructure And Secrets | Signing-secret rotation is operator-managed via environment-injected values; in-app key-rollover is a hardening enhancement, not a vulnerability. | Dropped finding ASVS-1334-LOW-001 | — |
| Infrastructure And Secrets | Internal API documentation (Swagger/OpenAPI) is gated behind FAB authentication; production toggle FAB_API_SWAGGER_UI is operator-configurable. | Dropped finding ASVS-1345-LOW-001 | — |
| Infrastructure And Secrets | Blocking build-artifact/metadata paths in the served static tree is delegated to reverse-proxy hardening rules. | Dropped finding ASVS-1346-LOW-001 | — |
| Sensitive Data Protection | Functional retention is enforced at read time (is_expired() + Redis TTL) independent of physical row pruning; DB-row pruning is an operator deployment-config opt-in. | source: Dropped finding ASVS-1427-INFO-001 | — |
| Dependency And Build Security | Extension `.supx` discovery operates only on the admin/deployment-controlled extensions directory inside the trusted install boundary; filesystem check-then-use shapes are not vulnerabilities because an actor with write access there already controls extension content. | Dropped finding ASVS-1542-INFO-001 | — |
| Audit Logging And Monitoring | Authentication-event logging delegated to Flask-AppBuilder, which owns the login flow and associated event logging | source: Scope analysis 16.3.1 (flask_appbuilder_security_controls.md) | — |
| Audit Logging And Monitoring | Structured DB log path is JSON-safe | Mentioned in finding description as already implemented | — |
| Audit Logging And Monitoring | Secure log transmission / TLS to a logically separate SIEM is delegated to deployment configuration via pluggable EVENT_LOGGER / LOGGING_CONFIGURATOR hooks | Scope analysis 16.4.3 (deployment_infrastructure_delegated.md) | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | **Pass** |  |
| 1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | **Pass** |  |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Partial** | See FINDING-013 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Pass** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | **N/A** |  |
| 1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | **N/A** |  |
| 1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | **N/A** |  |
| 1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | **Pass** |  |
| 1.2.10 | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | **Pass** |  |
| 1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | **Fail** | See FINDING-002 |
| 1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | **Pass** |  |
| 1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | **N/A** |  |
| 1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | **Pass** |  |
| 1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | **N/A** |  |
| 1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | **N/A** |  |
| 1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | **Pass** |  |
| 1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | **Pass** |  |
| 1.3.12 | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | **Pass** |  |
| 1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | **N/A** |  |
| 1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | **N/A** |  |
| 1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | **N/A** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| 1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | **Pass** |  |
| 1.5.3 | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | **Pass** | See FINDING-014 |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | **N/A** |  |
| 2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Fail** | See FINDING-003 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.2.3 | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| 2.3.2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | **Pass** |  |
| 2.3.3 | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | **Pass** |  |
| 2.3.4 | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | **Pass** |  |
| 2.3.5 | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | **N/A** |  |
| 2.4.1 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | **Pass** |  |
| 2.4.2 | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | **Pass** |  |
| **V3: Web Frontend Security** | | | |
| 3.1.1 | Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access). | **Pass** |  |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Pass** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.2.3 | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | **N/A** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Pass** |  |
| 3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | **Pass** |  |
| 3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | **Pass** |  |
| 3.3.5 | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | **Pass** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **Pass** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | **Pass** |  |
| 3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | **Pass** |  |
| 3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | **Pass** |  |
| 3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | **Pass** |  |
| 3.4.7 | Verify that the Content-Security-Policy header field specifies a location to report violations. | **Pass** |  |
| 3.4.8 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | **Pass** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Partial** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| 3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | **N/A** |  |
| 3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | **Partial** | See FINDING-015 |
| 3.5.6 | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.7 | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.8 | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | **Pass** |  |
| 3.6.1 | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | **Pass** |  |
| 3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | **Pass** |  |
| 3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | **Pass** |  |
| 3.7.3 | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | **Pass** |  |
| 3.7.4 | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | **N/A** |  |
| 3.7.5 | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Partial** | See FINDING-016 |
| 4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | **N/A** |  |
| 4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | **N/A** |  |
| 4.1.4 | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | **Pass** |  |
| 4.1.5 | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | **N/A** |  |
| 4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | **N/A** |  |
| 4.2.2 | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | **N/A** |  |
| 4.2.3 | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | **N/A** |  |
| 4.2.4 | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | **N/A** |  |
| 4.2.5 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status. | **N/A** |  |
| 4.3.1 | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | **N/A** |  |
| 4.3.2 | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | **N/A** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| 4.4.2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | **N/A** |  |
| 4.4.3 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | **Pass** |  |
| 4.4.4 | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | **Pass** |  |
| **V5: File Handling** | | | |
| 5.1.1 | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | **N/A** |  |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Fail** | See FINDING-003 |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Pass** |  |
| 5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | **Fail** | See FINDING-003 |
| 5.2.4 | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | **N/A** |  |
| 5.2.5 | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | **N/A** |  |
| 5.2.6 | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** |  |
| 5.3.3 | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | **Pass** |  |
| 5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | **Pass** |  |
| 5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | **Pass** |  |
| 5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** |  |
| 6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | **N/A** |  |
| 6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | **N/A** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **Pass** |  |
| 6.2.2 | Verify that users can change their password. | **Pass** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **Fail** | See FINDING-004 |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
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
| 6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | **Partial** | See FINDING-004 |
| 6.3.5 | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | **Partial** |  |
| 6.3.6 | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | **Pass** |  |
| 6.3.7 | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | **Partial** | See FINDING-017 |
| 6.3.8 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | **Partial** | See FINDING-018 |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Pass** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| 6.4.3 | Verify that a secure process for resetting a forgotten password is implemented, that does not bypass any enabled multi-factor authentication mechanisms. | **N/A** |  |
| 6.4.4 | Verify that if a multi-factor authentication factor is lost, evidence of identity proofing is performed at the same level as during enrollment. | **N/A** |  |
| 6.4.5 | Verify that renewal instructions for authentication mechanisms which expire are sent with enough time to be carried out before the old authentication mechanism expires, configuring automated reminders if necessary. | **N/A** |  |
| 6.4.6 | Verify that administrative users can initiate the password reset process for the user, but that this does not allow them to change or choose the user's password. This prevents a situation where they know the user's password. | **N/A** |  |
| 6.5.1 | Verify that lookup secrets, out-of-band authentication requests or codes, and time-based one-time passwords (TOTPs) are only successfully usable once. | **N/A** |  |
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
| 6.8.1 | Verify that, if the application supports multiple identity providers (IdPs), the user's identity cannot be spoofed via another supported identity provider (eg. by using the same user identifier). The standard mitigation would be for the application to register and identify the user using a combination of the IdP ID (serving as a namespace) and the user's ID in the IdP. | **N/A** |  |
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
| 7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | **Pass** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Pass** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Pass** |  |
| 7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | **N/A** |  |
| 7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | **N/A** |  |
| 7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | **N/A** |  |
| 7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | **N/A** |  |
| 7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | **N/A** |  |
| 7.5.3 | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | **N/A** |  |
| 7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | **Pass** |  |
| 7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | **Pass** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | **Pass** |  |
| 8.1.3 | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | **N/A** |  |
| 8.1.4 | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | **N/A** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** |  |
| 8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | **Pass** |  |
| 8.2.4 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | **N/A** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| 8.3.2 | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | **Pass** |  |
| 8.3.3 | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | **Pass** |  |
| 8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | **Pass** |  |
| 8.4.2 | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | **N/A** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Partial** | See FINDING-008 |
| 9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | **Partial** | See FINDING-009 |
| 9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | **Pass** |  |
| 9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | **Pass** |  |
| **V10: OAuth and OIDC** | | | |
| 10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | **Pass** |  |
| 10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | **Partial** | See FINDING-006, FINDING-007 |
| 10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | **Pass** |  |
| 10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | **N/A** |  |
| 10.2.3 | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | **Pass** |  |
| 10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | **Pass** |  |
| 10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | **Pass** |  |
| 10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | **Pass** |  |
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
| 11.1.1 | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | **Partial** | See FINDING-010, FINDING-019 |
| 11.1.2 | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | **N/A** |  |
| 11.1.3 | Verify that cryptographic discovery mechanisms are employed to identify all instances of cryptography in the system, including encryption, hashing, and signing operations. | **N/A** |  |
| 11.1.4 | Verify that a cryptographic inventory is maintained. This must include a documented plan that outlines the migration path to new cryptographic standards, such as post-quantum cryptography, in order to react to future threats. | **N/A** |  |
| 11.2.1 | Verify that industry-validated implementations (including libraries and hardware-accelerated implementations) are used for cryptographic operations. | **Pass** |  |
| 11.2.2 | Verify that the application is designed with crypto agility such that random number, authenticated encryption, MAC, or hashing algorithms, key lengths, rounds, ciphers and modes can be reconfigured, upgraded, or swapped at any time, to protect against cryptographic breaks. Similarly, it must also be possible to replace keys and passwords and re-encrypt data. This will allow for seamless upgrades to post-quantum cryptography (PQC), once high-assurance implementations of approved PQC schemes or standards are widely available. | **Pass** |  |
| 11.2.3 | Verify that all cryptographic primitives utilize a minimum of 128-bits of security based on the algorithm, key size, and configuration. For example, a 256-bit ECC key provides roughly 128 bits of security where RSA requires a 3072-bit key to achieve 128 bits of security. | **Pass** |  |
| 11.2.4 | Verify that all cryptographic operations are constant-time, with no 'short-circuit' operations in comparisons, calculations, or returns, to avoid leaking information. | **Pass** |  |
| 11.2.5 | Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable vulnerabilities, such as Padding Oracle attacks. | **Pass** |  |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Pass** |  |
| 11.3.3 | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method or by combining an approved encryption method with an approved MAC algorithm. | **Pass** |  |
| 11.3.4 | Verify that nonces, initialization vectors, and other single-use numbers are not used for more than one encryption key and data-element pair. The method of generation must be appropriate for the algorithm being used. | **Pass** |  |
| 11.3.5 | Verify that any combination of an encryption algorithm and a MAC algorithm is operating in encrypt-then-MAC mode. | **Pass** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** | See FINDING-020 |
| 11.4.2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | **N/A** |  |
| 11.4.3 | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | **Pass** |  |
| 11.4.4 | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | **N/A** |  |
| 11.5.1 | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | **Pass** |  |
| 11.5.2 | Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand. | **Pass** |  |
| 11.6.1 | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | **Partial** | See FINDING-010 |
| 11.6.2 | Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks. | **N/A** |  |
| 11.7.1 | Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes. | **N/A** |  |
| 11.7.2 | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | **N/A** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | **N/A** |  |
| 12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | **N/A** |  |
| 12.1.4 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | **N/A** |  |
| 12.1.5 | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| 12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | **N/A** |  |
| 12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | **N/A** |  |
| 12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | **N/A** |  |
| 12.3.5 | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | **N/A** |  |
| 13.1.2 | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | **N/A** |  |
| 13.1.3 | Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | **Pass** |  |
| 13.1.4 | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | **Fail** | See FINDING-010, FINDING-011 |
| 13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | **N/A** |  |
| 13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | **Pass** |  |
| 13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | **N/A** |  |
| 13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | **N/A** |  |
| 13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | **Pass** |  |
| 13.2.6 | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | **Pass** |  |
| 13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | **Fail** | See FINDING-010 |
| 13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | **Pass** |  |
| 13.3.3 | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | **N/A** |  |
| 13.3.4 | Verify that secrets are configured to expire and be rotated based on the application's documentation. | **Fail** | See FINDING-010 |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| 13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | **Pass** |  |
| 13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | **Pass** |  |
| 13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | **Pass** |  |
| 13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | **N/A** |  |
| 13.4.6 | Verify that the application does not expose detailed version information of backend components. | **N/A** |  |
| 13.4.7 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | **N/A** |  |
| 14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | **N/A** |  |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **N/A** |  |
| 14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | **Partial** | See FINDING-021 |
| 14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | **Pass** | See FINDING-022 |
| 14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | **Pass** |  |
| 14.2.5 | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | **N/A** |  |
| 14.2.6 | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | **Pass** |  |
| 14.2.7 | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | **Pass** |  |
| 14.2.8 | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | **N/A** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| 14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | **Pass** |  |
| 14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | **N/A** |  |
| 15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | **N/A** |  |
| 15.1.4 | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | **N/A** |  |
| 15.1.5 | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | **Pass** |  |
| 15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | **Pass** |  |
| 15.2.4 | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | **N/A** |  |
| 15.2.5 | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | **Pass** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **N/A** |  |
| 15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | **N/A** |  |
| 15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | **N/A** |  |
| 15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | **N/A** |  |
| 15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | **Pass** |  |
| 15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | **N/A** |  |
| 15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | **N/A** |  |
| 15.4.1 | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | **Pass** | See FINDING-023 |
| 15.4.2 | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it. | **N/A** |  |
| 15.4.3 | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | **N/A** |  |
| 15.4.4 | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | **N/A** |  |
| **V16: Security Logging and Error Handling** | | | |
| 16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | **N/A** |  |
| 16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | **Partial** | See FINDING-024 |
| 16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | **Partial** | See FINDING-025 |
| 16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | **Pass** |  |
| 16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | **Pass** |  |
| 16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | **Fail** | See FINDING-001 |
| 16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | **N/A** |  |
| 16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | **Partial** | See FINDING-026 |
| 16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | **Partial** |  |
| 16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | **Fail** | See FINDING-005 |
| 16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | **Partial** | See FINDING-012 |
| 16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | **Pass** |  |
| 16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | **Pass** |  |
| 16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | **Pass** |  |
| 16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | **Pass** |  |
| 16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | **Fail** | See FINDING-005 |
| 16.5.4 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | **N/A** |  |
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
- **Pass**: 140 requirements (40.6%)
- **Partial**: 19 requirements (5.5%)
- **N/A**: 175 requirements (50.7%)
- **Fail**: 11 requirements (3.2%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | High | 16.2.5 | — | superset/utils/log.py |
| FINDING-002 | Medium | 1.3.4 | — | superset/utils/core.py, superset/themes/utils.py |
| FINDING-003 | Medium | 2.2.1, 5.2.1, 5.2.3 | — | superset/commands/database/uploaders/columnar_reader.py |
| FINDING-004 | Medium | 6.2.3, 6.3.4 | — | superset/views/users/api.py, superset/views/users/schemas.py |
| FINDING-005 | Medium | 16.3.4, 16.5.3 | — | superset/models/helpers.py |
| FINDING-006 | Low | 10.1.2 | — | superset/commands/database/oauth2.py |
| FINDING-007 | Low | 10.1.2 | — | superset/utils/oauth2.py, superset/commands/database/oauth2.py |
| FINDING-008 | Low | 9.2.1 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-009 | Low | 9.2.2 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-010 | Low | 11.1.1, 11.6.1, 13.1.4, 13.3.1, 13.3.4 | FINDING-011 | superset/config.py |
| FINDING-011 | Low | 13.1.4 | FINDING-010 | superset/config.py |
| FINDING-012 | Low | 16.4.1 | — | superset/models/helpers.py |
| FINDING-013 | Informational | 1.2.1 | — | superset/reports/notifications/email.py |
| FINDING-014 | Informational | 1.5.3 | — | superset/sql/parse.py |
| FINDING-015 | Informational | 3.5.5 | — | superset/embedded/view.py |
| FINDING-016 | Informational | 4.1.1 | — | superset/extensions/api.py |
| FINDING-017 | Informational | 6.3.7 | — | superset/views/users/api.py, superset/security/manager.py |
| FINDING-018 | Informational | 6.3.8 | — | superset/views/users/api.py |
| FINDING-019 | Informational | 11.1.1 | — | superset/config.py |
| FINDING-020 | Informational | 11.4.1 | — | superset/config.py, superset/key_value/shared_entries.py |
| FINDING-021 | Informational | 14.2.2 | — | superset/key_value/models.py |
| FINDING-022 | Informational | 14.2.3 | — | superset/config.py |
| FINDING-023 | Informational | 15.4.1 | — | superset/extensions/contributions.py |
| FINDING-024 | Informational | 16.2.1 | — | superset/utils/log.py |
| FINDING-025 | Informational | 16.2.2 | — | superset/models/helpers.py, superset/config.py |
| FINDING-026 | Informational | 16.3.2 | — | superset/views/log/api.py |

**Total Unique Findings**: 26 (0 Critical, 1 High, 4 Medium, 7 Low, 14 Info)

*12 of 26 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 12 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 6 |
| L2 | 183 | 18 |
| L3 | 92 | 8 |

**Total consolidated findings: 26**

*End of Consolidated Security Audit Report*