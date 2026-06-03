# Security Issues

*12 actionable finding(s). 14 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Plaintext credentials/tokens persisted to Log.json (curation bypassed on records path)
**Labels:** bug, security, priority:high
**Description:**
### Summary
User credentials, passwords, JWT tokens, and API keys submitted in request bodies or query strings are persisted in plaintext to `Log.json` in the metadata database, bypassing the intended redaction mechanisms. This violates the project's credential-masking requirements.

### Details
**Data Flow:**
1. User request body/query string (may contain password, JWT/guest tokens, API keys)
2. `collect_request_payload()` ingests all form fields, query args, and JSON body
3. `records = [payload]` → `DBEventLogger.log()` → `json.dumps(record)`
4. Persisted to `Log.json` in metadata database

**Root Cause:**
The allow-list redaction (`curate_payload` / `curated_payload_params`) is applied only to the `curated_payload` argument. The `records` path that `DBEventLogger` actually persists bypasses curation entirely, with no denylist/masking of credential or token fields.

**Concrete Example:**
`CurrentUserRestApi.update_me` (PUT `/api/v1/me/`) logs the JSON body including the `password` field in plaintext.

**Scope Justification:**
This is in scope per the project's credential-masking requirement (admin_role_trusted.md / hardening_vs_vulnerability_classification.md): credential/secret material must be masked, and read/write masking asymmetry is a bug.

### Remediation
1. Apply redaction on the persisted path: make `DBEventLogger` store the curated/redacted payload
2. Alternatively, scrub a denylist of sensitive keys in `collect_request_payload()` before records are built
3. Treat `Log.json` as a classified store and exclude credential/token fields by policy
4. Audit and purge already-captured secrets from existing logs

### Acceptance Criteria
- [ ] Credential fields (password, token, api_key, etc.) are redacted before persistence to `Log.json`
- [ ] Test added verifying sensitive fields are masked in logged records
- [ ] Existing `Log.json` entries audited and purged of captured secrets
- [ ] Documentation updated to reflect logging security controls

### References
- **Affected File:** `superset/utils/log.py`
- **CWE:** N/A
- **ASVS:** 16.2.5 (L2)
- **Source Report:** 16.2.5.md

### Priority
**High** - Credentials are actively being logged in plaintext, creating immediate exposure risk.

---
## Issue: FINDING-002 - Regex-based SVG sanitizer is bypassable; does not strip foreignObject or entity-encoded script vectors
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The theme token `brandSpinnerSvg` uses a regex-based sanitizer (`sanitize_svg_content`) that can be bypassed using `foreignObject` elements, entity-encoded `javascript:` schemes, and SMIL animation handlers, creating a stored XSS vulnerability.

### Details
**Attack Vector:**
1. Theme token `brandSpinnerSvg` is sanitized using denylist regex
2. Sanitizer fails to strip:
   - `foreignObject` elements
   - Entity-encoded `javascript:` schemes
   - SMIL animation handlers
3. Malicious SVG is stored and rendered as brand spinner in users' browsers

**Security Boundary:**
Per `frontend_backend_enforcement_boundary.md`, the frontend IS the enforcement boundary for XSS/output-encoding, making this a stored-XSS vector against the browser.

**Severity Justification:**
Rated Medium because the profile does not document theme-management role restrictions. If less-privileged roles can persist theme tokens, this becomes a high-severity stored XSS vulnerability.

### Remediation
Replace regex sanitization with an allowlist SVG sanitizer:
1. Use a library like `nh3` with a curated SVG tag/attribute set
2. Configure with `url_schemes=set()` to block all URL schemes
3. Exclude dangerous elements: `script`, `foreignObject`, `use`/`image` with external refs
4. Block event handlers and SMIL animation attributes
5. Perform entity decoding before validation to prevent encoding bypasses

### Acceptance Criteria
- [ ] Allowlist-based SVG sanitizer implemented
- [ ] Test suite includes bypass attempts (foreignObject, entity-encoded handlers, SMIL)
- [ ] Existing theme tokens re-validated through new sanitizer
- [ ] Documentation updated with safe SVG usage guidelines

### References
- **Affected Files:** 
  - `superset/utils/core.py`
  - `superset/themes/utils.py`
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.3.4 (L2)
- **Source Report:** 1.3.4.md

### Priority
**Medium** - Stored XSS vulnerability with unclear role-based exposure scope.

---
## Issue: FINDING-003 - Columnar (Parquet) ZIP upload path missing zip-bomb guard (check_is_safe_zip not invoked)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The columnar (Parquet) ZIP upload endpoints do not validate uncompressed size or member count before decompression, allowing authenticated users to trigger memory/CPU exhaustion via zip-bomb attacks.

### Details
**Data Flow:**
1. Columnar ZIP upload → `ZipFile.namelist()`/`open().read()`
2. Each member is read fully into memory without checking `ZipInfo.file_size`
3. No cap on number of members before decompression
4. `_yield_files` reads full uncompressed bytes into `BytesIO`
5. `file_to_dataframe` concatenates all members

**Attack Scenario:**
- **Attacker Capability:** Authenticated user with columnar upload permission
- **Attack Vector:** Upload ZIP with single highly-compressible Parquet member, or ZIP with thousands of small members
- **Impact:** Memory/CPU exhaustion DoS; small uploaded ZIP expands to gigabytes

**PoC:**
Upload a `columnar` ZIP whose single Parquet member compresses extremely well. Peak memory usage far exceeds upload size limit.

**Gap Context:**
The import flow already calls `check_is_safe_zip` before reading entries. This gap is specific to the columnar upload ZIP handler (both `/upload/` and `/upload_metadata/`).

### Remediation
1. Before reading members, sum `info.file_size` across `zip_file.infolist()`
2. Enforce maximum total uncompressed size (e.g., 10x compressed size)
3. Enforce maximum member count (e.g., 1000 files)
4. Reuse `superset.utils.core.check_is_safe_zip` as the import flow does

**Implementation:**
```python
from superset.utils.core import check_is_safe_zip

# Before processing
check_is_safe_zip(zip_file)
```

### Acceptance Criteria
- [ ] `check_is_safe_zip` invoked before columnar ZIP decompression
- [ ] Test added with zip-bomb attempt (high compression ratio)
- [ ] Test added with excessive member count
- [ ] Both upload endpoints protected (`/upload/` and `/upload_metadata/`)

### References
- **Affected File:** `superset/commands/database/uploaders/columnar_reader.py`
- **CWE:** CWE-409 (Improper Handling of Highly Compressed Data)
- **ASVS:** 2.2.1 (L1), 5.2.1 (L2), 5.2.3 (L2)
- **Source Reports:** 2.2.1.md, 5.2.1.md, 5.2.3.md

### Priority
**Medium** - Requires authentication but enables easy DoS with small payload.

---
## Issue: FINDING-004 - Password Change Does Not Require Current Password Verification
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The password change endpoint (`PUT /api/v1/me/`) allows users to change their password without verifying the current password, enabling account takeover persistence from temporary session access.

### Details
**Data Flow:**
1. `request.json["password"]` (attacker-controlled new password)
2. `CurrentUserPutSchema.load` validates complexity only
3. `setattr(g.user, "password", ...)` + `pre_update` (hash + persist)
4. **Missing Control:** No `current_password` field required or verified

**Attack Scenario:**
An attacker with temporary session access can permanently change the victim's password:
- **Access Vectors:** Hijacked/stolen session cookie, shared/unlocked workstation, token leaked to logs/history
- **Impact:** Account takeover persistence and victim lockout
- **PoC:** `PUT /api/v1/me/` with `{"password": "NewControlledPassw0rd!"}` returns 200 with no current-password challenge

**Context:**
This is a Superset-specific endpoint that does not reuse FAB's password verification step.

### Remediation
1. Add `current_password` field to `CurrentUserPutSchema` (required when changing password)
2. In `update_me` method, verify current password against stored hash using `security_manager.check_password`
3. Reject request if verification fails
4. **Optional Enhancement:** Invalidate other active sessions upon successful password change

**Implementation Example:**
```python
# In CurrentUserPutSchema
current_password = fields.String(required=True, load_only=True)

# In update_me method
if "password" in request.json:
    if not security_manager.check_password(
        request.json["current_password"], 
        g.user.password
    ):
        raise SupersetSecurityException("Current password is incorrect")
```

### Acceptance Criteria
- [ ] `current_password` field added and enforced
- [ ] Password verification implemented before change
- [ ] Test added: password change rejected with wrong current password
- [ ] Test added: password change succeeds with correct current password
- [ ] Consider session invalidation on password change

### References
- **Affected Files:**
  - `superset/views/users/api.py` (lines 150-185)
  - `superset/views/users/schemas.py` (lines 38-51)
- **CWE:** CWE-620 (Unverified Password Change)
- **ASVS:** 6.2.3 (L1), 6.3.4 (L2)
- **Source Reports:** 6.2.3.md, 6.3.4.md

### Priority
**Medium** - Requires initial session access but enables persistent account takeover.

---
## Issue: FINDING-005 - RLS application fails open on virtual dataset SQL (logged warning, query proceeds unfiltered)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When Row-Level Security (RLS) application fails on virtual dataset SQL due to parsing or dialect errors, the system logs a warning but proceeds to execute the query without RLS filters, potentially exposing unauthorized data.

### Details
**Data Flow:**
1. Virtual dataset SQL → `apply_rls` throws exception (parse/dialect error)
2. Exception caught and logged at WARNING level
3. Query continues to execute with `from_sql` unmodified
4. **Result:** Query executes without RLS predicates

**Security Impact:**
- The security-control failure is logged (satisfying 16.3.4 logging requirement)
- **However:** Control fails open rather than secure
- Authenticated user can potentially trigger `apply_rls` failure to bypass RLS
- Impact: Data exposure beyond user's authorized scope

**Current Behavior:**
```python
try:
    apply_rls(sql)
except Exception as e:
    logger.warning("RLS application failed: %s", e)
    # Query proceeds unfiltered!
```

### Remediation
**Fail Closed:** On RLS-application exception, abort the query rather than executing unfiltered SQL.

**Implementation:**
1. Log at ERROR level with `exc_info=True` for debugging
2. Raise `QueryObjectValidationError` or `SupersetSecurityException`
3. Return clear error message to user about RLS enforcement failure

```python
try:
    apply_rls(sql)
except Exception as e:
    logger.error("RLS application failed - aborting query", exc_info=True)
    raise SupersetSecurityException(
        "Unable to apply row-level security filters. Query aborted."
    )
```

### Acceptance Criteria
- [ ] RLS application failures abort query execution
- [ ] Error logged at ERROR level with full context
- [ ] Test added: RLS parse error prevents query execution
- [ ] Test added: RLS dialect error prevents query execution
- [ ] User receives clear error message (no data exposure)

### References
- **Affected File:** `superset/models/helpers.py`
- **CWE:** N/A
- **ASVS:** 16.3.4 (L2), 16.5.3 (L2)
- **Source Reports:** 16.3.4.md, 16.5.3.md

### Priority
**Medium** - Potential RLS bypass requiring specific error conditions, but impacts data authorization.

---
## Issue: FINDING-006 - PKCE silently degrades to a non-PKCE token exchange when the code_verifier cannot be retrieved
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth2 token exchange silently proceeds without PKCE protection when the `code_verifier` cannot be retrieved from storage, degrading the security of the authorization flow.

### Details
**Location:** `superset/commands/database/oauth2.py`, `OAuth2StoreTokenCommand.run()`, lines ~57–80

**Issue:**
- No assertion that `code_verifier` was found before performing token exchange
- If `tab_id` is malformed, KV entry expired, or already consumed, exchange proceeds with `code_verifier=None`
- Loses PKCE binding for that single exchange

**Mitigation:**
Confidential-client secret still gates the token endpoint, so no direct token theft is possible. However, this represents a defense-in-depth gap.

**Context:**
This is in Superset's own OAuth2 client code (in scope, not delegated to external library).

### Remediation
**Fail Closed:** Reject the token exchange when PKCE was initiated but the verifier is missing.

**Implementation:**
1. Record in the signed state whether PKCE was initiated
2. On callback, verify verifier is available if PKCE was started
3. Reject exchange if flag is set but verifier is missing

```python
if self._state.get("pkce_initiated") and not code_verifier:
    raise OAuth2Error(
        "PKCE code_verifier missing or expired; restart authorization."
    )
```

### Acceptance Criteria
- [ ] PKCE initiation flag added to signed state
- [ ] Token exchange aborted when verifier missing but PKCE initiated
- [ ] Test added: exchange fails with missing verifier
- [ ] Test added: exchange succeeds with valid verifier
- [ ] Clear error message guides user to restart authorization

### References
- **Affected File:** `superset/commands/database/oauth2.py` (lines 57-80)
- **CWE:** N/A
- **ASVS:** 10.1.2 (L2)
- **Source Report:** 10.1.2.md

### Priority
**Low** - Defense-in-depth hardening; confidential client secret provides baseline protection.

---
## Issue: FINDING-007 - OAuth2 state is bound to the initiating user (signed user_id) but not to the specific user-agent session
**Labels:** bug, security, priority:low
**Description:**
### Summary
The OAuth2 state parameter is signed and bound to `user_id` but not to a specific session, creating a narrow window for state token reuse across sessions belonging to the same user.

### Details
**Location:** 
- `superset/utils/oauth2.py`: `encode_oauth2_state` / `decode_oauth2_state`
- `superset/commands/database/oauth2.py`: `OAuth2StoreTokenCommand`

**Current Binding:**
- State is signed (unguessable)
- Short-lived (5 minutes)
- Bound to `user_id`
- **Not bound to:** Specific session cookie/nonce

**Exploitation Requirements:**
1. Attacker possesses a still-valid signed state JWT
2. Attacker possesses a valid authorization code
3. Both conditions must be met within 5-minute window

**Residual Controls:**
- Signed state (unguessable without key)
- 5-minute expiry
- Single-use verifier (PKCE)
- Confidential client secret

**Risk Assessment:**
Narrow, non-default condition with strong residual controls limiting impact.

### Remediation
Add session-bound, single-use binding to state:

1. Store a random nonce in user's server-side session
2. Include nonce hash in signed state
3. On callback, verify decoded nonce matches current session
4. Consume nonce after successful validation

**Implementation:**
```python
# In encode_oauth2_state
session_nonce = secrets.token_urlsafe(32)
session["oauth2_nonce"] = session_nonce
state_payload["nonce_hash"] = hashlib.sha256(session_nonce.encode()).hexdigest()

# In decode_oauth2_state / callback
expected_hash = hashlib.sha256(session.pop("oauth2_nonce").encode()).hexdigest()
if state_payload["nonce_hash"] != expected_hash:
    raise OAuth2Error("State token not bound to this session")
```

### Acceptance Criteria
- [ ] Session nonce generated and stored during authorization initiation
- [ ] Nonce hash included in signed state
- [ ] Callback validates nonce matches current session
- [ ] Nonce consumed (single-use) after validation
- [ ] Test added: state rejected when used in different session
- [ ] Test added: state rejected when reused after consumption

### References
- **Affected Files:**
  - `superset/utils/oauth2.py`
  - `superset/commands/database/oauth2.py`
- **CWE:** N/A
- **ASVS:** 10.1.2 (L2)
- **Source Report:** 10.1.2.md

### Priority
**Low** - Narrow exploitation window with multiple strong residual controls.

---
## Issue: FINDING-008 - nbf (not-before) claim not enforced; only exp validated
**Labels:** bug, security, priority:low
**Description:**
### Summary
JWT tokens with a future `nbf` (not-before) claim are accepted before their intended validity window because the verifier only validates the `exp` (expiration) claim.

### Details
**Data Flow:**
1. Token claims extracted via `self.jwt.decode()`
2. `exp` validated (required + not in past)
3. `nbf` claim never read or enforced
4. `.validate()` not invoked, so authlib does not automatically validate `nbf`

**Impact:**
- Validly-signed token with future `nbf` is accepted prematurely
- Minor impact: tokens are short-lived and issuer's documented claim set is `iat`/`exp`/`aud`/`sub`
- No evidence `nbf` is currently used in practice

**Context:**
This is an unconditional code gap not addressed by any profile section.

### Remediation
Enforce `nbf` symmetrically with `exp`, allowing small clock skew:

**Option 1 - Manual Check:**
```python
nbf = claims.get('nbf')
if nbf is not None:
    if time.time() + LEEWAY_SECONDS < nbf:
        raise JWTValidationError("Token not yet valid (nbf)")
```

**Option 2 - Use authlib validation:**
```python
claims.validate(leeway=LEEWAY_SECONDS)  # Validates both nbf and exp
```

### Acceptance Criteria
- [ ] `nbf` claim validation implemented with clock skew tolerance
- [ ] Test added: token rejected when current time < nbf - leeway
- [ ] Test added: token accepted when current time >= nbf - leeway
- [ ] Test added: token accepted when nbf claim absent (optional claim)
- [ ] Documentation updated to reflect supported JWT claims

### References
- **Affected File:** `superset/mcp_service/jwt_verifier.py`
- **CWE:** N/A
- **ASVS:** 9.2.1 (L1, L2, L3)
- **Source Report:** 9.2.1.md

### Priority
**Low** - Minor temporal validation gap with limited practical impact given short-lived tokens.

---
## Issue: FINDING-009 - No explicit token-type / token_use claim validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The JWT verifier does not validate a token-type claim (e.g., `typ`, `token_use`), potentially allowing cross-use of different JWT types (ID tokens, refresh tokens) if they share the same audience and scope.

### Details
**Current Validation:**
- ✅ Audience validated
- ✅ Scope validated
- ❌ Token type not validated

**Potential Risk:**
An attacker holding a different type of JWT (e.g., an ID token) issued by the same issuer and bearing a matching `aud`/`scope` set could attempt to use it as an access token.

**Mitigation:**
In practice, mitigated by audience + scope validation. Profile does not address token-type checks.

**Best Practice:**
Where the issuer emits multiple token types, explicit type validation provides defense-in-depth.

### Remediation
Validate a type claim explicitly when the issuer emits multiple token types:

```python
if self.expected_token_use:
    token_use = claims.get('token_use') or claims.get('typ')
    if token_use != self.expected_token_use:
        raise JWTValidationError(
            f"Invalid token type: expected {self.expected_token_use}, "
            f"got {token_use}"
        )
```

**Configuration:**
```python
# In config
JWT_EXPECTED_TOKEN_USE = "access_token"  # or "at+jwt", etc.
```

### Acceptance Criteria
- [ ] Token-type validation implemented (configurable)
- [ ] Test added: access token accepted with correct type claim
- [ ] Test added: ID token rejected when used as access token
- [ ] Test added: tokens without type claim handled per policy
- [ ] Documentation updated with supported token types

### References
- **Affected File:** `superset/mcp_service/jwt_verifier.py`
- **CWE:** N/A
- **ASVS:** 9.2.2 (L2, L3)
- **Source Report:** 9.2.2.md

### Priority
**Low** - Defense-in-depth improvement; existing aud/scope validation provides baseline protection.

---
## Issue: FINDING-010 - Insecure default for GLOBAL_ASYNC_QUERIES_JWT_SECRET not caught by startup validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `GLOBAL_ASYNC_QUERIES_JWT_SECRET` uses a hardcoded default value (`"test-secret-change-me"`) that is not detected by startup validation, potentially allowing attackers to forge async-query JWTs and access other users' query results.

### Details
**Root Cause:**
Unlike `SECRET_KEY` and `GUEST_TOKEN_JWT_SECRET` (which use `CHANGE_ME` sentinels that startup validation detects), this key is a plausible-looking literal that CHANGE_ME detection does not catch.

**Attack Scenario:**
With `GLOBAL_ASYNC_QUERIES=True` and the default secret:
1. Attacker computes `HS256(payload, "test-secret-change-me")` for victim channel
2. Submits forged token to async endpoint
3. **Impact:** Read other users' async query results (cross-user data disclosure)

**Exploitation Requirements:**
1. `GLOBAL_ASYNC_QUERIES` feature flag enabled (non-default)
2. Operator leaves literal default secret unchanged (non-default)

**Scope:**
Root cause is Superset-side asymmetry where the `CHANGE_ME` sentinel guard is not extended to this secret.

### Remediation
1. **Replace default** with a `CHANGE_ME`-style sentinel that startup validation rejects in production
2. **Extend startup validation** to reject any async/guest JWT secret shorter than 32 bytes (256-bit entropy)
3. **Require explicit value** when feature is enabled

**Implementation:**
```python
# In config.py
GLOBAL_ASYNC_QUERIES_JWT_SECRET = os.environ.get(
    "SUPERSET_ASYNC_JWT_SECRET"
) or "CHANGE_ME_ASYNC_SECRET"

# In startup validation
if GLOBAL_ASYNC_QUERIES:
    if (GLOBAL_ASYNC_QUERIES_JWT_SECRET == "CHANGE_ME_ASYNC_SECRET" or
        len(GLOBAL_ASYNC_QUERIES_JWT_SECRET) < 32):
        raise ValueError(
            "GLOBAL_ASYNC_QUERIES_JWT_SECRET must be set to a secure "
            "value (minimum 32 bytes) when GLOBAL_ASYNC_QUERIES is enabled"
        )
```

### Acceptance Criteria
- [ ] Default changed to `CHANGE_ME` sentinel
- [ ] Startup validation rejects sentinel in production
- [ ] Startup validation enforces minimum 32-byte length
- [ ] Environment variable sourcing added
- [ ] Test added: startup fails with insecure default
- [ ] Documentation updated with secret generation guidance

### References
- **Affected File:** `superset/config.py`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **ASVS:** 11.1.1 (L2), 11.6.1 (L2), 13.1.4 (L3), 13.3.1 (L2), 13.3.4 (L2)
- **Source Reports:** 11.1.1.md, 11.6.1.md, 13.1.4.md, 13.3.1.md, 13.3.4.md
- **Related:** FINDING-011

### Priority
**Low** - Requires two non-default configuration choices; mitigated by startup checks in typical deployments.

---
## Issue: FINDING-011 - GUEST_TOKEN_JWT_SECRET lacks environment-variable sourcing parity and rotation documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `GUEST_TOKEN_JWT_SECRET` configuration lacks environment-variable sourcing parity with `SECRET_KEY` and has no documented rotation schedule, creating operational security gaps for embedded guest token deployments.

### Details
**Current State:**
- Uses `CHANGE_ME` placeholder requiring operator override ✅
- Startup checks typically flag the sentinel ✅
- **Missing:** Environment-variable fallback path (unlike `SECRET_KEY`)
- **Missing:** Documented rotation schedule

**Impact:**
- Exploitable only if `EMBEDDED_SUPERSET` is enabled AND placeholder is left unchanged
- Startup validation typically catches this, but pattern inconsistency creates operational risk
- Lack of rotation documentation may lead to indefinite key usage

**Comparison with SECRET_KEY:**
```python
# SECRET_KEY has env-var sourcing
SECRET_KEY = os.environ.get("SUPERSET_SECRET_KEY") or "CHANGE_ME"

# GUEST_TOKEN_JWT_SECRET does not
GUEST_TOKEN_JWT_SECRET = "CHANGE_ME"
```

### Remediation
1. **Add env-var sourcing parity:**
```python
GUEST_TOKEN_JWT_SECRET = os.environ.get(
    "SUPERSET_GUEST_TOKEN_SECRET"
) or "CHANGE_ME_GUEST_SECRET"
```

2. **Document rotation schedule:**
   - Include all signing secrets in critical-secrets register
   - Define rotation cadence (e.g., quarterly for production)
   - Provide rotation procedure without downtime

3. **Enhance startup validation:**
```python
if EMBEDDED_SUPERSET and GUEST_TOKEN_JWT_SECRET == "CHANGE_ME_GUEST_SECRET":
    raise ValueError(
        "GUEST_TOKEN_JWT_SECRET must be set when EMBEDDED_SUPERSET is enabled"
    )
```

### Acceptance Criteria
- [ ] Environment variable sourcing added
- [ ] Startup validation enhanced for embedded mode
- [ ] Critical-secrets register created/updated
- [ ] Rotation schedule documented
- [ ] Rotation procedure documented (zero-downtime)
- [ ] Test added: startup fails with default when embedded enabled

### References
- **Affected File:** `superset/config.py`
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **ASVS:** 13.1.4 (L3)
- **Source Report:** 13.1.4.md
- **Related:** FINDING-010

### Priority
**Low** - Operational security hardening; startup validation provides baseline protection.

---
## Issue: FINDING-012 - Log injection via unsanitized CR/LF in flat Python-logging sink
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-controlled input (SQL text, schema names, imported object fields) is logged without CR/LF sanitization, allowing authenticated users to inject fake log entries and compromise log integrity.

### Details
**Data Flow:**
1. User-controlled SQL text / schema names / imported object fields
2. Passed as `%s` arguments to Python logging module
3. Rendered via flat `LOG_FORMAT` into console/file/forwarded logs
4. **No CR/LF or control-character neutralization**
5. Newline-bearing input can forge additional log lines

**Attack Scenario:**
```python
# User submits SQL with embedded newline
sql = "SELECT * FROM table\n2024-01-15 10:00:00 [CRITICAL] ADMIN LOGIN FAILED"

# Logged as:
logger.info("Executing SQL: %s", sql)

# Results in forged log entry:
# 2024-01-15 09:00:00 [INFO] Executing SQL: SELECT * FROM table
# 2024-01-15 10:00:00 [CRITICAL] ADMIN LOGIN FAILED
```

**Impact:**
- **Attacker:** Authenticated user
- **Affected:** Log integrity / forensic reliability
- **Note:** Structured DB log path is already JSON-safe

### Remediation
**Option 1 - Neutralize Control Characters:**
```python
def sanitize_log_value(value: str) -> str:
    """Escape CR/LF and control characters for flat logging."""
    if not isinstance(value, str):
        return value
    return value.replace('\r', '\\r').replace('\n', '\\n').replace('\t', '\\t')

# Usage
logger.info("Executing SQL: %s", sanitize_log_value(sql))
```

**Option 2 - Structured Formatter:**
Switch affected log sinks to JSON formatter:
```python
import json_log_formatter

formatter = json_log_formatter.JSONFormatter()
handler.setFormatter(formatter)

# Automatically escapes all values
logger.info("sql_executed", extra={"sql": sql})
```

### Acceptance Criteria
- [ ] CR/LF neutralization helper implemented
- [ ] Helper applied to all user-controlled log values
- [ ] OR structured/JSON formatter enabled for affected sinks
- [ ] Test added: newline in SQL does not create fake log entry
- [ ] Test added: control characters properly escaped
- [ ] Audit existing logs for injected entries

### References
- **Affected File:** `superset/models/helpers.py`
- **CWE:** N/A
- **ASVS:** 16.4.1 (L2)
- **Source Report:** 16.4.1.md

### Priority
**Low** - Impacts log integrity rather than direct data/system security; requires authentication.