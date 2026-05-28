# Security Issues

---
## Issue: FINDING-001 - MCP service does not check user active status, allowing disabled accounts continued tool access
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The MCP service's production JWT authentication path does not verify the `User.active` status, allowing disabled user accounts to continue making MCP tool calls with valid JWTs. While Flask-Login checks `is_active` for web sessions, the MCP authentication path (`load_user_with_relationships` and `_setup_user_context`) bypasses this control.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.4.2 (Level 1)
- **Affected File:** `superset/mcp_service/auth.py`
- **Related Findings:** FINDING-005, FINDING-007

A disabled user retaining a valid JWT can continue to:
- Execute data queries
- Retrieve charts
- Perform dashboard operations
- Retain all RBAC permissions

This creates a gap between intended access control (account disabled) and actual access control (JWT still valid).

### Remediation
Add an active status check in `_setup_user_context()` after user loading:
```python
if not getattr(user, 'is_active', True):
    raise ValueError("User account is disabled")
```
This aligns MCP authentication behavior with Flask-Login's standard session management.

### Acceptance Criteria
- [ ] Active status check added to `_setup_user_context()` in `superset/mcp_service/auth.py`
- [ ] Test added verifying disabled users cannot authenticate via MCP
- [ ] Test added verifying active users can still authenticate normally
- [ ] Documentation updated to reflect authentication flow

### References
- Source Report: 7.4.2.md
- Original ID: ASVS-742-MED-001

### Priority
**Medium** - Disabled accounts should not retain access, but requires valid JWT and does respect RBAC boundaries.

---
## Issue: FINDING-002 - User-supplied filename used in Content-Disposition header without sanitization
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-supplied filenames from `request.form.get('filename')` are used directly in Content-Disposition headers without `secure_filename()` sanitization. While Werkzeug's header validation layer prevents header injection exploitation, this creates a consistency issue with other filename handling in the codebase.

### Details
- **CWE:** CWE-116 (Improper Encoding or Escaping of Output)
- **ASVS:** 1.2.1 (Level 1)
- **Affected File:** `superset/charts/data/api.py`

The fallback path applies `secure_filename()` but the primary user-supplied path does not, creating inconsistent security posture.

### Remediation
Apply `secure_filename()` to user-provided filenames in `_extract_export_params_from_request()`:
```python
filename = secure_filename(request.form.get('filename', 'query_result'))
```

### Acceptance Criteria
- [ ] `secure_filename()` applied to user-supplied filenames in `_extract_export_params_from_request()`
- [ ] Test added verifying special characters in filenames are properly sanitized
- [ ] Test added verifying normal filenames still work correctly
- [ ] Consistent filename handling across all export endpoints

### References
- Source Report: 1.2.1.md
- Original ID: ASVS-121-LOW-001

### Priority
**Low** - Not currently exploitable due to framework protections, but improves defense-in-depth and code consistency.

---
## Issue: FINDING-003 - sanitize_clause() MySQL dialect fallback creates parser differential risk
**Labels:** bug, security, priority:low
**Description:**
### Summary
When SQL parsing fails for an unknown database engine dialect containing backticks, the code falls back to using MySQL dialect for validation. This creates a parser differential risk where the validated SQL could be interpreted differently by the target database than by the MySQL parser used for validation.

### Details
- **CWE:** CWE-436 (Interpretation Conflict)
- **ASVS:** 1.2.4 (Level 1)
- **Affected File:** `superset/sql/parse.py`

This requires:
- An unusual database engine with no sqlglot dialect mapping
- SQL containing backticks
- Target database that interprets backtick-containing SQL differently than MySQL

While the attack surface is narrow, the fallback behavior is undocumented and could lead to unexpected security bypasses.

### Remediation
1. Add logging when MySQL fallback is triggered for audit purposes
2. Consider restricting the fallback to only activate for explicitly configured databases
3. Document the fallback behavior and its security implications

### Acceptance Criteria
- [ ] Logging added when MySQL dialect fallback is triggered
- [ ] Configuration option added to control fallback behavior
- [ ] Test added verifying fallback is logged appropriately
- [ ] Documentation added explaining parser differential risks
- [ ] Consider rejecting unknown dialects instead of fallback (breaking change)

### References
- Source Report: 1.2.4.md
- Original ID: ASVS-124-LOW-001

### Priority
**Low** - Requires unusual database configuration and specific SQL patterns, but represents a potential security gap.

---
## Issue: FINDING-004 - Dynamic dispatch via getattr with user-controlled operation name and kwargs in post-processing execution
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `exec_post_processing()` function uses `getattr(pandas_postprocessing, operation)(df, **options)` where both `operation` and `options` are user-controlled. The only guard is `hasattr(pandas_postprocessing, operation)` rather than an explicit allowlist, allowing users to invoke any public attribute of the pandas_postprocessing module with arbitrary keyword arguments.

### Details
- **CWE:** CWE-470 (Use of Externally-Controlled Input to Select Classes or Code)
- **ASVS:** 1.3.2 (Level 1)
- **Affected File:** `superset/common/query_object.py`

While the pandas_postprocessing module is controlled code, this pattern:
- Violates defense-in-depth principles
- Could expose unintended functionality if the module is extended
- Is inconsistent with allowlist patterns used elsewhere in the codebase

### Remediation
Replace the `hasattr` check with an explicit allowlist of permitted operations:
```python
ALLOWED_POST_PROCESSING_OPS = frozenset([
    'aggregate',
    'boxplot',
    'compare',
    'contribution',
    # ... other allowed operations
])

if operation not in ALLOWED_POST_PROCESSING_OPS:
    raise QueryObjectValidationError(f"Invalid post-processing operation: {operation}")
```

### Acceptance Criteria
- [ ] Explicit allowlist implemented in `query_object.py`
- [ ] All currently used post-processing operations added to allowlist
- [ ] Test added verifying allowed operations work correctly
- [ ] Test added verifying disallowed operations are rejected
- [ ] Documentation updated with list of supported operations

### References
- Source Report: 1.3.2.md
- Original ID: ASVS-132-LOW-001

### Priority
**Low** - Limited to controlled module but violates secure coding principles.

---
## Issue: FINDING-005 - Guest tokens (self-contained JWTs) lack early revocation mechanism
**Labels:** bug, security, priority:low
**Description:**
### Summary
Guest tokens are self-contained JWTs validated only for signature, expiration, and audience with no revocation check. ASVS requires a blocklist, not-before timestamp, or per-user key rotation mechanism for self-contained tokens. Users with revoked access can continue using valid tokens until expiration.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.4.1 (Level 1)
- **Affected File:** `superset/security/manager.py`
- **Related Findings:** FINDING-001, FINDING-007

Impact is bounded by:
- `GUEST_TOKEN_JWT_EXP_SECONDS` configuration (default expiration time)
- Guest tokens are limited to read-only dashboard viewing
- No write operations or sensitive data access

However, when an admin revokes guest access, the user can continue accessing dashboards until token expiration.

### Remediation
Option 1: Add a per-embedded-dashboard `revoked_before` timestamp checked during `parse_jwt_guest_token`:
```python
if dashboard.guest_access_revoked_before and token_issued_at < dashboard.guest_access_revoked_before:
    raise ValueError("Guest access has been revoked")
```

Option 2: Reduce `GUEST_TOKEN_JWT_EXP_SECONDS` to a short value (e.g., 5 minutes) and implement a refresh endpoint that validates current access state.

### Acceptance Criteria
- [ ] Revocation mechanism implemented (either option)
- [ ] Test added verifying revoked tokens are rejected
- [ ] Test added verifying valid tokens continue to work
- [ ] Admin UI updated to show revocation status
- [ ] Documentation updated with revocation behavior

### References
- Source Report: 7.4.1.md
- Original ID: ASVS-741-LOW-001

### Priority
**Low** - Limited to guest token scope with read-only access, but violates session management best practices.

---
## Issue: FINDING-006 - Algorithm allowlist check is conditional on configuration being set
**Labels:** bug, security, priority:low
**Description:**
### Summary
The algorithm enforcement check in `DetailedJWTVerifier.load_access_token()` is conditional on `self.algorithm` being truthy. If `self.algorithm` is not configured, the check is skipped entirely and the token proceeds to decode with any declared algorithm. While authlib provides secondary validation and the parent class typically requires algorithm specification, this creates an unsafe default.

### Details
- **CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)
- **ASVS:** 9.1.2 (Level 1)
- **Affected File:** `superset/mcp_service/jwt_verifier.py`

Current code:
```python
if self.algorithm and token_algorithm != self.algorithm:
    # reject
```

If `self.algorithm` is None/empty, the algorithm check is bypassed entirely.

### Remediation
Make the algorithm check unconditional:
```python
if not self.algorithm:
    raise ValueError("JWT algorithm must be configured")

if token_algorithm != self.algorithm:
    raise ValueError(f"Invalid algorithm: {token_algorithm}")
```

Move the configuration check to `__init__()` to fail fast.

### Acceptance Criteria
- [ ] Algorithm configuration made mandatory in `__init__()`
- [ ] Unconditional algorithm validation in `load_access_token()`
- [ ] Test added verifying unconfigured algorithm raises error at initialization
- [ ] Test added verifying mismatched algorithms are rejected
- [ ] Test added verifying correct algorithm is accepted

### References
- Source Report: 9.1.2.md
- Original ID: ASVS-912-LOW-001

### Priority
**Low** - Parent class typically enforces configuration, but creates unsafe default if misconfigured.

---
## Issue: FINDING-007 - No explicit `nbf` (not-before) claim validation in DetailedJWTVerifier
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `DetailedJWTVerifier.load_access_token()` method has an explicit `exp` (expiration) check but no corresponding explicit `nbf` (not-before) check. A token with a future `nbf` claim could potentially be accepted before its intended activation time. While authlib's `jwt.decode()` may validate `nbf` during decode, this is not explicitly verified or documented.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 9.2.1 (Level 1)
- **Affected File:** `superset/mcp_service/jwt_verifier.py`
- **Related Findings:** FINDING-001, FINDING-005

The code explicitly validates `exp`:
```python
if exp and exp < time.time():
    # reject
```

But has no parallel check for `nbf`, creating asymmetric temporal validation.

### Remediation
Add explicit `nbf` validation alongside the `exp` check:
```python
nbf = claims.get("nbf")
if nbf and nbf > time.time():
    return None, "Token not yet valid"
```

### Acceptance Criteria
- [ ] Explicit `nbf` validation added to `load_access_token()`
- [ ] Test added verifying future-dated tokens are rejected
- [ ] Test added verifying past `nbf` tokens are accepted
- [ ] Test added verifying tokens without `nbf` claim work correctly
- [ ] Documentation updated explaining temporal claim validation

### References
- Source Report: 9.2.1.md
- Original ID: ASVS-921-LOW-001

### Priority
**Low** - Authlib likely validates `nbf` generically, but explicit validation improves security clarity.

---
## Issue: FINDING-008 - ChartPutSchema.query_context missing JSON validation inconsistent with ChartPostSchema
**Labels:** bug, security, priority:low
**Description:**
### Summary
`ChartPutSchema.query_context` lacks the `validate=utils.validate_json` validator that is present on `ChartPostSchema`. This allows invalid JSON to be stored in the database during chart updates, which could cause chart rendering failures when the invalid JSON is later parsed.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level 1)
- **Affected File:** `superset/charts/schemas.py`

Attack flow:
1. Authenticated user with chart edit permissions
2. PUT request with invalid JSON in `query_context`
3. ChartPutSchema deserialization (no JSON validation)
4. Invalid data stored in database
5. Chart rendering attempts to parse JSON and fails

Impact: Data integrity violation leading to application errors, not a security vulnerability.

### Remediation
Add `validate=utils.validate_json` to `ChartPutSchema.query_context`:
```python
query_context = fields.String(
    allow_none=True,
    validate=utils.validate_json,
    metadata={"description": "..."}
)
```

### Acceptance Criteria
- [ ] JSON validation added to `ChartPutSchema.query_context`
- [ ] Test added verifying invalid JSON is rejected on PUT
- [ ] Test added verifying valid JSON is accepted on PUT
- [ ] Test added verifying null/empty values are handled correctly
- [ ] Consistent validation between POST and PUT schemas

### References
- Source Report: 2.2.1.md
- Original ID: ASVS-221-LOW-001

### Priority
**Low** - Data integrity issue requiring authenticated user with edit permissions, not a security vulnerability.

---
## Issue: FINDING-009 - ChartDataProphetOptionsSchema.periods field lacks Range validator despite documented minimum
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `periods` field in `ChartDataProphetOptionsSchema` has `min: 0` documented in metadata but no actual Range validator enforcing this constraint. This allows unbounded values to be passed to the Prophet forecasting library, potentially causing computational resource exhaustion. The `window` field in `ChartDataRollingOptionsSchema` has the same pattern.

### Details
- **CWE:** CWE-1284 (Improper Validation of Specified Quantity in Input)
- **ASVS:** 2.2.1 (Level 1)
- **Affected File:** `superset/charts/schemas.py`

Attack flow:
1. Authenticated user with dataset access
2. Chart data request with extremely large `periods` value
3. ChartDataProphetOptionsSchema deserialization (no Range validation)
4. Value passed to Prophet forecasting library
5. Unbounded computation causing DoS

Impact: Potential computational resource exhaustion (DoS) if extremely large values submitted.

### Remediation
Add Range validators to enforce documented constraints:
```python
periods = fields.Integer(
    metadata={"description": "...", "min": 0},
    validate=Range(min=0, max=10000)
)
```

Apply similar fix to `ChartDataRollingOptionsSchema.window`.

### Acceptance Criteria
- [ ] Range validator added to `ChartDataProphetOptionsSchema.periods`
- [ ] Range validator added to `ChartDataRollingOptionsSchema.window`
- [ ] Test added verifying values above maximum are rejected
- [ ] Test added verifying negative values are rejected
- [ ] Test added verifying valid values are accepted
- [ ] Maximum values documented and justified

### References
- Source Report: 2.2.1.md
- Original ID: ASVS-221-LOW-002

### Priority
**Low** - Requires authenticated user with dataset access, but could enable resource exhaustion attacks.