# Security Issues

## Issue: FINDING-001 - Tokens without `jti` claim bypass revocation check
**Labels:** bug, security, priority:low
**Description:**

### Summary
Tokens from external issuers (via `trusted_jwks_url`) that omit the optional `jti` claim silently skip the revocation check in `get_user_from_token()`. This prevents proper token revocation for externally-issued tokens that don't include the JWT ID claim.

### Details
- **CWE:** N/A
- **ASVS:** 7.4.1 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py`

The `jti` claim is not included in `required_claims`, so tokens without it pass validation but cannot be revoked through Airflow's token revocation mechanism. This creates a gap where some valid tokens cannot be revoked if needed.

### Remediation
Add `jti` to `required_claims` or log a warning when tokens without `jti` are accepted. Alternatively, reject tokens without `jti` to ensure all tokens in the system can be revoked.

### Acceptance Criteria
- [ ] Fixed: Either `jti` is required for all tokens, or a warning is logged when tokens without `jti` are accepted
- [ ] Test added: Unit tests verify behavior for tokens with and without `jti` claim
- [ ] Documentation updated to clarify token revocation requirements

### References
- Source Report: 7.4.1.md
- Related Findings: None

### Priority
**Low** - External token issuers may not include optional claims, but revocation capability should be consistent across all token sources.

---

## Issue: FINDING-002 - No mechanism to terminate all active sessions when a user account is disabled or deleted
**Labels:** bug, security, priority:low
**Description:**

### Summary
The `base_auth_manager.py` lacks per-user bulk session revocation. While production deployments delegate authentication to external auth managers (FAB, Keycloak) which handle user lifecycle, there is no abstract interface for triggering bulk session termination.

### Details
- **CWE:** N/A
- **ASVS:** 7.4.2 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/models/revoked_token.py`

**Note:** Downgraded from Medium severity because production deployments delegate authentication to external auth managers which handle user lifecycle and session termination. The proof-of-concept scenario relies on SimpleAuthManager which is dev-only.

### Remediation
Add an abstract `revoke_all_user_sessions(user_id)` method to `BaseAuthManager` and implement a per-user not-before timestamp mechanism, enabling production auth managers to trigger bulk session termination on account state changes.

### Acceptance Criteria
- [ ] Fixed: Abstract method added to `BaseAuthManager` for bulk session revocation
- [ ] Test added: Unit tests verify the interface contract
- [ ] Documentation added for auth manager implementers

### References
- Source Report: 7.4.2.md
- Related Findings: None

### Priority
**Low** - Production auth managers handle this, but a standard interface would improve consistency.

---

## Issue: FINDING-003 - Bulk CREATE with `action_on_existence=overwrite` Bypasses Existing Resource Team Authorization Check
**Labels:** bug, security, priority:low
**Description:**

### Summary
The bulk CREATE+overwrite path skips team lookup for CREATE entities, passing `team_name=None` to the authorization check, potentially allowing cross-team resource overwrites in multi-team mode.

### Details
- **CWE:** CWE-639 (Authorization Bypass Through User-Controlled Key)
- **ASVS:** 8.2.2 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/security.py`

**Note:** Downgraded from Medium severity because the multi-team feature is documented as experimental/work-in-progress. However, the authorization bypass should be fixed before the feature becomes stable.

When `action_on_existence=overwrite` is used with bulk operations, CREATE entities don't have their team context checked, which could allow users to overwrite resources belonging to other teams.

### Remediation
Include CREATE entities in the team mapping lookup for all three bulk handlers:
- `requires_access_connection_bulk`
- `requires_access_pool_bulk`
- `requires_access_variable_bulk`

This ensures that when `action_on_existence=overwrite` is used, the authorization check includes the existing resource's team context.

### Acceptance Criteria
- [ ] Fixed: CREATE entities included in team lookup for all bulk handlers
- [ ] Test added: Integration tests verify cross-team overwrite protection
- [ ] Test added: Tests verify authorized same-team overwrites still work

### References
- Source Report: 8.2.2.md
- Related Findings: None

### Priority
**Low** - Multi-team feature is experimental, but should be fixed before stabilization.

---

## Issue: FINDING-004 - TaskInstancesBatchBody.page_limit Missing Maximum Enforcement and Documentation
**Labels:** bug, security, priority:low
**Description:**

### Summary
The `page_limit` field in `TaskInstancesBatchBody` has no upper bound enforcement or documentation, unlike `LimitFilter` which clamps to `maximum_page_limit`. An authenticated user could request an extremely large number of task instances in a single response.

### Details
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **ASVS:** 2.1.1, 2.2.1 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/datamodels/task_instances.py`

The field declares only a non-negative constraint (`ge=0`) and a default of 100, but does not document or enforce the same `maximum_page_limit` that `LimitFilter` enforces. This could lead to:
- Memory exhaustion
- Database performance degradation
- Inconsistent API behavior between query-parameter and request-body pagination

Additionally, the `order_by` field lacks documentation of valid values.

### Remediation
1. Apply `Field(default=100, ge=0, le=conf.getint('api', 'maximum_page_limit'))` constraint to `TaskInstancesBatchBody.page_limit`
2. Add description documenting the upper bound
3. Document valid `order_by` values in the field description to match `LimitFilter` protection

### Acceptance Criteria
- [ ] Fixed: Maximum limit enforced on `page_limit` field
- [ ] Test added: Tests verify rejection of excessive page_limit values
- [ ] Documentation updated: Field descriptions include valid ranges and values

### References
- Source Reports: 2.1.1.md, 2.2.1.md
- Related Findings: None

### Priority
**Low** - Authenticated users only, but resource exhaustion is possible.

---

## Issue: FINDING-005 - URL Protocol Validation Depends on External Regex Pattern
**Labels:** bug, security, priority:low
**Description:**

### Summary
The `renderStructuredLog.tsx` component creates clickable links from URLs found in log content without explicit protocol allowlist validation. If the external `urlRegex` could match `javascript:` or `data:` URLs, clicking a link in task logs could trigger script execution.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.2 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/ui/src/components/renderStructuredLog.tsx` (line 52)

The function relies entirely on `urlRegex` (imported from `src/constants/urlRegex`) to identify URLs. There is no explicit protocol allowlist validation (e.g., only `https://` or `http://`) applied before setting the `href` attribute.

Given that DAG Authors are trusted, this is a cross-trust-boundary concern only in multi-team deployments where Operations Users may view logs from untrusted DAG Authors.

### Remediation
Add explicit protocol allowlist validation before creating clickable links:

```typescript
const SAFE_PROTOCOLS = /^https?:\/\//i;

const addAnsiWithLinks = (line: string) => {
  const urlMatches = [...line.matchAll(urlRegex)];
  const url = match[0];
  if (SAFE_PROTOCOLS.test(url)) {
    elements.push(
      <Link href={url} rel="noopener noreferrer" target="_blank">
        {url}
      </Link>,
    );
  } else {
    elements.push(
      <AnsiRenderer linkify={false}>{url}</AnsiRenderer>,
    );
  }
};
```

### Acceptance Criteria
- [ ] Fixed: Protocol allowlist validation added before creating links
- [ ] Test added: Unit tests verify rejection of `javascript:` and `data:` URLs
- [ ] Test added: Tests verify `http://` and `https://` URLs work correctly

### References
- Source Report: 1.2.2.md
- Related Findings: None

### Priority
**Low** - Requires multi-team deployment with untrusted DAG Authors viewing each other's logs.

---

## Issue: FINDING-006 - No Explicit Anti-Forgery Token Mechanism Visible for Cookie-Authenticated Endpoints
**Labels:** bug, security, priority:low
**Description:**

### Summary
No visible explicit anti-forgery token mechanism for cookie-authenticated core API endpoints. The application relies on CORS preflight and JSON content-type requirements for CSRF protection, but this strategy is not explicitly documented.

### Details
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **ASVS:** 3.5.1 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

**Note:** Downgraded from Medium severity because the application relies on CORS preflight (deferred to 3.5.2), and FastAPI's JSON body requirement provides implicit preflight triggering for most endpoints.

Auth manager middlewares may provide additional protection but implementation is not visible in the audited code.

### Remediation
1. Document the CSRF protection strategy explicitly in code comments and/or security documentation
2. Consider adding a custom header requirement (e.g., `X-Requested-With`) as defense-in-depth for endpoints that accept no body or optional bodies

### Acceptance Criteria
- [ ] Fixed: CSRF protection strategy documented in code
- [ ] Test added: Tests verify CSRF protection for cookie-authenticated endpoints
- [ ] Documentation: Security documentation updated with CSRF protection approach

### References
- Source Report: 3.5.1.md
- Related Findings: FINDING-007

### Priority
**Low** - Implicit protections exist, but explicit documentation and defense-in-depth would improve security posture.

---

## Issue: FINDING-007 - No Content-Type Enforcement Visible at Application Level to Guarantee CORS Preflight
**Labels:** bug, security, priority:low
**Description:**

### Summary
No explicit middleware rejects CORS-safelisted Content-Types for state-changing requests. While FastAPI's Pydantic parsing rejects incorrect content types at deserialization, endpoints accepting no body (e.g., DELETE with path params) could potentially process cross-origin simple requests without triggering preflight.

### Details
- **CWE:** CWE-352 (Cross-Site Request Forgery)
- **ASVS:** 3.5.2 (L1)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/app.py`

CORS-safelisted Content-Types include:
- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`

Endpoints that don't require a request body (e.g., DELETE operations with only path parameters) may not trigger CORS preflight, potentially allowing CSRF attacks via simple requests.

### Remediation
Add a middleware that validates Content-Type for state-changing requests, rejecting CORS-safelisted types for sensitive endpoints:

```python
@app.middleware("http")
async def enforce_content_type(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        content_type = request.headers.get("content-type", "").split(";")[0].strip()
        safelisted = [
            "application/x-www-form-urlencoded",
            "multipart/form-data", 
            "text/plain"
        ]
        if content_type in safelisted:
            return JSONResponse(
                status_code=415,
                content={"detail": "Unsupported Content-Type"}
            )
    return await call_next(request)
```

### Acceptance Criteria
- [ ] Fixed: Middleware added to reject CORS-safelisted Content-Types for state-changing requests
- [ ] Test added: Tests verify rejection of safelisted Content-Types
- [ ] Test added: Tests verify accepted Content-Types still work (application/json)

### References
- Source Report: 3.5.2.md
- Related Findings: FINDING-006

### Priority
**Low** - Related to CSRF protection strategy; should be addressed alongside FINDING-006.