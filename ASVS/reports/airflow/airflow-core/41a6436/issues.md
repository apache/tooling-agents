# Security Issues

---
## Issue: FINDING-001 - No Mechanism to Terminate All Active Sessions on User Account Disable/Delete
**Labels:** bug, security, priority:high
**Description:**
### Summary
When an administrator disables or deletes a user account, there is no mechanism to invalidate all active JWT tokens for that user. Existing tokens remain valid until their natural expiration, allowing disabled users to continue accessing the system.

### Details
The `RevokedToken` model only supports individual JTI-based revocation with no user-to-JTI mapping or per-user invalidation timestamp. This means:
- No bulk revocation capability exists for a specific user
- Account disable/delete operations cannot identify all active sessions for a user
- Compromised or terminated user accounts can continue API access until token expiration

**CWE:** CWE-613 (Insufficient Session Expiration)  
**ASVS:** 7.4.2 (L1)  
**Affected Files:** `airflow-core/src/airflow/models/revoked_token.py`

### Remediation
Implement one of the following approaches:
1. Add a `UserTokenInvalidation` table with per-user invalidation timestamps checked during JWT validation
2. Extend `RevokedToken` with a `username` column to support bulk revocation queries

Wire the chosen mechanism into account disable/delete flows to ensure immediate session termination.

### Acceptance Criteria
- [ ] Per-user session invalidation mechanism implemented
- [ ] Account disable flow automatically revokes all user sessions
- [ ] Account delete flow automatically revokes all user sessions
- [ ] Test added for bulk session revocation
- [ ] Test added for disabled user token validation failure

### References
- Source Report: 7.4.2.md
- Related: CWE-613

### Priority
High

---
## Issue: FINDING-002 - Unbounded `dag_runs_limit` Parameter Allows Excessive Database Load
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `dag_runs_limit` parameter accepts any integer value without an upper bound, allowing authenticated users to request arbitrarily large result sets that could cause excessive database load and memory consumption.

### Details
While authentication is required and deployment-level rate limiting is expected, the lack of application-level bounds bypasses pagination controls. An authenticated user could specify `dag_runs_limit=999999` to retrieve massive datasets in a single request.

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)  
**ASVS:** 2.2.1 (L1)  
**Affected Files:** `airflow-core/src/airflow/api_fastapi/core_api/routes/ui/dags.py`

### Remediation
Add upper bound validation to the parameter definition:
```python
dag_runs_limit: Annotated[int, Query(ge=1, le=100, description="Number of recent DAG runs per DAG")] = 10
```

### Acceptance Criteria
- [ ] Fixed: Upper bound (e.g., 100) added to `dag_runs_limit` parameter
- [ ] Test added verifying requests above limit are rejected with 422
- [ ] Test added verifying valid values within range are accepted
- [ ] Documentation updated with parameter limits

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-003

### Priority
Low

---
## Issue: FINDING-003 - Unbounded `run_ids` List in Streaming Endpoint Allows Excessive Sequential Processing
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `run_ids` query parameter accepts an unbounded list of strings, allowing authenticated attackers to submit thousands of run IDs that cause resource exhaustion through sequential processing overhead.

### Details
Each iteration in the endpoint opens a database session and executes queries. With no length limit on the `run_ids` list, a worker thread can be tied up for extended periods processing an excessive number of IDs.

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)  
**ASVS:** 2.2.1 (L1)  
**Affected Files:** `airflow-core/src/airflow/api_fastapi/core_api/routes/ui/grid.py`

### Remediation
Add length limit to the parameter:
```python
run_ids: Annotated[list[str] | None, Query(max_length=100)] = None
```
Or validate at function start before processing.

### Acceptance Criteria
- [ ] Fixed: Maximum length (e.g., 100) added to `run_ids` parameter
- [ ] Test added verifying requests with excessive IDs are rejected
- [ ] Test added verifying valid requests within limit work correctly
- [ ] Documentation updated with parameter limits

### References
- Source Report: 2.2.1.md
- Related Findings: FINDING-002

### Priority
Low

---
## Issue: FINDING-004 - Missing `rel` and `target` Attributes on Markdown-Rendered Links
**Labels:** bug, security, priority:low
**Description:**
### Summary
Markdown-rendered links in DAG descriptions lack `rel="noopener noreferrer"` attributes, allowing opened pages to access `window.opener` and potentially perform reverse tabnabbing attacks.

### Details
When users middle-click or browser extensions open markdown links in new tabs, the target page can execute `window.opener.location = 'https://phishing.example.com'` to navigate the original Airflow tab.

While `react-markdown` already sanitizes `javascript:` and `data:` protocols, this is a defense-in-depth issue. A DAG description containing `[Click here](https://attacker.example.com)` renders without proper security attributes.

**ASVS:** 1.2.1 (L1)  
**Affected Files:** `airflow-core/src/airflow/ui/src/components/ReactMarkdown.tsx:47-54`

### Remediation
Update the `LinkComponent` to include security attributes:
```tsx
<Link 
  color="fg.info" 
  fontWeight="bold" 
  href={href} 
  rel="noopener noreferrer" 
  target="_blank" 
  title={title}
>
  {children}
</Link>
```

### Acceptance Criteria
- [ ] Fixed: `rel="noopener noreferrer"` and `target="_blank"` added to Link component
- [ ] Test added verifying rendered links include security attributes
- [ ] Manual test confirming `window.opener` is null in opened tabs

### References
- Source Report: 1.2.1.md

### Priority
Low

---
## Issue: FINDING-005 - Missing URL Encoding for mapIndex Parameter in Iframe URL Construction
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `mapIndex` parameter is directly substituted into iframe src URLs without `encodeURIComponent()` encoding, while other parameters are properly encoded, potentially allowing query parameter injection.

### Details
Data flows from URL path parameter (user-controlled) through `useParams()` to `mapIndex` and is directly substituted into iframe src. If a plugin defines href with `{MAP_INDEX}` placeholder, a user could inject additional query parameters.

Impact is limited by iframe sandbox (`allow-scripts allow-same-origin allow-forms`) and the base template coming from trusted plugin configuration.

**ASVS:** 1.2.2 (L1)  
**Affected Files:** `airflow-core/src/airflow/ui/src/pages/Iframe.tsx:43`

### Remediation
Apply `encodeURIComponent` to the `mapIndex` parameter:
```typescript
if (mapIndex !== undefined) {
  src = src.replaceAll("{MAP_INDEX}", encodeURIComponent(mapIndex));
}
```

### Acceptance Criteria
- [ ] Fixed: `encodeURIComponent()` applied to `mapIndex` parameter
- [ ] Test added with special characters in mapIndex verifying proper encoding
- [ ] Test added attempting parameter injection to verify it's blocked

### References
- Source Report: 1.2.2.md

### Priority
Low

---
## Issue: FINDING-006 - JWKS URL Mode Lacks Explicit Static Algorithm Allowlist
**Labels:** bug, security, priority:low
**Description:**
### Summary
When using `trusted_jwks_url` without explicitly setting `jwt_algorithm`, the effective algorithm allowlist is whatever algorithms appear in the JWKS keys, providing no defense-in-depth against JWKS endpoint compromise.

### Details
If the JWKS endpoint is compromised or serves keys with unexpected algorithms, tokens signed with those algorithms would be accepted. The current implementation uses `["GUESS"]` mode which accepts any algorithm present in the JWKS.

**CWE:** CWE-757 (Selection of Less-Secure Algorithm During Negotiation)  
**ASVS:** 9.1.2 (L1)  
**Affected Files:** `airflow-core/src/airflow/api_fastapi/auth/tokens.py`

### Remediation
When `trusted_jwks_url` is configured without an explicit `jwt_algorithm`, default to `["RS256", "EdDSA"]` rather than `["GUESS"]` to provide defense-in-depth against JWKS endpoint compromise.

### Acceptance Criteria
- [ ] Fixed: Default algorithm allowlist set to `["RS256", "EdDSA"]` for JWKS mode
- [ ] Test added verifying only allowed algorithms are accepted
- [ ] Test added verifying tokens with disallowed algorithms are rejected
- [ ] Documentation updated explaining algorithm allowlist behavior

### References
- Source Report: 9.1.2.md

### Priority
Low

---
## Issue: FINDING-007 - No Cookie Security Configuration Visible in Application Initialization
**Labels:** bug, security, priority:low
**Description:**
### Summary
No application-wide cookie security defaults are configured, though this is speculative as no cookies are currently set in the analyzed code (JWT Bearer tokens are used for authentication).

### Details
This finding represents a coverage gap rather than a confirmed vulnerability. The codebase uses JWT Bearer tokens for authentication, and no cookies are actually set in the analyzed code. However, if cookies were to be used anywhere in the auth flow, there are no established security defaults.

**ASVS:** 3.3.1 (L1)  
**Affected Files:** `airflow-core/src/airflow/api_fastapi/core_api/app.py`

### Remediation
If cookies are used anywhere in the auth flow, establish application-wide cookie security defaults with:
- `Secure` attribute (HTTPS only)
- `HttpOnly` attribute (no JavaScript access)
- `SameSite` attribute (CSRF protection)
- `__Host-` or `__Secure-` prefixes

### Acceptance Criteria
- [ ] Audit completed confirming whether cookies are used in auth flow
- [ ] If cookies are used: security defaults implemented
- [ ] If cookies are used: tests added verifying security attributes
- [ ] Documentation updated clarifying cookie usage (or lack thereof)

### References
- Source Report: 3.3.1.md

### Priority
Low

---
## Issue: FINDING-008 - Unconstrained import_string() in Exception and Trigger Deserialization
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `BaseSerialization.deserialize()` method uses `import_string()` to dynamically load exception and trigger classes without validating against a whitelist or checking subclass relationships, though exploitation requires database content manipulation.

### Details
For `AIRFLOW_EXC_SER`, any importable class path can be specified and instantiated with arbitrary args/kwargs. The `BASE_TRIGGER` path similarly loads and instantiates any importable class.

**Context:** Per the project's security model, DAG authors are trusted with code execution. The source data is the metadata database, written exclusively by DagFileProcessorProcess from trusted DAG authors. `import_string()` only loads already-installed modules (not arbitrary code execution like eval()).

This represents a defense-in-depth gap rather than an active vulnerability.

**ASVS:** 1.3.2 (L1)  
**Affected Files:** `airflow-core/src/airflow/serialization/serialized_objects.py` (within deserialize classmethod)

### Remediation
Add type validation:

**For exceptions:**
```python
elif type_ == DAT.AIRFLOW_EXC_SER:
    exc_cls = import_string(exc_cls_name)
    if not (isinstance(exc_cls, type) and issubclass(exc_cls, BaseException)):
        raise TypeError(f"Expected exception class, got {exc_cls_name}")
    return exc_cls(*args, **kwargs)
```

**For triggers:**
```python
elif type_ == DAT.BASE_TRIGGER:
    tr_cls = import_string(tr_cls_name)
    if not (isinstance(tr_cls, type) and issubclass(tr_cls, BaseTrigger)):
        raise TypeError(f"Expected trigger class, got {tr_cls_name}")
    return tr_cls(**kwargs)
```

### Acceptance Criteria
- [ ] Fixed: Type validation added for exception deserialization
- [ ] Fixed: Type validation added for trigger deserialization
- [ ] Test added verifying invalid exception classes are rejected
- [ ] Test added verifying invalid trigger classes are rejected
- [ ] Test added verifying valid classes still deserialize correctly

### References
- Source Report: 1.3.2.md

### Priority
Low

---
## Issue: FINDING-009 - No Client-Side Cleanup Mechanism for Session Termination Scenarios
**Labels:** bug, security, priority:low
**Description:**
### Summary
The application does not implement client-side storage cleanup mechanisms for session termination scenarios, though practical security impact is minimal as no authenticated data is stored in browser-accessible storage.

### Details
The `LogoutModal` performs no explicit client-side storage cleanup before redirecting to server logout. There are no `beforeunload` or 401-response handlers to clear client storage on non-interactive session termination.

**Context:** Audit confirmed that no authenticated data (tokens, credentials) is stored in browser-accessible storage—only UI preferences are stored in localStorage. This represents a defense-in-depth gap rather than an active vulnerability.

**CWE:** CWE-922 (Insecure Storage of Sensitive Information)  
**ASVS:** 14.3.1 (L1)  
**Affected Files:** `airflow-core/src/airflow/ui/src/layouts/Nav/LogoutModal.tsx`

### Remediation
Implement a centralized client-side storage cleanup utility that:
1. Is invoked in the logout flow before server redirect
2. Registers a `beforeunload` event handler to clear storage on browser close
3. Implements an API response interceptor to clear storage on 401 responses

Document the current architecture decision that authentication data is not stored client-side.

### Acceptance Criteria
- [ ] Fixed: Centralized storage cleanup utility implemented
- [ ] Fixed: Cleanup invoked on explicit logout
- [ ] Fixed: `beforeunload` handler registered
- [ ] Fixed: 401 response interceptor implemented
- [ ] Test added verifying storage cleared on logout
- [ ] Documentation updated explaining client-side storage policy

### References
- Source Report: 14.3.1.md

### Priority
Low

---
## Issue: FINDING-010 - DagRun.set_state() Lacks Explicit State Machine Transition Validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `set_state()` method validates that the target state is valid but does not validate that the transition from the current state to the target state is logically valid according to workflow progression rules.

### Details
While all current callers follow correct patterns, this is a defense-in-depth gap. Invalid state transitions could bypass expected workflow progression. For example, a QUEUED DAG run should not be able to transition directly to SUCCESS without going through RUNNING.

This represents a potential violation of sequential business logic flow enforcement.

**CWE:** CWE-841 (Improper Enforcement of Behavioral Workflow)  
**ASVS:** 2.3.1 (L1)  
**Affected Files:** `airflow-core/src/airflow/models/dagrun.py`

### Remediation
Add explicit state transition validation map in `DagRun.set_state()` to enforce valid transitions. Implement a state machine pattern that validates transitions against allowed paths before allowing state changes.

Example valid transitions:
- QUEUED → RUNNING, FAILED
- RUNNING → SUCCESS, FAILED
- (but not QUEUED → SUCCESS)

### Acceptance Criteria
- [ ] Fixed: State transition validation map implemented
- [ ] Fixed: Validation enforced in `set_state()` method
- [ ] Test added verifying invalid transitions are rejected
- [ ] Test added verifying all valid transitions still work
- [ ] Documentation added explaining valid state transitions

### References
- Source Report: 2.3.1.md

### Priority
Low