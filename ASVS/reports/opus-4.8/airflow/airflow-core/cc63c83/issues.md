# Security Issues

*31 actionable finding(s). 4 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Core API and Execution API tokens share a single audience and signing key, so audience restriction does not uniquely identify the intended service
**Labels:** security, priority:medium
**Description:**
### Summary
A signing key is resolved once via `get_signing_args()` and is shared by all issuers. The audience is a single value (`apache-airflow`) for the Core API. The Execution API validator validates the same audience and the same key. Because the audience does not differentiate "Core API user token" from "Execution API task token," a token minted for the Core API audience also satisfies the Execution API's audience check. The only remaining isolation is the `scope` claim (which defaults to `execution` when absent) and the `ti:self` route scope (only enforced on opted-in routes). A Core API user JWT (no `scope` claim → defaults to `execution`, arbitrary `sub` accepted by `TIClaims`) would therefore pass crypto + audience + claims validation on any Execution API route that does not declare `ti:self`.

### Details
- **ASVS Sections:** 9.2.4
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/api_fastapi/auth/tokens.py`
  - `airflow-core/src/airflow/api_fastapi/execution_api/security.py`

**Attacker Capability Required:** An authenticated Core API user with network reachability to the Execution API.

**Impact:** Cross-service token usage allowing calls to worker-to-scheduler endpoints with a user token on non-`ti:self` endpoints.

### Remediation
Issue distinct audiences per service when reusing the same private key, and require the audience the receiving service expects (e.g. `apache-airflow-api` for Core API, `apache-airflow-execution` for Execution API). Validate the service-specific audience in each validator, and stop defaulting `scope` to `execution` — require an explicit `scope` claim for execution-API tokens so an audience/scope-less token cannot be silently treated as a task token.

### Acceptance Criteria
- [ ] Core API and Execution API use distinct audience values
- [ ] Each validator enforces its service-specific audience
- [ ] `scope` claim is explicitly required for execution tokens (no defaulting to `execution`)
- [ ] Test added validating Core API tokens are rejected by Execution API
- [ ] Documentation updated describing audience separation

### References
- Source Report: 9.2.4.md
- Related: JWT-3, ASVS-924-MED-001

### Priority
Medium

---
## Issue: FINDING-002 - `default_action_log` persists raw `full_command` (CLI argv) to the metadata DB without secret masking
**Labels:** security, priority:medium
**Description:**
### Summary
`full_command` (the complete argv) is serialized verbatim into the `extra` JSON column of the `log` table with no masking/redaction, unlike the HTTP access path which runs `secrets_masker`. CLI subcommands routinely carry secrets as arguments (passwords, connection URIs with embedded credentials, tokens), so any such credential is durably persisted in cleartext, readable by any principal with audit-log access.

### Details
- **ASVS Sections:** 16.2.5
- **ASVS Level:** L2
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Files:**
  - `airflow-core/src/airflow/utils/cli_action_loggers.py`

**Attacker Capability Required:** A reader of the metadata DB/audit log plus another user having passed a secret on a CLI argument; not remotely exploitable by an unauthenticated attacker.

**Impact:** Cleartext credential disclosure in audit logs for any secrets passed via CLI arguments.

### Remediation
Apply `secrets_masker.redact` to the command vector before serialization, and ensure the upstream `action_logging` builder strips/redacts known sensitive flags (e.g., `--password`, `--conn-uri`) so credentials never reach this sink.

### Acceptance Criteria
- [ ] `full_command` is redacted through `secrets_masker.redact` before logging
- [ ] Known sensitive CLI flags are stripped or masked
- [ ] Test added verifying secrets in CLI args are masked in audit logs
- [ ] Documentation updated on CLI secret handling in logs

### References
- Source Report: 16.2.5.md
- Related: LOGGING-3, ASVS-1625-MED-001, FINDING-013

### Priority
Medium

---
## Issue: FINDING-003 - `DagErrorHandler` unconditionally embeds the raw exception string in the API response, bypassing the generic-message control
**Labels:** security, priority:medium
**Description:**
### Summary
A `DeserializationError` raised during DAG deserialization has its `str(exc)` interpolated directly into the HTTP 500 `detail` field returned to the client. The sibling `_UniqueConstraintErrorHandler` checks `conf.get('api','expose_stacktrace')` and returns a generic message when not enabled, but `DagErrorHandler` ignores that pattern and always returns the raw exception text for a security-sensitive HTTP 500 condition, regardless of the production hardening configuration.

### Details
- **ASVS Sections:** 16.5.1
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/exceptions.py`

**Attacker Capability Required:** An authenticated API consumer able to trigger a DAG deserialization error.

**Impact:** Information disclosure through raw exception messages in production (no stack trace, but contradicts generic-message requirement).

### Remediation
Log the exception server-side with a correlation ID and gate raw exception text behind `api.expose_stacktrace`, returning a generic message with the correlation ID otherwise.

### Acceptance Criteria
- [ ] `DagErrorHandler` respects `api.expose_stacktrace` configuration
- [ ] Generic error message returned when stacktrace exposure is disabled
- [ ] Correlation ID included in error response
- [ ] Full exception details logged server-side with correlation ID
- [ ] Test added validating generic message behavior

### References
- Source Report: 16.5.1.md
- Related: ERROR_HANDLING-1, ASVS-1651-MED-001

### Priority
Medium

---
## Issue: FINDING-004 - Several Execution API query endpoints declare no authentication dependency
**Labels:** security, priority:medium
**Description:**
### Summary
Four endpoints in the Execution API (get_task_instance_count, get_previous_task_instance, get_task_instance_states, get_task_instance_breadcrumbs) are registered on the bare `router` without router-level `Security(require_auth, ...)` dependency. Unlike endpoints on `ti_id_router`, these four have no `Security(require_auth)` and no `route_class=ExecutionAPIRoute`. They accept arbitrary `dag_id` parameters, so they are not constrained by `ti:self` scope even if a token were required.

### Details
- **ASVS Sections:** 13.2.1
- **ASVS Level:** L2
- **CWE:** CWE-306 (Missing Authentication for Critical Function)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/execution_api/routes/task_instances.py`

**Attacker Capability Required:** Network reachability to the Execution API. If the parent `execution_api_router` does not attach a global `Security` dependency, any client reaching the endpoint can query task state for any DAG.

**Impact:** Disclosure of task-instance state, counts, operator names, and run history across DAGs — information disclosure on internal backend communication. No write/RCE capability.

### Remediation
Apply authentication consistently to these routes — either move them under a router carrying `Security(require_auth)`/`route_class=ExecutionAPIRoute`, or add the dependency explicitly to each endpoint. If cross-DAG querying is required by legitimate SDK callers (e.g., external task sensors), keep authentication mandatory and document the intentional broad read scope, rather than leaving the route without any `require_auth` dependency. Verify the parent `execution_api_router` does not already supply this before downgrading severity.

### Acceptance Criteria
- [ ] All four endpoints have authentication enforced
- [ ] Authentication mechanism consistent with other Execution API routes
- [ ] Test added verifying unauthenticated requests are rejected
- [ ] Documentation updated on cross-DAG query authorization model

### References
- Source Report: 13.2.1.md
- Related: SERVICE_COMMUNICATION-1, ASVS-1321-MED-001

### Priority
Medium

---
## Issue: FINDING-005 - Token revocation is not enforced on the Execution API token-validation path
**Labels:** security, priority:low
**Description:**
### Summary
Execution API request → JWTBearer → avalidated_claims (signature/claim checks only) → token accepted. The core-API path adds RevokedToken.is_revoked(jti) (see BaseAuthManager.get_user_from_token), but the execution-API path never consults the revocation table.

### Details
- **ASVS Sections:** 10.4.9
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/execution_api/security.py`

**Attacker Capability Required:** Possession of a still-unexpired execution/workload JWT (e.g., a leaked task-instance token); authenticated/privileged precondition.

**Impact:** A revoked-but-unexpired execution token would still be accepted by the Execution API. Because execution tokens are scoped to a single task instance (ti:self) and used for worker↔scheduler traffic, blast radius is narrow.

### Remediation
If execution tokens are ever to be revocable mid-flight, add a revocation check after claim validation: if (jti := claims.get("jti")) and RevokedToken.is_revoked(jti): raise HTTPException(status_code=403, detail="Token revoked"). Alternatively document explicitly that execution tokens are intentionally non-revocable and rely on short scope + completion-based invalidation.

### Acceptance Criteria
- [ ] Revocation check added to Execution API token validation OR
- [ ] Documentation explicitly states execution tokens are non-revocable with justification
- [ ] Test added validating revoked tokens are rejected (if revocation implemented)
- [ ] Architecture decision recorded

### References
- Source Report: 10.4.9.md
- Related: JWT-1, ASVS-1049-LOW-001

### Priority
Low

---
## Issue: FINDING-006 - Prior session token is not revoked when a renewed token is issued by the refresh middleware
**Labels:** security, priority:low
**Description:**
### Summary
Refresh middleware obtains a refreshed user, mints new_token, and sets it as the cookie. The previously valid current_token is not added to the revocation table; it remains valid until its own exp. During the original token's remaining lifetime both old and renewed token are accepted, slightly widening the window for a stolen-token replay.

### Details
- **ASVS Sections:** 7.2.4
- **ASVS Level:** L1
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

**Attacker Capability Required:** Authenticated precondition required; standard stateless-JWT behavior, and logout still revokes whatever token the client currently holds.

**Impact:** Overlapping token validity window during refresh allows temporary dual-token acceptance.

### Remediation
If overlapping-token windows are a concern, revoke the superseded jti when minting a replacement (get_auth_manager().revoke_token(current_token) before generate_jwt). Otherwise document the overlapping-validity window as accepted given short token lifetimes.

### Acceptance Criteria
- [ ] Old token revoked on refresh OR
- [ ] Overlapping-validity window documented and accepted
- [ ] Test added validating behavior (revocation or overlap)
- [ ] Security implications documented

### References
- Source Report: 7.2.4.md
- Related: JWT-2, ASVS-724-LOW-001

### Priority
Low

---
## Issue: FINDING-007 - Username Enumeration via Timing Side Channel in Login Flow
**Labels:** security, priority:low
**Description:**
### Summary
The login implementation in SimpleAuthManager uses a list comprehension with short-circuit evaluation that only invokes hmac.compare_digest() when user.username == body.username matches an existing user. For a non-existent username, no hmac comparison runs at all, so the request returns measurably faster than for an existing username with a wrong password. This creates a timing side channel that allows remote unauthenticated attackers to enumerate valid usernames through statistical timing analysis.

### Details
- **ASVS Sections:** 6.3.8
- **ASVS Level:** L3
- **CWE:** CWE-208 (Observable Timing Discrepancy)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py` (lines 57-72)

**Note:** This issue exists only in a development-only auth manager documented as unsuitable for production.

**Attacker Capability Required:** Remote unauthenticated access to the login endpoint.

**Impact:** Username enumeration through timing analysis.

### Remediation
Always perform a constant-time comparison against a dummy hash even when no username matches, so processing time does not depend on username existence. Example:
```python
DUMMY = 'x' * 16
matched = next((u for u in users if u.username == body.username), None)
stored = passwords.get(matched.username, DUMMY) if matched else DUMMY
password_ok = hmac.compare_digest(stored.encode(), body.password.encode())
if not matched or not password_ok:
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials')
```
This keeps one comparison on every code path regardless of username validity.

### Acceptance Criteria
- [ ] Constant-time comparison implemented for all login paths
- [ ] Test added measuring timing consistency
- [ ] Documentation notes this is development-only auth manager

### References
- Source Report: 6.3.8.md
- Related: AUTH-1, ASVS-638-LOW-001

### Priority
Low

---
## Issue: FINDING-008 - Single expiry knob serves both timeout roles; refresh middleware turns absolute expiry into a sliding window with no documented absolute cap
**Labels:** security, priority:low
**Description:**
### Summary
A single configuration value ([api_auth] jwt_expiration_time) is used as the only token lifetime parameter. When a concrete auth manager implements refresh_user, the middleware mints a brand-new token with a fresh full-length expiry on each request, so total session lifetime is unbounded relative to first authentication. The inactivity timeout and absolute maximum session lifetime are represented by one knob with no separate documented absolute lifetime ceiling.

### Details
- **ASVS Sections:** 7.1.1
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

**Impact:** The distinction ASVS 7.1.1 asks to be documented and justified is not present.

### Remediation
Document (and ideally enforce) two distinct values: an inactivity/refresh interval and an absolute maximum session lifetime, with justification for any deviation from NIST SP 800-63B re-authentication. To enforce an absolute cap, carry an immutable auth_time/session-start claim and refuse to refresh once now - auth_time > absolute_max.

### Acceptance Criteria
- [ ] Two distinct timeout values documented (inactivity and absolute)
- [ ] Absolute maximum session lifetime enforced via immutable claim
- [ ] NIST SP 800-63B compliance documented
- [ ] Configuration options added for both timeout types
- [ ] Test added validating absolute cap enforcement

### References
- Source Report: 7.1.1.md
- Related: SESSION-1, ASVS-711-LOW-001

### Priority
Low

---
## Issue: FINDING-009 - No distinct inactivity timeout; only fixed token expiry is enforced
**Labels:** security, priority:low
**Description:**
### Summary
The default refresh_user is a no-op, so the only timeout is the absolute jwt_expiration_time checked by JWTValidator. There is no separate inactivity-based expiry that resets on user activity and forces re-auth after a period of inactivity specifically. For default deployments token expiry does enforce eventual re-authentication; whether the chosen single value satisfies the documented risk analysis cannot be verified from code.

### Details
- **ASVS Sections:** 7.3.1
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

**Impact:** Acceptable for default config, but under-specified vs. requirement.

### Remediation
Either document that fixed token expiry is the accepted inactivity control (with justification), or implement an idle-timeout claim (last_seen) validated on each request and refreshed only on genuine activity.

### Acceptance Criteria
- [ ] Inactivity timeout mechanism implemented OR
- [ ] Fixed expiry documented as accepted inactivity control with risk justification
- [ ] Test added validating timeout behavior
- [ ] Risk analysis documented

### References
- Source Report: 7.3.1.md
- Related: SESSION-2, ASVS-731-LOW-001

### Priority
Low

---
## Issue: FINDING-010 - Refresh middleware can extend a session indefinitely with no absolute lifetime ceiling
**Labels:** security, priority:low
**Description:**
### Summary
An auth manager whose refresh_user returns a refreshed user feeds generate_jwt, which stamps a brand-new exp of jwt_expiration_time from now. With no immutable session-start (auth_time) claim and no comparison against an absolute maximum, each refresh resets the clock and total session lifetime is unbounded. Default base behavior is a no-op so default deployments retain a fixed absolute expiry, keeping severity low.

### Details
- **ASVS Sections:** 7.3.2
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

**Attacker Capability Required:** A compromised but still-valid token could be kept alive indefinitely under a refresh_user-capable auth manager.

**Impact:** Unbounded session lifetime when refresh is enabled.

### Remediation
Embed an immutable auth_time claim at first authentication and refuse refresh past the absolute ceiling. Document the absolute maximum and its NIST 800-63B justification.

### Acceptance Criteria
- [ ] Immutable auth_time claim added to tokens
- [ ] Absolute maximum session lifetime enforced
- [ ] NIST 800-63B justification documented
- [ ] Test added validating absolute ceiling enforcement
- [ ] Refresh rejection after ceiling implemented

### References
- Source Report: 7.3.2.md
- Related: SESSION-3, ASVS-732-LOW-001

### Priority
Low

---
## Issue: FINDING-011 - Refresh middleware resolves tokens via resolve_user_from_token, which must replicate the revocation check
**Labels:** security, priority:low
**Description:**
### Summary
A revoked-but-not-yet-expired token presented in the _token cookie is resolved by the middleware through resolve_user_from_token and, on success, sets request.state.user plus the trusted-middleware sentinel and may re-mint a fresh token. If resolve_user_from_token does not consult RevokedToken.is_revoked, a logged-out token would continue to authenticate and could be refreshed into a new valid token — defeating logout.

### Details
- **ASVS Sections:** 7.4.1
- **ASVS Level:** L1
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

**Impact:** The revocation check is present in get_user_from_token but its presence in the middleware's resolver cannot be confirmed from the supplied files.

### Remediation
Ensure resolve_user_from_token performs the same RevokedToken.is_revoked(jti) check as get_user_from_token, or have the middleware funnel through get_auth_manager().get_user_from_token(...). Add a regression test that revokes a token then asserts the refresh middleware rejects it.

### Acceptance Criteria
- [ ] Revocation check confirmed in resolve_user_from_token
- [ ] Test added validating revoked tokens rejected by refresh middleware
- [ ] Code review confirms consistent revocation checking

### References
- Source Report: 7.4.1.md
- Related: SESSION-4, ASVS-741-LOW-001

### Priority
Low

---
## Issue: FINDING-012 - Event-log list filter unconditionally returns all non-Dag (dag_id IS NULL) audit rows
**Labels:** security, priority:low
**Description:**
### Summary
PermittedEventLogFilter.to_orm returns the user's permitted-Dag logs plus every row where dag_id IS NULL. Data flow: authenticated user → list event-log endpoint (gated by generic AUDIT_LOG GET check) → filter returns global/non-Dag audit events to any audit-log reader.

### Details
- **ASVS Sections:** 8.2.2
- **ASVS Level:** L1
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/security.py`

**Impact:** Information disclosure of system-level audit events to users with access to only a subset of Dags; no write/priv-esc, bounded by the per-endpoint authorization gate. The object-level filter is intentionally broadened for the NULL case.

### Remediation
If non-Dag audit rows can carry sensitive context, gate the dag_id IS NULL branch behind an explicit 'global audit log' permission (e.g. an AccessView/admin check) rather than returning them to every audit-log reader.

### Acceptance Criteria
- [ ] Global audit events require explicit permission OR
- [ ] Design decision documented and accepted
- [ ] Test added validating authorization behavior
- [ ] Documentation updated on audit log access model

### References
- Source Report: 8.2.2.md
- Related: AUTHZ-1, ASVS-822-LOW-001

### Priority
Low

---
## Issue: FINDING-013 - Malformed query string returned unredacted to access log
**Labels:** security, priority:low
**Description:**
### Summary
On a malformed query string, `parse_qsl` raises `ValueError` and the raw query is returned and logged without secret redaction. A secret-looking parameter embedded in a deliberately malformed query could bypass redaction. `parse_qsl` rarely raises with `keep_blank_values=True`, and an attacker would expose only their own crafted value, so practical impact is minimal.

### Details
- **ASVS Sections:** 14.2.1, 16.4.1
- **ASVS Level:** L1, L2
- **CWE:** CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

**Impact:** Potential secret disclosure in logs via malformed query strings.

### Remediation
On the parse-failure branch, redact the raw string conservatively rather than returning it verbatim, e.g. pass the whole string through `secrets_masker.redact(query)`.

### Acceptance Criteria
- [ ] Malformed query strings redacted before logging
- [ ] Test added with malformed query containing secret-like values
- [ ] Verify redaction occurs on parse failure path

### References
- Source Report: 14.2.1.md, 16.4.1.md
- Related: SECRETS_MASKING-1, ASVS-1421-LOW-001, LOGGING-6, FINDING-002

### Priority
Low

---
## Issue: FINDING-014 - `FilterParam` CONTAINS branch does not escape LIKE wildcards
**Labels:** bug, priority:low
**Description:**
### Summary
The `FilterParam.to_orm` method's `CONTAINS` branch constructs a LIKE query without escaping LIKE metacharacters (`%`, `_`). While this does not create a SQL injection vulnerability (values are properly bound as parameters), it creates inconsistent behavior compared to other literal-match filters in the same file.

### Details
- **ASVS Sections:** 1.1.2
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/parameters.py`

**Impact:** LOW because no SQL injection risk (parameter binding provides interpreter-level escaping), limited impact (semantic over-matching of authorized rows), and no current exploitation path (no in-scope query parameter instantiates FilterParam with CONTAINS); it is a defense-in-depth/consistency concern.

### Remediation
Apply LIKE escaping consistent with other literal-match filters:

```python
if self.filter_option == FilterOptionEnum.CONTAINS:
    from sqlalchemy import Text, cast
    escaped = _escape_like_pattern(str(self.value))
    target = cast(self.attribute, Text) if str(self.attribute.type).upper() in ("JSON", "JSONB") else self.attribute
    return select.where(target.ilike(f"%{escaped}%", escape=_LIKE_ESCAPE_CHAR))
```

### Acceptance Criteria
- [ ] LIKE wildcard escaping implemented for CONTAINS filter
- [ ] Test added validating wildcard characters are escaped
- [ ] Consistency verified with other filter implementations

### References
- Source Report: 1.1.2.md
- Related: INPUT_VALIDATION-1, ASVS-112-LOW-001

### Priority
Low

---
## Issue: FINDING-015 - ConnectionBody.conn_type lacks positive allow-list/pattern/length validation
**Labels:** bug, priority:low
**Description:**
### Summary
API request → `conn_type` → used downstream to resolve hook/provider behaviour. No positive allow-list, pattern, or length range is applied. This field also lacks documented structure as required by ASVS 2.1.1.

### Details
- **ASVS Sections:** 2.1.1, 2.2.1
- **ASVS Level:** L1, L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py`

**Attacker Capability Required:** Authenticated user with connection-write permission.

**Impact:** Arbitrary string stored; functional misuse only, no injection path (ORM-parameterized). Bounded → Low.

**PoC:** `POST /api/v2/connections {"connection_id":"x","conn_type":"<4000-char string>"}` is accepted.

### Remediation
Document and enforce an expected structure for `conn_type` with length bounds and a conservative pattern:
```python
conn_type: str = Field(max_length=500, pattern=r"^[\w.\-]+$")
```
Also document and constrain free-text fields:
```python
description: str | None = Field(default=None, max_length=5000)
```

### Acceptance Criteria
- [ ] conn_type field has pattern and length validation
- [ ] Documentation added describing expected structure
- [ ] Test added validating rejection of invalid patterns
- [ ] Test added validating length limits

### References
- Source Report: 2.1.1.md, 2.2.1.md
- Related: INPUT_VALIDATION-2, ASVS-211-LOW-001, ASVS-221-LOW-001

### Priority
Low

---
## Issue: FINDING-016 - Request-tracing headers (x-request-id, correlation-id) are accepted from the client and used/echoed without provenance validation
**Labels:** security, priority:low
**Description:**
### Summary
Client-supplied x-request-id / correlation-id headers are bound into the structured log context and echoed into the response header without provenance validation. Data flow: client header → log context / response header → access logs and downstream log correlation.

### Details
- **ASVS Sections:** 4.1.3
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`
  - `airflow-core/src/airflow/api_fastapi/execution_api/app.py`

**Attacker Capability Required:** Any client able to set request headers.

**Impact:** Log-correlation forgery / log spoofing; no auth/authz/rate-limiting decision is made from these headers, so impact is limited to log/trace integrity. The echo cannot be used for CRLF/header-injection because Starlette/h11 reject control characters in header values.

### Remediation
When a trusted intermediary is expected to set these headers, configure the proxy to strip/overwrite them on ingress. If application-side hardening is desired, validate the format (e.g., require a UUID) and prefer regenerating a server-side ID when the header is absent or malformed.

### Acceptance Criteria
- [ ] Header validation implemented (UUID format) OR
- [ ] Proxy configuration documented to strip/overwrite headers OR
- [ ] Server-side ID generation when header invalid
- [ ] Test added validating header handling
- [ ] Documentation updated on tracing header handling

### References
- Source Report: 4.1.3.md
- Related: API-1, ASVS-413-LOW-001

### Priority
Low

---
## Issue: FINDING-017 - openapi_jsons mutates resp.body after Content-Length is computed, producing a Content-Length/body conflict
**Labels:** bug, priority:low
**Description:**
### Summary
CadwynWithOpenAPICustomization.openapi_jsons re-renders a larger body after Starlette has already computed and stored Content-Length, leaving a stale (shorter) Content-Length emitted with a longer body. Data flow: super().openapi_jsons() builds a JSONResponse with computed Content-Length → code reassigns resp.body with customized schema → stale header emitted at send time.

### Details
- **ASVS Sections:** 4.2.2
- **ASVS Level:** L3
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/execution_api/app.py`

**Attacker Capability Required:** Any client able to reach /execution/openapi.json; content is not attacker-controlled, the mismatch is deterministic.

**Impact:** Realistic outcome is a broken /openapi.json response or connection drop (h11 usually rejects the mismatch) rather than true smuggling — hence Low.

### Remediation
Construct a fresh response so headers are recomputed instead of mutating .body in place, or explicitly recompute `resp.headers['content-length'] = str(len(resp.body))`.

### Acceptance Criteria
- [ ] Content-Length correctly computed after body modification
- [ ] Test added validating Content-Length matches body
- [ ] /openapi.json endpoint returns valid response

### References
- Source Report: 4.2.2.md
- Related: API-2, ASVS-422-LOW-001

### Priority
Low

---
## Issue: FINDING-018 - correlation-id request header reflected into response header without CR/LF validation
**Labels:** security, priority:low
**Description:**
### Summary
CorrelationIdMiddleware.dispatch reflects the client-controlled correlation-id request header verbatim into a response header and into structlog context with no CR/LF or control-character validation.

### Details
- **ASVS Sections:** 4.2.4
- **ASVS Level:** L3
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/execution_api/app.py`

**Attacker Capability Required:** Any client able to set a correlation-id header.

**Impact:** Classic header-injection/response-splitting primitive, but inbound HTTP/2 (hpack/h2) and outbound HTTP/1.1 (h11/uvicorn) layers reject CR/LF in header values, so injection is blocked at the server layer — a defense-in-depth gap rather than an exploitable split. Application-level validation is absent.

### Remediation
Validate/sanitize the echoed value (e.g., allowlist regex `^[A-Za-z0-9._\-]{1,128}$`) before binding to log context and reflecting into the response header.

### Acceptance Criteria
- [ ] correlation-id header validated before reflection
- [ ] Test added validating rejection of invalid characters
- [ ] Test added validating length limits
- [ ] Documentation updated on header validation

### References
- Source Report: 4.2.4.md
- Related: API-3, ASVS-424-LOW-001

### Priority
Low

---
## Issue: FINDING-019 - JWT refresh-token cookie name lacks the `__Secure-`/`__Host-` prefix
**Labels:** security, priority:low
**Description:**
### Summary
Cookie name `_token` (COOKIE_NAME_JWT_TOKEN) carries no `__Secure-`/`__Host-` prefix, so the browser does not enforce secure-channel or host/path binding, allowing a related-domain attacker to overwrite the session/refresh token (session fixation / forced-login style).

### Details
- **ASVS Sections:** 3.3.1
- **ASVS Level:** L1
- **CWE:** CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`

**Impact:** Data flow: auth manager generates JWT → middleware writes it as cookie `_token` → browser stores cookie with no name-prefix binding. ASVS 3.3.1 requires the `__Secure-` prefix if `__Host-` is not used; neither is present.

### Remediation
Use a prefixed name. Because cookie_path is configurable, `__Host-` (which mandates Path=/, no Domain, and Secure) may not always be valid; at minimum adopt `__Secure-`: `COOKIE_NAME_JWT_TOKEN = "__Secure-_token"`, or `__Host-_token` when cookie_path == "/" and no Domain is set. Prefixed cookies are only honored when the Secure attribute is present.

### Acceptance Criteria
- [ ] Cookie name uses `__Secure-` prefix (minimum)
- [ ] Cookie name uses `__Host-` prefix when path="/" and no Domain
- [ ] Test added validating prefix enforcement
- [ ] Documentation updated on cookie security

### References
- Source Report: 3.3.1.md
- Related: COOKIE-1, ASVS-331-LOW-001, FINDING-020

### Priority
Low

---
## Issue: FINDING-020 - `Secure` attribute on the refresh-token cookie is conditional and can resolve to `False`
**Labels:** security, priority:low
**Description:**
### Summary
`secure = request.base_url.scheme == "https" or bool(conf.get("api", "ssl_cert", fallback=""))` can resolve to False when TLS is terminated at a proxy whose forwarded-proto is not honored and ssl_cert is empty, causing the browser to transmit the JWT cookie over plaintext HTTP and rendering any name prefix ineffective.

### Details
- **ASVS Sections:** 3.3.1
- **ASVS Level:** L1
- **CWE:** CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

**Impact:** Pure TLS termination/proxy header handling is delegated infrastructure; the in-scope defect is the application logic that can silently emit a non-Secure sensitive cookie.

### Remediation
Default Secure to True for this sensitive cookie and require an explicit opt-out only for documented local-dev scenarios; ensure forwarded-proto is trusted via the proxy middleware.

### Acceptance Criteria
- [ ] Secure attribute defaults to True
- [ ] Explicit configuration required to disable (dev-only)
- [ ] Proxy middleware configured to trust forwarded-proto
- [ ] Test added validating Secure attribute set
- [ ] Documentation warns about disabling Secure

### References
- Source Report: 3.3.1.md
- Related: COOKIE-2, ASVS-331-LOW-002, FINDING-019

### Priority
Low

---
## Issue: FINDING-021 - Session/refresh-token cookie does not use the `__Host-` prefix despite being host-scoped
**Labels:** security, priority:low
**Description:**
### Summary
JWT issued by auth manager is written as cookie `_token` with no `Domain` set but a configurable `path`; browser stores without host-binding enforcement. An attacker controlling or compromising a sibling subdomain could plant a `_token` cookie that the application accepts, enabling cookie overwrite/fixation. The `__Host-` prefix would force the browser to reject any cookie carrying a `Domain` attribute and require `Path=/` + `Secure`.

### Details
- **ASVS Sections:** 3.3.3
- **ASVS Level:** L2
- **CWE:** CWE-16 (Configuration)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py`
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

**Impact:** Adoption must be conditional on `cookie_path == "/"` (otherwise fall back to `__Secure-`).

### Remediation
When `cookie_path == "/"` and no `Domain` is set, use `COOKIE_NAME_JWT_TOKEN = "__Host-_token"`; this requires `secure=True` and `path="/"`. Pair with the always-Secure change (ASVS-331-LOW-002), since `__Host-` cookies are ignored unless `Secure` is set.

### Acceptance Criteria
- [ ] `__Host-` prefix used when cookie_path="/" and no Domain
- [ ] Fallback to `__Secure-` for other configurations
- [ ] Test added validating prefix behavior
- [ ] Documentation updated on cookie prefix requirements

### References
- Source Report: 3.3.3.md
- Related: COOKIE-3, ASVS-333-LOW-001

### Priority
Low

---
## Issue: FINDING-022 - No length check on JWT cookie value before writing Set-Cookie
**Labels:** bug, priority:low
**Description:**
### Summary
serialize_user(user) → JWT claims → JWTGenerator.generate() → new_token → set_cookie; token length is never validated against the 4096-byte browser limit. A concrete auth manager (e.g., an external IdP packing many claims/groups) could produce a JWT exceeding 4096 bytes, causing the browser to silently drop the cookie and a hard-to-diagnose login/redirect loop.

### Details
- **ASVS Sections:** 3.3.5
- **ASVS Level:** L3
- **CWE:** CWE-400 (Uncontrolled Resource Consumption)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py`

**Impact:** No confidentiality/integrity impact — availability/correctness foot-gun only.

### Remediation
Validate combined name+value length at the write site and fail loudly (log error / fall back) instead of emitting a cookie the browser will discard.

### Acceptance Criteria
- [ ] Cookie length validation implemented (4096 byte limit)
- [ ] Error logged when cookie exceeds limit
- [ ] Graceful fallback or rejection implemented
- [ ] Test added validating length check

### References
- Source Report: 3.3.5.md
- Related: COOKIE-4, ASVS-335-LOW-001

### Priority
Low

---
## Issue: FINDING-023 - Unchecked `as JSON` type assertion on parsed user JSON
**Labels:** bug, priority:low
**Description:**
### Summary
Location: `airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx`, `handleChange` (lines ~29-42); `airflow-core/src/airflow/ui/src/components/ConfigForm.tsx`, `validateAndPrettifyJson` (lines ~44-63). Data flow: user JSON text (JsonEditor) → `JSON.parse(...) as JSON` → stored as `param.value` / form `conf`. The `as JSON` assertion tells the compiler the result is a specific type without runtime verification.

### Details
- **ASVS Sections:** 15.3.5
- **ASVS Level:** L2
- **CWE:** CWE-843 (Access of Resource Using Incompatible Type)
- **Affected Files:**
  - `airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx` (lines 29-42)
  - `airflow-core/src/airflow/ui/src/components/ConfigForm.tsx` (lines 44-63)

**Attacker Capability Required:** An authenticated UI user editing a DAG trigger config; the parsed value is sent to the server, which performs authoritative validation.

**Impact:** No direct C/I/A impact — a type-confusion foot-gun in client code; server-side validation is the real control. Defense-in-depth/code-quality issue, not an exploitable vulnerability.

### Remediation
Avoid blanket `as JSON` casts; validate the parsed shape before use (parse into `unknown` then narrow with a runtime guard before assigning).

### Acceptance Criteria
- [ ] Type assertions replaced with runtime validation
- [ ] Parse to `unknown` then validate shape
- [ ] Test added validating type safety
- [ ] TypeScript strict mode compliance verified

### References
- Source Report: 15.3.5.md
- Related: UI_INPUT-1, ASVS-1535-LOW-001

### Priority
Low

---
## Issue: FINDING-024 - Object literals used for key/value collections instead of Map/Set
**Labels:** bug, priority:low
**Description:**
### Summary
Location: `airflow-core/src/airflow/ui/src/components/FilterBar/FilterBar.tsx`, `updateFiltersRecord` (lines ~75-84); `airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx`, `handleChange` (lines ~29-42). Data flow: filter keys (`filter.config.key`) originate from developer-defined `FilterConfig` objects, not user input; param `name` comes from the DAG-provided schema. JSON-parsed user content is stored as a leaf `value`, never iterated to assign attacker-named keys.

### Details
- **ASVS Sections:** 15.3.6
- **ASVS Level:** L2
- **CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
- **Affected Files:**
  - `airflow-core/src/airflow/ui/src/components/FilterBar/FilterBar.tsx` (lines 75-84)
  - `airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx` (lines 29-42)

**Attacker Capability Required:** None practical — bracket-assignment keys are not user-controlled, so the classic `__proto__`/`constructor` injection vector is not reachable.

**Impact:** No realistic exploit path; flagged only because 15.3.6 recommends `Map()`/`Set()` over object literals as defense-in-depth. Residual risk minimal since keys are trusted.

### Remediation
Where collections accumulate values by key, prefer `Map` to structurally eliminate prototype-chain interaction; if object literals must be retained, create them with `Object.create(null)` and reject `__proto__`/`constructor`/`prototype` keys if any key could become user-influenced in the future.

### Acceptance Criteria
- [ ] Object literals replaced with Map/Set where appropriate OR
- [ ] Object.create(null) used for object literals
- [ ] Prototype pollution prevention verified
- [ ] Test added validating safe key handling

### References
- Source Report: 15.3.6.md
- Related: UI_INPUT-2, ASVS-1536-LOW-001

### Priority
Low

---
## Issue: FINDING-025 - HTTP access log omits authenticated principal (who) metadata
**Labels:** bug, priority:low
**Description:**
### Summary
The HTTP access log captures where (`client_addr`, `path`), what (`method`, `status_code`), and a correlation handle (`request_id`), but does not capture the authenticated user/principal. The DB `Log` model and CLI action logger both capture owner/user, so this gap is specific to the HTTP access stream.

### Details
- **ASVS Sections:** 16.2.1
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

**Impact:** Investigative-completeness gap, not an exploit path.

### Remediation
After authentication resolves, bind the resolved principal to the structlog context (e.g., `structlog.contextvars.bind_contextvars(user_id=principal.id)`) so the access-log event includes the authenticated subject when available.

### Acceptance Criteria
- [ ] Authenticated principal logged in HTTP access log
- [ ] structlog context binding implemented
- [ ] Test added validating principal appears in logs
- [ ] Documentation updated on access log format

### References
- Source Report: 16.2.1.md
- Related: LOGGING-1, ASVS-1621-LOW-001

### Priority
Low

---
## Issue: FINDING-026 - HTTP access log relies on externally-configured structlog processor for UTC/offset timestamp
**Labels:** bug, priority:low
**Description:**
### Summary
The middleware emits `duration_us` but never attaches an explicit wall-clock event timestamp; whether the entry carries a UTC/offset-bearing timestamp depends entirely on the structlog processor chain configured elsewhere. The DB `Log` model and CLI logger both pin UTC explicitly; the HTTP access stream does not.

### Details
- **ASVS Sections:** 16.2.2
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

**Impact:** Configuration-robustness/timeline-ambiguity gap (note: NTP time-source sync across hosts remains deployment-managed and out of scope).

### Remediation
Ensure the structlog processor chain for this logger includes a UTC timestamper (`TimeStamper(fmt='iso', utc=True)`), or attach the timestamp explicitly at emit time using `timezone.utcnow().isoformat()`.

### Acceptance Criteria
- [ ] UTC timestamp explicitly added to log entries OR
- [ ] structlog processor chain verified to include UTC timestamper
- [ ] Test added validating timestamp format and timezone
- [ ] Documentation updated on timestamp requirements

### References
- Source Report: 16.2.2.md
- Related: LOGGING-2, ASVS-1622-LOW-001

### Priority
Low

---
## Issue: FINDING-027 - Attacker-controlled request fields logged without CR/LF neutralization
**Labels:** security, priority:low
**Description:**
### Summary
The redaction step (`secrets_masker.redact`) neutralizes secret values but does not strip CR/LF or other control characters. Unlike the stdlib audit path (which has `_sanitize_for_stdlib_log`), the structlog access path has no equivalent sanitization and depends on the renderer to encode control characters. An attacker can place arbitrary (URL-decoded) bytes in the request path/query. If a deployment configures structlog with a plain-text/console renderer rather than the default JSON renderer, embedded `\n`/`\r` could forge additional log lines (CWE-117).

### Details
- **ASVS Sections:** 16.4.1
- **ASVS Level:** L2
- **CWE:** CWE-117 (Improper Output Neutralization for Logs)
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/http_access_log.py`

**Impact:** In the default JSON-rendered configuration this is fully mitigated, hence Low.

### Remediation
Apply CR/LF (and other control-character) neutralization to attacker-controlled string fields before they enter the logger, mirroring the existing stdlib helper, so protection does not depend on renderer choice.

### Acceptance Criteria
- [ ] CR/LF neutralization implemented for request fields
- [ ] Control character sanitization added
- [ ] Test added validating neutralization with various inputs
- [ ] Works regardless of structlog renderer configuration

### References
- Source Report: 16.4.1.md
- Related: LOGGING-5, ASVS-1641-LOW-001

### Priority
Low

---
## Issue: FINDING-028 - _UniqueConstraintErrorHandler.exception_handler silently falls through when dialect prefix is not matched
**Labels:** bug, priority:low
**Description:**
### Summary
An IntegrityError whose str(exc.orig) does not contain one of the three known dialect prefixes causes the handler to return None without raising or returning a Response, neither surfacing a structured failure nor logging. This is a fail-soft path violating the fail-closed expectation.

### Details
- **ASVS Sections:** 16.5.3
- **ASVS Level:** L2
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/exceptions.py`

**Impact:** Low real-world impact because all officially supported backends are covered by the prefix list.

### Remediation
Re-raise (or return a controlled generic 500/409) and log the unmatched error when no dialect matches.

### Acceptance Criteria
- [ ] Handler re-raises or returns controlled response on unmatched dialect
- [ ] Unmatched errors logged with details
- [ ] Test added validating behavior with unknown dialect
- [ ] No silent failures

### References
- Source Report: 16.5.3.md
- Related: ERROR_HANDLING-2, ASVS-1653-LOW-001

### Priority
Low

---
## Issue: FINDING-029 - `DagErrorHandler` raises without server-side logging, losing error details for unhandled deserialization failures
**Labels:** bug, priority:low
**Description:**
### Summary
Unlike `_UniqueConstraintErrorHandler`, which logs the assembled stacktrace with a correlation ID, `DagErrorHandler` performs no logging at all before raising. A 500-class deserialization failure therefore leaves no dedicated server-side log record, degrading incident response and monitoring.

### Details
- **ASVS Sections:** 16.5.4
- **ASVS Level:** L3
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/api_fastapi/common/exceptions.py`

**Impact:** Operational/forensics weakness, not directly attacker-driven.

### Remediation
Add `log.error(...)` with a correlation ID before raising, and surface the correlation ID instead of the raw exception.

### Acceptance Criteria
- [ ] Server-side logging added before raising
- [ ] Correlation ID generated and logged
- [ ] Correlation ID included in error response
- [ ] Test added validating logging occurs

### References
- Source Report: 16.5.4.md
- Related: ERROR_HANDLING-3, ASVS-1654-LOW-001

### Priority
Low

---
## Issue: FINDING-030 - Individually-owned scoped dependency increases supply-chain / dependency-confusion surface
**Labels:** security, priority:low
**Description:**
### Summary
Location: `airflow-core/src/airflow/ui/package.json:34` — `"@guanmingchiu/sqlparser-ts": "^0.61.1"`. Data flow: dependency resolution → public npm registry → individually-maintained scope `@guanmingchiu` → bundled into UI build. A caret range on an individually-owned scoped package means a future compromised minor/patch release would be picked up automatically (subject to release-age delay).

### Details
- **ASVS Sections:** 15.2.4
- **ASVS Level:** L3
- **CWE:** Not specified
- **Affected Files:**
  - `airflow-core/src/airflow/ui/package.json` (line 34)

**Attacker Capability Required:** Compromise of an upstream single-maintainer npm package — not an attacker capability against Airflow directly.

**Impact:** Malicious code execution in the UI build/runtime if a compromised version is published and resolved. Why Low: no demonstrated exploit path; `minimumReleaseAge` and lockfile-based integrity substantially mitigate.

### Remediation
Continue to rely on `pnpm-lock.yaml` with integrity hashes committed to the repo, and ensure the resolved registry for all scopes is pinned via an `.npmrc` that forbids fallback to a public registry for internal scopes. Consider replacing single-maintainer parsing libraries with better-maintained alternatives, or vendoring/pinning to an exact version with hash verification.

### Acceptance Criteria
- [ ] pnpm-lock.yaml with integrity hashes committed
- [ ] .npmrc configured to pin registry for all scopes
- [ ] Evaluation of alternative libraries documented OR
- [ ] Exact version pinning with hash verification implemented
- [ ] Supply-chain security policy documented

### References
- Source Report: 15.2.4.md
- Related: DEPENDENCY_MANAGEMENT-1, ASVS-1524-LOW-001

### Priority
Low

---
## Issue: FINDING-031 - Filesystem check-then-act in latest-log symlink creation
**Labels:** bug, priority:low
**Description:**
### Summary
File: `airflow-core/src/airflow/dag_processing/manager.py`, function `_symlink_latest_log_directory` (~line 1138). Data flow: filesystem state (`os.path.islink` / `os.path.isdir` / `os.path.isfile`) → decision branch → `os.unlink` + `os.symlink` (the dependent action) are separate, non-atomic syscalls. Between the `islink` check and the `unlink`/`symlink`, the entry can be replaced — the classic TOCTOU pattern.

### Details
- **ASVS Sections:** 15.4.2
- **ASVS Level:** L3
- **CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)
- **Affected Files:**
  - `airflow-core/src/airflow/dag_processing/manager.py` (line 1138)

**Attacker Capability Required:** Local write access to the parent of the DAG-processor log directory — a privileged location normally owned by the Airflow service account.

**Impact:** At most redirection of the convenience `latest` symlink within a privileged, service-owned directory; bounded by the surrounding `try/except OSError`. No remote impact, no data-integrity impact on task state. Why Low: requires local privileged co-residence in a service-owned directory and the outcome is limited to a log convenience symlink.

### Remediation
Make the replacement atomic by creating a uniquely-named temp symlink and `os.replace`/`os.rename` it into place, so no observable check-then-act window exists.

### Acceptance Criteria
- [ ] Atomic symlink replacement implemented
- [ ] Temp symlink created with unique name
- [ ] os.replace/os.rename used for atomic operation
- [ ] Test added validating atomic behavior
- [ ] TOCTOU window eliminated

### References
- Source Report: 15.4.2.md
- Related: CONCURRENCY-1, ASVS-1542-LOW-001

### Priority
Low