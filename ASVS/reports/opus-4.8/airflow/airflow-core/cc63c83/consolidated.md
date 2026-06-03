# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/airflow-core |
| ASVS Level | L3 |
| Severity Threshold | none (all findings included) |
| Commit | cc63c83 |
| Date | Jun 03, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 345 |
| Total Findings | 35 |
| Actionable Issues | 31 |

*Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the 31 actionable items.*

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0     |
| High     | 0     |
| Medium   | 4     |
| Low      | 27    |
| Info     | 4     |

### ASVS Level Coverage

This audit was conducted against ASVS Level 3 (L3), the most rigorous verification tier, with all findings included regardless of severity threshold. Coverage spans authentication, session and JWT lifecycle management, authorization, cryptographic operations, logging/audit, input validation, and supply-chain controls across the audited directories.

### Top 5 Risks

1. **Shared audience and signing key across Core API and Execution API tokens** [Medium] — A single audience and signing key are reused for both services, so audience restriction cannot uniquely identify the intended service and a token issued for one API is accepted by the other.
2. **Unauthenticated Execution API query endpoints** [Medium] — Several Execution API query endpoints declare no authentication dependency, exposing them to unauthenticated access.
3. **Raw CLI argv persisted without secret masking** [Medium] — `default_action_log` writes the raw `full_command` (CLI argv) to the metadata DB without secret masking, risking exposure of credentials embedded in command lines.
4. **Raw exception strings leaked in API responses** [Medium] — `DagErrorHandler` unconditionally embeds the raw exception string in the API response, bypassing the generic-message control and disclosing internal details.
5. **Session refresh enables indefinite session extension** [Low] — The refresh middleware converts absolute token expiry into a sliding window with no documented absolute lifetime ceiling, allowing sessions to be extended indefinitely.

### Positive Controls Observed

- **Constant-time password comparison** using `hmac.compare_digest` with an empty-string fallback preserving constant-time behaviour when a password entry is missing.
- **Uniform invalid-credential response** — a single generic 401 regardless of which credential was wrong, avoiding message-based user enumeration.
- **Cryptographically strong password generation** using the `secrets` module (CSPRNG) over a 16-character ambiguity-reduced alphabet (~90 bits entropy), generated once under an exclusive file lock.
- **No hardcoded default credentials** — accounts and passwords are operator-configured or randomly generated; passwordless admin mode is opt-in behind `simple_auth_manager_all_admins`.
- **Consistent authentication pathway gating** — all login routes converge on `get_auth_manager().generate_jwt` and route through `create_token_all_admins`, with a single gating flag governing all passwordless pathways.
- **Open-redirect protection** — the `next` query parameter is validated with `is_safe_url` before use, falling back to the configured base URL.
- **Secure cookie attributes on the JWT cookie** — `httponly=True`, `samesite=lax`, with `secure` derived from HTTPS scheme or configured `ssl_cert`.
- **Production-shape warning** — a loud startup warning is emitted when the dev-only auth manager is used in a production-shaped deployment.
- **Pluggable `BaseAuthManager` extension point** enabling MFA-capable production auth managers to replace the dev-only one.
- **jti-based RevokedToken list** consulted on every validation path in `get_user_from_token`, with expired-entry pruning and a persistence layer backing user-scoped/admin revocation.
- **Single FernetProtocol seam** (`get_fernet()`) for all at-rest secret encryption, with `MultiFernet` staged key rotation and full re-encryption via `rotate_fernet_key()`.
- **Secrets-masking data controls** — server-side caching avoids retaining sensitive data, sensitive data is not sent to untrusted third parties, logging controls for sensitive data are defined, and browser storage is properly scoped.
- **Client-side security controls** — allowlist-based external-redirect validation, no JSONP/legacy insecure plugins, safe text-rendering functions, DOM-clobbering protections, and context-rendering protections.
- **Logging/audit maturity** — documented logging inventory, restriction to documented sinks, a common parseable structured format, and logging of security events and control-bypass/failure conditions.
- **Dependency-management integrity** — `pnpm-lock.yaml` with integrity hashes committed and a `minimumReleaseAge` delay mitigating compromised-release uptake.
- **Mass-assignment protection** in place for UI input handling.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: Core API and Execution API tokens share a single audience and signing key, so audience restriction does not uniquely identify the intended service

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 9.2.4 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/tokens.py, airflow-core/src/airflow/api_fastapi/execution_api/security.py |
| **Source Report(s)** | 9.2.4.md |
| **Related Finding(s)** | None |

**Description:**

A signing key is resolved once via `get_signing_args()` and is shared by all issuers. The audience is a single value (`apache-airflow`) for the Core API. The Execution API validator validates the same audience and the same key. Because the audience does not differentiate "Core API user token" from "Execution API task token," a token minted for the Core API audience also satisfies the Execution API's audience check. The only remaining isolation is the `scope` claim (which defaults to `execution` when absent) and the `ti:self` route scope (only enforced on opted-in routes). A Core API user JWT (no `scope` claim → defaults to `execution`, arbitrary `sub` accepted by `TIClaims`) would therefore pass crypto + audience + claims validation on any Execution API route that does not declare `ti:self`. Attacker capability required: an authenticated Core API user with network reachability to the Execution API. Impact: cross-service token usage allowing calls to worker-to-scheduler endpoints with a user token on non-`ti:self` endpoints. Note: the profile's acceptance of symmetric/shared key mode covers key sharing between api-server and scheduler, but does not address audience/scope separation between the Core and Execution API surfaces, so this application-logic defect remains in scope.

**Remediation:**

Issue distinct audiences per service when reusing the same private key, and require the audience the receiving service expects (e.g. `apache-airflow-api` for Core API, `apache-airflow-execution` for Execution API). Validate the service-specific audience in each validator, and stop defaulting `scope` to `execution` — require an explicit `scope` claim for execution-API tokens so an audience/scope-less token cannot be silently treated as a task token.

---

#### FINDING-002: `default_action_log` persists raw `full_command` (CLI argv) to the metadata DB without secret masking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-532 |
| **ASVS Section(s)** | 16.2.5 |
| **File(s)** | airflow-core/src/airflow/utils/cli_action_loggers.py |
| **Source Report(s)** | 16.2.5.md |
| **Related Finding(s)** | FINDING-013 |

**Description:**

`full_command` (the complete argv) is serialized verbatim into the `extra` JSON column of the `log` table with no masking/redaction, unlike the HTTP access path which runs `secrets_masker`. CLI subcommands routinely carry secrets as arguments (passwords, connection URIs with embedded credentials, tokens), so any such credential is durably persisted in cleartext, readable by any principal with audit-log access. This is a documented sensitive-value-masking control (per `secrets/index.rst` / `mask-sensitive-values`) not being applied at this sink. Requires a reader of the metadata DB/audit log plus another user having passed a secret on a CLI argument; not remotely exploitable by an unauthenticated attacker.

**Remediation:**

Apply `secrets_masker.redact` to the command vector before serialization, and ensure the upstream `action_logging` builder strips/redacts known sensitive flags (e.g., `--password`, `--conn-uri`) so credentials never reach this sink.

---

#### FINDING-003: `DagErrorHandler` unconditionally embeds the raw exception string in the API response, bypassing the generic-message control

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | N/A |
| **ASVS Section(s)** | 16.5.1 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/common/exceptions.py |
| **Source Report(s)** | 16.5.1.md |
| **Related Finding(s)** | None |

**Description:**

A `DeserializationError` raised during DAG deserialization has its `str(exc)` interpolated directly into the HTTP 500 `detail` field returned to the client. The sibling `_UniqueConstraintErrorHandler` checks `conf.get('api','expose_stacktrace')` and returns a generic message when not enabled, but `DagErrorHandler` ignores that pattern and always returns the raw exception text for a security-sensitive HTTP 500 condition, regardless of the production hardening configuration. Requires an authenticated API consumer able to trigger a DAG deserialization error. Limited sensitivity (no stack trace), but contradicts the generic-message requirement.

**Remediation:**

Log the exception server-side with a correlation ID and gate raw exception text behind `api.expose_stacktrace`, returning a generic message with the correlation ID otherwise.

---

#### FINDING-004: Several Execution API query endpoints declare no authentication dependency

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-306 |
| **ASVS Section(s)** | 13.2.1 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/execution_api/routes/task_instances.py |
| **Source Report(s)** | 13.2.1.md |
| **Related Finding(s)** | None |

**Description:**

Four endpoints in the Execution API (get_task_instance_count, get_previous_task_instance, get_task_instance_states, get_task_instance_breadcrumbs) are registered on the bare `router` without router-level `Security(require_auth, ...)` dependency. Unlike endpoints on `ti_id_router`, these four have no `Security(require_auth)` and no `route_class=ExecutionAPIRoute`. They accept arbitrary `dag_id` parameters, so they are not constrained by `ti:self` scope even if a token were required. Data flow: unauthenticated/cross-scope HTTP request (`dag_id`, `run_ids`, `states`, etc.) → query against `TaskInstance`/`DagRun` → returns task counts/states/breadcrumbs/previous-TI metadata across DAGs, with no `require_auth` dependency at the route or router level. Attacker capability: Network reachability to the Execution API. If the parent `execution_api_router` (not in audit scope) does not attach a global `Security` dependency, any client reaching the endpoint can query task state for any DAG. If it does, the residual issue is missing `ti:self`/scope narrowing (cross-task information access with any valid execution token). Impact: Disclosure of task-instance state, counts, operator names, and run history across DAGs — information disclosure on internal backend communication. No write/RCE capability.

**Remediation:**

Apply authentication consistently to these routes — either move them under a router carrying `Security(require_auth)`/`route_class=ExecutionAPIRoute`, or add the dependency explicitly to each endpoint. If cross-DAG querying is required by legitimate SDK callers (e.g., external task sensors), keep authentication mandatory and document the intentional broad read scope, rather than leaving the route without any `require_auth` dependency. Verify the parent `execution_api_router` does not already supply this before downgrading severity.

### 3.4 Low

#### FINDING-005: Token revocation is not enforced on the Execution API token-validation path

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 10.4.9 |
| **Files** | airflow-core/src/airflow/api_fastapi/execution_api/security.py |
| **Source Reports** | 10.4.9.md |
| **Related** | - |

**Description:**

Execution API request → JWTBearer → avalidated_claims (signature/claim checks only) → token accepted. The core-API path adds RevokedToken.is_revoked(jti) (see BaseAuthManager.get_user_from_token), but the execution-API path never consults the revocation table. Attacker capability required: possession of a still-unexpired execution/workload JWT (e.g., a leaked task-instance token); authenticated/privileged precondition. Impact: a revoked-but-unexpired execution token would still be accepted by the Execution API. Because execution tokens are scoped to a single task instance (ti:self) and used for worker↔scheduler traffic, blast radius is narrow. Low because this is a defense-in-depth gap on an internal API surface; task-instance tokens are tightly scoped; no remote-unauth path and no broad C/I/A impact.

**Remediation:**

If execution tokens are ever to be revocable mid-flight, add a revocation check after claim validation: if (jti := claims.get("jti")) and RevokedToken.is_revoked(jti): raise HTTPException(status_code=403, detail="Token revoked"). Alternatively document explicitly that execution tokens are intentionally non-revocable and rely on short scope + completion-based invalidation.

---

#### FINDING-006: Prior session token is not revoked when a renewed token is issued by the refresh middleware

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| **Source Reports** | 7.2.4.md |
| **Related** | - |

**Description:**

Refresh middleware obtains a refreshed user, mints new_token, and sets it as the cookie. The previously valid current_token is not added to the revocation table; it remains valid until its own exp. During the original token's remaining lifetime both old and renewed token are accepted, slightly widening the window for a stolen-token replay. Authenticated precondition required; standard stateless-JWT behavior, and logout still revokes whatever token the client currently holds.

**Remediation:**

If overlapping-token windows are a concern, revoke the superseded jti when minting a replacement (get_auth_manager().revoke_token(current_token) before generate_jwt). Otherwise document the overlapping-validity window as accepted given short token lifetimes.

---

#### FINDING-007: Username Enumeration via Timing Side Channel in Login Flow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-208 |
| **ASVS sections** | 6.3.8 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:57-72 |
| **Source Reports** | 6.3.8.md |
| **Related** | - |

**Description:**

The login implementation in SimpleAuthManager uses a list comprehension with short-circuit evaluation that only invokes hmac.compare_digest() when user.username == body.username matches an existing user. For a non-existent username, no hmac comparison runs at all, so the request returns measurably faster than for an existing username with a wrong password. This creates a timing side channel that allows remote unauthenticated attackers to enumerate valid usernames through statistical timing analysis. The error message and HTTP status are uniform, but the processing time differential reveals username existence. This issue exists only in a development-only auth manager documented as unsuitable for production.

**Remediation:**

Always perform a constant-time comparison against a dummy hash even when no username matches, so processing time does not depend on username existence. Example: DUMMY = 'x' * 16; matched = next((u for u in users if u.username == body.username), None); stored = passwords.get(matched.username, DUMMY) if matched else DUMMY; password_ok = hmac.compare_digest(stored.encode(), body.password.encode()); if not matched or not password_ok: raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials'). This keeps one comparison on every code path regardless of username validity.

---

#### FINDING-008: Single expiry knob serves both timeout roles; refresh middleware turns absolute expiry into a sliding window with no documented absolute cap

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 7.1.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| **Source Reports** | 7.1.1.md |
| **Related** | - |

**Description:**

A single configuration value ([api_auth] jwt_expiration_time) is used as the only token lifetime parameter. When a concrete auth manager implements refresh_user, the middleware mints a brand-new token with a fresh full-length expiry on each request, so total session lifetime is unbounded relative to first authentication. The inactivity timeout and absolute maximum session lifetime are represented by one knob with no separate documented absolute lifetime ceiling — the distinction ASVS 7.1.1 asks to be documented and justified.

**Remediation:**

Document (and ideally enforce) two distinct values: an inactivity/refresh interval and an absolute maximum session lifetime, with justification for any deviation from NIST SP 800-63B re-authentication. To enforce an absolute cap, carry an immutable auth_time/session-start claim and refuse to refresh once now - auth_time > absolute_max.

---

#### FINDING-009: No distinct inactivity timeout; only fixed token expiry is enforced (acceptable for default config, under-specified vs. requirement)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 7.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 7.3.1.md |
| **Related** | - |

**Description:**

The default refresh_user is a no-op, so the only timeout is the absolute jwt_expiration_time checked by JWTValidator. There is no separate inactivity-based expiry that resets on user activity and forces re-auth after a period of inactivity specifically. For default deployments token expiry does enforce eventual re-authentication; whether the chosen single value satisfies the documented risk analysis cannot be verified from code.

**Remediation:**

Either document that fixed token expiry is the accepted inactivity control (with justification), or implement an idle-timeout claim (last_seen) validated on each request and refreshed only on genuine activity.

---

#### FINDING-010: Refresh middleware can extend a session indefinitely with no absolute lifetime ceiling

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 7.3.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 7.3.2.md |
| **Related** | - |

**Description:**

An auth manager whose refresh_user returns a refreshed user feeds generate_jwt, which stamps a brand-new exp of jwt_expiration_time from now. With no immutable session-start (auth_time) claim and no comparison against an absolute maximum, each refresh resets the clock and total session lifetime is unbounded. Default base behavior is a no-op so default deployments retain a fixed absolute expiry, keeping severity low. A compromised but still-valid token could be kept alive indefinitely under a refresh_user-capable auth manager.

**Remediation:**

Embed an immutable auth_time claim at first authentication and refuse refresh past the absolute ceiling. Document the absolute maximum and its NIST 800-63B justification.

---

#### FINDING-011: Refresh middleware resolves tokens via resolve_user_from_token, which must replicate the revocation check that get_user_from_token performs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 7.4.1.md |
| **Related** | - |

**Description:**

A revoked-but-not-yet-expired token presented in the _token cookie is resolved by the middleware through resolve_user_from_token and, on success, sets request.state.user plus the trusted-middleware sentinel and may re-mint a fresh token. If resolve_user_from_token does not consult RevokedToken.is_revoked, a logged-out token would continue to authenticate and could be refreshed into a new valid token — defeating logout. The revocation check is present in get_user_from_token but its presence in the middleware's resolver cannot be confirmed from the supplied files.

**Remediation:**

Ensure resolve_user_from_token performs the same RevokedToken.is_revoked(jti) check as get_user_from_token, or have the middleware funnel through get_auth_manager().get_user_from_token(...). Add a regression test that revokes a token then asserts the refresh middleware rejects it.

---

#### FINDING-012: Event-log list filter unconditionally returns all non-Dag (dag_id IS NULL) audit rows

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| **Source Reports** | 8.2.2.md |
| **Related** | - |

**Description:**

PermittedEventLogFilter.to_orm returns the user's permitted-Dag logs plus every row where dag_id IS NULL. Data flow: authenticated user → list event-log endpoint (gated by generic AUDIT_LOG GET check) → filter returns global/non-Dag audit events to any audit-log reader. Impact: information disclosure of system-level audit events to users with access to only a subset of Dags; no write/priv-esc, bounded by the per-endpoint authorization gate. The object-level filter is intentionally broadened for the NULL case.

**Remediation:**

If non-Dag audit rows can carry sensitive context, gate the dag_id IS NULL branch behind an explicit 'global audit log' permission (e.g. an AccessView/admin check) rather than returning them to every audit-log reader.

---

#### FINDING-013: Malformed query string returned unredacted to access log

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | CWE-532 |
| **ASVS sections** | 14.2.1, 16.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| **Source Reports** | 14.2.1.md, 16.4.1.md |
| **Related** | FINDING-002 |

**Description:**

On a malformed query string, `parse_qsl` raises `ValueError` and the raw query is returned and logged without secret redaction. A secret-looking parameter embedded in a deliberately malformed query could bypass redaction. `parse_qsl` rarely raises with `keep_blank_values=True`, and an attacker would expose only their own crafted value, so practical impact is minimal.

**Remediation:**

On the parse-failure branch, redact the raw string conservatively rather than returning it verbatim, e.g. pass the whole string through `secrets_masker.redact(query)`.

---

#### FINDING-014: `FilterParam` CONTAINS branch does not escape LIKE wildcards

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 1.1.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| **Source Reports** | 1.1.2.md |
| **Related** | - |

**Description:**

The `FilterParam.to_orm` method's `CONTAINS` branch constructs a LIKE query without escaping LIKE metacharacters (`%`, `_`). While this does not create a SQL injection vulnerability (values are properly bound as parameters, satisfying ASVS 1.1.2's core requirement), it creates inconsistent behavior compared to other literal-match filters in the same file. Data flow: user value → FilterParam.value → ColumnOperators.contains() → SQL LIKE '%' || :value || '%'. Gap Type A (missing control on this code path). LOW because no SQL injection risk (parameter binding provides interpreter-level escaping), limited impact (semantic over-matching of authorized rows), and no current exploitation path (no in-scope query parameter instantiates FilterParam with CONTAINS); it is a defense-in-depth/consistency concern.

**Remediation:**

Apply LIKE escaping consistent with other literal-match filters:

```python
if self.filter_option == FilterOptionEnum.CONTAINS:
    from sqlalchemy import Text, cast
    escaped = _escape_like_pattern(str(self.value))
    target = cast(self.attribute, Text) if str(self.attribute.type).upper() in ("JSON", "JSONB") else self.attribute
    return select.where(target.ilike(f"%{escaped}%", escape=_LIKE_ESCAPE_CHAR))
```

---

#### FINDING-015: ConnectionBody.conn_type lacks positive allow-list/pattern/length validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1, L2 |
| **CWE** | - |
| **ASVS sections** | 2.1.1, 2.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py |
| **Source Reports** | 2.1.1.md, 2.2.1.md |
| **Related** | - |

**Description:**

API request → `conn_type` → used downstream to resolve hook/provider behaviour. No positive allow-list, pattern, or length range is applied. Attacker capability: authenticated user with connection-write permission. Impact: arbitrary string stored; functional misuse only, no injection path (ORM-parameterized). Bounded → Low. PoC: `POST /api/v2/connections {"connection_id":"x","conn_type":"<4000-char string>"}` is accepted. This field also lacks documented structure as required by ASVS 2.1.1.

**Remediation:**

Document and enforce an expected structure for `conn_type` with length bounds and a conservative pattern: `conn_type: str = Field(max_length=500, pattern=r"^[\w.\-]+$")`. Also document and constrain free-text fields: `description: str | None = Field(default=None, max_length=5000)`.

---

#### FINDING-016: Request-tracing headers (x-request-id, correlation-id) are accepted from the client and used/echoed without provenance validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 4.1.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/http_access_log.py, airflow-core/src/airflow/api_fastapi/execution_api/app.py |
| **Source Reports** | 4.1.3.md |
| **Related** | - |

**Description:**

Client-supplied x-request-id / correlation-id headers are bound into the structured log context and echoed into the response header without provenance validation. Data flow: client header → log context / response header → access logs and downstream log correlation. Attacker capability: any client able to set request headers. Impact: log-correlation forgery / log spoofing; no auth/authz/rate-limiting decision is made from these headers, so impact is limited to log/trace integrity. The echo cannot be used for CRLF/header-injection because Starlette/h11 reject control characters in header values. This is application-level log-integrity hardening, not solely a proxy-delegated control.

**Remediation:**

When a trusted intermediary is expected to set these headers, configure the proxy to strip/overwrite them on ingress. If application-side hardening is desired, validate the format (e.g., require a UUID) and prefer regenerating a server-side ID when the header is absent or malformed.

---

#### FINDING-017: openapi_jsons mutates resp.body after Content-Length is computed, producing a Content-Length/body conflict

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 4.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/execution_api/app.py |
| **Source Reports** | 4.2.2.md |
| **Related** | - |

**Description:**

CadwynWithOpenAPICustomization.openapi_jsons re-renders a larger body after Starlette has already computed and stored Content-Length, leaving a stale (shorter) Content-Length emitted with a longer body. Data flow: super().openapi_jsons() builds a JSONResponse with computed Content-Length → code reassigns resp.body with customized schema → stale header emitted at send time. Attacker capability: any client able to reach /execution/openapi.json; content is not attacker-controlled, the mismatch is deterministic. Impact: realistic outcome is a broken /openapi.json response or connection drop (h11 usually rejects the mismatch) rather than true smuggling — hence Low. This is a genuine application-layer instance of the exact pattern 4.2.2 warns against.

**Remediation:**

Construct a fresh response so headers are recomputed instead of mutating .body in place, or explicitly recompute resp.headers['content-length'] = str(len(resp.body)).

---

#### FINDING-018: correlation-id request header reflected into response header without CR/LF validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 4.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/execution_api/app.py |
| **Source Reports** | 4.2.4.md |
| **Related** | - |

**Description:**

CorrelationIdMiddleware.dispatch reflects the client-controlled correlation-id request header verbatim into a response header and into structlog context with no CR/LF or control-character validation. Attacker capability: any client able to set a correlation-id header. Impact: classic header-injection/response-splitting primitive, but inbound HTTP/2 (hpack/h2) and outbound HTTP/1.1 (h11/uvicorn) layers reject CR/LF in header values, so injection is blocked at the server layer — a defense-in-depth gap rather than an exploitable split. Application-level validation is absent.

**Remediation:**

Validate/sanitize the echoed value (e.g., allowlist regex ^[A-Za-z0-9._\-]{1,128}$) before binding to log context and reflecting into the response header.

---

#### FINDING-019: JWT refresh-token cookie name lacks the `__Secure-`/`__Host-` prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-614 |
| **ASVS sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 3.3.1.md |
| **Related** | FINDING-020 |

**Description:**

Cookie name `_token` (COOKIE_NAME_JWT_TOKEN) carries no `__Secure-`/`__Host-` prefix, so the browser does not enforce secure-channel or host/path binding, allowing a related-domain attacker to overwrite the session/refresh token (session fixation / forced-login style). Data flow: auth manager generates JWT → middleware writes it as cookie `_token` → browser stores cookie with no name-prefix binding. ASVS 3.3.1 requires the `__Secure-` prefix if `__Host-` is not used; neither is present.

**Remediation:**

Use a prefixed name. Because cookie_path is configurable, `__Host-` (which mandates Path=/, no Domain, and Secure) may not always be valid; at minimum adopt `__Secure-`: COOKIE_NAME_JWT_TOKEN = "__Secure-_token", or `__Host-_token` when cookie_path == "/" and no Domain is set. Prefixed cookies are only honored when the Secure attribute is present.

---

#### FINDING-020: `Secure` attribute on the refresh-token cookie is conditional and can resolve to `False`

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-614 |
| **ASVS sections** | 3.3.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| **Source Reports** | 3.3.1.md |
| **Related** | FINDING-019 |

**Description:**

`secure = request.base_url.scheme == "https" or bool(conf.get("api", "ssl_cert", fallback=""))` can resolve to False when TLS is terminated at a proxy whose forwarded-proto is not honored and ssl_cert is empty, causing the browser to transmit the JWT cookie over plaintext HTTP and rendering any name prefix ineffective. Pure TLS termination/proxy header handling is delegated infrastructure; the in-scope defect is the application logic that can silently emit a non-Secure sensitive cookie.

**Remediation:**

Default Secure to True for this sensitive cookie and require an explicit opt-out only for documented local-dev scenarios; ensure forwarded-proto is trusted via the proxy middleware.

---

#### FINDING-021: Session/refresh-token cookie does not use the `__Host-` prefix despite being host-scoped

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-16 |
| **ASVS sections** | 3.3.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| **Source Reports** | 3.3.3.md |
| **Related** | - |

**Description:**

JWT issued by auth manager is written as cookie `_token` with no `Domain` set but a configurable `path`; browser stores without host-binding enforcement. An attacker controlling or compromising a sibling subdomain could plant a `_token` cookie that the application accepts, enabling cookie overwrite/fixation. The `__Host-` prefix would force the browser to reject any cookie carrying a `Domain` attribute and require `Path=/` + `Secure`. Adoption must be conditional on `cookie_path == "/"` (otherwise fall back to `__Secure-`).

**Remediation:**

When `cookie_path == "/"` and no `Domain` is set, use `COOKIE_NAME_JWT_TOKEN = "__Host-_token"`; this requires `secure=True` and `path="/"`. Pair with the always-Secure change (ASVS-331-LOW-002), since `__Host-` cookies are ignored unless `Secure` is set.

---

#### FINDING-022: No length check on JWT cookie value before writing Set-Cookie

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-400 |
| **ASVS sections** | 3.3.5 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| **Source Reports** | 3.3.5.md |
| **Related** | - |

**Description:**

serialize_user(user) → JWT claims → JWTGenerator.generate() → new_token → set_cookie; token length is never validated against the 4096-byte browser limit. A concrete auth manager (e.g., an external IdP packing many claims/groups) could produce a JWT exceeding 4096 bytes, causing the browser to silently drop the cookie and a hard-to-diagnose login/redirect loop. No confidentiality/integrity impact — availability/correctness foot-gun only.

**Remediation:**

Validate combined name+value length at the write site and fail loudly (log error / fall back) instead of emitting a cookie the browser will discard.

---

#### FINDING-023: Unchecked `as JSON` type assertion on parsed user JSON

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-843 |
| **ASVS sections** | 15.3.5 |
| **Files** | airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx:29-42, airflow-core/src/airflow/ui/src/components/ConfigForm.tsx:44-63 |
| **Source Reports** | 15.3.5.md |
| **Related** | - |

**Description:**

Location: `airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx`, `handleChange` (lines ~29-42); `airflow-core/src/airflow/ui/src/components/ConfigForm.tsx`, `validateAndPrettifyJson` (lines ~44-63). Data flow: user JSON text (JsonEditor) → `JSON.parse(...) as JSON` → stored as `param.value` / form `conf`. The `as JSON` assertion tells the compiler the result is a specific type without runtime verification. Attacker capability: an authenticated UI user editing a DAG trigger config; the parsed value is sent to the server, which performs authoritative validation. Impact: no direct C/I/A impact — a type-confusion foot-gun in client code; server-side validation is the real control. Defense-in-depth/code-quality issue, not an exploitable vulnerability.

**Remediation:**

Avoid blanket `as JSON` casts; validate the parsed shape before use (parse into `unknown` then narrow with a runtime guard before assigning).

---

#### FINDING-024: Object literals used for key/value collections instead of Map/Set

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-1321 |
| **ASVS sections** | 15.3.6 |
| **Files** | airflow-core/src/airflow/ui/src/components/FilterBar/FilterBar.tsx:75-84, airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx:29-42 |
| **Source Reports** | 15.3.6.md |
| **Related** | - |

**Description:**

Location: `airflow-core/src/airflow/ui/src/components/FilterBar/FilterBar.tsx`, `updateFiltersRecord` (lines ~75-84); `airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx`, `handleChange` (lines ~29-42). Data flow: filter keys (`filter.config.key`) originate from developer-defined `FilterConfig` objects, not user input; param `name` comes from the DAG-provided schema. JSON-parsed user content is stored as a leaf `value`, never iterated to assign attacker-named keys. Attacker capability: none practical — bracket-assignment keys are not user-controlled, so the classic `__proto__`/`constructor` injection vector is not reachable. Impact: no realistic exploit path; flagged only because 15.3.6 recommends `Map()`/`Set()` over object literals as defense-in-depth. Residual risk minimal since keys are trusted.

**Remediation:**

Where collections accumulate values by key, prefer `Map` to structurally eliminate prototype-chain interaction; if object literals must be retained, create them with `Object.create(null)` and reject `__proto__`/`constructor`/`prototype` keys if any key could become user-influenced in the future.

---

#### FINDING-025: HTTP access log omits authenticated principal (who) metadata

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| **Source Reports** | 16.2.1.md |
| **Related** | - |

**Description:**

The HTTP access log captures where (`client_addr`, `path`), what (`method`, `status_code`), and a correlation handle (`request_id`), but does not capture the authenticated user/principal. The DB `Log` model and CLI action logger both capture owner/user, so this gap is specific to the HTTP access stream. Investigative-completeness gap, not an exploit path.

**Remediation:**

After authentication resolves, bind the resolved principal to the structlog context (e.g., `structlog.contextvars.bind_contextvars(user_id=principal.id)`) so the access-log event includes the authenticated subject when available.

---

#### FINDING-026: HTTP access log relies on externally-configured structlog processor for UTC/offset timestamp

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| **Source Reports** | 16.2.2.md |
| **Related** | - |

**Description:**

The middleware emits `duration_us` but never attaches an explicit wall-clock event timestamp; whether the entry carries a UTC/offset-bearing timestamp depends entirely on the structlog processor chain configured elsewhere. The DB `Log` model and CLI logger both pin UTC explicitly; the HTTP access stream does not. Configuration-robustness/timeline-ambiguity gap (note: NTP time-source sync across hosts remains deployment-managed and out of scope).

**Remediation:**

Ensure the structlog processor chain for this logger includes a UTC timestamper (`TimeStamper(fmt='iso', utc=True)`), or attach the timestamp explicitly at emit time using `timezone.utcnow().isoformat()`.

---

#### FINDING-027: Attacker-controlled request fields logged without CR/LF neutralization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | CWE-117 |
| **ASVS sections** | 16.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| **Source Reports** | 16.4.1.md |
| **Related** | - |

**Description:**

The redaction step (`secrets_masker.redact`) neutralizes secret values but does not strip CR/LF or other control characters. Unlike the stdlib audit path (which has `_sanitize_for_stdlib_log`), the structlog access path has no equivalent sanitization and depends on the renderer to encode control characters. An attacker can place arbitrary (URL-decoded) bytes in the request path/query. If a deployment configures structlog with a plain-text/console renderer rather than the default JSON renderer, embedded `\n`/`\r` could forge additional log lines (CWE-117). In the default JSON-rendered configuration this is fully mitigated, hence Low.

**Remediation:**

Apply CR/LF (and other control-character) neutralization to attacker-controlled string fields before they enter the logger, mirroring the existing stdlib helper, so protection does not depend on renderer choice.

---

#### FINDING-028: _UniqueConstraintErrorHandler.exception_handler silently falls through (returns None) when the dialect prefix is not matched

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.5.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/exceptions.py |
| **Source Reports** | 16.5.3.md |
| **Related** | - |

**Description:**

An IntegrityError whose str(exc.orig) does not contain one of the three known dialect prefixes causes the handler to return None without raising or returning a Response, neither surfacing a structured failure nor logging. This is a fail-soft path violating the fail-closed expectation. Low real-world impact because all officially supported backends are covered by the prefix list.

**Remediation:**

Re-raise (or return a controlled generic 500/409) and log the unmatched error when no dialect matches.

---

#### FINDING-029: `DagErrorHandler` raises without server-side logging, losing error details for unhandled deserialization failures

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 16.5.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/exceptions.py |
| **Source Reports** | 16.5.4.md |
| **Related** | - |

**Description:**

Unlike `_UniqueConstraintErrorHandler`, which logs the assembled stacktrace with a correlation ID, `DagErrorHandler` performs no logging at all before raising. A 500-class deserialization failure therefore leaves no dedicated server-side log record, degrading incident response and monitoring. Operational/forensics weakness, not directly attacker-driven.

**Remediation:**

Add `log.error(...)` with a correlation ID before raising, and surface the correlation ID instead of the raw exception.

---

#### FINDING-030: Individually-owned scoped dependency increases supply-chain / dependency-confusion surface

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | - |
| **ASVS sections** | 15.2.4 |
| **Files** | airflow-core/src/airflow/ui/package.json:34 |
| **Source Reports** | 15.2.4.md |
| **Related** | - |

**Description:**

Location: `airflow-core/src/airflow/ui/package.json:34` — `"@guanmingchiu/sqlparser-ts": "^0.61.1"`. Data flow: dependency resolution → public npm registry → individually-maintained scope `@guanmingchiu` → bundled into UI build. A caret range on an individually-owned scoped package means a future compromised minor/patch release would be picked up automatically (subject to release-age delay). Dependency-confusion (15.2.4) is governed primarily by registry/scope configuration (`.npmrc`, `pnpm-lock.yaml`) not present in this file. Attacker capability: compromise of an upstream single-maintainer npm package — not an attacker capability against Airflow directly. Impact: malicious code execution in the UI build/runtime if a compromised version is published and resolved. Why Low: no demonstrated exploit path; `minimumReleaseAge` and lockfile-based integrity substantially mitigate.

**Remediation:**

Continue to rely on `pnpm-lock.yaml` with integrity hashes committed to the repo, and ensure the resolved registry for all scopes is pinned via an `.npmrc` that forbids fallback to a public registry for internal scopes. Consider replacing single-maintainer parsing libraries with better-maintained alternatives, or vendoring/pinning to an exact version with hash verification.

---

#### FINDING-031: Filesystem check-then-act in latest-log symlink creation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L3 |
| **CWE** | CWE-367 |
| **ASVS sections** | 15.4.2 |
| **Files** | airflow-core/src/airflow/dag_processing/manager.py:1138 |
| **Source Reports** | 15.4.2.md |
| **Related** | - |

**Description:**

File: `airflow-core/src/airflow/dag_processing/manager.py`, function `_symlink_latest_log_directory` (~line 1138). Data flow: filesystem state (`os.path.islink` / `os.path.isdir` / `os.path.isfile`) → decision branch → `os.unlink` + `os.symlink` (the dependent action) are separate, non-atomic syscalls. Between the `islink` check and the `unlink`/`symlink`, the entry can be replaced — the classic TOCTOU pattern. Missing control: there is no atomic create-or-replace. Attacker capability required: local write access to the parent of the DAG-processor log directory — a privileged location normally owned by the Airflow service account. Impact: at most redirection of the convenience `latest` symlink within a privileged, service-owned directory; bounded by the surrounding `try/except OSError`. No remote impact, no data-integrity impact on task state. Why Low: requires local privileged co-residence in a service-owned directory and the outcome is limited to a log convenience symlink.

**Remediation:**

Make the replacement atomic by creating a uniquely-named temp symlink and `os.replace`/`os.rename` it into place, so no observable check-then-act window exists.

### 3.5 Informational

#### FINDING-032: Revocation is silently skipped for tokens lacking a jti claim

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| **Source Reports** | 7.4.1.md |
| **Related** | - |

**Description:**

If any code path issues a token without a jti, the short-circuit (jti := ...) and ... evaluates falsy and the revocation list is never consulted — such a token can never be terminated. This is only a concrete defect if a tokens-without-jti path exists; the generator code is not in scope here, so this is reported as a verified code shape without a confirmed exploit path.

**Remediation:**

Require jti at validation time — treat a missing jti as invalid for any deployment relying on revocation.

---

#### FINDING-033: No documented/validated bound-ordering rule on Range filters

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 2.1.2, 2.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| **Source Reports** | 2.1.2.md, 2.2.3.md |
| **Related** | - |

**Description:**

There is no documented rule (and no validator) requiring `lower_bound <= upper_bound`. A request with `_gte` greater than `_lte` is accepted and silently returns an empty result set rather than a 422. Additionally, no pre-defined rule checks that mutually exclusive bounds (`_gte` and `_gt` together) are coherent. Attacker capability: authenticated API user. Impact: none beyond confusing/empty results or logically inconsistent ranges that silently produce empty/odd result sets; no C/I/A impact. Real but non-exploitable consistency-rule gap.

**Remediation:**

Document the bound-ordering contract and add a `model_validator(mode="after")` on `Range` that raises when a lower bound exceeds the corresponding upper bound or when mutually exclusive bounds are provided. Reject incoherent combinations with 422.

---

#### FINDING-034: Truthiness bound check drops legitimate 0.0 numeric range bounds

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 2.3.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| **Source Reports** | 2.3.2.md |
| **Related** | - |

**Description:**

Bounds are gated with a truthiness check (`if self.value.lower_bound_gte:`) rather than `is not None`. For numeric range filters a legitimate bound of `0.0` is falsy and silently dropped (e.g., `?duration_gte=0` is ignored). Datetime ranges unaffected. Attacker capability: none — correctness defect, not exploitable; filter under-applies and no authorization boundary is crossed. No C/I/A impact.

**Remediation:**

Use explicit `is not None` checks: `if self.value.lower_bound_gte is not None: select = select.where(self.attribute >= self.value.lower_bound_gte)`.

---

#### FINDING-035: Access-log emission failures are silently suppressed, so a logging-control failure produces no record

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L2 |
| **CWE** | - |
| **ASVS sections** | 16.3.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| **Source Reports** | 16.3.4.md |
| **Related** | - |

**Description:**

The middleware wraps `logger.info` in `contextlib.suppress(Exception)` to preserve the propagating application exception in `finally`. If structured logging fails (misconfigured renderer, downstream sink error), the failure of the access-logging control is itself unrecorded — no counter, secondary emit, or metric. Minor observability gap; intentional and documented in-line. No attacker-driven exploit.

**Remediation:**

Emit a minimal counter or best-effort `sys.stderr` breadcrumb inside the suppression block so repeated logging failures become detectable without risking exception replacement.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Jwt Token Management | Absolute session/refresh-token expiry is enforced by the concrete production auth manager (signaled via AuthManagerRefreshTokenExpiredException, honored by JWTRefreshMiddleware), consistent with delegated token-refresh lifecycle. | Promoted from dropped finding ASVS-1048-LOW-001 | — |
| Authentication Mechanisms | Constant-time password comparison using hmac.compare_digest | Credential check uses hmac.compare_digest with an empty-string fallback that preserves constant time when the user record exists but the password entry is missing | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:58 |
| Authentication Mechanisms | Uniform invalid-credential response | Returns a single generic 401 'Invalid credentials' regardless of whether the username or password was wrong, avoiding message-based user enumeration | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:71 |
| Authentication Mechanisms | Brute-force / anti-automation control delegated to reverse proxy | Delegated to reverse proxy / WAF layer. Coverage applies to POST /token and POST /token/cli at the proxy boundary | — |
| Authentication Mechanisms | Cryptographically strong password generation using CSPRNG | Dev passwords are 16 characters drawn from a non-ambiguous alphabet using the secrets module (CSPRNG), not random | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:392 |
| Authentication Mechanisms | Consistent authentication pathway gating | Both GET /token and middleware-injected token route through create_token_all_admins, which raises 403 unless simple_auth_manager_all_admins is explicitly enabled | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:86 |
| Authentication Mechanisms | Shared token issuance across all pathways | All login routes converge on get_auth_manager().generate_jwt, giving uniform token format/expiry handling rather than per-route ad-hoc tokens | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:80 |
| Authentication Mechanisms | Open-redirect protection on redirect pathway | The next query parameter is validated with is_safe_url before being used as the redirect target, falling back to the configured base URL otherwise | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:90 |
| Authentication Mechanisms | Secure cookie attributes on JWT cookie | The JWT cookie is set httponly=True, samesite=lax, with secure derived from HTTPS scheme or configured ssl_cert | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:96 |
| Authentication Mechanisms | Production-shape warning | init emits a loud warning when the deployment looks production-shaped (non-sqlite DB, non-local host, or distributed executor) while the dev-only manager is active | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:185 |
| Authentication Mechanisms | No periodic password rotation enforcement | init() writes a password once per user if absent and never expires it. No expiry timestamp, no password age check, and no forced-change-on-interval logic in SimpleAuthManager or login service | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:191-225 |
| Authentication Mechanisms | No password composition rules enforced | create_token() accepts arbitrary password content; no regex/character-class rules are applied. Password verification compares raw bytes with hmac.compare_digest() and imposes no character-class requirements | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:58 |
| Authentication Mechanisms | Standard JSON/form body acceptance with no input transformation | The /token endpoint accepts password via both application/json and application/x-www-form-urlencoded with no server-imposed input transformation that would impede password-manager autofill | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:55-62 |
| Authentication Mechanisms | Password verified exactly as received | SimpleAuthManagerLogin.create_token compares passwords with no modification, case transformation, or truncation. hmac.compare_digest is used directly on the raw UTF-8 bytes of the received password | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:54-71 |
| Authentication Mechanisms | No maximum password length restriction | body.password is compared at full length; nothing truncates long passwords. The comparison handles arbitrary-length inputs including passwords of 64+ characters | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:54-71 |
| Authentication Mechanisms | No hardcoded default credentials | Accounts and passwords are operator-configured / randomly generated using secrets.choice() over 16 chars, no static default. Passwordless admin mode is opt-in, gated behind simple_auth_manager_all_admins configuration flag | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:402 |
| Authentication Mechanisms | Pluggable BaseAuthManager extension point for MFA | Allows MFA-capable production auth managers to replace the dev-only one | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:84 |
| Authentication Mechanisms | Single gating flag for all passwordless pathways | core.simple_auth_manager_all_admins controls endpoints and middleware consistently. 403 guard on all-admins token endpoint rejects when flag is off | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:93 |
| Authentication Mechanisms | Authentication uses password + JWT, not email | Credential model is LoginBody (username/password) issuing JWTs, not email-based authentication | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py:33 |
| Authentication Mechanisms | No user-facing credential update endpoint | SimpleAuthManager exposes no user-facing credential update endpoint, so there is no unnotified-change vector in the audited code | airflow-core/src/airflow/api_fastapi/auth/managers/simple/routes/login.py:35 |
| Authentication Mechanisms | File locking for safe credential file initialization | Manager implements file locking during credential file operations to prevent race conditions | — |
| Authentication Mechanisms | Cryptographically secure initial-password generation | Uses secrets.choice over a 16-character draw from an ambiguity-reduced alphabet providing ~90 bits of entropy | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:437 |
| Authentication Mechanisms | Generated passwords created once under exclusive file lock | fcntl.flock(LOCK_EX \| LOCK_NB) ensures only one worker process generates/writes the password set, avoiding race-induced duplicate generation | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:188 |
| Authentication Mechanisms | Production-shape warning | _looks_like_production() emits a loud startup warning when the dev-only manager is used in a production-shaped deployment, reducing the chance dev credentials silently become long-term production credentials | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py:136 |
| Session Management | jti-based RevokedToken list consulted on every validation path in get_user_from_token, with expired-entry pruning | Promoted from dropped finding ASVS-742-MED-001 | — |
| Session Management | RevokedToken persistence layer exists and can back user-scoped/admin revocation in concrete auth managers | Promoted from dropped finding ASVS-745-LOW-001 | — |
| Authorization Rbac | Alert-and-revert / live grant re-validation for self-contained JWTs is delegated to concrete production auth managers via the per-request refresh_user hook and token revocation list (RevokedToken). | Dropped finding ASVS-832-LOW-001 | — |
| Secrets Encryption | All at-rest secret encryption funneled through a single FernetProtocol seam (get_fernet()), with MultiFernet staged key rotation and full re-encryption via rotate_fernet_key(); algorithm/cipher selection treated as a deployment-owned configuration surface. | Observed in cryptographic implementation review for ASVS 11.2.2 | — |
| Secrets Masking | Server-side caching does not retain sensitive data inappropriately | 14.2.2 passed - application prevents sensitive data caching in server components | — |
| Secrets Masking | Sensitive data not sent to untrusted third parties | 14.2.3 passed - no unwanted collection of sensitive data by external trackers | — |
| Secrets Masking | Sensitive data logging controls implemented | 14.2.4 passed - controls around encryption, retention, and access to sensitive data in logs are defined | — |
| Secrets Masking | Browser storage does not contain sensitive data except session tokens | 14.3.3 passed - localStorage, sessionStorage, IndexedDB, and cookies properly scoped | — |
| Input Validation | Variable value size bounded by deployment-level payload limits and DB/storage limits rather than application validation layer | source: Dropped finding ASVS-221-LOW-002 | — |
| Api Security | In-application rate limiting / anti-automation intentionally delegated to reverse-proxy/WAF layer | Report scope note 2.4.1 (delegated_infrastructure_controls.md) | — |
| Client Side Security | Plugin/iframe view content is treated as deployment-trusted; missing per-parameter encoding of self-scoped route segments is not a vulnerability under the plugin trust model. | Documented in dropped finding ASVS-321-INFO-001 | — |
| Client Side Security | Application uses modern, supported client-side technologies without legacy insecure plugins (Flash, ActiveX, Silverlight, etc.) | 3.7.1 verification passed | — |
| Client Side Security | Application implements allowlist-based validation for automatic redirects to external domains | 3.7.2 verification passed | — |
| Client Side Security | JSONP functionality is not enabled anywhere across the application, preventing XSSI attacks | 3.5.6 verification passed | — |
| Client Side Security | Safe rendering functions are used for text content to prevent unintended HTML/JavaScript execution | 3.2.2 verification passed | — |
| Client Side Security | DOM clobbering protections implemented through explicit variable declarations and namespace isolation | 3.2.3 verification passed | — |
| Client Side Security | Security controls prevent browsers from rendering content in incorrect context | 3.2.1 verification passed | — |
| Ui Input Handling | Mass assignment protection in place | ASVS 15.3.3 marked as Pass | — |
| Logging Audit | Logging inventory exists and is documented (16.1.1 Pass) | Documentation confirms logging inventory covers application layers, events, formats, storage, access control, and retention | — |
| Logging Audit | Logs only stored/broadcast to documented destinations (16.2.3 Pass) | Application logging restricted to documented sinks per inventory | — |
| Logging Audit | Logs use common, parseable format (16.2.4 Pass) | Structured logging with consistent format enables correlation by log processors | — |
| Logging Audit | Security events and control bypass attempts logged (16.3.3 Pass) | Application logs defined security events and attempts to bypass controls including input validation, business logic, and anti-automation | — |
| Logging Audit | Unexpected errors and security control failures logged (16.3.4 Pass) | Application logs unexpected errors and security control failures such as backend TLS failures | — |
| Dependency Management | Lockfile-based integrity verification | pnpm-lock.yaml with integrity hashes committed to repo | — |
| Dependency Management | Minimum release age delay | minimumReleaseAge configuration mitigates automatic uptake of compromised releases | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.1.1 | Verify that input is decoded or unescaped into a canonical form only once, it is only decoded when encoded data in that form is expected, and that this is done before processing the input further, for example it is not performed after input validation or sanitization. | **Pass** |  |
| 1.1.2 | Verify that the application performs output encoding and escaping either as a final step before being used by the interpreter for which it is intended or by the interpreter itself. | **Pass** | See FINDING-014 |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Pass** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.2.6 | Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP injection have been implemented. | **N/A** |  |
| 1.2.7 | Verify that the application is protected against XPath injection attacks by using query parameterization or precompiled queries. | **N/A** |  |
| 1.2.8 | Verify that LaTeX processors are configured securely (such as not using the "--shell-escape" flag) and an allowlist of commands is used to prevent LaTeX injection attacks. | **N/A** |  |
| 1.2.9 | Verify that the application escapes special characters in regular expressions (typically using a backslash) to prevent them from being misinterpreted as metacharacters. | **N/A** |  |
| 1.2.10 | Verify that the application is protected against CSV and Formula Injection. The application must follow the escaping rules defined in RFC 4180 sections 2.6 and 2.7 when exporting CSV content. Additionally, when exporting to CSV or other spreadsheet formats (such as XLS, XLSX, or ODF), special characters (including '=', '+', '-', '@', '\t' (tab), and '\0' (null character)) must be escaped with a single quote if they appear as the first character in a field value. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.3.3 | Verify that data being passed to a potentially dangerous context is sanitized beforehand to enforce safety measures, such as only allowing characters which are safe for this context and trimming input which is too long. | **Pass** |  |
| 1.3.4 | Verify that user-supplied Scalable Vector Graphics (SVG) scriptable content is validated or sanitized to contain only tags and attributes (such as draw graphics) that are safe for the application, e.g., do not contain scripts and foreignObject. | **N/A** |  |
| 1.3.5 | Verify that the application sanitizes or disables user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL stylesheets, BBCode, or similar. | **Pass** |  |
| 1.3.6 | Verify that the application protects against Server-side Request Forgery (SSRF) attacks, by validating untrusted data against an allowlist of protocols, domains, paths and ports and sanitizing potentially dangerous characters before using the data to call another service. | **N/A** |  |
| 1.3.7 | Verify that the application protects against template injection attacks by not allowing templates to be built based on untrusted input. Where there is no alternative, any untrusted input being included dynamically during template creation must be sanitized or strictly validated. | **N/A** |  |
| 1.3.8 | Verify that the application appropriately sanitizes untrusted input before use in Java Naming and Directory Interface (JNDI) queries and that JNDI is configured securely to prevent JNDI injection attacks. | **N/A** |  |
| 1.3.9 | Verify that the application sanitizes content before it is sent to memcache to prevent injection attacks. | **N/A** |  |
| 1.3.10 | Verify that format strings which might resolve in an unexpected or malicious way when used are sanitized before being processed. | **N/A** |  |
| 1.3.11 | Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | **N/A** |  |
| 1.3.12 | Verify that regular expressions are free from elements causing exponential backtracking, and ensure untrusted input is sanitized to mitigate ReDoS or Runaway Regex attacks. | **N/A** |  |
| 1.4.1 | Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or heap overflows. | **N/A** |  |
| 1.4.2 | Verify that sign, range, and input validation techniques are used to prevent integer overflows. | **N/A** |  |
| 1.4.3 | Verify that dynamically allocated memory and resources are released, and that references or pointers to freed memory are removed or set to null to prevent dangling pointers and use-after-free vulnerabilities. | **N/A** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| 1.5.2 | Verify that deserialization of untrusted data enforces safe input handling, such as using an allowlist of object types or restricting client-defined object types, to prevent deserialization attacks. Deserialization mechanisms that are explicitly defined as insecure must not be used with untrusted input. | **Pass** |  |
| 1.5.3 | Verify that different parsers used in the application for the same data type (e.g., JSON parsers, XML parsers, URL parsers), perform parsing in a consistent way and use the same character encoding mechanism to avoid issues such as JSON Interoperability vulnerabilities or different URI or file parsing behavior being exploited in Remote File Inclusion (RFI) or Server-side Request Forgery (SSRF) attacks. | **Pass** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-015 |
| 2.1.2 | Verify that the application's documentation defines how to validate the logical and contextual consistency of combined data items, such as checking that suburb and ZIP code match. | **Pass** | See FINDING-033 |
| 2.1.3 | Verify that expectations for business logic limits and validations are documented, including both per-user and globally across the application. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-015 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.2.3 | Verify that the application ensures that combinations of related data items are reasonable according to the pre-defined rules. | **Pass** | See FINDING-033 |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **N/A** |  |
| 2.3.2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. | **Pass** | See FINDING-034 |
| 2.3.3 | Verify that transactions are being used at the business logic level such that either a business logic operation succeeds in its entirety or it is rolled back to the previous correct state. | **N/A** |  |
| 2.3.4 | Verify that business logic level locking mechanisms are used to ensure that limited quantity resources (such as theater seats or delivery slots) cannot be double-booked by manipulating the application's logic. | **N/A** |  |
| 2.3.5 | Verify that high-value business logic flows require multi-user approval to prevent unauthorized or accidental actions. This could include but is not limited to large monetary transfers, contract approvals, access to classified information, or safety overrides in manufacturing. | **N/A** |  |
| 2.4.1 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. | **N/A** |  |
| 2.4.2 | Verify that business logic flows require realistic human timing, preventing excessively rapid transaction submissions. | **N/A** |  |
| **V3: Web Frontend Security** | | | |
| 3.1.1 | Verify that application documentation states the expected security features that browsers using the application must support (such as HTTPS, HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), and other relevant HTTP security mechanisms). It must also define how the application must behave when some of these features are not available (such as warning the user or blocking access). | **N/A** |  |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Pass** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.2.3 | Verify that the application avoids DOM clobbering when using client-side JavaScript by employing explicit variable declarations, performing strict type checking, avoiding storing global variables on the document object, and implementing namespace isolation. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Partial** | See FINDING-019, FINDING-020 |
| 3.3.2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.3.3 | Verify that cookies have the '__Host-' prefix for the cookie name unless they are explicitly designed to be shared with other hosts. | **Partial** | See FINDING-021 |
| 3.3.4 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e. g. session token) must only be transferred to the client via the 'Set-Cookie' header field. | **Pass** |  |
| 3.3.5 | Verify that when the application writes a cookie, the cookie name and value length combined are not over 4096 bytes. Overly large cookies will not be stored by the browser and therefore not sent with requests, preventing the user from using application functionality which relies on that cookie. | **Partial** | See FINDING-022 |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.4.3 | Verify that HTTP responses include a Content-Security-Policy response header field which defines directives to ensure the browser only loads and executes trusted content or resources, in order to limit execution of malicious JavaScript. As a minimum, a global policy must be used which includes the directives object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes. For an L3 application, a per-response policy with nonces or hashes must be defined. | **N/A** |  |
| 3.4.4 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. This instructs browsers not to use content sniffing and MIME type guessing for the given response, and to require the response's Content-Type header field value to match the destination resource. For example, the response to a request for a style is only accepted if the response's Content-Type is 'text/css'. This also enables the use of the Cross-Origin Read Blocking (CORB) functionality by the browser. | **N/A** |  |
| 3.4.5 | Verify that the application sets a referrer policy to prevent leakage of technically sensitive data to third-party services via the 'Referer' HTTP request header field. This can be done using the Referrer-Policy HTTP response header field or via HTML element attributes. Sensitive data could include path and query data in the URL, and for internal non-public applications also the hostname. | **N/A** |  |
| 3.4.6 | Verify that the web application uses the frame-ancestors directive of the Content-Security-Policy header field for every HTTP response to ensure that it cannot be embedded by default and that embedding of specific resources is allowed only when necessary. Note that the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon. | **N/A** |  |
| 3.4.7 | Verify that the Content-Security-Policy header field specifies a location to report violations. | **N/A** |  |
| 3.4.8 | Verify that all HTTP responses that initiate a document rendering (such as responses with Content-Type text/html), include the Cross‑Origin‑Opener‑Policy header field with the same-origin directive or the same-origin-allow-popups directive as required. This prevents attacks that abuse shared access to Window objects, such as tabnabbing and frame counting. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Pass** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| 3.5.4 | Verify that separate applications are hosted on different hostnames to leverage the restrictions provided by same-origin policy, including how documents or scripts loaded by one origin can interact with resources from another origin and hostname-based restrictions on cookies. | **N/A** |  |
| 3.5.5 | Verify that messages received by the postMessage interface are discarded if the origin of the message is not trusted, or if the syntax of the message is invalid. | **N/A** |  |
| 3.5.6 | Verify that JSONP functionality is not enabled anywhere across the application to avoid Cross-Site Script Inclusion (XSSI) attacks. | **Pass** |  |
| 3.5.7 | Verify that data requiring authorization is not included in script resource responses, like JavaScript files, to prevent Cross-Site Script Inclusion (XSSI) attacks. | **N/A** |  |
| 3.5.8 | Verify that authenticated resources (such as images, videos, scripts, and other documents) can be loaded or embedded on behalf of the user only when intended. This can be accomplished by strict validation of the Sec-Fetch-* HTTP request header fields to ensure that the request did not originate from an inappropriate cross-origin call, or by setting a restrictive Cross-Origin-Resource-Policy HTTP response header field to instruct the browser to block returned content. | **N/A** |  |
| 3.6.1 | Verify that client-side assets, such as JavaScript libraries, CSS, or web fonts, are only hosted externally (e.g., on a Content Delivery Network) if the resource is static and versioned and Subresource Integrity (SRI) is used to validate the integrity of the asset. If this is not possible, there should be a documented security decision to justify this for each resource. | **N/A** |  |
| 3.7.1 | Verify that the application only uses client-side technologies which are still supported and considered secure. Examples of technologies which do not meet this requirement include NSAPI plugins, Flash, Shockwave, ActiveX, Silverlight, NACL, or client-side Java applets. | **Pass** |  |
| 3.7.2 | Verify that the application will only automatically redirect the user to a different hostname or domain (which is not controlled by the application) where the destination appears on an allowlist. | **Pass** |  |
| 3.7.3 | Verify that the application shows a notification when the user is being redirected to a URL outside of the application's control, with an option to cancel the navigation. | **N/A** |  |
| 3.7.4 | Verify that the application's top-level domain (e.g., site.tld) is added to the public preload list for HTTP Strict Transport Security (HSTS). This ensures that the use of TLS for the application is built directly into the main browsers, rather than relying only on the Strict-Transport-Security response header field. | **N/A** |  |
| 3.7.5 | Verify that the application behaves as documented (such as warning the user or blocking access) if the browser used to access the application does not support the expected security features. | **N/A** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.1.2 | Verify that only user-facing endpoints (intended for manual web-browser access) automatically redirect from HTTP to HTTPS, while other services or endpoints do not implement transparent redirects. This is to avoid a situation where a client is erroneously sending unencrypted HTTP requests, but since the requests are being automatically redirected to HTTPS, the leakage of sensitive data goes undiscovered. | **N/A** |  |
| 4.1.3 | Verify that any HTTP header field used by the application and set by an intermediary layer, such as a load balancer, a web proxy, or a backend-for-frontend service, cannot be overridden by the end-user. Example headers might include X-Real-IP, X-Forwarded-*, or X-User-ID. | **Fail** | See FINDING-016 |
| 4.1.4 | Verify that only HTTP methods that are explicitly supported by the application or its API (including OPTIONS during preflight requests) can be used and that unused methods are blocked. | **Pass** |  |
| 4.1.5 | Verify that per-message digital signatures are used to provide additional assurance on top of transport protections for requests or transactions which are highly sensitive or which traverse a number of systems. | **N/A** |  |
| 4.2.1 | Verify that all application components (including load balancers, firewalls, and application servers) determine boundaries of incoming HTTP messages using the appropriate mechanism for the HTTP version to prevent HTTP request smuggling. In HTTP/1.x, if a Transfer-Encoding header field is present, the Content-Length header must be ignored per RFC 2616. When using HTTP/2 or HTTP/3, if a Content-Length header field is present, the receiver must ensure that it is consistent with the length of the DATA frames. | **N/A** |  |
| 4.2.2 | Verify that when generating HTTP messages, the Content-Length header field does not conflict with the length of the content as determined by the framing of the HTTP protocol, in order to prevent request smuggling attacks. | **Fail** | See FINDING-017 |
| 4.2.3 | Verify that the application does not send nor accept HTTP/2 or HTTP/3 messages with connection-specific header fields such as Transfer-Encoding to prevent response splitting and header injection attacks. | **N/A** |  |
| 4.2.4 | Verify that the application only accepts HTTP/2 and HTTP/3 requests where the header fields and values do not contain any CR (\r), LF (\n), or CRLF (\r\n) sequences, to prevent header injection attacks. | **Fail** | See FINDING-018 |
| 4.2.5 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs (such as for API calls) or HTTP request header fields (such as Authorization or Cookie), which are too long to be accepted by the receiving component. This could cause a denial of service, such as when sending an overly long request (e.g., a long cookie header field), which results in the server always responding with an error status. | **N/A** |  |
| 4.3.1 | Verify that a query allowlist, depth limiting, amount limiting, or query cost analysis is used to prevent GraphQL or data layer expression Denial of Service (DoS) as a result of expensive, nested queries. | **N/A** |  |
| 4.3.2 | Verify that GraphQL introspection queries are disabled in the production environment unless the GraphQL API is meant to be used by other parties. | **N/A** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| 4.4.2 | Verify that, during the initial HTTP WebSocket handshake, the Origin header field is checked against a list of origins allowed for the application. | **N/A** |  |
| 4.4.3 | Verify that, if the application's standard session management cannot be used, dedicated tokens are being used for this, which comply with the relevant Session Management security requirements. | **N/A** |  |
| 4.4.4 | Verify that dedicated WebSocket session management tokens are initially obtained or validated through the previously authenticated HTTPS session when transitioning an existing HTTPS session to a WebSocket channel. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.1.1 | Verify that the documentation defines the permitted file types, expected file extensions, and maximum size (including unpacked size) for each upload feature. Additionally, ensure that the documentation specifies how files are made safe for end-users to download and process, such as how the application behaves when a malicious file is detected. | **N/A** |  |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** |  |
| 5.2.3 | Verify that the application checks compressed files (e.g., zip, gz, docx, odt) against maximum allowed uncompressed size and against maximum number of files before uncompressing the file. | **N/A** |  |
| 5.2.4 | Verify that a file size quota and maximum number of files per user are enforced to ensure that a single user cannot fill up the storage with too many files, or excessively large files. | **N/A** |  |
| 5.2.5 | Verify that the application does not allow uploading compressed files containing symlinks unless this is specifically required (in which case it will be necessary to enforce an allowlist of the files that can be symlinked to). | **N/A** |  |
| 5.2.6 | Verify that the application rejects uploaded images with a pixel size larger than the maximum allowed, to prevent pixel flood attacks. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** |  |
| 5.3.3 | Verify that server-side file processing, such as file decompression, ignores user-provided path information to prevent vulnerabilities such as zip slip. | **N/A** |  |
| 5.4.1 | Verify that the application validates or ignores user-submitted filenames, including in a JSON, JSONP, or URL parameter and specifies a filename in the Content-Disposition header field in the response. | **N/A** |  |
| 5.4.2 | Verify that file names served (e.g., in HTTP response header fields or email attachments) are encoded or sanitized (e.g., following RFC 6266) to preserve document structure and prevent injection attacks. | **N/A** |  |
| 5.4.3 | Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent serving of known malicious content. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** |  |
| 6.1.2 | Verify that a list of context-specific words is documented in order to prevent their use in passwords. The list could include permutations of organization names, product names, system identifiers, project codenames, department or role names, and similar. | **N/A** |  |
| 6.1.3 | Verify that, if the application includes multiple authentication pathways, these are all documented together with the security controls and authentication strength which must be consistently enforced across them. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **Pass** |  |
| 6.2.2 | Verify that users can change their password. | **Pass** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.2.9 | Verify that passwords of at least 64 characters are permitted. | **Pass** |  |
| 6.2.10 | Verify that a user's password stays valid until it is discovered to be compromised or the user rotates it. The application must not require periodic credential rotation. | **Pass** |  |
| 6.2.11 | Verify that the documented list of context specific words is used to prevent easy to guess passwords being created. | **Pass** |  |
| 6.2.12 | Verify that passwords submitted during account registration or password changes are checked against a set of breached passwords. | **N/A** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.3.3 | Verify that either a multi-factor authentication mechanism or a combination of single-factor authentication mechanisms, must be used in order to access the application. For L3, one of the factors must be a hardware-based authentication mechanism which provides compromise and impersonation resistance against phishing attacks while verifying the intent to authenticate by requiring a user-initiated action (such as a button press on a FIDO hardware key or a mobile phone). Relaxing any of the considerations in this requirement requires a fully documented rationale and a comprehensive set of mitigating controls. | **N/A** |  |
| 6.3.4 | Verify that, if the application includes multiple authentication pathways, there are no undocumented pathways and that security controls and authentication strength are enforced consistently. | **Pass** |  |
| 6.3.5 | Verify that users are notified of suspicious authentication attempts (successful or unsuccessful). This may include authentication attempts from an unusual location or client, partially successful authentication (only one of multiple factors), an authentication attempt after a long period of inactivity or a successful authentication after several unsuccessful attempts. | **N/A** |  |
| 6.3.6 | Verify that email is not used as either a single-factor or multi-factor authentication mechanism. | **N/A** |  |
| 6.3.7 | Verify that users are notified after updates to authentication details, such as credential resets or modification of the username or email address. | **N/A** |  |
| 6.3.8 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. | **Partial** | See FINDING-007 |
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
| 6.8.2 | Verify that the presence and integrity of digital signatures on authentication assertions (for example on JWTs or SAML assertions) are always validated, rejecting any assertions that are unsigned or have invalid signatures. | **N/A** |  |
| 6.8.3 | Verify that SAML assertions are uniquely processed and used only once within the validity period to prevent replay attacks. | **N/A** |  |
| 6.8.4 | Verify that, if an application uses a separate Identity Provider (IdP) and expects specific authentication strength, methods, or recentness for specific functions, the application verifies this using the information returned by the IdP. For example, if OIDC is used, this might be achieved by validating ID Token claims such as 'acr', 'amr', and 'auth_time' (if present). If the IdP does not provide this information, the application must have a documented fallback approach that assumes that the minimum strength authentication mechanism was used (for example, single-factor authentication using username and password). | **N/A** |  |
| **V7: Session Management** | | | |
| 7.1.1 | Verify that the user's session inactivity timeout and absolute maximum session lifetime are documented, are appropriate in combination with other controls, and that the documentation includes justification for any deviations from NIST SP 800-63B re-authentication requirements. | **Partial** | See FINDING-008 |
| 7.1.2 | Verify that the documentation defines how many concurrent (parallel) sessions are allowed for one account as well as the intended behaviors and actions to be taken when the maximum number of active sessions is reached. | **N/A** |  |
| 7.1.3 | Verify that all systems that create and manage user sessions as part of a federated identity management ecosystem (such as SSO systems) are documented along with controls to coordinate session lifetimes, termination, and any other conditions that require re-authentication. | **N/A** |  |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Partial** | See FINDING-006 |
| 7.3.1 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. | **Partial** | See FINDING-009 |
| 7.3.2 | Verify that there is an absolute maximum session lifetime such that re-authentication is enforced according to risk analysis and documented security decisions. | **Partial** | See FINDING-010 |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Partial** | See FINDING-011, FINDING-032 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** |  |
| 7.4.3 | Verify that the application gives the option to terminate all other active sessions after a successful change or removal of any authentication factor (including password change via reset or recovery and, if present, an MFA settings update). | **N/A** |  |
| 7.4.4 | Verify that all pages that require authentication have easy and visible access to logout functionality. | **Pass** |  |
| 7.4.5 | Verify that application administrators are able to terminate active sessions for an individual user or for all users. | **N/A** |  |
| 7.5.1 | Verify that the application requires full re-authentication before allowing modifications to sensitive account attributes which may affect authentication such as email address, phone number, MFA configuration, or other information used in account recovery. | **N/A** |  |
| 7.5.2 | Verify that users are able to view and (having authenticated again with at least one factor) terminate any or all currently active sessions. | **N/A** |  |
| 7.5.3 | Verify that the application requires further authentication with at least one factor or secondary verification before performing highly sensitive transactions or operations. | **Pass** |  |
| 7.6.1 | Verify that session lifetime and termination between Relying Parties (RPs) and Identity Providers (IdPs) behave as documented, requiring re-authentication as necessary such as when the maximum time between IdP authentication events is reached. | **Pass** |  |
| 7.6.2 | Verify that creation of a session requires either the user's consent or an explicit action, preventing the creation of new application sessions without user interaction. | **Pass** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.1.2 | Verify that authorization documentation defines rules for field-level access restrictions (both read and write) based on consumer permissions and resource attributes. Note that these rules might depend on other attribute values of the relevant data object, such as state or status. | **N/A** |  |
| 8.1.3 | Verify that the application's documentation defines the environmental and contextual attributes (including but not limited to, time of day, user location, IP address, or device) that are used in the application to make security decisions, including those pertaining to authentication and authorization. | **N/A** |  |
| 8.1.4 | Verify that authentication and authorization documentation defines how environmental and contextual factors are used in decision-making, in addition to function-level, data-specific, and field-level authorization. This should include the attributes evaluated, thresholds for risk, and actions taken (e.g., allow, challenge, deny, step-up authentication). | **N/A** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Partial** | See FINDING-012 |
| 8.2.3 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). | **N/A** |  |
| 8.2.4 | Verify that adaptive security controls based on a consumer's environmental and contextual attributes (such as time of day, location, IP address, or device) are implemented for authentication and authorization decisions, as defined in the application's documentation. These controls must be applied when the consumer tries to start a new session and also during an existing session. | **N/A** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| 8.3.2 | Verify that changes to values on which authorization decisions are made are applied immediately. Where changes cannot be applied immediately, (such as when relying on data in self-contained tokens), there must be mitigating controls to alert when a consumer performs an action when they are no longer authorized to do so and revert the change. Note that this alternative would not mitigate information leakage. | **Pass** |  |
| 8.3.3 | Verify that access to an object is based on the originating subject's (e.g. consumer's) permissions, not on the permissions of any intermediary or service acting on their behalf. For example, if a consumer calls a web service using a self-contained token for authentication, and the service then requests data from a different service, the second service will use the consumer's token, rather than a machine-to-machine token from the first service, to make permission decisions. | **N/A** |  |
| 8.4.1 | Verify that multi-tenant applications use cross-tenant controls to ensure consumer operations will never affect tenants with which they do not have permissions to interact. | **Pass** |  |
| 8.4.2 | Verify that access to administrative interfaces incorporates multiple layers of security, including continuous consumer identity verification, device security posture assessment, and contextual risk analysis, ensuring that network location or trusted endpoints are not the sole factors for authorization even though they may reduce the likelihood of unauthorized access. | **N/A** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Pass** |  |
| 9.2.2 | Verify that the service receiving a token validates the token to be the correct type and is meant for the intended purpose before accepting the token's contents. For example, only access tokens can be accepted for authorization decisions and only ID Tokens can be used for proving user authentication. | **Pass** |  |
| 9.2.3 | Verify that the service only accepts tokens which are intended for use with that service (audience). For JWTs, this can be achieved by validating the 'aud' claim against an allowlist defined in the service. | **Pass** |  |
| 9.2.4 | Verify that, if a token issuer uses the same private key for issuing tokens to different audiences, the issued tokens contain an audience restriction that uniquely identifies the intended audiences. This will prevent a token from being reused with an unintended audience. If the audience identifier is dynamically provisioned, the token issuer must validate these audiences in order to make sure that they do not result in audience impersonation. | **Fail** | See FINDING-001 |
| **V10: OAuth and OIDC** | | | |
| 10.1.1 | Verify that tokens are only sent to components that strictly need them. For example, when using a backend-for-frontend pattern for browser-based JavaScript applications, access and refresh tokens shall only be accessible for the backend. | **Pass** |  |
| 10.1.2 | Verify that the client only accepts values from the authorization server (such as the authorization code or ID Token) if these values result from an authorization flow that was initiated by the same user agent session and transaction. This requires that client-generated secrets, such as the proof key for code exchange (PKCE) 'code_verifier', 'state' or OIDC 'nonce', are not guessable, are specific to the transaction, and are securely bound to both the client and the user agent session in which the transaction was started. | **N/A** |  |
| 10.2.1 | Verify that, if the code flow is used, the OAuth client has protection against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF), which trigger token requests, either by using proof key for code exchange (PKCE) functionality or checking the 'state' parameter that was sent in the authorization request. | **N/A** |  |
| 10.2.2 | Verify that, if the OAuth client can interact with more than one authorization server, it has a defense against mix-up attacks. For example, it could require that the authorization server return the 'iss' parameter value and validate it in the authorization response and the token response. | **N/A** |  |
| 10.2.3 | Verify that the OAuth client only requests the required scopes (or other authorization parameters) in requests to the authorization server. | **N/A** |  |
| 10.3.1 | Verify that the resource server only accepts access tokens that are intended for use with that service (audience). The audience may be included in a structured access token (such as the 'aud' claim in JWT), or it can be checked using the token introspection endpoint. | **Pass** |  |
| 10.3.2 | Verify that the resource server enforces authorization decisions based on claims from the access token that define delegated authorization. If claims such as 'sub', 'scope', and 'authorization_details' are present, they must be part of the decision. | **Pass** |  |
| 10.3.3 | Verify that if an access control decision requires identifying a unique user from an access token (JWT or related token introspection response), the resource server identifies the user from claims that cannot be reassigned to other users. Typically, it means using a combination of 'iss' and 'sub' claims. | **N/A** |  |
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
| 10.4.9 | Verify that refresh tokens and reference access tokens can be revoked by an authorized user using the authorization server user interface, to mitigate the risk of malicious clients or stolen tokens. | **Partial** | See FINDING-005 |
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
| 11.1.1 | Verify that there is a documented policy for management of cryptographic keys and a cryptographic key lifecycle that follows a key management standard such as NIST SP 800-57. This should include ensuring that keys are not overshared (for example, with more than two entities for shared secrets and more than one entity for private keys). | **Pass** |  |
| 11.1.2 | Verify that a cryptographic inventory is performed, maintained, regularly updated, and includes all cryptographic keys, algorithms, and certificates used by the application. It must also document where keys can and cannot be used in the system, and the types of data that can and cannot be protected using the keys. | **Pass** |  |
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
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| 11.4.2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function (also known as a "password hashing function"), with parameter settings configured based on current guidance. The settings should balance security and performance to make brute-force attacks sufficiently challenging for the required level of security. | **N/A** |  |
| 11.4.3 | Verify that hash functions used in digital signatures, as part of data authentication or data integrity are collision resistant and have appropriate bit-lengths. If collision resistance is required, the output length must be at least 256 bits. If only resistance to second pre-image attacks is required, the output length must be at least 128 bits. | **Pass** |  |
| 11.4.4 | Verify that the application uses approved key derivation functions with key stretching parameters when deriving secret keys from passwords. The parameters in use must balance security and performance to prevent brute-force attacks from compromising the resulting cryptographic key. | **N/A** |  |
| 11.5.1 | Verify that all random numbers and strings which are intended to be non-guessable must be generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at least 128 bits of entropy. Note that UUIDs do not respect this condition. | **Pass** |  |
| 11.5.2 | Verify that the random number generation mechanism in use is designed to work securely, even under heavy demand. | **Pass** |  |
| 11.6.1 | Verify that only approved cryptographic algorithms and modes of operation are used for key generation and seeding, and digital signature generation and verification. Key generation algorithms must not generate insecure keys vulnerable to known attacks, for example, RSA keys which are vulnerable to Fermat factorization. | **Pass** |  |
| 11.6.2 | Verify that approved cryptographic algorithms are used for key exchange (such as Diffie-Hellman) with a focus on ensuring that key exchange mechanisms use secure parameters. This will prevent attacks on the key establishment process which could lead to adversary-in-the-middle attacks or cryptographic breaks. | **N/A** |  |
| 11.7.1 | Verify that full memory encryption is in use that protects sensitive data while it is in use, preventing access by unauthorized users or processes. | **N/A** |  |
| 11.7.2 | Verify that data minimization ensures the minimal amount of data is exposed during processing, and ensure that data is encrypted immediately after use or as soon as feasible. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.1.2 | Verify that only recommended cipher suites are enabled, with the strongest cipher suites set as preferred. L3 applications must only support cipher suites which provide forward secrecy. | **N/A** |  |
| 12.1.3 | Verify that the application validates that mTLS client certificates are trusted before using the certificate identity for authentication or authorization. | **N/A** |  |
| 12.1.4 | Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | **N/A** |  |
| 12.1.5 | Verify that Encrypted Client Hello (ECH) is enabled in the application's TLS settings to prevent exposure of sensitive metadata, such as the Server Name Indication (SNI), during TLS handshake processes. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| 12.3.1 | Verify that an encrypted protocol such as TLS is used for all inbound and outbound connections to and from the application, including monitoring systems, management tools, remote access and SSH, middleware, databases, mainframes, partner systems, or external APIs. The server must not fall back to insecure or unencrypted protocols. | **N/A** |  |
| 12.3.2 | Verify that TLS clients validate certificates received before communicating with a TLS server. | **N/A** |  |
| 12.3.3 | Verify that TLS or another appropriate transport encryption mechanism used for all connectivity between internal, HTTP-based services within the application, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.3.4 | Verify that TLS connections between internal services use trusted certificates. Where internally generated or self-signed certificates are used, the consuming service must be configured to only trust specific internal CAs and specific self-signed certificates. | **N/A** |  |
| 12.3.5 | Verify that services communicating internally within a system (intra-service communications) use strong authentication to ensure that each endpoint is verified. Strong authentication methods, such as TLS client authentication, must be employed to ensure identity, using public-key infrastructure and mechanisms that are resistant to replay attacks. For microservice architectures, consider using a service mesh to simplify certificate management and enhance security. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.1.1 | Verify that all communication needs for the application are documented. This must include external services which the application relies upon and cases where an end user might be able to provide an external location to which the application will then connect. | **N/A** |  |
| 13.1.2 | Verify that for each service the application uses, the documentation defines the maximum number of concurrent connections (e.g., connection pool limits) and how the application behaves when that limit is reached, including any fallback or recovery mechanisms, to prevent denial of service conditions. | **N/A** |  |
| 13.1.3 | Verify that the application documentation defines resource‑management strategies for every external system or service it uses (e.g., databases, file handles, threads, HTTP connections). This should include resource‑release procedures, timeout settings, failure handling, and where retry logic is implemented, specifying retry limits, delays, and back‑off algorithms. For synchronous HTTP request–response operations it should mandate short timeouts and either disable retries or strictly limit retries to prevent cascading delays and resource exhaustion. | **N/A** |  |
| 13.1.4 | Verify that the application's documentation defines the secrets that are critical for the security of the application and a schedule for rotating them, based on the organization's threat model and business requirements. | **N/A** |  |
| 13.2.1 | Verify that communications between backend application components that don't support the application's standard user session mechanism, including APIs, middleware, and data layers, are authenticated. Authentication must use individual service accounts, short-term tokens, or certificate-based authentication and not unchanging credentials such as passwords, API keys, or shared accounts with privileged access. | **Fail** | See FINDING-004 |
| 13.2.2 | Verify that communications between backend application components, including local or operating system services, APIs, middleware, and data layers, are performed with accounts assigned the least necessary privileges. | **Pass** |  |
| 13.2.3 | Verify that if a credential has to be used for service authentication, the credential being used by the consumer is not a default credential (e.g., root/root or admin/admin). | **Pass** |  |
| 13.2.4 | Verify that an allowlist is used to define the external resources or systems with which the application is permitted to communicate (e.g., for outbound requests, data loads, or file access). This allowlist can be implemented at the application layer, web server, firewall, or a combination of different layers. | **N/A** |  |
| 13.2.5 | Verify that the web or application server is configured with an allowlist of resources or systems to which the server can send requests or load data or files from. | **N/A** |  |
| 13.2.6 | Verify that where the application connects to separate services, it follows the documented configuration for each connection, such as maximum parallel connections, behavior when maximum allowed connections is reached, connection timeouts, and retry strategies. | **N/A** |  |
| 13.3.1 | Verify that a secrets management solution, such as a key vault, is used to securely create, store, control access to, and destroy backend secrets. These could include passwords, key material, integrations with databases and third-party systems, keys and seeds for time-based tokens, other internal secrets, and API keys. Secrets must not be included in application source code or included in build artifacts. For an L3 application, this must involve a hardware-backed solution such as an HSM. | **Pass** |  |
| 13.3.2 | Verify that access to secret assets adheres to the principle of least privilege. | **Pass** |  |
| 13.3.3 | Verify that all cryptographic operations are performed using an isolated security module (such as a vault or hardware security module) to securely manage and protect key material from exposure outside of the security module. | **N/A** |  |
| 13.3.4 | Verify that secrets are configured to expire and be rotated based on the application's documentation. | **N/A** |  |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** |  |
| 13.4.2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. | **N/A** |  |
| 13.4.3 | Verify that web servers do not expose directory listings to clients unless explicitly intended. | **N/A** |  |
| 13.4.4 | Verify that using the HTTP TRACE method is not supported in production environments, to avoid potential information leakage. | **N/A** |  |
| 13.4.5 | Verify that documentation (such as for internal APIs) and monitoring endpoints are not exposed unless explicitly intended. | **N/A** |  |
| 13.4.6 | Verify that the application does not expose detailed version information of backend components. | **N/A** |  |
| 13.4.7 | Verify that the web tier is configured to only serve files with specific file extensions to prevent unintentional information, configuration, and source code leakage. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.1.1 | Verify that all sensitive data created and processed by the application has been identified and classified into protection levels. This includes data that is only encoded and therefore easily decoded, such as Base64 strings or the plaintext payload inside a JWT. Protection levels need to take into account any data protection and privacy regulations and standards which the application is required to comply with. | **Pass** |  |
| 14.1.2 | Verify that all sensitive data protection levels have a documented set of protection requirements. This must include (but not be limited to) requirements related to general encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, database-level encryption, privacy and privacy-enhancing technologies to be used, and other confidentiality requirements. | **Pass** |  |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Partial** | See FINDING-013 |
| 14.2.2 | Verify that the application prevents sensitive data from being cached in server components, such as load balancers and application caches, or ensures that the data is securely purged after use. | **Pass** |  |
| 14.2.3 | Verify that defined sensitive data is not sent to untrusted parties (e.g., user trackers) to prevent unwanted collection of data outside of the application's control. | **Pass** |  |
| 14.2.4 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, privacy and privacy-enhancing technologies, are implemented as defined in the documentation for the specific data's protection level. | **Pass** |  |
| 14.2.5 | Verify that caching mechanisms are configured to only cache responses which have the expected content type for that resource and do not contain sensitive, dynamic content. The web server should return a 404 or 302 response when a non-existent file is accessed rather than returning a different, valid file. This should prevent Web Cache Deception attacks. | **N/A** |  |
| 14.2.6 | Verify that the application only returns the minimum required sensitive data for the application's functionality. For example, only returning some of the digits of a credit card number and not the full number. If the complete data is required, it should be masked in the user interface unless the user specifically views it. | **N/A** |  |
| 14.2.7 | Verify that sensitive information is subject to data retention classification, ensuring that outdated or unnecessary data is deleted automatically, on a defined schedule, or as the situation requires. | **N/A** |  |
| 14.2.8 | Verify that sensitive information is removed from the metadata of user-submitted files unless storage is consented to by the user. | **N/A** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| 14.3.2 | Verify that the application sets sufficient anti-caching HTTP response header fields (i.e., Cache-Control: no-store) so that sensitive data is not cached in browsers. | **N/A** |  |
| 14.3.3 | Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data, with the exception of session tokens. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.1.2 | Verify that an inventory catalog, such as software bill of materials (SBOM), is maintained of all third-party libraries in use, including verifying that components come from pre-defined, trusted, and continually maintained repositories. | **N/A** |  |
| 15.1.3 | Verify that the application documentation identifies functionality which is time-consuming or resource-demanding. This must include how to prevent a loss of availability due to overusing this functionality and how to avoid a situation where building a response takes longer than the consumer's timeout. Potential defenses may include asynchronous processing, using queues, and limiting parallel processes per user and per application. | **N/A** |  |
| 15.1.4 | Verify that application documentation highlights third-party libraries which are considered to be "risky components". | **N/A** |  |
| 15.1.5 | Verify that application documentation highlights parts of the application where "dangerous functionality" is being used. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.2.2 | Verify that the application has implemented defenses against loss of availability due to functionality which is time-consuming or resource-demanding, based on the documented security decisions and strategies for this. | **N/A** |  |
| 15.2.3 | Verify that the production environment only includes functionality that is required for the application to function, and does not expose extraneous functionality such as test code, sample snippets, and development functionality. | **Pass** |  |
| 15.2.4 | Verify that third-party components and all of their transitive dependencies are included from the expected repository, whether internally owned or an external source, and that there is no risk of a dependency confusion attack. | **Partial** | See FINDING-030 |
| 15.2.5 | Verify that the application implements additional protections around parts of the application which are documented as containing "dangerous functionality" or using third-party libraries considered to be "risky components". This could include techniques such as sandboxing, encapsulation, containerization or network level isolation to delay and deter attackers who compromise one part of an application from pivoting elsewhere in the application. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **N/A** |  |
| 15.3.2 | Verify that where the application backend makes calls to external URLs, it is configured to not follow redirects unless it is intended functionality. | **N/A** |  |
| 15.3.3 | Verify that the application has countermeasures to protect against mass assignment attacks by limiting allowed fields per controller and action, e.g., it is not possible to insert or update a field value when it was not intended to be part of that action. | **Pass** |  |
| 15.3.4 | Verify that all proxying and middleware components transfer the user's original IP address correctly using trusted data fields that cannot be manipulated by the end user, and the application and web server use this correct value for logging and security decisions such as rate limiting, taking into account that even the original IP address may not be reliable due to dynamic IPs, VPNs, or corporate firewalls. | **N/A** |  |
| 15.3.5 | Verify that the application explicitly ensures that variables are of the correct type and performs strict equality and comparator operations. This is to avoid type juggling or type confusion vulnerabilities caused by the application code making an assumption about a variable type. | **Partial** | See FINDING-023 |
| 15.3.6 | Verify that JavaScript code is written in a way that prevents prototype pollution, for example, by using Set() or Map() instead of object literals. | **Partial** | See FINDING-024 |
| 15.3.7 | Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no distinction about the source of request parameters (query string, body parameters, cookies, or header fields). | **N/A** |  |
| 15.4.1 | Verify that shared objects in multi-threaded code (such as caches, files, or in-memory objects accessed by multiple threads) are accessed safely by using thread-safe types and synchronization mechanisms like locks or semaphores to avoid race conditions and data corruption. | **Pass** |  |
| 15.4.2 | Verify that checks on a resource's state, such as its existence or permissions, and the actions that depend on them are performed as a single atomic operation to prevent time-of-check to time-of-use (TOCTOU) race conditions. For example, checking if a file exists before opening it, or verifying a user’s access before granting it. | **Partial** | See FINDING-031 |
| 15.4.3 | Verify that locks are used consistently to avoid threads getting stuck, whether by waiting on each other or retrying endlessly, and that locking logic stays within the code responsible for managing the resource to ensure locks cannot be inadvertently or maliciously modified by external classes or code. | **Pass** |  |
| 15.4.4 | Verify that resource allocation policies prevent thread starvation by ensuring fair access to resources, such as by leveraging thread pools, allowing lower-priority threads to proceed within a reasonable timeframe. | **Pass** |  |
| **V16: Security Logging and Error Handling** | | | |
| 16.1.1 | Verify that an inventory exists documenting the logging performed at each layer of the application's technology stack, what events are being logged, log formats, where that logging is stored, how it is used, how access to it is controlled, and for how long logs are kept. | **Pass** |  |
| 16.2.1 | Verify that each log entry includes necessary metadata (such as when, where, who, what) that would allow for a detailed investigation of the timeline when an event happens. | **Partial** | See FINDING-025 |
| 16.2.2 | Verify that time sources for all logging components are synchronized, and that timestamps in security event metadata use UTC or include an explicit time zone offset. UTC is recommended to ensure consistency across distributed systems and to prevent confusion during daylight saving time transitions. | **Partial** | See FINDING-026 |
| 16.2.3 | Verify that the application only stores or broadcasts logs to the files and services that are documented in the log inventory. | **Pass** |  |
| 16.2.4 | Verify that logs can be read and correlated by the log processor that is in use, preferably by using a common logging format. | **Pass** |  |
| 16.2.5 | Verify that when logging sensitive data, the application enforces logging based on the data's protection level. For example, it may not be allowed to log certain data, such as credentials or payment details. Other data, such as session tokens, may only be logged by being hashed or masked, either in full or partially. | **Fail** | See FINDING-002 |
| 16.3.1 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. Additional metadata, such as the type of authentication or factors used, should also be collected. | **N/A** |  |
| 16.3.2 | Verify that failed authorization attempts are logged. For L3, this must include logging all authorization decisions, including logging when sensitive data is accessed (without logging the sensitive data itself). | **N/A** |  |
| 16.3.3 | Verify that the application logs the security events that are defined in the documentation and also logs attempts to bypass the security controls, such as input validation, business logic, and anti-automation. | **Pass** |  |
| 16.3.4 | Verify that the application logs unexpected errors and security control failures such as backend TLS failures. | **Pass** | See FINDING-035 |
| 16.4.1 | Verify that all logging components appropriately encode data to prevent log injection. | **Partial** | See FINDING-013, FINDING-027 |
| 16.4.2 | Verify that logs are protected from unauthorized access and cannot be modified. | **N/A** |  |
| 16.4.3 | Verify that logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation. The aim is to ensure that if the application is breached, the logs are not compromised. | **N/A** |  |
| 16.5.1 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. | **Fail** | See FINDING-003 |
| 16.5.2 | Verify that the application continues to operate securely when external resource access fails, for example, by using patterns such as circuit breakers or graceful degradation. | **N/A** |  |
| 16.5.3 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. | **Fail** | See FINDING-028 |
| 16.5.4 | Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. This is both to avoid losing error details that must go to log files and to ensure that an error does not take down the entire application process, leading to a loss of availability. | **Fail** | See FINDING-029 |
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
- **Pass**: 103 requirements (29.9%)
- **Partial**: 21 requirements (6.1%)
- **N/A**: 212 requirements (61.4%)
- **Fail**: 9 requirements (2.6%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 9.2.4 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/tokens.py, airflow-core/src/airflow/api_fastapi/execution_api/security.py |
| FINDING-002 | Medium | 16.2.5 | FINDING-013 | airflow-core/src/airflow/utils/cli_action_loggers.py |
| FINDING-003 | Medium | 16.5.1 | — | airflow-core/src/airflow/api_fastapi/common/exceptions.py |
| FINDING-004 | Medium | 13.2.1 | — | airflow-core/src/airflow/api_fastapi/execution_api/routes/task_instances.py |
| FINDING-005 | Low | 10.4.9 | — | airflow-core/src/airflow/api_fastapi/execution_api/security.py |
| FINDING-006 | Low | 7.2.4 | — | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| FINDING-007 | Low | 6.3.8 | — | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py |
| FINDING-008 | Low | 7.1.1 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| FINDING-009 | Low | 7.3.1 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| FINDING-010 | Low | 7.3.2 | — | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| FINDING-011 | Low | 7.4.1 | — | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| FINDING-012 | Low | 8.2.2 | — | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| FINDING-013 | Low | 14.2.1, 16.4.1 | FINDING-002 | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-014 | Low | 1.1.2 | — | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| FINDING-015 | Low | 2.1.1, 2.2.1 | — | airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py |
| FINDING-016 | Low | 4.1.3 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py, airflow-core/src/airflow/api_fastapi/execution_api/app.py |
| FINDING-017 | Low | 4.2.2 | — | airflow-core/src/airflow/api_fastapi/execution_api/app.py |
| FINDING-018 | Low | 4.2.4 | — | airflow-core/src/airflow/api_fastapi/execution_api/app.py |
| FINDING-019 | Low | 3.3.1 | FINDING-020 | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py, airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| FINDING-020 | Low | 3.3.1 | FINDING-019 | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| FINDING-021 | Low | 3.3.3 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| FINDING-022 | Low | 3.3.5 | — | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| FINDING-023 | Low | 15.3.5 | — | airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx, airflow-core/src/airflow/ui/src/components/ConfigForm.tsx |
| FINDING-024 | Low | 15.3.6 | — | airflow-core/src/airflow/ui/src/components/FilterBar/FilterBar.tsx, airflow-core/src/airflow/ui/src/components/FlexibleForm/FieldObject.tsx |
| FINDING-025 | Low | 16.2.1 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-026 | Low | 16.2.2 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-027 | Low | 16.4.1 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |
| FINDING-028 | Low | 16.5.3 | — | airflow-core/src/airflow/api_fastapi/common/exceptions.py |
| FINDING-029 | Low | 16.5.4 | — | airflow-core/src/airflow/api_fastapi/common/exceptions.py |
| FINDING-030 | Low | 15.2.4 | — | airflow-core/src/airflow/ui/package.json |
| FINDING-031 | Low | 15.4.2 | — | airflow-core/src/airflow/dag_processing/manager.py |
| FINDING-032 | Informational | 7.4.1 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py |
| FINDING-033 | Informational | 2.1.2, 2.2.3 | — | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| FINDING-034 | Informational | 2.3.2 | — | airflow-core/src/airflow/api_fastapi/common/parameters.py |
| FINDING-035 | Informational | 16.3.4 | — | airflow-core/src/airflow/api_fastapi/common/http_access_log.py |

**Total Unique Findings**: 35 (0 Critical, 0 High, 4 Medium, 27 Low, 4 Info)

*31 of 35 are actionable. Informational findings are recorded here but not opened as GitHub issues; see issues.md for the 31 actionable items.*

## 7. Level Coverage Analysis


**Audit scope:** up to L3

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 8 |
| L2 | 183 | 22 |
| L3 | 92 | 7 |

**Total consolidated findings: 35**

*End of Consolidated Security Audit Report*