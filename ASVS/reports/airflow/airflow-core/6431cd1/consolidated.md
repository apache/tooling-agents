# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | apache/airflow/airflow-core |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 19, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 20 |

## Executive Summary

This consolidated report presents the results of an automated security audit of the Apache Airflow core repository, evaluated against OWASP ASVS Level 1 requirements across 15 security domains. The audit synthesized 70 individual source reports into 20 confirmed findings.

### Severity Distribution

| Severity | Count |
|----------|-------| Medium | 2 | Informational | 1 |
| **Total** | **19** |

### Level Coverage

All findings are mapped to ASVS Level 1 (L1) requirements. The audit scope was limited to L1 controls, representing the minimum baseline for all applications.

### Top 5 Risks

2. **No Mechanism for Bulk Session Invalidation on Account Termination (FINDING-002, High)** — When user accounts are terminated or deactivated, there is no mechanism to invalidate all outstanding tokens for that user, leaving a window where terminated users retain access (ASVS 7.4.2).

3. **Token Refresh Does Not Revoke Previous Token (FINDING-003, Medium)** — The token refresh flow issues a new token without invalidating the previous one, allowing token accumulation and extending the effective attack window if any token is compromised (ASVS 7.2.4).

4. **ReactMarkdown Missing rehype-sanitize Allows javascript: Protocol in Markdown Links (FINDING-004, Medium)** — User-supplied markdown content rendered via ReactMarkdown lacks sanitization, permitting `javascript:` protocol URLs in rendered links, creating a stored XSS vector (ASVS 1.2.2, 1.3.1).

5. **is_authorized_custom_view Ignores Method Parameter — Write Operations Authorized at VIEWER Level (FINDING-008, Low)** — The SimpleAuthManager's custom view authorization method does not differentiate between HTTP methods, effectively granting write-level access to users with only VIEWER privileges (ASVS 8.2.1).

### Positive Controls

The audit identified 32 positive security controls demonstrating mature security practices across the codebase:

- **JWT Infrastructure**: Signature validation is enforced via PyJWT with explicit algorithm specification; signing keys are sourced from configuration (not token headers); expiry and not-before claims are validated; tokens are dynamically generated rather than static secrets.
- **Authentication Design**: Constant-time credential comparison via `hmac.compare_digest()`; cryptographically random auto-generated passwords (~85–91 bits entropy); no hardcoded default accounts; password composition rules aligned with modern NIST guidance (no character-type requirements, no truncation).
- **Authorization Enforcement**: All authorization checks are performed server-side in the auth manager backend; parameterized queries and ORM usage protect against injection; server-side validation enforced via FastAPI and Pydantic.
- **Delegation Model**: TLS termination, HSTS, CORS, rate limiting, and file size limits are explicitly delegated to Deployment Managers at the reverse proxy layer, with documentation in `security_model.rst`. This is an intentional architecture decision for a library/platform component.
- **Dependency Management**: The project publishes per-version SBOMs, uses provider package architecture to scope dependency blast radius, and documents an explicit policy requiring proof of exploitability before accepting upstream CVEs as Airflow vulnerabilities.
- **Output Encoding**: `getSafeExternalUrl()` utility exists for URL protocol validation; consistent `encodeURIComponent` usage for primary URL parameters (dagId, runId, taskId); sensitive field redaction via `redact_password()`.

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

### 3.2 High

#### FINDING-002: No Mechanism for Bulk Session Invalidation on Account Termination

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Reports** | 7.4.2.md |
| **Related** | - |

**Description:**

The `JWTValidator` class provides only `revoke_token(self, token: str)` which revokes a single known token by its JTI. There is no `revoke_all_user_tokens(user_id)` method, no per-user 'not valid before' timestamp mechanism, no per-user signing key rotation, and no user-scoped token invalidation of any kind. When an employee leaves and their account is disabled/deleted, any previously issued JWT tokens remain valid until their natural expiration (up to 24 hours for REST API tokens).

**Remediation:**

Implement per-user 'not valid before' timestamp: add a `user_session_invalidation` table with `(user_id, not_valid_before)` and check `iat` against it during validation. Wire this into account disable/delete workflows.

---

### 3.3 Medium

#### FINDING-003: Token Refresh Does Not Revoke Previous Token

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 7.2.4 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/middlewares/refresh_token.py |
| **Source Reports** | 7.2.4.md |
| **Related** | - |

**Description:**

When a token is refreshed (approaching expiry), a new token is generated and set as a cookie, but the previous token is not revoked via `JWTValidator.revoke_token()`. If the old token was captured (e.g., via a man-in-the-middle attack or browser extension), it remains valid until its natural expiration. For the REST API with a 24-hour default expiration, this provides a substantial window where both old and new tokens are simultaneously valid. Note: severity is tempered by the fact that for cookie-based sessions, the old cookie is overwritten on the client side, limiting exposure to scenarios where tokens are intercepted in transit.

**Remediation:**

In `JWTRefreshMiddleware`, call `revoke_token(current_token)` before issuing the replacement token.

---

#### FINDING-004: ReactMarkdown missing rehype-sanitize allows javascript: protocol in markdown links

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS sections** | 1.2.2, 1.3.1 |
| **Files** | airflow-core/src/airflow/ui/src/components/ReactMarkdown.tsx |
| **Source Reports** | 1.2.2.md, 1.3.1.md |
| **Related** | FINDING-015 |

**Description:**

The ReactMarkdown component uses `skipHtml` to strip raw HTML but does not apply `rehype-sanitize`. Without protocol sanitization, markdown links with `javascript:` or `data:` protocols could pass through. DAG descriptions support markdown, and without protocol validation, these URLs could execute in the viewer's session. While DAG authors are trusted per the security model, this could enable privilege escalation from DAG author to admin via stored XSS when admins view DAG descriptions in the UI. The `getSafeExternalUrl()` utility exists in the codebase but is NOT applied in ReactMarkdown.tsx where markdown link hrefs are rendered.

**Remediation:**

Add `rehype-sanitize` with a schema restricting href protocols to http, https, and mailto. Alternatively, apply `getSafeExternalUrl()` to the LinkComponent's href prop to validate protocols before rendering.

### 3.4 Low

#### FINDING-005: Auto-Generated Signing Key Uses Only 128 Bits for HS512 Algorithm

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 7.2.3 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Reports** | 7.2.3.md |
| **Related Findings** | - |

**Description:**

DOWNGRADED from Medium: The auto-generated key is a fallback with an explicit log warning directing Deployment Managers to configure the key. Per the profile, symmetric JWT key configuration is delegated to Deployment Managers ('if the secret is only available to api-server and scheduler via deployment configuration'). The 128-bit fallback remains computationally infeasible to brute-force and primarily causes operational issues (cross-process mismatch) rather than a direct security bypass.

**Remediation:**

Change `os.urandom(16)` to `os.urandom(64)` for HS512 algorithm strength alignment.

---

#### FINDING-006: No Explicit Denial of "none" Algorithm in Allowlist Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 9.1.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Reports** | 9.1.2.md |
| **Related Findings** | - |

**Description:**

The JWTValidator and JWTGenerator do not programmatically block the 'none' algorithm. If an administrator sets jwt_algorithm = none in airflow.cfg, jwt.decode(..., algorithms=["none"]) would accept unsigned tokens, allowing authentication bypass. While this requires administrator misconfiguration, the code lacks safeguards against this class of configuration error.

**Remediation:**

Add explicit 'none' algorithm denial in JWTValidator.__attrs_post_init__() and JWTGenerator.__attrs_post_init__() by checking the configured algorithm list against a blocked set containing 'none' and raising ValueError if matched.

---

#### FINDING-007: Role-to-Resource Mapping Not Formally Documented Outside Implementation Code

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.1.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 8.1.1.md |
| **Related Findings** | - |

**Description:**

The authorization rules for the SimpleAuthManager are defined programmatically within `_is_authorized()` and the individual `is_authorized_*` methods, but there is no formal documentation artifact that maps roles to resource permissions in a way that can be easily audited or reviewed by non-developers.

**Remediation:**

Create a formal authorization matrix document that maps roles × resources × methods to allow/deny decisions, generated from or validated against the code implementation.

---

#### FINDING-008: is_authorized_custom_view Ignores Method Parameter — Write Operations Authorized at VIEWER Level

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | - |

**Description:**

[DOWNGRADED from Medium] SimpleAuthManager is a development-only auth manager not intended for production use. The `is_authorized_custom_view` method hardcodes method='GET' ignoring the actual method parameter, allowing VIEWER-role users to perform write operations on custom views. Impact is limited to development environments as production deployments should use a production-ready auth manager.

**Remediation:**

Pass the actual `method` parameter to `_is_authorized()` instead of hardcoding 'GET', using `allow_get_role=SimpleAuthManagerRole.VIEWER` and `allow_role=SimpleAuthManagerRole.ADMIN`.

---

#### FINDING-009: filter_authorized_menu_items Returns All Items Without Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | - |

**Description:**

All authenticated users (including VIEWER role) see all menu items in the UI, regardless of whether they have permission to access the underlying resources. While this doesn't grant actual access (API-level auth still applies), it exposes the existence of restricted functionality and can mislead users about their access level.

**Remediation:**

Implement basic menu filtering in SimpleAuthManager based on user role to provide development parity with production auth managers.

---

#### FINDING-010: SimpleAuthManager Does Not Use Resource-Specific Identifiers for Authorization Decisions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | - |

**Description:**

[DOWNGRADED from Medium] SimpleAuthManager is a development-only auth manager not intended for production. It receives resource details (conn_id, dag_id, etc.) but only uses team_name for access decisions. The abstract interface (BaseAuthManager) properly supports per-resource authorization; production auth managers should implement finer-grained control.

**Remediation:**

For production deployments, ensure a production-ready auth manager (FAB, Keycloak) is configured that utilizes the resource detail identifiers for per-resource authorization decisions.

---

#### FINDING-011: Authorization Details Can Be None, Bypassing Team Isolation Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py |
| **Source Reports** | 8.2.2.md |
| **Related Findings** | - |

**Description:**

When `details` is `None` (as allowed by all `is_authorized_*` signatures), `team_name` defaults to `None`, and the team check is skipped entirely. If any API endpoint fails to pass resource details to the authorization check, team-based isolation is bypassed.

**Remediation:**

In multi-team mode, add a defensive check that denies access by default when team_name is None for team-scoped resources. Log a warning for debugging.

---

#### FINDING-012: Resource identifier path parameters lack documented format validation rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.1.1, 2.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/routes/public/backfills.py, airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py, airflow-core/src/airflow/api_fastapi/core_api/routes/public/dags.py, airflow-core/src/airflow/api_fastapi/core_api/routes/public/pools.py, airflow-core/src/airflow/api_fastapi/core_api/routes/public/variables.py |
| **Source Reports** | 2.1.1.md, 2.2.1.md |
| **Related Findings** | - |

**Description:**

Several API endpoints accept resource identifiers as plain string parameters without documented or enforced format constraints defining what constitutes a valid identifier. While Pydantic models provide structural validation for request bodies, path and query parameters for resource identifiers lack defined patterns, length limits, or character restrictions. This affects the ability to enforce business expectations about valid identifier formats.

**Remediation:**

Define format validation rules for all resource identifiers using Path() constraints with explicit validation. Add Path(min_length=1, max_length=250, pattern=r'^[\w\-\.]+$') or similar constraints to resource identifier path parameters. Document these validation rules in OpenAPI schema annotations or Pydantic validators, e.g. Path(min_length=1, max_length=250, pattern=DAG_ID_PATTERN).

---

#### FINDING-013: update_mask query parameter in connections lacks allow-list validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/routes/public/connections.py |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | - |

**Description:**

The update_mask parameter in patch_connection() accepts arbitrary field names without an explicit allow-list, unlike patch_dag() which explicitly validates update_mask. While the intersection with model_fields_set provides implicit filtering, this is a less explicit and auditable approach that doesn't enforce positive validation against expected values.

**Remediation:**

Define an explicit ALLOWED_CONNECTION_UPDATE_FIELDS set and validate update_mask against it, raising HTTP 400 for invalid fields. This approach should mirror the explicit validation pattern used in patch_dag().

---

#### FINDING-014: mapIndex not encoded with encodeURIComponent in Iframe.tsx

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS Section(s)** | 1.2.2 |
| **Files** | airflow-core/src/airflow/ui/src/pages/Iframe.tsx |
| **Source Reports** | 1.2.2.md |
| **Related Findings** | - |

**Description:**

In Iframe.tsx, `mapIndex` is substituted into iframe src URL without `encodeURIComponent()`, while peer parameters (dagId, runId, taskId) are all encoded. This inconsistency could allow URL fragment injection within the same trusted origin configured by the plugin.

**Remediation:**

Apply `encodeURIComponent(mapIndex)` consistent with peer parameter handling.

---

#### FINDING-015: ReactMarkdown Missing rehype-sanitize Despite Documented Architecture

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 3.2.2 |
| **Files** | airflow-core/src/airflow/ui/src/components/ReactMarkdown.tsx |
| **Source Reports** | 3.2.2.md |
| **Related Findings** | FINDING-004 |

**Description:**

DAG authors are trusted users who can execute arbitrary code by design. The missing rehype-sanitize is a defense-in-depth gap but not exploitable given skipHtml + react-markdown built-in URL sanitization, and the trusted DAG author threat model. However, the implementation does not align with documented architecture expectations.

**Remediation:**

Add rehype-sanitize to ReactMarkdown component to align implementation with documented architecture and provide defense-in-depth.

---

#### FINDING-016: Documentation Lacks Malicious Account Lockout Prevention Guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-307 |
| **ASVS Section(s)** | 6.1.1 |
| **Files** | airflow-core/docs/security/security_model.rst |
| **Source Reports** | 6.1.1.md |
| **Related Findings** | - |

**Description:**

The application security documentation delegates rate limiting and anti-automation controls to the Deployment Manager per the security profile. While existing documentation mentions rate-limiting delegation, it lacks specific guidance on preventing malicious account lockout scenarios. More detailed guidance on lockout-prevention strategies (e.g., IP-based throttling over account-based lockout) would improve the security posture of deployments by helping Deployment Managers configure these controls more effectively against credential stuffing and brute force attacks.

**Remediation:**

Add a brief section to security_model.rst noting that account lockout prevention (e.g., IP-based throttling over account-based lockout) is recommended when deployment managers configure rate limiting. Include guidance on distinguishing between legitimate failed login attempts and malicious brute force patterns to prevent attackers from weaponizing lockout mechanisms.

---

#### FINDING-017: DagRun.update_state() Lacks Pre-condition State Assertion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | airflow-core/src/airflow/models/dagrun.py |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | - |

**Description:**

DOWNGRADED from Medium: The scheduler is a trusted component that 'never runs user code' (profile). All current callers correctly filter for RUNNING state. The concern is purely about defense-in-depth against hypothetical future internal callers, not an externally exploitable gap. The update_state() method processes state transitions without asserting that the DagRun is in the expected RUNNING state.

**Remediation:**

Add pre-condition assertion verifying self._state == DagRunState.RUNNING at the start of update_state().

---

#### FINDING-018: DagRun.set_state() Does Not Enforce Documented Transition Paths

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | airflow-core/src/airflow/models/dagrun.py |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | - |

**Description:**

DOWNGRADED from Medium: The scheduler is a trusted component and all current callers follow correct transitions. The concern is about future-proofing internal code discipline, not an externally exploitable vulnerability. The method validates the target state is a valid DagRunState but does not validate that the transition from the current state to the target state follows documented allowed paths.

**Remediation:**

Define a VALID_DR_TRANSITIONS map and enforce allowed transitions in set_state().

---

#### FINDING-019: clear_task_instances() Executes Database Modifications Before Validation Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | airflow-core/src/airflow/models/taskinstance.py |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | - |

**Description:**

The prepare_db_for_next_try() call executes before the prevent_running_task validation check. While the SQLAlchemy transaction model ensures rollback on exception, the ordering violates the principle of validating before modifying.

**Remediation:**

Reorder the prevent_running_task check to occur before prepare_db_for_next_try().

### 3.5 Informational

#### FINDING-020: ConnectionResponse includes redacted password field rather than omitting it entirely

| Attribute | Value |
|-----------|-------|
| Severity | ⚪ Info |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 15.3.1 |
| Files | airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py |
| Source Reports | 15.3.1.md |
| Related | - |

**Description:**

DOWNGRADED from Low to Informational. The password field is properly redacted via redact_password(). The profile documents sensitive value masking as a positive control. This is a defense-in-depth suggestion only; the current redaction approach is functionally secure per the report's own assessment.

**Remediation:**

Consider creating a ConnectionSummaryResponse model without the password field for collection/list endpoints.

---

---

# 4. Positive Security Controls

| Control ID | Domain | Control Description | Evidence | Related Files |
|------------|--------|---------------------|----------|---------------|
| PSC-001 | jwt_token_authentication | SimpleAuthManager is scoped to development environments; production auth manager selection is Deployment Manager's responsibility | Dropped finding ASVS-721-LOW-001 | - |
| PSC-002 | jwt_token_authentication | JWT tokens are self-contained and dynamically generated (not static API secrets) | 7.2.2 section passed | - |
| PSC-003 | jwt_token_authentication | JWT signature validation enforced via PyJWT library with algorithm specification | 9.1.1 section passed | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` |
| PSC-004 | jwt_token_authentication | JWT validation uses pre-configured signing keys from configuration, not from token headers | 9.1.3 section passed - no jku, x5u, or jwk header processing | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` |
| PSC-005 | jwt_token_authentication | JWT expiry (exp) and not-before (nbf) claims are validated by PyJWT library | 9.2.1 section passed | `airflow-core/src/airflow/api_fastapi/auth/tokens.py` |
| PSC-006 | auth_manager_authorization | Authorization enforcement occurs at trusted service layer (SimpleAuthManager backend) | All authorization checks are performed server-side in SimpleAuthManager methods, not client-side | `airflow-core/src/airflow/api_fastapi/auth/managers/simple/simple_auth_manager.py` |
| PSC-007 | tls_transport_security | TLS protocol version and cipher suite configuration is delegated to Deployment Manager as part of reverse proxy responsibilities | Dropped finding ASVS-1211-MED-001 | - |
| PSC-008 | tls_transport_security | TLS termination and HTTPS enforcement is delegated to the reverse proxy layer managed by Deployment Managers | Dropped finding ASVS-1221-MED-001 | - |
| PSC-009 | tls_transport_security | TLS certificate selection and trust configuration is delegated to Deployment Manager as part of infrastructure responsibilities | Promoted from dropped finding ASVS-1222-LOW-001 | - |
| PSC-010 | tls_transport_security | TLS termination and transport security headers (including HSTS) are delegated to the reverse proxy layer managed by Deployment Managers | Dropped finding ASVS-341-HIGH-001 | - |
| PSC-011 | tls_transport_security | TLS termination and WSS enforcement is delegated to the reverse proxy layer managed by Deployment Managers | Dropped finding ASVS-441-MED-001 | - |
| PSC-012 | api_input_validation | Parameterized queries and ORM usage protects against SQL injection | ASVS 1.2.4 passed - application uses parameterized queries and ORMs | - |
| PSC-013 | api_input_validation | No OS command injection vulnerabilities identified | ASVS 1.2.5 passed - OS calls are properly protected | - |
| PSC-014 | api_input_validation | Server-side validation enforced at trusted service layer | ASVS 2.2.2 passed - validation occurs server-side using FastAPI and Pydantic | - |
| PSC-015 | ui_output_encoding | getSafeExternalUrl() utility exists in codebase for URL protocol validation | Referenced in ReactMarkdown.tsx finding as existing but not applied | - |
| PSC-016 | ui_output_encoding | Consistent use of encodeURIComponent for URL parameters (dagId, runId, taskId) | Peer parameters in Iframe.tsx are properly encoded | `airflow-core/src/airflow/ui/src/pages/Iframe.tsx` |
| PSC-017 | ui_output_encoding | Plugin external views are loaded from trusted sources controlled by Deployment Managers; permissive iframe sandbox is an intentional design decision | Dropped finding ASVS-321-LOW-001 | - |
| PSC-018 | http_security_headers | CORS configuration including origin allowlists is delegated to Deployment Manager via airflow.cfg settings | Dropped finding ASVS-342-MED-002 | - |
| PSC-019 | password_authentication | SimpleAuthManager auto-generates 16-character passwords with cryptographic randomness (secrets.choice), exceeding ASVS 6.2.1 minimum of 8 characters (15 recommended) | Auto-generated passwords have ~85-91 bits of entropy making common password collisions statistically impossible | - |
| PSC-020 | password_authentication | SimpleAuthManager is explicitly documented as dev-only with _looks_like_production() warning; production deployments use pluggable auth managers (FAB, Keycloak) that support password change | Production detection heuristic warns operators when dev-only auth manager is used in production-like configurations | - |
| PSC-021 | password_authentication | Constant-time comparison via hmac.compare_digest() is implemented for credential verification infrastructure | Generic error messages and constant-time comparison prevent user enumeration as defense-in-depth | - |
| PSC-022 | password_authentication | User list is configuration-driven with no hardcoded default accounts; all-admins mode requires explicit opt-in | No default accounts (root, admin, sa) present in application code | - |
| PSC-023 | password_authentication | Password composition rules allow any character combination without enforcing character type requirements | ASVS 6.2.5 compliance verified | - |
| PSC-024 | password_authentication | Password paste functionality and password manager integration permitted | ASVS 6.2.7 compliance verified | - |
| PSC-025 | password_authentication | Passwords verified exactly as received without truncation or case transformation | ASVS 6.2.8 compliance verified | - |
| PSC-026 | password_authentication | No password hints or knowledge-based authentication present | ASVS 6.4.2 compliance verified | - |
| PSC-027 | rate_limiting_anti_automation | Rate limiting and brute force protection explicitly delegated to Deployment Manager with documentation in security_model.rst | Documented delegation model in security profile | `airflow-core/docs/security/security_model.rst` |
| PSC-028 | rate_limiting_anti_automation | HttpAccessLogMiddleware provides structured logs (client IP, path, status code) enabling external rate limiting systems | Middleware implementation supports external rate limiting through comprehensive access logging | - |
| PSC-029 | file_upload_handling | Payload/file size limits delegated to Deployment Manager at proxy layer | security/api.rst: 'implement appropriate size limits at the proxy layer' | `security/api.rst` |
| PSC-030 | api_data_exposure | Password redaction via redact_password() function | The password field is properly redacted and documented as sensitive value masking positive control | `airflow-core/src/airflow/api_fastapi/core_api/datamodels/connections.py` |
| PSC-031 | dependency_management | Project documents explicit policy on 3rd-party dependency vulnerabilities: CVEs not accepted without proof of exploitability in Airflow; SBOM published per-version for dependency inventory; dependency management delegated to deployers | 15.1.1.md - Dropped finding ASVS-1511-MED-001 | - |
| PSC-032 | dependency_management | 3rd-party dependency lifecycle management delegated to deployers; project publishes SBOM and uses provider package architecture to scope dependency blast radius | 15.2.1.md - Dropped finding ASVS-1521-MED-001 | - |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Architecture, Design and Threat Modeling** |
| 1.2.1 | Output encoding for HTTP response, HTML document, or XML document | ✅ Pass | - |
| 1.2.2 | Dynamic URL building with untrusted data encoding | ⚠️ Partial | FINDING-004, FINDING-014 |
| 1.2.3 | Output encoding when dynamically building JavaScript content | ✅ Pass | - |
| 1.2.4 | Injection Prevention - Database Queries | ✅ Pass | PSC-012 |
| 1.2.5 | Injection Prevention - OS Command Injection | ✅ Pass | PSC-013 |
| 1.3.1 | HTML sanitization from WYSIWYG editors | ⚠️ Partial | FINDING-004 |
| 1.3.2 | Avoid eval() or dynamic code execution | ✅ Pass | - |
| 1.5.1 | Safe Deserialization - XML Parser Configuration | ➖ N/A | No XML parsing in scope |
| **V2: Authentication** |
| 2.1.1 | Validation and Business Logic Documentation | ⚠️ Partial | FINDING-012 |
| 2.2.1 | Input Validation | ⚠️ Partial | FINDING-012, FINDING-013 |
| 2.2.2 | Server-Side Validation | ✅ Pass | PSC-014 |
| 2.3.1 | Business logic flows sequential step order | ⚠️ Partial | FINDING-017, FINDING-018, FINDING-019 |
| **V3: Session Management** |
| 3.2.1 | Security controls to prevent unintended content rendering | ➖ N/A | Not browser-rendered content |
| 3.2.2 | Safe rendering functions for text content | ⚠️ Partial | FINDING-015 |
| 3.3.1 | Cookie Setup - Secure attribute verification | ✅ Pass | - |
| 3.4.1 | Browser Security Mechanism Headers - HSTS header enforcement | ➖ N/A | Delegated to Deployment Manager (PSC-010) |
| 3.4.2 | Browser Security Mechanism Headers - CORS Access-Control-Allow-Origin validation | ➖ N/A | Delegated to Deployment Manager (PSC-018) |
| 3.5.1 | Browser Origin Separation - Anti-forgery token validation | ✅ Pass | - |
| 3.5.2 | Browser Origin Separation - CORS preflight mechanism enforcement | ✅ Pass | - |
| 3.5.3 | Browser Origin Separation - HTTP method validation | ✅ Pass | - |
| **V4: Access Control** |
| 4.1.1 | Generic Web Service Security - Content-Type header verification | ✅ Pass | - |
| 4.4.1 | WebSocket - WSS for all WebSocket connections | ➖ N/A | Delegated to Deployment Manager (PSC-011) |
| **V5: Validation, Sanitization and Encoding** |
| 5.2.1 | File Upload - Size Validation | ➖ N/A | Delegated to Deployment Manager (PSC-029) |
| 5.2.2 | File Upload - Extension and Content Type Validation | ➖ N/A | No file upload in scope |
| 5.3.1 | File Storage - Execution Prevention | ✅ Pass | - |
| 5.3.2 | File Storage - Path Traversal Prevention | ➖ N/A | No user-controlled file paths |
| **V6: Stored Cryptography** |
| 6.1.1 | Authentication Documentation - Rate Limiting and Anti-Automation Controls | ⚠️ Partial | FINDING-016 |
| 6.2.1 | User set passwords at least 8 characters | ➖ N/A | Auto-generated only (PSC-019) |
| 6.2.2 | Users can change their password | ➖ N/A | Dev-only auth manager (PSC-020) |
| 6.2.3 | Password change requires current and new password | ➖ N/A | Dev-only auth manager (PSC-020) |
| 6.2.4 | Passwords checked against top 3000 common passwords | ➖ N/A | Auto-generated only (PSC-019) |
| 6.2.5 | Passwords of any composition can be used | ✅ Pass | PSC-023 |
| 6.2.6 | Password input fields use type=password | ➖ N/A | No password input fields |
| 6.2.7 | Paste functionality and password managers permitted | ✅ Pass | PSC-024 |
| 6.2.8 | Password verified exactly as received | ✅ Pass | PSC-025 |
| 6.3.1 | Controls to prevent credential stuffing and brute force | ➖ N/A | Delegated to Deployment Manager (PSC-027) |
| 6.3.2 | Default accounts not present or disabled | ➖ N/A | No default accounts (PSC-022) |
| 6.4.1 | System generated passwords are secure and expire | ➖ N/A | Tokens used for API access |
| 6.4.2 | Password hints or secret questions not present | ✅ Pass | PSC-026 |
| **V7: Error Handling and Logging** |
| 7.2.1 | Application performs session token verification using trusted backend service | ✅ Pass | PSC-006 |
| 7.2.2 | Self-contained or reference tokens dynamically generated | ✅ Pass | PSC-002 |
| 7.2.3 | Reference tokens unique with 128 bits entropy | ⚠️ Partial | FINDING-005 |
| 7.2.4 | New session token on authentication, terminate current | ⚠️ Partial | FINDING-003 |
| 7.4.1 | Session termination disallows further use | ❌ Fail | |
| 7.4.2 | Terminate all sessions when account disabled/deleted | ❌ Fail | FINDING-002 |
| **V8: Data Protection** |
| 8.1.1 | Authorization Documentation | ⚠️ Partial | FINDING-007 |
| 8.2.1 | General Authorization Design - Function-Level Access | ⚠️ Partial | FINDING-008, FINDING-009 |
| 8.2.2 | General Authorization Design - Data-Specific Access | ⚠️ Partial | FINDING-010, FINDING-011 |
| 8.3.1 | Operation Level Authorization | ✅ Pass | - |
| **V9: Communication** |
| 9.1.1 | Self-contained tokens validated using digital signature or MAC | ✅ Pass | PSC-003 |
| 9.1.2 | Only allowlist algorithms for tokens | ⚠️ Partial | FINDING-006 |
| 9.1.3 | Key material from trusted pre-configured sources | ✅ Pass | PSC-004 |
| 9.2.1 | Token validity time span verification | ✅ Pass | PSC-005 |
| **V10: Malicious Code** |
| 10.4.1 | OAuth Authorization Server - Redirect URI Validation | ➖ N/A | Not OAuth provider |
| 10.4.2 | OAuth Authorization Server - Authorization Code Single Use | ➖ N/A | Not OAuth provider |
| 10.4.3 | OAuth Authorization Server - Authorization Code Lifetime | ➖ N/A | Not OAuth provider |
| 10.4.4 | OAuth Authorization Server - Grant Type Restrictions | ➖ N/A | Not OAuth provider |
| 10.4.5 | OAuth Authorization Server - Refresh Token Replay Mitigation | ➖ N/A | Not OAuth provider |
| **V11: Business Logic** |
| 11.3.1 | Insecure Block Modes and Padding | ✅ Pass | - |
| 11.3.2 | Approved Ciphers and Modes | ✅ Pass | - |
| 11.4.1 | Approved Hash Functions | ✅ Pass | - |
| **V12: Files and Resources** |
| 12.1.1 | General TLS Security Guidance - Latest TLS versions enabled | ➖ N/A | Delegated to Deployment Manager (PSC-007) |
| 12.2.1 | HTTPS Communication - TLS for all connectivity | ➖ N/A | Delegated to Deployment Manager (PSC-008) |
| 12.2.2 | HTTPS Communication - Publicly trusted TLS certificates | ➖ N/A | Delegated to Deployment Manager (PSC-009) |
| **V13: API and Web Service** |
| 13.4.1 | Unintended Information Leakage | ➖ N/A | No sensitive info in errors |
| **V14: Configuration** |
| 14.2.1 | General Data Protection - Sensitive data not in URL/query strings | ✅ Pass | - |
| 14.3.1 | Client-side Data Protection - Authenticated data cleared | ✅ Pass | - |
| **V15: Configuration** |
| 15.1.1 | Secure Coding and Architecture Documentation | ➖ N/A | Delegated to deployers (PSC-031) |
| 15.2.1 | Security Architecture and Dependencies | ➖ N/A | Delegated to deployers (PSC-032) |
| 15.3.1 | Defensive Coding - Return only required subset of fields | ✅ Pass | PSC-030 (with FINDING-020 note) |

### Summary Statistics
- ✅ **Pass**: 31 requirements
- ⚠️ **Partial**: 14 requirements
- ❌ **Fail**: 2 requirements
- ➖ **N/A**: 26 requirements (delegated or out of scope)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related PSCs | Affected Domains |
|------------|----------|-------------------|--------------|------------------|
| FINDING-002 | High | 7.4.2 | PSC-006 | auth_manager_authorization |
| FINDING-003 | Medium | 7.2.4 | PSC-002, PSC-003 | jwt_token_authentication |
| FINDING-004 | Medium | 1.2.2, 1.3.1 | PSC-015 | ui_output_encoding |
| FINDING-005 | Low | 7.2.3 | PSC-003, PSC-004 | jwt_token_authentication |
| FINDING-006 | Low | 9.1.2 | PSC-003 | jwt_token_authentication |
| FINDING-007 | Low | 8.1.1 | PSC-006 | auth_manager_authorization |
| FINDING-008 | Low | 8.2.1 | PSC-006 | auth_manager_authorization |
| FINDING-009 | Low | 8.2.1 | PSC-006 | auth_manager_authorization |
| FINDING-010 | Low | 8.2.2 | PSC-006 | auth_manager_authorization |
| FINDING-011 | Low | 8.2.2 | PSC-006 | auth_manager_authorization |
| FINDING-012 | Low | 2.1.1, 2.2.1 | PSC-014 | api_input_validation |
| FINDING-013 | Low | 2.2.1 | PSC-014 | api_input_validation |
| FINDING-014 | Low | 1.2.2 | PSC-016 | ui_output_encoding |
| FINDING-015 | Low | 3.2.2 | PSC-015 | ui_output_encoding |
| FINDING-016 | Low | 6.1.1 | PSC-027, PSC-028 | rate_limiting_anti_automation |
| FINDING-017 | Low | 2.3.1 | PSC-014 | api_input_validation |
| FINDING-018 | Low | 2.3.1 | PSC-014 | api_input_validation |
| FINDING-019 | Low | 2.3.1 | PSC-014 | api_input_validation |
| FINDING-020 | Informational | 15.3.1 | PSC-030 | api_data_exposure |

### Domain Coverage Summary

|--------|----------------|----------|------|--------|-----|------|--------------|
| jwt_token_authentication | 0 | 1 | 0 | 1 | 2 | 0 | PSC-001 through PSC-005 |
| auth_manager_authorization | 6 | 0 | 1 | 0 | 5 | 0 | PSC-006 |
| ui_output_encoding | 3 | 0 | 0 | 1 | 2 | 0 | PSC-015, PSC-016, PSC-017 |
| api_input_validation | 5 | 0 | 0 | 0 | 5 | 0 | PSC-012, PSC-013, PSC-014 |
| rate_limiting_anti_automation | 1 | 0 | 0 | 0 | 1 | 0 | PSC-027, PSC-028 |
| api_data_exposure | 1 | 0 | 0 | 0 | 0 | 1 | PSC-030 |
| tls_transport_security | 0 | 0 | 0 | 0 | 0 | 0 | PSC-007 through PSC-011 |
| password_authentication | 0 | 0 | 0 | 0 | 0 | 0 | PSC-019 through PSC-026 |
| file_upload_handling | 0 | 0 | 0 | 0 | 0 | 0 | PSC-029 |
| dependency_management | 0 | 0 | 0 | 0 | 0 | 0 | PSC-031, PSC-032 |

### ASVS Chapter Coverage

| ASVS Chapter | Pass | Partial | Fail | N/A | Total |
|--------------|------|---------|------|-----|-------|
| V1: Architecture | 4 | 2 | 0 | 1 | 7 |
| V2: Authentication | 1 | 2 | 0 | 0 | 3 |
| V3: Session Management | 4 | 1 | 0 | 2 | 7 |
| V4: Access Control | 1 | 0 | 0 | 1 | 2 |
| V5: Validation | 1 | 0 | 0 | 3 | 4 |
| V6: Cryptography | 4 | 1 | 0 | 7 | 12 |
| V7: Error Handling | 2 | 2 | 2 | 0 | 6 |
| V8: Data Protection | 1 | 2 | 0 | 0 | 3 |
| V9: Communication | 2 | 1 | 0 | 0 | 3 |
| V10: Malicious Code | 0 | 0 | 0 | 5 | 5 |
| V11: Business Logic | 3 | 0 | 0 | 0 | 3 |
| V12: Files/Resources | 0 | 0 | 0 | 3 | 3 |
| V13: API | 0 | 0 | 0 | 1 | 1 |
| V14: Configuration | 2 | 0 | 0 | 0 | 2 |
| V15: Configuration | 1 | 0 | 0 | 2 | 3 |

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 20 |

**Total consolidated findings: 20**

*End of Consolidated Security Audit Report*