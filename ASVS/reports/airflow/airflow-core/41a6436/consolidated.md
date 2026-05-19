# Security Audit Consolidated Report — apache/airflow/airflow-core

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/airflow-core |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | N/A |
| Date | May 19, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 10 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 1 | 0 | 9 | 0 |

### Level Coverage

All 10 findings map to ASVS Level 1 (L1) requirements. The audit scope covered 18 security domains across the airflow-core repository, including API input validation, session management, UI output encoding, authorization enforcement, and DAG serialization security.

### Top 5 Risks

1. **No Mechanism to Terminate All Active Sessions on User Account Disable/Delete (FINDING-001, High)** — When a user account is disabled or deleted, existing active sessions are not invalidated, allowing continued access until natural session expiry. This is the only High-severity finding and represents the most immediate security risk.

2. **Unbounded `dag_runs_limit` Parameter Allows Excessive Database Load (FINDING-002, Low)** — The absence of an upper bound on the `dag_runs_limit` parameter enables clients to trigger resource-exhaustive database queries, potentially causing denial-of-service conditions.

3. **Unbounded `run_ids` List in Streaming Endpoint Allows Excessive Sequential Processing (FINDING-003, Low)** — Similar to FINDING-002, an unbounded list parameter in a streaming endpoint can cause excessive sequential processing and resource consumption.

4. **Unconstrained `import_string()` in Exception and Trigger Deserialization (FINDING-008, Low)** — The use of `import_string()` without an explicit allowlist during deserialization could permit instantiation of unintended classes if an attacker gains write access to the metadata database.

5. **JWKS URL mode lacks explicit static algorithm allowlist (FINDING-006, Low)** — Without a fixed algorithm allowlist when using JWKS URL mode for JWT verification, the system may accept tokens signed with weaker algorithms than intended.

### Positive Controls

The audit identified substantial defensive measures already in place across the codebase:

- **Comprehensive SQL Injection Prevention** — All database operations use SQLAlchemy ORM with parameterized queries. Zero instances of raw SQL string construction or interpolation were found across all audited files. Filter operations, text search, prefix search, cursor pagination, and DELETE operations all use bound parameters consistently.

- **Layered Input Validation Architecture** — A four-layer validation approach is implemented: FastAPI/Pydantic type coercion, BaseParam subclass validation, business logic validation in route handlers, and SQLAlchemy parameterization at the database layer.

- **Robust XSS Prevention in UI** — React JSX auto-escaping is applied to all user-controlled values. Markdown rendering uses `skipHtml` to prevent raw HTML injection, and `react-markdown` provides built-in URL sanitization blocking `javascript:` and `data:` protocols. ANSI log rendering disables auto-linking, and extracted URLs receive `rel="noopener noreferrer"` attributes.

- **Consistent Authorization Enforcement** — Every API endpoint uses dependency-injected authorization decorators (`requires_access_dag`, `requires_access_asset`, `requires_access_connection`, `requires_access_variable`) via FastAPI's `Depends()` mechanism, ensuring no unprotected routes.

- **Sensitive Data Redaction** — Multiple layers of redaction are implemented: `redact_password` and `redact_extra` field validators for connection responses, `redact_val` model validators for variable responses, and safe error handling that prevents information leakage through malformed data. Stacktrace exposure is gated behind configuration flags with random tracking IDs.

- **Infrastructure Security Delegation** — TLS termination, CORS configuration, WebSocket security (WSS), payload size limits, and rate limiting are properly delegated to the deployment manager via reverse proxy configuration, as documented in project infrastructure control documentation.

---

## 3. Findings

### 3.2 High

#### FINDING-001: 🟠 No Mechanism to Terminate All Active Sessions on User Account Disable/Delete

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.4.2 |
| **File(s)** | airflow-core/src/airflow/models/revoked_token.py |
| **Source Report(s)** | 7.4.2.md |
| **Related Finding(s)** | None |

**Description:**

The RevokedToken model (shared infrastructure) has no per-user bulk revocation capability. When an admin disables/deletes a user account, there is no mechanism to identify or invalidate all active JTIs for that user. Existing tokens remain valid until natural expiration. The model only supports individual JTI-based revocation with no user-to-JTI mapping or per-user invalidation timestamp.

**Remediation:**

Implement a per-user invalidation timestamp (e.g., UserTokenInvalidation table) checked during JWT validation, or extend RevokedToken with a username column to support bulk revocation queries. Wire the chosen mechanism into account disable/delete flows.

---

### 3.4 Low

#### FINDING-002: 🔵 Unbounded `dag_runs_limit` Parameter Allows Excessive Database Load

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/core_api/routes/ui/dags.py |
| **Source Report(s)** | 2.2.1.md |
| **Related Finding(s)** | FINDING-003 |

**Description:**

The `dag_runs_limit` parameter accepts any integer value with no upper bound, bypassing pagination controls. While authentication is required and deployment-level rate limiting is expected, the lack of application-level bounds allows authenticated users to request arbitrarily large result sets, potentially causing excessive database load and memory consumption.

**Remediation:**

Add upper bound validation: `dag_runs_limit: Annotated[int, Query(ge=1, le=100, description="Number of recent DAG runs per DAG")] = 10`

---

#### FINDING-003: 🔵 Unbounded `run_ids` List in Streaming Endpoint Allows Excessive Sequential Processing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/core_api/routes/ui/grid.py |
| **Source Report(s)** | 2.2.1.md |
| **Related Finding(s)** | FINDING-002 |

**Description:**

The `run_ids` query parameter accepts an unbounded list of strings with no length limit. Each iteration opens a database session and executes queries, potentially tying up a worker thread for extended periods. An authenticated attacker could submit thousands of run IDs, causing resource exhaustion through sequential processing overhead.

**Remediation:**

Add length limit: `run_ids: Annotated[list[str] | None, Query(max_length=100)] = None` or validate at function start.

---

#### FINDING-004: 🔵 Missing `rel` and `target` Attributes on Markdown-Rendered Links

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | airflow-core/src/airflow/ui/src/components/ReactMarkdown.tsx:47-54 |
| **Source Report(s)** | 1.2.1.md |
| **Related Finding(s)** | - |

**Description:**

When users middle-click or browser extensions open markdown links in new tabs, the opened page can access `window.opener` to navigate the original Airflow tab (reverse tabnabbing). User-authored markdown (DAG descriptions) is parsed by react-markdown and the `href` is passed to `LinkComponent` which renders as `<a>` element without `rel="noopener noreferrer"`. This is a defense-in-depth issue since `react-markdown` already sanitizes `javascript:` and `data:` protocols via `micromark-util-sanitize-uri`. A DAG description containing `[Click here](https://attacker.example.com)` renders without `rel="noopener noreferrer"`, allowing the target page to execute `window.opener.location = 'https://phishing.example.com'`.

**Remediation:**

Add `rel="noopener noreferrer"` and `target="_blank"` attributes to the Link component in LinkComponent. Update the component to: `<Link color="fg.info" fontWeight="bold" href={href} rel="noopener noreferrer" target="_blank" title={title}>{children}</Link>`

---

#### FINDING-005: 🔵 Missing URL Encoding for mapIndex Parameter in Iframe URL Construction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 1.2.2 |
| **File(s)** | airflow-core/src/airflow/ui/src/pages/Iframe.tsx:43 |
| **Source Report(s)** | 1.2.2.md |
| **Related Finding(s)** | - |

**Description:**

The mapIndex parameter is directly substituted into the iframe src URL without encodeURIComponent() encoding, while other parameters (dagId, runId, taskId) are properly encoded. Data flows from URL path parameter (user-controlled via browser URL) through useParams() to mapIndex (string) and is directly substituted into iframe src. If a plugin defines href with {MAP_INDEX} placeholder, a user could inject additional query parameters. Impact is limited by iframe sandbox (allow-scripts allow-same-origin allow-forms) and the base template coming from trusted plugin configuration.

**Remediation:**

Apply encodeURIComponent to mapIndex parameter: if (mapIndex !== undefined) { src = src.replaceAll("{MAP_INDEX}", encodeURIComponent(mapIndex)); }

---

#### FINDING-006: 🔵 JWKS URL mode lacks explicit static algorithm allowlist

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-757 |
| **ASVS Section(s)** | 9.1.2 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Report(s)** | 9.1.2.md |
| **Related Finding(s)** | - |

**Description:**

When using a `trusted_jwks_url` without explicitly setting `[api_auth] jwt_algorithm`, the effective algorithm allowlist is whatever algorithms appear in the JWKS keys. If the JWKS endpoint is compromised or serves keys with unexpected algorithms, tokens signed with those algorithms would be accepted. This provides no defense-in-depth against JWKS endpoint compromise.

**Remediation:**

When `trusted_jwks_url` is configured without an explicit `jwt_algorithm`, default to `["RS256", "EdDSA"]` rather than `["GUESS"]` to provide defense-in-depth against JWKS endpoint compromise.

---

#### FINDING-007: 🔵 No Cookie Security Configuration Visible in Application Initialization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 3.3.1 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Report(s)** | 3.3.1.md |
| **Related Finding(s)** | - |

**Description:**

DOWNGRADED from Medium: Finding is speculative — no cookies are actually set in the analyzed code. JWT Bearer tokens are used for authentication. The report itself states 'this remains a coverage gap rather than a confirmed vulnerability.'

**Remediation:**

If cookies are used anywhere in the auth flow, establish application-wide cookie security defaults with Secure, HttpOnly, SameSite attributes and __Host-/__Secure- prefixes.

---

#### FINDING-008: 🔵 Unconstrained import_string() in Exception and Trigger Deserialization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | airflow-core/src/airflow/serialization/serialized_objects.py:within the deserialize classmethod |
| **Source Report(s)** | 1.3.2.md |
| **Related Finding(s)** | - |

**Description:**

The BaseSerialization.deserialize() method uses import_string() to dynamically load and instantiate exception classes (AIRFLOW_EXC_SER) and trigger classes (BASE_TRIGGER) without validating against a whitelist or checking subclass relationships. For AIRFLOW_EXC_SER, any importable class path can be specified and instantiated with arbitrary args/kwargs. The BASE_TRIGGER path similarly loads and instantiates any importable class. The data flow is: Serialized JSON (metadata database) → BaseSerialization.deserialize() → import_string(exc_cls_name) → exc_cls(*args, **kwargs). However, the source data is the metadata database, written exclusively by the DagFileProcessorProcess from trusted DAG authors. Per the project's security model, DAG authors are trusted with code execution. The known false positive guidance explicitly states that DAG serialization storing Python code as JSON strings is intentional because DAGs must be reconstructed for execution. import_string() only loads already-installed modules (not arbitrary code execution like eval()). Exploitation requires database content manipulation, which presupposes prior compromise.

**Remediation:**

For exceptions: validate against known exception base classes:
```python
elif type_ == DAT.AIRFLOW_EXC_SER:
    exc_cls = import_string(exc_cls_name)
    if not (isinstance(exc_cls, type) and issubclass(exc_cls, BaseException)):
        raise TypeError(f"Expected exception class, got {exc_cls_name}")
    return exc_cls(*args, **kwargs)
```

For triggers: validate against BaseTrigger:
```python
elif type_ == DAT.BASE_TRIGGER:
    tr_cls = import_string(tr_cls_name)
    if not (isinstance(tr_cls, type) and issubclass(tr_cls, BaseTrigger)):
        raise TypeError(f"Expected trigger class, got {tr_cls_name}")
    return tr_cls(**kwargs)
```

---

#### FINDING-009: 🔵 No Client-Side Cleanup Mechanism for Session Termination Scenarios

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-922 |
| **ASVS Section(s)** | 14.3.1 |
| **File(s)** | airflow-core/src/airflow/ui/src/layouts/Nav/LogoutModal.tsx |
| **Source Report(s)** | 14.3.1.md |
| **Related Finding(s)** | - |

**Description:**

The application does not implement client-side storage cleanup mechanisms for session termination scenarios. The LogoutModal performs no explicit client-side storage cleanup before redirecting to server logout, and there are no beforeunload or 401-response handlers to clear client storage on non-interactive session termination. However, the practical security impact is minimal as the audit confirmed that no authenticated data (tokens, credentials) is stored in browser-accessible storage—only UI preferences are stored in localStorage. This represents a defense-in-depth gap rather than an active vulnerability.

**Remediation:**

Implement a centralized client-side storage cleanup utility that: (1) is invoked in the logout flow before server redirect, (2) registers a beforeunload event handler to clear storage on browser close, and (3) implements an API response interceptor to clear storage on 401 responses. If authentication tokens are ever stored in browser-accessible storage in the future, ensure this cleanup mechanism is activated. Document the current architecture decision that authentication data is not stored client-side.

---

#### FINDING-010: 🔵 DagRun.set_state() Lacks Explicit State Machine Transition Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-841 |
| **ASVS Section(s)** | 2.3.1 |
| **File(s)** | airflow-core/src/airflow/models/dagrun.py |
| **Source Report(s)** | 2.3.1.md |
| **Related Finding(s)** | - |

**Description:**

The set_state() method validates that the target state is a member of State.dag_states but does not validate that the transition from the current state to the target state is logically valid. While all current callers follow correct patterns, this is a defense-in-depth gap. This represents a potential violation of sequential business logic flow enforcement, as invalid state transitions could bypass expected workflow progression.

**Remediation:**

Add explicit state transition validation map in DagRun.set_state() to enforce valid transitions (e.g., QUEUED can only go to RUNNING/FAILED, not directly to SUCCESS). Implement a state machine pattern that validates transitions against allowed paths before allowing state changes.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Api Input Validation | SQLAlchemy ORM parameterized queries | All route handlers use SQLAlchemy ORM with bound parameters, preventing SQL injection | — |
| Api Input Validation | Column comparison operators with bound parameters | parameters.py FilterParam.to_orm() - All filter operations (==, !=, <, >, IN, etc.) use parameterized queries | parameters.py |
| Api Input Validation | SQLAlchemy ilike() with bound params | parameters.py _SearchParam.to_orm() - All text search operations use parameterized queries | parameters.py |
| Api Input Validation | Range comparison with bound params | parameters.py _PrefixSearchParam._prefix_clause() - All prefix search operations use parameterized queries | parameters.py |
| Api Input Validation | Keyset pagination with bound params | cursors.py _nested_keyset_predicate() - All cursor-based pagination uses parameterized queries | cursors.py |
| Api Input Validation | Attribute allowlist for sort columns | parameters.py SortParam._resolve() - Prevents arbitrary attribute access via allowlist validation | parameters.py |
| Api Input Validation | getattr(model, attribute) gated by allowlist | parameters.py SortParam._resolve() - Only allowlisted attributes resolved, preventing attribute injection | parameters.py |
| Api Input Validation | .filter_by() with keyword args | Route handlers - Named-parameter filtering prevents SQL injection | — |
| Api Input Validation | Consistent use of SQLAlchemy ORM | All database operations - No raw SQL strings or string concatenation for query building | — |
| Api Input Validation | Hardcoded collation string | _MySQLCollate._compile_mysql_collate_mysql() uses hardcoded utf8mb4_0900_ai_ci, not user-controlled input | — |
| Api Input Validation | Parameterized DELETE operations | All DELETE operations use parameterized WHERE clauses (e.g., delete(Variable).where(Variable.key == variable_key)) | — |
| Api Input Validation | No OS command execution | All audited files - No subprocess/system calls present | — |
| Api Input Validation | Connection test gated by config | connections.py test_connection() - test_connection must be enabled | connections.py |
| Api Input Validation | Transient env var cleanup | connections.py test_connection() finally block - Environment variable removed after test | connections.py |
| Api Input Validation | Consistent Authorization Pattern | Every endpoint uses dependency-injected authorization decorators (requires_access_dag, requires_access_asset, requires_access_connection, requires_access_variable) via FastAPI's Depends() mechanism | — |
| Api Input Validation | Layered Validation Architecture | Four-layer validation: FastAPI/Pydantic type coercion, BaseParam subclasses, business logic validation in route handlers, SQLAlchemy parameterization | parameters.py |
| Api Input Validation | Parameterization Consistency | All database queries use SQLAlchemy ORM operations with zero instances of raw SQL string construction or interpolation | — |
| Api Input Validation | Cursor Pagination Security | Cursor-based pagination uses msgpack+base64url encoding with server-side validation (structure check, element count match, UUID coercion) | — |
| Api Input Validation | Information Disclosure Controls | _UniqueConstraintErrorHandler gates stacktrace/SQL statement exposure behind expose_stacktrace configuration flag with random tracking ID | — |
| Api Input Validation | Payload size limits delegated to Deployment Manager | Reverse proxy configuration handles payload size limits per delegated_infrastructure_controls.md | — |
| Api Input Validation | No server-side file upload endpoints | Variable import uses client-side JSON parsing transmitted as structured API payload (BulkBody[VariableBody]), no file upload handling | — |
| Ui Output Encoding | React JSX auto-escaping | All user-controlled values rendered through JSX `{}` expressions are automatically escaped, preventing HTML injection in component output | All .tsx components |
| Ui Output Encoding | `skipHtml` prevents raw HTML | Explicitly disables raw HTML rendering in markdown, preventing XSS through markdown content | ReactMarkdown.tsx:169 |
| Ui Output Encoding | react-markdown URL sanitization | Built into react-markdown v6+ - Blocks `javascript:`, `data:` protocols | ReactMarkdown.tsx |
| Ui Output Encoding | `redact_password` field validator | Masks passwords in responses | connections.py:46 |
| Ui Output Encoding | `redact_extra` field validator | Masks sensitive extra fields | connections.py:53 |
| Ui Output Encoding | `redact_val` model validator | Masks variable values | variables.py:34 |
| Ui Output Encoding | FastAPI JSON Content-Type | API responses served as `application/json` | FastAPI framework default |
| Ui Output Encoding | ANSI renderer with `linkify={false}` | Prevents auto-link injection in log rendering | renderStructuredLog.tsx:60, renderStructuredLog.tsx:63, renderStructuredLog.tsx:83 |
| Ui Output Encoding | `rel="noopener noreferrer"` on log links | Applied to extracted URLs in logs | renderStructuredLog.tsx:71 |
| Ui Output Encoding | Safe error handling in `redact_extra` | Raises `ValueError` on `JSONDecodeError` ensuring no information leakage through malformed data | connections.py:64 |
| Ui Output Encoding | JSON.stringify for complex log values | Uses `JSON.stringify(val)` for objects before rendering through React, providing double encoding protection | renderStructuredLog.tsx:268 |
| Ui Output Encoding | Consistent encodeURIComponent for dagId, runId, and taskId parameters | All three parameters are properly URL-encoded before substitution into the iframe URL template | airflow-core/src/airflow/ui/src/pages/Iframe.tsx:34, airflow-core/src/airflow/ui/src/pages/Iframe.tsx:37, airflow-core/src/airflow/ui/src/pages/Iframe.tsx:40 |
| Ui Output Encoding | Protocol validation for absolute URLs | Code checks src.startsWith('http://') \|\| src.startsWith('https://') and constructs URL object for validation, preventing protocol misuse | airflow-core/src/airflow/ui/src/pages/Iframe.tsx:47 |
| Ui Output Encoding | URL normalization using new URL().toString() | Normalizes absolute URLs to prevent URL parsing inconsistencies | airflow-core/src/airflow/ui/src/pages/Iframe.tsx:49 |
| Ui Output Encoding | Connection ID regex validation | ConnectionBody.connection_id uses pattern ^[\w.-]+$ (max 200 chars) preventing URL-unsafe characters in identifiers | connections.py:138 |
| Ui Output Encoding | React Router URL encoding | Route parameters handled by react-router are properly decoded/encoded through the routing layer | — |
| Ui Output Encoding | Iframe sandboxing | Iframe uses sandbox attribute with allow-scripts allow-same-origin allow-forms to isolate plugin content | — |
| Ui Output Encoding | JSON.stringify(content, undefined, 2) for safe JSON serialization | Used for display rendering in RenderedJsonField component | RenderedJsonField.tsx:38 |
| Ui Output Encoding | json.dumps(redacted_dict) for Python JSON serialization | Python JSON serialization in connections module | connections.py:58 |
| Ui Output Encoding | json.loads(v) with validation and error handling | JSON parsing with proper error handling | connections.py:56, variables.py:38 |
| Ui Output Encoding | Pydantic model serialization | FastAPI handles JSON response encoding automatically | connections.py, variables.py |
| Ui Output Encoding | Monaco Editor with language='json' | Editor handles content as structured data, not executable code | JsonEditor.tsx:54, RenderedJsonField.tsx:61 |
| Ui Output Encoding | Strict JSON validation in API inputs | ConnectionBody.validate_extra() validates extra field is proper JSON dict, rejecting malformed JSON | connections.py:147 |
| Ui Output Encoding | Safe fallback for JSON decode failures | VariableResponse.redact_val() handles JSONDecodeError gracefully with key-based redaction fallback | variables.py:42 |
| Ui Output Encoding | Read-only mode for JSON display | RenderedJsonField.tsx sets readOnly: true in editor options to prevent user modification | RenderedJsonField.tsx |
| Session Management | SimpleAuthManager login flow is dev-only; production auth managers handle session lifecycle independently | Dropped finding ASVS-724-MED-001 | airflow-core/src/airflow/api_fastapi/auth/managers/simple/services/login.py |
| Tls Configuration | WSS enforcement delegated to Deployment Manager via reverse proxy TLS termination | documented in run-behind-proxy.rst and delegated_infrastructure_controls.md | run-behind-proxy.rst, delegated_infrastructure_controls.md |
| Http Security Headers | CORS configuration (including origin allowlist and credentials policy) is delegated to Deployment Manager via configuration | source: Dropped finding ASVS-342-MED-001 | — |
| Http Security Headers | Execution API correctly omits CORS middleware for server-to-server communication | source: Dropped finding ASVS-342-LOW-001 | — |
| Http Security Headers | JWT Bearer token in Authorization header inherently triggers CORS preflight for all authenticated cross-origin requests | Promoted from dropped finding ASVS-352-LOW-001 | — |
| Http Security Headers | FastAPI framework enforces explicit HTTP method decorators per endpoint, preventing accidental exposure of state-changing logic via GET | Promoted from dropped finding ASVS-353-LOW-001. All visible endpoints are appropriately read-only GET | — |
| Dag Serialization Security | No eval() or exec() usage | All serialization modules | — |
| Dag Serialization Security | Registered type validation for timetables | validates via is_core_timetable_import_path() or find_registered_custom_timetable() | airflow-core/src/airflow/serialization/decoders.py |
| Dag Serialization Security | Registered type validation for partition mappers | validates via is_core_partition_mapper_import_path() or find_registered_custom_partition_mapper() | airflow-core/src/airflow/serialization/decoders.py |
| Dag Serialization Security | Builtins restriction for BASE_EXC_SER | prefixes with builtins. to constrain scope | airflow-core/src/airflow/serialization/serialized_objects.py |
| Dag Serialization Security | Priority weight strategy registration check | _get_registered_priority_weight_strategy() returns None for unregistered | airflow-core/src/airflow/serialization/serialized_objects.py |
| Dag Serialization Security | JSON Schema validation | called in DagSerialization.to_dict() before storage | airflow-core/src/airflow/serialization/serialized_objects.py |
| Dag Serialization Security | Type markers (Encoding.TYPE) | All encode/decode paths use discriminated union to prevent type confusion | — |
| Dag Serialization Security | Callable serialization is one-way | str(get_python_source(var)) produces string only | airflow-core/src/airflow/serialization/serialized_objects.py |
| Dag Serialization Security | JSON-based serialization | Entire serialization framework uses JSON (not pickle or YAML) which inherently avoids deserialization vulnerabilities | — |
| Dag Serialization Security | Serializer version tracking | SERIALIZER_VERSION = 3 with version upgrade paths (conversion_v1_to_v2, conversion_v2_to_v3) ensures structural integrity | airflow-core/src/airflow/serialization/serialized_objects.py |
| Dag Serialization Security | Strict mode for serialization | BaseSerialization.serialize(var, strict=True) raises SerializationError for unexpected types | airflow-core/src/airflow/serialization/serialized_objects.py |
| Dag Serialization Security | JSON-exclusive design for DAG serialization | The architectural decision to use JSON for DAG serialization (rather than XML or YAML) inherently eliminates the entire class of XXE vulnerabilities from this subsystem | decoders.py, encoders.py, serialized_objects.py |
| Dag Serialization Security | Schema loaded from package data without external resolution | The JSON schema is loaded from bundled package data (pkgutil.get_data(__name__, 'schema.json')), not from external URLs or user-provided paths | json_schema.py:load_dag_schema_dict() |
| Dag Serialization Security | No external references in schema loading | load_dag_schema_dict() loads a local file and does not resolve external references, $ref URIs, or remote schemas | json_schema.py:load_dag_schema_dict() |
| Password Management | SimpleAuthManager is dev-only; credential lifecycle management delegated to production auth managers | Profile: Out-of-Scope ASVS Categories | — |
| Password Management | Rate limiting explicitly delegated to Deployment Manager (reverse proxy/WAF); SimpleAuthManager is dev-only | Dropped finding ASVS-631-LOW-001 | — |
| Password Management | SimpleAuthManager anonymous admin is configuration-gated dev-only convenience; production must use external auth managers | Dropped finding ASVS-632-LOW-001 | — |
| Password Management | SimpleAuthManager is dev-only; initial password lifecycle delegated to production auth managers | Profile: Out-of-Scope ASVS Categories | — |
| Rate Limiting | Rate limiting, anti-automation delegated to Deployment Manager per documented infrastructure controls | Profile: Out-of-Scope ASVS Categories | — |
| Client Side Storage | No authenticated data stored in localStorage - only UI preferences | Audit analysis confirmed no tokens, credentials, or authenticated session data in browser-accessible storage | airflow-core/src/airflow/ui/src/layouts/Nav/LogoutModal.tsx |
| Client Side Storage | Clear-Site-Data and security response headers are deployment-level concerns | Configuration responsibility assigned to Deployment Manager per architectural decision | — |
| Dependency Management | Docker/Helm-based deployment architecture inherently excludes .git metadata from production; production hardening delegated to Deployment Manager | Dropped finding ASVS-1341-LOW-001 | — |
| Dependency Management | No fixed remediation SLA commitments is a documented design decision; remediation timing depends on issue complexity, impact, severity, and other factors | Dropped finding ASVS-1511-MED-001 | — |
| Dependency Management | Dependency remediation timing is intentionally not fixed to SLAs; Docker image dependency management delegated to user | Dropped finding ASVS-1521-MED-001 | — |
| Business Logic Flow | State enumeration validation exists | set_state() validates target state is member of State.dag_states | airflow-core/src/airflow/models/dagrun.py |
| File Upload Security | Files uploaded or generated by untrusted input stored in public folders are not executed as server-side code when accessed directly | ASVS 5.3.1 passed validation | — |
| File Upload Security | No filesystem operations with user-controlled data; all variable data stored exclusively in database via SQLAlchemy ORM | Profile: Out-of-Scope ASVS 5.3.2 confirmed by architecture analysis | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Partial** | See FINDING-004 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-005 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Pass** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** | See FINDING-008 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-002, FINDING-003 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Partial** | See FINDING-010 |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **N/A** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Partial** | See FINDING-007 |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Pass** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Pass** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **N/A** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **N/A** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **N/A** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Pass** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Fail** | See FINDING-001 |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Partial** | See FINDING-006 |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Pass** |  |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** |  |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** |  |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** |  |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** |  |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Pass** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Partial** | See FINDING-009 |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |

**Summary Statistics:**
- **Pass**: 32 requirements (45.7%)
- **Partial**: 7 requirements (10.0%)
- **N/A**: 30 requirements (42.9%)
- **Fail**: 1 requirements (1.4%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | High | 7.4.2 | — | airflow-core/src/airflow/models/revoked_token.py |
| FINDING-002 | Low | 2.2.1 | FINDING-003 | airflow-core/src/airflow/api_fastapi/core_api/routes/ui/dags.py |
| FINDING-003 | Low | 2.2.1 | FINDING-002 | airflow-core/src/airflow/api_fastapi/core_api/routes/ui/grid.py |
| FINDING-004 | Low | 1.2.1 | — | airflow-core/src/airflow/ui/src/components/ReactMarkdown.tsx |
| FINDING-005 | Low | 1.2.2 | — | airflow-core/src/airflow/ui/src/pages/Iframe.tsx |
| FINDING-006 | Low | 9.1.2 | — | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| FINDING-007 | Low | 3.3.1 | — | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| FINDING-008 | Low | 1.3.2 | — | airflow-core/src/airflow/serialization/serialized_objects.py |
| FINDING-009 | Low | 14.3.1 | — | airflow-core/src/airflow/ui/src/layouts/Nav/LogoutModal.tsx |
| FINDING-010 | Low | 2.3.1 | — | airflow-core/src/airflow/models/dagrun.py |

**Total Unique Findings**: 10 (0 Critical, 1 High, 0 Medium, 9 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 10 |

**Total consolidated findings: 10**

*End of Consolidated Security Audit Report*