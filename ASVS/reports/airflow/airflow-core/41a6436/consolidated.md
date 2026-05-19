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
| **Total Findings** | 8 |

## Executive Summary

This consolidated report aggregates results from 70 source security audit reports covering 14 security domains within the Apache Airflow core codebase. The audit was scoped to ASVS Level 1 requirements with no severity threshold applied, meaning all findings regardless of severity are included.

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 7 |
| Informational | 1 |
| **Total** | **8** |

The absence of Critical, High, and Medium findings indicates a mature security posture across the audited codebase. All identified issues fall within the Low or Informational severity bands, representing defense-in-depth gaps or hardening opportunities rather than immediately exploitable vulnerabilities.

### Level Coverage

All 8 findings map to ASVS L1 requirements. The audit scope was limited to L1; L2 and L3 requirements were not assessed.

### Top 5 Risks

1. **Token revocation bypass (FINDING-001)** — Tokens issued without a `jti` claim cannot be individually revoked, weakening the ability to respond to credential compromise scenarios. (ASVS 7.4.1)

2. **No session termination on account disable/delete (FINDING-002)** — Active sessions persist after a user account is disabled or deleted, creating a window where deprovisioned users retain access. (ASVS 7.4.2)

3. **Authorization bypass via bulk overwrite (FINDING-003)** — The `action_on_existence=overwrite` parameter in bulk CREATE operations skips team-level authorization checks on existing resources, potentially allowing unauthorized modification. (ASVS 8.2.2)

4. **Unbounded pagination in batch endpoints (FINDING-004)** — `TaskInstancesBatchBody.page_limit` lacks a maximum enforcement, enabling resource exhaustion through excessively large page requests. (ASVS 2.1.1, 2.2.1)

5. **Missing anti-forgery token for cookie-authenticated endpoints (FINDING-006)** — No explicit CSRF protection mechanism is visible for endpoints relying on cookie-based authentication, leaving state-changing operations potentially vulnerable to cross-site request forgery. (ASVS 3.5.1)

### Positive Controls

The audit identified substantial security controls already in place across the codebase:

- **Parameterized database queries throughout** — All database interactions use SQLAlchemy ORM with parameterized queries, with no raw SQL or string concatenation observed. Filter classes, LIKE operations, and sort parameters all flow through safe ORM abstractions.

- **Comprehensive XSS prevention** — React JSX auto-escaping is consistently applied with no instances of `dangerouslySetInnerHTML`, `eval()`, `innerHTML`, or dynamic code generation. Monaco Editor is used for code display (avoiding WYSIWYG sanitization issues), and ANSI log rendering properly escapes content.

- **Defense-in-depth input validation** — Multiple layers including Pydantic model validation, allowlist-based sort column resolution, enum-validated filter values, and a centralized filter application function (`apply_filters_to_select()`).

- **Secret redaction at serialization boundaries** — Pydantic validators in connection and variable models redact sensitive fields before API responses are emitted, preventing accidental secret exposure independent of access control enforcement.

- **Infrastructure security delegation** — TLS termination, HTTPS enforcement, certificate provisioning, cookie security attributes, and CORS configuration are explicitly delegated to the deployment manager's reverse proxy layer, following a well-documented responsibility model.

- **Absence of dangerous code patterns** — No `eval()`, `exec()`, `new Function()`, template expression injection, subprocess invocation, or dynamic code generation patterns were identified in the audited code paths.

---

## 3. Findings

### 3.4 Low

#### FINDING-001: 🔵 Tokens without `jti` claim bypass revocation check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 7.4.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Reports** | 7.4.1.md |
| **Related** | - |

**Description:**

Tokens from external issuers (via trusted_jwks_url) that omit the optional `jti` claim silently skip the revocation check in get_user_from_token(). The `jti` claim is not in required_claims, so such tokens pass validation but cannot be revoked through Airflow's token revocation mechanism.

**Remediation:**

Add `jti` to required_claims or log a warning when tokens without `jti` are accepted. Alternatively, reject tokens without `jti` to ensure all tokens in the system can be revoked.

---

#### FINDING-002: 🔵 No mechanism to terminate all active sessions when a user account is disabled or deleted

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 7.4.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/models/revoked_token.py |
| **Source Reports** | 7.4.2.md |
| **Related** | - |

**Description:**

DOWNGRADED from Medium: The base_auth_manager.py lacks per-user bulk session revocation. However, production deployments delegate authentication to external auth managers (FAB, Keycloak) which handle user lifecycle and session termination; the proof-of-concept scenario relies on SimpleAuthManager which is dev-only.

**Remediation:**

Add an abstract `revoke_all_user_sessions(user_id)` method to BaseAuthManager and a per-user not-before timestamp mechanism, enabling production auth managers to trigger bulk session termination on account state changes.

---

#### FINDING-003: 🔵 Bulk CREATE with `action_on_existence=overwrite` Bypasses Existing Resource Team Authorization Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS Section(s)** | 8.2.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| **Source Reports** | 8.2.2.md |
| **Related** | - |

**Description:**

DOWNGRADED from Medium: Multi-team feature is documented as experimental/work-in-progress; however, the bulk CREATE+overwrite path skips team lookup for CREATE entities, passing team_name=None to the authorization check, potentially allowing cross-team resource overwrites in multi-team mode.

**Remediation:**

Include CREATE entities in the team mapping lookup for all three bulk handlers (requires_access_connection_bulk, requires_access_pool_bulk, requires_access_variable_bulk) so that when action_on_existence=overwrite is used, the authorization check includes the existing resource's team context.

---

#### FINDING-004: 🔵 TaskInstancesBatchBody.page_limit Missing Maximum Enforcement and Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.1.1, 2.2.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/datamodels/task_instances.py |
| **Source Reports** | 2.1.1.md, 2.2.1.md |
| **Related** | - |

**Description:**

The page_limit field in TaskInstancesBatchBody has no upper bound enforcement or documentation, unlike LimitFilter which clamps to maximum_page_limit. The field declares only a non-negative constraint (ge=0) and a default of 100, but does not document or enforce the same maximum_page_limit that LimitFilter enforces. An authenticated user could request an extremely large number of task instances in a single response, potentially causing memory exhaustion or database performance degradation. Additionally, the order_by field lacks documentation of valid values, creating inconsistent documentation between query-parameter and request-body pagination interfaces.

**Remediation:**

Apply Field(default=100, ge=0, le=conf.getint('api', 'maximum_page_limit')) constraint and add description to TaskInstancesBatchBody.page_limit documenting the upper bound. Document valid order_by values in the field description to match LimitFilter protection and maintain consistency with query-parameter pagination.

---

#### FINDING-005: 🔵 URL Protocol Validation Depends on External Regex Pattern

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS Section(s)** | 1.2.2 |
| **Files** | airflow-core/src/airflow/ui/src/components/renderStructuredLog.tsx:52 |
| **Source Reports** | 1.2.2.md |
| **Related** | - |

**Description:**

The function creates clickable links from URLs found in log content using urlRegex (imported from src/constants/urlRegex). There is no explicit protocol allowlist validation (e.g., only https:// or http://) applied after regex matching and before setting the href attribute. The safety of this pattern depends entirely on the urlRegex implementation (not provided in the audit scope). If urlRegex could match javascript: or data: URLs, an Operations User clicking a link in task logs could trigger script execution. Given that DAG Authors are trusted, this is a cross-trust-boundary concern only in multi-team deployments where Operations Users may view logs from untrusted DAG Authors.

**Remediation:**

Add explicit protocol allowlist validation before creating clickable links. Example implementation:

```javascript
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

---

#### FINDING-006: 🔵 No Explicit Anti-Forgery Token Mechanism Visible for Cookie-Authenticated Endpoints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Section(s)** | 3.5.1 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.5.1.md |
| **Related** | FINDING-007 |

**Description:**

No visible explicit anti-forgery token mechanism for cookie-authenticated core API endpoints. The application relies on CORS preflight and JSON content-type requirements for CSRF protection. Auth manager middlewares may provide additional protection but implementation is not visible. DOWNGRADED from Medium: the report acknowledges the application relies on CORS preflight (deferring to 3.5.2), and FastAPI's JSON body requirement provides implicit preflight triggering for most endpoints.

**Remediation:**

Document the CSRF protection strategy explicitly. Consider adding a custom header requirement (e.g., X-Requested-With) as defense-in-depth for endpoints that accept no body or optional bodies.

---

#### FINDING-007: 🔵 No Content-Type Enforcement Visible at Application Level to Guarantee CORS Preflight

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-352 |
| **ASVS Section(s)** | 3.5.2 |
| **Files** | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| **Source Reports** | 3.5.2.md |
| **Related** | FINDING-006 |

**Description:**

No explicit middleware rejects CORS-safelisted Content-Types for state-changing requests. While FastAPI's Pydantic parsing rejects incorrect content types at deserialization, endpoints accepting no body (e.g., DELETE with path params) could potentially process cross-origin simple requests without triggering preflight.

**Remediation:**

Add a middleware that validates Content-Type for state-changing requests, rejecting CORS-safelisted types (application/x-www-form-urlencoded, multipart/form-data, text/plain) for sensitive endpoints.

### 3.5 Informational

#### FINDING-008: No Explicit Blocklist Prevents "None" Algorithm Configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | ⚪ Informational |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 9.1.2 |
| **File(s)** | airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| **Source Report(s)** | 9.1.2.md |
| **Related** | None |

**Description:**

DOWNGRADED from Low to Informational-Low: Configuration is delegated to Deployment Manager per profile; safe defaults (GUESS→HS512) are in place. Finding retained as defense-in-depth recommendation only.

**Remediation:**

Add a validation check in both JWTValidator.__attrs_post_init__() and JWTGenerator.__attrs_post_init__() that rejects configurations containing "none" (case-insensitive).

---

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Authentication And Session Management | SimpleAuthManager is a development-only component; production deployments must use external auth managers with full session lifecycle management | source: Dropped finding ASVS-724-MED-001 | — |
| Api Input Validation | SQLAlchemy ORM parameterized queries | All filter classes consistently use SQLAlchemy ORM for database interactions, which inherently provides parameterized queries | parameters.py |
| Api Input Validation | Allowlist validation for sort columns | SortParam._resolve() validates user-provided sort columns against self.allowed_attrs before using getattr | parameters.py:350 |
| Api Input Validation | MAX_SORT_PARAMS limit | Maximum of 10 sort parameters enforced to prevent resource exhaustion | parameters.py:322 |
| Api Input Validation | Centralized filter application | apply_filters_to_select() provides single point through which all filters are applied | common/db/common.py:48-56 |
| Api Input Validation | ORM comparison operators in FilterParam | FilterParam.to_orm() uses ORM comparison operators instead of raw SQL | parameters.py:436-492 |
| Api Input Validation | Parameterized LIKE operations | _SearchParam.to_orm() uses .ilike() with parameterized patterns where % characters become part of the bound parameter value | parameters.py:228-257 |
| Api Input Validation | Parameterized prefix search | _PrefixSearchParam._prefix_clause() uses ORM range operators for prefix matching | parameters.py:260-283 |
| Api Input Validation | Hardcoded collation strings | _MySQLCollate uses hardcoded collation string 'utf8mb4_0900_ai_ci' with no user input | parameters.py |
| Api Input Validation | Enum-validated filter values | Transform functions like _transform_dag_run_states and _transform_ti_states validate user strings against known Enum values before query execution | parameters.py |
| Api Input Validation | Consistent ORM Usage | All database interactions use SQLAlchemy ORM exclusively with no raw SQL or string concatenation | — |
| Api Input Validation | Separation of Concerns | Code handles only request validation and database query construction with no OS command execution, subprocess executions, shell commands, or process spawning | — |
| Api Input Validation | Defense-in-Depth for Sort Injection | Sort column validation uses allowlist check, getattr on known model class, and MAX_SORT_PARAMS limit | — |
| Api Input Validation | Query-parameter pagination maximum enforcement | LimitFilter implements maximum_page_limit enforcement for query-parameter-based pagination | — |
| Api Input Validation | Server-side validation enforcement | All input validation is performed at the FastAPI service layer using Pydantic models and custom validators | — |
| Output Encoding And Xss Prevention | React JSX auto-escaping | All user-facing content is rendered through JSX expressions ({value}), which automatically encodes HTML entities. No use of dangerouslySetInnerHTML is present in the provided code. | All .tsx files |
| Output Encoding And Xss Prevention | Pydantic JSON serialization | All API response models inherit from BaseModel and use Pydantic's type-safe serialization, ensuring values are properly encoded for JSON context. | connections.py, variables.py |
| Output Encoding And Xss Prevention | Monaco Editor content sandboxing | Content treated as text/code tokens, avoiding entire classes of XSS vulnerabilities for code display, JSON editing, and diff viewing. | JsonEditor.tsx, Code.tsx, CodeDiffViewer.tsx |
| Output Encoding And Xss Prevention | AnsiRenderer escaping | ANSI rendering without HTML injection. Log content processed by AnsiRenderer (which handles escaping) or rendered as JSX children (auto-escaped). | renderStructuredLog.tsx:55 |
| Output Encoding And Xss Prevention | JSON.stringify for Complex Objects | Complex log field values are serialized with JSON.stringify before being rendered in JSX, preventing structure injection. | renderStructuredLog.tsx:244 |
| Output Encoding And Xss Prevention | API Response Content-Type | API returns application/json for all responses, preventing browsers from interpreting responses as HTML. | — |
| Output Encoding And Xss Prevention | Consistent external link handling | All external links consistently apply rel="noopener noreferrer" and target="_blank", preventing tab-nabbing attacks. | renderStructuredLog.tsx, Code.tsx |
| Output Encoding And Xss Prevention | urlRegex pattern matching | renderStructuredLog.tsx:55 | renderStructuredLog.tsx:55 |
| Output Encoding And Xss Prevention | RouterLink for internal navigation using React Router (no unsafe protocol) | renderStructuredLog.tsx:277 | renderStructuredLog.tsx:277 |
| Output Encoding And Xss Prevention | URL.createObjectURL creates blob: URL programmatically | Logs.tsx:123 | Logs.tsx:123 |
| Output Encoding And Xss Prevention | Secret redaction at serialization layer using Pydantic validators | connections.py and variables.py | connections.py, variables.py |
| Output Encoding And Xss Prevention | Typed interfaces using OpenAPI-generated types for data flow | Architecture observation - separation of data retrieval and rendering | — |
| Output Encoding And Xss Prevention | Pydantic JSON serialization with redaction | JSON data is serialized using Python's json.dumps, which properly escapes special characters, preventing JSON injection in API responses | connections.py:59-60 |
| Output Encoding And Xss Prevention | React Data Flow - typed props through component system | Configuration and data are passed as typed props through React's component system. No pattern of embedding data in <script> tags or generating JavaScript strings dynamically | All .tsx files |
| Output Encoding And Xss Prevention | json.dumps with redact for safe JSON re-serialization | Safe JSON re-serialization of redacted dictionary data | connections.py:60 |
| Output Encoding And Xss Prevention | Architectural Decision: Monaco Editor instead of WYSIWYG | The application uses Monaco Editor (a code editor) rather than WYSIWYG editors, eliminating the need for HTML sanitization of rich text input | JsonEditor.tsx, Code.tsx, CodeDiffViewer.tsx |
| Output Encoding And Xss Prevention | Defense in Depth for Secret Exposure | Secret redaction implemented at the serialization layer (Pydantic validators) rather than relying solely on access controls | connections.py, variables.py |
| Output Encoding And Xss Prevention | Separation of Rendering and Data | Clean separation between data retrieval (API calls) and rendering (React components). Data flows through typed interfaces (OpenAPI-generated types) | — |
| Output Encoding And Xss Prevention | No eval() usage | All provided files | — |
| Output Encoding And Xss Prevention | No new Function() | All provided files | — |
| Output Encoding And Xss Prevention | No setTimeout/setInterval with strings | All provided files | — |
| Output Encoding And Xss Prevention | No innerHTML assignment | All provided files | — |
| Output Encoding And Xss Prevention | No dangerouslySetInnerHTML | All provided files | — |
| Output Encoding And Xss Prevention | No Python eval()/exec() | connections.py, variables.py | connections.py, variables.py |
| Output Encoding And Xss Prevention | No SpEL or template expressions | All provided files | — |
| Output Encoding And Xss Prevention | JSON Parsing via Standard Library | JSON deserialization uses json.loads (safe parser) rather than eval() or similar | connections.py:56, connections.py:151 |
| Output Encoding And Xss Prevention | Monaco Editor for Code Display (not execution) | Monaco Editor instances configured as display/edit tools only with readOnly: true | Code.tsx, CodeDiffViewer.tsx, JsonEditor.tsx |
| Output Encoding And Xss Prevention | Pydantic Validation (not dynamic execution) | Input validation uses Pydantic field validators and model validators - declarative validation rather than dynamic code execution | connections.py, variables.py |
| Output Encoding And Xss Prevention | React Component Architecture | UI passes data through typed props and state, avoiding patterns that would require dynamic code generation or evaluation | — |
| Http Security Headers And Cors | TLS termination and protocol version selection explicitly delegated to Deployment Manager via reverse proxy | Profile: delegated_infrastructure_controls.md | — |
| Http Security Headers And Cors | HTTPS enforcement for external-facing traffic delegated to Deployment Manager's reverse proxy | Profile: delegated_infrastructure_controls.md | — |
| Http Security Headers And Cors | Publicly trusted TLS certificate provisioning delegated to Deployment Manager | Profile: delegated_infrastructure_controls.md | — |
| Http Security Headers And Cors | Cookie security attributes (Secure, __Host-/__Secure- prefix) delegated to reverse proxy and auth manager infrastructure | source: Dropped finding ASVS-331-MED-001 | — |
| Http Security Headers And Cors | CORS configuration (including origin allowlist) delegated to Deployment Manager | Dropped finding ASVS-342-LOW-001 | — |
| Http Security Headers And Cors | WSS enforcement delegated to reverse proxy/Deployment Manager | Architecture observation | — |
| Task Execution Isolation | Dependency management in Docker images delegated to user; project explicitly states it will ignore dependency scan results | ASVS 15.1.1 - Documentation acknowledges dependency management is user responsibility | — |
| Task Execution Isolation | Dependency management and vulnerability scanning delegated to user; uv.lock provides auditable dependency snapshot | ASVS 15.2.1 - uv.lock file enables dependency tracking and audit | — |
| Oauth And External Auth | OAuth AS functionality (redirect URI validation) is delegated to external auth managers via pluggable architecture | Report confirmation - OAuth authorization server responsibilities are handled externally | — |
| Oauth And External Auth | OAuth authorization code lifecycle management is delegated to external auth managers | Report confirmation - Single-use authorization code enforcement handled externally | — |
| Oauth And External Auth | OAuth authorization code lifetime enforcement is delegated to external auth managers | Report confirmation - Authorization code expiration handled externally | — |
| Oauth And External Auth | OAuth grant type restrictions are delegated to external auth managers | Report confirmation - Grant type allowlist enforcement handled externally | — |
| Oauth And External Auth | OAuth refresh token replay protection is delegated to external auth managers | Report confirmation - Refresh token security mechanisms handled externally | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-005 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-004 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-004 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Pass** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Partial** | See FINDING-006 |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Partial** | See FINDING-007 |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **Pass** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **N/A** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Partial** | See FINDING-001 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Partial** | See FINDING-002 |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Partial** | See FINDING-003 |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Partial** | See FINDING-008 |
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
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |

**Summary Statistics:**
- **Pass**: 35 requirements (50.0%)
- **Partial**: 9 requirements (12.9%)
- **N/A**: 26 requirements (37.1%)
- **Fail**: 0 requirements (0.0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Low | 7.4.1 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/api_fastapi/auth/tokens.py |
| FINDING-002 | Low | 7.4.2 | — | airflow-core/src/airflow/api_fastapi/auth/managers/base_auth_manager.py, airflow-core/src/airflow/models/revoked_token.py |
| FINDING-003 | Low | 8.2.2 | — | airflow-core/src/airflow/api_fastapi/core_api/security.py |
| FINDING-004 | Low | 2.1.1, 2.2.1 | — | airflow-core/src/airflow/api_fastapi/core_api/datamodels/task_instances.py |
| FINDING-005 | Low | 1.2.2 | — | airflow-core/src/airflow/ui/src/components/renderStructuredLog.tsx |
| FINDING-006 | Low | 3.5.1 | FINDING-007 | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| FINDING-007 | Low | 3.5.2 | FINDING-006 | airflow-core/src/airflow/api_fastapi/core_api/app.py |
| FINDING-008 | Informational | 9.1.2 | — | airflow-core/src/airflow/api_fastapi/auth/tokens.py |

**Total Unique Findings**: 8 (0 Critical, 0 High, 0 Medium, 7 Low, 1 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 8 |

**Total consolidated findings: 8**

*End of Consolidated Security Audit Report*