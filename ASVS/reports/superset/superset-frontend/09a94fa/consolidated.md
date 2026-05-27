# Security Audit Consolidated Report — apache/superset/superset-frontend

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset-frontend |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | `09a94fa` |
| Date | May 27, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 11 |

## Executive Summary

### Severity Distribution


| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High     | 2 | 20.0% |
| Medium   | 4 | 40.0% |
| Low      | 4 | 40.0% |
| Info     | 0 | 0.0% |

### ASVS Level Coverage

This audit was scoped to **ASVS Level 1** controls across 20 security domains within the `superset-frontend` directory tree. All 11 actionable findings map to L1 verification requirements, confirming that the identified issues represent baseline security expectations that are not yet fully met in the frontend codebase.

### Top 4 Risks


1. **SQL Injection via Numeric BETWEEN Interpolation (High)** — Numeric range values used in BETWEEN clauses are string-interpolated without type enforcement, allowing injection of arbitrary SQL fragments through manipulated numeric filter controls.

2. **Arbitrary Code Execution in DeckGL sandboxedEval (High)** — User-supplied JavaScript expressions are executed via dynamic code evaluation without input sanitization or AST validation, enabling arbitrary code execution within the browser context of any user viewing a crafted DeckGL visualization.

3. **Stored XSS in NVD3 Tooltip Rendering (Medium)** — Multiple tooltip generation functions (`generateMultiLineTooltipContent`, `generateBubbleTooltipContent`, `tipFactory`) render data-driven values into DOM without sanitization, enabling stored cross-site scripting when malicious payloads are present in dataset values.

4. **javascript: Protocol XSS in SafeMarkdown (Medium)** — When `transformLinkUri` is explicitly disabled, the SafeMarkdown component permits `javascript:` protocol URLs in rendered links, enabling XSS through crafted Markdown content in dashboards or chart descriptions.

### Positive Controls Observed

The audit identified substantial positive security architecture across the evaluated domains:

- **Defense-in-depth for XSS**: DOMPurify is actively used in several tooltip functions within the same file where gaps were found, and SafeMarkdown defaults to `htmlSanitization=true` with rehype-sanitize active unless explicitly overridden. This indicates awareness and partial implementation of output encoding controls.

- **Backend-enforced security boundary**: The frontend consistently delegates security-critical operations (cryptography, command execution, authentication, authorization, session management, file upload validation) to the backend API layer. Server-side query parameterization, Flask-AppBuilder authentication controls, and independent API-level authorization re-validation provide a strong trust boundary.

- **Sensitive data handling**: Authentication tokens and credentials are transmitted via HTTP body/headers rather than URL parameters. Client-side storage is controlled through whitelist-based persistence keys, query result TTLs with size limits, and the `SqllabBackendPersistence` feature flag to minimize localStorage reliance.

- **Token validation**: Self-contained tokens are validated using digital signatures with allowlisted algorithms (excluding `None`), temporal claim verification (nbf/exp), and backend `allowed_domains` enforcement preventing privilege escalation.

- **Deployment-aware architecture**: TLS enforcement, rate limiting, anti-automation, and source control metadata protection are explicitly delegated to deployment infrastructure, with clean separation between development and production configurations.

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

### 3.2 High

#### FINDING-002: Numeric BETWEEN Values Interpolated Without Type Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-89 |
| **ASVS Sections** | 1.2.4 |
| **Files** | superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts |
| **Source Reports** | 1.2.4.md |
| **Related** | |

**Description:**

Numeric filter values for the IN_RANGE operator (which generates SQL BETWEEN clauses) are interpolated directly into SQL without type coercion or validation. The validateFilterValue function accepts strings, and there is no enforcement that BETWEEN values are actually numeric before interpolation. Exploitable via filter state manipulation on metric columns.

**Remediation:**

Enforce numeric types via Number() coercion with Number.isNaN() validation before interpolation. Return empty string for non-numeric values.

---

#### FINDING-003: No Input Sanitization or AST Validation Before Dynamic Code Execution in DeckGL sandboxedEval

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-94 |
| **ASVS Sections** | 1.3.2 |
| **Files** | superset-frontend/plugins/preset-chart-deckgl/src/layers/Geojson/Geojson.tsx, superset-frontend/plugins/preset-chart-deckgl/src/utils/sandbox.ts |
| **Source Reports** | 1.3.2.md |
| **Related** | None |

**Description:**

User-provided JavaScript strings from chart form data are passed directly to sandboxedEval() without any AST validation, pattern blocking, or input sanitization. The sandbox implementation uses a restricted execution context but does not validate input before execution, allowing constructor chain escape attacks. A chart creator with edit permissions can set js_data_mutator to escape the sandbox via constructor chains (e.g., console.constructor.constructor('return this')()) achieving full browser API access. When any user views the dashboard containing this chart, the malicious code executes with full browser privileges.

**Remediation:**

Add AST-based input validation to sandboxedEval modeled after safeEChartOptionsParser.ts, blocking constructor, __proto__, and prototype member access. Additionally freeze GLOBAL_CONTEXT objects to prevent constructor chain access.

### 3.3 Medium

#### FINDING-004: Stored XSS in generateMultiLineTooltipContent via unsanitized series.key

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS sections** | 1.2.1, 3.2.2 |
| **Files** | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| **Source Reports** | 1.2.1.md, 3.2.2.md |
| **Related** | FINDING-005, FINDING-006, FINDING-007 |

**Description:**

User-controlled data (groupby column values) flows through series.key → getFormattedKey(key, false) (sanitization explicitly skipped) → string interpolation into HTML → rendered via D3's .html() (innerHTML). DOMPurify.sanitize exists in the same file and is used by generateCompareTooltipContent and generateTimePivotTooltip, but NOT called in this function. Attacker uploads data with XSS payload in column values, creates chart on shared dashboard, and XSS triggers when other users hover over tooltips. This violates both output encoding requirements (1.2.1) and safe text rendering requirements (3.2.2).

**Remediation:**

Apply dompurify.sanitize() to tooltip output and change getFormattedKey call to use shouldDompurify=true, matching the pattern already used by other tooltip functions in the same file. Alternatively, HTML-encode all data-derived values before interpolation.

---

#### FINDING-005: Stored XSS in generateBubbleTooltipContent via unsanitized point entity/group

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS sections** | 1.2.1, 3.2.2 |
| **Files** | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| **Source Reports** | 1.2.1.md, 3.2.2.md |
| **Related** | FINDING-004, FINDING-006, FINDING-007 |

**Description:**

Query result data flows through point[entity] / point.group → string interpolation into HTML → rendered via D3 .html() (innerHTML). DOMPurify is imported and used elsewhere in this file but not called here. Attacker creates dataset with XSS payload in entity column, creates bubble chart, and XSS triggers on tooltip hover by other users on shared dashboards. This violates both output encoding requirements (1.2.1) and safe text rendering requirements (3.2.2).

**Remediation:**

Apply dompurify.sanitize() to all user-derived values before interpolation and to the final HTML string before return. Alternatively, HTML-encode all data-derived values before interpolation to ensure text-safe rendering.

---

#### FINDING-006: Stored XSS in tipFactory via unsanitized annotation data values

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS sections** | 1.2.1, 3.2.2 |
| **Files** | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| **Source Reports** | 1.2.1.md, 3.2.2.md |
| **Related** | FINDING-004, FINDING-005, FINDING-007 |

**Description:**

Annotation data values (d[layer.titleColumn], d[column]) flow through string interpolation → d3-tip .html() callback → innerHTML on tooltip DOM element. DOMPurify exists in the same module but not applied here. Attacker configures annotation layer pointing to dataset with XSS payload in title column, affecting users who hover over annotations on shared charts. This violates both output encoding requirements (1.2.1) and safe text rendering requirements (3.2.2).

**Remediation:**

Apply dompurify.sanitize() to the HTML string returned by the .html() callback. Alternatively, HTML-encode all data-derived values before interpolation to ensure text-safe rendering.

---

#### FINDING-007: javascript: protocol XSS in SafeMarkdown when transformLinkUri is disabled

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS sections** | 1.2.2 |
| **Files** | superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx |
| **Source Reports** | 1.2.2.md |
| **Related** | FINDING-004, FINDING-005, FINDING-006 |

**Description:**

SafeMarkdown sets transformLinkUri={null} which disables URL protocol sanitization. When the EscapeMarkdownHtml feature flag is enabled (removing rehype-sanitize from the pipeline), markdown links like [text](javascript:...) render as clickable XSS payloads. Attacker with markdown authoring access (dashboard descriptions, text widgets) can inject javascript: protocol links affecting other users who click them.

**Remediation:**

Replace transformLinkUri={null} with a protocol-safe sanitizer that blocks javascript:, vbscript:, and data: protocols regardless of which rehype plugins are active.

### 3.4 Low

#### FINDING-008: Inconsistent Field Filtering — useDashboardCharts Returns Full Chart Objects Without Column Specification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-213 |
| ASVS Section(s) | 15.3.1 |
| File(s) | superset-frontend/src/hooks/apiResources/dashboards.ts |
| Source Report(s) | 15.3.1.md |
| Related | FINDING-009, FINDING-010, FINDING-011 |

**Description:**

DOWNGRADED from Medium: Per profile's documented design decision, low-impact boundary variations in existing access controls are classified as hardening improvements rather than vulnerabilities. User is already authorized to view dashboard charts; no trust boundary crossed. Original: useDashboardCharts requests full chart list without column specification unlike useDashboard which explicitly specifies DASHBOARD_GET_COLUMNS.

**Remediation:**

Add explicit column specifications to useDashboardCharts to request only fields needed for rendering.

---

#### FINDING-009: useDatasetDrillInfo Returns Full Dataset Object Without Field Specification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-213 |
| ASVS Section(s) | 15.3.1 |
| File(s) | superset-frontend/src/hooks/apiResources/datasets.ts |
| Source Report(s) | 15.3.1.md |
| Related | FINDING-008, FINDING-010, FINDING-011 |

**Description:**

DOWNGRADED from Medium: Per profile's documented design decision, low-impact boundary variations in existing access controls are classified as hardening improvements. User is already authorized to access dataset drill info; no trust boundary crossed. Original: The hook only needs columns and metrics to build a verbose_map but the full dataset response is stored and cached.

**Remediation:**

Add explicit column specifications to useDatasetDrillInfo to request only fields needed for drill-by functionality.

---

#### FINDING-010: useEmbeddedDashboard Returns Full Embedded Configuration Without Column Specification

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-213 |
| ASVS Section(s) | 15.3.1 |
| File(s) | superset-frontend/src/hooks/apiResources/dashboards.ts |
| Source Report(s) | 15.3.1.md |
| Related | FINDING-008, FINDING-009, FINDING-011 |

**Description:**

useEmbeddedDashboard does not specify column filtering. Embedded dashboard contexts are used with guest tokens. The embedded endpoint may return internal configuration fields not needed by the embedded rendering context.

**Remediation:**

Add explicit column specifications to useEmbeddedDashboard to limit fields returned in embedded contexts.

---

#### FINDING-011: queryApi Generic Base Query Has No Default Field-Limiting Mechanism

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-213 |
| ASVS Section(s) | 15.3.1 |
| File(s) | superset-frontend/src/hooks/apiResources/queryApi.ts |
| Source Report(s) | 15.3.1.md |
| Related | FINDING-008, FINDING-009, FINDING-010 |

**Description:**

The generic supersetClientQuery base query function passes through the entire API response if no transformResponse is provided. There is no enforcement mechanism or default behavior that strips unnecessary fields from responses.

**Remediation:**

Consider adding a utility or convention that makes field specification explicit for all endpoint definitions.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Xss Prevention | DOMPurify library imported and used in some tooltip functions | DOMPurify.sanitize is used by generateCompareTooltipContent and generateTimePivotTooltip functions in the same file | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| Xss Prevention | SafeMarkdown defaults to htmlSanitization=true, ensuring rehype-sanitize is active unless explicitly overridden by developer code | Dropped finding ASVS-131-LOW-001 | — |
| Command Injection Prevention | Frontend is purely a data collection layer; all OS-sensitive operations occur on the backend with server-side validation via useDatabaseValidation() hook. | Promoted from dropped findings ASVS-125-MED-001, ASVS-125-MED-002, ASVS-125-MED-003 | — |
| Cryptography | Frontend delegates all cryptographic operations to the backend; no client-side cipher usage | Audit observation - ASVS 11.3.1 | — |
| Cryptography | Frontend delegates all cryptographic operations to the backend; no deprecated or weak ciphers referenced | Audit observation - ASVS 11.3.2 | — |
| Cryptography | Frontend does not use any hash functions; password hashing and HMAC delegated to backend | Audit observation - ASVS 11.4.1 | — |
| Tls Configuration | TLS version enforcement delegated to backend/deployment infrastructure; frontend provides configuration UI only | Application does not enforce TLS versions at code level; responsibility delegated to deployment layer | — |
| Tls Configuration | WebSocket URL configuration is an admin-only server setting; TLS enforcement delegated to deployment | WebSocket TLS configuration controlled via administrative settings with enforcement at deployment level | — |
| Tls Configuration | sslForced mechanism exists to enforce SSL for database connections when required by deployment policy | Database connection layer supports SSL enforcement through sslForced configuration option | — |
| Tls Configuration | WebSocket fallback to HTTP polling uses relative URLs that inherit page HTTPS protocol, maintaining transport security | WebSocket fallback mechanism preserves transport security by inheriting protocol from parent page | — |
| Tls Configuration | Async event system gated behind feature flag (GlobalAsyncQueries), disabled by default | WebSocket-dependent async query feature disabled by default, reducing attack surface | — |
| Source Control Metadata | Deployment-level source control metadata protection delegated to web server/container configuration (nginx deny rules, Dockerfile multi-stage builds, .dockerignore) | Promoted from dropped finding ASVS-1341-MED-002 | — |
| Source Control Metadata | Environment-aware DevTools configuration disables Redux DevTools in production builds | Promoted from dropped finding ASVS-1341-MED-001 | — |
| Sensitive Data Exposure | Filter state values transmitted in HTTP body via jsonPayload, not URL parameters | Authentication and sensitive data transmission handled through HTTP body and headers rather than query strings | — |
| Sensitive Data Exposure | No credentials/tokens observed in query strings; authentication handled via SupersetClient headers/cookies | Verified that API keys and session tokens are not exposed in URLs | — |
| Sensitive Data Exposure | Whitelist-based persistence (PERSISTENT_QUERY_EDITOR_KEYS) prevents credential storage in localStorage | Controlled persistence mechanism ensures sensitive authentication data is not stored client-side | — |
| Sensitive Data Exposure | Query results have 24-hour TTL and 1MB size limit enforced via shouldEmptyQueryResults | Automatic expiration and size limits reduce risk of sensitive data accumulation in client storage | — |
| Sensitive Data Exposure | SqllabBackendPersistence feature flag reduces localStorage reliance to unsaved deltas only | Backend persistence option minimizes client-side storage of potentially sensitive query data | — |
| Dependency Management | Third-party dependency management delegated to ASF governance processes and dependency maintainers | Documented in SECURITY.md; ASF governance provides foundation-level security processes externally | — |
| Dependency Management | Third-party dependency security responsibility explicitly delegated to dependency maintainers and image extenders per SECURITY.md | Documented in SECURITY.md | — |
| Dependency Management | Legacy plugins isolated in independent packages limiting blast radius of outdated dependencies | Architecture design for legacy plugin isolation | — |
| Input Validation | Security enforcement delegated to backend API layer; client-side validators are UX utilities only | Backend query parameterization and server-side validation implementation | — |
| Input Validation | Backend query parameterization provides security enforcement independent of optional frontend validation | Observed in backend implementation patterns | — |
| Input Validation | Server-configured allowedExtensions prop indicates backend awareness of file type restrictions | File upload validation configured at server level | — |
| Input Validation | Form-level gating enforces all required fields before actual upload submission (onFinish) | Form validation ensures required field completion before submission | — |
| Browser Security Headers | Development vs. production separation: security-relaxing configurations are cleanly isolated to development tooling directories | source: Dropped finding ASVS-411-INFO-001 | — |
| File Upload Security | Upload endpoints require authentication via SupersetClient (CSRF tokens, session cookies); unauthenticated users cannot reach upload flows | Promoted from dropped finding ASVS-521-LOW-001 | — |
| File Upload Security | Client-side extension validation via validateUploadFileExtension() with case-insensitive comparison and strict final-extension regex | source: Dropped finding ASVS-522-LOW-001 | — |
| Authentication Controls | Rate limiting and brute force protection delegated to deployment infrastructure by design | Application architecture delegates rate limiting, anti-automation, and adaptive response controls to deployment infrastructure layer | — |
| Authentication Controls | Password policy enforcement delegated to Flask-AppBuilder backend | Minimum password length and composition requirements handled by Flask-AppBuilder framework | — |
| Authentication Controls | Users can change their password | Password change functionality verified as present and operational | — |
| Authentication Controls | Password change enforcement handled by Flask-AppBuilder backend | Current and new password validation during password change delegated to Flask-AppBuilder framework | — |
| Authentication Controls | Password complexity/blocklist enforcement delegated to Flask-AppBuilder backend | Common password checking against blocklist handled by Flask-AppBuilder framework | — |
| Authentication Controls | No restrictive password composition rules enforced | Application allows passwords of any character composition without mandatory character type requirements | — |
| Authentication Controls | Password fields use proper masking | Password input fields use type=password for entry masking | — |
| Authentication Controls | Password paste and password manager support enabled | Application permits paste functionality, browser password helpers, and external password managers | — |
| Authentication Controls | Passwords verified without modification | Application verifies user passwords exactly as received without truncation or case transformation | — |
| Authentication Controls | Anti-automation/rate limiting on login delegated to deployment infrastructure by design | Credential stuffing and brute force prevention controls implemented at infrastructure layer per security documentation | — |
| Authentication Controls | No default accounts present or enabled | Default user accounts (root, admin, sa) verified as absent or disabled | — |
| Authentication Controls | Secure initial password/activation code generation | System-generated initial passwords are securely random, follow password policy, and expire appropriately | — |
| Authentication Controls | No password hints or knowledge-based authentication | Password hints and secret questions verified as not present in the application | — |
| Authorization Controls | Authorization rules implemented consistently using [action, resource] tuple pattern with test coverage as documentation | 8.1.1 - Authorization documentation present through consistent implementation pattern and test coverage | — |
| Authorization Controls | Admin role blanket permission bypass is intentional design decision for trusted admin boundary | 8.2.1 - Function-level access control design includes explicit admin role handling | — |
| Authorization Controls | Filter scope configuration delegated to backend for enforcement; frontend is UI optimization only | 8.2.2 - Data-specific access control enforced server-side, preventing IDOR/BOLA vulnerabilities | — |
| Authorization Controls | Backend independently re-validates authorization on every API call regardless of frontend permission state | 8.3.1 - Authorization enforced at trusted service layer, not dependent on client-side controls | — |
| Token Validation | Self-contained tokens are validated using their digital signature or MAC to protect against tampering | ASVS 9.1.1 - Pass status indicates proper signature validation is implemented | — |
| Token Validation | Only allowlisted algorithms are used to create and verify self-contained tokens, excluding 'None' algorithm | ASVS 9.1.2 - Pass status indicates proper algorithm allowlisting is in place | — |
| Token Validation | Backend allowed_domains enforcement and server-side token signature validation prevent privilege escalation | ASVS 9.1.3 - Key material validation from trusted pre-configured sources | — |
| Token Validation | Token validity time span (nbf, exp claims) is properly verified before accepting token content | ASVS 9.2.1 - Pass status indicates proper temporal validation of tokens | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Fail** | See FINDING-004, FINDING-005, FINDING-006 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Fail** | See FINDING-007 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** | |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Fail** | See FINDING-002 |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** | |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** | |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Fail** | See FINDING-003 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** | |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** | |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Pass** | |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** | |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** | |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** | |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Fail** | See FINDING-004, FINDING-005, FINDING-006 |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** | |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** | |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** | |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** | |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Pass** | |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** | |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **N/A** | |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** | |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** | |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** | |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** | |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** | |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** | |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** | |
| 6.2.2 | Verify that users can change their password. | **Pass** | |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** | |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** | |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** | |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **Pass** | |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** | |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** | |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **N/A** | |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** | |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Pass** | |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** | |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** | |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** | |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **Pass** | |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** | |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Pass** | |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Pass** | |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** | |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** | |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** | |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** | |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** | |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** | |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** | |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Pass** | |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** | |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** | |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** | |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** | |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** | |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **N/A** | |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **N/A** | |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **N/A** | |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** | |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** | |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Pass** | |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** | |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** | |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** | |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** | |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** | |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Partial** | See FINDING-008, FINDING-009, FINDING-010, FINDING-011 |

**Summary Statistics:**
- **Pass**: 36 requirements (51.4%)
- **Partial**: 1 requirements (1.4%)
- **N/A**: 28 requirements (40.0%)
- **Fail**: 5 requirements (7.1%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-002 | High | 1.2.4 | | superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts |
| FINDING-003 | High | 1.3.2 | — | superset-frontend/plugins/preset-chart-deckgl/src/layers/Geojson/Geojson.tsx, superset-frontend/plugins/preset-chart-deckgl/src/utils/sandbox.ts |
| FINDING-004 | Medium | 1.2.1, 3.2.2 | FINDING-005, FINDING-006, FINDING-007 | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| FINDING-005 | Medium | 1.2.1, 3.2.2 | FINDING-004, FINDING-006, FINDING-007 | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| FINDING-006 | Medium | 1.2.1, 3.2.2 | FINDING-004, FINDING-005, FINDING-007 | superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts |
| FINDING-007 | Medium | 1.2.2 | FINDING-004, FINDING-005, FINDING-006 | superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx |
| FINDING-008 | Low | 15.3.1 | FINDING-009, FINDING-010, FINDING-011 | superset-frontend/src/hooks/apiResources/dashboards.ts |
| FINDING-009 | Low | 15.3.1 | FINDING-008, FINDING-010, FINDING-011 | superset-frontend/src/hooks/apiResources/datasets.ts |
| FINDING-010 | Low | 15.3.1 | FINDING-008, FINDING-009, FINDING-011 | superset-frontend/src/hooks/apiResources/dashboards.ts |
| FINDING-011 | Low | 15.3.1 | FINDING-008, FINDING-009, FINDING-010 | superset-frontend/src/hooks/apiResources/queryApi.ts |

**Total Unique Findings**: 11 (1 Critical, 2 High, 4 Medium, 4 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 11 |

**Total consolidated findings: 11**

*End of Consolidated Security Audit Report*