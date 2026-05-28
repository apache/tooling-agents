# Security Issues

---
## Issue: FINDING-003 - `tipFactory` renders annotation data into HTML without sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `tipFactory` function creates d3-tip tooltip instances for annotation layers and renders annotation data (titles and description columns) directly into HTML without sanitization.

### Details
**Attack Flow:**
1. Annotation query data → `d[layer.titleColumn]`, `d[column]` values
2. HTML string construction
3. d3-tip `.html()` callback → DOM insertion as innerHTML when users interact with chart annotations

**Attacker Capability Required:**
Authenticated user who controls annotation data source content. Annotations are typically admin-configured, significantly reducing exploitability compared to general chart data.

**Impact:**
XSS via annotation tooltips. Despite DOMPurify being available in the module, the annotation tooltip HTML is not sanitized. Lower severity due to restricted attacker capability (typically requires admin access to configure annotation data sources).

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**ASVS:** 1.2.1, 3.2.2 (Level 1)

### Remediation
Wrap the HTML return value in the `.html()` callback with `dompurify.sanitize()` to ensure annotation data is sanitized before DOM insertion.

### Acceptance Criteria
- [ ] Fixed - Sanitize annotation HTML output in d3-tip callback
- [ ] Test added - Unit test with XSS payload in annotation data
- [ ] Test added - Integration test verifying annotation tooltip renders safely

### References
- **File:** `superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts`
- **Related Findings:** FINDING-001, FINDING-002, FINDING-004
- **Source Reports:** 1.2.1.md, 3.2.2.md

### Priority
**Medium** - Limited exploitability (requires admin-level access to annotation configuration)

---
## Issue: FINDING-004 - SafeMarkdown disables URL protocol filtering, enabling javascript: URIs when EscapeMarkdownHtml is active
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SafeMarkdown component sets `transformLinkUri={null}` which disables the default URI protocol filtering provided by react-markdown, allowing `javascript:` and other dangerous protocol links to render when the `EscapeMarkdownHtml` feature flag is enabled.

### Details
**Vulnerability Condition:**
When `FeatureFlag.EscapeMarkdownHtml` is enabled:
- `rehypePlugins` array is empty (no rehype-sanitize plugin)
- `transformLinkUri={null}` means no URL protocol filtering is applied
- Result: `javascript:`, `vbscript:`, `data:` and other dangerous protocol links can render

**Attack Flow:**
URL context encoding bypass where malicious URLs are not validated or encoded according to safe URL protocols.

**Attacker Capability Required:**
Authenticated user (Alpha/Gamma+ role) with ability to create or edit markdown-containing content (dashboards, chart descriptions, etc.).

**Impact:**
The `EscapeMarkdownHtml` feature flag's name implies increased security but silently fails to protect against dangerous URL protocols, creating a false sense of security.

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)
**ASVS:** 1.2.2 (Level 1)

### Remediation
Replace `transformLinkUri={null}` with a safe URI transformer function that:
1. Validates and blocks dangerous protocols (javascript, vbscript, data, etc.)
2. Allows safe protocols (http, https, mailto)
3. Ensures this validation is active regardless of the EscapeMarkdownHtml feature flag state

### Acceptance Criteria
- [ ] Fixed - Implement safe URI transformer function
- [ ] Fixed - Apply transformer regardless of feature flag state
- [ ] Test added - Unit test with `javascript:` URI
- [ ] Test added - Unit test verifying safe protocols still work
- [ ] Test added - Test coverage for both feature flag states

### References
- **File:** `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`
- **Related Findings:** FINDING-001, FINDING-002, FINDING-003
- **Source Reports:** 1.2.2.md

### Priority
**Medium** - Requires authenticated user with content editing privileges

---
## Issue: FINDING-005 - Inconsistent SQL Escaping in AG Grid IN_RANGE Filter Path
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `simpleFilterToWhereClause` function constructs SQL WHERE clause fragments for AG Grid filters but omits SQL escaping for the IN_RANGE operator case, creating an inconsistency in SQL injection protection.

### Details
**Inconsistent Escaping:**
- ILIKE and string comparison operators: ✅ Correctly apply `escapeSQLString`
- IN_RANGE operator: ❌ Interpolates values directly into SQL BETWEEN clause without escaping

**Exploitability:**
Practical exploitability is limited by AG Grid's UI producing numeric values, but the inconsistency represents a real gap in the security control's coverage for the `extras.where` path which is included as raw SQL by the backend.

**Attack Vector:**
If an attacker can manipulate the filter values sent to this function (e.g., via API interception or client-side manipulation), they could inject SQL fragments through the IN_RANGE path.

**CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
**ASVS:** 1.2.4 (Level 1)

### Remediation
Apply consistent escaping and type validation to the IN_RANGE case:
1. Add runtime type assertion to ensure range values are numeric, OR
2. Apply `escapeSQLString` for string values
3. Consider using parameterized queries instead of string concatenation

### Acceptance Criteria
- [ ] Fixed - Add escaping or type validation to IN_RANGE case
- [ ] Test added - Unit test with SQL injection payload in range values
- [ ] Test added - Verify numeric values still work correctly
- [ ] Code review - Verify consistent escaping across all filter operators

### References
- **File:** `superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts`
- **Source Reports:** 1.2.4.md

### Priority
**Medium** - Limited exploitability but represents defense-in-depth gap

---
## Issue: FINDING-006 - Query Results Key Transmitted in GET URL Query Parameter
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `fetchQueryResults` function transmits a sensitive query results key (`resultsKey`) as a URL query parameter in a GET request, violating ASVS 14.2.1 which requires that sensitive data like API keys and session tokens must not be transmitted in URLs.

### Details
**Sensitive Data Exposure:**
The `resultsKey` is a server-generated bearer-like token that grants access to cached query results containing potentially sensitive business data, PII, or financial information.

**Exposure Vectors:**
The complete URL including the results key is recorded in:
- Browser history
- Reverse proxy logs
- Load balancer logs
- WAF logs
- Server access logs
- Referrer headers on external navigation

**Attack Scenarios:**
1. Shared computer: Results key visible in browser history
2. Log aggregation: Results keys exposed in centralized logging systems
3. Referrer leakage: Results key sent to external sites via referrer header
4. Shoulder surfing: Results key visible in browser address bar

**CWE:** CWE-598 (Use of GET Request Method With Sensitive Query Strings)
**ASVS:** 14.2.1 (Level 1)

### Remediation
1. Migrate `resultsKey` to POST body or custom header
2. Update `/api/v1/sqllab/results/` endpoint to accept POST requests with body `{ key: string, rows: number }`
3. Maintain GET endpoint temporarily for backward compatibility with deprecation warning
4. Add migration timeline and remove GET endpoint in future release

### Acceptance Criteria
- [ ] Fixed - Implement POST endpoint accepting resultsKey in body
- [ ] Fixed - Update `fetchQueryResults` to use POST method
- [ ] Test added - Integration test verifying POST method works
- [ ] Test added - Verify resultsKey not in URL/logs
- [ ] Documentation - Update API documentation
- [ ] Migration plan - Document deprecation timeline for GET endpoint

### References
- **File:** `superset-frontend/src/SqlLab/actions/sqlLab.ts` (lines 296-301)
- **Source Reports:** 14.2.1.md

### Priority
**Medium** - Sensitive data exposure, but requires access to logs or browser history

---
## Issue: FINDING-007 - useListViewResource Has Optional Field Projection — Callers May Receive Unrestricted Responses
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `useListViewResource` hook includes a `selectColumns` parameter for field projection, but this parameter is optional. Callers that don't provide `selectColumns` receive all default list columns from the backend, potentially including fields the specific list view doesn't display or need, violating the principle of data minimization.

### Details
**Data Minimization Issue:**
When `selectColumns` is not specified, the API returns all default columns, which may include:
- Fields not displayed in the UI
- Sensitive metadata
- Fields not required for the specific use case

**Impact:**
- Unnecessary data exposure to client
- Increased network payload
- Potential information disclosure if default columns include sensitive fields
- Violation of least privilege principle for data access

**CWE:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
**ASVS:** 15.3.1 (Level 1)

### Remediation
Consider one or more of the following approaches:
1. Make `selectColumns` a required parameter
2. Add ESLint rule to warn when `selectColumns` is not provided
3. Add code review checklist item to ensure all callers specify needed columns
4. Document best practice in component documentation
5. Provide sensible minimal defaults per resource type

### Acceptance Criteria
- [ ] Fixed - Implement chosen remediation approach
- [ ] Test added - Audit all existing callers of `useListViewResource`
- [ ] Test added - Verify all callers specify `selectColumns`
- [ ] Documentation - Update hook documentation with best practices
- [ ] Code review - Add checklist item for future reviews

### References
- **File:** `superset-frontend/src/views/CRUD/hooks.ts`
- **Source Reports:** 15.3.1.md

### Priority
**Low** - Data minimization concern, no direct security exploit, primarily a best practice issue