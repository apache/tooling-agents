# Security Issues

---
## Issue: FINDING-002 - Numeric BETWEEN Values Interpolated Without Type Enforcement
**Labels:** bug, security, priority:high
**Description:**

### Summary
Numeric filter values for the `IN_RANGE` operator (which generates SQL BETWEEN clauses) are interpolated directly into SQL without type coercion or validation. The `validateFilterValue` function accepts strings, and there is no enforcement that BETWEEN values are actually numeric before interpolation. Exploitable via filter state manipulation on metric columns.

### Details
- **CWE:** CWE-89 (SQL Injection)
- **ASVS:** 1.2.4 (Level 1)
- **Affected File:** `superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts`
- **Related Findings:** FINDING-001

### Remediation
Enforce numeric types via `Number()` coercion with `Number.isNaN()` validation before interpolation. Return empty string for non-numeric values.

### Acceptance Criteria
- [ ] Fixed: Numeric type enforcement implemented for BETWEEN values
- [ ] Fixed: Non-numeric values are rejected or safely handled
- [ ] Test added: IN_RANGE filter with non-numeric input
- [ ] Test added: IN_RANGE filter with malicious string input

### References
- Source Reports: 1.2.4.md
- Merged From: ASVS-124-HIGH-001

### Priority
**High** - SQL injection vulnerability in numeric filter handling

---
## Issue: FINDING-003 - No Input Sanitization or AST Validation Before Dynamic Code Execution in DeckGL sandboxedEval
**Labels:** bug, security, priority:high
**Description:**

### Summary
User-provided JavaScript strings from chart form data are passed directly to `sandboxedEval()` without any AST validation, pattern blocking, or input sanitization. The sandbox implementation uses a restricted execution context but does not validate input before execution, allowing constructor chain escape attacks. A chart creator with edit permissions can set `js_data_mutator` to escape the sandbox via constructor chains (e.g., `console.constructor.constructor('return this')()`) achieving full browser API access. When any user views the dashboard containing this chart, the malicious code executes with full browser privileges.

### Details
- **CWE:** CWE-94 (Code Injection)
- **ASVS:** 1.3.2 (Level 1)
- **Affected Files:**
  - `superset-frontend/plugins/preset-chart-deckgl/src/layers/Geojson/Geojson.tsx`
  - `superset-frontend/plugins/preset-chart-deckgl/src/utils/sandbox.ts`

### Remediation
Add AST-based input validation to `sandboxedEval` modeled after `safeEChartOptionsParser.ts`, blocking `constructor`, `__proto__`, and `prototype` member access. Additionally freeze `GLOBAL_CONTEXT` objects to prevent constructor chain access.

### Acceptance Criteria
- [ ] Fixed: AST validation blocks constructor chain access patterns
- [ ] Fixed: GLOBAL_CONTEXT objects are frozen
- [ ] Test added: Constructor chain escape attempt is blocked
- [ ] Test added: __proto__ and prototype access attempts are blocked

### References
- Source Reports: 1.3.2.md
- Merged From: ASVS-132-HIGH-001

### Priority
**High** - Sandbox escape leading to arbitrary JavaScript execution

---
## Issue: FINDING-004 - Stored XSS in generateMultiLineTooltipContent via unsanitized series.key
**Labels:** bug, security, priority:medium
**Description:**

### Summary
User-controlled data (groupby column values) flows through `series.key` → `getFormattedKey(key, false)` (sanitization explicitly skipped) → string interpolation into HTML → rendered via D3's `.html()` (innerHTML). `DOMPurify.sanitize` exists in the same file and is used by `generateCompareTooltipContent` and `generateTimePivotTooltip`, but NOT called in this function. Attacker uploads data with XSS payload in column values, creates chart on shared dashboard, and XSS triggers when other users hover over tooltips.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.1, 3.2.2 (Level 1)
- **Affected File:** `superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts`
- **Related Findings:** FINDING-005, FINDING-006, FINDING-007

### Remediation
Apply `dompurify.sanitize()` to tooltip output and change `getFormattedKey` call to use `shouldDompurify=true`, matching the pattern already used by other tooltip functions in the same file. Alternatively, HTML-encode all data-derived values before interpolation.

### Acceptance Criteria
- [ ] Fixed: DOMPurify sanitization applied to tooltip content
- [ ] Fixed: getFormattedKey called with shouldDompurify=true
- [ ] Test added: XSS payload in groupby column value
- [ ] Test added: Tooltip rendering with malicious data

### References
- Source Reports: 1.2.1.md, 3.2.2.md
- Merged From: ASVS-121-MED-001, ASVS-322-MED-001 (generateMultiLineTooltipContent portion)

### Priority
**Medium** - Stored XSS affecting shared dashboard users

---
## Issue: FINDING-005 - Stored XSS in generateBubbleTooltipContent via unsanitized point entity/group
**Labels:** bug, security, priority:medium
**Description:**

### Summary
Query result data flows through `point[entity]` / `point.group` → string interpolation into HTML → rendered via D3 `.html()` (innerHTML). DOMPurify is imported and used elsewhere in this file but not called here. Attacker creates dataset with XSS payload in entity column, creates bubble chart, and XSS triggers on tooltip hover by other users on shared dashboards.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.1, 3.2.2 (Level 1)
- **Affected File:** `superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts`
- **Related Findings:** FINDING-004, FINDING-006, FINDING-007

### Remediation
Apply `dompurify.sanitize()` to all user-derived values before interpolation and to the final HTML string before return. Alternatively, HTML-encode all data-derived values before interpolation to ensure text-safe rendering.

### Acceptance Criteria
- [ ] Fixed: DOMPurify sanitization applied to point entity/group values
- [ ] Fixed: Final HTML string sanitized before return
- [ ] Test added: XSS payload in entity column
- [ ] Test added: Bubble chart tooltip with malicious data

### References
- Source Reports: 1.2.1.md, 3.2.2.md
- Merged From: ASVS-121-MED-002, ASVS-322-MED-001 (generateBubbleTooltipContent portion)

### Priority
**Medium** - Stored XSS affecting shared dashboard users

---
## Issue: FINDING-006 - Stored XSS in tipFactory via unsanitized annotation data values
**Labels:** bug, security, priority:medium
**Description:**

### Summary
Annotation data values (`d[layer.titleColumn]`, `d[column]`) flow through string interpolation → `d3-tip` `.html()` callback → innerHTML on tooltip DOM element. DOMPurify exists in the same module but not applied here. Attacker configures annotation layer pointing to dataset with XSS payload in title column, affecting users who hover over annotations on shared charts.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.1, 3.2.2 (Level 1)
- **Affected File:** `superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts`
- **Related Findings:** FINDING-004, FINDING-005, FINDING-007

### Remediation
Apply `dompurify.sanitize()` to the HTML string returned by the `.html()` callback. Alternatively, HTML-encode all data-derived values before interpolation to ensure text-safe rendering.

### Acceptance Criteria
- [ ] Fixed: DOMPurify sanitization applied to annotation tooltip HTML
- [ ] Fixed: All data-derived values sanitized before interpolation
- [ ] Test added: XSS payload in annotation title column
- [ ] Test added: Annotation tooltip with malicious data

### References
- Source Reports: 1.2.1.md, 3.2.2.md
- Merged From: ASVS-121-MED-003, ASVS-322-MED-001 (tipFactory portion)

### Priority
**Medium** - Stored XSS affecting users viewing annotated charts

---
## Issue: FINDING-007 - javascript: protocol XSS in SafeMarkdown when transformLinkUri is disabled
**Labels:** bug, security, priority:medium
**Description:**

### Summary
SafeMarkdown sets `transformLinkUri={null}` which disables URL protocol sanitization. When the `EscapeMarkdownHtml` feature flag is enabled (removing rehype-sanitize from the pipeline), markdown links like `[text](javascript:...)` render as clickable XSS payloads. Attacker with markdown authoring access (dashboard descriptions, text widgets) can inject javascript: protocol links affecting other users who click them.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.2 (Level 1)
- **Affected File:** `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`
- **Related Findings:** FINDING-004, FINDING-005, FINDING-006

### Remediation
Replace `transformLinkUri={null}` with a protocol-safe sanitizer that blocks `javascript:`, `vbscript:`, and `data:` protocols regardless of which rehype plugins are active.

### Acceptance Criteria
- [ ] Fixed: Protocol sanitization implemented for markdown links
- [ ] Fixed: javascript:, vbscript:, and data: protocols blocked
- [ ] Test added: javascript: protocol in markdown link
- [ ] Test added: Other dangerous protocols blocked

### References
- Source Reports: 1.2.2.md
- Merged From: ASVS-122-MED-001

### Priority
**Medium** - XSS via dangerous URL protocols in markdown content

---
## Issue: FINDING-008 - Inconsistent Field Filtering — useDashboardCharts Returns Full Chart Objects Without Column Specification
**Labels:** bug, security, priority:low
**Description:**

### Summary
DOWNGRADED from Medium: Per profile's documented design decision, low-impact boundary variations in existing access controls are classified as hardening improvements rather than vulnerabilities. User is already authorized to view dashboard charts; no trust boundary crossed. Original: `useDashboardCharts` requests full chart list without column specification unlike `useDashboard` which explicitly specifies `DASHBOARD_GET_COLUMNS`.

### Details
- **CWE:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
- **ASVS:** 15.3.1 (Level 1)
- **Affected File:** `superset-frontend/src/hooks/apiResources/dashboards.ts`
- **Related Findings:** FINDING-009, FINDING-010, FINDING-011

### Remediation
Add explicit column specifications to `useDashboardCharts` to request only fields needed for rendering.

### Acceptance Criteria
- [ ] Fixed: Column specification added to useDashboardCharts
- [ ] Test added: Verify only required fields returned

### References
- Source Reports: 15.3.1.md
- Merged From: ASVS-1531-MED-001

### Priority
**Low** - Hardening improvement, no trust boundary violation

---
## Issue: FINDING-009 - useDatasetDrillInfo Returns Full Dataset Object Without Field Specification
**Labels:** bug, security, priority:low
**Description:**

### Summary
DOWNGRADED from Medium: Per profile's documented design decision, low-impact boundary variations in existing access controls are classified as hardening improvements. User is already authorized to access dataset drill info; no trust boundary crossed. Original: The hook only needs columns and metrics to build a `verbose_map` but the full dataset response is stored and cached.

### Details
- **CWE:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
- **ASVS:** 15.3.1 (Level 1)
- **Affected File:** `superset-frontend/src/hooks/apiResources/datasets.ts`
- **Related Findings:** FINDING-008, FINDING-010, FINDING-011

### Remediation
Add explicit column specifications to `useDatasetDrillInfo` to request only fields needed for drill-by functionality.

### Acceptance Criteria
- [ ] Fixed: Column specification added to useDatasetDrillInfo
- [ ] Test added: Verify only columns and metrics returned

### References
- Source Reports: 15.3.1.md
- Merged From: ASVS-1531-MED-002

### Priority
**Low** - Hardening improvement, no trust boundary violation

---
## Issue: FINDING-010 - useEmbeddedDashboard Returns Full Embedded Configuration Without Column Specification
**Labels:** bug, security, priority:low
**Description:**

### Summary
`useEmbeddedDashboard` does not specify column filtering. Embedded dashboard contexts are used with guest tokens. The embedded endpoint may return internal configuration fields not needed by the embedded rendering context.

### Details
- **CWE:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
- **ASVS:** 15.3.1 (Level 1)
- **Affected File:** `superset-frontend/src/hooks/apiResources/dashboards.ts`
- **Related Findings:** FINDING-008, FINDING-009, FINDING-011

### Remediation
Add explicit column specifications to `useEmbeddedDashboard` to limit fields returned in embedded contexts.

### Acceptance Criteria
- [ ] Fixed: Column specification added to useEmbeddedDashboard
- [ ] Test added: Verify only required fields returned in embedded context

### References
- Source Reports: 15.3.1.md
- Merged From: ASVS-1531-LOW-001

### Priority
**Low** - Potential information disclosure in embedded contexts

---
## Issue: FINDING-011 - queryApi Generic Base Query Has No Default Field-Limiting Mechanism
**Labels:** bug, security, priority:low
**Description:**

### Summary
The generic `supersetClientQuery` base query function passes through the entire API response if no `transformResponse` is provided. There is no enforcement mechanism or default behavior that strips unnecessary fields from responses.

### Details
- **CWE:** CWE-213 (Exposure of Sensitive Information Due to Incompatible Policies)
- **ASVS:** 15.3.1 (Level 1)
- **Affected File:** `superset-frontend/src/hooks/apiResources/queryApi.ts`
- **Related Findings:** FINDING-008, FINDING-009, FINDING-010

### Remediation
Consider adding a utility or convention that makes field specification explicit for all endpoint definitions.

### Acceptance Criteria
- [ ] Fixed: Default field-limiting mechanism or convention implemented
- [ ] Test added: Verify field filtering applies to new endpoints

### References
- Source Reports: 15.3.1.md
- Merged From: ASVS-1531-LOW-002

### Priority
**Low** - Infrastructure hardening improvement