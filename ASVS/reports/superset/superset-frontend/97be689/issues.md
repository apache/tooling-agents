# Security Issues

---
## Issue: FINDING-001 - Unsanitized HTML in NVD3 Tooltip Generators Allows Stored XSS
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Multiple tooltip generator functions in the NVD3 chart plugin return HTML without sanitization before rendering via innerHTML. Database column values flow through chart data into tooltips without DOMPurify sanitization, allowing authenticated users with datasource write access to inject malicious HTML/JS that executes against any user viewing the tooltips.

### Details
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**ASVS Sections:** 1.1.2, 1.3.1, 1.3.7  
**ASVS Levels:** L1, L2

**Affected Functions:**
- `generateMultiLineTooltipContent` (~line 126)
- `generateBubbleTooltipContent` (~line 188)
- `tipFactory`

These functions construct HTML strings from user-controlled data (series keys, entity names) without sanitization, unlike `generateCompareTooltipContent` which correctly applies `dompurify.sanitize()`.

**Attack Vector:**
1. Authenticated user with datasource write access inserts malicious HTML/JS into database columns
2. Data flows into chart series keys or entity names
3. Tooltip renders unsanitized HTML via innerHTML
4. XSS payload executes in victim's browser when hovering over chart elements

### Remediation
Apply `dompurify.sanitize()` to the final HTML string returned by:
- `generateMultiLineTooltipContent`
- `generateBubbleTooltipContent`
- `tipFactory`

Change `getFormattedKey(series.key, false)` to `getFormattedKey(series.key, true)` in affected functions to enable sanitization.

### Acceptance Criteria
- [ ] All tooltip HTML output is sanitized with DOMPurify before rendering
- [ ] `getFormattedKey` calls use `true` flag for sanitization
- [ ] Test added with XSS payload in chart data to verify sanitization
- [ ] Manual verification that tooltips render safely with malicious input

### References
- Related: FINDING-003, FINDING-004, FINDING-009
- File: `superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts`

### Priority
**Medium** - Requires authentication and datasource write access, but enables stored XSS affecting all chart viewers.

---
## Issue: FINDING-002 - AG Grid Filter Column Name Validation Allows SQL Injection via complexWhere Path
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `COLUMN_NAME_REGEX` in AG Grid filter converter allows spaces, parentheses, and other characters that permit SQL keyword injection through column names. Gamma+ users crafting direct API requests can inject SQL via the complexWhere/havingClause path designed for raw SQL fragments.

### Details
**CWE:** CWE-89 (SQL Injection)  
**ASVS Sections:** 1.3.7  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts`

**Attack Vector:**
1. Gamma+ user crafts API request with malicious column name
2. Frontend SQL filter construction creates SQL clauses with injected keywords
3. Backend processes complexWhere/havingClause without sufficient validation
4. SQL injection executes in database context

**Root Cause:**
- Overly permissive regex allows SQL-dangerous characters
- Frontend constructs SQL strings instead of structured filter objects
- Backend trusts frontend-generated SQL fragments

### Remediation
Implement one or more of the following:
1. Restrict column name regex to disallow SQL keywords and special characters
2. Quote column identifiers with proper database-specific escaping
3. **Preferred:** Send structured filter objects to backend instead of constructing SQL on frontend
4. Backend must validate/sanitize all complexWhere clauses regardless of frontend changes

### Acceptance Criteria
- [ ] Column name validation rejects SQL keywords and injection patterns
- [ ] Column identifiers are properly quoted/escaped in generated SQL
- [ ] Test added with malicious column names to verify injection prevention
- [ ] Backend validation added for complexWhere clauses
- [ ] Consider architectural change to structured filters

### References
- Related: FINDING-008
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts`

### Priority
**Medium** - Requires Gamma+ role and direct API access, but enables SQL injection with potential data exfiltration.

---
## Issue: FINDING-003 - NVD3 tooltip generators produce HTML without context-appropriate encoding for HTML element content
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Tooltip generator functions interpolate values like `series.key`, `point[entity]`, and `point.group` into HTML `<td>` element content without HTML entity encoding or sanitization, violating ASVS 1.2.1 requirement for context-appropriate output encoding.

### Details
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**ASVS Sections:** 1.2.1  
**ASVS Levels:** L1, L2, L3

**Affected Functions:**
- `generateMultiLineTooltipContent` (line ~126)
- `generateBubbleTooltipContent` (line ~188)

**Attack Vector:**
Authenticated user with datasource write access stores XSS payload in database that executes against chart viewers when rendered in tooltip HTML element content.

**Technical Detail:**
Values are directly interpolated into HTML strings:
```javascript
<td>${series.key}</td>  // No encoding applied
<td>${point[entity]}</td>  // No encoding applied
```

### Remediation
Apply one of:
1. `dompurify.sanitize()` to the final HTML string (consistent with other tooltip functions)
2. Context-appropriate HTML entity encoding for all dynamic values before interpolation
3. Use DOM APIs instead of string concatenation

### Acceptance Criteria
- [ ] All dynamic values in tooltip HTML are encoded/sanitized
- [ ] Test added with HTML special characters in data values
- [ ] Test added with XSS payload to verify prevention
- [ ] Manual verification tooltips render safely with malicious input

### References
- Related: FINDING-001, FINDING-004, FINDING-009
- File: `superset-frontend/plugins/legacy-preset-chart-nvd3/src/utils.ts`

### Priority
**Medium** - Requires authentication and datasource write access, enables stored XSS affecting all chart viewers.

---
## Issue: FINDING-004 - SafeMarkdown disables URI protocol sanitization via transformLinkUri={null}, allowing javascript: URLs in markdown links
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The SafeMarkdown component sets `transformLinkUri={null}`, which overrides react-markdown's built-in javascript: protocol blocking. When EscapeMarkdownHtml feature flag is enabled, rehype-sanitize is NOT applied, allowing authenticated users to create stored XSS via `[text](javascript:...)` links in dashboard markdown components.

### Details
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**ASVS Sections:** 1.2.2  
**ASVS Levels:** L1, L2, L3

**Affected Component:**
- File: `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`

**Vulnerable Configurations:**
1. `EscapeMarkdownHtml` enabled: **vulnerable**
2. `htmlSanitization=false`: **vulnerable**
3. `EscapeMarkdownHtml` disabled AND `htmlSanitization=true`: protected

**Attack Vector:**
1. Authenticated user with dashboard edit permission creates markdown component
2. User inserts malicious link: `[Click here](javascript:alert(document.cookie))`
3. Victim clicks link in dashboard
4. JavaScript payload executes in victim's browser context

### Remediation
Remove `transformLinkUri={null}` to use react-markdown's default URI sanitizer, OR provide an explicit safe-protocol allowlist function:

```javascript
transformLinkUri={(uri) => {
  const allowed = ['http:', 'https:', 'mailto:'];
  try {
    const protocol = new URL(uri, window.location.href).protocol;
    return allowed.includes(protocol) ? uri : '';
  } catch {
    return '';
  }
}}
```

Block: `javascript:`, `vbscript:`, `data:`, and other dangerous protocols.

### Acceptance Criteria
- [ ] `transformLinkUri={null}` removed or replaced with safe allowlist
- [ ] Test added with `javascript:` URL to verify blocking
- [ ] Test added with `data:` URL to verify blocking
- [ ] Test added with `http:` and `https:` URLs to verify allowance
- [ ] Manual verification in all SafeMarkdown usage contexts

### References
- Related: FINDING-001, FINDING-003, FINDING-009
- File: `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`

### Priority
**Medium** - Requires authentication and dashboard edit permission, but enables stored XSS requiring only one click.

---
## Issue: FINDING-005 - postMessage origin validation is commented out in embedded page initializer
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The embedded dashboard's `validateMessageEvent()` function has origin validation completely commented out. Any origin can establish a MessagePort connection with the embedded page and invoke all registered Switchboard methods, enabling unauthorized data exfiltration if an attacker possesses a valid guest token.

### Details
**CWE:** CWE-346 (Origin Validation Error)  
**ASVS Sections:** 3.5.5  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/src/embedded/index.tsx`

**Attack Scenario:**
1. Attacker obtains valid guest token (via social engineering, token leakage, etc.)
2. Attacker embeds Superset dashboard in malicious site
3. Malicious site establishes MessagePort connection (no origin check)
4. Attacker calls `guestToken` method to authenticate
5. Attacker invokes `getChartDataPayloads` and `getDataMask` to exfiltrate dashboard data
6. Data accessible only to authorized embedding origins is stolen

**Current State:**
Origin validation code exists but is commented out, suggesting incomplete implementation.

### Remediation
1. Uncomment and implement origin validation in `validateMessageEvent()`
2. Server must provide allowed origins list in bootstrap data for embedded page
3. Derive allowed origins from same domain allowlist used for guest token generation
4. Reject all postMessage connections from non-allowlisted origins

**Implementation:**
```javascript
function validateMessageEvent(event: MessageEvent): boolean {
  const allowedOrigins = getBootstrapData().allowedOrigins; // from server
  if (!allowedOrigins.includes(event.origin)) {
    console.warn('Rejected message from unauthorized origin:', event.origin);
    return false;
  }
  return true;
}
```

### Acceptance Criteria
- [ ] Origin validation uncommented and implemented
- [ ] Server provides allowed origins in embedded page bootstrap data
- [ ] Test added verifying rejection of unauthorized origins
- [ ] Test added verifying acceptance of authorized origins
- [ ] Security review of allowed origins configuration mechanism
- [ ] Documentation updated with embedding security requirements

### References
- File: `superset-frontend/src/embedded/index.tsx`

### Priority
**Medium** - Requires valid guest token to exploit, but completely bypasses origin-based access control for embedded dashboards.

---
## Issue: FINDING-006 - Number filter values interpolated into SQL without runtime type validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
In `convertFilterToSQL`, number filter values are interpolated directly into SQL strings without runtime numeric validation. An attacker who can manipulate AG Grid chart state can inject arbitrary SQL if the backend trusts frontend-generated SQL fragments. Text filters are properly escaped via `escapeStringValue()`, but number filters have zero runtime validation.

### Details
**CWE:** CWE-20 (Improper Input Validation)  
**ASVS Sections:** 15.3.5  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/stateConversion.ts`

**Attack Vector:**
1. Attacker manipulates AG Grid chart state via permalink, browser DevTools, or saved state
2. Sets number filter value to malicious string (e.g., `"1 OR 1=1--"`)
3. Frontend interpolates value directly into SQL without validation
4. Backend trusts frontend-generated complexWhere clause
5. SQL injection executes

**Vulnerable Code Pattern:**
```javascript
// Text filters: escaped ✓
WHERE column = '${escapeStringValue(filter.filter)}'

// Number filters: no validation ✗
WHERE column = ${filter.filter}
```

### Remediation
Add runtime numeric validation before interpolating number values:

```javascript
if (filterType === 'number') {
  const numValue = Number(filter.filter);
  if (!Number.isFinite(numValue)) {
    console.warn('Invalid number filter value:', filter.filter);
    return null; // or throw error
  }
  return `${columnName} ${operator} ${numValue}`;
}
```

### Acceptance Criteria
- [ ] `Number.isFinite()` validation added for all number filter values
- [ ] Non-numeric values rejected (return null or throw error)
- [ ] Test added with string value in number filter to verify rejection
- [ ] Test added with `Infinity`, `NaN` to verify rejection
- [ ] Test added with valid numbers to verify acceptance
- [ ] Consider moving SQL construction to backend with parameterized queries

### References
- Related: FINDING-007
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/stateConversion.ts`

### Priority
**Medium** - Requires ability to manipulate chart state, but enables SQL injection if backend trusts frontend SQL.

---
## Issue: FINDING-007 - Complex filter operator value interpolated into SQL without allowlist validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
In `convertFilterToSQL`, the `filter.operator` value (expected to be 'AND' or 'OR') is directly interpolated into SQL join expressions without allowlist validation. An attacker who can manipulate AG Grid chart state can inject arbitrary SQL between conditions by setting operator to a malicious value.

### Details
**CWE:** CWE-20 (Improper Input Validation)  
**ASVS Sections:** 15.3.5  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/stateConversion.ts`

**Attack Vector:**
1. Attacker manipulates AG Grid chart state
2. Sets `filter.operator` to malicious SQL (e.g., `"OR 1=1) --"`)
3. Frontend interpolates operator directly into SQL join expression
4. Generated SQL: `(condition1 OR 1=1) -- condition2)`
5. SQL injection executes, bypassing intended filter logic

**Vulnerable Code Pattern:**
```javascript
// No validation of operator value
return `(${condition1} ${filter.operator} ${condition2})`;
```

### Remediation
Validate `filter.operator` against strict allowlist:

```javascript
const ALLOWED_OPERATORS = new Set(['AND', 'OR']);

if (!ALLOWED_OPERATORS.has(filter.operator?.toUpperCase())) {
  console.warn('Invalid filter operator:', filter.operator);
  return null; // or throw error
}

return `(${condition1} ${filter.operator.toUpperCase()} ${condition2})`;
```

### Acceptance Criteria
- [ ] Operator allowlist validation added (`Set(['AND', 'OR'])`)
- [ ] Invalid operators rejected (return null or throw error)
- [ ] Operator normalized to uppercase
- [ ] Test added with malicious operator value to verify rejection
- [ ] Test added with 'AND' and 'OR' to verify acceptance
- [ ] Test added with lowercase 'and'/'or' to verify normalization

### References
- Related: FINDING-006
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/stateConversion.ts`

### Priority
**Medium** - Requires ability to manipulate chart state, but enables SQL injection in filter join logic.

---
## Issue: FINDING-008 - Missing Escaping in AG Grid IN_RANGE Filter SQL Clause Construction
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `simpleFilterToWhereClause` function does not apply `escapeSQLString()` to IN_RANGE filter values, despite applying it to other string-type filter operators. If the backend processes the complexWhere string without additional validation, this could allow SQL injection through IN_RANGE filter values.

### Details
**CWE:** CWE-89 (SQL Injection)  
**ASVS Sections:** 1.3.3  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts`

**Inconsistent Escaping:**
- EQUALS, NOT_EQUAL, CONTAINS, etc.: `escapeSQLString()` applied ✓
- IN_RANGE: No escaping applied ✗

**Attack Vector:**
1. User sets IN_RANGE filter with malicious string values
2. Frontend constructs SQL without escaping
3. Backend processes complexWhere without validation
4. SQL injection executes

**Severity Justification (Low):**
- Most IN_RANGE filters use numeric types (already interpolated unsafely - see FINDING-006)
- String-typed IN_RANGE filters are less common
- Requires backend to trust frontend SQL without validation
- Lower probability than other SQL injection vectors

### Remediation
Apply consistent escaping to IN_RANGE filter values:

```javascript
case 'IN_RANGE':
  if (filterType === 'text') {
    return `${columnName} BETWEEN '${escapeSQLString(filter.filter)}' AND '${escapeSQLString(filter.filterTo)}'`;
  }
  // ... numeric handling
```

**Preferred:** Move all SQL construction to backend with parameterized queries.

### Acceptance Criteria
- [ ] `escapeSQLString()` applied to IN_RANGE filter values for string types
- [ ] Test added with SQL injection payload in IN_RANGE filter
- [ ] Consistent escaping verified across all filter operators
- [ ] Consider architectural change to backend SQL construction

### References
- Related: FINDING-002
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/utils/agGridFilterConverter.ts`

### Priority
**Low** - Inconsistent escaping pattern, but requires uncommon string-typed IN_RANGE filters and backend trust of frontend SQL.

---
## Issue: FINDING-009 - CSS Injection via Unfiltered Style Attributes in XSS Filter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The FilterXSS configuration permits style attributes on whitelisted elements but sets `css: false`, disabling CSS property validation. An authenticated user who can write data to a queried database can inject CSS enabling UI overlay/phishing attacks against other users viewing charts with `allowRenderHtml=true`.

### Details
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**ASVS Sections:** 1.3.5  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/packages/superset-ui-core/src/utils/html.tsx`

**Attack Vector:**
1. Authenticated user with datasource write access injects CSS in database
2. Chart rendered with `allowRenderHtml=true`
3. Malicious CSS creates overlay UI elements
4. Victim sees fake login form, clickjacking overlay, etc.

**Example Malicious CSS:**
```html
<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:white;z-index:9999">
  Fake login form
</div>
```

**Severity Justification (Low):**
- Requires `allowRenderHtml=true` (not default)
- CSS injection less severe than JavaScript execution
- Limited to UI manipulation, not credential theft
- Defense-in-depth issue

### Remediation
Enable CSS property filtering with restrictive allowlist:

```javascript
css: {
  whiteList: {
    'color': true,
    'background-color': true,
    'font-size': true,
    'font-weight': true,
    'text-align': true,
    // ... safe properties only
    // Exclude: position, z-index, width, height, etc.
  }
}
```

**Alternative:** Remove `style` from attribute whitelist entirely.

### Acceptance Criteria
- [ ] CSS property allowlist implemented with safe properties only
- [ ] Dangerous properties blocked (position, z-index, width, height, etc.)
- [ ] Test added with malicious CSS to verify filtering
- [ ] Test added with safe CSS to verify allowance
- [ ] Consider removing style attribute entirely
- [ ] Documentation updated on `allowRenderHtml` security implications

### References
- Related: FINDING-001, FINDING-003, FINDING-004
- File: `superset-frontend/packages/superset-ui-core/src/utils/html.tsx`

### Priority
**Low** - Requires authentication, datasource write access, and non-default `allowRenderHtml=true`. Enables UI manipulation but not script execution.

---
## Issue: FINDING-010 - EncryptedField Component May Render Unmasked Credentials from Backend Response
**Labels:** bug, security, priority:low
**Description:**
### Summary
The EncryptedField component derives `encryptedValue` directly from backend-provided database parameters. While a useEffect on mount calls onParametersChange to clear the field, React renders synchronously before effects execute, meaning the first render will display whatever the backend returned. If the backend returns unmasked service account credentials, they briefly appear in the DOM.

### Details
**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS Sections:** 13.3.1  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/src/features/databases/DatabaseModal/DatabaseConnectionForm/EncryptedField.tsx`

**Technical Detail:**
```javascript
// Component derives value from backend
const encryptedValue = db.parameters?.[field];

// useEffect clears it, but runs AFTER first render
useEffect(() => {
  if (isEditMode) {
    onParametersChange({ ...db.parameters, [field]: '' });
  }
}, []);
```

**Attack Scenario:**
1. Admin edits database connection
2. Backend returns database parameters including unmasked credentials
3. First React render displays credentials in DOM
4. useEffect clears field on subsequent render
5. Credentials briefly visible in DOM inspector or to screen recording

**Severity Justification (Low):**
- Requires admin access to database edit form
- Brief exposure (single render cycle)
- Depends on backend returning unmasked credentials
- Defense-in-depth issue

### Remediation
Never display existing credential values in edit mode. Initialize to empty string:

```javascript
const encryptedValue = isEditMode 
  ? '' 
  : (db.parameters?.[field] || '');
```

**Backend:** Ensure `mask_password_info()` is applied to all database parameter responses regardless of caller privilege.

### Acceptance Criteria
- [ ] `encryptedValue` initialized to empty string in edit mode
- [ ] No reliance on useEffect for credential masking
- [ ] Test added verifying credentials never appear in DOM during edit
- [ ] Backend verification that `mask_password_info()` is always applied
- [ ] Manual testing with browser DevTools during database edit
- [ ] Security review of all credential-handling components

### References
- File: `superset-frontend/src/features/databases/DatabaseModal/DatabaseConnectionForm/EncryptedField.tsx`

### Priority
**Low** - Requires admin access, brief exposure window, and backend configuration issue. Defense-in-depth improvement.

---
## Issue: FINDING-011 - Object literal used as dictionary with user-influenced keys in `convertFilterModel`
**Labels:** bug, security, priority:low
**Description:**
### Summary
In `convertFilterModel`, an object literal `Record<string, string>` is used as a dictionary with user-influenced keys (column IDs from AG Grid filter state). While `validateColumnName` likely rejects prototype-pollution key names, the protection is indirect. This is a defense-in-depth issue with very low exploitability.

### Details
**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)  
**ASVS Sections:** 15.3.6  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/stateConversion.ts`

**Vulnerable Pattern:**
```javascript
const sqlClauses: Record<string, string> = {};
// User-influenced columnId becomes object key
sqlClauses[columnId] = whereClause;
```

**Theoretical Attack:**
If `validateColumnName` fails to reject keys like `__proto__`, `constructor`, or `prototype`, an attacker could potentially pollute the object prototype chain.

**Severity Justification (Low):**
- `validateColumnName` likely provides protection
- No evidence of direct exploitability
- Modern JavaScript engines have prototype pollution mitigations
- Defense-in-depth improvement only

### Remediation
Use `Object.create(null)` for dictionaries with user-influenced keys:

```javascript
const sqlClauses: Record<string, string> = Object.create(null);
```

**Alternative:** Use `Map<string, string>` instead of object literal:

```javascript
const sqlClauses = new Map<string, string>();
sqlClauses.set(columnId, whereClause);
```

### Acceptance Criteria
- [ ] `Object.create(null)` used for `sqlClauses` dictionary
- [ ] OR `Map<string, string>` used instead of object literal
- [ ] Test added with `__proto__` key to verify no prototype pollution
- [ ] Test added with `constructor` key to verify no prototype pollution
- [ ] Review other user-influenced dictionary patterns in codebase

### References
- File: `superset-frontend/plugins/plugin-chart-ag-grid-table/src/stateConversion.ts`

### Priority
**Low** - Defense-in-depth improvement. Existing `validateColumnName` likely provides protection. Very low exploitability.

---
## Issue: FINDING-012 - Request Parameter Override Potential in URL Construction
**Labels:** bug, security, priority:low
**Description:**
### Summary
In `getExploreUrl`, caller-supplied `requestParams` can overwrite previously set security-relevant parameters (`form_data`, `force`, `standalone`) in the URL search object. Impact is bounded to the user's own session since this constructs a client-side request. No direct user-to-requestParams path is visible but the pattern permits it.

### Details
**CWE:** CWE-235 (Improper Handling of Extra Parameters)  
**ASVS Sections:** 15.3.7  
**ASVS Levels:** L2

**Affected Component:**
- File: `superset-frontend/src/explore/exploreUtils/index.ts`

**Vulnerable Pattern:**
```javascript
const url = new URL(...);
url.search.set('form_data', ...);
url.search.set('force', ...);
url.search.set('standalone', ...);

// Caller-supplied params can overwrite above
Object.entries(requestParams).forEach(([key, value]) => {
  url.search.set(key, value);
});
```

**Potential Issue:**
If caller supplies `requestParams = { force: 'false', standalone: '3' }`, security-relevant parameters are overwritten.

**Severity Justification (Low):**
- Impact limited to user's own session (client-side URL construction)
- No direct path from user input to requestParams visible
- Theoretical architectural concern
- Defense-in-depth improvement

### Remediation
Add parameter precedence validation with reserved parameters set:

```javascript
const RESERVED_PARAMS = new Set(['form_data', 'force', 'standalone']);

Object.entries(requestParams).forEach(([key, value]) => {
  if (RESERVED_PARAMS.has(key)) {
    console.warn(`Ignoring attempt to override reserved parameter: ${key}`);
    return;
  }
  url.search.set(key, value);
});
```

### Acceptance Criteria
- [ ] `RESERVED_PARAMS` set defined with security-relevant parameters
- [ ] Caller-supplied params cannot override reserved parameters
- [ ] Warning logged when override attempt detected
- [ ] Test added verifying reserved params cannot be overridden
- [ ] Test added verifying non-reserved params can be set
- [ ] Review all callers of `getExploreUrl` for requestParams usage

### References
- File: `superset-frontend/src/explore/exploreUtils/index.ts`

### Priority
**Low** - Theoretical architectural concern with no visible exploit path. Impact limited to user's own session. Defense-in-depth improvement.