# Security Issues

---
## Issue: FINDING-001 - No format validation on dashboard `id` parameter before URL interpolation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `id` parameter is interpolated directly into the iframe URL without any format validation. While TypeScript enforces it's a `string`, there's no runtime check for expected format (e.g., UUID pattern, alphanumeric only, length limits). If a host application dynamically sets `id` based on user input (e.g., from a URL parameter or database), path manipulation characters could alter the target URL.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected File:** `superset-embedded-sdk/src/index.ts`
- **Severity:** Low

The lack of format validation on the dashboard `id` parameter creates a potential attack vector where malicious input could manipulate the target URL construction. While the immediate risk is low given typical usage patterns, defense-in-depth principles require input validation at all trust boundaries.

### Remediation
Validate `id` format before use with a regex pattern (e.g., `/^[a-f0-9-]+$/i`) and throw an error for invalid formats. This ensures only expected dashboard identifier formats are accepted.

```typescript
function validateDashboardId(id: string): void {
  if (!/^[a-f0-9-]+$/i.test(id)) {
    throw new Error('Invalid dashboard id format');
  }
}
```

### Acceptance Criteria
- [ ] Fixed: Dashboard `id` parameter validated against expected format pattern
- [ ] Test added: Unit tests for valid and invalid `id` formats
- [ ] Test added: Integration test verifying rejection of malformed IDs
- [ ] Documentation updated with expected `id` format requirements

### References
- Related: FINDING-002, FINDING-003
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- ASVS 2.2.1

### Priority
**Low** - While this represents a potential security gap, exploitation requires specific conditions in the host application. Should be addressed as part of general input validation hardening.

---
## Issue: FINDING-002 - No safe-list validation on `iframeSandboxExtras` parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `iframeSandboxExtras` parameter accepts arbitrary strings without validation against a safe-list of sandbox tokens. Dangerous tokens like `allow-top-navigation` could be added, allowing the embedded iframe to navigate the parent page.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected File:** `superset-embedded-sdk/src/index.ts`
- **Severity:** Low

The iframe sandbox attribute is a critical security control that restricts capabilities of embedded content. Allowing arbitrary sandbox tokens without validation could enable developers to inadvertently weaken security by adding dangerous permissions like `allow-top-navigation`, `allow-modals`, or `allow-popups` without understanding the security implications.

### Remediation
Validate `iframeSandboxExtras` against an allow-list or at minimum warn when dangerous values like `allow-top-navigation` are used.

```typescript
const DANGEROUS_SANDBOX_TOKENS = ['allow-top-navigation', 'allow-top-navigation-by-user-activation'];
const ALLOWED_SANDBOX_TOKENS = ['allow-forms', 'allow-popups', 'allow-popups-to-escape-sandbox', 'allow-same-origin', 'allow-scripts'];

function validateSandboxExtras(extras: string[]): void {
  const dangerous = extras.filter(token => DANGEROUS_SANDBOX_TOKENS.includes(token));
  if (dangerous.length > 0) {
    console.warn(`Dangerous sandbox tokens detected: ${dangerous.join(', ')}`);
  }
}
```

### Acceptance Criteria
- [ ] Fixed: Validation logic implemented for `iframeSandboxExtras` parameter
- [ ] Test added: Unit tests for allowed and dangerous sandbox tokens
- [ ] Test added: Warning mechanism verified for dangerous tokens
- [ ] Documentation updated with security guidance on sandbox configuration

### References
- Related: FINDING-001, FINDING-003
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- ASVS 2.2.1
- MDN iframe sandbox: https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#attr-sandbox

### Priority
**Low** - Requires developer misconfiguration to create risk. However, providing guardrails prevents accidental security weakening.

---
## Issue: FINDING-003 - No URL format validation on `supersetDomain` parameter
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `supersetDomain` parameter only receives trailing-slash removal. No validation checks that it is a valid URL with a proper protocol (https), no path components, and no embedded credentials. Since this value is used as the `targetOrigin` in `postMessage`, an incorrectly formatted domain could weaken origin validation.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.1 (Level L1)
- **Affected File:** `superset-embedded-sdk/src/index.ts`
- **Severity:** Low

The `supersetDomain` parameter is critical for `postMessage` origin validation. Without proper URL validation, malformed inputs could bypass security checks or create unexpected behavior. For example, URLs with paths, credentials, or non-HTTPS protocols should be rejected to ensure secure communication.

### Remediation
Validate `supersetDomain` using `new URL()` to ensure it has a valid protocol, no path, and return `url.origin` for use in postMessage targetOrigin.

```typescript
function validateSupersetDomain(domain: string): string {
  try {
    const url = new URL(domain);
    
    if (url.protocol !== 'https:' && url.hostname !== 'localhost') {
      throw new Error('supersetDomain must use HTTPS protocol');
    }
    
    if (url.pathname !== '/' || url.search || url.hash) {
      throw new Error('supersetDomain must not contain path, query, or hash components');
    }
    
    return url.origin;
  } catch (error) {
    throw new Error(`Invalid supersetDomain format: ${error.message}`);
  }
}
```

### Acceptance Criteria
- [ ] Fixed: URL validation implemented for `supersetDomain` parameter
- [ ] Test added: Unit tests for valid and invalid URL formats
- [ ] Test added: Protocol validation (HTTPS enforcement except localhost)
- [ ] Test added: Path/query/hash component rejection
- [ ] Documentation updated with `supersetDomain` format requirements

### References
- Related: FINDING-001, FINDING-002
- CWE-20: https://cwe.mitre.org/data/definitions/20.html
- ASVS 2.2.1
- MDN postMessage: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage

### Priority
**Low** - Most significant for postMessage security. Should be prioritized alongside other input validation improvements to ensure secure cross-origin communication.