# Security Issues

*3 actionable finding(s). 2 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Unsanitized data interpolated into Datamaps popup HTML in WorldMap chart

**Labels:** bug, security, priority:high

**Description:**

### Summary
The WorldMap chart plugin renders hover tooltips by directly interpolating dataset values into HTML without sanitization, creating a stored XSS vulnerability. Unlike sibling nvd3 charts that sanitize all tooltip content through DOMPurify, the WorldMap popupTemplate functions inject user-controlled dimension values directly into the DOM.

### Details
**Location:** `superset-frontend/plugins/legacy-plugin-chart-world-map/src/WorldMap.ts`

**Data Flow:**
1. Query result row → `mapData[country].name` (d.name)
2. String interpolation into HTML template: `` `&lt;div class="hoverinfo"&gt;&lt;strong&gt;${d.name}&lt;/strong&gt;...` ``
3. Datamaps renders the returned string as innerHTML for hover tooltip
4. No sanitization applied at the encoding boundary

**Attack Vector:**
- Authenticated user with dataset/column editing capability injects markup into dimension values (e.g., `<img src=x onerror=alert(document.cookie)>`)
- Payload executes in browsers of all users who hover over the affected chart
- Enables session/credential theft, CSRF-token exfiltration, and actions-on-behalf

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**ASVS:** 1.3.1 (L1)

### Remediation
Import and apply `sanitizeHtml` from `@superset-ui/core` to all interpolated content in popup templates, mirroring the pattern used in `legacy-preset-chart-nvd3/src/utils.ts`:

```typescript
import { sanitizeHtml } from '@superset-ui/core';

// In geographyConfig:
popupTemplate: (geo, d) => 
  d && sanitizeHtml(`<div class="hoverinfo"><strong>${d.name}</strong><br>${formatter(d.m1)}</div>`)

// In bubblesConfig:
popupTemplate: (geo, d) => 
  d && sanitizeHtml(`<div class="hoverinfo"><strong>${d.name}</strong><br>${formatter(d.m1)}</div>`)
```

Sanitizing the entire template string (not just `d.name`) provides defense-in-depth against future template modifications.

### Acceptance Criteria
- [ ] All `popupTemplate` functions in WorldMap.ts sanitize interpolated content using `sanitizeHtml`
- [ ] Manual test confirms XSS payloads in dimension values are neutralized in hover tooltips
- [ ] Automated test added verifying sanitization of malicious markup in popup templates
- [ ] Code review confirms consistency with nvd3 tooltip sanitization patterns

### References
- Related findings: FINDING-003, FINDING-005
- Source: 1.3.1.md
- nvd3 sanitization reference: `legacy-preset-chart-nvd3/src/utils.ts` (wrapTooltip function)

### Priority
**High** - Stored XSS exploitable by authenticated users, affecting all chart viewers. Meets L1 baseline security requirements.

---
## Issue: FINDING-002 - postMessage origin validation fails open when allowedDomains is empty/undefined

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The embedded dashboard's postMessage origin validation defaults to allow-all when the `allowedDomains` configuration is empty or undefined, creating a fail-open security control. This allows untrusted origins to establish the embedded-comms control channel when operators deploy embeds without explicit allow-list configuration.

### Details
**Location:** `superset-frontend/src/embedded/originValidation.ts`

**Data Flow:**
1. `event.origin` (attacker-controlled via embedding page) → `validateMessageEvent`
2. → `isMessageOriginAllowed` 
3. → Returns `true` when `allowedDomains` is empty/undefined
4. → `__embedded_comms__` handshake accepted from any origin

**Attack Vector:**
- Attacker embeds Superset dashboard/chart iframe in malicious page
- Posts structurally valid handshake message from untrusted origin
- Establishes control channel despite no explicit trust relationship

**Impact:**
Defense-in-depth control bypass. While backend guest-token authentication and RLS/field-level controls still gate data access, the fail-open default provides zero origin protection in misconfigured deployments. Rated Medium because exploitation requires operator misconfiguration and data path remains backend-protected.

**CWE:** CWE-346 (Origin Validation Error)  
**ASVS:** 3.5.1 (L1), 3.5.5 (L2)

### Remediation
Implement fail-closed defaults:

1. **Deny by default:** Reject postMessage communication when `allowedDomains` is empty/undefined
2. **Explicit opt-out:** Require clearly-named flag to enable unrestricted mode:
   ```typescript
   interface EmbedConfig {
     allowedDomains?: string[];
     allowUnrestrictedOrigins?: boolean; // Explicit, defaults to false
   }
   
   function isMessageOriginAllowed(origin: string, config: EmbedConfig): boolean {
     if (config.allowUnrestrictedOrigins === true) {
       console.warn('SECURITY: Unrestricted postMessage origins enabled');
       return true;
     }
     if (!config.allowedDomains?.length) {
       return false; // Fail closed
     }
     return config.allowedDomains.some(domain => origin.endsWith(domain));
   }
   ```
3. **Documentation:** Prominently document security implications of unrestricted mode in embedding guides

### Acceptance Criteria
- [ ] Origin validation rejects messages when `allowedDomains` is empty/undefined (no explicit allow-list)
- [ ] Unrestricted mode requires explicit `allowUnrestrictedOrigins: true` flag
- [ ] Console warning logged when unrestricted mode is enabled
- [ ] Test added verifying fail-closed behavior with empty configuration
- [ ] Test added verifying unrestricted mode requires explicit flag
- [ ] Embedding documentation updated with security guidance

### References
- Source: 3.5.1.md, 3.5.5.md
- Merged from: ASVS-351-LOW-001, ASVS-355-MED-001

### Priority
**Medium** - Defense-in-depth control bypass requiring misconfiguration. Backend controls remain effective but origin validation should fail-secure by default.

---
## Issue: FINDING-003 - SafeMarkdown disables react-markdown's built-in link-URI sanitization when EscapeMarkdownHtml flag is enabled

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The SafeMarkdown component creates a security regression when the `EscapeMarkdownHtml` feature flag is enabled. Setting `transformLinkUri={null}` disables react-markdown's built-in link sanitization, and the flag configuration removes the rehype-sanitize plugin that would otherwise strip dangerous URI schemes, allowing `javascript:` URIs in markdown links to render unsanitized.

### Details
**Location:** `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`

**Data Flow:**
1. Markdown source with link: `[click me](javascript:alert(1))`
2. react-markdown converts to `<a href>` node
3. With `transformLinkUri={null}`, react-markdown skips URI sanitization
4. When `escapeHtml === true` (EscapeMarkdownHtml flag enabled), `rehypePlugins` is empty
5. No rehype-sanitize runs → dangerous href remains intact
6. Clickable link with `javascript:` URI rendered in DOM

**Default Configuration (Safe):**
- `escapeHtml === false` → rehype-sanitize runs with `defaultSchema`
- `protocols.href` allowlist strips `javascript:`/`data:` URIs

**Regression Scenario (Unsafe):**
- EscapeMarkdownHtml flag enabled → rehype-sanitize disabled → `javascript:` URIs preserved
- Creates foot-gun where hardening flag removes sanitization layer

**Attack Vector:**
- Authenticated user with markdown editing capability (dashboard components, Handlebars templates)
- Deployment with non-default EscapeMarkdownHtml flag enabled
- User-interaction required (click on malicious link)

**Impact:** Reflected/stored DOM XSS via `javascript:` link execution

**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**ASVS:** 1.3.5 (L2)

### Remediation
Provide explicit link URI sanitization independent of the `escapeHtml`/rehype-sanitize code path:

```typescript
import { sanitizeUrl } from '@braintree/sanitize-url';

<ReactMarkdown
  {...otherProps}
  transformLinkUri={uri => sanitizeUrl(uri)}
  rehypePlugins={escapeHtml ? [] : [rehypeRaw, [rehypeSanitize, htmlSanitizationSchema]]}
>
  {source}
</ReactMarkdown>
```

This ensures link URIs are sanitized in all feature-flag combinations rather than relying on rehype-sanitize presence.

**Alternative:** Implement allowlist-based URI scheme validation:
```typescript
const SAFE_URI_SCHEMES = ['http:', 'https:', 'mailto:', 'tel:'];

transformLinkUri={uri => {
  try {
    const url = new URL(uri, window.location.href);
    return SAFE_URI_SCHEMES.includes(url.protocol) ? uri : '#';
  } catch {
    return uri.startsWith('/') || uri.startsWith('#') ? uri : '#';
  }
}}
```

### Acceptance Criteria
- [ ] Link URI sanitization applied independent of `escapeHtml` flag state
- [ ] Test added verifying `javascript:` URIs are neutralized with EscapeMarkdownHtml enabled
- [ ] Test added verifying `data:` URIs are neutralized with EscapeMarkdownHtml enabled
- [ ] Test added verifying legitimate URIs (`http:`, `https:`, `mailto:`) remain functional
- [ ] Manual test confirms XSS payloads in markdown links are neutralized in both flag states
- [ ] Code review confirms sanitization runs in all rehype-plugin configurations

### References
- Related findings: FINDING-001, FINDING-005
- Source: 1.3.5.md
- Merged from: ASVS-135-LOW-001

### Priority
**Medium** - XSS requiring non-default configuration and user interaction. Defense-in-depth issue where hardening flag creates security regression.