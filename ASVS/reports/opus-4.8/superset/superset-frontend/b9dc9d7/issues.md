# Security Issues

*12 actionable finding(s). 3 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---
## Issue: FINDING-001 - Missing Session Regeneration on Authentication
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not generate a new session token upon user authentication or re-authentication, creating a risk of session fixation attacks where an attacker can pre-set a session identifier and hijack the user's authenticated session.

### Details
- **CWE:** CWE-384 (Session Fixation)
- **ASVS:** 7.2.4 (L1, L2, L3)
- **Severity:** High

The application violates ASVS 7.2.4 requirements by failing to terminate the current session token and generate a new one during authentication events. This allows an attacker to potentially fix a session identifier before authentication and then hijack the authenticated session once the victim logs in.

### Remediation
Implement session regeneration logic that:
- Generates a new session token immediately after successful authentication and re-authentication
- Invalidates the previous session token to prevent reuse
- Applies to all authentication paths including login, password reset, and account recovery flows

### Acceptance Criteria
- [ ] Fixed - New session token generated on all authentication events
- [ ] Test added - Verify old session tokens are invalidated after authentication
- [ ] Test added - Verify session regeneration occurs on password reset
- [ ] Test added - Verify session regeneration occurs on account recovery

### References
- Source Report: 7.2.4.md

### Priority
High

---
## Issue: FINDING-002 - Incomplete Session Invalidation on Termination
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not properly invalidate sessions when termination is triggered (logout or expiration), allowing continued use of terminated session tokens to access protected resources.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.4.1 (L1, L2, L3)
- **Severity:** High
- **Related Findings:** FINDING-003, FINDING-004, FINDING-005, FINDING-006

The application violates ASVS 7.4.1 requirements by failing to properly invalidate session data at the backend when sessions are terminated through logout, timeout, or expiration events.

### Remediation
Ensure that all session termination events properly invalidate session data:
- For reference tokens or stateful sessions: Remove or mark the session as invalid in the session store
- For self-contained tokens (JWT): Implement token revocation mechanisms such as a denylist or short expiration times combined with refresh token rotation
- Verify that terminated sessions cannot be reused for any application functionality

### Acceptance Criteria
- [ ] Fixed - Sessions invalidated on logout
- [ ] Fixed - Sessions invalidated on timeout
- [ ] Fixed - Sessions invalidated on expiration
- [ ] Test added - Verify terminated sessions cannot access protected resources
- [ ] Test added - Verify JWT revocation mechanism (if applicable)

### References
- Source Report: 7.4.1.md

### Priority
High

---
## Issue: FINDING-003 - Sessions Not Terminated on Account Disable or Deletion
**Labels:** bug, security, priority:high
**Description:**
### Summary
The application does not terminate all active sessions when a user account is disabled or deleted, allowing disabled or deleted accounts to continue accessing the application through existing active sessions until they naturally expire.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.4.2 (L1, L2, L3)
- **Severity:** High
- **Related Findings:** FINDING-002, FINDING-004, FINDING-005, FINDING-006

This violates ASVS 7.4.2 requirements and creates a security risk during employee offboarding, account suspension, and account deletion processes.

### Remediation
Implement automatic session termination logic that:
- Is triggered when user accounts are disabled or deleted
- Invalidates all active sessions associated with the account immediately
- Integrates with user management workflows (employee offboarding, account suspension, account deletion)
- Maintains a mapping of user accounts to active sessions to enable bulk termination

### Acceptance Criteria
- [ ] Fixed - All sessions terminated on account disable
- [ ] Fixed - All sessions terminated on account deletion
- [ ] Test added - Verify disabled account sessions are invalidated
- [ ] Test added - Verify deleted account sessions are invalidated
- [ ] Test added - Verify session-to-account mapping functionality

### References
- Source Report: 7.4.2.md

### Priority
High

---
## Issue: FINDING-004 - Missing Inactivity Timeout Enforcement
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not enforce an inactivity timeout that would require re-authentication after a period of user inactivity, allowing sessions to remain active indefinitely without user interaction.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.3.1 (L2, L3)
- **Severity:** Medium
- **Related Findings:** FINDING-002, FINDING-003, FINDING-005, FINDING-006

This violates ASVS 7.3.1 requirements and increases the window of opportunity for session hijacking or unauthorized access from unattended devices.

### Remediation
Implement an inactivity timeout mechanism:
- Track the last activity timestamp for each session
- Invalidate sessions that exceed the defined inactivity period
- Configure appropriate timeout values based on application sensitivity (e.g., 15-30 minutes for sensitive applications)
- Provide clear user notification before timeout occurs
- Base timeout values on documented risk analysis

### Acceptance Criteria
- [ ] Fixed - Inactivity timeout mechanism implemented
- [ ] Fixed - User notification before timeout
- [ ] Test added - Verify sessions expire after inactivity period
- [ ] Documentation - Risk analysis for timeout values documented

### References
- Source Report: 7.3.1.md

### Priority
Medium

---
## Issue: FINDING-005 - Missing Absolute Maximum Session Lifetime
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not enforce an absolute maximum session lifetime that would require re-authentication regardless of activity, allowing sessions to persist indefinitely as long as they remain active.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.3.2 (L2, L3)
- **Severity:** Medium
- **Related Findings:** FINDING-002, FINDING-003, FINDING-004, FINDING-006

This violates ASVS 7.3.2 requirements and may not align with security policies requiring periodic re-authentication.

### Remediation
Implement an absolute maximum session lifetime:
- Track session creation timestamp
- Invalidate sessions that exceed the maximum lifetime (e.g., 8-24 hours depending on risk profile)
- Enforce re-authentication after the defined period regardless of activity
- Document the chosen lifetime based on risk analysis and compliance requirements

### Acceptance Criteria
- [ ] Fixed - Absolute maximum session lifetime enforced
- [ ] Test added - Verify sessions expire after maximum lifetime
- [ ] Test added - Verify re-authentication required after expiration
- [ ] Documentation - Maximum lifetime values documented with risk justification

### References
- Source Report: 7.3.2.md

### Priority
Medium

---
## Issue: FINDING-006 - Missing Option to Terminate Other Sessions After Authentication Factor Change
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The application does not provide users with the option to terminate all other active sessions after successfully changing or removing authentication factors (password, MFA settings, etc.), preventing users from invalidating potentially compromised sessions.

### Details
- **CWE:** CWE-613 (Insufficient Session Expiration)
- **ASVS:** 7.4.3 (L2, L3)
- **Severity:** Medium
- **Related Findings:** FINDING-002, FINDING-003, FINDING-004, FINDING-005

This violates ASVS 7.4.3 requirements by not allowing users to secure their account after credential changes.

### Remediation
Implement functionality that offers users the option to terminate all other active sessions after changing authentication factors:
- Password changes
- Password resets
- MFA configuration updates
- Recovery method modifications

Present this as a checkbox during the change process or as a prompt after successful changes. Consider making this automatic for high-risk changes like password reset via recovery.

### Acceptance Criteria
- [ ] Fixed - Option to terminate other sessions on password change
- [ ] Fixed - Option to terminate other sessions on MFA change
- [ ] Test added - Verify session termination functionality
- [ ] UX - User interface for session termination option implemented

### References
- Source Report: 7.4.3.md

### Priority
Medium

---
## Issue: FINDING-007 - `SafeMarkdown` disables react-markdown link sanitization
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `SafeMarkdown` component disables react-markdown's built-in link sanitization (`transformLinkUri={null}`), relying solely on optional rehype-sanitize, which can enable javascript:-scheme links/XSS when sanitization is disabled.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.2.2 (L1)
- **Severity:** Low
- **Related Findings:** FINDING-008
- **Affected Files:**
  - `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`

Data flow: markdown source → react-markdown link/HTML pipeline → DOM. Setting `transformLinkUri={null}` removes react-markdown's built-in javascript:/data: URL stripping. Protocol filtering then depends ONLY on rehypeSanitize, which is conditionally applied. In default configuration (htmlSanitization = true), no exploit path exists; exploitation requires opting out of sanitization.

### Remediation
Do not disable the built-in URI transform unconditionally:
- Retain react-markdown's default `transformLinkUri` 
- OR supply an explicit allowlisting transform via @braintree/sanitize-url
- Ensure link-protocol safety does not depend solely on the optional rehypeSanitize plugin

### Acceptance Criteria
- [ ] Fixed - URI transform re-enabled or explicit allowlist implemented
- [ ] Test added - Verify javascript: URLs are blocked
- [ ] Test added - Verify data: URLs are blocked
- [ ] Test added - Verify behavior with htmlSanitization=false

### References
- Source Report: 1.2.2.md

### Priority
Low

---
## Issue: FINDING-008 - `getOverrideHtmlSchema` mutates shared rehype-sanitize default schema
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `getOverrideHtmlSchema` function mutates the shared `rehype-sanitize` default schema object in place, causing any SafeMarkdown instance that passes overrides to permanently widen the allowlist for all other instances.

### Details
- **CWE:** CWE-79 (Cross-site Scripting)
- **ASVS:** 1.3.1 (L1)
- **Severity:** Low
- **Related Findings:** FINDING-007
- **Affected Files:**
  - `superset-frontend/packages/superset-ui-core/src/components/SafeMarkdown/SafeMarkdown.tsx`

`lodash.mergeWith` mutates its first argument. Because `defaultSchema` is a shared module singleton, overrides from one component affect all subsequent SafeMarkdown renders. Not directly attacker-reachable (htmlSchemaOverrides is supplied by application code), but creates a latent sanitization-integrity bug increasing stored-XSS surface.

### Remediation
Treat the base schema as immutable:
- Deep-clone the schema before merging: `cloneDeep(originalSchema)` before `mergeWith`
- Ensure each SafeMarkdown instance operates on an independent schema copy

### Acceptance Criteria
- [ ] Fixed - Schema deep-cloned before merge
- [ ] Test added - Verify schema mutations don't affect other instances
- [ ] Test added - Verify override isolation between components

### References
- Source Report: 1.3.1.md

### Priority
Low

---
## Issue: FINDING-009 - postMessage origin validation defaults to permissive when allowed_domains is unset
**Labels:** bug, security, priority:low
**Description:**
### Summary
The embedded dashboard's postMessage origin validation accepts any origin when `allowed_domains` is unset, creating a permissive-default configuration that may accept messages from unintended origins.

### Details
- **CWE:** CWE-346 (Origin Validation Error)
- **ASVS:** 3.5.1 (L1)
- **Severity:** Low
- **Affected Files:**
  - `superset-frontend/src/embedded/originValidation.ts`
  - `superset-frontend/src/embedded/index.tsx`

When `allowed_domains` is empty/undefined, the origin check is skipped and the handshake proceeds. Impact is limited: the embedded page still requires a valid host-issued guest token before rendering data, so an attacker cannot cause data exposure without a token. Realistic impact is confined to accepting benign UI-control messages from unintended origins.

### Remediation
Treat an empty/undefined allowlist as fail-closed for production embeds:
- Reject postMessage events when `allowed_domains` is not configured
- OR require operators to explicitly opt into unrestricted mode behind a named configuration flag
- Make the secure posture the default

### Acceptance Criteria
- [ ] Fixed - Empty allowlist treated as fail-closed
- [ ] Test added - Verify messages rejected when allowed_domains unset
- [ ] Test added - Verify explicit opt-in flag functionality
- [ ] Documentation - Configuration requirements documented

### References
- Source Report: 3.5.1.md

### Priority
Low

---
## Issue: FINDING-010 - Automatic redirect relies on client-side trust list without server-side validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The automatic redirect functionality relies entirely on client-side trust decisions (localStorage) without server-maintained or configured destination-host allowlist validation.

### Details
- **CWE:** CWE-601 (URL Redirection to Untrusted Site)
- **ASVS:** 3.7.2 (L2)
- **Severity:** Low
- **Affected Files:**
  - `superset-frontend/src/pages/RedirectWarning/index.tsx`
  - `superset-frontend/src/pages/RedirectWarning/utils.ts`

Data flow: `?url=` query param → `getTargetUrl()` → `useEffect` → automatic `window.location.href` assignment when URL is in client-side `superset_trusted_urls`. The trust decision is entirely client-side with no server allowlist. The automatic path only fires for previously-trusted destinations and scheme is gated to http:/https:. Abuse requires same-origin XSS or social engineering.

### Remediation
Pair the client-side trust mechanism with a server-side or configured allowlist:
- Add server-side configuration (e.g., `REDIRECT_ALLOWED_HOSTS`)
- Ensure automatic redirects only proceed when destination host is on the server allowlist
- Make validation independent of client-side localStorage

### Acceptance Criteria
- [ ] Fixed - Server-side allowlist configuration added
- [ ] Fixed - Automatic redirects validated against server allowlist
- [ ] Test added - Verify redirects blocked for non-allowlisted hosts
- [ ] Test added - Verify client-side trust doesn't bypass server validation

### References
- Source Report: 3.7.2.md

### Priority
Low

---
## Issue: FINDING-011 - Client-side log timestamps taken from unsynchronized browser clock
**Labels:** bug, security, priority:low
**Description:**
### Summary
Client-side log timestamps are generated from the browser's unsynchronized clock (Date.now()), which can be skewed or altered by users, potentially causing timeline confusion in logs.

### Details
- **ASVS:** 16.2.2 (L2)
- **Severity:** Low
- **Affected Files:**
  - `superset-frontend/src/middleware/loggerMiddleware.ts`

Browser Date.now() → ts field → shipped to /superset/log/. The value originates from a client clock the server doesn't control. An authenticated user can set their device clock arbitrarily, causing incorrect timestamps. Impact is low if the backend records its own server-side receipt timestamp and treats client ts as advisory.

### Remediation
Ensure the backend /superset/log/ handler:
- Stamps an authoritative server-side UTC `received_at` timestamp
- Uses server timestamp (not client ts) as the canonical event time for ordering/correlation
- Retains client ts only as supplementary data
- No client-code change strictly required

### Acceptance Criteria
- [ ] Fixed - Backend stamps server-side timestamp
- [ ] Fixed - Server timestamp used for event ordering
- [ ] Test added - Verify server timestamp takes precedence
- [ ] Documentation - Timestamp handling documented

### References
- Source Report: 16.2.2.md

### Priority
Low

---
## Issue: FINDING-012 - Logger middleware forwards full URL and payload without client-side redaction
**Labels:** bug, security, priority:low
**Description:**
### Summary
The logger middleware forwards the full page URL and arbitrary event payload to the backend without client-side redaction, relying entirely on server-side log filtering to prevent sensitive data exposure.

### Details
- **ASVS:** 16.2.5 (L2)
- **Severity:** Low
- **Affected Files:**
  - `superset-frontend/src/middleware/loggerMiddleware.ts`

window.location.href / caller-supplied eventData → batched event → /superset/log/. The client performs no masking of URL query parameters or spread fields before transmission. Risk materializes only if URL/eventData carries sensitive content AND backend log filter is not configured to redact it. Current Superset URL content is documented as non-secret.

### Remediation
- Treat the client logger as untrusted input on the backend
- Apply allow-list field projection plus credential/token redaction in /superset/log/ handler
- Optionally strip query strings from path client-side when events don't require them
- Ensure backend never persists guest_token form field into event store

### Acceptance Criteria
- [ ] Fixed - Backend applies allow-list field projection
- [ ] Fixed - Backend redacts credentials/tokens
- [ ] Fixed - guest_token not persisted in event store
- [ ] Test added - Verify sensitive fields are redacted
- [ ] Documentation - Logging security configuration documented

### References
- Source Report: 16.2.5.md

### Priority
Low