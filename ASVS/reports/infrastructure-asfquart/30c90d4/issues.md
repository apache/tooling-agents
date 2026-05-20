# Security Issues

---
## Issue: FINDING-001 - No rate limiting or brute force protection on HTTP Basic Authentication endpoint
**Labels:** bug, security, priority:high
**Description:**
### Summary
No rate limiting or brute force protection exists on the HTTP Basic Authentication endpoint. Each request triggers an LDAP bind attempt with no failed attempt counter, account lockout mechanism, progressive delay, IP-based rate limiting, or CAPTCHA.

### Details
Attackers can perform credential stuffing or brute-force password guessing against any ASF user account without throttling. This lack of implementation and documentation violates both 6.1.1 (documentation requirement) and 6.3.1 (implementation requirement).

**CWE:** CWE-307  
**ASVS Sections:** 6.1.1, 6.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/session.py` (lines 60-84)

### Remediation
Implement rate limiting at the application level with per-IP and per-username tracking (e.g., cap at 5 attempts per 5-minute window before returning HTTP 429). Use quart-rate-limiter or similar. Document rate limit thresholds, lockout prevention strategy, and adaptive response escalation policy in security documentation.

### Acceptance Criteria
- [ ] Rate limiting implemented with per-IP tracking
- [ ] Rate limiting implemented with per-username tracking
- [ ] HTTP 429 returned after threshold exceeded
- [ ] Rate limit thresholds documented in security documentation
- [ ] Test added for rate limiting behavior
- [ ] Test added for lockout prevention

### References
- Related: FINDING-017
- Source reports: 6.1.1.md, 6.3.1.md

### Priority
High

---
## Issue: FINDING-002 - Self-contained session tokens (signed cookies) have no server-side revocation mechanism
**Labels:** bug, security, priority:high
**Description:**
### Summary
When session.clear() is called on logout, only the current request context is cleared and the browser is instructed to delete the cookie. There is no server-side revocation list or per-user timestamp check. If an attacker captures a valid session cookie before logout, it remains cryptographically valid until natural expiry (default: 7 days).

### Details
The codebase contains no functionality to:
- Enumerate active sessions for a specific user
- Invalidate all sessions belonging to a specific user
- Maintain a per-user invalidated-after timestamp
- Check against an external user status during session validation

Session data from the cookie is trusted as-is until expiry. Disabled or deleted user accounts retain access for up to 7 days by default.

**CWE:** CWE-613  
**ASVS Sections:** 7.4.1, 7.4.2 (Level 1)  
**Affected Files:**
- `src/asfquart/session.py`
- `src/asfquart/generics.py`
- `src/asfquart/auth.py`

### Remediation
Implement a server-side revocation registry with per-user invalidation timestamps checked on every session.read() call. Provide an invalidate_all_user_sessions(uid) API. Add periodic user status validation (e.g., every 5 minutes) against LDAP/directory. Consider reducing default session expiry from 7 days.

### Acceptance Criteria
- [ ] Server-side revocation registry implemented
- [ ] Per-user invalidation timestamps tracked
- [ ] Session validation checks revocation status
- [ ] invalidate_all_user_sessions(uid) API provided
- [ ] Periodic user status validation implemented
- [ ] Test added for revocation functionality
- [ ] Test added for disabled user account handling

### References
- Related: FINDING-019
- Source reports: 7.4.1.md, 7.4.2.md

### Priority
High

---
## Issue: FINDING-003 - Unescaped OAuth UID in HTTP response body (redirect path)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `oauth_data['uid']` value is sourced from the ASF OAuth provider's JSON response and inserted directly into the response body without output encoding. While `content_type="text/plain"` mitigates XSS risk in modern browsers, no `X-Content-Type-Options: nosniff` header is set.

### Details
If a reverse proxy or CDN were to override or strip the content type, MIME-sniffing could result in the response being interpreted as HTML, potentially enabling XSS attacks.

**CWE:** CWE-79  
**ASVS Sections:** 1.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
HTML-escape `oauth_data['uid']` and add `X-Content-Type-Options: nosniff` header to all responses.

### Acceptance Criteria
- [ ] OAuth UID HTML-escaped before insertion into response
- [ ] X-Content-Type-Options: nosniff header added
- [ ] Test added for output encoding
- [ ] Test added for header presence

### References
- Related: FINDING-022
- Source reports: 1.2.1.md

### Priority
Medium

---
## Issue: FINDING-004 - OAuth code parameter not URL-encoded before URL construction
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The OAuth authorization `code` parameter from the query string is interpolated into the token exchange URL via `%s` formatting without URL-encoding or format validation.

### Details
While state verification significantly limits exploitability (attacker must have a valid pending state), the code value is not validated against an expected pattern (e.g., alphanumeric, specific length) before being used in a server-side HTTP request. A malicious code containing `&` characters could inject additional query parameters into the token exchange request (HTTP parameter pollution).

**CWE:** CWE-74  
**ASVS Sections:** 1.2.2, 2.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Validate code format (OAuth codes are typically alphanumeric) and URL-encode the code parameter before interpolation into the token exchange URL.

### Acceptance Criteria
- [ ] OAuth code format validated (alphanumeric pattern)
- [ ] Code parameter URL-encoded before use
- [ ] Test added for code validation
- [ ] Test added for URL encoding
- [ ] Test added for parameter pollution prevention

### References
- Source reports: 1.2.2.md, 2.2.1.md

### Priority
Medium

---
## Issue: FINDING-005 - LDAP injection via unvalidated username from HTTP Basic Auth
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `auth_user` value from the HTTP Authorization header is passed directly to `ldap.LDAPClient` without LDAP-specific escaping or validation.

### Details
Based on the code inventory, the LDAP module constructs the bind DN using string interpolation (`uid=%s`). If the username contains LDAP special characters (`,`, `=`, `+`, `<`, `>`, `#`, `;`, `\`, `"`), this could lead to LDAP injection attacks.

**CWE:** CWE-90  
**ASVS Sections:** 1.2.4 (Level 1)  
**Affected Files:**
- `src/asfquart/session.py`

### Remediation
Validate username against a safe pattern (e.g., `^[a-zA-Z][a-zA-Z0-9._-]{0,63}$`) before passing to LDAP client.

### Acceptance Criteria
- [ ] Username validation regex implemented
- [ ] Invalid usernames rejected before LDAP call
- [ ] Test added for username validation
- [ ] Test added for LDAP special character rejection

### References
- Related: FINDING-012
- Source reports: 1.2.4.md

### Priority
Medium

---
## Issue: FINDING-006 - Missing Strict-Transport-Security (HSTS) header
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The framework does not set the `Strict-Transport-Security` (HSTS) header on responses. While session cookies are correctly marked `Secure`, the absence of HSTS creates security gaps.

### Details
Without HSTS:
- First-time visitors could have their initial request intercepted before HTTPS redirect
- No protection against SSL stripping attacks
- Browsers won't automatically upgrade HTTP→HTTPS for subsequent visits

**CWE:** CWE-319  
**ASVS Sections:** 12.2.1, 3.4.1 (Level 1)  
**Affected Files:**
- `src/asfquart/base.py`

### Remediation
In construct() function in src/asfquart/base.py, add after cookie config:
```python
@app.after_request
async def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

### Acceptance Criteria
- [ ] HSTS header added to all responses
- [ ] max-age set to at least 1 year
- [ ] includeSubDomains directive included
- [ ] Test added for header presence
- [ ] Test added for header value

### References
- Related: FINDING-025
- Source reports: 12.2.1.md, 3.4.1.md

### Priority
Medium

---
## Issue: FINDING-007 - No enforcement of TLS when Secure cookies are configured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The framework configures session cookies with `Secure=True` but `runx()` defaults to no TLS and allows HTTP-only serving. There is no validation that any provided certificate is from a publicly trusted CA versus self-signed, and no enforcement that a TLS-terminating proxy is present.

### Details
This creates a configuration mismatch where secure cookies are configured but TLS is not enforced, potentially leading to deployment issues or security misconfigurations.

**CWE:** CWE-295  
**ASVS Sections:** 12.2.2 (Level 1)  
**Affected Files:**
- `src/asfquart/base.py`

### Remediation
Add a require_tls parameter or startup check that raises an error or warning when certfile is not provided in non-debug mode.

### Acceptance Criteria
- [ ] TLS enforcement check implemented
- [ ] Error/warning raised when TLS not configured in production mode
- [ ] Configuration validation added
- [ ] Test added for TLS enforcement
- [ ] Documentation updated

### References
- Source reports: 12.2.2.md

### Priority
Medium

---
## Issue: FINDING-008 - OAuth authorization code sent via GET query string to token endpoint
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The OAuth token exchange sends the authorization code as a URL query parameter via an HTTP GET request. While this is a server-to-server call, the authorization code is sensitive and could be logged in intermediate proxy access logs, server logs, or network monitoring tools.

### Details
Note: This appears to be constrained by the ASF OAuth server's API design (it uses a GET endpoint).

**CWE:** CWE-598  
**ASVS Sections:** 14.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
If upstream supports it, use POST with code in the body instead of GET with code in URL.

### Acceptance Criteria
- [ ] Investigate if ASF OAuth server supports POST
- [ ] If supported, implement POST-based token exchange
- [ ] If not supported, document limitation
- [ ] Test added for implementation

### References
- Source reports: 14.2.1.md

### Priority
Medium

---
## Issue: FINDING-009 - Bearer token logged to stdout in debug message
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When no PAT handler is registered, the bearer token from the Authorization header is printed to stdout in a debug message. This exposes the sensitive token in application logs.

### Details
The debug message includes the full token value, which could be captured in log aggregation systems, log files, or monitoring tools.

**CWE:** CWE-532  
**ASVS Sections:** 14.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/session.py`

### Remediation
Replace `print(f"Debug: No PAT handler registered to handle token {quart.request.authorization.token}")` with a logger call that does not include the token value.

### Acceptance Criteria
- [ ] Debug message modified to exclude token value
- [ ] Proper logging mechanism used instead of print
- [ ] Test added to verify token not logged

### References
- Source reports: 14.2.1.md

### Priority
Medium

---
## Issue: FINDING-010 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The project defines dependency version constraints in pyproject.toml but lacks documentation defining risk-based remediation timeframes for addressing known vulnerabilities in dependencies.

### Details
Missing documentation for:
1. Risk-based remediation timeframes for addressing known vulnerabilities
2. A general policy for updating third-party libraries
3. Classification of components by risk level (critical, high, medium, low)
4. Expected SLAs for patching (e.g., "Critical CVEs in dependencies must be addressed within 72 hours")

**CWE:** CWE-1104  
**ASVS Sections:** 15.1.1 (Level 1)  
**Affected Files:**
- `pyproject.toml`

### Remediation
Create a SECURITY.md or equivalent document defining remediation timeframes by severity (Critical: 48h, High: 7d, Medium: 30d, Low: 90d), a general update policy, and risk classification of components.

### Acceptance Criteria
- [ ] SECURITY.md created with remediation timeframes
- [ ] Risk classification defined for components
- [ ] Update policy documented
- [ ] SLAs defined by severity level

### References
- Related: FINDING-029
- Source reports: 15.1.1.md

### Priority
Medium

---
## Issue: FINDING-011 - Full OAuth response written unfiltered to session cookie
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The entire OAuth provider response is written verbatim to the session cookie via `oauth_data = await rv.json(); asfquart.session.write(oauth_data)`. Quart's default session is a signed cookie that is base64-encoded but not encrypted — meaning the client can read all data.

### Details
The OAuth response may contain fields not intended for client exposure. While ClientSession.__init__ filters fields when reading the session back, the raw session cookie persisted on the client contains ALL OAuth-returned fields.

**CWE:** CWE-200  
**ASVS Sections:** 15.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Filter OAuth data before writing to session using an explicit allowlist:
```python
ALLOWED_SESSION_FIELDS = {"uid", "dn", "fullname", "email", "isMember", "isChair", "isRoot", "pmcs", "projects", "mfa", "roleaccount", "metadata"}
filtered_data = {k: v for k, v in oauth_data.items() if k in ALLOWED_SESSION_FIELDS}
asfquart.session.write(filtered_data)
```

### Acceptance Criteria
- [ ] OAuth data filtered before session write
- [ ] Allowlist of session fields defined
- [ ] Only allowed fields written to cookie
- [ ] Test added for field filtering
- [ ] Test added to verify unexpected fields excluded

### References
- Related: FINDING-030
- Source reports: 15.3.1.md

### Priority
Medium

---
## Issue: FINDING-012 - LDAP username not validated before DN construction
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The LDAP username from the HTTP Basic authentication header is inserted directly into the LDAP Distinguished Name without validation or escaping per RFC 4514.

### Details
Special DN characters (`,`, `=`, `+`, `<`, `>`, `#`, `;`, `\`, `"`) are not escaped. While this is used as a bind DN (limiting injection scope), no format validation ensures the username matches expected ASF username patterns (e.g., alphanumeric + limited special chars).

**CWE:** CWE-90  
**ASVS Sections:** 2.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/ldap.py`

### Remediation
Enforce a strict regex (e.g., `^[a-z][a-z0-9_-]{1,63}$`) before DN construction to validate username format.

### Acceptance Criteria
- [ ] Username validation regex implemented
- [ ] Validation occurs before DN construction
- [ ] Invalid usernames rejected
- [ ] Test added for validation
- [ ] Test added for special character rejection

### References
- Related: FINDING-005
- Source reports: 2.2.1.md

### Priority
Medium

---
## Issue: FINDING-013 - Content-length check executes after request body is already parsed
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The content-length size check is labeled "Pre-parse check" but is executed AFTER `await quart.request.form` has already read and parsed the request body into memory. By the time the size check runs, a large payload has already been buffered by Quart.

### Details
This makes the size validation ineffective as a server-side protection against large payloads causing memory exhaustion. Additionally, JSON request bodies (`quart.request.is_json`) have NO size check at all.

**CWE:** CWE-770  
**ASVS Sections:** 2.2.2 (Level 1)  
**Affected Files:**
- `src/asfquart/utils.py`

### Remediation
Move the content-length check before `await quart.request.form` to make the size limit effective. Also add size validation for JSON request bodies.

### Acceptance Criteria
- [ ] Content-length check moved before body parsing
- [ ] JSON body size validation added
- [ ] Size limit enforced before memory allocation
- [ ] Test added for form body size limit
- [ ] Test added for JSON body size limit

### References
- Related: FINDING-018, FINDING-034
- Source reports: 2.2.2.md

### Priority
Medium

---
## Issue: FINDING-014 - Missing security response headers (X-Content-Type-Options, CSP, X-Frame-Options)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The framework does not set any response headers to prevent unintended content interpretation by browsers.

### Details
The following headers are absent from all HTTP responses:

1. **`X-Content-Type-Options: nosniff`** — Not set anywhere. Without this, browsers may MIME-sniff responses and interpret `text/plain` content as HTML/script.
2. **`Content-Security-Policy`** — No CSP header is configured. API responses or error messages could be rendered in a full browser context without sandbox restrictions.
3. **`X-Frame-Options`** or CSP `frame-ancestors` — No framing protections. Responses can be embedded in iframes on malicious sites.

**ASVS Sections:** 3.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/base.py`
- `src/asfquart/generics.py`

### Remediation
Add a framework-wide `after_request` handler in `construct()`:
```python
@app.after_request
async def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return response
```

### Acceptance Criteria
- [ ] X-Content-Type-Options header added
- [ ] X-Frame-Options header added
- [ ] Content-Security-Policy header added
- [ ] Test added for header presence
- [ ] Test added for header values

### References
- Source reports: 3.2.1.md

### Priority
Medium

---
## Issue: FINDING-015 - Session cookie missing `__Secure-` or `__Host-` name prefix
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No `SESSION_COOKIE_NAME` configuration setting the cookie name to use `__Host-` or `__Secure-` prefix. The session cookie is set as `session=<value>; Secure; HttpOnly; SameSite=Strict; Path=/` when it should use `__Host-session` prefix.

### Details
Without the `__Host-` prefix, the cookie is not bound to the specific host and path by browser enforcement. An attacker on a related subdomain could potentially set or overwrite this cookie.

**ASVS Sections:** 3.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/base.py`

### Remediation
In construct() function, add cookie name prefix:
```python
app.config["SESSION_COOKIE_NAME"] = f"__Host-{name}"
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
```

### Acceptance Criteria
- [ ] Cookie name uses __Host- prefix
- [ ] Cookie configuration updated
- [ ] Test added for cookie name
- [ ] Test added for cookie attributes

### References
- Source reports: 3.3.1.md

### Priority
Medium

---
## Issue: FINDING-016 - State-changing logout functionality accessible via GET without Sec-Fetch-* validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Session destruction (forced logout) is a state-changing operation performed via HTTP GET without Sec-Fetch-* header validation.

### Details
While `SameSite=Strict` prevents cross-site attacks, same-site origins (other subdomains under the same registrable domain) can trigger session destruction. Additionally, resource loads (images, scripts, prefetch) from the same origin bypass the lack of Sec-Fetch-Mode/Sec-Fetch-Dest validation.

**ASVS Sections:** 3.5.3 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Add Sec-Fetch-* validation for GET requests performing state-changing operations, or restrict logout to POST-only. Validate `Sec-Fetch-Dest: document` and `Sec-Fetch-Mode: navigate` for GET requests to logout functionality.

### Acceptance Criteria
- [ ] Sec-Fetch-* validation added to logout endpoint
- [ ] Or logout restricted to POST-only
- [ ] Test added for validation
- [ ] Test added for unauthorized access prevention

### References
- Source reports: 3.5.3.md

### Priority
Medium

---
## Issue: FINDING-017 - No rate limiting on Bearer token validation attempts
**Labels:** bug, security, priority:medium
**Description:**
### Summary
No rate limiting exists on Bearer token validation attempts. Attackers can enumerate or brute-force bearer tokens without any throttling.

### Details
The severity depends on the token entropy used by the application's token handler, but the framework provides no built-in protection.

**CWE:** CWE-307  
**ASVS Sections:** 6.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/session.py` (lines 52-63)

### Remediation
Apply rate limiting keyed on client IP address for bearer token attempts. Document this control in security documentation per 6.1.1 requirements.

### Acceptance Criteria
- [ ] Rate limiting implemented for bearer token validation
- [ ] IP-based rate limiting applied
- [ ] Rate limit thresholds documented
- [ ] Test added for rate limiting
- [ ] Test added for lockout behavior

### References
- Related: FINDING-001
- Source reports: 6.3.1.md

### Priority
Medium

---
## Issue: FINDING-018 - No rate limiting on OAuth flow initiation causing potential memory exhaustion
**Labels:** bug, security, priority:medium
**Description:**
### Summary
An attacker can repeatedly hit ?login to fill pending_states dictionary with entries, causing memory exhaustion (DoS). While states expire after 900 seconds, there's no limit on how many states can be created in that window.

### Details
This represents both a lack of anti-automation controls and unbounded resource consumption.

**CWE:** CWE-770  
**ASVS Sections:** 6.1.1, 6.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py` (lines 36-53)

### Remediation
Limit the rate of OAuth flow initiations per client IP, and/or cap the maximum size of pending_states with eviction of oldest entries. Document this control in security documentation.

### Acceptance Criteria
- [ ] Rate limiting implemented for OAuth flow initiation
- [ ] Maximum pending_states size capped
- [ ] Eviction policy implemented
- [ ] Rate limits documented
- [ ] Test added for rate limiting
- [ ] Test added for memory bounds

### References
- Related: FINDING-013, FINDING-034
- Source reports: 6.1.1.md, 6.3.1.md

### Priority
Medium

---
## Issue: FINDING-019 - Bearer token sessions (PATs) have no framework-level revocation mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The framework delegates token validation entirely to the application-defined token_handler callback. There is no framework-level mechanism to track which tokens have been revoked, enforce token expiry, or signal to applications that they should implement revocation.

### Details
The example token handler matches tokens against a YAML config with no revocation capability.

**CWE:** CWE-613  
**ASVS Sections:** 7.4.1, 7.2.2 (Level 1)  
**Affected Files:**
- `src/asfquart/session.py`

### Remediation
Add framework-level guidance and optional enforcement for token lifecycle. Document in docs/sessions.md that token handlers SHOULD validate expiry and use cryptographically generated tokens rather than static secrets.

### Acceptance Criteria
- [ ] Framework guidance added for token lifecycle
- [ ] Documentation updated with token handler requirements
- [ ] Example implementation provided for token expiry
- [ ] Revocation mechanism documented

### References
- Related: FINDING-002
- Source reports: 7.4.1.md, 7.2.2.md

### Priority
Medium

---
## Issue: FINDING-020 - Authorization documentation lacks data-specific access rules and resource-level authorization guidance
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The authorization documentation in docs/auth.md defines rules for function-level access based on organizational roles but does not define data-specific access rules, resource attribute-based access patterns, or scope-based token authorization as a standard pattern.

### Details
Without documented data-specific access rules, developers using this framework may:
- Forget to implement resource-level authorization
- Implement it inconsistently
- Not understand that function-level auth alone is insufficient for data protection

**CWE:** CWE-862  
**ASVS Sections:** 8.1.1 (Level 1)  
**Affected Files:**
- `docs/auth.md`
- `docs/sessions.md`

### Remediation
Add documentation covering data-specific access control patterns, including examples of restricting access to user's own projects by checking session.committees against route parameters.

### Acceptance Criteria
- [ ] Data-specific access control patterns documented
- [ ] Resource-level authorization examples added
- [ ] Guidance on IDOR/BOLA prevention included
- [ ] Examples showing session.committees validation

### References
- Related: FINDING-038
- Source reports: 8.1.1.md

### Priority
Medium

---
## Issue: FINDING-021 - Framework provides no mechanism for data-specific authorization (IDOR/BOLA prevention)
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The Requirements class and @require decorator only support role-based authorization checks. There is no framework-level mechanism to verify that a user has access to a specific data item identified by an ID or path parameter.

### Details
Issues:
- No decorator supports parameterized resource checks
- No utility function exists to verify access to a specific resource
- Applications must implement all data-level authorization manually

This creates IDOR/BOLA risk for applications using the framework.

**CWE:** CWE-639  
**ASVS Sections:** 8.2.2 (Level 1)  
**Affected Files:**
- `src/asfquart/auth.py`

### Remediation
Add a resource-level requirement to the Requirements class or a parameterized decorator (e.g., @require_resource) that checks data-level access based on route parameters against session.committees/projects.

### Acceptance Criteria
- [ ] Resource-level authorization mechanism added
- [ ] Parameterized decorator implemented
- [ ] Route parameter validation supported
- [ ] Example usage documented
- [ ] Test added for resource-level checks

### References
- Source reports: 8.2.2.md

### Priority
Medium

---
## Issue: FINDING-022 - Unescaped OAuth UID in HTTP response body (non-redirect path)
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `oauth_data['uid']` value is inserted directly into the response body without output encoding in the non-redirect success path. While `content_type="text/plain"` mitigates XSS risk in modern browsers, no `X-Content-Type-Options: nosniff` header is set.

### Details
If a reverse proxy or CDN were to override or strip the content type, MIME-sniffing could result in the response being interpreted as HTML. This instance lacks the Refresh header interaction present in the redirect path.

**CWE:** CWE-79  
**ASVS Sections:** 1.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
HTML-escape `oauth_data['uid']` as defense-in-depth.

### Acceptance Criteria
- [ ] OAuth UID HTML-escaped before insertion
- [ ] Test added for output encoding

### References
- Related: FINDING-003
- Source reports: 1.2.1.md

### Priority
Low

---
## Issue: FINDING-023 - No explicit TLS version constraint on outbound OAuth HTTPS connection
**Labels:** bug, security, priority:low
**Description:**
### Summary
The outbound HTTPS connection to the OAuth provider (`oauth.apache.org`) does not explicitly configure minimum TLS version requirements.

### Details
While Python 3.10+ defaults to TLS 1.2+ via `ssl.create_default_context()`, no explicit `ssl.SSLContext` is passed to enforce this policy at the application level.

**CWE:** CWE-327  
**ASVS Sections:** 12.1.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Create an ssl.SSLContext with minimum_version = ssl.TLSVersion.TLSv1_2 and pass it to the aiohttp session.

### Acceptance Criteria
- [ ] SSLContext created with minimum TLS version
- [ ] Context passed to aiohttp session
- [ ] Test added for TLS version enforcement

### References
- Related: FINDING-024
- Source reports: 12.1.1.md

### Priority
Low

---
## Issue: FINDING-024 - No explicit TLS version configuration on LDAPS connection
**Labels:** bug, security, priority:low
**Description:**
### Summary
The LDAPS connection to `ldap-eu.apache.org:636` does not explicitly set minimum TLS version.

### Details
While LDAPS uses implicit TLS and the underlying bonsai library likely uses secure defaults, no explicit enforcement is visible at the application level.

**CWE:** CWE-327  
**ASVS Sections:** 12.1.1 (Level 1)  
**Affected Files:**
- `src/asfquart/ldap.py`

### Remediation
Configure explicit TLS settings when constructing the LDAP client, if supported by the asfpy.aioldap API.

### Acceptance Criteria
- [ ] Investigate asfpy.aioldap TLS configuration support
- [ ] If supported, configure minimum TLS version
- [ ] Document TLS configuration
- [ ] Test added if configuration possible

### References
- Related: FINDING-023
- Source reports: 12.1.1.md

### Priority
Low

---
## Issue: FINDING-025 - No warning when running without TLS in non-debug mode
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `runx()` method allows the application to be started without TLS (`certfile=None`), in which case it serves HTTP traffic. While this is expected for development and behind-reverse-proxy deployments, there is no warning or enforcement mechanism to prevent accidental HTTP-only production deployment.

### Details
This could lead to accidental insecure deployments in production environments.

**CWE:** CWE-319  
**ASVS Sections:** 12.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/base.py`

### Remediation
Log a warning when `debug=False` and `certfile=None` to alert operators that a TLS-terminating reverse proxy must be configured.

### Acceptance Criteria
- [ ] Warning logged in non-debug mode without TLS
- [ ] Warning message clearly indicates reverse proxy requirement
- [ ] Test added for warning behavior

### References
- Related: FINDING-006
- Source reports: 12.2.1.md

### Priority
Low

---
## Issue: FINDING-026 - Misleading protocol detection comment
**Labels:** bug, security, priority:low
**Description:**
### Summary
The comment on line 170 states 'If certfile is None then https' which is inverted from the actual logic (`"https" if certfile is not None else "http"`).

### Details
This could lead developers to misconfigure TLS settings based on incorrect documentation in the code.

**CWE:** CWE-1078  
**ASVS Sections:** 12.2.2 (Level 1)  
**Affected Files:**
- `src/asfquart/base.py` (line 170)

### Remediation
Fix the comment to accurately reflect the logic.

### Acceptance Criteria
- [ ] Comment corrected to match logic
- [ ] Code review to identify other misleading comments

### References
- Source reports: 12.2.2.md

### Priority
Low

---
## Issue: FINDING-027 - No deployment guidance or safeguards against source control metadata exposure
**Labels:** bug, security, priority:low
**Description:**
### Summary
The framework does not include any deployment configuration, documentation, or code-level safeguards to prevent `.git` or `.svn` directories from being accessible in production deployments.

### Details
While Quart applications do not automatically serve the entire filesystem, applications built with this framework that configure a `static_folder` overlapping with the project root could inadvertently expose source control metadata. The `pyproject.toml` does not include a `.gitignore` equivalent for production builds, and there is no deployment documentation (Dockerfile, nginx config, etc.) that explicitly excludes these directories.

**ASVS Sections:** 13.4.1 (Level 1)

### Remediation
Add deployment documentation explicitly noting that `.git`/`.svn` directories must not be deployed or must be inaccessible. Consider adding a startup check that warns if source control directories are present in the application directory.

### Acceptance Criteria
- [ ] Deployment documentation added
- [ ] .git/.svn exclusion documented
- [ ] Optional startup check for source control directories
- [ ] Example deployment configurations provided

### References
- Source reports: 13.4.1.md

### Priority
Low

---
## Issue: FINDING-028 - No client-side data clearing mechanism when server connection is unavailable
**Labels:** bug, security, priority:low
**Description:**
### Summary
The framework implements Clear-Site-Data header on logout responses but provides no client-side mechanism (JavaScript, Service Worker, etc.) to clear authenticated data if the session is terminated but the server connection is unavailable.

### Details
Since this is a server-side framework, the gap is expected but should be documented for consuming applications.

**CWE:** CWE-525  
**ASVS Sections:** 14.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Provide documentation and optional middleware for consuming applications to implement client-side session cleanup (e.g., service worker template or meta-refresh pattern).

### Acceptance Criteria
- [ ] Documentation added for client-side cleanup
- [ ] Example service worker template provided
- [ ] Guidance on offline session handling

### References
- Source reports: 14.3.1.md

### Priority
Low

---
## Issue: FINDING-029 - Unable to verify component currency against non-existent remediation policy
**Labels:** bug, security, priority:low
**Description:**
### Summary
Since no documented remediation timeframes exist (per ASVS 15.1.1 finding), it is impossible to verify whether current dependency versions comply with any update policy.

### Details
Issues identified:
- Wide version ranges allow potentially vulnerable versions
- No lock file is present in the repository
- Test dependencies are pinned to old versions (pytest==7.2.0, released November 2022)

**CWE:** CWE-1104  
**ASVS Sections:** 15.2.1 (Level 1)  
**Affected Files:**
- `pyproject.toml`

### Remediation
1. Establish the remediation policy (see 15.1.1)
2. Include a lock file in the repository to track exact versions
3. Implement automated dependency scanning (e.g., Dependabot, Snyk, or pip-audit)
4. Update pinned test dependencies to current versions

### Acceptance Criteria
- [ ] Remediation policy established (see FINDING-010)
- [ ] Lock file added to repository
- [ ] Automated dependency scanning configured
- [ ] Test dependencies updated
- [ ] Dependency update process documented

### References
- Related: FINDING-010
- Source reports: 15.2.1.md

### Priority
Low

---
## Issue: FINDING-030 - /auth endpoint returns entire ClientSession object without context-specific filtering
**Labels:** bug, security, priority:low
**Description:**
### Summary
The /auth endpoint returns the entire ClientSession object (a dict subclass containing all session fields: uid, dn, fullname, email, isMember, isChair, isRoot, committees, projects, mfa, isRole, metadata).

### Details
Fields like dn (LDAP distinguished name) and isRoot (infrastructure privilege flag) are implementation details not necessarily needed by all API consumers.

**CWE:** CWE-200  
**ASVS Sections:** 15.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Return only a defined subset of user-facing fields, or allow the consuming application to specify which fields are needed.

### Acceptance Criteria
- [ ] Field filtering implemented for /auth endpoint
- [ ] Allowlist of public fields defined
- [ ] Optional field selection mechanism added
- [ ] Test added for field filtering

### References
- Related: FINDING-011
- Source reports: 15.3.1.md

### Priority
Low

---
## Issue: FINDING-031 - formdata() utility merges all input sources without field allow-listing enabling mass assignment
**Labels:** bug, security, priority:low
**Description:**
### Summary
The formdata() utility merges ALL input sources (query string, form body, JSON body) without any field allow-listing. This creates a mass-assignment enabler — consuming applications receive an unfiltered dict where later sources override earlier ones (JSON > POST > query string).

### Details
An attacker can inject unexpected fields via JSON body that override intended form parameters.

**CWE:** CWE-915  
**ASVS Sections:** 15.3.1 (Level 1)  
**Affected Files:**
- `src/asfquart/utils.py`

### Remediation
Add an optional allowed_fields parameter:
```python
async def formdata(allowed_fields: set = None):
    ...
    if allowed_fields:
        form_data = {k: v for k, v in form_data.items() if k in allowed_fields}
    return form_data
```

### Acceptance Criteria
- [ ] allowed_fields parameter added
- [ ] Field filtering implemented
- [ ] Documentation updated with usage examples
- [ ] Test added for field filtering
- [ ] Test added for mass assignment prevention

### References
- Source reports: 15.3.1.md

### Priority
Low

---
## Issue: FINDING-032 - Validation and Business Logic Documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The framework lacks formal input validation documentation or schemas that define expected data formats.

### Details
Missing documentation for:
1. The OAuth `code` parameter format (expected pattern from OAuth provider)
2. The OAuth `state` parameter format (hex string of specific length)
3. LDAP usernames (expected character set, length limits)
4. Bearer token format expectations
5. Redirect URI validation rules (documented inline but not as a formal spec)

While the code implements some validation (e.g., redirect URI must start with `/`), there is no centralized documentation of input validation rules that would define the expected structure for all data items entering the system.

**ASVS Sections:** 2.1.1 (Level 1)  
**Affected Files:**
- Multiple files (framework-wide)

### Remediation
Create a validation specification document (e.g., `docs/input-validation.md`) that defines:
- Expected format for all input parameters (regex patterns, length limits, allowed characters)
- Business logic constraints (e.g., OAuth workflow timeout, session expiry)
- Reference these rules from code comments

### Acceptance Criteria
- [ ] Input validation documentation created
- [ ] All input parameters documented with format specifications
- [ ] Business logic constraints documented
- [ ] Code comments reference validation documentation

### References
- Source reports: 2.1.1.md

### Priority
Low

---
## Issue: FINDING-033 - JSON request bodies parsed without schema validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
JSON request bodies are parsed and merged into the form data dict without any schema validation. No type checking, no field validation, no depth limits.

### Details
The consuming application receives an arbitrary dict from potentially untrusted JSON input. While this is a utility function (validation is the application's responsibility), the framework provides no mechanism to specify expected schemas.

**CWE:** CWE-20  
**ASVS Sections:** 2.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/utils.py`

### Remediation
Consider adding optional schema validation support to the formdata() utility function.

### Acceptance Criteria
- [ ] Schema validation mechanism designed
- [ ] Optional schema parameter added to formdata()
- [ ] Documentation added for schema validation
- [ ] Example schemas provided
- [ ] Test added for schema validation

### References
- Source reports: 2.2.1.md

### Priority
Low

---
## Issue: FINDING-034 - OAuth pending_states dictionary never cleaned of expired entries
**Labels:** bug, security, priority:low
**Description:**
### Summary
While the OAuth flow correctly enforces sequential steps (state must exist and not be expired), the `pending_states` dictionary is never cleaned of expired entries. States that are initiated but never completed (user abandons OAuth flow) accumulate indefinitely.

### Details
An attacker could initiate thousands of OAuth flows without completing them, growing `pending_states` unboundedly.

**CWE:** CWE-770  
**ASVS Sections:** 2.3.1, 6.4.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Add periodic cleanup of expired states, either on each request or on a schedule, to prevent memory growth from abandoned OAuth flows.

### Acceptance Criteria
- [ ] Cleanup mechanism implemented for expired states
- [ ] Cleanup runs periodically or on-demand
- [ ] Memory bounds enforced
- [ ] Test added for cleanup behavior
- [ ] Test added for memory bounds

### References
- Related: FINDING-013, FINDING-018
- Source reports: 2.3.1.md, 6.4.1.md

### Priority
Low

---
## Issue: FINDING-035 - Sec-Fetch-Site check limited in scope; no Sec-Fetch-Dest validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The Sec-Fetch-Site check is limited in scope.

### Details
Limitations:
1. Only applies to POST requests — GET requests to the OAuth endpoint are not validated
2. Only applies to the OAuth endpoint — no framework-wide Sec-Fetch-* validation
3. Allows `None` value — requests from non-browser clients or older browsers bypass the check entirely

For ASVS 3.2.1 compliance, Sec-Fetch-Dest validation should also be considered (e.g., rejecting `Sec-Fetch-Dest: script` or `Sec-Fetch-Dest: style` for API endpoints to prevent them being loaded as subresources).

**ASVS Sections:** 3.2.1, 3.5.1 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Add Sec-Fetch-Dest validation for API endpoints:
```python
@app.before_request
async def validate_fetch_metadata():
    sec_fetch_dest = quart.request.headers.get("Sec-Fetch-Dest")
    if sec_fetch_dest in ("script", "style", "image", "font"):
        sec_fetch_site = quart.request.headers.get("Sec-Fetch-Site")
        if sec_fetch_site not in (None, "same-origin", "same-site"):
            return quart.Response(status=403, response="Forbidden", 
                                content_type="text/plain; charset=utf-8")
```

### Acceptance Criteria
- [ ] Sec-Fetch-Dest validation implemented
- [ ] Framework-wide validation applied
- [ ] GET request validation added
- [ ] Test added for validation
- [ ] Test added for subresource blocking

### References
- Source reports: 3.2.1.md, 3.5.1.md

### Priority
Low

---
## Issue: FINDING-036 - Login initiation creates server-side state via GET without Sec-Fetch-* validation
**Labels:** bug, security, priority:low
**Description:**
### Summary
Login initiation via GET creates entries in the process-local `pending_states` dictionary. Without Sec-Fetch-* validation on GET requests, resource loads or prefetch from the same origin could trigger state creation.

### Details
While individual entries are small and expire after 900 seconds, rapid automated requests could cause memory accumulation. The severity is LOW because SameSite=Strict prevents cross-site triggering and individual OAuth state entries have bounded lifetime.

**ASVS Sections:** 3.5.3 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Apply Sec-Fetch-Dest validation to ensure login initiation only comes from user navigations:
```python
if login_uri or quart.request.query_string == b"login":
    if quart.request.method == "GET":
        sec_fetch_dest = quart.request.headers.get("Sec-Fetch-Dest")
        if sec_fetch_dest is not None and sec_fetch_dest != "document":
            return quart.Response(status=403, response="Invalid request context\n",
                                  content_type="text/plain; charset=utf-8")
```

### Acceptance Criteria
- [ ] Sec-Fetch-Dest validation added to login initiation
- [ ] Non-navigation requests rejected
- [ ] Test added for validation
- [ ] Test added for resource load prevention

### References
- Source reports: 3.5.3.md

### Priority
Low

---
## Issue: FINDING-037 - No explicit session clear before writing new session on re-authentication
**Labels:** bug, security, priority:low
**Description:**
### Summary
When the OAuth callback completes, session.write() is called without first calling session.clear(). While this is safe in the current signed-cookie architecture (because write() completely replaces session content and produces a new signed cookie value), it is fragile if the session mechanism is ever changed to server-side sessions.

### Details
This creates a potential session fixation vulnerability if the session mechanism is changed in the future.

**CWE:** CWE-384  
**ASVS Sections:** 7.2.4 (Level 1)  
**Affected Files:**
- `src/asfquart/generics.py`

### Remediation
Add explicit session invalidation before authentication for defense-in-depth: call asfquart.session.clear() before asfquart.session.write(oauth_data) in generics.py OAuth callback handler.

### Acceptance Criteria
- [ ] session.clear() called before session.write()
- [ ] Test added for session invalidation
- [ ] Documentation updated

### References
- Source reports: 7.2.4.md

### Priority
Low

---
## Issue: FINDING-038 - No framework enforcement that all endpoints have authorization decorators applied
**Labels:** bug, security, priority:low
**Description:**
### Summary
The @require decorator provides robust function-level access control when applied. However, the framework does not enforce that all routes have an auth decorator.

### Details
The framework does not:
1. Enforce that all routes have an auth decorator
2. Provide a 'deny by default' mechanism requiring explicit @public marking for unauthenticated endpoints
3. Offer an audit mechanism to enumerate unprotected endpoints

This is an opt-in model where developers must remember to add the decorator.

**CWE:** CWE-862  
**ASVS Sections:** 8.2.1 (Level 1)  
**Affected Files:**
- `src/asfquart/auth.py`

### Remediation
Consider adding a 'secure by default' mode where all endpoints require explicit @public or @require(...) decorators, preventing accidental exposure of sensitive endpoints.

### Acceptance Criteria
- [ ] Secure-by-default mode designed
- [ ] Optional enforcement mechanism added
- [ ] Audit mechanism for unprotected endpoints
- [ ] Documentation updated
- [ ] Test added for enforcement

### References
- Related: FINDING-020
- Source reports: 8.2.1.md

### Priority
Low