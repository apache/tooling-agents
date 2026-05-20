# Security Audit Consolidated Report — apache/infrastructure-asfquart

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/infrastructure-asfquart |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | 30c90d4 |
| Date | May 20, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 38 |

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 19 |
| Low | 17 |
| Info | 0 |

All 38 findings are actionable. The repository was assessed against ASVS Level 1 requirements across all directories. No critical-severity issues were identified; however, two high-severity findings relate to authentication rate limiting and session revocation gaps that warrant prompt remediation.

### Level Coverage

This audit covers **ASVS Level 1 (L1)** controls. All findings are tagged at L1, representing the minimum baseline security posture expected for any internet-facing application. The assessment spans authentication (Chapter 6), session management (Chapter 7), input validation (Chapter 2), access control (Chapter 8), communications security (Chapter 12), configuration (Chapter 14), and supply chain (Chapter 15).

### Top 5 Risks

1. **No rate limiting or brute force protection on HTTP Basic Authentication endpoint (FINDING-001)** — Attackers can perform unlimited credential-stuffing or brute-force attempts against the Basic Auth endpoint without any throttling or account lockout mechanism.

2. **Self-contained session tokens have no server-side revocation mechanism (FINDING-002)** — Signed cookie-based sessions cannot be invalidated server-side, meaning compromised sessions remain valid until natural expiry regardless of logout or credential change events.

3. **LDAP injection via unvalidated username from HTTP Basic Auth (FINDING-005)** — User-supplied usernames are incorporated into LDAP Distinguished Name construction without sanitization, potentially allowing LDAP injection attacks against the directory service.

4. **Missing Strict-Transport-Security (HSTS) header (FINDING-006)** — The application does not emit an HSTS header, leaving users vulnerable to protocol downgrade and man-in-the-middle attacks on initial connections.

5. **Bearer token logged to stdout in debug message (FINDING-009)** — Sensitive bearer tokens are written to application logs, risking credential exposure through log aggregation systems, container output, or shared infrastructure.

### Positive Controls

The audit identified the following security controls that are correctly implemented:

| Control | Evidence |
|---------|----------|
| No dynamic code execution (eval, exec, etc.) detected | ASVS 1.3.2 — Pass |
| Session cookies are correctly marked Secure | Confirmed in communications security review |
| OAuth states are properly expired with 900s timeout | `src/asfquart/generics.py:45-48` |
| OAuth states are single-use (popped on consumption) | `src/asfquart/generics.py:45-48` |
| Passwords can be of any composition without character type restrictions | ASVS 6.2.5 — Pass |
| Passwords are verified exactly as received without modification | ASVS 6.2.8 — Pass |
| No default accounts present or they are disabled | ASVS 6.3.2 — Pass |
| No password hints or knowledge-based authentication present | ASVS 6.4.2 — Pass |
| Authorization rules enforced at trusted service layer | Server-side decorators in `src/asfquart/auth.py` |

These controls demonstrate that the project has foundational security practices in place, particularly around OAuth state management, password handling policy, and avoidance of dangerous code patterns. The findings in this report represent areas where additional hardening is needed to meet the full L1 baseline.

---

## 3. Findings

### 3.2 High

#### FINDING-001: No rate limiting or brute force protection on HTTP Basic Authentication endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-307 |
| **ASVS sections** | 6.1.1, 6.3.1 |
| **Files** | src/asfquart/session.py:60-84 |
| **Source Reports** | 6.1.1.md, 6.3.1.md |
| **Related** | FINDING-017 |

**Description:**

No rate limiting or brute force protection exists on the HTTP Basic Authentication endpoint. Each request triggers an LDAP bind attempt with no failed attempt counter, account lockout mechanism, progressive delay, IP-based rate limiting, or CAPTCHA. Attackers can perform credential stuffing or brute-force password guessing against any ASF user account. This lack of implementation and documentation violates both 6.1.1 (documentation requirement) and 6.3.1 (implementation requirement).

**Remediation:**

Implement rate limiting at the application level with per-IP and per-username tracking (e.g., cap at 5 attempts per 5-minute window before returning HTTP 429). Use quart-rate-limiter or similar. Document rate limit thresholds, lockout prevention strategy, and adaptive response escalation policy in security documentation.

---

#### FINDING-002: Self-contained session tokens (signed cookies) have no server-side revocation mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS sections** | 7.4.1, 7.4.2 |
| **Files** | src/asfquart/session.py, src/asfquart/generics.py, src/asfquart/auth.py |
| **Source Reports** | 7.4.1.md, 7.4.2.md |
| **Related** | FINDING-019 |

**Description:**

When session.clear() is called on logout, only the current request context is cleared and the browser is instructed to delete the cookie. There is no server-side revocation list or per-user timestamp check. If an attacker captures a valid session cookie before logout, it remains cryptographically valid and will pass all validation checks in session.read() until it naturally expires (default: 7 days). Additionally, the codebase contains no functionality to enumerate active sessions for a specific user, invalidate all sessions belonging to a specific user, maintain a per-user invalidated-after timestamp, or check against an external user status during session validation. Session data from the cookie is trusted as-is until expiry. Disabled or deleted user accounts retain access for up to 7 days by default.

**Remediation:**

Implement a server-side revocation registry with per-user invalidation timestamps checked on every session.read() call. Provide an invalidate_all_user_sessions(uid) API. Add periodic user status validation (e.g., every 5 minutes) against LDAP/directory. Consider reducing default session expiry from 7 days.

### 3.3 Medium

#### FINDING-003: Unescaped OAuth UID in HTTP response body (redirect path)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-79 |
| **ASVS sections** | 1.2.1 |
| **Files** | src/asfquart/generics.py |
| **Source Reports** | 1.2.1.md |
| **Related** | FINDING-022 |

**Description:**

The `oauth_data['uid']` value is sourced from the ASF OAuth provider's JSON response and inserted directly into the response body without output encoding. While the `content_type="text/plain"` mitigates XSS risk in modern browsers, no `X-Content-Type-Options: nosniff` header is set. If a reverse proxy or CDN were to override or strip the content type, MIME-sniffing could result in the response being interpreted as HTML.

**Remediation:**

HTML-escape `oauth_data['uid']` and add `X-Content-Type-Options: nosniff` header.

---

#### FINDING-004: OAuth code parameter not URL-encoded before URL construction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-74 |
| **ASVS sections** | 1.2.2, 2.2.1 |
| **Files** | src/asfquart/generics.py |
| **Source Reports** | 1.2.2.md, 2.2.1.md |
| **Related** | - |

**Description:**

The OAuth authorization `code` parameter from the query string is interpolated into the token exchange URL via `%s` formatting without URL-encoding or format validation. While the state verification significantly limits exploitability (attacker must have a valid pending state), the code value is not validated against an expected pattern (e.g., alphanumeric, specific length) before being used in a server-side HTTP request. A malicious code containing `&` characters could inject additional query parameters into the token exchange request (HTTP parameter pollution).

**Remediation:**

Validate code format (OAuth codes are typically alphanumeric) and URL-encode the code parameter before interpolation into the token exchange URL.

---

#### FINDING-005: LDAP injection via unvalidated username from HTTP Basic Auth

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-90 |
| **ASVS sections** | 1.2.4 |
| **Files** | src/asfquart/session.py |
| **Source Reports** | 1.2.4.md |
| **Related** | FINDING-012 |

**Description:**

The `auth_user` value from the HTTP Authorization header is passed directly to `ldap.LDAPClient` without LDAP-specific escaping or validation. Based on the code inventory, the LDAP module constructs the bind DN using string interpolation (`uid=%s`). If the username contains LDAP special characters, this could lead to LDAP injection.

**Remediation:**

Validate username against a safe pattern (e.g., `^[a-zA-Z][a-zA-Z0-9._-]{0,63}$`) before passing to LDAP client.

---

#### FINDING-006: Missing Strict-Transport-Security (HSTS) header

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS sections** | 12.2.1, 3.4.1 |
| **Files** | src/asfquart/base.py |
| **Source Reports** | 12.2.1.md, 3.4.1.md |
| **Related** | FINDING-025 |

**Description:**

The framework does not set the `Strict-Transport-Security` (HSTS) header on responses. While session cookies are correctly marked `Secure`, the absence of HSTS means first-time visitors could have their initial request intercepted before HTTPS redirect, no protection against SSL stripping attacks, and browsers won't automatically upgrade HTTP→HTTPS for subsequent visits.

**Remediation:**

In construct() function in src/asfquart/base.py, add after cookie config:
```python
@app.after_request
async def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
```

---

#### FINDING-007: No enforcement of TLS when Secure cookies are configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-295 |
| **ASVS sections** | 12.2.2 |
| **Files** | src/asfquart/base.py |
| **Source Reports** | 12.2.2.md |
| **Related** | - |

**Description:**

The framework configures session cookies with `Secure=True` but `runx()` defaults to no TLS and allows HTTP-only serving. There is no validation that any provided certificate is from a publicly trusted CA versus self-signed, and no enforcement that a TLS-terminating proxy is present.

**Remediation:**

Add a require_tls parameter or startup check that raises an error or warning when certfile is not provided in non-debug mode.

---

#### FINDING-008: OAuth authorization code sent via GET query string to token endpoint

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-598 |
| **ASVS sections** | 14.2.1 |
| **Files** | src/asfquart/generics.py |
| **Source Reports** | 14.2.1.md |
| **Related** | - |

**Description:**

The OAuth token exchange sends the authorization code as a URL query parameter via an HTTP GET request. While this is a server-to-server call, the authorization code is sensitive and could be logged in intermediate proxy access logs, server logs, or network monitoring tools. Note: This appears to be constrained by the ASF OAuth server's API design (it uses a GET endpoint).

**Remediation:**

If upstream supports it, use POST with code in the body instead of GET with code in URL.

---

#### FINDING-009: Bearer token logged to stdout in debug message

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-532 |
| **ASVS sections** | 14.2.1 |
| **Files** | src/asfquart/session.py |
| **Source Reports** | 14.2.1.md |
| **Related** | - |

**Description:**

When no PAT handler is registered, the bearer token from the Authorization header is printed to stdout in a debug message. This exposes the sensitive token in application logs.

**Remediation:**

Replace print(f"Debug: No PAT handler registered to handle token {quart.request.authorization.token}") with a logger call that does not include the token value.

---

#### FINDING-010: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1104 |
| **ASVS sections** | 15.1.1 |
| **Files** | pyproject.toml |
| **Source Reports** | 15.1.1.md |
| **Related** | FINDING-029 |

**Description:**

The project defines dependency version constraints in pyproject.toml but lacks documentation defining: 1. Risk-based remediation timeframes for addressing known vulnerabilities in dependencies 2. A general policy for updating third-party libraries 3. Classification of components by risk level (critical, high, medium, low) 4. Expected SLAs for patching (e.g., "Critical CVEs in dependencies must be addressed within 72 hours")

**Remediation:**

Create a SECURITY.md or equivalent document defining remediation timeframes by severity (Critical: 48h, High: 7d, Medium: 30d, Low: 90d), a general update policy, and risk classification of components.

---

#### FINDING-011: Full OAuth response written unfiltered to session cookie

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS sections** | 15.3.1 |
| **Files** | src/asfquart/generics.py |
| **Source Reports** | 15.3.1.md |
| **Related** | FINDING-030 |

**Description:**

The entire OAuth provider response is written verbatim to the session cookie via oauth_data = await rv.json(); asfquart.session.write(oauth_data). Quart's default session is a signed cookie that is base64-encoded but not encrypted — meaning the client can read all data. The OAuth response may contain fields not intended for client exposure. While ClientSession.__init__ filters fields when reading the session back, the raw session cookie persisted on the client contains ALL OAuth-returned fields.

**Remediation:**

Filter OAuth data before writing to session using an explicit allowlist: ALLOWED_SESSION_FIELDS = {"uid", "dn", "fullname", "email", "isMember", "isChair", "isRoot", "pmcs", "projects", "mfa", "roleaccount", "metadata"}; filtered_data = {k: v for k, v in oauth_data.items() if k in ALLOWED_SESSION_FIELDS}; asfquart.session.write(filtered_data)

---

#### FINDING-012: LDAP username not validated before DN construction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-90 |
| **ASVS sections** | 2.2.1 |
| **Files** | src/asfquart/ldap.py |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005 |

**Description:**

The LDAP username from the HTTP Basic authentication header is inserted directly into the LDAP Distinguished Name without validation or escaping per RFC 4514. Special DN characters (`,`, `=`, `+`, `<`, `>`, `#`, `;`, `\`, `"`) are not escaped. While this is used as a bind DN (limiting injection scope), no format validation ensures the username matches expected ASF username patterns (e.g., alphanumeric + limited special chars).

**Remediation:**

Enforce a strict regex (e.g., `^[a-z][a-z0-9_-]{1,63}$`) before DN construction to validate username format.

---

#### FINDING-013: Content-length check executes after request body is already parsed

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS sections** | 2.2.2 |
| **Files** | src/asfquart/utils.py |
| **Source Reports** | 2.2.2.md |
| **Related** | FINDING-018, FINDING-034 |

**Description:**

The content-length size check is labeled "Pre-parse check" but is executed AFTER `await quart.request.form` has already read and parsed the request body into memory. By the time the size check runs, a large payload has already been buffered by Quart. This makes the size validation ineffective as a server-side protection against large payloads causing memory exhaustion. Additionally, JSON request bodies (`quart.request.is_json`) have NO size check at all.

**Remediation:**

Move the content-length check before `await quart.request.form` to make the size limit effective. Also add size validation for JSON request bodies.

---

#### FINDING-014: Missing security response headers (X-Content-Type-Options, CSP, X-Frame-Options)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 3.2.1 |
| **Files** | src/asfquart/base.py, src/asfquart/generics.py |
| **Source Reports** | 3.2.1.md |
| **Related** | - |

**Description:**

The framework does not set any response headers to prevent unintended content interpretation by browsers. Specifically, the following headers are absent from all HTTP responses:

1. **`X-Content-Type-Options: nosniff`** — Not set anywhere. Without this, browsers may MIME-sniff responses and interpret `text/plain` content as HTML/script.
2. **`Content-Security-Policy`** — No CSP header is configured. API responses or error messages could be rendered in a full browser context without sandbox restrictions.
3. **`X-Frame-Options`** or CSP `frame-ancestors` — No framing protections. Responses can be embedded in iframes on malicious sites.

**Remediation:**

Add a framework-wide `after_request` handler in `construct()`:
```python
@app.after_request
async def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    return response
```

---

#### FINDING-015: Session cookie missing `__Secure-` or `__Host-` name prefix

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 3.3.1 |
| **Files** | src/asfquart/base.py |
| **Source Reports** | 3.3.1.md |
| **Related** | - |

**Description:**

No `SESSION_COOKIE_NAME` configuration setting the cookie name to use `__Host-` or `__Secure-` prefix. The session cookie is set as `session=<value>; Secure; HttpOnly; SameSite=Strict; Path=/` when it should use `__Host-session` prefix. Without the `__Host-` prefix, the cookie is not bound to the specific host and path by browser enforcement. An attacker on a related subdomain could potentially set or overwrite this cookie.

**Remediation:**

In construct() function, add cookie name prefix:
```python
app.config["SESSION_COOKIE_NAME"] = f"__Host-{name}"
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
```

---

#### FINDING-016: State-changing logout functionality accessible via GET without Sec-Fetch-* validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 3.5.3 |
| **Files** | src/asfquart/generics.py |
| **Source Reports** | 3.5.3.md |
| **Related** | - |

**Description:**

Session destruction (forced logout) is a state-changing operation performed via HTTP GET without Sec-Fetch-* header validation. While `SameSite=Strict` prevents cross-site attacks, same-site origins (other subdomains under the same registrable domain) can trigger session destruction. Additionally, resource loads (images, scripts, prefetch) from the same origin bypass the lack of Sec-Fetch-Mode/Sec-Fetch-Dest validation.

**Remediation:**

Add Sec-Fetch-* validation for GET requests performing state-changing operations, or restrict logout to POST-only. Validate `Sec-Fetch-Dest: document` and `Sec-Fetch-Mode: navigate` for GET requests to logout functionality.

---

#### FINDING-017: No rate limiting on Bearer token validation attempts

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-307 |
| **ASVS sections** | 6.3.1 |
| **Files** | src/asfquart/session.py |
| **Source Reports** | 6.3.1.md |
| **Related** | FINDING-001 |

**Description:**

No rate limiting exists on Bearer token validation attempts. Attackers can enumerate or brute-force bearer tokens without any throttling. The severity depends on the token entropy used by the application's token handler, but the framework provides no built-in protection.

**Remediation:**

Apply rate limiting keyed on client IP address for bearer token attempts. Document this control in security documentation per 6.1.1 requirements.

---

#### FINDING-018: No rate limiting on OAuth flow initiation causing potential memory exhaustion

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS sections** | 6.1.1, 6.3.1 |
| **Files** | src/asfquart/generics.py |
| **Source Reports** | 6.1.1.md, 6.3.1.md |
| **Related** | FINDING-013, FINDING-034 |

**Description:**

An attacker can repeatedly hit ?login to fill pending_states dictionary with entries, causing memory exhaustion (DoS). While states expire after 900 seconds, there's no limit on how many states can be created in that window. This represents both a lack of anti-automation controls and unbounded resource consumption.

**Remediation:**

Limit the rate of OAuth flow initiations per client IP, and/or cap the maximum size of pending_states with eviction of oldest entries. Document this control in security documentation.

---

#### FINDING-019: Bearer token sessions (PATs) have no framework-level revocation mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS sections** | 7.4.1, 7.2.2 |
| **Files** | src/asfquart/session.py |
| **Source Reports** | 7.4.1.md, 7.2.2.md |
| **Related** | FINDING-002 |

**Description:**

The framework delegates token validation entirely to the application-defined token_handler callback. There is no framework-level mechanism to track which tokens have been revoked, enforce token expiry, or signal to applications that they should implement revocation. The example token handler matches tokens against a YAML config with no revocation capability.

**Remediation:**

Add framework-level guidance and optional enforcement for token lifecycle. Document in docs/sessions.md that token handlers SHOULD validate expiry and use cryptographically generated tokens rather than static secrets.

---

#### FINDING-020: Authorization documentation lacks data-specific access rules and resource-level authorization guidance

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-862 |
| **ASVS sections** | 8.1.1 |
| **Files** | docs/auth.md, docs/sessions.md |
| **Source Reports** | 8.1.1.md |
| **Related** | FINDING-038 |

**Description:**

The authorization documentation in docs/auth.md defines rules for function-level access based on organizational roles but does not define: (1) Data-specific access rules, (2) Resource attribute-based access patterns, (3) Scope-based token authorization as a standard pattern. Without documented data-specific access rules, developers using this framework may forget to implement resource-level authorization, implement it inconsistently, or not understand that function-level auth alone is insufficient for data protection.

**Remediation:**

Add documentation covering data-specific access control patterns, including examples of restricting access to user's own projects by checking session.committees against route parameters.

---

#### FINDING-021: Framework provides no mechanism for data-specific authorization (IDOR/BOLA prevention)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-639 |
| **ASVS sections** | 8.2.2 |
| **Files** | src/asfquart/auth.py |
| **Source Reports** | 8.2.2.md |
| **Related** | - |

**Description:**

The Requirements class and @require decorator only support role-based authorization checks. There is no framework-level mechanism to verify that a user has access to a specific data item identified by an ID or path parameter. No decorator supports parameterized resource checks, no utility function exists to verify access to a specific resource, and applications must implement all data-level authorization manually. This creates IDOR/BOLA risk for applications using the framework.

**Remediation:**

Add a resource-level requirement to the Requirements class or a parameterized decorator (e.g., @require_resource) that checks data-level access based on route parameters against session.committees/projects.

### 3.4 Low

#### FINDING-022: Unescaped OAuth UID in HTTP response body (non-redirect path)

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-79 |
| ASVS Section(s) | 1.2.1 |
| Files | src/asfquart/generics.py |
| Source Reports | 1.2.1.md |
| Related Findings | FINDING-003 |

**Description:**

The `oauth_data['uid']` value is inserted directly into the response body without output encoding in the non-redirect success path. While the `content_type="text/plain"` mitigates XSS risk in modern browsers, no `X-Content-Type-Options: nosniff` header is set. If a reverse proxy or CDN were to override or strip the content type, MIME-sniffing could result in the response being interpreted as HTML. This instance lacks the Refresh header interaction present in the redirect path.

**Remediation:**

HTML-escape `oauth_data['uid']` as defense-in-depth.

---

#### FINDING-023: No explicit TLS version constraint on outbound OAuth HTTPS connection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-327 |
| ASVS Section(s) | 12.1.1 |
| Files | src/asfquart/generics.py |
| Source Reports | 12.1.1.md |
| Related Findings | FINDING-024 |

**Description:**

The outbound HTTPS connection to the OAuth provider (`oauth.apache.org`) does not explicitly configure minimum TLS version requirements. While Python 3.10+ defaults to TLS 1.2+ via `ssl.create_default_context()`, no explicit `ssl.SSLContext` is passed to enforce this policy at the application level.

**Remediation:**

Create an ssl.SSLContext with minimum_version = ssl.TLSVersion.TLSv1_2 and pass it to the aiohttp session.

---

#### FINDING-024: No explicit TLS version configuration on LDAPS connection

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-327 |
| ASVS Section(s) | 12.1.1 |
| Files | src/asfquart/ldap.py |
| Source Reports | 12.1.1.md |
| Related Findings | FINDING-023 |

**Description:**

The LDAPS connection to `ldap-eu.apache.org:636` does not explicitly set minimum TLS version. While LDAPS uses implicit TLS and the underlying bonsai library likely uses secure defaults, no explicit enforcement is visible at the application level.

**Remediation:**

Configure explicit TLS settings when constructing the LDAP client, if supported by the asfpy.aioldap API.

---

#### FINDING-025: No warning when running without TLS in non-debug mode

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-319 |
| ASVS Section(s) | 12.2.1 |
| Files | src/asfquart/base.py |
| Source Reports | 12.2.1.md |
| Related Findings | FINDING-006 |

**Description:**

The `runx()` method allows the application to be started without TLS (`certfile=None`), in which case it serves HTTP traffic. While this is expected for development and behind-reverse-proxy deployments, there is no warning or enforcement mechanism to prevent accidental HTTP-only production deployment.

**Remediation:**

Log a warning when `debug=False` and `certfile=None` to alert operators that a TLS-terminating reverse proxy must be configured.

---

#### FINDING-026: Misleading protocol detection comment

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-1078 |
| ASVS Section(s) | 12.2.2 |
| Files | src/asfquart/base.py:170 |
| Source Reports | 12.2.2.md |
| Related Findings | |

**Description:**

The comment on line 170 states 'If certfile is None then https' which is inverted from the actual logic (`"https" if certfile is not None else "http"`). This could lead developers to misconfigure TLS.

**Remediation:**

Fix the comment to accurately reflect the logic.

---

#### FINDING-027: No deployment guidance or safeguards against source control metadata exposure

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Section(s) | 13.4.1 |
| Files | |
| Source Reports | 13.4.1.md |
| Related Findings | |

**Description:**

The framework does not include any deployment configuration, documentation, or code-level safeguards to prevent `.git` or `.svn` directories from being accessible in production deployments. While Quart applications do not automatically serve the entire filesystem, applications built with this framework that configure a `static_folder` overlapping with the project root could inadvertently expose source control metadata. The `pyproject.toml` does not include a `.gitignore` equivalent for production builds, and there is no deployment documentation (Dockerfile, nginx config, etc.) that explicitly excludes these directories.

**Remediation:**

Add deployment documentation explicitly noting that `.git`/`.svn` directories must not be deployed or must be inaccessible. Consider adding a startup check that warns if source control directories are present in the application directory.

---

#### FINDING-028: No client-side data clearing mechanism when server connection is unavailable

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-525 |
| ASVS Section(s) | 14.3.1 |
| Files | src/asfquart/generics.py |
| Source Reports | 14.3.1.md |
| Related Findings | |

**Description:**

The framework implements Clear-Site-Data header on logout responses but provides no client-side mechanism (JavaScript, Service Worker, etc.) to clear authenticated data if the session is terminated but the server connection is unavailable. Since this is a server-side framework, the gap is expected but should be documented for consuming applications.

**Remediation:**

Provide documentation and optional middleware for consuming applications to implement client-side session cleanup (e.g., service worker template or meta-refresh pattern).

---

#### FINDING-029: Unable to verify component currency against non-existent remediation policy

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-1104 |
| ASVS Section(s) | 15.2.1 |
| Files | pyproject.toml |
| Source Reports | 15.2.1.md |
| Related Findings | FINDING-010 |

**Description:**

Since no documented remediation timeframes exist (per ASVS 15.1.1 finding), it is impossible to verify whether current dependency versions comply with any update policy. Wide version ranges allow potentially vulnerable versions, no lock file is present in the repository, and test dependencies are pinned to old versions (pytest==7.2.0, released November 2022).

**Remediation:**

1. Establish the remediation policy (see 15.1.1) 2. Include a lock file in the repository to track exact versions 3. Implement automated dependency scanning (e.g., Dependabot, Snyk, or pip-audit) 4. Update pinned test dependencies to current versions

---

#### FINDING-030: /auth endpoint returns entire ClientSession object without context-specific filtering

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-200 |
| ASVS Section(s) | 15.3.1 |
| Files | src/asfquart/generics.py |
| Source Reports | 15.3.1.md |
| Related Findings | FINDING-011 |

**Description:**

The /auth endpoint returns the entire ClientSession object (a dict subclass containing all session fields: uid, dn, fullname, email, isMember, isChair, isRoot, committees, projects, mfa, isRole, metadata). Fields like dn (LDAP distinguished name) and isRoot (infrastructure privilege flag) are implementation details not necessarily needed by all API consumers.

**Remediation:**

Return only a defined subset of user-facing fields, or allow the consuming application to specify which fields are needed.

---

#### FINDING-031: formdata() utility merges all input sources without field allow-listing enabling mass assignment

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-915 |
| ASVS Section(s) | 15.3.1 |
| Files | src/asfquart/utils.py |
| Source Reports | 15.3.1.md |
| Related Findings | |

**Description:**

The formdata() utility merges ALL input sources (query string, form body, JSON body) without any field allow-listing. This creates a mass-assignment enabler — consuming applications receive an unfiltered dict where later sources override earlier ones (JSON > POST > query string). An attacker can inject unexpected fields via JSON body that override intended form parameters.

**Remediation:**

Add an optional allowed_fields parameter: async def formdata(allowed_fields: set = None): ... if allowed_fields: form_data = {k: v for k, v in form_data.items() if k in allowed_fields}; return form_data

---

#### FINDING-032: Validation and Business Logic Documentation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Section(s) | 2.1.1 |
| Files | Multiple files (framework-wide) |
| Source Reports | 2.1.1.md |
| Related Findings | |

**Description:**

The framework lacks formal input validation documentation or schemas that define expected data formats for: 1. The OAuth `code` parameter format (expected pattern from OAuth provider) 2. The OAuth `state` parameter format (hex string of specific length) 3. LDAP usernames (expected character set, length limits) 4. Bearer token format expectations 5. Redirect URI validation rules (documented inline but not as a formal spec). While the code implements some validation (e.g., redirect URI must start with `/`), there is no centralized documentation of input validation rules that would define the expected structure for all data items entering the system.

**Remediation:**

Create a validation specification document (e.g., `docs/input-validation.md`) that defines: Expected format for all input parameters (regex patterns, length limits, allowed characters), Business logic constraints (e.g., OAuth workflow timeout, session expiry), Reference these rules from code comments.

---

#### FINDING-033: JSON request bodies parsed without schema validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-20 |
| ASVS Section(s) | 2.2.1 |
| Files | src/asfquart/utils.py |
| Source Reports | 2.2.1.md |
| Related Findings | |

**Description:**

JSON request bodies are parsed and merged into the form data dict without any schema validation. No type checking, no field validation, no depth limits. The consuming application receives an arbitrary dict from potentially untrusted JSON input. While this is a utility function (validation is the application's responsibility), the framework provides no mechanism to specify expected schemas.

**Remediation:**

Consider adding optional schema validation support to the formdata() utility function.

---

#### FINDING-034: OAuth pending_states dictionary never cleaned of expired entries

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-770 |
| ASVS Section(s) | 2.3.1, 6.4.1 |
| Files | src/asfquart/generics.py |
| Source Reports | 2.3.1.md, 6.4.1.md |
| Related Findings | FINDING-013, FINDING-018 |

**Description:**

While the OAuth flow correctly enforces sequential steps (state must exist and not be expired), the `pending_states` dictionary is never cleaned of expired entries. States that are initiated but never completed (user abandons OAuth flow) accumulate indefinitely. An attacker could initiate thousands of OAuth flows without completing them, growing `pending_states` unboundedly.

**Remediation:**

Add periodic cleanup of expired states, either on each request or on a schedule, to prevent memory growth from abandoned OAuth flows.

---

#### FINDING-035: Sec-Fetch-Site check limited in scope; no Sec-Fetch-Dest validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Section(s) | 3.2.1, 3.5.1 |
| Files | src/asfquart/generics.py |
| Source Reports | 3.2.1.md, 3.5.1.md |
| Related Findings | |

**Description:**

The Sec-Fetch-Site check is limited in scope: 1. Only applies to POST requests — GET requests to the OAuth endpoint are not validated 2. Only applies to the OAuth endpoint — no framework-wide Sec-Fetch-* validation 3. Allows `None` value — requests from non-browser clients or older browsers bypass the check entirely. For ASVS 3.2.1 compliance, Sec-Fetch-Dest validation should also be considered (e.g., rejecting `Sec-Fetch-Dest: script` or `Sec-Fetch-Dest: style` for API endpoints to prevent them being loaded as subresources).

**Remediation:**

Add Sec-Fetch-Dest validation for API endpoints: ```python @app.before_request async def validate_fetch_metadata(): sec_fetch_dest = quart.request.headers.get("Sec-Fetch-Dest") if sec_fetch_dest in ("script", "style", "image", "font"): sec_fetch_site = quart.request.headers.get("Sec-Fetch-Site") if sec_fetch_site not in (None, "same-origin", "same-site"): return quart.Response(status=403, response="Forbidden", content_type="text/plain; charset=utf-8") ```

---

#### FINDING-036: Login initiation creates server-side state via GET without Sec-Fetch-* validation

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | |
| ASVS Section(s) | 3.5.3 |
| Files | src/asfquart/generics.py |
| Source Reports | 3.5.3.md |
| Related Findings | |

**Description:**

Login initiation via GET creates entries in the process-local `pending_states` dictionary. Without Sec-Fetch-* validation on GET requests, resource loads or prefetch from the same origin could trigger state creation. While individual entries are small and expire after 900 seconds, rapid automated requests could cause memory accumulation. The severity is LOW because SameSite=Strict prevents cross-site triggering and individual OAuth state entries have bounded lifetime.

**Remediation:**

Apply Sec-Fetch-Dest validation to ensure login initiation only comes from user navigations: ```python if login_uri or quart.request.query_string == b"login": if quart.request.method == "GET": sec_fetch_dest = quart.request.headers.get("Sec-Fetch-Dest") if sec_fetch_dest is not None and sec_fetch_dest != "document": return quart.Response(status=403, response="Invalid request context\n", content_type="text/plain; charset=utf-8") ```

---

#### FINDING-037: No explicit session clear before writing new session on re-authentication

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-384 |
| ASVS Section(s) | 7.2.4 |
| Files | src/asfquart/generics.py |
| Source Reports | 7.2.4.md |
| Related Findings | |

**Description:**

When the OAuth callback completes, session.write() is called without first calling session.clear(). While this is safe in the current signed-cookie architecture (because write() completely replaces session content and produces a new signed cookie value), it is fragile if the session mechanism is ever changed to server-side sessions.

**Remediation:**

Add explicit session invalidation before authentication for defense-in-depth: call asfquart.session.clear() before asfquart.session.write(oauth_data) in generics.py OAuth callback handler.

---

#### FINDING-038: No framework enforcement that all endpoints have authorization decorators applied

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-862 |
| ASVS Section(s) | 8.2.1 |
| Files | src/asfquart/auth.py |
| Source Reports | 8.2.1.md |
| Related Findings | FINDING-020 |

**Description:**

The @require decorator provides robust function-level access control when applied. However, the framework does not: (1) Enforce that all routes have an auth decorator, (2) Provide a 'deny by default' mechanism requiring explicit @public marking for unauthenticated endpoints, (3) Offer an audit mechanism to enumerate unprotected endpoints. This is an opt-in model where developers must remember to add the decorator.

**Remediation:**

Consider adding a 'secure by default' mode where all endpoints require explicit @public or @require(...) decorators, preventing accidental exposure of sensitive endpoints.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Ch01 | No dynamic code execution (eval, exec, etc.) detected | 1.3.2 status: Pass | — |
| Ch12 | Session cookies are correctly marked Secure | Mentioned in ASVS-1221-MED-001 description | — |
| Ch06 | OAuth states are properly expired with 900s timeout | 6.4.1 audit confirmed proper timeout implementation | src/asfquart/generics.py:45-48 |
| Ch06 | OAuth states are single-use (popped on consumption) | 6.4.1 audit confirmed single-use enforcement | src/asfquart/generics.py:45-48 |
| Ch06 | Passwords can be of any composition without character type restrictions | 6.2.5 passed - no artificial password composition rules enforced | — |
| Ch06 | Passwords are verified exactly as received without modification | 6.2.8 passed - no truncation or case transformation applied | — |
| Ch06 | No default accounts present or they are disabled | 6.3.2 passed - no root/admin/sa accounts found | — |
| Ch06 | No password hints or knowledge-based authentication present | 6.4.2 passed - no secret questions implemented | — |
| Ch08 | Authorization rules enforced at trusted service layer | 8.3.1 passed - authorization checks performed server-side via decorators | src/asfquart/auth.py |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Partial** | See FINDING-003, FINDING-022 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-004 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Partial** | See FINDING-005 |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Fail** | See FINDING-032 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Fail** | See FINDING-004, FINDING-012, FINDING-033 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Fail** | See FINDING-013 |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Fail** | See FINDING-034 |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Fail** | See FINDING-014, FINDING-035 |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **Fail** | See FINDING-015 |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **Fail** | See FINDING-006 |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** | See FINDING-035 |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Fail** | See FINDING-016, FINDING-036 |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Fail** | See FINDING-001, FINDING-018 |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Fail** | See FINDING-001, FINDING-017, FINDING-018 |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Partial** | See FINDING-034 |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Partial** | See FINDING-019 |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Partial** | See FINDING-037 |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Fail** | See FINDING-002, FINDING-019 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Fail** | See FINDING-002 |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Partial** | See FINDING-020 |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Partial** | See FINDING-038 |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Fail** | See FINDING-021 |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Pass** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Pass** |  |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** |  |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** |  |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** |  |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** |  |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **N/A** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **N/A** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **N/A** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Partial** | See FINDING-023, FINDING-024 |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Partial** | See FINDING-006, FINDING-025 |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Partial** | See FINDING-007, FINDING-026 |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Fail** | See FINDING-027 |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Partial** | See FINDING-008, FINDING-009 |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Partial** | See FINDING-028 |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Fail** | See FINDING-010 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Fail** | See FINDING-029 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Fail** | See FINDING-011, FINDING-030, FINDING-031 |

**Summary Statistics:**
- **Pass**: 16 requirements (22.9%)
- **Partial**: 13 requirements (18.6%)
- **N/A**: 24 requirements (34.3%)
- **Fail**: 17 requirements (24.3%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | High | 6.1.1, 6.3.1 | FINDING-017 | src/asfquart/session.py |
| FINDING-002 | High | 7.4.1, 7.4.2 | FINDING-019 | src/asfquart/session.py, src/asfquart/generics.py, src/asfquart/auth.py |
| FINDING-003 | Medium | 1.2.1 | FINDING-022 | src/asfquart/generics.py |
| FINDING-004 | Medium | 1.2.2, 2.2.1 | — | src/asfquart/generics.py |
| FINDING-005 | Medium | 1.2.4 | FINDING-012 | src/asfquart/session.py |
| FINDING-006 | Medium | 12.2.1, 3.4.1 | FINDING-025 | src/asfquart/base.py |
| FINDING-007 | Medium | 12.2.2 | — | src/asfquart/base.py |
| FINDING-008 | Medium | 14.2.1 | — | src/asfquart/generics.py |
| FINDING-009 | Medium | 14.2.1 | — | src/asfquart/session.py |
| FINDING-010 | Medium | 15.1.1 | FINDING-029 | pyproject.toml |
| FINDING-011 | Medium | 15.3.1 | FINDING-030 | src/asfquart/generics.py |
| FINDING-012 | Medium | 2.2.1 | FINDING-005 | src/asfquart/ldap.py |
| FINDING-013 | Medium | 2.2.2 | FINDING-018, FINDING-034 | src/asfquart/utils.py |
| FINDING-014 | Medium | 3.2.1 | — | src/asfquart/base.py, src/asfquart/generics.py |
| FINDING-015 | Medium | 3.3.1 | — | src/asfquart/base.py |
| FINDING-016 | Medium | 3.5.3 | — | src/asfquart/generics.py |
| FINDING-017 | Medium | 6.3.1 | FINDING-001 | src/asfquart/session.py |
| FINDING-018 | Medium | 6.1.1, 6.3.1 | FINDING-013, FINDING-034 | src/asfquart/generics.py |
| FINDING-019 | Medium | 7.4.1, 7.2.2 | FINDING-002 | src/asfquart/session.py |
| FINDING-020 | Medium | 8.1.1 | FINDING-038 | docs/auth.md, docs/sessions.md |
| FINDING-021 | Medium | 8.2.2 | — | src/asfquart/auth.py |
| FINDING-022 | Low | 1.2.1 | FINDING-003 | src/asfquart/generics.py |
| FINDING-023 | Low | 12.1.1 | FINDING-024 | src/asfquart/generics.py |
| FINDING-024 | Low | 12.1.1 | FINDING-023 | src/asfquart/ldap.py |
| FINDING-025 | Low | 12.2.1 | FINDING-006 | src/asfquart/base.py |
| FINDING-026 | Low | 12.2.2 | — | src/asfquart/base.py |
| FINDING-027 | Low | 13.4.1 | — | — |
| FINDING-028 | Low | 14.3.1 | — | src/asfquart/generics.py |
| FINDING-029 | Low | 15.2.1 | FINDING-010 | pyproject.toml |
| FINDING-030 | Low | 15.3.1 | FINDING-011 | src/asfquart/generics.py |
| FINDING-031 | Low | 15.3.1 | — | src/asfquart/utils.py |
| FINDING-032 | Low | 2.1.1 | — | Multiple files (framework-wide) |
| FINDING-033 | Low | 2.2.1 | — | src/asfquart/utils.py |
| FINDING-034 | Low | 2.3.1, 6.4.1 | FINDING-013, FINDING-018 | src/asfquart/generics.py |
| FINDING-035 | Low | 3.2.1, 3.5.1 | — | src/asfquart/generics.py |
| FINDING-036 | Low | 3.5.3 | — | src/asfquart/generics.py |
| FINDING-037 | Low | 7.2.4 | — | src/asfquart/generics.py |
| FINDING-038 | Low | 8.2.1 | FINDING-020 | src/asfquart/auth.py |

**Total Unique Findings**: 38 (0 Critical, 2 High, 19 Medium, 17 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 38 |

**Total consolidated findings: 38**

*End of Consolidated Security Audit Report*