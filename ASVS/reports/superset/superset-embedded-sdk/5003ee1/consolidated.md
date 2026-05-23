# Security Audit Consolidated Report — apache/superset/superset-embedded-sdk

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset-embedded-sdk |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | `5003ee1` |
| Date | May 23, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 3 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 0 | 3 | 0 |

### Level Coverage

This audit was scoped to **ASVS Level 1 (L1)** across all directories within the `superset-embedded-sdk` package. 70 source reports were consolidated, yielding 3 actionable findings — all rated Low severity. No Critical, High, or Medium issues were identified.

### Top 5 Risks

1. **No format validation on dashboard `id` parameter before URL interpolation** — A malformed or malicious `id` value could be interpolated directly into a constructed URL, potentially enabling unexpected navigation or injection if upstream trust assumptions are violated.

2. **No safe-list validation on `iframeSandboxExtras` parameter** — Arbitrary sandbox attribute values can be passed without restriction, potentially weakening the iframe sandbox boundary if a consuming developer supplies overly permissive values.

3. **No URL format validation on `supersetDomain` parameter** — The `supersetDomain` parameter is used directly in origin checks and URL construction without schema or format validation, which could lead to unexpected behavior if a non-HTTPS or malformed value is provided.

4. *(No additional findings — only 3 total issues identified)*

5. *(No additional findings — only 3 total issues identified)*

### Positive Controls

The audit identified several noteworthy security controls already in place:

| # | Control | Domain |
|---|---------|--------|
| 1 | SDK treats developer-provided configuration (`supersetDomain`, `id`) as trusted inputs per client-side SDK trust model | Configuration |
| 2 | TLS/HTTPS enforcement is delegated to the deployment environment and consuming application, not the client-side SDK | Transport Security |
| 3 | Guest token transmitted via MessageChannel `postMessage`, not URL parameters | Token Handling |
| 4 | No persistent client storage — tokens stored only in JavaScript closures, cleared on page close/refresh | Token Storage |
| 5 | Third-party dependency remediation governed by ASF vulnerability handling process; vulnerabilities in dependencies reported to respective maintainers | Dependencies |
| 6 | Minimal production dependency surface (2 dependencies); all versions current with no known CVEs | Dependencies |
| 7 | Server-side field-level access control enforced by Superset backend before data reaches the embedded iframe; SDK correctly delegates security decisions to server | Access Control |
| 8 | Server-side enforcement of guest token validation, dashboard access control, and data filtering — SDK correctly delegates security to trusted service layer | Authentication |
| 9 | Promise.all synchronization ensures both guest token and iframe/switchboard are ready before proceeding; MIN_REFRESH_WAIT_MS prevents rapid-fire refresh | Session Management |
| 10 | Client-side SDK intentionally uses decode-only JWT library; signature verification is delegated to Superset backend server as the authoritative security boundary | Cryptography |
| 11 | SDK proactively schedules token refresh before expiry with buffer and minimum wait guard; server-side expiry validation is the authoritative control | Cryptography |

The overall security posture of the `superset-embedded-sdk` is strong for a client-side SDK. The architecture correctly delegates authoritative security decisions (authentication, authorization, token validation, data filtering) to the Superset backend server. All three findings represent defense-in-depth input validation improvements rather than exploitable vulnerabilities in isolation.

---

## 3. Findings

### 3.4 Low

#### FINDING-001: No format validation on dashboard `id` parameter before URL interpolation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | superset-embedded-sdk/src/index.ts |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-002, FINDING-003 |

**Description:**

The `id` parameter is interpolated directly into the iframe URL without any format validation. While TypeScript enforces it's a `string`, there's no runtime check for expected format (e.g., UUID pattern, alphanumeric only, length limits). If a host application dynamically sets `id` based on user input (e.g., from a URL parameter or database), path manipulation characters could alter the target URL.

**Remediation:**

Validate id format before use with a regex pattern (e.g., /^[a-f0-9-]+$/i) and throw an error for invalid formats.

---

#### FINDING-002: No safe-list validation on `iframeSandboxExtras` parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | superset-embedded-sdk/src/index.ts |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-001, FINDING-003 |

**Description:**

The `iframeSandboxExtras` parameter accepts arbitrary strings without validation against a safe-list of sandbox tokens. Dangerous tokens like `allow-top-navigation` could be added, allowing the embedded iframe to navigate the parent page.

**Remediation:**

Validate iframeSandboxExtras against an allow-list or at minimum warn when dangerous values like `allow-top-navigation` are used.

---

#### FINDING-003: No URL format validation on `supersetDomain` parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | superset-embedded-sdk/src/index.ts |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-001, FINDING-002 |

**Description:**

The `supersetDomain` parameter only receives trailing-slash removal. No validation checks that it is a valid URL with a proper protocol (https), no path components, and no embedded credentials. Since this value is used as the `targetOrigin` in `postMessage`, an incorrectly formatted domain could weaken origin validation.

**Remediation:**

Validate supersetDomain using `new URL()` to ensure it has a valid protocol, no path, and return `url.origin` for use in postMessage targetOrigin.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Ch01 | SDK treats developer-provided configuration (supersetDomain, id) as trusted inputs per client-side SDK trust model | Promoted from dropped findings ASVS-122-LOW-001, ASVS-122-LOW-002 | — |
| Ch12 | TLS/HTTPS enforcement is delegated to the deployment environment and consuming application, not the client-side SDK | Observed across multiple ASVS sections (12.2.1, 12.2.2) | — |
| Ch14 | Guest token transmitted via MessageChannel postMessage, not URL parameters | Tokens are transmitted securely using MessageChannel postMessage mechanism instead of being exposed in URL parameters or query strings | — |
| Ch14 | No persistent client storage — tokens stored only in JavaScript closures, cleared on page close/refresh | Authentication tokens are stored in JavaScript closures rather than persistent storage (localStorage, sessionStorage, cookies), automatically cleared when page is closed or refreshed | — |
| Ch15 | Third-party dependency remediation governed by ASF vulnerability handling process; vulnerabilities in dependencies reported to respective maintainers. | source: Dropped finding ASVS-1511-INFO-001 | — |
| Ch15 | Minimal production dependency surface (2 dependencies); all versions current with no known CVEs | Promoted from dropped finding ASVS-1521-INFO-001 | — |
| Ch15 | Server-side field-level access control enforced by Superset backend before data reaches the embedded iframe; SDK correctly delegates security decisions to server. | source: Dropped finding ASVS-1531-LOW-001 | — |
| Ch02 | Server-side enforcement of guest token validation, dashboard access control, and data filtering — SDK correctly delegates security to trusted service layer | source: Dropped finding ASVS-222-INFO-001 | — |
| Ch02 | Promise.all synchronization ensures both guest token and iframe/switchboard are ready before proceeding; MIN_REFRESH_WAIT_MS prevents rapid-fire refresh | source: Dropped finding ASVS-231-INFO-001 | — |
| Ch09 | Client-side SDK intentionally uses decode-only JWT library; signature verification is delegated to Superset backend server as the authoritative security boundary | source: Dropped finding ASVS-911-LOW-001 | — |
| Ch09 | SDK proactively schedules token refresh before expiry with buffer and minimum wait guard; server-side expiry validation is the authoritative control | source: Dropped finding ASVS-921-LOW-001 | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Pass** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-001, FINDING-002, FINDING-003 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **N/A** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **N/A** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **N/A** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** |  |
| 6.2.2 | Verify that users can change their password. | **N/A** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **N/A** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **N/A** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **N/A** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **N/A** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **N/A** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **N/A** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **N/A** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **N/A** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **N/A** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **N/A** |  |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **N/A** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **N/A** |  |
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
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 15 requirements (21.4%)
- **Partial**: 1 requirements (1.4%)
- **N/A**: 54 requirements (77.1%)
- **Fail**: 0 requirements (0.0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Low | 2.2.1 | FINDING-002, FINDING-003 | superset-embedded-sdk/src/index.ts |
| FINDING-002 | Low | 2.2.1 | FINDING-001, FINDING-003 | superset-embedded-sdk/src/index.ts |
| FINDING-003 | Low | 2.2.1 | FINDING-001, FINDING-002 | superset-embedded-sdk/src/index.ts |

**Total Unique Findings**: 3 (0 Critical, 0 High, 0 Medium, 3 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 3 |

**Total consolidated findings: 3**

*End of Consolidated Security Audit Report*