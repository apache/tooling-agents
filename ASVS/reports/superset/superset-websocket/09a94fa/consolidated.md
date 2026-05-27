# Security Audit Consolidated Report — apache/superset/superset-websocket

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset-websocket |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | `09a94fa` |
| Date | May 27, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 4 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 1 | 3 | 0 |

### Level Coverage

This audit was scoped to **ASVS Level 1 (L1)** across all directories within the `superset-websocket` sidecar service. All 4 findings are actionable and map to L1 verification requirements. No findings were excluded by severity threshold.

### Top 5 Risks

1. **Cross-Site WebSocket Hijacking (CSWSH)** — The WebSocket upgrade handler does not validate the `Origin` header, allowing a malicious page to establish an authenticated WebSocket connection on behalf of a victim whose browser automatically sends the session cookie. This is the highest-severity finding (Medium) and could lead to unauthorized real-time data access.

2. **Missing format validation for `last_id` query parameter** — The `last_id` parameter accepted during WebSocket connection is not validated for expected format, potentially enabling unexpected Redis query behavior or minor information leakage through error paths.

3. **No JWT expiration enforcement** — While the `jsonwebtoken` library's default behavior preserves `exp` claim checking, the application does not explicitly mandate or enforce token expiration, allowing tokens without an `exp` claim to remain valid indefinitely.

4. **No mechanism to invalidate or rotate WebSocket sessions on JWT compromise** — Once a WebSocket connection is established, there is no server-side mechanism to revoke the session if the underlying JWT is compromised, nor is there periodic re-validation of token validity during long-lived connections.

5. *(No fifth risk — only 4 findings identified.)*

### Positive Controls

The audit identified **18 positive security controls** that contribute to the overall security posture of the service:

- **TLS and Transport Security**: Node.js 22 engine requirement ensures secure TLS defaults (TLSv1.2 minimum). Redis TLS with hostname validation is available and configurable. The sidecar architecture properly delegates external TLS termination to a reverse proxy/ingress controller, with HSTS handled at the infrastructure layer.

- **Dependency Management**: Third-party dependency vulnerability management is governed by ASF Security Team processes. Lockfile enforcement via `npm ci` ensures reproducible, pinned dependency resolution regardless of declared semver ranges.

- **Authentication & Session Integrity**: JWT signature verification ensures cookie content integrity. A secure default algorithm allowlist (`['HS256']`) is enforced with no environment variable override path. Library default `exp`/`nbf` validation is preserved (`ignoreExpiration` not set). Channel isolation via JWT ensures users only receive events from their authorized channel.

- **Input/Output Safety**: Minimal HTTP surface with only static hardcoded response bodies eliminates reflected content risks. WebSocket messages use safe JSON serialization with no user-controlled content reflected in HTTP responses. Response bodies are static strings, eliminating MIME-sniffing exploitation vectors.

- **Infrastructure Delegation**: Rate limiting is delegated to reverse proxy/deployment infrastructure. CORS configuration is properly implemented. The WebSocket server uses `noServer` mode compatible with TLS-terminating reverse proxies.

- **Development Hygiene**: Test utility (`utils/client-ws-app`) is development-only tooling not deployed to production.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: Cross-Site WebSocket Hijacking (CSWSH) - Missing Origin Validation on WebSocket Upgrade

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-346 |
| **ASVS sections** | 3.5.1, 3.5.3 |
| **Files** | superset-websocket/src/index.ts |
| **Source Reports** | 3.5.1.md, 3.5.3.md |
| **Related** | None |

**Description:**

The httpUpgrade handler in the WebSocket server authenticates connections using JWT cookies but does not validate the Origin or Sec-Fetch-* headers. This allows an attacker-controlled web page to establish an authenticated WebSocket connection using the victim's automatically sent cookies (if SameSite attribute permits cross-site sending). The attacker can then receive real-time async query result events intended for the victim on their channel, leading to unauthorized access to sensitive data streams.

**Remediation:**

Add Origin header validation in the httpUpgrade handler to reject cross-origin WebSocket connections. Alternatively, validate Sec-Fetch-Site header to ensure requests originate from same-origin. Implement a configurable allowedOrigins list to specify trusted origins. Ensure the JWT cookie has appropriate SameSite attribute (Strict or Lax) as defense-in-depth.

---

### 3.4 Low

#### FINDING-002: Missing format validation for last_id query parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | superset-websocket/src/index.ts |
| **Source Report(s)** | 2.2.1.md |
| **Related Finding(s)** | - |

**Description:**

The `last_id` parameter is not validated against the expected Redis stream ID format (`\d+-\d+`). Malformed inputs like `last_id=abc-xyz` produce `abc-NaN` after `incrementId`. While Redis handles these gracefully and the user can only query their own channel's stream, no positive validation enforces the expected format.

**Remediation:**

Add regex validation (`/^\d{1,15}-\d{1,10}$/`) to `getLastId` before processing, returning null for invalid formats.

---

#### FINDING-003: No JWT expiration enforcement allows indefinite token validity

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.2.2 |
| **File(s)** | superset-websocket/src/index.ts |
| **Source Report(s)** | 7.2.2.md |
| **Related Finding(s)** | FINDING-004 |

**Description:**

JWT verification in `readChannelId()` does not use `maxAge` option, allowing tokens to remain valid indefinitely regardless of age. Requires possession of a leaked/stolen JWT token. Impact: indefinite WebSocket access to event stream for the channel embedded in the JWT.

**Remediation:**

Add `maxAge` option to `jwt.verify()` to enforce maximum token lifetime, e.g., `maxAge: opts.jwtMaxAge || '1h'`.

---

#### FINDING-004: No mechanism to invalidate or rotate WebSocket sessions on JWT compromise

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.2.4, 7.4.1, 7.4.2 |
| **File(s)** | superset-websocket/src/index.ts |
| **Source Report(s)** | 7.2.4.md, 7.4.1.md, 7.4.2.md |
| **Related Finding(s)** | FINDING-003 |

**Description:**

Once a WebSocket connection is established, it remains active regardless of whether the original JWT or the user's session in the main application has been revoked. This is a defense-in-depth gap. WebSocket connections are inherently persistent, and the data accessible through this channel (async query status events) has limited sensitivity. Exploitation requires prior token compromise.

**Remediation:**

Add user ID tracking to SocketInstance, implement a Redis pub/sub subscription for account lifecycle events (user:disabled, user:deleted), and terminate all associated WebSocket connections upon receiving such events.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Ch12 | Node.js 22 engine requirement ensures secure TLS defaults (minVersion TLSv1.2) | Package.json enforces Node.js 22 runtime with secure TLS configuration | — |
| Ch12 | Redis TLS with hostname validation is available and configurable | Redis client supports TLS configuration with hostname validation for secure backend connections | — |
| Ch12 | Sidecar architecture delegates TLS termination to deployment infrastructure (reverse proxy/ingress controller) | WebSocket sidecar designed for deployment behind TLS-terminating reverse proxy for external-facing HTTPS | — |
| Ch15 | Third-party dependency vulnerability management delegated to ASF Security Team processes and dependency maintainers | Documented in SECURITY.md with foundation-level processes governing dependency management | — |
| Ch15 | Lockfile enforcement via npm ci ensures reproducible, pinned dependency resolution regardless of declared semver ranges | Promoted from dropped finding ASVS-1521-LOW-001 | — |
| Ch15 | Channel isolation via JWT ensures users only receive events from their own authorized channel, limiting any information disclosure scope | Promoted from dropped finding ASVS-1531-LOW-001 | — |
| Ch03 | Minimal HTTP surface with only static hardcoded response bodies eliminates reflected content risks | Application does not reflect user-controlled content in HTTP responses | — |
| Ch03 | No user-controlled content in HTTP responses; WebSocket messages use JSON serialization | Content rendering uses safe JSON serialization for WebSocket messages | — |
| Ch03 | JWT signature verification ensures cookie content integrity regardless of cookie prefix | JWT validation provides cryptographic verification of cookie authenticity | — |
| Ch03 | Transport security delegated to TLS-terminating reverse proxy by design | HSTS and transport security handled at infrastructure layer | — |
| Ch03 | CORS configuration properly implemented | Section 3.4.2 passed validation | — |
| Ch04 | Response bodies are static strings with no user-controlled data reflected, eliminating MIME-sniffing exploitation vectors | ASVS 4.1.1 audit - no Content-Type header issues identified due to static response content | — |
| Ch04 | WebSocket server uses noServer mode compatible with TLS-terminating reverse proxy; TLS delegated to deployment infrastructure | ASVS 4.4.1 audit - WebSocket security handled at infrastructure layer | — |
| Ch04 | Redis TLS support properly implemented with configurable hostname validation | ASVS 4.4.1 audit - secure Redis connections with TLS validation | — |
| Ch06 | Rate limiting delegated to reverse proxy / deployment infrastructure | Documented in SECURITY.md as delegated to deployment infrastructure | — |
| Ch07 | Test utility (utils/client-ws-app) is development-only tooling, not deployed to production | source: Dropped finding ASVS-741-LOW-001 | — |
| Ch09 | Secure default algorithm allowlist ['HS256'] with no environment variable override path | Promoted from dropped finding ASVS-912-LOW-001 | — |
| Ch09 | Library default exp/nbf validation preserved; ignoreExpiration not set | source: Dropped finding ASVS-921-LOW-001 | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Pass** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-002 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **N/A** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Fail** | See FINDING-001 |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Fail** | See FINDING-001 |
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
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Partial** | See FINDING-003 |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Partial** | See FINDING-004 |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Fail** | See FINDING-004 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Fail** | See FINDING-004 |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** |  |
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
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Pass** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Pass** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Pass** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 24 requirements (34.3%)
- **Partial**: 3 requirements (4.3%)
- **N/A**: 39 requirements (55.7%)
- **Fail**: 4 requirements (5.7%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 3.5.1, 3.5.3 | — | superset-websocket/src/index.ts |
| FINDING-002 | Low | 2.2.1 | — | superset-websocket/src/index.ts |
| FINDING-003 | Low | 7.2.2 | FINDING-004 | superset-websocket/src/index.ts |
| FINDING-004 | Low | 7.2.4, 7.4.1, 7.4.2 | FINDING-003 | superset-websocket/src/index.ts |

**Total Unique Findings**: 4 (0 Critical, 0 High, 1 Medium, 3 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 4 |

**Total consolidated findings: 4**

*End of Consolidated Security Audit Report*