# Security Audit Consolidated Report — apache/airflow/task-sdk

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/airflow/task-sdk |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | N/A |
| Date | May 19, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 3 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 1 | 2 | 0 |

### Level Coverage

This audit was scoped to **ASVS Level 1 (L1)** requirements across 13 security domains: sentry_integration, dag_parsing_context, log_masking, provider_plugin_loading, secrets_management, websocket_security, oauth_authorization, http_security_headers, jinja_template_sandboxing, execution_api_authentication, general_security, ipc_serialization, and ch09_general. A total of 70 source reports were consolidated, yielding only 3 findings — indicating a mature security posture for the task-sdk component at the L1 assurance tier.

### Top 5 Risks

1. **Sensitive variable values logged in exception paths** — `Variable.set()` does not mask sensitive values before logging exceptions, potentially exposing secrets in log output (Medium, ASVS 15.3.1).
2. **Inconsistent server URL validation** — Divergent validation logic between `supervise_task` and `supervise_callback` entry points could allow malformed or unexpected server URLs in one path but not the other (Low, ASVS 2.2.1).
3. **Credentials embedded in connection URI representation** — The connection URI format encodes credentials in a query-string-like structure that is susceptible to inadvertent logging or caching by intermediary systems (Low, ASVS 14.2.1).
4. No additional findings at this severity threshold.
5. No additional findings at this severity threshold.

### Positive Controls

The audit identified several well-implemented security controls that materially reduce risk:

- **TLS enforcement and certificate management**: The codebase uses `ssl.create_default_context()` enforcing TLS 1.2+ by default, with no `verify=False` bypass present. Certificate management and HTTPS enforcement for external-facing services are appropriately delegated to the Deployment Manager.
- **Robust session and token management**: Session tokens are dynamically generated, rotated on authentication, validated via digital signature, and invalidated on termination events. Self-contained tokens exclude the `None` algorithm and validate key material against trusted sources (ASVS 7.2.x, 7.4.x, 9.1.x).
- **Secrets management design**: Fernet encryption selection is a deployment-level decision. The `SecretCache` implementation uses memory-only storage with TTL-based expiration within the supervisor trust boundary — documented as intentional design.
- **Template sandboxing**: Jinja2 template output encoding is delegated to trusted DAG authors with `|e` and `|urlencode` filters available, appropriate for the trust model where DAG authors operate within a privileged boundary.
- **Dependency management delegation**: Provider/dependency version management is explicitly delegated to the deployment manager and image builder, with remediation timing determined case-by-case per ASF severity rating methodology rather than generic CVSS timeframes.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: Variable.set() Does Not Mask Sensitive Value Before Logging Exception

| Attribute | Value |
|-----------|-------|
| Severity | 🟡 Medium |
| ASVS Level(s) | L1 |
| CWE | CWE-532 |
| ASVS Sections | 15.3.1 |
| Files | task-sdk/src/airflow/sdk/definitions/variable.py |
| Source Reports | 15.3.1.md |
| Related | None |

**Description:**

The Variable.set() method does not apply masking to sensitive values before potential exception logging. When an exception occurs during the set operation (e.g., network error), the AirflowRuntimeError may expose the raw variable value in logs. While exploitation requires an exception condition and DAG authors are considered trusted users per the project's threat model, this represents a defense-in-depth gap since the codebase has existing masking infrastructure that is applied inconsistently across variable operations.

**Remediation:**

Add `mask_secret(value, name=key)` to `Variable.set()` before the try block to ensure consistent masking across all variable operations. This will prevent sensitive values from appearing in exception messages and logs.

---

### 3.4 Low

#### FINDING-002: Inconsistent Server URL Validation Between supervise_task and supervise_callback

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| **Source Reports** | 2.2.1.md |
| **Related** | None |

**Description:**

supervise_callback does not validate the server URL (scheme, netloc) before passing it to _ensure_client, unlike supervise_task which performs explicit validation. While the server parameter originates from trusted infrastructure configuration, this represents an inconsistency in defensive programming between two parallel entry points.

**Remediation:**

Extract URL validation logic from supervise_task into a shared utility and apply it in supervise_callback for consistency and defense-in-depth.

---

#### FINDING-003: Connection URI Representation Embeds Credentials in Query-String-Like Format Suitable for Logging/Caching

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-598 |
| **ASVS Section(s)** | 14.2.1 |
| **Files** | task-sdk/src/airflow/sdk/definitions/connection.py |
| **Source Reports** | 14.2.1.md |
| **Related** | None |

**Description:**

The Connection.get_uri() method generates URI strings with passwords and extras in query-string format. While this is an internal connection-string representation transmitted via IPC (not HTTP URLs) and mask_secret() is applied on access, the risk exists for accidental logging of the internal format in its unmasked state. The query-string-like structure increases the likelihood of credentials being inadvertently exposed through logging, caching, or tracing mechanisms that may not properly redact these fields.

**Remediation:**

Consider separating sensitive fields from the URI representation for caching purposes, or ensure all logging/tracing redacts URI credentials. Implement a dedicated internal format that does not resemble URL query strings to reduce the risk of accidental exposure through systems that assume standard URL patterns.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Execution Api Authentication | TLS protocol version enforcement delegated to Deployment Manager; code uses ssl.create_default_context() enforcing TLS 1.2+ by default | Profile: delegated_infrastructure_controls.md, ASVS 6.1.1/12.1.1 out-of-scope | — |
| Execution Api Authentication | HTTPS enforcement for external-facing services delegated to Deployment Manager; client enforces TLS verification with no verify=False bypass | Profile: delegated_infrastructure_controls.md, ASVS 12.2.1 out-of-scope | — |
| Execution Api Authentication | Publicly trusted TLS certificate management delegated to Deployment Manager; client uses certifi (Mozilla CA bundle) for verification | Profile: delegated_infrastructure_controls.md, ASVS 12.2.2 out-of-scope | — |
| Execution Api Authentication | Session token verification performed using trusted backend service | ASVS 7.2.1 Pass status | — |
| Execution Api Authentication | Application uses dynamically generated tokens for session management (not static API secrets) | ASVS 7.2.2 Pass status | — |
| Execution Api Authentication | New session token generated on user authentication and current session terminated | ASVS 7.2.4 Pass status | — |
| Execution Api Authentication | Session invalidation enforced at backend on termination events (logout/expiration) | ASVS 7.4.1 Pass status | — |
| Execution Api Authentication | All active sessions terminated when user account is disabled or deleted | ASVS 7.4.2 Pass status | — |
| Execution Api Authentication | Self-contained tokens validated using digital signature or MAC before accepting contents | ASVS 9.1.1 Pass status | — |
| Execution Api Authentication | Token creation and verification restricted to allowlisted algorithms (excludes 'None' algorithm) | ASVS 9.1.2 Pass status | — |
| Execution Api Authentication | Key material for token validation sourced from trusted pre-configured sources; untrusted header sources (jku, x5u, jwk) validated against allowlist | ASVS 9.1.3 Pass status | — |
| Secrets Management | Fernet (AES-128-CBC+HMAC-SHA256) cipher selection is a deployment-level configuration decision; Deployment Manager chooses encryption approach | Dropped finding ASVS-1132-LOW-001 from 11.3.2 audit | — |
| Secrets Management | SecretCache uses memory-only multiprocessing dict with TTL-based expiration (default 15min), disabled by default, team-scoped keys, within supervisor trust boundary — documented as intentional design | Dropped finding ASVS-1431-LOW-001 from 14.3.1 audit | — |
| Jinja Template Sandboxing | Template output encoding is delegated to trusted DAG authors who control output context; Jinja2 \|e and \|urlencode filters are available for use when needed | ASVS 1.2.1 audit - dropped finding ASVS-121-LOW-001 | — |
| Provider Plugin Loading | Remediation timing is intentionally not fixed to generic CVSS-based timeframes; determined case-by-case per ASF severity rating methodology | Documented in security profile - remediation timing depends on issue complexity and potential impact per ASF severity rating methodology | — |
| Provider Plugin Loading | Provider/dependency version management is delegated to the deployment manager and image builder; runtime enforcement is intentionally excluded | Dropped finding ASVS-1521-MED-001 | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** |  |
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
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
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
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **N/A** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Pass** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Pass** |  |
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
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **N/A** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Partial** | See FINDING-003 |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Partial** | See FINDING-001 |

**Summary Statistics:**
- **Pass**: 27 requirements (38.6%)
- **Partial**: 3 requirements (4.3%)
- **N/A**: 40 requirements (57.1%)
- **Fail**: 0 requirements (0.0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 15.3.1 | — | task-sdk/src/airflow/sdk/definitions/variable.py |
| FINDING-002 | Low | 2.2.1 | — | task-sdk/src/airflow/sdk/execution_time/callback_supervisor.py, task-sdk/src/airflow/sdk/execution_time/supervisor.py |
| FINDING-003 | Low | 14.2.1 | — | task-sdk/src/airflow/sdk/definitions/connection.py |

**Total Unique Findings**: 3 (0 Critical, 0 High, 1 Medium, 2 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 3 |

**Total consolidated findings: 3**

*End of Consolidated Security Audit Report*