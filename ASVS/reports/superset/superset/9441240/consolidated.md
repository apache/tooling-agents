# Security Audit Consolidated Report — apache/superset/superset

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/superset/superset |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | 9441240 |
| Date | May 28, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 9 |

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 8 |
| Info | 0 |

### ASVS Level Coverage

This audit covers all thirteen security domains within the repository at ASVS Level 1. All L1 verification requirements applicable to the assessed directories were evaluated, yielding nine actionable findings with no critical or high severity issues.

### Top 5 Risks

1. **MCP service does not check user active status, allowing disabled accounts continued tool access** [Medium] — The MCP service layer bypasses the user-active flag check, permitting deactivated accounts to continue invoking MCP tools until their session naturally expires.
2. **User-supplied filename used in Content-Disposition header without sanitization** [Low] — Filenames originating from user input are placed directly into Content-Disposition response headers without escaping or sanitization, creating a potential header injection vector.
3. **sanitize_clause() MySQL dialect fallback creates parser differential risk** [Low] — When the MySQL dialect is unavailable, the clause sanitization logic falls back to a generic parser that may interpret SQL differently, introducing a risk of filter bypass.
4. **Dynamic dispatch via getattr with user-controlled operation name and kwargs in post-processing execution** [Low] — Post-processing logic resolves operation names from user-supplied input through `getattr`, potentially exposing unintended callable paths despite an existing allowlist.
5. **Guest tokens (self-contained JWTs) lack early revocation mechanism** [Low] — Self-contained guest JWTs have no server-side revocation capability, meaning compromised tokens remain valid until natural expiry.

### Positive Controls Observed

- **TLS protocol version enforcement delegated to deployment infrastructure** — No TLS version downgrade logic exists in application code; protocol selection is handled at the infrastructure layer.
- **HTTPS enforcement delegated to deployment infrastructure** — Configuration knobs are exposed for operators to enforce HTTPS via reverse proxy or load balancer.
- **TLS certificate provisioning delegated to deployment infrastructure** — Outbound requests use the system CA store with `verify=True` by default.
- **TLS termination for WebSocket connections delegated to reverse proxy** — The application provides `wss://` configuration for operators.
- **HSTS enforcement delegated to deployment infrastructure** — Talisman provides development defaults; production HSTS is expected at the reverse proxy layer.
- **Client-side authenticated data properly cleared from browser storage** — Session data is removed on logout.
- **Session token verification performed using trusted backend service** — Tokens are validated server-side, not solely on the client.
- **Dynamic session tokens used instead of static API secrets** — Session management relies on ephemeral tokens.
- **New session token generated on user authentication and re-authentication** — Session fixation is mitigated by token rotation.
- **AUTH_PASSWORD_VALIDATORS configuration knob available** — Flask-AppBuilder exposes an extensibility mechanism for operator-configured breached-password checking.
- **MCP tools require authentication even without RBAC metadata** — Unauthenticated access to MCP tool endpoints is impossible; function-level access control is enforced.
- **File upload restricted to admin role** — Upload functionality is gated behind the fully-trusted admin role per the project's threat model.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: MCP service does not check user active status, allowing disabled accounts continued tool access

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.4.2 |
| **File(s)** | superset/mcp_service/auth.py |
| **Source Report(s)** | 7.4.2.md |
| **Related** | FINDING-005, FINDING-007 |

**Description:**

The MCP service's production JWT auth path in load_user_with_relationships and _setup_user_context does not check User.active status. A disabled user with a valid JWT can continue making MCP tool calls (data queries, chart retrieval, dashboard operations) retaining all RBAC permissions. Flask-Login checks is_active for web sessions but the MCP path bypasses this control.

**Remediation:**

Add `if not getattr(user, 'is_active', True): raise ValueError(...)` check in _setup_user_context() after user loading to align MCP authentication with Flask-Login's standard behavior.

---

### 3.4 Low

#### FINDING-002: User-supplied filename used in Content-Disposition header without sanitization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | superset/charts/data/api.py |
| **Source Report(s)** | 1.2.1.md |
| **Related** | None |

**Description:**

User-supplied filename from request.form.get('filename') is used directly in Content-Disposition header without secure_filename() sanitization. Header injection prevented by Werkzeug's header validation layer, making this a consistency issue rather than exploitable vulnerability.

**Remediation:**

Apply secure_filename() to user-provided filenames in _extract_export_params_from_request() for consistency with the fallback path.

---

#### FINDING-003: sanitize_clause() MySQL dialect fallback creates parser differential risk

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-436 |
| **ASVS Section(s)** | 1.2.4 |
| **File(s)** | superset/sql/parse.py |
| **Source Report(s)** | 1.2.4.md |
| **Related** | None |

**Description:**

When SQL parsing fails for an unknown engine dialect and the script contains backticks, a MySQL dialect fallback is used. This creates a parser differential risk where the validated clause could be interpreted differently by the target database than by the MySQL parser used for validation. Requires an unusual database engine with no sqlglot dialect mapping that interprets backtick-containing SQL differently than MySQL.

**Remediation:**

Add logging when the MySQL fallback is triggered for audit purposes. Consider restricting the fallback to only activate for explicitly configured databases rather than all unknown engines.

---

#### FINDING-004: Dynamic dispatch via getattr with user-controlled operation name and kwargs in post-processing execution

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-470 |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | superset/common/query_object.py |
| **Source Report(s)** | 1.3.2.md |
| **Related** | None |

**Description:**

exec_post_processing() uses getattr(pandas_postprocessing, operation)(df, **options) where operation and options are user-controlled. The only guard is hasattr(pandas_postprocessing, operation) rather than an explicit allowlist. A user can invoke any public attribute of the pandas_postprocessing module with arbitrary keyword arguments.

**Remediation:**

Replace the hasattr check with an explicit allowlist (frozenset) of permitted post-processing operations, aligning with allowlist patterns used elsewhere in the codebase.

---

#### FINDING-005: Guest tokens (self-contained JWTs) lack early revocation mechanism

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 7.4.1 |
| **File(s)** | superset/security/manager.py |
| **Source Report(s)** | 7.4.1.md |
| **Related** | FINDING-001, FINDING-007 |

**Description:**

Guest tokens are self-contained JWTs validated only for signature/expiration/audience with no revocation check. ASVS requires a blocklist, not-before timestamp, or per-user key rotation for self-contained tokens. Access continues until token expiration after admin intends to revoke. Impact bounded by GUEST_TOKEN_JWT_EXP_SECONDS and limited to read-only dashboard viewing.

**Remediation:**

Add a per-embedded-dashboard 'revoked_before' timestamp checked during parse_jwt_guest_token, or reduce GUEST_TOKEN_JWT_EXP_SECONDS to a short value with a refresh endpoint that validates current access state.

---

#### FINDING-006: Algorithm allowlist check is conditional on configuration being set

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-757 |
| **ASVS Section(s)** | 9.1.2 |
| **File(s)** | superset/mcp_service/jwt_verifier.py |
| **Source Report(s)** | 9.1.2.md |
| **Related** | None |

**Description:**

The algorithm enforcement check in `DetailedJWTVerifier.load_access_token()` is conditional on `self.algorithm` being truthy. If `self.algorithm` is not configured, the check is skipped entirely and the token proceeds to decode with any declared algorithm. In practice, authlib's `jwt.decode()` validates algorithm-key type compatibility as a secondary defense, and the parent class constructor typically requires algorithm specification.

**Remediation:**

Make the algorithm check unconditional by raising an error if `self.algorithm` is not configured at initialization time, and remove the `if self.algorithm` guard from the check.

---

#### FINDING-007: No explicit `nbf` (not-before) claim validation in DetailedJWTVerifier

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-613 |
| **ASVS Section(s)** | 9.2.1 |
| **File(s)** | superset/mcp_service/jwt_verifier.py |
| **Source Report(s)** | 9.2.1.md |
| **Related** | FINDING-001, FINDING-005 |

**Description:**

The `DetailedJWTVerifier.load_access_token()` method has an explicit `exp` check but no corresponding explicit `nbf` (not-before) check. A token with a future `nbf` claim could potentially be accepted before its intended activation time. Authlib's `jwt.decode()` may validate `nbf` during decode (caught generically by the `JoseError` handler), but this is not explicitly verified or documented.

**Remediation:**

Add explicit `nbf` validation alongside the `exp` check: if `nbf` is present and greater than current time, reject the token with reason 'Token not yet valid'.

---

#### FINDING-008: ChartPutSchema.query_context missing JSON validation inconsistent with ChartPostSchema

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | superset/charts/schemas.py |
| **Source Report(s)** | 2.2.1.md |
| **Related** | None |

**Description:**

ChartPutSchema.query_context lacks `validate=utils.validate_json` that is present on ChartPostSchema. User-controlled PUT request → ChartPutSchema deserialization (no JSON validation) → stored in database → later parsed as JSON during chart rendering. Attacker capability required: Authenticated user with chart edit permissions. Impact: Data integrity violation — invalid JSON stored in database could cause chart rendering failures.

**Remediation:**

Add `validate=utils.validate_json` to `ChartPutSchema.query_context` to match `ChartPostSchema` behavior.

---

#### FINDING-009: ChartDataProphetOptionsSchema.periods field lacks Range validator despite documented minimum

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1284 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | superset/charts/schemas.py |
| **Source Report(s)** | 2.2.1.md |
| **Related** | None |

**Description:**

The `periods` field in ChartDataProphetOptionsSchema has `min: 0` documented in metadata but no actual Range validator. User-controlled chart data request → ChartDataProphetOptionsSchema deserialization (no Range validation) → passed to Prophet forecasting library → unbounded computation. Attacker capability required: Authenticated user with dataset access who can trigger Prophet post-processing. Impact: Potential computational resource exhaustion (DoS) if extremely large values submitted. The `window` field in `ChartDataRollingOptionsSchema` has the same pattern.

**Remediation:**

Add `Range(min=0, max=10000)` validator to the `periods` field and similar upper bound to `ChartDataRollingOptionsSchema.window`.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Tls And Transport Security | TLS protocol version enforcement delegated to deployment infrastructure; no TLS version downgrade in application code | ASVS section 12.1.1 audit | — |
| Tls And Transport Security | HTTPS enforcement delegated to deployment infrastructure with configuration knobs exposed for operators | ASVS section 12.2.1 audit | — |
| Tls And Transport Security | TLS certificate provisioning delegated to deployment infrastructure; outbound requests use system CA store with verify=True | ASVS section 12.2.2 audit | — |
| Tls And Transport Security | TLS termination for WebSocket connections is delegated to the reverse proxy; application provides wss:// configuration knob for operators | ASVS section 4.4.1 audit | — |
| Http Security Headers | HSTS enforcement delegated to deployment infrastructure (reverse proxy/load balancer); Talisman provides development defaults. | No findings detected in application code; delegation documented in deployment architecture | — |
| Session Management | Client-side authenticated data is properly cleared from browser storage | 14.3.1 passed audit | — |
| Session Management | Session token verification performed using trusted backend service | 7.2.1 passed audit | — |
| Session Management | Dynamic session tokens used instead of static API secrets | 7.2.2 passed audit | — |
| Session Management | New session token generated on user authentication and re-authentication | 7.2.4 passed audit | — |
| Authentication And Password Management | AUTH_PASSWORD_VALIDATORS configuration knob available via Flask-AppBuilder for operator-configured breached-password checking | Promoted from dropped finding ASVS-624-LOW-001 - provides extensibility mechanism for password validation against breached password databases | — |
| Authorization And Rbac | MCP tools require authentication even without RBAC metadata; unauthenticated access is impossible | Observed in 8.2.1 audit - function-level access control enforcement | — |
| File Upload And Csv Import | File upload restricted to admin role, which is fully trusted per threat model | ASVS 5.2.1 audit - dropped finding ASVS-521-LOW-001 | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** | See FINDING-002 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Pass** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **Pass** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** | See FINDING-003 |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **Pass** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Partial** | See FINDING-004 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Pass** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-008, FINDING-009 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Pass** |  |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **Pass** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **Pass** |  |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** |  |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** |  |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **Pass** |  |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **Pass** |  |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **Pass** |  |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **Pass** |  |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Pass** |  |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** |  |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Pass** |  |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Pass** |  |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **Pass** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Pass** |  |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **Pass** |  |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **Pass** |  |
| 6.2.2 | Verify that users can change their password. | **Pass** |  |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **Pass** |  |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** |  |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **Pass** |  |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **Pass** |  |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **Pass** |  |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **Pass** |  |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Pass** |  |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **Pass** |  |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **Pass** |  |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **Pass** |  |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **Pass** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **Pass** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **Pass** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **Partial** | See FINDING-005 |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **Partial** | See FINDING-001 |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Pass** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Pass** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Pass** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** |  |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **Pass** |  |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **Partial** | See FINDING-006 |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **Pass** |  |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **Partial** | See FINDING-007 |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** |  |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** |  |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** |  |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** |  |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** |  |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Pass** |  |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **Pass** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Pass** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Pass** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |

**Summary Statistics:**
- **Pass**: 49 requirements (70.0%)
- **Partial**: 6 requirements (8.6%)
- **N/A**: 15 requirements (21.4%)
- **Fail**: 0 requirements (0.0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 7.4.2 | FINDING-005, FINDING-007 | superset/mcp_service/auth.py |
| FINDING-002 | Low | 1.2.1 | — | superset/charts/data/api.py |
| FINDING-003 | Low | 1.2.4 | — | superset/sql/parse.py |
| FINDING-004 | Low | 1.3.2 | — | superset/common/query_object.py |
| FINDING-005 | Low | 7.4.1 | FINDING-001, FINDING-007 | superset/security/manager.py |
| FINDING-006 | Low | 9.1.2 | — | superset/mcp_service/jwt_verifier.py |
| FINDING-007 | Low | 9.2.1 | FINDING-001, FINDING-005 | superset/mcp_service/jwt_verifier.py |
| FINDING-008 | Low | 2.2.1 | — | superset/charts/schemas.py |
| FINDING-009 | Low | 2.2.1 | — | superset/charts/schemas.py |

**Total Unique Findings**: 9 (0 Critical, 0 High, 1 Medium, 8 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 9 |

**Total consolidated findings: 9**

*End of Consolidated Security Audit Report*