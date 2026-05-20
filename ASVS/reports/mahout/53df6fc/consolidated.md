# Security Audit Consolidated Report — apache/mahout

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/mahout |
| Branch | v0.6-stable |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | 53df6fc |
| Date | May 20, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 10 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 4 | 6 | 0 |

All 10 findings are actionable. No critical or high severity issues were identified. The four medium-severity findings center on path traversal and input validation gaps, while the six low-severity findings relate to documentation deficiencies, missing precondition checks, and insufficient format verification.

### Level Coverage

This audit was scoped to **ASVS Level 1 (L1)**. All findings map to L1 verification requirements across chapters 2 (Authentication/Verification), 5 (Validation, Sanitization & Encoding), and 15 (Software Composition & Configuration).

### Top 5 Risks

1. **Path traversal in `encode_from_file`** (FINDING-002) — User-supplied file paths are not validated against directory traversal sequences, potentially allowing access to files outside expected directories.
2. **Path traversal in `QuantumDataLoader.source_file()`** (FINDING-004) — Similar lack of traversal prevention in the data loading pipeline, compounding the attack surface for file-based operations.
3. **No explicit file size limit before parsing** (FINDING-003) — Absent upper-bound checks on input file size create a denial-of-service vector through resource exhaustion during parsing.
4. **Missing remediation timeframes for third-party vulnerabilities** (FINDING-001) — No documented policy defining acceptable timelines for patching known vulnerabilities in dependencies.
5. **Unable to verify component freshness** (FINDING-005) — Absence of dependency manifests and remediation policy prevents verification that third-party components are current and free of known vulnerabilities.

### Positive Controls

The audit identified the following effective security controls already in place:

| Control | Evidence | Relevant Files |
|---------|----------|----------------|
| Input validation is enforced at trusted service layer (Rust core) | 2.2.2 audit passed — validation occurs in Rust core, not relying on Python client-side checks | — |
| `torch.load` called with `weights_only=True` | Mitigates arbitrary code execution from pickle deserialization in PyTorch model loading | `qdp/qdp-python/qumat_qdp/loader.py` |

These controls demonstrate security-conscious design decisions in critical areas of deserialization and trust boundary enforcement, reducing the overall risk posture of the repository.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: Missing documented remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **File(s)** | dev/release.md, Project-wide |
| **Source Report(s)** | 15.1.1.md |
| **Related** | None |

**Description:**

The project uses numerous third-party dependencies (Rust crates and Python packages) but provides no documentation defining risk-based remediation timeframes for known vulnerabilities in dependencies, update cadence expectations for third-party libraries, or classification of components by risk level.

**Remediation:**

Create a SECURITY.md or docs/security-policy.md document defining remediation timeframes by severity, dangerous functionality components, update cadence, and risky components tracking.

---

#### FINDING-002: Path traversal not validated in encode_from_file

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 2.2.1, 5.3.2 |
| **File(s)** | qdp/qdp-python/src/engine.rs |
| **Source Report(s)** | 2.2.1.md, 5.3.2.md |
| **Related** | FINDING-004 |

**Description:**

The `encode_from_file` function validates file extension but does not validate the `path` string against path traversal patterns or null bytes before passing it to the core for file I/O operations. While this is a library (not a web endpoint), the `encode()` function accepts arbitrary strings and routes them to file operations based on duck-typing heuristics.

**Remediation:**

Add optional path sanitization: reject paths with null bytes, and document that applications accepting user-provided paths should validate/restrict them before passing to encode(). Consider adding an optional `allowed_paths` or `base_directory` parameter.

---

#### FINDING-003: No explicit file size limit before parsing input files

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-400 |
| **ASVS Section(s)** | 5.2.1 |
| **File(s)** | qdp/qdp-python/src/engine.rs, qdp/qdp-core/src/lib.rs |
| **Source Report(s)** | 5.2.1.md |
| **Related** | None |

**Description:**

File-based encoding paths accept files without explicit pre-processing size limits. No explicit file size check before beginning to parse or load the file content. While `ensure_device_memory_available` validates GPU memory for OUTPUT allocation, there is no corresponding check on INPUT file size before the file is opened, read, and parsed. Denial of service through host memory exhaustion during file parsing, before the GPU pre-flight memory checks are reached.

**Remediation:**

Add a max_file_size parameter or configuration, or implement a Rust-level validate_file_size function that checks file metadata before parsing begins.

---

#### FINDING-004: No path traversal prevention in QuantumDataLoader.source_file()

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **File(s)** | qdp/qdp-python/qumat_qdp/loader.py |
| **Source Report(s)** | 5.3.2.md |
| **Related** | FINDING-002 |

**Description:**

User-provided path string is stored directly in self._file_path and passed to os.path.exists(), torch.load(), np.load(), or Rust create_file_loader without any path traversal sanitization. An attacker could read arbitrary files on the filesystem that have supported extensions when the library is used in a context where file paths originate from external input.

**Remediation:**

Canonicalize paths using os.path.realpath(os.path.abspath(path)), reject path traversal sequences ('..'), and optionally restrict to allowed base directories.

### 3.4 Low

#### FINDING-005: Unable to verify component freshness due to missing remediation policy and dependency manifests

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **File(s)** | Project-wide |
| **Source Report(s)** | 15.2.1.md |
| **Related Finding(s)** | None |

**Description:**

Since ASVS 15.1.1 identified that no remediation timeframes are documented, it is impossible to verify whether current dependencies comply with those (non-existent) timeframes. No cargo audit or cargo deny output is provided to verify absence of known vulnerabilities. No CI configuration was provided to confirm automated vulnerability scanning.

**Remediation:**

Add cargo audit to CI pipeline, add cargo deny for license and vulnerability checking, and once 15.1.1 is addressed with documented timeframes, verify all current dependencies comply.

---

#### FINDING-006: QuMat class exposes internal implementation details as public attributes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.3.1 |
| **File(s)** | qumat/qumat.py |
| **Source Report(s)** | 15.3.1.md |
| **Related Finding(s)** | None |

**Description:**

The QuMat class exposes internal implementation details as public attributes (backend_config, backend_module, backend, circuit, parameters) that are not part of the intended public API surface. Any code holding a reference to a QuMat instance can access the full backend_config dictionary, the raw backend module reference, and internal parameters dict. While this is a library (not a web service), it violates the principle of minimal exposure and could leak configuration details if the instance is inadvertently serialized or logged.

**Remediation:**

Use Python name-mangling or property accessors for internal state. Prefix internal attributes with underscore and expose only necessary read-only properties.

---

#### FINDING-007: Incomplete documentation of input validation rules per encoding method

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.1.1 |
| **File(s)** | qdp/qdp-python/src/engine.rs |
| **Source Report(s)** | 2.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The `encode` method's docstring documents accepted input types and encoding methods, but does not specify numerical constraints (e.g., amplitude encoding requires non-zero-norm data, angle encoding requires exactly `num_qubits` features per sample, basis encoding requires integer-valued indices in `[0, 2^num_qubits)`). These rules are enforced by the core but not documented at the API boundary.

**Remediation:**

Expand the docstring to specify all validation rules per encoding method including constraints for amplitude (non-zero L2 norm, no NaN/Inf), angle (exactly num_qubits values), basis (integer values in range), iqp, and iqp-z encodings.

---

#### FINDING-008: No dimension validation after loading torch files

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | qdp/qdp-python/qumat_qdp/loader.py |
| **Source Report(s)** | 2.2.1.md |
| **Related Finding(s)** | None |

**Description:**

When using the PyTorch backend fallback for `.pt`/`.pth` files, the loader calls `torch.load(path, weights_only=True)` without validating the structure of the loaded data beyond checking it's a `torch.Tensor`. No validation that tensor dimensions are compatible with the configured `num_qubits` or `encoding_method` before attempting encoding.

**Remediation:**

Add dimension validation immediately after loading: check ndim is 1 or 2, and validate feature dimension compatibility with the encoding method.

---

#### FINDING-009: measure_overlap does not enforce expected circuit state precondition

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1 |
| **File(s)** | qumat/qumat.py |
| **Source Report(s)** | 2.3.1.md |
| **Related Finding(s)** | None |

**Description:**

The `measure_overlap` method appends gates to the current circuit state without verifying the circuit is in a clean/expected state. If called on a circuit that already has gates applied, the swap test protocol will produce incorrect (but not obviously erroneous) results, because it assumes the circuit starts in a specific state.

**Remediation:**

Document the precondition clearly or add a guard that checks whether the circuit is in the expected initial state before proceeding with the swap test.

---

#### FINDING-010: No explicit magic byte verification before dispatching to format-specific parsers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-434 |
| **ASVS Section(s)** | 5.2.2 |
| **File(s)** | qdp/qdp-python/src/engine.rs, qdp/qdp-core/src/lib.rs |
| **Source Report(s)** | 5.2.2.md |
| **Related Finding(s)** | None |

**Description:**

The library validates file extensions against an allowlist but does not perform explicit magic byte verification before dispatching to the appropriate parser. A file named `malicious.parquet` that is actually a different file type would be passed to the Parquet parser, which would reject it during parsing — but only after potentially beginning to process it. Impact is low because parsing libraries themselves provide content validation by failing on invalid format, this is a local library, and no code execution occurs from file content.

**Remediation:**

Implement lightweight magic byte verification before dispatching to format-specific parsers, particularly for formats with well-known signatures (Parquet `PAR1`, NumPy `\x93NUMPY`).

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Ch02 | Input validation is enforced at trusted service layer (Rust core) | 2.2.2 audit passed - validation occurs in Rust core, not relying on Python client-side checks | — |
| Ch05 | torch.load called with weights_only=True | Mitigates arbitrary code execution from pickle deserialization in PyTorch model loading | qdp/qdp-python/qumat_qdp/loader.py |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **N/A** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **N/A** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-007 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-002, FINDING-008 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Partial** | See FINDING-009 |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** |  |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **N/A** |  |
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
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Fail** | See FINDING-003 |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Partial** | See FINDING-010 |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** |  |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Fail** | See FINDING-002, FINDING-004 |
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
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **N/A** |  |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **N/A** |  |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** |  |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **N/A** |  |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **N/A** |  |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** |  |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **N/A** |  |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **N/A** |  |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **N/A** |  |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **N/A** |  |
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
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **N/A** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Fail** | See FINDING-001 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Fail** | See FINDING-005 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Partial** | See FINDING-006 |

**Summary Statistics:**
- **Pass**: 1 requirements (1.4%)
- **Partial**: 5 requirements (7.1%)
- **N/A**: 60 requirements (85.7%)
- **Fail**: 4 requirements (5.7%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 15.1.1 | — | dev/release.md, Project-wide |
| FINDING-002 | Medium | 2.2.1, 5.3.2 | FINDING-004 | qdp/qdp-python/src/engine.rs |
| FINDING-003 | Medium | 5.2.1 | — | qdp/qdp-python/src/engine.rs, qdp/qdp-core/src/lib.rs |
| FINDING-004 | Medium | 5.3.2 | FINDING-002 | qdp/qdp-python/qumat_qdp/loader.py |
| FINDING-005 | Low | 15.2.1 | — | Project-wide |
| FINDING-006 | Low | 15.3.1 | — | qumat/qumat.py |
| FINDING-007 | Low | 2.1.1 | — | qdp/qdp-python/src/engine.rs |
| FINDING-008 | Low | 2.2.1 | — | qdp/qdp-python/qumat_qdp/loader.py |
| FINDING-009 | Low | 2.3.1 | — | qumat/qumat.py |
| FINDING-010 | Low | 5.2.2 | — | qdp/qdp-python/src/engine.rs, qdp/qdp-core/src/lib.rs |

**Total Unique Findings**: 10 (0 Critical, 0 High, 4 Medium, 6 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 10 |

**Total consolidated findings: 10**

*End of Consolidated Security Audit Report*