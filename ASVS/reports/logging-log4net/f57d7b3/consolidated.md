# Security Audit Consolidated Report — apache/logging-log4net

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/logging-log4net |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | f57d7b3 |
| Date | May 19, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 2 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|----------|------|--------|-----|------|
| 0 | 0 | 0 | 2 | 0 |

The audit of apache/logging-log4net at ASVS Level 1 produced **2 actionable findings**, both rated **Low** severity. No Critical, High, or Medium issues were identified. This reflects a mature codebase with strong foundational security controls.

### Level Coverage

This audit assessed the repository against **ASVS Level 1** requirements across 13 domain directories: variable substitution, cryptographic controls, event log appender, Windows security context, ADO.NET SQL injection, serialization/deserialization, dependency management, general security, network appenders, XML configuration parsing, file system access, log injection/output encoding, and general chapter 2 controls.

### Top 5 Risks

1. **Absence of documented remediation time frames for third-party vulnerabilities** — Without a formal policy specifying risk-based deadlines for patching known vulnerabilities in dependencies, response times may be inconsistent or delayed (FINDING-001).
2. **Inability to verify dependency update compliance** — The lack of a dependency manifest and accompanying remediation policy prevents automated or manual verification that components are maintained at current, non-vulnerable versions (FINDING-002).
3. **BinaryFormatter usage on legacy .NET Framework targets** — While mitigated by conditional compilation on modern platforms, legacy .NET 4.6.2+ builds retain BinaryFormatter serialization paths that carry inherent deserialization risks in untrusted transport scenarios.
4. **Administrator-controlled configuration as trust boundary** — The security model assumes configuration sources are trusted; compromise of configuration channels could enable type instantiation or network endpoint redirection.
5. **PatternLayout text output lacks structured encoding** — Unlike the XML layouts which apply comprehensive encoding, plain-text PatternLayout delegates log injection prevention to consuming applications and log viewers.

### Positive Controls

The audit identified **35 verified positive security controls** across the codebase, demonstrating defense-in-depth practices:

- **XXE Protection**: All XML parsing entry points disable `XmlResolver` and set `DtdProcessing` to `Ignore`, providing robust protection against XML External Entity attacks across `XmlConfigurator.cs`.
- **Type Instantiation Constraints**: Dynamic type creation via `Activator.CreateInstance` is guarded by interface checks (`EnsureIs<IAppender>`), superclass assignability validation (`IsAssignableFrom`), and type constraint enforcement — preventing arbitrary type instantiation from configuration.
- **Comprehensive XML Output Encoding**: A centralized extension method pattern (`WriteAttributeStringSafe`, `WriteEscapedXmlString`) ensures all user-controlled data in XML layouts is properly encoded with context-aware handling for attributes versus element content, invalid character replacement, and optional Base64 encoding.
- **Managed File System Operations**: All file I/O uses direct .NET `System.IO` APIs with no shell invocation, command execution, or string-to-command interpretation patterns.
- **Minimal Attack Surface**: The project maintains near-zero external dependencies, operates under Apache Software Foundation release governance, publishes CycloneDX VDR artifacts, defaults to `NullSecurityContext` (no privileges), and disables BinaryFormatter on modern .NET platforms via conditional compilation.

---

## 3. Findings

### 3.4 Low

#### FINDING-001: 🔵 No documented risk-based remediation time frames for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **File(s)** | Repository-level documentation gap |
| **Source Report(s)** | 15.1.1.md |
| **Related** | None |

**Description:**

DOWNGRADED from MEDIUM: The project is a library with minimal third-party dependencies governed by ASF release processes, and publishes a CycloneDX VDR. The absence of explicit SLA time frames is a documentation gap, not a material security risk for a library with near-zero external dependencies.

**Remediation:**

Consider documenting remediation time frames in SECURITY.md or equivalent, aligned with ASF security response processes.

---

#### FINDING-002: 🔵 Unable to verify component update compliance due to absence of dependency manifest and remediation policy

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **File(s)** | Repository-level assessment |
| **Source Report(s)** | 15.2.1.md |
| **Related** | None |

**Description:**

Without a documented remediation policy (prerequisite from 15.1.1), it is technically impossible to determine whether any component has breached a time frame. This represents a governance gap rather than a known vulnerable component.

**Remediation:**

Establish the remediation time frame policy (per ASVS-1511-MED-001) and add automated dependency scanning to CI/CD.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Xml Configuration Parsing | XXE Protection - XmlResolver disabled and DTD processing ignored | Both XML parsing entry points apply defense-in-depth against XXE. XmlResolver set to null and DtdProcessing set to Ignore on all XmlDocument and XmlReader instances | XmlConfigurator.cs:340, XmlConfigurator.cs:345, XmlConfigurator.cs:530, XmlConfigurator.cs:350 |
| Xml Configuration Parsing | Interface constraint on Activator.CreateInstance | Dynamic type instantiation is constrained using .EnsureIs<IAppender>() to validate interface compliance | XmlHierarchyConfigurator.cs:210 |
| Xml Configuration Parsing | Superclass assignability check | Type instantiation validates superclass compatibility using IsAssignableFrom before object creation | OptionConverter.cs:190 |
| Xml Configuration Parsing | Interface check for converters | Converter instantiation validates IConvertFrom interface using typeof(IConvertFrom).IsAssignableFrom | ConverterRegistry.cs:115 |
| Xml Configuration Parsing | Type constraint validation | XML object creation validates type constraints using typeConstraint.IsAssignableFrom(objectType) | XmlHierarchyConfigurator.cs:710 |
| Xml Configuration Parsing | No eval() or script execution | The codebase does not use CSharpScript.EvaluateAsync, CompileAssemblyFromSource, Expression.Compile(), or any other pattern that would allow arbitrary code evaluation from strings | — |
| Xml Configuration Parsing | Simple variable substitution (not expression language) | The variable substitution pattern (${key}) is a simple dictionary lookup, not an expression language. It does not evaluate expressions, perform arithmetic, or invoke methods | — |
| Xml Configuration Parsing | Defensive error handling with fatal exception filtering | All dynamic operations use catch (Exception e) when (!e.IsFatal()) patterns that prevent crashes from propagating while logging the error internally | — |
| Xml Configuration Parsing | Thread-safe configuration with atomic swap patterns | The ConfigureAndWatch mechanism uses timer-based debouncing (500ms) and ConcurrentDictionary for handler management. Appender replacement uses atomic swap patterns (ReplaceAppenders) | — |
| Log Injection Output Encoding | WriteAttributeStringSafe() for XML attribute encoding | Applied to ALL attribute values containing user data (logger, thread, domain, identity, username, level, property names, property values, location info) | XmlLayout.cs:185-270, XmlLayoutSchemaLog4j.cs:150-230 |
| Log Injection Output Encoding | WriteEscapedXmlString() for XML element text content encoding | Applied to ALL element text content (message, exception, NDC) | XmlLayout.cs:220-225, XmlLayout.cs:255, XmlLayoutSchemaLog4j.cs:175, XmlLayoutSchemaLog4j.cs:185, XmlLayoutSchemaLog4j.cs:215 |
| Log Injection Output Encoding | InvalidCharReplacement for invalid XML character handling | Passed to all encoding calls for invalid XML character handling | XmlLayoutBase.cs |
| Log Injection Output Encoding | Base64EncodeMessage / Base64EncodeProperties for binary data protection | Optional additional protection for binary data | XmlLayout.cs:125, XmlLayout.cs:140 |
| Log Injection Output Encoding | Structural separation of element names from user data | XML element names and structural components are cached from administrator-controlled configuration prefixes, keeping structure separate from user data | — |
| Log Injection Output Encoding | XmlWriter usage for structural protection | Underlying System.Xml.XmlWriter provides a layer of structural protection | — |
| Log Injection Output Encoding | Extension method pattern for centralized encoding | Encoding logic centralized in extension methods from log4net.Layout.Internal namespace (WriteAttributeStringSafe and WriteEscapedXmlString) ensuring consistent application across both XML layout variants | — |
| Log Injection Output Encoding | Clear separation of encoding contexts between text layout (PatternLayout) and XML layouts (XmlLayout, XmlLayoutSchemaLog4j) | XML layouts consistently encode all user-controlled data through dedicated safe-writing extension methods | PatternLayout.cs, XmlLayout.cs, XmlLayoutSchemaLog4j.cs |
| Log Injection Output Encoding | Defense-in-depth layering in XML layouts | Multiple encoding levels: InvalidCharReplacement for XML-invalid characters, context-aware encoding (attribute vs. element content), optional base64 encoding for binary data, underlying XmlWriter structural protection | XmlLayout.cs, XmlLayoutSchemaLog4j.cs |
| Log Injection Output Encoding | Well-documented and consistently applied trust boundary | Configuration-sourced values (pattern strings, prefix names, element names) treated as trusted, while runtime log event data (messages, properties, exceptions) is always encoded in XML contexts | PatternLayout.cs, XmlLayout.cs, XmlLayoutSchemaLog4j.cs |
| File System Access | Direct .NET IO API usage for stream creation | LockingModelBase.CreateStream() method uses managed System.IO APIs | FileAppender.cs |
| File System Access | Direct .NET IO API usage for file rolling operations | RollingFileAppender.RollFile() uses managed System.IO APIs | RollingFileAppender.cs |
| File System Access | Direct .NET IO API usage for file deletion | RollingFileAppender.DeleteFile() uses managed System.IO APIs | RollingFileAppender.cs |
| File System Access | No shell invocation or command execution | All file operations use direct .NET APIs; no Process class or shell usage detected | FileAppender.cs, RollingFileAppender.cs |
| File System Access | Exclusive use of managed .NET APIs | Consistent use of System.IO.FileStream, System.IO.File, and System.IO.Directory classes for all file system interactions | FileAppender.cs, RollingFileAppender.cs |
| File System Access | No string-to-command interpretation | File paths constructed via string manipulation (e.g., CombinePath(), GetNextOutputFileName()) are only consumed by file system APIs, never by command execution APIs | FileAppender.cs, RollingFileAppender.cs |
| File System Access | Parameterized file operations | All file operations accept typed parameters (string paths, enum modes) rather than constructing command strings | FileAppender.cs, RollingFileAppender.cs |
| Windows Security Context | Default NullSecurityContext (no privileges) ensures unconfigured components operate with minimal privileges; impersonation requires explicit trusted administrator configuration | Promoted from dropped finding ASVS-811-LOW-001 | — |
| Windows Security Context | In-process trust model: all code in the process is equally trusted; isolation for untrusted components is delegated to deployment infrastructure via separate processes | source: Dropped finding ASVS-821-LOW-001 | — |
| Serialization Deserialization | Library faithfully records log content without transformation, maintaining correct responsibility boundary | The library does not accept or render HTML content; sanitization before logging is the calling application's responsibility, and sanitization when displaying logs is the log viewer's responsibility | — |
| Serialization Deserialization | Conditional compilation disables BinaryFormatter serialization on modern .NET platforms | Conditional compilation in Serializable.cs disables BinaryFormatter serialization on non-NET462_OR_GREATER platforms, reducing attack surface | Serializable.cs |
| Serialization Deserialization | Explicit trust boundary documentation | Project provides clear documentation about what is considered within the trust boundary (configuration, serialization transport) versus what is the library's responsibility | — |
| Serialization Deserialization | LoggingEvent serialization assumes authenticated transport with trusted peers; field-level filtering is a deployment concern, not a library responsibility | source: Dropped finding ASVS-1531-LOW-001 | — |
| Dependency Management | Minimal third-party dependencies | Project is a library with near-zero external dependencies | — |
| Dependency Management | ASF release processes | Project governed by Apache Software Foundation release processes | — |
| Dependency Management | CycloneDX VDR publication | Project publishes a CycloneDX VDR | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Pass** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **Pass** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **N/A** |  |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **N/A** |  |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **N/A** |  |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **N/A** |  |
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
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Pass** |  |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** |  |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Partial** | See FINDING-001 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Partial** | See FINDING-002 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 8 requirements (11.4%)
- **Partial**: 2 requirements (2.9%)
- **N/A**: 60 requirements (85.7%)
- **Fail**: 0 requirements (0.0%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Low | 15.1.1 | — | Repository-level documentation gap |
| FINDING-002 | Low | 15.2.1 | — | Repository-level assessment |

**Total Unique Findings**: 2 (0 Critical, 0 High, 0 Medium, 2 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 2 |

**Total consolidated findings: 2**

*End of Consolidated Security Audit Report*