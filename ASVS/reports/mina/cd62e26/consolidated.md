# Security Audit Consolidated Report — apache/mina

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/mina |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | cd62e26 |
| Date | May 20, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 19 |

## Executive Summary

This report consolidates the results of 70 source security audit reports covering 10 audit domains within the Apache MINA repository, evaluated against OWASP ASVS Level 1 requirements. All 19 findings are actionable.

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 4 |
| Medium | 11 |
| Low | 4 |
| Info | 0 |

### Level Coverage

All findings are mapped to **ASVS L1** controls. The audit scope was limited to L1; no L2 or L3 controls were evaluated.

### Top 5 Risks

1. **HTTP/2 Signed Byte Interpretation of Padding Length Field (FINDING-001)** — A signed byte interpretation allows negative padding values, potentially enabling frame boundary confusion and memory safety issues in HTTP/2 processing.

2. **HTTP/1.x Header Parsing Missing Bounds Check on Colon Split (FINDING-002)** — Missing bounds validation after splitting header lines on the colon delimiter can lead to ArrayIndexOutOfBoundsException or header injection via malformed input.

3. **HTTP/1.x Request Line Parsing Missing Bounds Check (FINDING-003)** — The request line parser does not validate segment count after splitting on whitespace, enabling denial-of-service or undefined behavior with malformed requests.

4. **HTTP Header Value CRLF Injection (FINDING-004)** — The HTTP server encoder does not sanitize header values for CRLF sequences, permitting response splitting attacks when application-supplied values contain injected line terminators.

5. **Silent Plaintext Fallback After TLS Session Closure (FINDING-015)** — After TLS session closure, the transport layer silently falls back to plaintext communication rather than terminating the connection, enabling potential downgrade attacks.

### Positive Controls

The audit identified the following positive security controls already in place:

| Control | Evidence | Domain |
|---------|----------|--------|
| All protocol decoders operate as server-side components parsing untrusted network input at the trusted service layer with no reliance on client-side validation | Promoted from dropped finding ASVS-222-MED-001 | protocol_decoder_input_validation |
| Content-Type header enforcement is explicitly delegated to the consuming application; the framework encoder serializes application-supplied headers as provided | Profile: Out-of-Scope ASVS 4.1.1 | http_response_security |

---

## 3. Findings

### 3.2 High

#### FINDING-001: 🟠 HTTP/2 Signed Byte Interpretation of Padding Length Field

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-681 |
| **ASVS Sections** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2DataFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2HeadersFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2PushPromiseFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

Wire byte (unsigned 0-255) is read via buffer.get() (Java signed byte -128 to 127) and sign-extended into padLength. A pad length byte of 0x80 (128 unsigned) is interpreted as -128, causing the decoder to create a BytePartialDecoder that consumes bytes beyond the frame boundary, reading data from subsequent frames. Affects Http2DataFrameDecoder, Http2HeadersFrameDecoder, and Http2PushPromiseFrameDecoder.

**Remediation:**

Change `padLength = buffer.get()` to `padLength = buffer.get() & 0xFF` and add RFC 7540-mandated validation that padding does not exceed frame payload length.

---

#### FINDING-002: 🟠 HTTP/1.x Header Parsing Missing Bounds Check on Colon Split

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-129 |
| **ASVS Sections** | 2.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-003 |

**Description:**

Header lines split on ':' without checking the result array length. A header line without a colon produces a single-element array, and accessing header[1] throws ArrayIndexOutOfBoundsException, crashing the connection handler.

**Remediation:**

Add bounds check after splitting: if (header.length < 2) throw ProtocolDecoderException. Also limit split to 2 parts to handle colons in header values.

---

#### FINDING-003: 🟠 HTTP/1.x Request Line Parsing Missing Bounds Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-129 |
| **ASVS Sections** | 2.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-002 |

**Description:**

Request line split on spaces without checking result array length. A request line with insufficient spaces produces too few elements, and accessing elements[2] throws ArrayIndexOutOfBoundsException.

**Remediation:**

Add bounds check: if (elements.length < 3) throw ProtocolDecoderException with descriptive message.

---

#### FINDING-004: 🟠 HTTP Header Value CRLF Injection Due to Missing Output Encoding in HttpServerEncoder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-113 |
| **ASVS Sections** | 1.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| **Source Reports** | 1.2.1.md |
| **Related** | - |

**Description:**

The HttpServerEncoder serializes application-supplied header names and values directly into the HTTP wire format without any validation or sanitization of CRLF characters. This enables HTTP Response Splitting attacks where an attacker who can influence header values can inject arbitrary headers or body content.

**Remediation:**

Add header name and value validation that rejects or strips \r and \n characters before serialization in HttpServerEncoder.visit(HttpResponse). Validate header names conform to RFC 7230 §3.2.6 token production.

### 3.3 Medium

#### FINDING-005: CoAP Decoder Lacks Documentation of Token Length Validation Rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| **Source Reports** | 2.1.1.md |
| **Related** | FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-011, FINDING-012 |

**Description:**

The CoAP decoder does not document or enforce the validation rule that Token Length (TKL) field values 9-15 are reserved per RFC 7252 §3. There is no javadoc, inline comment, or configuration that defines the valid range.

**Remediation:**

Add validation documentation either in javadoc or in a validation rules file documenting TKL (0-8), option delta/length constraints, and version requirements.

---

#### FINDING-006: HTTP/1.x Decoder Lacks Documentation of Header Parsing Validation Rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.1.1.md |
| **Related** | FINDING-005, FINDING-007, FINDING-008, FINDING-010, FINDING-011, FINDING-012 |

**Description:**

The HTTP server decoder does not document expected structural constraints for parsed input including: maximum header count, maximum header line length, maximum total header size, required format for header lines, or valid characters in header names/values.

**Remediation:**

Document the expected HTTP parsing rules including maximum header size, maximum header count, header line format requirements, and request line structure.

---

#### FINDING-007: HTTP/2 Frame Decoders Lack Documentation of Protocol-Required Length Constraints

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2FrameHeadePartialDecoder.java |
| **Source Reports** | 2.1.1.md |
| **Related** | FINDING-005, FINDING-006, FINDING-008, FINDING-010, FINDING-011, FINDING-012 |

**Description:**

The HTTP/2 implementation does not document validation rules for frame-type-specific length requirements mandated by RFC 7540 (PING=8, RST_STREAM=4, PRIORITY=5, WINDOW_UPDATE=4, SETTINGS=%6).

**Remediation:**

Add protocol-specific validation documentation to each frame decoder class.

---

#### FINDING-008: CoAP Decoder Accepts Reserved Token Length Values 9-15

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005, FINDING-006, FINDING-007, FINDING-010, FINDING-011, FINDING-012 |

**Description:**

TKL field extracted as byte0 & 0xF (range 0-15) and used directly for token array allocation. RFC 7252 §3 states TKL values 9-15 are reserved and MUST be treated as a message format error.

**Remediation:**

Add validation: if (tkl > 8) throw ProtocolDecoderException.

---

#### FINDING-009: HTTP/2 Frame Header Accepts Unrestricted Frame Length

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2FrameHeadePartialDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-014 |

**Description:**

Frame length field (24-bit, up to 16,777,215) is accepted without validation against SETTINGS_MAX_FRAME_SIZE (default 16,384 per RFC 7540 §4.2). A single frame can trigger 16 MB heap allocation.

**Remediation:**

Enforce configurable maximum frame size (default 16,384) in Http2FrameHeadePartialDecoder after parsing the length field.

---

#### FINDING-010: HTTP/2 PING Frame Length Not Validated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-011, FINDING-012 |

**Description:**

PING frame decoder accepts any length without validating RFC 7540 §6.7 requirement of exactly 8 octets. Non-8-byte PING frames should be treated as FRAME_SIZE_ERROR.

**Remediation:**

Add validation in constructor: if (header.getLength() != 8) throw ProtocolDecoderException.

---

#### FINDING-011: HTTP/2 RST_STREAM Frame Length Not Validated

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2RstStreamFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-012 |

**Description:**

RST_STREAM decoder accepts any length without validating RFC 7540 §6.4 requirement of exactly 4 octets.

**Remediation:**

Add validation: if (header.getLength() != 4) throw ProtocolDecoderException.

---

#### FINDING-012: HTTP/2 SETTINGS Frame Length Not Validated as Multiple of 6

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2SettingsFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-011 |

**Description:**

SETTINGS frame length divided by 6 using integer division, silently discarding remainder bytes. RFC 7540 §6.5 requires length to be a multiple of 6.

**Remediation:**

Add validation: if (header.getLength() % 6 != 0) throw ProtocolDecoderException.

---

#### FINDING-013: HTTP/2 GoAway Frame Decoder Missing Break Statement Causes Incorrect Parsing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-484 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2GoAwayFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | |

**Description:**

Missing break statement between LAST_STREAM_ID and CODE cases in switch statement. When decoder.consume() returns false for LAST_STREAM_ID, execution falls through to CODE case, potentially causing ClassCastException or parsing corruption under specific TCP fragmentation patterns.

**Remediation:**

Add break statement after the LAST_STREAM_ID case block.

---

#### FINDING-014: HTTP/1.x No Maximum Header Size Enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-009 |

**Description:**

The HEAD state accumulates partial buffers indefinitely without a maximum size check. An attacker can exhaust memory by slowly sending header bytes without a terminating blank line.

**Remediation:**

Add a configurable maximum header size check (e.g., 8192 bytes) in the HEAD state before concatenating buffers.

---

#### FINDING-015: Silent plaintext fallback after TLS session closure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS Section(s)** | 12.2.1 |
| **Files** | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| **Source Reports** | 12.2.1.md |
| **Related** | FINDING-018 |

**Description:**

When the TLS session transitions to NO_CREDENTIALS state (via switchToNoSecure()), subsequent application messages are silently passed through without encryption. The method does not throw an exception, log a warning, or refuse the write. This constitutes a silent plaintext fallback.

**Remediation:**

Change the NO_CREDENTIALS case to throw an exception or refuse the write. If plaintext fallback is intentional for specific scenarios, require explicit opt-in via a session attribute.

### 3.4 Low

#### FINDING-016: SSLEngine cipher suites not restricted to AEAD modes

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS Section(s) | 11.3.2 |
| Files | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| Source Reports | 11.3.2.md |
| Related | - |

**Description:**

The SSLEngine is used without restricting cipher suites to approved AEAD modes (AES-GCM, ChaCha20-Poly1305). Modern JDKs still enable CBC-based cipher suites which do not provide authenticated encryption. Low practical risk on modern JDKs where GCM suites are preferred during negotiation, but CBC-mode suites remain as fallback options.

**Remediation:**

Filter enabled cipher suites to GCM and ChaCha20-Poly1305 variants in SslHelper.init(), e.g., Arrays.stream(sslEngine.getSupportedCipherSuites()).filter(c -> c.contains("_GCM_") || c.contains("CHACHA20")).toArray(String[]::new)

---

#### FINDING-017: No setEnabledProtocols() call restricting TLS versions

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-327 |
| ASVS Section(s) | 12.1.1 |
| Files | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| Source Reports | 12.1.1.md |
| Related | - |

**Description:**

After creating the SSLEngine, the init() method never calls sslEngine.setEnabledProtocols() to restrict protocols to TLS 1.2 and TLS 1.3. DOWNGRADED from Medium: per project severity policy, TLS version restriction findings in SslHelper should not be rated Medium/High when JDK 11+ defaults already disable legacy protocols; characterized as defense-in-depth improvement with low practical risk.

**Remediation:**

Add sslEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"}) in init(). Provide an attribute key for applications needing to override.

---

#### FINDING-018: ProxyTcpSessionConfig silently discards TLS configuration

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-319 |
| ASVS Section(s) | 12.2.1 |
| Files | core/src/main/java/org/apache/mina/transport/tcp/ProxyTcpSessionConfig.java |
| Source Reports | 12.2.1.md |
| Related | FINDING-015 |

**Description:**

The ProxyTcpSessionConfig implementation silently discards any attempt to configure TLS via setSslContext(). An application that sets an SSLContext on this config would receive no error but get a plaintext connection.

**Remediation:**

Make setSslContext() throw UnsupportedOperationException when a non-null SSLContext is provided, to make the incompatibility explicit.

---

#### FINDING-019: No hostname verification enabled for client-mode SSLEngine

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | CWE-297 |
| ASVS Section(s) | 12.2.2 |
| Files | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| Source Reports | 12.2.2.md |
| Related | - |

**Description:**

When the SSLEngine is configured in client mode, hostname verification is never enabled via SSLParameters.setEndpointIdentificationAlgorithm("HTTPS"). Unlike HttpsURLConnection, raw SSLEngine does NOT perform hostname verification by default. DOWNGRADED from Medium: per project security profile, TLS configuration is partially delegated to application-supplied SSLParameters; the application can configure endpoint identification. However, unlike protocol version restrictions, JDK defaults do NOT cover this for raw SSLEngine, so this remains a valid defense-in-depth finding.

**Remediation:**

In SslHelper.init(), when useClientMode is true, set SSLParameters.setEndpointIdentificationAlgorithm("HTTPS"). Provide an attribute key (SKIP_HOSTNAME_VERIFICATION) for applications that explicitly need to bypass this.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Protocol Decoder Input Validation | All protocol decoders operate as server-side components parsing untrusted network input at the trusted service layer with no reliance on client-side validation | Promoted from dropped finding ASVS-222-MED-001 | — |
| Http Response Security | Content-Type header enforcement is explicitly delegated to the consuming application; the framework encoder serializes application-supplied headers as provided. | Profile: Out-of-Scope ASVS 4.1.1 | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Fail** | See FINDING-004 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** |  |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** |  |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Fail** | See FINDING-005, FINDING-006, FINDING-007 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Fail** | See FINDING-001, FINDING-002, FINDING-003, FINDING-008, FINDING-009, FINDING-010, FINDING-011, FINDING-012, FINDING-013, FINDING-014 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Pass** |  |
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
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Pass** |  |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Partial** | See FINDING-016 |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** |  |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Partial** | See FINDING-017 |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Fail** | See FINDING-015, FINDING-018 |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Partial** | See FINDING-019 |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **N/A** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** |  |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** |  |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **N/A** |  |

**Summary Statistics:**
- **Pass**: 5 requirements (7.1%)
- **Partial**: 3 requirements (4.3%)
- **N/A**: 58 requirements (82.9%)
- **Fail**: 4 requirements (5.7%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | High | 2.2.1 | — | http2/src/main/java/org/apache/mina/http2/impl/Http2DataFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2HeadersFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2PushPromiseFrameDecoder.java |
| FINDING-002 | High | 2.2.1 | FINDING-003 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-003 | High | 2.2.1 | FINDING-002 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-004 | High | 1.2.1 | — | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| FINDING-005 | Medium | 2.1.1 | FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-011, FINDING-012 | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| FINDING-006 | Medium | 2.1.1 | FINDING-005, FINDING-007, FINDING-008, FINDING-010, FINDING-011, FINDING-012 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-007 | Medium | 2.1.1 | FINDING-005, FINDING-006, FINDING-008, FINDING-010, FINDING-011, FINDING-012 | http2/src/main/java/org/apache/mina/http2/impl/Http2FrameHeadePartialDecoder.java |
| FINDING-008 | Medium | 2.2.1 | FINDING-005, FINDING-006, FINDING-007, FINDING-010, FINDING-011, FINDING-012 | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| FINDING-009 | Medium | 2.2.1 | FINDING-014 | http2/src/main/java/org/apache/mina/http2/impl/Http2FrameHeadePartialDecoder.java |
| FINDING-010 | Medium | 2.2.1 | FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-011, FINDING-012 | http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java |
| FINDING-011 | Medium | 2.2.1 | FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-012 | http2/src/main/java/org/apache/mina/http2/impl/Http2RstStreamFrameDecoder.java |
| FINDING-012 | Medium | 2.2.1 | FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-011 | http2/src/main/java/org/apache/mina/http2/impl/Http2SettingsFrameDecoder.java |
| FINDING-013 | Medium | 2.2.1 | — | http2/src/main/java/org/apache/mina/http2/impl/Http2GoAwayFrameDecoder.java |
| FINDING-014 | Medium | 2.2.1 | FINDING-009 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-015 | Medium | 12.2.1 | FINDING-018 | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-016 | Low | 11.3.2 | — | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-017 | Low | 12.1.1 | — | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-018 | Low | 12.2.1 | FINDING-015 | core/src/main/java/org/apache/mina/transport/tcp/ProxyTcpSessionConfig.java |
| FINDING-019 | Low | 12.2.2 | — | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |

**Total Unique Findings**: 19 (0 Critical, 4 High, 11 Medium, 4 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 19 |

**Total consolidated findings: 19**

*End of Consolidated Security Audit Report*