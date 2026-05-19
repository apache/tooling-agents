# Security Audit Consolidated Report — apache/mina

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/mina |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | cd62e26 |
| Date | May 19, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 21 |

## Executive Summary

This consolidated report presents the results of an automated security audit of the `apache/mina` repository, evaluated against OWASP ASVS Level 1 requirements across 11 analysis domains. A total of 21 actionable findings were identified from 70 source reports.

### Severity Distribution


| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High     | 7 | 35.0% |
| Medium   | 13 | 65.0% |
| Low      | 0 | 0.0% |
| Info     | 0 | 0.0% |

### Level Coverage

All 21 findings are mapped to ASVS Level 1 (L1) requirements, confirming that the audit scope addresses foundational security controls expected of any internet-facing application framework.

### Top 5 Risks


2. **No TLS protocol version restriction in SslHelper.init() (High)** — The TLS initialization path does not constrain protocol versions, allowing negotiation of deprecated protocols (SSLv3, TLS 1.0, TLS 1.1) vulnerable to known cryptographic attacks such as POODLE and BEAST.

3. **HTTP request line and header parsing lacks structural validation (High)** — Multiple parsing routines in the HTTP/1.x decoder fail to validate that split operations produce the expected number of elements, enabling malformed requests to trigger unexpected exceptions or bypass downstream logic.

4. **HTTP/1.x decoder enforces no maximum limit on header size (High)** — The absence of an upper bound on accumulated header data allows remote attackers to exhaust server memory with arbitrarily large headers, resulting in denial of service.

5. **HTTP/2 frame decoders allocate arrays from wire-declared length without enforcing SETTINGS_MAX_FRAME_SIZE (High)** — Frame payload lengths read directly from the wire are used to allocate byte arrays without validation against the negotiated maximum frame size, enabling heap exhaustion attacks via a single crafted frame.

### Positive Controls

The audit identified the following positive security control already present in the codebase:

| Control | Evidence | Relevant Files |
|---------|----------|----------------|
| Server-side decoder architecture ensures validation occurs at trusted service layer | All protocol decoders (CoAP, HTTP/1.x, HTTP/2) execute on the server side, ensuring that input validation is not deferred to client-side logic | `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`, `coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java`, `http2/src/main/java/org/apache/mina/http2/impl/*FrameDecoder.java` |

This architectural decision provides a sound foundation for input validation; however, the findings in this report demonstrate that the validation logic within these decoders requires significant hardening to meet ASVS L1 requirements.

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

### 3.2 High

#### FINDING-002: No TLS protocol version restriction in SslHelper.init()

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 12.1.1 |
| **Files** | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| **Source Reports** | 12.1.1.md |
| **Related** | FINDING-009, FINDING-010 |

**Description:**

The SslHelper.init() method does not call sslEngine.setEnabledProtocols() to restrict TLS versions to 1.2 and 1.3. Depending on the JDK version and configuration, this could allow negotiation of deprecated TLS versions (TLS 1.0, TLS 1.1) which have known vulnerabilities (BEAST, POODLE variants). While JDK 11+ disables TLS 1.0/1.1 by default, applications running on older JDKs or with custom java.security configurations remain vulnerable.

**Remediation:**

Add sslEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"}) in SslHelper.init() after SSLEngine creation.

---

#### FINDING-003: HTTP request line parser does not validate split result structure

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-129 |
| **ASVS Section(s)** | 2.2.1, 2.2.2 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.1.md, 2.2.2.md |
| **Related** | FINDING-004 |

**Description:**

The decoders correctly execute on the server side as the trusted service layer. However, the validation that IS present is incomplete (see ASVS-2.2.1 findings), meaning the trusted layer exists but lacks sufficient controls. Specifically, the HttpServerDecoder has a control gap where validation of request structure happens at the server level but is incomplete.

**Remediation:**

Enhance the server-side validation controls as detailed in ASVS-2.2.1 findings. The architecture is correct; the implementation needs strengthening.

---

#### FINDING-004: HTTP header parsing does not validate colon-split produces 2 elements

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-129 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-003 |

**Description:**

HTTP header parsing does not validate that the colon-split produces at least 2 elements. A header line without a colon character causes ArrayIndexOutOfBoundsException.

**Remediation:**

Use split(pattern, 2) and validate header.length >= 2 before accessing header[1], throwing ProtocolDecoderException on malformed headers.

---

#### FINDING-005: HTTP/1.x decoder enforces no maximum limit on header size

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-006, FINDING-015 |

**Description:**

The HTTP/1.x decoder enforces no maximum limit on total header size, individual header sizes, number of headers, or request line length. An attacker can send arbitrarily large headers to consume server memory until exhaustion.

**Remediation:**

Implement a configurable maximum header size limit (e.g., 8KB default) and reject requests exceeding it with ProtocolDecoderException.

---

#### FINDING-006: HTTP/2 frame decoders allocate arrays from wire-declared length without enforcing SETTINGS_MAX_FRAME_SIZE

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2DataFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2ContinuationFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2HeadersFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2PushPromiseFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2UnknownFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005, FINDING-015 |

**Description:**

HTTP/2 frame decoders allocate byte arrays based on the frame length field from the wire without enforcing SETTINGS_MAX_FRAME_SIZE (default 16,384 bytes per RFC 7540 Section 6.5.2). The frame length field is 24 bits, allowing values up to 16,777,215 (16MB). An attacker can trigger allocation of 16MB byte arrays per frame.

**Remediation:**

Add a configurable maximum frame size (default 16,384 per RFC 7540) and reject frames exceeding it with FRAME_SIZE_ERROR before allocating buffers.

---

#### FINDING-007: No Function-Level Access Control Enforcement in Request Routing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-285 |
| **ASVS Section(s)** | 8.2.1, 8.2.2 |
| **Files** | coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java |
| **Source Reports** | 8.2.1.md, 8.2.2.md |
| **Related** | FINDING-017 |

**Description:**

Resource access is determined solely by whether a path string exists in the `handlers` map. There is no verification that the requesting consumer has permission to access the specific data item at that path. This is a textbook Broken Object Level Authorization (BOLA) pattern: if a consumer knows or guesses the path of a resource (e.g., `users/admin/config`), they can access it without ownership or permission validation. The path is consumer-supplied (constructed from `URI_PATH` options) and directly used as a lookup key.

**Remediation:**

Add a data-level authorization check in ResourceRegistry.respond() before handler invocation that verifies the authenticated consumer has explicit permission to access the specific resource identified by the requested path.

---

#### FINDING-008: HTTP Response Splitting via Unvalidated Header Values in HttpServerEncoder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-113 |
| **ASVS Section(s)** | 1.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| **Source Reports** | 1.2.1.md |
| **Related** | FINDING-020 |

**Description:**

No validation or encoding of \r\n (CRLF) sequences in header keys or values before writing them into the HTTP response structure. Application-provided header values flow through msg.getHeaders() via direct concatenation into HTTP response and onto the wire. If application code sets a header value containing CRLF, the resulting wire output would contain an injected header and potentially an injected body, splitting the HTTP response.

**Remediation:**

Add CRLF validation to HttpServerEncoder. Reject or strip CR and LF characters in header names and values per RFC 7230 before writing them to the wire.

### 3.3 Medium

#### FINDING-009: No cipher suite restriction in SslHelper.init() allows PKCS#1 v1.5 padding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS sections** | 11.3.1, 11.3.2 |
| **Files** | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| **Source Reports** | 11.3.1.md, 11.3.2.md |
| **Related** | FINDING-002, FINDING-010 |

**Description:**

The SslHelper.init() method creates an SSLEngine without calling setEnabledCipherSuites() to disable cipher suites that use PKCS#1 v1.5 RSA key exchange (e.g., TLS_RSA_WITH_AES_128_CBC_SHA256). These cipher suites are vulnerable to Bleichenbacher-style padding oracle attacks (ROBOT attack). While modern JDKs may disable some of these by default, the framework provides no explicit enforcement.

**Remediation:**

Implement a configurable cipher suite allowlist in SslHelper defaulting to GCM and CHACHA20-POLY1305 modes only, filtering supported suites at initialization.

---

#### FINDING-010: Example code uses generic SSLContext.getInstance("TLS") without version restriction

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS sections** | 12.1.1 |
| **Files** | examples/src/main/java/org/apache/mina/examples/http/BogusSslContextFactory.java |
| **Source Reports** | 12.1.1.md |
| **Related** | FINDING-002, FINDING-009 |

**Description:**

The example factory uses SSLContext.getInstance("TLS") which returns an SSLContext that supports all TLS versions available in the JDK. While this is example code, the pattern without subsequent protocol restriction in SslHelper means any code copying this pattern will not enforce TLS 1.2+.

**Remediation:**

Change PROTOCOL constant to "TLSv1.3" or "TLSv1.2" as minimum in example code.

---

#### FINDING-011: Plaintext fallback after TLS session closure in SslHelper.processWrite()

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS sections** | 12.2.1 |
| **Files** | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| **Source Reports** | 12.2.1.md |
| **Related** | |

**Description:**

When an SSL/TLS session is closed (either by the peer or due to an error), the SslHelper transitions to NO_CREDENTIALS state. In this state, processWrite() passes messages through without encryption. This creates a potential plaintext fallback scenario where application data that was being sent over an encrypted channel could silently fall back to plaintext transmission if the TLS session terminates unexpectedly.

**Remediation:**

In processWrite() NO_CREDENTIALS case, throw IllegalStateException or close the session instead of allowing plaintext writes.

---

#### FINDING-012: No hostname verification or certificate trust validation in SslHelper

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-295 |
| **ASVS sections** | 12.2.2 |
| **Files** | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| **Source Reports** | 12.2.2.md |
| **Related** | |

**Description:**

The SslHelper constructor and init() method accept any SSLContext without validation that it uses publicly trusted certificates or has proper trust chain configuration. Additionally, for client-mode connections, there is no explicit enabling of hostname verification (SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")). Applications could be configured with self-signed certificates for external-facing services, or client connections could be vulnerable to MITM attacks.

**Remediation:**

Enable hostname verification for client mode by setting SSLParameters.setEndpointIdentificationAlgorithm("HTTPS") in SslHelper.init().

---

#### FINDING-013: CoAP token length field accepts reserved values 9-15

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS sections** | 2.2.1, 2.1.1 |
| **Files** | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| **Source Reports** | 2.2.1.md, 2.1.1.md |
| **Related** | FINDING-014 |

**Description:**

The protocol decoders lack documented input validation rules defining the expected structure and constraints of incoming data. While the code references RFCs implicitly (CoAP RFC 7252, HTTP/1.1 RFC 7230, HTTP/2 RFC 7540), no formal validation rules document specifies: Maximum token lengths for CoAP (RFC specifies 0-8, code allows 0-15), Maximum header sizes, number of headers, or request line length for HTTP/1.x, Maximum frame sizes (SETTINGS_MAX_FRAME_SIZE) for HTTP/2, Acceptable ranges for padding lengths, Maximum payload/body sizes for any protocol.

**Remediation:**

Create a validation rules document (or annotate the code with formal constraints) specifying protocol-specific constraints such as CoAP Token Length (TKL) MUST be 0-8, Option Delta valid quartets, Option Length bounds, and Message size limits.

---

#### FINDING-014: HTTP/2 frame-specific decoders do not validate RFC-required frame lengths

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS sections** | 2.2.1 |
| **Files** | http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2SettingsFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2RstStreamFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2WindowUpdateFrameDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-013 |

**Description:**

HTTP/2 frame-specific decoders do not validate that the declared frame length matches the RFC-required size for their frame type. Per RFC 7540: PING must be 8, RST_STREAM must be 4, WINDOW_UPDATE must be 4, SETTINGS must be a multiple of 6. Invalid sizes should trigger FRAME_SIZE_ERROR.

**Remediation:**

Add frame-type-specific length validation in each decoder constructor and throw FRAME_SIZE_ERROR for non-compliant lengths.

---

#### FINDING-015: CoAP option decoder does not enforce limits on number of options or total option data size

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS sections** | 2.2.1 |
| **Files** | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-005, FINDING-006 |

**Description:**

The CoAP option decoder does not enforce limits on the number of options or total option data size. An attacker can send a CoAP message with thousands of options, each with large values, consuming excessive memory through ArrayList growth and byte array allocations.

**Remediation:**

Add configurable maximum option count (e.g., 64) and maximum option size (e.g., 1034 per RFC 7252) limits, throwing ProtocolDecoderException when exceeded.

---

#### FINDING-016: No Authorization Documentation Exists in CoAP Resource Framework

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS sections** | 8.1.1 |
| **Files** | coap/src/main/java/org/apache/mina/coap/resource/ResourceHandler.java, coap/src/main/java/org/apache/mina/coap/resource/AbstractResourceHandler.java |
| **Source Reports** | 8.1.1.md |
| **Related** | |

**Description:**

The CoAP resource framework defines no authorization rules, documentation, or contracts specifying how function-level access (which CoAP methods are permitted) or data-specific access (which resources a consumer may access) should be restricted. The `ResourceHandler` interface's `handle()` method documentation describes only request/response mechanics with no mention of required authorization checks. The `AbstractResourceHandler` base class provides convenience defaults for metadata methods but omits any authorization-related methods, constants, annotations, or documentation that would define access control rules.

**Remediation:**

Define authorization documentation either as Javadoc contracts, security annotations, or a companion design document specifying that implementations MUST verify CoAP method code permissions and data-level access before processing requests.

---

#### FINDING-017: AbstractResourceHandler Provides No Authorization Baseline for Subclasses

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-285 |
| **ASVS sections** | 8.2.1 |
| **Files** | coap/src/main/java/org/apache/mina/coap/resource/AbstractResourceHandler.java |
| **Source Reports** | 8.2.1.md |
| **Related** | FINDING-007 |

**Description:**

The `AbstractResourceHandler` base class is the intended extension point for resource handler implementations. It provides convenience defaults for metadata methods but offers no authorization template, no `checkPermission()` utility method, no authentication extraction helper, and no example of how `handle()` implementations should verify function-level access. Subclasses that extend this class receive no security baseline and must independently discover and implement authorization from scratch.

**Remediation:**

Add a checkFunctionAccess() template method to AbstractResourceHandler that subclasses must implement or explicitly override, along with a getPermittedMethods() abstract method to declare allowed operations.

---

#### FINDING-018: Discovery Endpoint Exposes All Registered Resources Without Authorization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-200 |
| **ASVS sections** | 8.2.2 |
| **Files** | coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java |
| **Source Reports** | 8.2.2.md |
| **Related** | |

**Description:**

The `.well-known/core` discovery endpoint unconditionally enumerates ALL registered resources including their paths, interface descriptions, resource types, and titles. No authorization check is performed, and no filtering is applied based on the consumer's permissions. This information disclosure directly facilitates BOLA attacks by revealing valid resource paths.

**Remediation:**

Filter .well-known/core discovery responses based on the consumer's permissions so that only resources the consumer is authorized to access are enumerated.

---

#### FINDING-019: Path Construction From Untrusted Options Without Canonicalization Enables Authorization Bypass

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-706 |
| **ASVS sections** | 8.2.2 |
| **Files** | coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java |
| **Source Reports** | 8.2.2.md |
| **Related** | |

**Description:**

The URL is constructed by concatenating raw `URI_PATH` option data without normalization or canonicalization. While the current exact-match lookup limits exploitability, if authorization policies are later added based on path prefixes, the lack of canonicalization could enable bypass. URI_PATH options could contain encoded characters, empty segments, or case variations that create multiple representations of the same logical resource.

**Remediation:**

Add path canonicalization (removing empty segments, normalizing case, decoding percent-encoding) before path lookup and any authorization checks.

---

#### FINDING-020: No Validation of Status Line Structure in HttpServerEncoder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-113 |
| **ASVS sections** | 1.2.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| **Source Reports** | 1.2.1.md |
| **Related** | FINDING-008 |

**Description:**

The status line returned by getStatus().line() is used directly as the first line of the HTTP response without validation. If custom implementations provide arbitrary values, the HTTP response structure could be altered.

**Remediation:**

Validate that the status line conforms to the expected HTTP status line format (HTTP/x.x NNN Reason\r\n).

---

#### FINDING-021: HTTP Response Encoder Does Not Validate or Enforce Content-Type Header Presence

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS sections** | 4.1.1 |
| **Files** | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| **Source Reports** | 4.1.1.md |
| **Related** | |

**Description:**

Application provides HttpResponse → encoder iterates msg.getHeaders() → writes headers to output buffer → no validation that Content-Type is present for responses with bodies. Applications using MINA's HTTP encoder can send responses with message bodies but without a Content-Type header or without a proper charset parameter, leading to browser content sniffing (MIME confusion attacks), character encoding attacks, and XSS via content-type mismatch.

**Remediation:**

Add optional validation in HttpServerEncoder to warn or reject responses missing Content-Type headers when a body is present. At minimum, log a warning when Content-Type is absent.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Protocol Input Validation | Server-side decoder architecture ensures validation occurs at trusted service layer | All protocol decoders (CoAP, HTTP/1.x, HTTP/2) execute on the server side | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java, coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/*FrameDecoder.java |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Fail** | See FINDING-008, FINDING-020 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** | |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** | |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** | |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** | |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** | |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Pass** | |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** | |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Fail** | See FINDING-013 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Fail** | See FINDING-003, FINDING-004, FINDING-005, FINDING-006, FINDING-013, FINDING-014, FINDING-015 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Partial** | See FINDING-003 |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **N/A** | |
| **V3: Web Frontend Security** | | | |
| 3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. | **N/A** | |
| 3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. | **N/A** | |
| 3.3.1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '__Secure-' prefix must be used for the cookie name. | **N/A** | |
| 3.4.1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined, and for L2 and up, the policy must apply to all subdomains as well. | **N/A** | |
| 3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. | **N/A** | |
| 3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). | **N/A** | |
| 3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. | **N/A** | |
| 3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. | **N/A** | |
| **V4: API and Web Service** | | | |
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **Fail** | See FINDING-021 |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** | |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **N/A** | |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** | |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** | |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **N/A** | |
| **V6: Authentication** | | | |
| 6.1.1 | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. | **N/A** | |
| 6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. | **N/A** | |
| 6.2.2 | Verify that users can change their password. | **N/A** | |
| 6.2.3 | Verify that password change functionality requires the user's current and new password. | **N/A** | |
| 6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. | **N/A** | |
| 6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. | **N/A** | |
| 6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. | **N/A** | |
| 6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | **N/A** | |
| 6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. | **N/A** | |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **N/A** | |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. | **N/A** | |
| 6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. | **N/A** | |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. | **N/A** | |
| **V7: Session Management** | | | |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. | **N/A** | |
| 7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. | **N/A** | |
| 7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. | **N/A** | |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. | **N/A** | |
| 7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. | **N/A** | |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). | **N/A** | |
| **V8: Authorization** | | | |
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Fail** | See FINDING-016 |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Fail** | See FINDING-007, FINDING-017 |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **Fail** | See FINDING-007, FINDING-018, FINDING-019 |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **Pass** | |
| **V9: Self-contained Tokens** | | | |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents. | **N/A** | |
| 9.1.2 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms, ideally only either symmetric or asymmetric algorithms, and must not include the 'None' algorithm. If both symmetric and asymmetric must be supported, additional controls will be needed to prevent key confusion. | **N/A** | |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer, preventing attackers from specifying untrusted sources and keys. For JWTs and other JWS structures, headers such as 'jku', 'x5u', and 'jwk' must be validated against an allowlist of trusted sources. | **N/A** | |
| 9.2.1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. For example, for JWTs, the claims 'nbf' and 'exp' must be verified. | **N/A** | |
| **V10: OAuth and OIDC** | | | |
| 10.4.1 | Verify that the authorization server validates redirect URIs based on a client-specific allowlist of pre-registered URIs using exact string comparison. | **N/A** | |
| 10.4.2 | Verify that, if the authorization server returns the authorization code in the authorization response, it can be used only once for a token request. For the second valid request with an authorization code that has already been used to issue an access token, the authorization server must reject a token request and revoke any issued tokens related to the authorization code. | **N/A** | |
| 10.4.3 | Verify that the authorization code is short-lived. The maximum lifetime can be up to 10 minutes for L1 and L2 applications and up to 1 minute for L3 applications. | **N/A** | |
| 10.4.4 | Verify that for a given client, the authorization server only allows the usage of grants that this client needs to use. Note that the grants 'token' (Implicit flow) and 'password' (Resource Owner Password Credentials flow) must no longer be used. | **N/A** | |
| 10.4.5 | Verify that the authorization server mitigates refresh token replay attacks for public clients, preferably using sender-constrained refresh tokens, i.e., Demonstrating Proof of Possession (DPoP) or Certificate-Bound Access Tokens using mutual TLS (mTLS). For L1 and L2 applications, refresh token rotation may be used. If refresh token rotation is used, the authorization server must invalidate the refresh token after usage, and revoke all refresh tokens for that authorization if an already used and invalidated refresh token is provided. | **N/A** | |
| **V11: Cryptography** | | | |
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Fail** | See FINDING-009 |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Fail** | See FINDING-009 |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Pass** | |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Fail** | See FINDING-002, FINDING-010 |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Fail** | See FINDING-011 |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Fail** | See FINDING-012 |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** | |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **N/A** | |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** | |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **N/A** | |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **N/A** | |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** | |

**Summary Statistics:**
- **Pass**: 5 requirements (7.1%)
- **Partial**: 1 requirements (1.4%)
- **N/A**: 52 requirements (74.3%)
- **Fail**: 12 requirements (17.1%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-002 | High | 12.1.1 | FINDING-009, FINDING-010 | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-003 | High | 2.2.1, 2.2.2 | FINDING-004 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-004 | High | 2.2.1 | FINDING-003 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-005 | High | 2.2.1 | FINDING-006, FINDING-015 | http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-006 | High | 2.2.1 | FINDING-005, FINDING-015 | http2/src/main/java/org/apache/mina/http2/impl/Http2DataFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2ContinuationFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2HeadersFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2PushPromiseFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2UnknownFrameDecoder.java |
| FINDING-007 | High | 8.2.1, 8.2.2 | FINDING-017 | coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java |
| FINDING-008 | High | 1.2.1 | FINDING-020 | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| FINDING-009 | Medium | 11.3.1, 11.3.2 | FINDING-002, FINDING-010 | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-010 | Medium | 12.1.1 | FINDING-002, FINDING-009 | examples/src/main/java/org/apache/mina/examples/http/BogusSslContextFactory.java |
| FINDING-011 | Medium | 12.2.1 | — | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-012 | Medium | 12.2.2 | — | core/src/main/java/org/apache/mina/transport/nio/SslHelper.java |
| FINDING-013 | Medium | 2.2.1, 2.1.1 | FINDING-014 | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| FINDING-014 | Medium | 2.2.1 | FINDING-013 | http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2SettingsFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2RstStreamFrameDecoder.java, http2/src/main/java/org/apache/mina/http2/impl/Http2WindowUpdateFrameDecoder.java |
| FINDING-015 | Medium | 2.2.1 | FINDING-005, FINDING-006 | coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java |
| FINDING-016 | Medium | 8.1.1 | — | coap/src/main/java/org/apache/mina/coap/resource/ResourceHandler.java, coap/src/main/java/org/apache/mina/coap/resource/AbstractResourceHandler.java |
| FINDING-017 | Medium | 8.2.1 | FINDING-007 | coap/src/main/java/org/apache/mina/coap/resource/AbstractResourceHandler.java |
| FINDING-018 | Medium | 8.2.2 | — | coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java |
| FINDING-019 | Medium | 8.2.2 | — | coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java |
| FINDING-020 | Medium | 1.2.1 | FINDING-008 | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| FINDING-021 | Medium | 4.1.1 | — | http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |

**Total Unique Findings**: 21 (1 Critical, 7 High, 13 Medium, 0 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 21 |

**Total consolidated findings: 21**

*End of Consolidated Security Audit Report*