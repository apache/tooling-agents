# Security Issues

---

## Issue: FINDING-002 - No TLS protocol version restriction in SslHelper.init()
**Labels:** bug, security, priority:high
**Description:**
### Summary
SslHelper.init() does not restrict TLS versions to 1.2 and 1.3, potentially allowing negotiation of deprecated TLS 1.0/1.1 on older JDKs or custom configurations.

### Details
The SslHelper.init() method does not call `sslEngine.setEnabledProtocols()` to restrict TLS versions. While JDK 11+ disables TLS 1.0/1.1 by default, applications running on older JDKs or with custom java.security configurations remain vulnerable to BEAST, POODLE, and related attacks.

**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)  
**ASVS:** 12.1.1 (L1)

### Remediation
Add `sslEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"})` in SslHelper.init() after SSLEngine creation.

### Acceptance Criteria
- [ ] Fixed: Explicit TLS version restriction added to SslHelper.init()
- [ ] Test added: Verify TLS 1.0/1.1 connections are rejected
- [ ] Test added: Verify TLS 1.2/1.3 connections succeed

### References
- **Affected Files:**
  - `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`
- **Related Findings:** FINDING-009, FINDING-010

### Priority
**High** - Allows use of deprecated cryptographic protocols with known vulnerabilities

---

## Issue: FINDING-003 - HTTP request line parser does not validate split result structure
**Labels:** bug, security, priority:high
**Description:**
### Summary
HTTP request line parsing lacks complete validation of the split result structure, allowing malformed requests to cause exceptions or undefined behavior.

### Details
The HttpServerDecoder executes on the server side as the trusted service layer, but validation is incomplete. The server-side validation controls have gaps where request structure validation happens but is insufficient. This can lead to ArrayIndexOutOfBoundsException or processing of malformed requests.

**CWE:** CWE-129 (Improper Validation of Array Index)  
**ASVS:** 2.2.1, 2.2.2 (L1)

### Remediation
Enhance the server-side validation controls: validate that request line split produces exactly 3 elements (method, URI, version) before accessing array indices, and throw ProtocolDecoderException for malformed requests.

### Acceptance Criteria
- [ ] Fixed: Request line split result validated for correct structure
- [ ] Test added: Verify malformed request lines are rejected
- [ ] Test added: Verify proper error handling without exceptions

### References
- **Affected Files:**
  - `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`
- **Related Findings:** FINDING-004

### Priority
**High** - Input validation failure can cause server crashes or undefined behavior

---

## Issue: FINDING-004 - HTTP header parsing does not validate colon-split produces 2 elements
**Labels:** bug, security, priority:high
**Description:**
### Summary
HTTP header parsing does not validate that colon-split produces at least 2 elements, causing ArrayIndexOutOfBoundsException when processing headers without colons.

### Details
A header line without a colon character causes the parser to throw ArrayIndexOutOfBoundsException when attempting to access the value portion of the split result.

**CWE:** CWE-129 (Improper Validation of Array Index)  
**ASVS:** 2.2.1 (L1)

### Remediation
Use `split(pattern, 2)` and validate `header.length >= 2` before accessing `header[1]`, throwing ProtocolDecoderException on malformed headers.

### Acceptance Criteria
- [ ] Fixed: Header split result validated before array access
- [ ] Test added: Verify headers without colons are rejected gracefully
- [ ] Test added: Verify valid headers are processed correctly

### References
- **Affected Files:**
  - `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`
- **Related Findings:** FINDING-003

### Priority
**High** - Causes server crash on malformed input

---

## Issue: FINDING-005 - HTTP/1.x decoder enforces no maximum limit on header size
**Labels:** bug, security, priority:high
**Description:**
### Summary
The HTTP/1.x decoder enforces no maximum limit on total header size, individual header sizes, number of headers, or request line length, enabling memory exhaustion attacks.

### Details
An attacker can send arbitrarily large headers to consume server memory until exhaustion. There are no limits on:
- Total header size
- Individual header size
- Number of headers
- Request line length

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)  
**ASVS:** 2.2.1 (L1)

### Remediation
Implement a configurable maximum header size limit (e.g., 8KB default) and reject requests exceeding it with ProtocolDecoderException.

### Acceptance Criteria
- [ ] Fixed: Maximum header size limits implemented
- [ ] Test added: Verify oversized headers are rejected
- [ ] Test added: Verify legitimate large headers within limits are accepted
- [ ] Documentation: Configuration options for header size limits

### References
- **Affected Files:**
  - `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`
- **Related Findings:** FINDING-006, FINDING-015

### Priority
**High** - Enables memory exhaustion denial of service

---

## Issue: FINDING-006 - HTTP/2 frame decoders allocate arrays from wire-declared length without enforcing SETTINGS_MAX_FRAME_SIZE
**Labels:** bug, security, priority:high
**Description:**
### Summary
HTTP/2 frame decoders allocate byte arrays based on the frame length field (up to 16MB) without enforcing SETTINGS_MAX_FRAME_SIZE (default 16,384 bytes per RFC 7540).

### Details
The frame length field is 24 bits, allowing values up to 16,777,215 (16MB). An attacker can trigger allocation of 16MB byte arrays per frame, leading to rapid memory exhaustion. RFC 7540 Section 6.5.2 specifies SETTINGS_MAX_FRAME_SIZE should be enforced.

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)  
**ASVS:** 2.2.1 (L1)

### Remediation
Add a configurable maximum frame size (default 16,384 per RFC 7540) and reject frames exceeding it with FRAME_SIZE_ERROR before allocating buffers.

### Acceptance Criteria
- [ ] Fixed: Maximum frame size enforcement added to all frame decoders
- [ ] Test added: Verify oversized frames trigger FRAME_SIZE_ERROR
- [ ] Test added: Verify frames at maximum size are accepted
- [ ] Configuration: Make max frame size configurable

### References
- **Affected Files:**
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2DataFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2ContinuationFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2HeadersFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2PushPromiseFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2UnknownFrameDecoder.java`
- **Related Findings:** FINDING-005, FINDING-015

### Priority
**High** - Enables memory exhaustion denial of service via HTTP/2

---

## Issue: FINDING-007 - No Function-Level Access Control Enforcement in Request Routing
**Labels:** bug, security, priority:high
**Description:**
### Summary
Resource access is determined solely by path existence in the handlers map without verifying the requesting consumer has permission to access the specific resource (Broken Object Level Authorization - BOLA).

### Details
If a consumer knows or guesses the path of a resource (e.g., `users/admin/config`), they can access it without ownership or permission validation. The path is consumer-supplied (constructed from `URI_PATH` options) and directly used as a lookup key without authorization checks.

**CWE:** CWE-285 (Improper Authorization)  
**ASVS:** 8.2.1, 8.2.2 (L1)

### Remediation
Add a data-level authorization check in ResourceRegistry.respond() before handler invocation that verifies the authenticated consumer has explicit permission to access the specific resource identified by the requested path.

### Acceptance Criteria
- [ ] Fixed: Authorization check added before resource handler invocation
- [ ] Test added: Verify unauthorized access attempts are rejected
- [ ] Test added: Verify authorized access succeeds
- [ ] Documentation: Authorization model documented

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java`
- **Related Findings:** FINDING-017

### Priority
**High** - Classic BOLA vulnerability enabling unauthorized data access

---

## Issue: FINDING-008 - HTTP Response Splitting via Unvalidated Header Values in HttpServerEncoder
**Labels:** bug, security, priority:high
**Description:**
### Summary
No validation or encoding of CRLF sequences in header keys or values before writing them into the HTTP response, enabling HTTP response splitting attacks.

### Details
Application-provided header values flow through `msg.getHeaders()` via direct concatenation into HTTP response and onto the wire. If application code sets a header value containing CRLF, the resulting wire output would contain an injected header and potentially an injected body, splitting the HTTP response.

**CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)  
**ASVS:** 1.2.1 (L1)

### Remediation
Add CRLF validation to HttpServerEncoder. Reject or strip CR and LF characters in header names and values per RFC 7230 before writing them to the wire.

### Acceptance Criteria
- [ ] Fixed: CRLF validation added to header encoding
- [ ] Test added: Verify headers with CRLF are rejected or sanitized
- [ ] Test added: Verify response splitting attacks are prevented

### References
- **Affected Files:**
  - `http/src/main/java/org/apache/mina/http/HttpServerEncoder.java`
- **Related Findings:** FINDING-020

### Priority
**High** - Enables HTTP response splitting and cache poisoning attacks

---

## Issue: FINDING-009 - No cipher suite restriction in SslHelper.init() allows PKCS#1 v1.5 padding
**Labels:** bug, security, priority:medium
**Description:**
### Summary
SslHelper.init() does not restrict cipher suites to disable PKCS#1 v1.5 RSA key exchange, which is vulnerable to Bleichenbacher-style padding oracle attacks (ROBOT).

### Details
The method creates an SSLEngine without calling `setEnabledCipherSuites()` to disable cipher suites using PKCS#1 v1.5 RSA key exchange (e.g., TLS_RSA_WITH_AES_128_CBC_SHA256). While modern JDKs may disable some by default, the framework provides no explicit enforcement.

**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)  
**ASVS:** 11.3.1, 11.3.2 (L1)

### Remediation
Implement a configurable cipher suite allowlist in SslHelper defaulting to GCM and CHACHA20-POLY1305 modes only, filtering supported suites at initialization.

### Acceptance Criteria
- [ ] Fixed: Cipher suite filtering implemented
- [ ] Test added: Verify weak cipher suites are disabled
- [ ] Test added: Verify strong cipher suites are enabled
- [ ] Configuration: Make cipher suite list configurable

### References
- **Affected Files:**
  - `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`
- **Related Findings:** FINDING-002, FINDING-010

### Priority
**Medium** - Allows use of cipher suites vulnerable to padding oracle attacks

---

## Issue: FINDING-010 - Example code uses generic SSLContext.getInstance("TLS") without version restriction
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Example factory uses `SSLContext.getInstance("TLS")` which supports all TLS versions available in the JDK, providing a pattern that developers may copy without proper version restrictions.

### Details
While this is example code, the pattern without subsequent protocol restriction in SslHelper means any code copying this pattern will not enforce TLS 1.2+. This creates a documentation and example quality issue that can propagate to production code.

**CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)  
**ASVS:** 12.1.1 (L1)

### Remediation
Change PROTOCOL constant to "TLSv1.3" or "TLSv1.2" as minimum in example code.

### Acceptance Criteria
- [ ] Fixed: Example code updated to use specific TLS version
- [ ] Documentation: Add comments explaining TLS version selection
- [ ] Review: Verify no other examples use generic "TLS" context

### References
- **Affected Files:**
  - `examples/src/main/java/org/apache/mina/examples/http/BogusSslContextFactory.java`
- **Related Findings:** FINDING-002, FINDING-009

### Priority
**Medium** - Example code promotes insecure pattern

---

## Issue: FINDING-011 - Plaintext fallback after TLS session closure in SslHelper.processWrite()
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When an SSL/TLS session is closed, SslHelper transitions to NO_CREDENTIALS state where processWrite() passes messages through without encryption, creating a plaintext fallback scenario.

### Details
When the TLS session terminates unexpectedly (either by the peer or due to an error), application data that was being sent over an encrypted channel could silently fall back to plaintext transmission. This violates the expectation of continuous encryption.

**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)  
**ASVS:** 12.2.1 (L1)

### Remediation
In processWrite() NO_CREDENTIALS case, throw IllegalStateException or close the session instead of allowing plaintext writes.

### Acceptance Criteria
- [ ] Fixed: NO_CREDENTIALS state prevents plaintext transmission
- [ ] Test added: Verify session closure prevents further writes
- [ ] Test added: Verify appropriate exception is thrown

### References
- **Affected Files:**
  - `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`

### Priority
**Medium** - Enables silent downgrade to plaintext transmission

---

## Issue: FINDING-012 - No hostname verification or certificate trust validation in SslHelper
**Labels:** bug, security, priority:medium
**Description:**
### Summary
SslHelper accepts any SSLContext without validation of publicly trusted certificates or proper trust chain configuration, and does not enable hostname verification for client-mode connections.

### Details
For client-mode connections, there is no explicit enabling of hostname verification (`SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`). Applications could be configured with self-signed certificates for external-facing services, or client connections could be vulnerable to MITM attacks.

**CWE:** CWE-295 (Improper Certificate Validation)  
**ASVS:** 12.2.2 (L1)

### Remediation
Enable hostname verification for client mode by setting `SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")` in SslHelper.init().

### Acceptance Criteria
- [ ] Fixed: Hostname verification enabled for client mode
- [ ] Test added: Verify hostname mismatch is rejected
- [ ] Test added: Verify valid hostname is accepted

### References
- **Affected Files:**
  - `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`

### Priority
**Medium** - Enables man-in-the-middle attacks on client connections

---

## Issue: FINDING-013 - CoAP token length field accepts reserved values 9-15
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Protocol decoders lack documented input validation rules and the CoAP decoder accepts token length values 9-15 which are reserved per RFC 7252 (valid range is 0-8).

### Details
While the code references RFCs implicitly, no formal validation rules document specifies constraints such as:
- Maximum token lengths for CoAP (RFC specifies 0-8, code allows 0-15)
- Maximum header sizes for HTTP/1.x
- Maximum frame sizes for HTTP/2
- Acceptable ranges for padding lengths

**CWE:** CWE-20 (Improper Input Validation)  
**ASVS:** 2.2.1, 2.1.1 (L1)

### Remediation
Create a validation rules document (or annotate the code with formal constraints) specifying protocol-specific constraints. Enforce CoAP Token Length (TKL) MUST be 0-8, reject values 9-15.

### Acceptance Criteria
- [ ] Fixed: Token length validation enforces 0-8 range
- [ ] Test added: Verify reserved token lengths are rejected
- [ ] Documentation: Validation rules documented

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java`
- **Related Findings:** FINDING-014

### Priority
**Medium** - Protocol compliance violation enables undefined behavior

---

## Issue: FINDING-014 - HTTP/2 frame-specific decoders do not validate RFC-required frame lengths
**Labels:** bug, security, priority:medium
**Description:**
### Summary
HTTP/2 frame-specific decoders do not validate that declared frame length matches RFC-required size for their frame type.

### Details
Per RFC 7540:
- PING must be 8 bytes
- RST_STREAM must be 4 bytes
- WINDOW_UPDATE must be 4 bytes
- SETTINGS must be a multiple of 6 bytes

Invalid sizes should trigger FRAME_SIZE_ERROR but are currently not validated.

**CWE:** CWE-20 (Improper Input Validation)  
**ASVS:** 2.2.1 (L1)

### Remediation
Add frame-type-specific length validation in each decoder constructor and throw FRAME_SIZE_ERROR for non-compliant lengths.

### Acceptance Criteria
- [ ] Fixed: Frame length validation added to all affected decoders
- [ ] Test added: Verify invalid frame lengths trigger FRAME_SIZE_ERROR
- [ ] Test added: Verify valid frame lengths are accepted

### References
- **Affected Files:**
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2SettingsFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2RstStreamFrameDecoder.java`
  - `http2/src/main/java/org/apache/mina/http2/impl/Http2WindowUpdateFrameDecoder.java`
- **Related Findings:** FINDING-013

### Priority
**Medium** - RFC compliance violation enables protocol confusion

---

## Issue: FINDING-015 - CoAP option decoder does not enforce limits on number of options or total option data size
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The CoAP option decoder does not enforce limits on the number of options or total option data size, enabling memory exhaustion attacks.

### Details
An attacker can send a CoAP message with thousands of options, each with large values, consuming excessive memory through ArrayList growth and byte array allocations. RFC 7252 suggests reasonable limits but these are not enforced.

**CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)  
**ASVS:** 2.2.1 (L1)

### Remediation
Add configurable maximum option count (e.g., 64) and maximum option size (e.g., 1034 per RFC 7252) limits, throwing ProtocolDecoderException when exceeded.

### Acceptance Criteria
- [ ] Fixed: Option count and size limits implemented
- [ ] Test added: Verify excessive options are rejected
- [ ] Test added: Verify legitimate option usage is accepted
- [ ] Configuration: Make limits configurable

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java`
- **Related Findings:** FINDING-005, FINDING-006

### Priority
**Medium** - Enables memory exhaustion denial of service

---

## Issue: FINDING-016 - No Authorization Documentation Exists in CoAP Resource Framework
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The CoAP resource framework defines no authorization rules, documentation, or contracts specifying how function-level or data-specific access should be restricted.

### Details
The `ResourceHandler` interface's `handle()` method documentation describes only request/response mechanics with no mention of required authorization checks. The `AbstractResourceHandler` base class provides convenience defaults but omits any authorization-related methods, constants, annotations, or documentation.

**ASVS:** 8.1.1 (L1)

### Remediation
Define authorization documentation either as Javadoc contracts, security annotations, or a companion design document specifying that implementations MUST verify CoAP method code permissions and data-level access before processing requests.

### Acceptance Criteria
- [ ] Documentation: Authorization requirements documented
- [ ] Documentation: Example authorization implementation provided
- [ ] Review: Security guidelines added to developer documentation

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/resource/ResourceHandler.java`
  - `coap/src/main/java/org/apache/mina/coap/resource/AbstractResourceHandler.java`

### Priority
**Medium** - Lack of authorization guidance leads to insecure implementations

---

## Issue: FINDING-017 - AbstractResourceHandler Provides No Authorization Baseline for Subclasses
**Labels:** bug, security, priority:medium
**Description:**
### Summary
AbstractResourceHandler provides no authorization template, utility methods, or examples, forcing subclasses to independently discover and implement authorization from scratch.

### Details
The base class is the intended extension point but offers no `checkPermission()` utility method, no authentication extraction helper, and no example of how `handle()` implementations should verify function-level access. This creates inconsistent security implementations.

**CWE:** CWE-285 (Improper Authorization)  
**ASVS:** 8.2.1 (L1)

### Remediation
Add a `checkFunctionAccess()` template method to AbstractResourceHandler that subclasses must implement or explicitly override, along with a `getPermittedMethods()` abstract method to declare allowed operations.

### Acceptance Criteria
- [ ] Fixed: Authorization template methods added to base class
- [ ] Documentation: Authorization pattern documented
- [ ] Example: Reference implementation provided

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/resource/AbstractResourceHandler.java`
- **Related Findings:** FINDING-007

### Priority
**Medium** - Missing security baseline leads to inconsistent implementations

---

## Issue: FINDING-018 - Discovery Endpoint Exposes All Registered Resources Without Authorization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `.well-known/core` discovery endpoint unconditionally enumerates ALL registered resources without authorization checks or permission-based filtering.

### Details
No authorization check is performed, and no filtering is applied based on the consumer's permissions. This information disclosure reveals:
- Resource paths
- Interface descriptions
- Resource types
- Titles

This directly facilitates BOLA attacks by revealing valid resource paths to unauthorized users.

**CWE:** CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)  
**ASVS:** 8.2.2 (L1)

### Remediation
Filter `.well-known/core` discovery responses based on the consumer's permissions so that only resources the consumer is authorized to access are enumerated.

### Acceptance Criteria
- [ ] Fixed: Discovery responses filtered by consumer permissions
- [ ] Test added: Verify unauthorized resources are not disclosed
- [ ] Test added: Verify authorized resources are included

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java`

### Priority
**Medium** - Information disclosure facilitates authorization bypass attacks

---

## Issue: FINDING-019 - Path Construction From Untrusted Options Without Canonicalization Enables Authorization Bypass
**Labels:** bug, security, priority:medium
**Description:**
### Summary
URL is constructed by concatenating raw `URI_PATH` option data without normalization or canonicalization, potentially enabling authorization bypass if path-based policies are added.

### Details
URI_PATH options could contain encoded characters, empty segments, or case variations that create multiple representations of the same logical resource. While current exact-match lookup limits exploitability, future path-prefix-based authorization policies could be bypassed.

**CWE:** CWE-706 (Use of Incorrectly-Resolved Name or Reference)  
**ASVS:** 8.2.2 (L1)

### Remediation
Add path canonicalization (removing empty segments, normalizing case, decoding percent-encoding) before path lookup and any authorization checks.

### Acceptance Criteria
- [ ] Fixed: Path canonicalization implemented
- [ ] Test added: Verify path variations resolve to same canonical path
- [ ] Test added: Verify authorization bypass attempts fail

### References
- **Affected Files:**
  - `coap/src/main/java/org/apache/mina/coap/resource/ResourceRegistry.java`

### Priority
**Medium** - Enables potential authorization bypass via path manipulation

---

## Issue: FINDING-020 - No Validation of Status Line Structure in HttpServerEncoder
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The status line returned by `getStatus().line()` is used directly as the first line of the HTTP response without validation, potentially allowing HTTP response structure alteration.

### Details
If custom implementations provide arbitrary values for the status line, the HTTP response structure could be altered. This is related to but distinct from CRLF injection in headers.

**CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)  
**ASVS:** 1.2.1 (L1)

### Remediation
Validate that the status line conforms to the expected HTTP status line format (`HTTP/x.x NNN Reason\r\n`) before writing to output.

### Acceptance Criteria
- [ ] Fixed: Status line format validation implemented
- [ ] Test added: Verify malformed status lines are rejected
- [ ] Test added: Verify valid status lines are accepted

### References
- **Affected Files:**
  - `http/src/main/java/org/apache/mina/http/HttpServerEncoder.java`
- **Related Findings:** FINDING-008

### Priority
**Medium** - Enables HTTP response structure manipulation

---

## Issue: FINDING-021 - HTTP Response Encoder Does Not Validate or Enforce Content-Type Header Presence
**Labels:** bug, security, priority:medium
**Description:**
### Summary
HttpServerEncoder does not validate that Content-Type header is present for responses with bodies, enabling browser content sniffing and MIME confusion attacks.

### Details
Applications using MINA's HTTP encoder can send responses with message bodies but without a Content-Type header or without a proper charset parameter. This leads to:
- Browser content sniffing (MIME confusion attacks)
- Character encoding attacks
- XSS via content-type mismatch

**CWE:** CWE-116 (Improper Encoding or Escaping of Output)  
**ASVS:** 4.1.1 (L1)

### Remediation
Add optional validation in HttpServerEncoder to warn or reject responses missing Content-Type headers when a body is present. At minimum, log a warning when Content-Type is absent.

### Acceptance Criteria
- [ ] Fixed: Content-Type validation added for responses with bodies
- [ ] Test added: Verify warning/error when Content-Type is missing
- [ ] Test added: Verify responses with Content-Type are accepted
- [ ] Configuration: Make validation level configurable (warn/error)

### References
- **Affected Files:**
  - `http/src/main/java/org/apache/mina/http/HttpServerEncoder.java`

### Priority
**Medium** - Enables content sniffing and XSS attacks