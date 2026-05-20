# Security Issues

---

## Issue: FINDING-001 - HTTP/2 Signed Byte Interpretation of Padding Length Field
**Labels:** bug, security, priority:high
**Description:**

### Summary
Wire byte (unsigned 0-255) is read via buffer.get() (Java signed byte -128 to 127) and sign-extended into padLength. A pad length byte of 0x80 (128 unsigned) is interpreted as -128, causing the decoder to create a BytePartialDecoder that consumes bytes beyond the frame boundary, reading data from subsequent frames.

### Details
**CWE:** CWE-681  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2DataFrameDecoder.java`
- `http2/src/main/java/org/apache/mina/http2/impl/Http2HeadersFrameDecoder.java`
- `http2/src/main/java/org/apache/mina/http2/impl/Http2PushPromiseFrameDecoder.java`

The padding length field is extracted as a signed byte and used directly without proper unsigned conversion, causing negative values for bytes 0x80-0xFF. This violates RFC 7540 frame padding semantics and can lead to reading beyond frame boundaries.

### Remediation
Change `padLength = buffer.get()` to `padLength = buffer.get() & 0xFF` and add RFC 7540-mandated validation that padding does not exceed frame payload length.

### Acceptance Criteria
- [ ] Fixed: All three decoders convert padding length to unsigned byte
- [ ] Test added: Unit test covering padding length values 0x00-0xFF
- [ ] Test added: Validation test rejecting padding exceeding payload length

### References
- RFC 7540 Section 6.1, 6.2, 6.6 (Padding)
- Source Report: 2.2.1.md

### Priority
High

---

## Issue: FINDING-002 - HTTP/1.x Header Parsing Missing Bounds Check on Colon Split
**Labels:** bug, security, priority:high
**Description:**

### Summary
Header lines split on ':' without checking the result array length. A header line without a colon produces a single-element array, and accessing header[1] throws ArrayIndexOutOfBoundsException, crashing the connection handler.

### Details
**CWE:** CWE-129  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

The header parsing logic splits on ':' and immediately accesses index [1] without verifying the array has at least 2 elements. Malformed headers (e.g., "HeaderName" without colon) cause uncaught exceptions.

### Remediation
Add bounds check after splitting: if (header.length < 2) throw ProtocolDecoderException. Also limit split to 2 parts to handle colons in header values.

### Acceptance Criteria
- [ ] Fixed: Bounds check added before accessing header[1]
- [ ] Test added: Malformed header without colon returns proper error
- [ ] Test added: Header with multiple colons parsed correctly

### References
- Source Report: 2.2.1.md
- Related: FINDING-003

### Priority
High

---

## Issue: FINDING-003 - HTTP/1.x Request Line Parsing Missing Bounds Check
**Labels:** bug, security, priority:high
**Description:**

### Summary
Request line split on spaces without checking result array length. A request line with insufficient spaces produces too few elements, and accessing elements[2] throws ArrayIndexOutOfBoundsException.

### Details
**CWE:** CWE-129  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

The request line parser splits on whitespace and accesses indices [0], [1], [2] without verifying the array contains 3 elements (method, URI, version). Malformed requests cause crashes.

### Remediation
Add bounds check: if (elements.length < 3) throw ProtocolDecoderException with descriptive message.

### Acceptance Criteria
- [ ] Fixed: Bounds check added before accessing elements[2]
- [ ] Test added: Request line with 0, 1, 2 spaces returns proper error
- [ ] Test added: Valid request line still parses correctly

### References
- Source Report: 2.2.1.md
- Related: FINDING-002

### Priority
High

---

## Issue: FINDING-004 - HTTP Header Value CRLF Injection Due to Missing Output Encoding in HttpServerEncoder
**Labels:** bug, security, priority:high
**Description:**

### Summary
The HttpServerEncoder serializes application-supplied header names and values directly into the HTTP wire format without any validation or sanitization of CRLF characters. This enables HTTP Response Splitting attacks where an attacker who can influence header values can inject arbitrary headers or body content.

### Details
**CWE:** CWE-113  
**ASVS:** 1.2.1 (L1)  
**Affected Files:**
- `http/src/main/java/org/apache/mina/http/HttpServerEncoder.java`

Application-controlled header values containing \r\n sequences are written directly to the wire, allowing injection of additional headers or premature response termination. This is a classic HTTP Response Splitting vulnerability.

### Remediation
Add header name and value validation that rejects or strips \r and \n characters before serialization in HttpServerEncoder.visit(HttpResponse). Validate header names conform to RFC 7230 §3.2.6 token production.

### Acceptance Criteria
- [ ] Fixed: Header values with \r or \n are rejected or sanitized
- [ ] Fixed: Header names validated against RFC 7230 token grammar
- [ ] Test added: Response splitting attack blocked
- [ ] Test added: Valid headers still encoded correctly

### References
- RFC 7230 Section 3.2
- Source Report: 1.2.1.md

### Priority
High

---

## Issue: FINDING-005 - CoAP Decoder Lacks Documentation of Token Length Validation Rules
**Labels:** documentation, security, priority:medium
**Description:**

### Summary
The CoAP decoder does not document or enforce the validation rule that Token Length (TKL) field values 9-15 are reserved per RFC 7252 §3. There is no javadoc, inline comment, or configuration that defines the valid range.

### Details
**CWE:** CWE-20  
**ASVS:** 2.1.1 (L1)  
**Affected Files:**
- `coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java`

The decoder extracts and uses TKL values without documenting the RFC-mandated constraints. This makes it difficult for maintainers to understand validation requirements.

### Remediation
Add validation documentation either in javadoc or in a validation rules file documenting TKL (0-8), option delta/length constraints, and version requirements.

### Acceptance Criteria
- [ ] Fixed: Javadoc added documenting TKL valid range (0-8)
- [ ] Fixed: Documentation covers option delta/length constraints
- [ ] Fixed: Version field requirements documented

### References
- RFC 7252 Section 3
- Source Report: 2.1.1.md
- Related: FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-011, FINDING-012

### Priority
Medium

---

## Issue: FINDING-006 - HTTP/1.x Decoder Lacks Documentation of Header Parsing Validation Rules
**Labels:** documentation, security, priority:medium
**Description:**

### Summary
The HTTP server decoder does not document expected structural constraints for parsed input including: maximum header count, maximum header line length, maximum total header size, required format for header lines, or valid characters in header names/values.

### Details
**CWE:** CWE-20  
**ASVS:** 2.1.1 (L1)  
**Affected Files:**
- `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

Without documented validation rules, implementers cannot determine the security boundaries of the parser or verify compliance with HTTP specifications.

### Remediation
Document the expected HTTP parsing rules including maximum header size, maximum header count, header line format requirements, and request line structure.

### Acceptance Criteria
- [ ] Fixed: Maximum header size documented
- [ ] Fixed: Maximum header count documented
- [ ] Fixed: Header line format requirements documented
- [ ] Fixed: Request line structure requirements documented

### References
- Source Report: 2.1.1.md
- Related: FINDING-005, FINDING-007, FINDING-008, FINDING-010, FINDING-011, FINDING-012

### Priority
Medium

---

## Issue: FINDING-007 - HTTP/2 Frame Decoders Lack Documentation of Protocol-Required Length Constraints
**Labels:** documentation, security, priority:medium
**Description:**

### Summary
The HTTP/2 implementation does not document validation rules for frame-type-specific length requirements mandated by RFC 7540 (PING=8, RST_STREAM=4, PRIORITY=5, WINDOW_UPDATE=4, SETTINGS=%6).

### Details
**CWE:** CWE-20  
**ASVS:** 2.1.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2FrameHeadePartialDecoder.java`

Frame decoders lack documentation of RFC-mandated fixed-length requirements, making it unclear whether validation is intended or missing.

### Remediation
Add protocol-specific validation documentation to each frame decoder class.

### Acceptance Criteria
- [ ] Fixed: Each frame decoder documents its RFC-mandated length constraint
- [ ] Fixed: Validation logic or rationale for absence documented

### References
- RFC 7540 Sections 6.4, 6.5, 6.7, 6.9
- Source Report: 2.1.1.md
- Related: FINDING-005, FINDING-006, FINDING-008, FINDING-010, FINDING-011, FINDING-012

### Priority
Medium

---

## Issue: FINDING-008 - CoAP Decoder Accepts Reserved Token Length Values 9-15
**Labels:** bug, security, priority:medium
**Description:**

### Summary
TKL field extracted as byte0 & 0xF (range 0-15) and used directly for token array allocation. RFC 7252 §3 states TKL values 9-15 are reserved and MUST be treated as a message format error.

### Details
**CWE:** CWE-20  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `coap/src/main/java/org/apache/mina/coap/codec/CoapDecoder.java`

The decoder accepts and processes reserved TKL values, violating RFC requirements. This could lead to interoperability issues or exploitation of implementation-specific behavior.

### Remediation
Add validation: if (tkl > 8) throw ProtocolDecoderException.

### Acceptance Criteria
- [ ] Fixed: TKL values 9-15 rejected with ProtocolDecoderException
- [ ] Test added: Reserved TKL values 9-15 all rejected
- [ ] Test added: Valid TKL values 0-8 still accepted

### References
- RFC 7252 Section 3
- Source Report: 2.2.1.md
- Related: FINDING-005, FINDING-006, FINDING-007, FINDING-010, FINDING-011, FINDING-012

### Priority
Medium

---

## Issue: FINDING-009 - HTTP/2 Frame Header Accepts Unrestricted Frame Length
**Labels:** bug, security, priority:medium
**Description:**

### Summary
Frame length field (24-bit, up to 16,777,215) is accepted without validation against SETTINGS_MAX_FRAME_SIZE (default 16,384 per RFC 7540 §4.2). A single frame can trigger 16 MB heap allocation.

### Details
**CWE:** CWE-770  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2FrameHeadePartialDecoder.java`

The frame header decoder accepts the full 24-bit length range without enforcing the default or negotiated maximum frame size, enabling memory exhaustion attacks.

### Remediation
Enforce configurable maximum frame size (default 16,384) in Http2FrameHeadePartialDecoder after parsing the length field.

### Acceptance Criteria
- [ ] Fixed: Default max frame size of 16,384 enforced
- [ ] Fixed: Max frame size configurable per connection
- [ ] Test added: Oversized frame rejected
- [ ] Test added: Frame at limit accepted

### References
- RFC 7540 Section 4.2
- Source Report: 2.2.1.md
- Related: FINDING-014

### Priority
Medium

---

## Issue: FINDING-010 - HTTP/2 PING Frame Length Not Validated
**Labels:** bug, security, priority:medium
**Description:**

### Summary
PING frame decoder accepts any length without validating RFC 7540 §6.7 requirement of exactly 8 octets. Non-8-byte PING frames should be treated as FRAME_SIZE_ERROR.

### Details
**CWE:** CWE-20  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2PingFrameDecoder.java`

The PING frame decoder does not enforce the fixed 8-byte payload requirement, allowing malformed frames to be processed.

### Remediation
Add validation in constructor: if (header.getLength() != 8) throw ProtocolDecoderException.

### Acceptance Criteria
- [ ] Fixed: PING frames with length != 8 rejected
- [ ] Test added: PING with length 7, 9 rejected
- [ ] Test added: PING with length 8 accepted

### References
- RFC 7540 Section 6.7
- Source Report: 2.2.1.md
- Related: FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-011, FINDING-012

### Priority
Medium

---

## Issue: FINDING-011 - HTTP/2 RST_STREAM Frame Length Not Validated
**Labels:** bug, security, priority:medium
**Description:**

### Summary
RST_STREAM decoder accepts any length without validating RFC 7540 §6.4 requirement of exactly 4 octets.

### Details
**CWE:** CWE-20  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2RstStreamFrameDecoder.java`

The RST_STREAM frame decoder does not enforce the fixed 4-byte payload requirement.

### Remediation
Add validation: if (header.getLength() != 4) throw ProtocolDecoderException.

### Acceptance Criteria
- [ ] Fixed: RST_STREAM frames with length != 4 rejected
- [ ] Test added: RST_STREAM with length 3, 5 rejected
- [ ] Test added: RST_STREAM with length 4 accepted

### References
- RFC 7540 Section 6.4
- Source Report: 2.2.1.md
- Related: FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-012

### Priority
Medium

---

## Issue: FINDING-012 - HTTP/2 SETTINGS Frame Length Not Validated as Multiple of 6
**Labels:** bug, security, priority:medium
**Description:**

### Summary
SETTINGS frame length divided by 6 using integer division, silently discarding remainder bytes. RFC 7540 §6.5 requires length to be a multiple of 6.

### Details
**CWE:** CWE-20  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2SettingsFrameDecoder.java`

The decoder uses integer division (length / 6) to determine the number of settings, silently ignoring any remainder bytes instead of treating this as a protocol error.

### Remediation
Add validation: if (header.getLength() % 6 != 0) throw ProtocolDecoderException.

### Acceptance Criteria
- [ ] Fixed: SETTINGS frames with length % 6 != 0 rejected
- [ ] Test added: SETTINGS with length 7, 11 rejected
- [ ] Test added: SETTINGS with length 0, 6, 12 accepted

### References
- RFC 7540 Section 6.5
- Source Report: 2.2.1.md
- Related: FINDING-005, FINDING-006, FINDING-007, FINDING-008, FINDING-010, FINDING-011

### Priority
Medium

---

## Issue: FINDING-013 - HTTP/2 GoAway Frame Decoder Missing Break Statement Causes Incorrect Parsing
**Labels:** bug, security, priority:medium
**Description:**

### Summary
Missing break statement between LAST_STREAM_ID and CODE cases in switch statement. When decoder.consume() returns false for LAST_STREAM_ID, execution falls through to CODE case, potentially causing ClassCastException or parsing corruption under specific TCP fragmentation patterns.

### Details
**CWE:** CWE-484  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http2/src/main/java/org/apache/mina/http2/impl/Http2GoAwayFrameDecoder.java`

The switch statement in the GoAway frame decoder is missing a break statement, causing fall-through behavior that can corrupt parsing state when partial frame data is received.

### Remediation
Add break statement after the LAST_STREAM_ID case block.

### Acceptance Criteria
- [ ] Fixed: Break statement added after LAST_STREAM_ID case
- [ ] Test added: Fragmented GoAway frame parsed correctly
- [ ] Test added: Complete GoAway frame still works

### References
- Source Report: 2.2.1.md

### Priority
Medium

---

## Issue: FINDING-014 - HTTP/1.x No Maximum Header Size Enforcement
**Labels:** bug, security, priority:medium
**Description:**

### Summary
The HEAD state accumulates partial buffers indefinitely without a maximum size check. An attacker can exhaust memory by slowly sending header bytes without a terminating blank line.

### Details
**CWE:** CWE-770  
**ASVS:** 2.2.1 (L1)  
**Affected Files:**
- `http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

The decoder concatenates partial header buffers without any size limit, enabling a slowloris-style memory exhaustion attack.

### Remediation
Add a configurable maximum header size check (e.g., 8192 bytes) in the HEAD state before concatenating buffers.

### Acceptance Criteria
- [ ] Fixed: Maximum header size enforced (default 8192 bytes)
- [ ] Fixed: Maximum configurable per connection
- [ ] Test added: Oversized headers rejected
- [ ] Test added: Headers at limit accepted

### References
- Source Report: 2.2.1.md
- Related: FINDING-009

### Priority
Medium

---

## Issue: FINDING-015 - Silent plaintext fallback after TLS session closure
**Labels:** bug, security, priority:medium
**Description:**

### Summary
When the TLS session transitions to NO_CREDENTIALS state (via switchToNoSecure()), subsequent application messages are silently passed through without encryption. The method does not throw an exception, log a warning, or refuse the write. This constitutes a silent plaintext fallback.

### Details
**CWE:** CWE-319  
**ASVS:** 12.2.1 (L1)  
**Affected Files:**
- `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`

After TLS close_notify, the session switches to NO_CREDENTIALS but continues accepting writes, sending them in plaintext. Applications may not realize encryption has been lost.

### Remediation
Change the NO_CREDENTIALS case to throw an exception or refuse the write. If plaintext fallback is intentional for specific scenarios, require explicit opt-in via a session attribute.

### Acceptance Criteria
- [ ] Fixed: Writes after TLS closure throw exception
- [ ] Fixed: Opt-in mechanism for intentional plaintext fallback
- [ ] Test added: Write after close_notify rejected
- [ ] Test added: Opt-in fallback works when enabled

### References
- Source Report: 12.2.1.md
- Related: FINDING-018

### Priority
Medium

---

## Issue: FINDING-016 - SSLEngine cipher suites not restricted to AEAD modes
**Labels:** enhancement, security, priority:low
**Description:**

### Summary
The SSLEngine is used without restricting cipher suites to approved AEAD modes (AES-GCM, ChaCha20-Poly1305). Modern JDKs still enable CBC-based cipher suites which do not provide authenticated encryption. Low practical risk on modern JDKs where GCM suites are preferred during negotiation, but CBC-mode suites remain as fallback options.

### Details
**ASVS:** 11.3.2 (L1)  
**Affected Files:**
- `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`

The SSLEngine uses default cipher suite list, which includes non-AEAD modes. While modern JDKs prefer GCM, CBC suites remain enabled as fallback.

### Remediation
Filter enabled cipher suites to GCM and ChaCha20-Poly1305 variants in SslHelper.init(), e.g., Arrays.stream(sslEngine.getSupportedCipherSuites()).filter(c -> c.contains("_GCM_") || c.contains("CHACHA20")).toArray(String[]::new)

### Acceptance Criteria
- [ ] Fixed: Only AEAD cipher suites enabled by default
- [ ] Fixed: Configuration option to override if needed
- [ ] Test added: Non-AEAD suites not negotiated

### References
- Source Report: 11.3.2.md

### Priority
Low (defense-in-depth)

---

## Issue: FINDING-017 - No setEnabledProtocols() call restricting TLS versions
**Labels:** enhancement, security, priority:low
**Description:**

### Summary
After creating the SSLEngine, the init() method never calls sslEngine.setEnabledProtocols() to restrict protocols to TLS 1.2 and TLS 1.3. DOWNGRADED from Medium: per project severity policy, TLS version restriction findings in SslHelper should not be rated Medium/High when JDK 11+ defaults already disable legacy protocols; characterized as defense-in-depth improvement with low practical risk.

### Details
**CWE:** CWE-327  
**ASVS:** 12.1.1 (L1)  
**Affected Files:**
- `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`

The SSLEngine relies on JDK defaults for protocol version selection. While JDK 11+ disables TLS 1.0/1.1 by default, explicit restriction provides defense-in-depth.

### Remediation
Add sslEngine.setEnabledProtocols(new String[]{"TLSv1.3", "TLSv1.2"}) in init(). Provide an attribute key for applications needing to override.

### Acceptance Criteria
- [ ] Fixed: Only TLS 1.2 and 1.3 enabled by default
- [ ] Fixed: Configuration option to override if needed
- [ ] Test added: TLS 1.0/1.1 not negotiated

### References
- Source Report: 12.1.1.md

### Priority
Low (defense-in-depth)

---

## Issue: FINDING-018 - ProxyTcpSessionConfig silently discards TLS configuration
**Labels:** bug, security, priority:low
**Description:**

### Summary
The ProxyTcpSessionConfig implementation silently discards any attempt to configure TLS via setSslContext(). An application that sets an SSLContext on this config would receive no error but get a plaintext connection.

### Details
**CWE:** CWE-319  
**ASVS:** 12.2.1 (L1)  
**Affected Files:**
- `core/src/main/java/org/apache/mina/transport/tcp/ProxyTcpSessionConfig.java`

The proxy config's setSslContext() is a no-op. Applications expecting TLS would silently get plaintext, though this is likely a configuration error rather than an attack vector.

### Remediation
Make setSslContext() throw UnsupportedOperationException when a non-null SSLContext is provided, to make the incompatibility explicit.

### Acceptance Criteria
- [ ] Fixed: setSslContext() with non-null argument throws exception
- [ ] Test added: Exception thrown when attempting TLS config

### References
- Source Report: 12.2.1.md
- Related: FINDING-015

### Priority
Low

---

## Issue: FINDING-019 - No hostname verification enabled for client-mode SSLEngine
**Labels:** enhancement, security, priority:low
**Description:**

### Summary
When the SSLEngine is configured in client mode, hostname verification is never enabled via SSLParameters.setEndpointIdentificationAlgorithm("HTTPS"). Unlike HttpsURLConnection, raw SSLEngine does NOT perform hostname verification by default. DOWNGRADED from Medium: per project security profile, TLS configuration is partially delegated to application-supplied SSLParameters; the application can configure endpoint identification. However, unlike protocol version restrictions, JDK defaults do NOT cover this for raw SSLEngine, so this remains a valid defense-in-depth finding.

### Details
**CWE:** CWE-297  
**ASVS:** 12.2.2 (L1)  
**Affected Files:**
- `core/src/main/java/org/apache/mina/transport/nio/SslHelper.java`

Client-mode SSLEngine does not enable hostname verification by default, unlike higher-level APIs. Applications must explicitly configure this.

### Remediation
In SslHelper.init(), when useClientMode is true, set SSLParameters.setEndpointIdentificationAlgorithm("HTTPS"). Provide an attribute key (SKIP_HOSTNAME_VERIFICATION) for applications that explicitly need to bypass this.

### Acceptance Criteria
- [ ] Fixed: Hostname verification enabled for client mode by default
- [ ] Fixed: Opt-out mechanism via session attribute
- [ ] Test added: Hostname mismatch rejected
- [ ] Test added: Opt-out allows mismatch when enabled

### References
- Source Report: 12.2.2.md

### Priority
Low (defense-in-depth)