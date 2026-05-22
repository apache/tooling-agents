# Security Issues

## Issue: FINDING-001 - Missing Transfer-Encoding handling enables HTTP Request Smuggling
**Labels:** bug, security, priority:high
**Description:**
### Summary
The HttpServerDecoder only checks Content-Length for body framing and completely ignores Transfer-Encoding headers. This enables HTTP Request Smuggling when the server is deployed behind a reverse proxy that prioritizes Transfer-Encoding per RFC 7230 §3.3.3.

### Details
**CWE:** CWE-444  
**ASVS:** 4.2.1, 4.2.2 (L2, L3)  
**Affected Files:**
- `mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

When both Content-Length and Transfer-Encoding headers are present, no conflict detection occurs, enabling CL.TE request smuggling attacks. The decoder does not implement chunked transfer encoding handling or validation.

### Remediation
After parsing headers, check for Transfer-Encoding. If both Transfer-Encoding and Content-Length are present, reject the request with 400 Bad Request. If only Transfer-Encoding: chunked is present, either implement chunked decoding or reject with 501 Not Implemented.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-009
- Source reports: 4.2.1.md, 4.2.2.md

### Priority
High

---
## Issue: FINDING-002 - No maximum size limit on accumulated partial HTTP request headers enables memory exhaustion DoS
**Labels:** bug, security, priority:high
**Description:**
### Summary
The HttpServerDecoder accumulates partial header data in a session attribute (PARTIAL_HEAD_ATT) without any size limit. An attacker can open many connections and slowly feed header bytes without completing them, causing unbounded heap memory allocation and eventual OOM.

### Details
**CWE:** CWE-770  
**ASVS:** 4.2.5 (L3)  
**Affected Files:**
- `mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

No configurable limits exist for maximum header count or maximum individual header line length, allowing resource exhaustion attacks.

### Remediation
Implement configurable limits for maximum header count (default 100) and maximum individual header line length (default 8KB). Return 431 Request Header Fields Too Large when exceeded.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-030
- Source reports: 4.2.5.md

### Priority
High

---
## Issue: FINDING-003 - Production module ships BogusTrustManagerFactory that bypasses all certificate validation with no runtime guard
**Labels:** bug, security, priority:medium
**Description:**
### Summary
BogusTrustManagerFactory in mina-core's public API implements X509TrustManager with empty checkClientTrusted/checkServerTrusted methods. When used with SslContextFactory, it completely bypasses certificate validation for both mTLS client certificates, TLS server certificate validation, and internal service certificate trust restrictions.

### Details
**CWE:** CWE-295  
**ASVS:** 12.1.3, 12.3.2, 12.3.4 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/BogusTrustManagerFactory.java`

This enables man-in-the-middle attacks when explicitly chosen by developers. Not exploitable in default configuration (SslContextFactory uses PKIX by default) but requires explicit developer choice to use. Class is in production module with no runtime guard or deprecation warning.

### Remediation
Add @Deprecated annotation, runtime WARN log on instantiation, and consider gating behind a system property. Provide a helper for restricted internal trust (createInternalCATrustManagerFactory) for legitimate internal CA use cases.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 12.1.3.md, 12.3.2.md, 12.3.4.md

### Priority
Medium

---
## Issue: FINDING-004 - ObjectSerializationInputStream performs Java deserialization with no class filtering mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ObjectSerializationInputStream performs Java deserialization with size limit and classloader controls but no mandatory class allowlist enforcement, no sandboxing, and no architectural isolation. This is a defense-in-depth gap rather than an exploitable vulnerability.

### Details
**CWE:** CWE-502  
**ASVS:** 1.5.2, 15.1.5, 15.2.5 (L2, L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationInputStream.java`

The class filtering exists in IoBuffer and the framework intentionally delegates security configuration to applications. The ASVS 15.2.5 requirement calls for additional protections around dangerous functionality.

### Remediation
Add security-focused Javadoc highlighting the dangerous functionality including a Security Warning about Java object deserialization risks and the need to configure a ClassNameMatcher allowlist.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-005, FINDING-018
- Source reports: 1.5.2.md, 15.1.5.md, 15.2.5.md

### Priority
Medium

---
## Issue: FINDING-005 - ObjectSerializationDecoder defaults to accepting all classes when no matchers are configured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
ObjectSerializationDecoder's acceptMatchers list defaults to an empty ArrayList. When no accept() calls are made by the application, setMatchers(emptyList) is passed before getObject(), meaning all classes are accepted. The filtering mechanism exists but is not enforced by default, creating a foot-gun for applications.

### Details
**CWE:** CWE-502  
**ASVS:** 1.5.2 (L2, L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationDecoder.java`

Applications that deploy the codec without configuring an allowlist are vulnerable to deserialization attacks.

### Remediation
Option A: Throw IllegalStateException when no matchers are configured (fail-closed). Option B: Log a warning when doDecode() is invoked with an empty acceptMatchers list. Provide an explicit acceptAll() marker method for applications that intentionally accept all classes.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-004, FINDING-018
- Source reports: 1.5.2.md

### Priority
Medium

---
## Issue: FINDING-006 - ConnectionThrottleFilter cleanup thread executes only once, leading to unbounded memory growth and DoS vulnerability
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ExpiredSessionThread in ConnectionThrottleFilter runs exactly once: it sleeps for allowedInterval (default 1000ms), performs a single cleanup pass, then exits. After this single execution (~1 second post-construction), no entries are ever reclaimed from the clients ConcurrentHashMap.

### Details
**CWE:** CWE-401  
**ASVS:** 15.2.2, 2.4.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java`

A sustained attack from diverse IPs exhausts JVM heap memory. The component designed to provide availability protection itself becomes an availability vulnerability, allowing unbounded memory accumulation as a DoS vector.

### Remediation
Convert the single-execution cleanup to a recurring loop using ScheduledExecutorService to perform periodic cleanup. Add a configurable maximum size to the clients map with fail-closed behavior when tracking capacity is exceeded.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-021
- Source reports: 15.2.2.md, 2.4.1.md

### Priority
Medium

---
## Issue: FINDING-007 - ConnectionThrottleFilter propagates session event downstream despite throttling, partially bypassing rate limit
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When a connection is throttled, the filter executes session.closeNow() but then unconditionally calls nextFilter.sessionCreated(session), propagating the session creation event to downstream filters and handlers.

### Details
**CWE:** CWE-367  
**ASVS:** 2.4.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java`

This allows downstream handlers to execute logic for throttled sessions before the asynchronous close completes, partially bypassing the rate limit protection.

### Remediation
Add a return statement immediately after session.closeNow() to prevent downstream event propagation, matching the pattern used by BlacklistFilter.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 2.4.1.md

### Priority
Medium

---
## Issue: FINDING-008 - IPv6 address handling in Subnet class is fundamentally broken, rendering BlacklistFilter ineffective for IPv6
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The toLong(InetAddress) method in the Subnet class iterates all 16 bytes of an IPv6 address while shifting into a 64-bit long, causing the upper 64 bits to overflow and be lost.

### Details
**CWE:** CWE-190  
**ASVS:** 2.4.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/firewall/Subnet.java`

This produces incorrect subnet matching results for IPv6 addresses, allowing complete bypass of BlacklistFilter for IPv6 subnets and undermining anti-automation controls for IPv6 clients.

### Remediation
Use BigInteger or a pair of long values to represent 128-bit IPv6 addresses properly, or explicitly reject IPv6 addresses with a clear error message until proper support is implemented.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-039
- Source reports: 2.4.1.md

### Priority
Medium

---
## Issue: FINDING-009 - Duplicate Content-Length headers silently resolved by last-wins semantics
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Header parsing uses HashMap.put() which silently overwrites earlier values. Multiple Content-Length headers with different values are not detected or rejected per RFC 7230 §3.3.3.

### Details
**CWE:** CWE-444  
**ASVS:** 4.2.1 (L2)  
**Affected Files:**
- `mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

This enables potential request smuggling when proxy and decoder disagree on which value to use.

### Remediation
Track whether Content-Length has been seen during header parsing. If a second, different value appears, reject the message.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-001
- Source reports: 4.2.1.md

### Priority
Medium

---
## Issue: FINDING-010 - Content-Length value not validated before use as message boundary
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Content-Length header value is passed directly to Integer.valueOf() without validation. Negative values, non-numeric values, or extremely large values cause incorrect message framing or unhandled exceptions.

### Details
**CWE:** CWE-20  
**ASVS:** 4.2.1, 4.2.2 (L2, L3)  
**Affected Files:**
- `mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

Client-supplied Content-Length is used as a body framing indicator without verification that it is a valid non-negative integer within implementation limits, potentially enabling request smuggling or DoS.

### Remediation
Parse Content-Length as a non-negative integer with bounds checking before using it for message framing. Reject requests with invalid values with a 400 Bad Request response.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 4.2.1.md, 4.2.2.md

### Priority
Medium

---
## Issue: FINDING-011 - Custom HMAC-MD5 implementation instead of JCA Mac class
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The hmacMD5 method implements the HMAC algorithm manually using raw MessageDigest and XOR operations instead of using Java's industry-validated javax.crypto.Mac.getInstance("HmacMD5").

### Details
**CWE:** CWE-327  
**ASVS:** 11.2.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/ntlm/NTLMResponses.java`

The custom implementation also has an RFC 2104 compliance defect: it does not hash keys longer than the block size (64 bytes) before use.

### Remediation
Replace custom implementation with javax.crypto.Mac.getInstance("HmacMD5") and SecretKeySpec.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-013, FINDING-014, FINDING-015, FINDING-023, FINDING-024
- Source reports: 11.2.1.md

### Priority
Medium

---
## Issue: FINDING-012 - IoServiceMBean exposes unrestricted OGNL expression evaluation with no production-disable mechanism
**Labels:** bug, security, priority:medium
**Description:**
### Summary
IoServiceMBean monitoring endpoint exposes unrestricted OGNL-based session inspection and manipulation with no built-in access control. findSessions, findAndRegisterSessions, and findAndProcessSessions operations are available without restriction once the MBean is registered.

### Details
**CWE:** CWE-94  
**ASVS:** 13.4.2, 13.4.5 (L2)  
**Affected Files:**
- `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java`

OGNL can traverse to IoService, its handlers, filter chains, and the entire application object graph.

### Remediation
Provide a mechanism to disable management/debug operations in production, or restrict OGNL evaluation to a safe subset. Option 1: Environment-aware guard with system property mina.jmx.disableOgnl. Option 2: Remove OGNL execution entirely, replace with safe attribute access.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 13.4.2.md, 13.4.5.md

### Priority
Medium

---
## Issue: FINDING-013 - SslContextFactory defaults to TLSv1.2 protocol, preventing TLS 1.3 negotiation unless explicitly overridden
**Labels:** bug, security, priority:low
**Description:**
### Summary
SslContextFactory.protocol defaults to "TLSv1.2". In Java's JSSE, SSLContext.getInstance("TLSv1.2") creates a context supporting protocols up to TLS 1.2 only. TLS 1.3 requires SSLContext.getInstance("TLSv1.3") or SSLContext.getInstance("TLS").

### Details
**CWE:** CWE-327  
**ASVS:** 12.1.1 (L1)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/SslContextFactory.java`

This prevents the application from preferring the latest TLS 1.3 protocol as required by ASVS 12.1.1.

### Remediation
Change default protocol to "TLSv1.3" to support TLS 1.3 as preferred while maintaining TLS 1.2 fallback.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-011, FINDING-014, FINDING-015, FINDING-023, FINDING-024
- Source reports: 12.1.1.md

### Priority
Low

---
## Issue: FINDING-014 - SslFilter does not enforce a minimum TLS protocol version when enabledProtocols is null
**Labels:** bug, security, priority:low
**Description:**
### Summary
SslFilter.enabledProtocols defaults to null. When null, no call to setEnabledProtocols is made, so SSLEngine uses JDK default enabled protocols. On JDK 11+ TLS 1.0/1.1 are disabled by default, but on older JDKs legacy protocols may remain enabled.

### Details
**CWE:** CWE-327  
**ASVS:** 12.1.1, 12.3.1 (L1, L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

This is a defense-in-depth gap rather than an active vulnerability. Affects both external-facing services and internal service-to-service communication.

### Remediation
Apply a secure default of TLSv1.2/TLSv1.3 when no explicit protocols are configured. Set a framework-level minimum of TLSv1.2/TLSv1.3 when enabledProtocols is null.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-011, FINDING-013, FINDING-015, FINDING-023, FINDING-024
- Source reports: 12.1.1.md, 12.3.1.md

### Priority
Low

---
## Issue: FINDING-015 - SslFilter does not enforce a cipher suite allowlist by default; relies entirely on JDK defaults
**Labels:** bug, security, priority:low
**Description:**
### Summary
SslFilter.enabledCipherSuites defaults to null. When null, no call to setEnabledCipherSuites is made, so SSLEngine uses all JDK-enabled cipher suites including non-forward-secrecy suites.

### Details
**CWE:** CWE-327  
**ASVS:** 12.1.2 (L2, L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

Modern JDKs prioritize AEAD/FS suites but may not exclusively enable them. For L3 applications, this fails to guarantee that only forward-secrecy cipher suites are enabled as required by ASVS 12.1.2.

### Remediation
Provide a secure default cipher suite list of AEAD-only forward-secrecy suites when none is explicitly configured.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-011, FINDING-013, FINDING-014, FINDING-023, FINDING-024
- Source reports: 12.1.2.md

### Priority
Low

---
## Issue: FINDING-016 - No API surface for configuring OCSP stapling or certificate revocation checking in the TLS configuration classes
**Labels:** bug, security, priority:low
**Description:**
### Summary
Neither SslContextFactory nor SslFilter expose any mechanism for enabling OCSP stapling, configuring PKIXRevocationChecker, or setting CRL distribution points. Java's default does not enable revocation checking unless explicitly configured.

### Details
**CWE:** CWE-299  
**ASVS:** 12.1.4 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/SslContextFactory.java`
- `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

The framework does not actively disable revocation checking and it can be configured at the JVM level, but lacks application-level API support required by ASVS 12.1.4 for L3 applications.

### Remediation
Add enableOcsp configuration to SslFilter or SslContextFactory exposing Java's PKIXRevocationChecker capabilities.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 12.1.4.md

### Priority
Low

---
## Issue: FINDING-017 - SslFilter does not enable hostname verification by default for client mode
**Labels:** bug, security, priority:low
**Description:**
### Summary
SslFilter.identificationAlgorithm defaults to null. When null, createEngine() skips setEndpointIdentificationAlgorithm(), so no hostname verification is performed. An attacker with any valid certificate could impersonate the target server.

### Details
**CWE:** CWE-297  
**ASVS:** 12.3.2 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

The framework exposes setEndpointIdentificationAlgorithm("HTTPS") for this purpose but does not enable it by default, failing ASVS 12.3.2 requirements for TLS clients to validate certificates received before communicating with a TLS server.

### Remediation
Enable hostname verification by default for client mode (when session.isServer() returns false).

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 12.3.2.md

### Priority
Low

---
## Issue: FINDING-018 - Two deserialization entry points for the same wire format have inconsistent security properties
**Labels:** bug, security, priority:low
**Description:**
### Summary
ObjectSerializationDecoder applies ClassNameMatcher filtering via in.setMatchers(acceptMatchers) before deserialization, while ObjectSerializationInputStream does not apply any matchers before calling buf.getObject(classLoader).

### Details
**CWE:** CWE-502  
**ASVS:** 1.5.3 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationDecoder.java`
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationInputStream.java`

Both parse the same wire format (4-byte big-endian length prefix + Java serialized object) and use the same underlying mechanism, but have divergent security properties. An application processing the same format through both paths will get different filtering behavior.

### Remediation
Ensure both deserialization entry points support and enforce the same class filtering. Add matcher support to ObjectSerializationInputStream consistent with the decoder's API.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-004, FINDING-005
- Source reports: 1.5.3.md

### Priority
Low

---
## Issue: FINDING-019 - BlacklistFilter performs O(n) iteration on every filter event without size bounds or performance documentation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The isBlocked() method performs a linear scan of the entire blacklist CopyOnWriteArrayList for every filter event (sessionCreated, messageReceived, messageSent, sessionIdle, sessionOpened, event). No size limit control exists on the blacklist.

### Details
**CWE:** CWE-400  
**ASVS:** 15.1.3, 15.2.2 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/firewall/BlacklistFilter.java`

No documentation describes the O(n) algorithmic complexity, memory growth characteristics, or performance implications. With thousands of entries and concurrent sessions, cumulative CPU cost could contribute to latency and throughput degradation.

### Remediation
Use a TreeSet or prefix-trie data structure for O(log n) lookups, or introduce a configurable MAX_BLACKLIST_SIZE with enforcement in block(). Add Javadoc documentation describing algorithmic complexity, memory growth characteristics, recommended maximum sizes, and guidance on combining with other controls.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-031
- Source reports: 15.1.3.md, 15.2.2.md

### Priority
Low

---
## Issue: FINDING-020 - Subnet.equals() only compares IPv4 fields, breaking unblock functionality for IPv6
**Labels:** bug, security, priority:low
**Description:**
### Summary
The equals() method in the Subnet class only compares subnetInt (always 0 for IPv6) and suffix, meaning all IPv6 subnets with the same prefix length are considered equal. This breaks the ability to unblock specific IPv6 subnets from the blacklist.

### Details
**CWE:** CWE-697  
**ASVS:** 2.4.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/firewall/Subnet.java`

Additionally, no hashCode() override is provided, violating the Java contract for objects used in collections.

### Remediation
Include the subnet InetAddress field in equality comparison and add a proper hashCode() override that includes all fields used in equals().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 2.4.1.md

### Priority
Low

---
## Issue: FINDING-021 - IoBuffer.free() not protected by try-finally — resource leak on exception paths
**Labels:** bug, security, priority:low
**Description:**
### Summary
In ProtocolCodecFilter.messageReceived(), in.free() is called after the decode loop but is not protected by a try-finally block. If an exception escapes the catch block (e.g., during decoderOut.flush() within the catch handler), the IoBuffer's direct memory is not released.

### Details
**CWE:** CWE-401  
**ASVS:** 1.4.3 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/ProtocolCodecFilter.java`

This potentially leads to resource exhaustion under sustained malformed input.

### Remediation
Wrap the decode loop in try-finally to ensure in.free() is always called regardless of exception paths.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-006
- Source reports: 1.4.3.md

### Priority
Low

---
## Issue: FINDING-022 - No key lifecycle management mechanisms in framework cryptographic components
**Labels:** bug, security, priority:low
**Description:**
### Summary
The KeyStoreFactory class provides KeyStore creation and loading but implements no key lifecycle management features (rotation, expiration tracking, revocation checking, or usage constraints).

### Details
**CWE:** CWE-316  
**ASVS:** 11.1.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/KeyStoreFactory.java`

The class stores the KeyStore password as a char[] field that is never zeroed after use, and passwords accepted as String remain in the JVM string pool indefinitely.

### Remediation
Accept char[] instead of String for passwords and zero the array after use via Arrays.fill.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-026, FINDING-027, FINDING-032
- Source reports: 11.1.1.md

### Priority
Low

---
## Issue: FINDING-023 - DigestUtilities provides no algorithm agility beyond RFC 2617 mandated MD5
**Labels:** bug, security, priority:low
**Description:**
### Summary
The DigestUtilities class initializes a static shared MessageDigest for MD5 with no mechanism to configure or swap the algorithm. RFC 7616 (2015) supersedes RFC 2617 and defines SHA-256 as a supported digest algorithm for HTTP Digest authentication.

### Details
**CWE:** CWE-327  
**ASVS:** 11.2.2, 11.4.1, 11.4.3 (L1, L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/DigestUtilities.java`

The current implementation cannot be reconfigured to use SHA-256 without code changes, preventing seamless upgrade to stronger algorithms.

### Remediation
Add support for the 'algorithm' directive to select SHA-256 per RFC 7616 and provide algorithm selection based on server's 'algorithm' directive.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-011, FINDING-013, FINDING-014, FINDING-015, FINDING-024
- Source reports: 11.2.2.md, 11.4.1.md, 11.4.3.md

### Priority
Low

---
## Issue: FINDING-024 - DES/ECB mode used in NTLM protocol implementation
**Labels:** bug, security, priority:low
**Description:**
### Summary
The lmHash() and lmResponse() methods use DES/ECB/NoPadding which is an insecure block mode. However, this is mandated by the NTLM protocol specification and cannot be changed without breaking compatibility.

### Details
**CWE:** CWE-327  
**ASVS:** 11.3.1 (L1)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/ntlm/NTLMResponses.java`

Applications should prefer NTLMv2 or modern authentication methods.

### Remediation
Prefer NTLMv2 (getNTLMv2Response) over LM (getLMResponse); consider deprecating LM methods with migration guidance to Negotiate/Kerberos or OAuth.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-011, FINDING-013, FINDING-014, FINDING-015, FINDING-023
- Source reports: 11.3.1.md

### Priority
Low

---
## Issue: FINDING-025 - Hardcoded Nonce Count Prevents Proper Nonce Reuse Detection in HTTP Digest Authentication
**Labels:** bug, security, priority:low
**Description:**
### Summary
The DigestUtilities class hardcodes nonce count as '00000001' regardless of actual reuse count, preventing servers from detecting replayed authentication responses via nonce count tracking.

### Details
**CWE:** CWE-330  
**ASVS:** 11.3.4 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/DigestUtilities.java`

If a proxy server reuses nonces across multiple requests, the client always claims nc=00000001.

### Remediation
Track nonce count per server nonce in the session and increment with each use.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 11.3.4.md

### Priority
Low

---
## Issue: FINDING-026 - KeyStoreFactory retains password and keystore data after use without zeroing
**Labels:** bug, security, priority:low
**Description:**
### Summary
KeyStoreFactory retains sensitive secret material (password and keystore data) in memory indefinitely without clearing. password and data fields are NEVER zeroed after use in newInstance().

### Details
**CWE:** CWE-316  
**ASVS:** 11.7.2, 13.3.1 (L3, L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/KeyStoreFactory.java`

Requires local/privileged access (heap dump, debugging attachment, memory forensics).

### Remediation
Add cleanup to zero sensitive fields after newInstance() completes using Arrays.fill(). Provide an explicit destroy() method or implement AutoCloseable.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-022, FINDING-027, FINDING-032
- Source reports: 11.7.2.md, 13.3.1.md

### Priority
Low

---
## Issue: FINDING-027 - NTLMResponses does not zero intermediate key material after cryptographic operations
**Labels:** bug, security, priority:low
**Description:**
### Summary
NTLMResponses methods (lmHash, lmResponse, hmacMD5) retain intermediate key-derived byte arrays (oemPassword, keyBytes, ipad, opad) in memory without zeroing after use.

### Details
**CWE:** CWE-316  
**ASVS:** 11.7.2 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/ntlm/NTLMResponses.java`

Requires local/physical JVM access. Effectiveness limited by Java String immutability of source password.

### Remediation
Zero intermediate arrays in finally blocks: Arrays.fill(oemPassword, (byte) 0) and Arrays.fill(keyBytes, (byte) 0) after cryptographic operations complete.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-022, FINDING-026, FINDING-032
- Source reports: 11.7.2.md

### Priority
Low

---
## Issue: FINDING-028 - MdcInjectionFilter.setProperty() does not encode values before MDC injection, enabling log injection when applications pass user-controlled input
**Labels:** bug, security, priority:low
**Description:**
### Summary
The setProperty() method accepts any string value and injects it directly into the SLF4J MDC without any encoding/sanitization. If application code passes user-controlled data, an attacker can inject newline characters and fake log entries into the log stream.

### Details
**CWE:** CWE-117  
**ASVS:** 16.4.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/logging/MdcInjectionFilter.java`

### Remediation
Sanitize values before injection into MDC, at minimum replacing control characters (CR, LF, TAB) in values passed to MDC.put().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 16.4.1.md

### Priority
Low

---
## Issue: FINDING-029 - ThreadLocal state leak when exception occurs before try-finally block
**Labels:** bug, security, priority:low
**Description:**
### Summary
The callDepth.set() and getAndFillContext() calls are outside the try-finally block. If getAndFillContext() throws (e.g., NPE from null remote address), the callDepth ThreadLocal retains a stale value, degrading MDC injection for subsequent sessions on that thread.

### Details
**CWE:** CWE-460  
**ASVS:** 16.5.3 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/logging/MdcInjectionFilter.java`

### Remediation
Wrap the entire method body in try-finally to ensure callDepth cleanup regardless of where the exception occurs.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 16.5.3.md

### Priority
Low

---
## Issue: FINDING-030 - Default Unbounded Thread Pool Without Documented Limits
**Labels:** bug, security, priority:low
**Description:**
### Summary
When no Executor is provided, AbstractIoService creates an unbounded CachedThreadPool. There is no documented maximum number of concurrent connections or threads, no fallback mechanism when resources are exhausted, and no recovery strategy.

### Details
**CWE:** CWE-770  
**ASVS:** 13.1.2 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/core/service/AbstractIoService.java`

Remote unauthenticated attacker can open many connections simultaneously causing DoS through thread/memory exhaustion.

### Remediation
Document the default behavior and recommend applications provide bounded executors. Consider adding a Javadoc warning on the constructor about the unbounded default.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-002
- Source reports: 13.1.2.md

### Priority
Low

---
## Issue: FINDING-031 - No Documented Resource-Release Procedures or Timeout Strategies for Default Executor
**Labels:** bug, security, priority:low
**Description:**
### Summary
The disposal mechanism uses Integer.MAX_VALUE seconds as the await-termination timeout, which is effectively infinite. No documented timeout strategy, no progressive shutdown procedure. If tasks hang, the disposal can block indefinitely.

### Details
**CWE:** CWE-400  
**ASVS:** 13.1.3 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/core/service/AbstractIoService.java`

### Remediation
Implement bounded await-termination timeout (e.g., 30 seconds) instead of Integer.MAX_VALUE. Document resource-release strategy.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-019
- Source reports: 13.1.3.md

### Priority
Low

---
## Issue: FINDING-032 - KeyStoreFactory accepts password as immutable Java String, preventing secret scrubbing of the original value
**Labels:** bug, security, priority:low
**Description:**
### Summary
KeyStoreFactory accepts password as immutable Java String, preventing secret scrubbing of the original value. The original String interned/pooled in JVM heap cannot be zeroed by caller or framework.

### Details
**CWE:** CWE-316  
**ASVS:** 13.3.1 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/ssl/KeyStoreFactory.java`

### Remediation
Provide an overloaded setPassword(char[]) method that accepts char[] directly for secure handling.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-022, FINDING-026, FINDING-027
- Source reports: 13.3.1.md

### Priority
Low

---
## Issue: FINDING-033 - IoServiceMBean uses blacklist-based method filtering rather than whitelist for JMX operation exposure
**Labels:** bug, security, priority:low
**Description:**
### Summary
IoServiceMBean uses blacklist-based method filtering rather than whitelist for JMX operation exposure. If IoService implementations add new sensitive methods in future versions, they are automatically exposed through JMX unless explicitly added to the blacklist.

### Details
**CWE:** CWE-16  
**ASVS:** 13.4.5 (L2)  
**Affected Files:**
- `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java`

### Remediation
Consider a whitelist approach where only explicitly permitted operations are accessible via JMX.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 13.4.5.md

### Priority
Low

---
## Issue: FINDING-034 - IoService exposes TransportMetadata and IoServiceStatistics through JMX without version information filtering
**Labels:** bug, security, priority:low
**Description:**
### Summary
IoService exposes TransportMetadata and IoServiceStatistics through JMX without version information filtering. Through OGNL, an attacker could access getClass().getPackage().getImplementationVersion() on any object in the graph, potentially disclosing exact library versions.

### Details
**CWE:** CWE-200  
**ASVS:** 13.4.6 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/core/service/IoService.java`
- `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java`

### Remediation
The ObjectMBean base class should filter attributes that contain version-identifying information, or the IoServiceMBean should override attribute exposure.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 13.4.6.md

### Priority
Low

---
## Issue: FINDING-035 - IoBuffer free() does not guarantee content clearing before pool return
**Labels:** bug, security, priority:low
**Description:**
### Summary
When using CachedBufferAllocator (non-default), IoBuffer.free() returns buffers to the pool without clearing content, potentially allowing sensitive data from one session to be visible to another session that receives the recycled buffer.

### Details
**CWE:** CWE-226  
**ASVS:** 14.2.2 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/core/buffer/IoBuffer.java`

Requires non-default configuration and co-tenant sessions in the same JVM.

### Remediation
Document in the free() Javadoc that applications handling sensitive data should call sweep() before free() when using CachedBufferAllocator.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 14.2.2.md

### Priority
Low

---
## Issue: FINDING-036 - No formal SBOM generation mechanism observed in the project
**Labels:** bug, security, priority:low
**Description:**
### Summary
The project relies on Maven pom.xml for dependency declarations but does not appear to generate a formal Software Bill of Materials (SBOM) in a standard format (CycloneDX, SPDX).

### Details
**ASVS:** 15.1.2 (L2)  
**Affected Files:**
- Project build configuration

While Maven provides dependency visibility via mvn dependency:tree, this is not a maintained, versioned SBOM artifact that can be audited, shared with consumers, or monitored for newly disclosed vulnerabilities.

### Remediation
Add a CycloneDX or SPDX Maven plugin to generate SBOM artifacts as part of the release process.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 15.1.2.md

### Priority
Low

---
## Issue: FINDING-037 - Deprecated API usage (Class.newInstance()) indicates component not updated for modern Java
**Labels:** bug, security, priority:low
**Description:**
### Summary
PropertyEditorFactory uses Class.newInstance() (line 121), which was deprecated in Java 9 (2017) in favor of Constructor.newInstance().

### Details
**ASVS:** 15.2.1 (L1)  
**Affected Files:**
- `mina-integration-beans/src/main/java/org/apache/mina/integration/beans/PropertyEditorFactory.java:121`

While not a security vulnerability per se, the continued use of deprecated APIs indicates that this component has not been updated to follow modern Java practices.

### Remediation
Replace Class.newInstance() with editorClass.getDeclaredConstructor().newInstance().

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 15.2.1.md

### Priority
Low

---
## Issue: FINDING-038 - Dynamic Class Loading in PropertyEditorFactory Uses Pattern Susceptible to Classpath Manipulation
**Labels:** bug, security, priority:low
**Description:**
### Summary
PropertyEditorFactory.getInstance(Class<?>) uses dynamic class loading that constructs class names via string concatenation within the org.apache.mina.integration.beans package namespace.

### Details
**ASVS:** 15.2.4, 15.1.5 (L3)  
**Affected Files:**
- `mina-integration-beans/src/main/java/org/apache/mina/integration/beans/PropertyEditorFactory.java`

If a malicious transitive dependency were to place a class in this exact package (possible via split packages in multi-JAR environments before Java modules), the newInstance() call would execute the no-arg constructor of the malicious class.

### Remediation
Add security-focused documentation noting that this class uses reflection-based dynamic class loading constrained to the org.apache.mina.integration.beans package, and that the type parameter should not be derived from untrusted user input without validation.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 15.2.4.md, 15.1.5.md

### Priority
Low

---
## Issue: FINDING-039 - Integer Overflow Due to Missing Upper Bound Validation on maxObjectSize
**Labels:** bug, security, priority:low
**Description:**
### Summary
When maxObjectSize is set to a value > Integer.MAX_VALUE - 4, an attacker-controlled stream providing objectSize = Integer.MAX_VALUE passes validation, then objectSize + 4 overflows to a negative value passed to IoBuffer.allocate().

### Details
**CWE:** CWE-190  
**ASVS:** 15.3.5 (L2)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationInputStream.java`

Requires unusual application configuration; default 1MB is safe.

### Remediation
Use Math.addExact(objectSize, 4) or validate objectSize <= Integer.MAX_VALUE - 4 before the addition.

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Related findings: FINDING-008
- Source reports: 15.3.5.md

### Priority
Low

---
## Issue: FINDING-040 - Mutable Field maxObjectSize Not Declared Volatile
**Labels:** bug, security, priority:low
**Description:**
### Summary
The maxObjectSize field is mutable via setMaxObjectSize() but not declared volatile. In multi-threaded access scenarios, a reading thread may see a stale value.

### Details
**CWE:** CWE-362  
**ASVS:** 15.4.1 (L3)  
**Affected Files:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationInputStream.java`

Exploitability is very low since InputStream objects are inherently sequential and per-session in typical Mina usage.

### Remediation
Declare private volatile int maxObjectSize = 1048576;

### Acceptance Criteria
- [ ] Fixed
- [ ] Test added

### References
- Source reports: 15.4.1.md

### Priority
Low

---

## Issue: FINDING-041 - Blocking I/O in readObject() May Contribute to Thread Starvation in Shared Worker Pools

**Labels:** bug, security, priority:low

**Description:**

### Summary
The `readObject()` method in `ObjectSerializationInputStream` performs blocking read operations that can hold worker threads indefinitely when processing data from slow or malicious clients. In shared worker pool scenarios, this behavior may contribute to thread pool exhaustion and denial of service conditions.

### Details
The `readObject()` method uses `DataInputStream.readFully()` to perform blocking reads for `objectSize` bytes from the network stream. This operation will hold a thread pool worker thread until all bytes are received, with no configurable timeout mechanism.

**Affected File:**
- `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationInputStream.java`

**Attack Scenario:**
1. A slow or malicious client connects to a service using `ObjectSerializationDecoder`
2. The client sends the object size header but deliberately sends payload data very slowly (slowloris-style attack)
3. A worker thread from the shared pool is held in blocking I/O waiting for the complete object
4. Multiple such connections can exhaust the thread pool, preventing legitimate requests from being processed

**CWE Mapping:** Resource exhaustion via blocking operations

**ASVS Reference:** 15.4.4 (Level 3)

### Remediation
Implement one or more of the following mitigations:

1. **Add configurable read timeout mechanism:**
   - Introduce an optional timeout parameter for read operations
   - Implement timeout logic around `readFully()` calls
   - Throw `InterruptedIOException` when timeout is exceeded

2. **Documentation improvements:**
   - Document that applications using `ObjectSerializationDecoder` should configure socket-level read timeouts
   - Provide guidance on appropriate thread pool sizing
   - Include security considerations for public-facing services

3. **Consider non-blocking I/O patterns:**
   - Evaluate using NIO-based non-blocking read operations where appropriate
   - Implement progressive read with yield points for long operations

### Acceptance Criteria
- [ ] Read timeout mechanism implemented or socket-level timeout configuration documented
- [ ] Security documentation added covering thread pool sizing and timeout configuration
- [ ] Test added demonstrating timeout behavior with slow clients
- [ ] Code review completed focusing on thread safety and resource management
- [ ] Performance impact assessed for timeout implementation

### References
- Source Report: `15.4.4.md`
- Related Findings: None
- ASVS 4.0 Section 15.4.4: Configuration Architecture

### Priority
**Low** - While this could contribute to resource exhaustion, it requires specific deployment conditions (shared thread pools, no socket timeouts) and can be mitigated through proper configuration at the application level.