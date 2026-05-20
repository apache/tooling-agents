# Security Issues

---
## Issue: FINDING-002 - ConnectionThrottleFilter Fails to Block Event Propagation After Throttle Detection
**Labels:** bug, security, priority:high
**Description:**
### Summary
In ConnectionThrottleFilter.sessionCreated(), after detecting a rate violation and calling session.closeNow(), the method unconditionally calls nextFilter.sessionCreated(session), allowing the session event to propagate through the entire filter chain. This defeats the purpose of the throttle as downstream handlers still process the connection.

### Details
- **CWE:** CWE-367 (Time-of-check Time-of-use Race Condition)
- **ASVS:** 6.3.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java`

### Remediation
Add `return` after `session.closeNow()` in `sessionCreated()` to prevent filter chain propagation. Mirror BlacklistFilter's correct if/else pattern.

### Acceptance Criteria
- [ ] Fixed: Filter chain propagation stops after throttle detection
- [ ] Test added: Verify downstream handlers are not invoked for throttled connections
- [ ] Code review completed

### References
- Source report: 6.3.1.md
- Merged from: ASVS-631-HIGH-001

### Priority
**High** - Access control bypass allows rate-limited connections to be processed

---
## Issue: FINDING-003 - Unbounded Header Accumulation Enables Memory Exhaustion DoS
**Labels:** bug, security, priority:high
**Description:**
### Summary
When the decoder receives a partial HTTP head (no `\r\n\r\n` terminator found), it accumulates the data in a session attribute (`PARTIAL_HEAD_ATT`) without any maximum size enforcement. An attacker can send an arbitrarily large stream of bytes without the header terminator, causing unbounded heap allocation until the JVM runs out of memory.

### Details
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **ASVS:** 2.2.1, 2.1.1 (Level L1)
- **Affected Files:**
  - `mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

### Remediation
Add a MAX_HEAD_SIZE constant (default 8KB) and check accumulated size in the HEAD state before storing partial buffers. Reject requests exceeding the limit with 431 Request Header Fields Too Large.

### Acceptance Criteria
- [ ] Fixed: Maximum header size enforced (configurable, default 8KB)
- [ ] Test added: Verify oversized header rejection with 431 response
- [ ] Test added: Verify legitimate large headers within limit are accepted
- [ ] Code review completed

### References
- Source report: 2.2.1.md, 2.1.1.md
- Related findings: FINDING-024
- Merged from: ASVS-221-HIGH-001, INPUT-1

### Priority
**High** - Trivial remote denial of service via memory exhaustion

---
## Issue: FINDING-004 - HTTP Response Splitting via Missing CRLF Sanitization in HttpServerEncoder
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application-supplied header values are concatenated into the HTTP response without CRLF filtering. The encoder is the last point before wire emission, and per the project's documented scope, 'When the encoder serializes application-supplied header values verbatim and the application has no opportunity to sanitize between construction and wire emission, the encoder owns sanitization.'

### Details
- **CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **ASVS:** 1.2.1 (Level L1)
- **Affected Files:**
  - `mina-http/src/main/java/org/apache/mina/http/HttpServerEncoder.java`

### Remediation
Strip or reject \r and \n characters in header names and header values before serialization in HttpServerEncoder.encode().

### Acceptance Criteria
- [ ] Fixed: CRLF characters stripped or rejected in header names and values
- [ ] Test added: Verify CRLF injection attempts are neutralized
- [ ] Test added: Verify legitimate headers continue to work
- [ ] Code review completed

### References
- Source report: 1.2.1.md
- Related findings: FINDING-005, FINDING-012
- Merged from: ASVS-121-HIGH-001

### Priority
**High** - HTTP response splitting enables cache poisoning and XSS attacks

---
## Issue: FINDING-005 - HTTP Request Smuggling via Missing CRLF Sanitization in HttpClientEncoder
**Labels:** bug, security, priority:high
**Description:**
### Summary
Application-supplied request path, query string, and header values are concatenated into the HTTP request without CRLF filtering. Both the request line components (path, query string) and all header names/values are emitted without structural encoding, enabling HTTP request smuggling.

### Details
- **CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **ASVS:** 1.2.1 (Level L1)
- **Affected Files:**
  - `mina-http/src/main/java/org/apache/mina/http/HttpClientEncoder.java`

### Remediation
Strip or reject \r and \n characters in header names, header values, request paths, and query strings before serialization in HttpClientEncoder.encode().

### Acceptance Criteria
- [ ] Fixed: CRLF characters stripped or rejected in all request components
- [ ] Test added: Verify CRLF injection attempts in request line are neutralized
- [ ] Test added: Verify CRLF injection attempts in headers are neutralized
- [ ] Code review completed

### References
- Source report: 1.2.1.md
- Related findings: FINDING-004, FINDING-012
- Merged from: ASVS-121-HIGH-002

### Priority
**High** - HTTP request smuggling enables proxy/cache poisoning and security control bypass

---
## Issue: FINDING-006 - Unsanitized OGNL Expression Execution in findAndProcessSessions
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `findAndProcessSessions` JMX operation accepts an OGNL command expression (params[1]) that is passed directly to Ognl.parseExpression() and Ognl.getValue() without any sanitization or validation. While the query parameter (params[0]) is properly validated through IoSessionFinder character-level validation, the command parameter bypasses all controls, creating a remote code execution vulnerability accessible to any JMX client with access to the MBean.

### Details
- **CWE:** CWE-94 (Improper Control of Generation of Code)
- **ASVS:** 1.3.2 (Level L1)
- **Affected Files:**
  - `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java`

### Remediation
Apply the same character validation as IoSessionFinder to the command parameter, or implement OGNL MemberAccess restrictions, or (preferred) replace with specific named JMX operations that don't require arbitrary expression evaluation.

### Acceptance Criteria
- [ ] Fixed: OGNL command parameter validated or replaced with safe alternatives
- [ ] Test added: Verify malicious OGNL expressions are rejected
- [ ] Test added: Verify legitimate operations continue to work
- [ ] Security review of JMX exposure completed

### References
- Source report: 1.3.2.md
- Merged from: ASVS-132-HIGH-001

### Priority
**High** - Remote code execution via JMX interface

---
## Issue: FINDING-007 - Thread-Local Event Queue Not Cleared on Exception — Stale Events Processed Out of Order
**Labels:** bug, security, priority:high
**Description:**
### Summary
When a transition handler calls `StateControl.breakAndReturnNow()`, the framework catches `BreakAndReturnException` and pops the call stack. However, there is no validation that the call stack is non-empty before calling `pop()`. If `breakAndReturnNow()` is called without a matching prior `breakAndCall*`, the `pop()` operation throws an unchecked `NoSuchElementException` that propagates out of `processEvents()`, triggering the stale queue issue and leaving the state machine in an inconsistent state. This allows business logic flows to be corrupted and processed out of expected sequential order.

### Details
- **CWE:** CWE-362 (Concurrent Execution using Shared Resource with Improper Synchronization)
- **ASVS:** 2.3.1 (Level L1)
- **Affected Files:**
  - `mina-statemachine/src/main/java/org/apache/mina/statemachine/StateMachine.java`

### Remediation
Check callStack.isEmpty() before calling pop() in the BreakAndReturnException handler. Throw a descriptive IllegalStateException rather than allowing NoSuchElementException to corrupt processing state.

### Acceptance Criteria
- [ ] Fixed: Call stack validated before pop() operation
- [ ] Test added: Verify breakAndReturnNow() without matching call throws clear exception
- [ ] Test added: Verify event queue is properly cleared on exception
- [ ] Code review completed

### References
- Source report: 2.3.1.md
- Related findings: FINDING-001
- Merged from: ASVS-231-HIGH-001, STATE_MACHINE_PROTOCOL-3

### Priority
**High** - State machine corruption enables business logic bypass

---
## Issue: FINDING-008 - End-of-life Log4j 1.x dependency with known critical CVEs in dependency management
**Labels:** bug, security, priority:high
**Description:**
### Summary
Log4j 1.2.17 reached End of Life in August 2015. It has multiple known CVEs including CVE-2019-17571 (CVSS 9.8), CVE-2021-4104 (CVSS 7.5), CVE-2022-23302 (CVSS 8.8), CVE-2022-23305 (CVSS 9.8), CVE-2022-23307 (CVSS 8.8). While the project uses slf4j-reload4j as its actual logging backend, having log4j:log4j:1.2.17 in &lt;dependencyManagement&gt; means any transitive dependency pulling log4j:log4j will resolve to this critically vulnerable version.

### Details
- **ASVS:** 15.2.1 (Level L1)
- **Affected Files:**
  - `pom.xml`

### Remediation
Either exclude log4j:log4j entirely or add an explicit ban via maven-enforcer-plugin bannedDependencies rule.

### Acceptance Criteria
- [ ] Fixed: log4j:log4j removed from dependency management or explicitly banned
- [ ] Test added: Maven enforcer plugin verification added
- [ ] Dependency scan confirms no log4j 1.x in resolved dependencies
- [ ] Code review completed

### References
- Source report: 15.2.1.md
- Merged from: ASVS-1521-HIGH-001

### Priority
**High** - Known critical CVEs in dependency management

---
## Issue: FINDING-009 - Production module ships BogusTrustManagerFactory that accepts all certificates without any guard against accidental use
**Labels:** bug, security, priority:medium
**Description:**
### Summary
BogusTrustManagerFactory in mina-core production module disables all certificate validation. It lives in the same package as legitimate SSL classes, making accidental use trivially easy via IDE autocomplete. No compile-time annotation, no runtime warning, and no mechanism to prevent use in non-test environments. The profile acknowledges this as a 'real foot-gun in a production module' that remains in scope.

### Details
- **ASVS:** 12.2.2 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/ssl/BogusTrustManagerFactory.java`

### Remediation
Add runtime detection and logging to prevent silent production misuse. Consider @Deprecated(forRemoval = true) annotation and a system property gate that must be explicitly set to allow use outside test contexts.

### Acceptance Criteria
- [ ] Fixed: Runtime warning added when BogusTrustManagerFactory is used
- [ ] Fixed: @Deprecated annotation added with clear warning
- [ ] Test added: Verify warning is logged on instantiation
- [ ] Documentation updated with security warning
- [ ] Code review completed

### References
- Source report: 12.2.2.md
- Merged from: ASVS-1222-MED-001

### Priority
**Medium** - Defense-in-depth issue enabling accidental TLS validation bypass

---
## Issue: FINDING-010 - ConnectionThrottleFilter Cleanup Thread Executes Only Once, Leading to Unbounded State Growth
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The ExpiredSessionThread.run() method sleeps once and performs a single cleanup pass, then the thread terminates. No further cleanup ever occurs, causing the clients ConcurrentHashMap to grow without bound over the server's lifetime, leading to memory leak and potential OutOfMemoryError.

### Details
- **CWE:** CWE-401 (Missing Release of Memory after Effective Lifetime)
- **ASVS:** 6.3.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java`

### Remediation
Wrap the sleep-and-cleanup logic in a `while (!Thread.currentThread().isInterrupted())` loop. Use `iterator.remove()` instead of `clients.remove()` to avoid ConcurrentModificationException.

### Acceptance Criteria
- [ ] Fixed: Cleanup thread runs continuously until interrupted
- [ ] Test added: Verify cleanup occurs on multiple iterations
- [ ] Test added: Verify no ConcurrentModificationException
- [ ] Test added: Long-running test confirms no memory leak
- [ ] Code review completed

### References
- Source report: 6.3.1.md
- Merged from: ASVS-631-MED-001

### Priority
**Medium** - Memory leak leads to eventual denial of service

---
## Issue: FINDING-011 - ObjectSerializationDecoder Defaults to Permissive Deserialization When No ClassNameMatcher Is Configured
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `acceptMatchers` list initializes empty, meaning when no `accept()` calls are made, `getObject()` proceeds without class filtering, accepting arbitrary classes for deserialization. Network wire bytes → IoBuffer → doDecode() → setMatchers(empty list) → getObject(classLoader) → unrestricted class instantiation. Remote code execution via Java deserialization gadget chains. The class name filtering mechanism (ClassNameMatcher) exists but is not enforced when the acceptMatchers list is empty (the default). Without configured matchers, any class type is accepted regardless of whether it matches what the application expects, enabling deserialization of arbitrary classes.

### Details
- **CWE:** CWE-502 (Deserialization of Untrusted Data)
- **ASVS:** 1.5.1, 5.2.2 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationDecoder.java`
  - `mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationCodecFactory.java`

### Remediation
The framework should adopt a default-deny posture. If no matchers are configured, deserialization should be rejected rather than allowed. Add an IllegalStateException when acceptMatchers is empty, or ship with a minimal safe-by-default allowlist that only permits JDK primitive wrapper types. Factory should require explicit type configuration via a constructor that mandates a ClassNameMatcher parameter, or add a default-deny guard in doDecode() that throws IllegalStateException when acceptMatchers is empty.

### Acceptance Criteria
- [ ] Fixed: Default-deny posture enforced when no matchers configured
- [ ] Test added: Verify deserialization fails with no matchers
- [ ] Test added: Verify explicit allowlist enables deserialization
- [ ] Documentation updated with secure configuration guidance
- [ ] Code review completed

### References
- Source report: 1.5.1.md, 5.2.2.md
- Merged from: ASVS-151-MED-001, ASVS-522-MED-001

### Priority
**Medium** - Insecure default enables deserialization attacks when not explicitly configured

---
## Issue: FINDING-012 - HTTP Response Encoder Does Not Validate Header Values for CRLF Injection
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `HttpServerEncoder` serializes response headers by concatenating application-supplied header names and values directly into the output buffer without validating that they do not contain CR or LF characters. Per the project security profile: 'When the encoder serializes application-supplied header values verbatim and the application has no opportunity to sanitize between construction and wire emission, the encoder owns sanitization.'

### Details
- **CWE:** CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
- **ASVS:** 2.2.1 (Level L1)
- **Affected Files:**
  - `mina-http/src/main/java/org/apache/mina/http/HttpServerEncoder.java`

### Remediation
Reject or strip CR/LF characters in header names and values during encoding. Throw ProtocolEncoderException if CRLF is detected in header name or value.

### Acceptance Criteria
- [ ] Fixed: CRLF validation added to encoder
- [ ] Test added: Verify CRLF in headers throws ProtocolEncoderException
- [ ] Test added: Verify legitimate headers encode correctly
- [ ] Code review completed

### References
- Source report: 2.2.1.md
- Related findings: FINDING-004, FINDING-005
- Merged from: ASVS-221-MED-001

### Priority
**Medium** - HTTP response splitting via encoder (duplicate coverage with FINDING-004)

---
## Issue: FINDING-013 - Decoder Validation Gaps at the Trusted Service Layer Allow Malformed Input to Reach Application Logic
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `HttpServerDecoder` operates within MINA's filter chain (`ProtocolCodecFilter`) which is the trusted server-side input validation boundary — the correct architectural position. However, several categories of malformed input pass through this layer without rejection, reaching application `IoHandler` implementations as seemingly-valid `HttpRequest` objects. This includes requests with invalid header name characters, negative or extremely large content-length values, and malformed request lines.

### Details
- **CWE:** CWE-20 (Improper Input Validation)
- **ASVS:** 2.2.2, 2.2.1 (Level L1)
- **Affected Files:**
  - `mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java`

### Remediation
Ensure the decoder rejects all protocol-violating input with appropriate HttpException or ProtocolDecoderException before outputting message objects. Only valid, validated requests should reach the application IoHandler.

### Acceptance Criteria
- [ ] Fixed: Invalid header name characters rejected
- [ ] Fixed: Negative Content-Length values rejected
- [ ] Fixed: Malformed request lines rejected
- [ ] Test added: Comprehensive malformed input test suite
- [ ] Code review completed

### References
- Source report: 2.2.2.md, 2.2.1.md
- Merged from: ASVS-222-MED-001, INPUT-4, INPUT-5, INPUT-7, INPUT-8

### Priority
**Medium** - Validation gaps allow protocol violations to reach application logic

---
## Issue: FINDING-014 - No Structural Validation of Request-URI Components in HttpClientEncoder
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Application-supplied path (getRequestPath()) and query string (getQueryString()) are directly concatenated into request-URI with no percent-encoding of reserved/unsafe characters and no validation that the path is a valid absolute-path per RFC 7230 §5.3. Malformed request-URIs can cause divergent parsing by proxies and servers.

### Details
- **CWE:** CWE-116 (Improper Encoding or Escaping of Output)
- **ASVS:** 1.2.2 (Level L1)
- **Affected Files:**
  - `mina-http/src/main/java/org/apache/mina/http/HttpClientEncoder.java`

### Remediation
At minimum, reject characters that break HTTP message structure (\r, \n, space) in request path and query string before serialization.

### Acceptance Criteria
- [ ] Fixed: Structural validation added for request-URI components
- [ ] Test added: Verify malformed URIs are rejected
- [ ] Test added: Verify legitimate URIs encode correctly
- [ ] Code review completed

### References
- Source report: 1.2.2.md
- Merged from: ASVS-122-MED-001

### Priority
**Medium** - Request smuggling via malformed URI components

---
## Issue: FINDING-015 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** documentation, security, priority:medium
**Description:**
### Summary
The project's pom.xml manages 30+ third-party dependencies via &lt;dependencyManagement&gt; but no companion document, POM property, or comment defines: 1. Maximum acceptable time to remediate critical/high/medium/low vulnerabilities in dependencies 2. General update cadence for libraries 3. Classification of components as "risky" or containing "dangerous functionality"

### Details
- **ASVS:** 15.1.1 (Level L1)
- **Affected Files:**
  - `pom.xml`

### Remediation
Create a dependency management policy (e.g., DEPENDENCY_POLICY.md or in project wiki) that defines remediation timeframes by vulnerability severity and a general update policy.

### Acceptance Criteria
- [ ] Fixed: DEPENDENCY_POLICY.md created with remediation timeframes
- [ ] Fixed: Policy includes update cadence guidelines
- [ ] Fixed: Policy includes risky component classification
- [ ] Documentation linked from main README
- [ ] Code review completed

### References
- Source report: 15.1.1.md
- Merged from: ASVS-1511-MED-001

### Priority
**Medium** - Process gap in vulnerability management

---
## Issue: FINDING-016 - Obsolete Spring Framework 2.5.6 dependency declared in dependency management
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Spring Framework 2.5.6 (released ~2008) is far beyond End of Life and has numerous known critical vulnerabilities. While this appears to be used by the mina-integration-xbean module, the monolithic spring artifact from 2008 introduces significant attack surface.

### Details
- **ASVS:** 15.2.1 (Level L1)
- **Affected Files:**
  - `pom.xml`

### Remediation
Migrate the xbean integration to use the modern Spring Framework version already declared (7.0.7) or remove the integration if it's no longer actively maintained.

### Acceptance Criteria
- [ ] Fixed: Spring 2.5.6 removed from dependency management
- [ ] Fixed: xbean integration migrated to Spring 7.0.7 or removed
- [ ] Test added: Integration tests pass with updated dependency
- [ ] Code review completed

### References
- Source report: 15.2.1.md
- Merged from: ASVS-1521-MED-001

### Priority
**Medium** - End-of-life dependency with known vulnerabilities

---
## Issue: FINDING-017 - JMX ObjectMBean exposes all bean properties by default using denylist approach
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When an IoService, IoSession, or custom handler is wrapped in ObjectMBean, all its JavaBean properties are automatically exposed through JMX. Only 7 specific properties are excluded via a denylist. The denylist approach means new properties added to managed objects are automatically exposed without explicit security review. Applications using this integration may unintentionally expose sensitive operational data to JMX clients.

### Details
- **ASVS:** 15.3.1 (Level L1)
- **Affected Files:**
  - `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/ObjectMBean.java`

### Remediation
Consider switching to an allowlist (opt-in) approach or documenting the exposure clearly. Provide an annotation-based or constructor-parameter-based allowlist mechanism.

### Acceptance Criteria
- [ ] Fixed: Allowlist mechanism implemented or exposure documented
- [ ] Test added: Verify only intended properties are exposed
- [ ] Documentation updated with security guidance
- [ ] Code review completed

### References
- Source report: 15.3.1.md
- Merged from: ASVS-1531-MED-001

### Priority
**Medium** - Information disclosure via automatic JMX exposure

---
## Issue: FINDING-018 - SslFilter does not enforce AEAD cipher suite requirement (AES-GCM or ChaCha20-Poly1305)
**Labels:** bug, security, priority:low
**Description:**
### Summary
When enabledCipherSuites is not explicitly configured by the application, the SSLEngine may negotiate cipher suites using RSA key exchange with PKCS#1 v1.5 padding, which is known to be vulnerable to padding oracle attacks. On modern JDKs, these suites are typically de-prioritized but not disabled. Per project security guidance, this is a defense-in-depth finding rated Low because the application is expected to configure cipher suites explicitly, and modern JDKs provide reasonable defaults.

### Details
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **ASVS:** 11.3.2, 11.3.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

### Remediation
Provide a recommended cipher suite list constant or log a warning when no cipher suite allowlist is configured.

### Acceptance Criteria
- [ ] Fixed: Recommended cipher suite constant added
- [ ] Fixed: Warning logged when using default cipher suites
- [ ] Documentation updated with secure configuration guidance
- [ ] Code review completed

### References
- Source report: 11.3.2.md, 11.3.1.md
- Related findings: FINDING-021, FINDING-022
- Merged from: ASVS-1132-LOW-001, SSL-TLS-1

### Priority
**Low** - Defense-in-depth: weak cipher suites may be negotiated with default configuration

---
## Issue: FINDING-019 - SslFilter does not enforce minimum TLS version and documents deprecated protocols as valid options
**Labels:** bug, security, priority:low
**Description:**
### Summary
The documentation lists SSLv2Hello, SSLv3, and TLSv1/TLSv1.1 as valid protocol options without deprecation warnings. If an application configures `setEnabledProtocols("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")`, the SslFilter would enable these deprecated protocols without warning. While modern JDKs (11+) disable TLS 1.0/1.1 at the JRE level, applications running on older JDKs or those that have re-enabled deprecated protocols would be vulnerable.

### Details
- **ASVS:** 12.1.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

### Remediation
1. Update Javadoc to mark SSLv2Hello, SSLv3, TLSv1, and TLSv1.1 as deprecated/insecure. 2. Consider logging a warning when deprecated protocols are configured.

### Acceptance Criteria
- [ ] Fixed: Javadoc updated with deprecation warnings
- [ ] Fixed: Runtime warning added for deprecated protocols
- [ ] Documentation updated with minimum TLS version guidance
- [ ] Code review completed

### References
- Source report: 12.1.1.md
- Merged from: ASVS-1211-LOW-001

### Priority
**Low** - Defense-in-depth: deprecated protocols may be configured without warning

---
## Issue: FINDING-020 - SslFilter does not enable hostname verification by default for client-mode connections
**Labels:** bug, security, priority:low
**Description:**
### Summary
Without endpoint identification (hostname verification), a TLS client will accept a valid certificate issued for any domain, not just the domain it's connecting to. The identificationAlgorithm field defaults to null, so hostname verification is not set unless the application explicitly configures it. Per project security guidance, rated Low as defense-in-depth since applications can configure via setEndpointIdentificationAlgorithm("HTTPS").

### Details
- **ASVS:** 12.2.2 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java`

### Remediation
For client-mode connections, default to HTTPS hostname verification when no explicit algorithm is set.

### Acceptance Criteria
- [ ] Fixed: Hostname verification enabled by default for client mode
- [ ] Test added: Verify hostname mismatch is detected
- [ ] Documentation updated with configuration guidance
- [ ] Code review completed

### References
- Source report: 12.2.2.md
- Merged from: ASVS-1222-LOW-001

### Priority
**Low** - Defense-in-depth: man-in-the-middle attacks possible without hostname verification

---
## Issue: FINDING-021 - HTTP Digest authentication handler explicitly rejects SHA-256 algorithm, limiting to MD5 only
**Labels:** bug, security, priority:low
**Description:**
### Summary
When a proxy server offers HTTP Digest authentication with SHA-256 (as defined in RFC 7616), the client throws a ProxyAuthException and cannot authenticate. This forces connections to only succeed with servers offering MD5-based digest, preventing adoption of approved hash functions even when the server supports them.

### Details
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **ASVS:** 11.4.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/HttpDigestAuthLogicHandler.java`

### Remediation
Add SHA-256 and SHA-256-sess support per RFC 7616 to HttpDigestAuthLogicHandler and DigestUtilities.

### Acceptance Criteria
- [ ] Fixed: SHA-256 algorithm support added
- [ ] Fixed: SHA-256-sess algorithm support added
- [ ] Test added: Verify SHA-256 authentication succeeds
- [ ] Test added: Verify MD5 authentication still works
- [ ] Code review completed

### References
- Source report: 11.4.1.md
- Related findings: FINDING-018, FINDING-022
- Merged from: ASVS-1141-LOW-001

### Priority
**Low** - Weak cryptography: MD5-only digest authentication

---
## Issue: FINDING-022 - DigestUtilities hardcodes a shared static MD5 MessageDigest instance with no support for alternative algorithms
**Labels:** bug, security, priority:low
**Description:**
### Summary
The utility class architecturally prevents the use of any hash algorithm other than MD5 for HTTP Digest authentication. The algorithm is hardcoded at class-load time and shared across all sessions. Even if HttpDigestAuthLogicHandler were updated to accept SHA-256, DigestUtilities.computeResponseValue() would still use MD5 for all hash computations.

### Details
- **CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **ASVS:** 11.4.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/DigestUtilities.java`

### Remediation
Parameterize the hash algorithm in DigestUtilities.computeResponseValue() to accept an algorithm parameter instead of hardcoding MD5.

### Acceptance Criteria
- [ ] Fixed: Algorithm parameter added to computeResponseValue()
- [ ] Fixed: Static MD5 instance removed or made algorithm-agnostic
- [ ] Test added: Verify multiple algorithms can be used
- [ ] Code review completed

### References
- Source report: 11.4.1.md
- Related findings: FINDING-018, FINDING-021
- Merged from: ASVS-1141-LOW-002

### Priority
**Low** - Weak cryptography: hardcoded MD5 prevents stronger algorithm adoption

---
## Issue: FINDING-023 - ProtocolDecoder Interface Lacks Guidance on Validation Responsibilities
**Labels:** documentation, security, priority:low
**Description:**
### Summary
The `ProtocolDecoder` interface Javadoc states implementations should throw exceptions "if the read data violated protocol specification" but provides no guidance on what validation rules implementations should document or enforce. For a framework that expects applications to implement custom decoders for untrusted network input, this is a gap in communicating the validation expectations.

### Details
- **ASVS:** 2.1.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/filter/codec/ProtocolDecoder.java`

### Remediation
Enhance interface Javadoc to document validation expectations including enforcing maximum message sizes, validating field formats, and rejecting malformed input early.

### Acceptance Criteria
- [ ] Fixed: Javadoc enhanced with validation guidance
- [ ] Fixed: Examples added for common validation patterns
- [ ] Documentation reviewed by security team
- [ ] Code review completed

### References
- Source report: 2.1.1.md
- Merged from: ASVS-211-LOW-001

### Priority
**Low** - Documentation gap in communicating security expectations

---
## Issue: FINDING-024 - No Maximum Allocation Size in Buffer Infrastructure
**Labels:** bug, security, priority:low
**Description:**
### Summary
The buffer infrastructure provides no configurable maximum allocation size. While the buffer layer correctly delegates size enforcement to codec implementations (as documented), there is no defense-in-depth mechanism to prevent a single codec with missing bounds checks from causing process-wide denial of service. This creates a risk where unbounded memory allocations could lead to performance degradation or denial of service if codecs fail to implement proper size validation.

### Details
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling)
- **ASVS:** 5.2.1 (Level L1)
- **Affected Files:**
  - `mina-core/src/main/java/org/apache/mina/core/buffer/IoBuffer.java`
  - `mina-core/src/main/java/org/apache/mina/core/buffer/CachedBufferAllocator.java`

### Remediation
Add defense-in-depth capabilities to the buffer infrastructure: Option 1: Add configurable max to IoBufferAllocator interface (setMaxAllocationSize). Option 2: Add max capacity to IoBuffer (setMaxCapacity) that auto-expansion would respect. This will provide a safety net even when individual codecs fail to implement proper bounds checking.

### Acceptance Criteria
- [ ] Fixed: Maximum allocation size mechanism added
- [ ] Test added: Verify allocation limit is enforced
- [ ] Test added: Verify legitimate allocations within limit succeed
- [ ] Documentation updated with configuration guidance
- [ ] Code review completed

### References
- Source report: 5.2.1.md
- Related findings: FINDING-003
- Merged from: ASVS-521-LOW-001

### Priority
**Low** - Defense-in-depth: no global allocation limit

---
## Issue: FINDING-025 - Unmaintained jzlib dependency (last release 2013)
**Labels:** bug, security, priority:low
**Description:**
### Summary
jzlib 1.1.3 was last released in 2013 and the project appears unmaintained. While no critical CVEs are currently known, unmaintained compression libraries handling untrusted network data represent an elevated risk over time.

### Details
- **ASVS:** 15.2.1 (Level L1)
- **Affected Files:**
  - `pom.xml`
  - `mina-filter-compression/pom.xml`

### Remediation
Consider migrating to java.util.zip (built-in JDK deflate/inflate) or a maintained alternative like Apache Commons Compress.

### Acceptance Criteria
- [ ] Fixed: jzlib replaced with maintained alternative
- [ ] Test added: Compression functionality tests pass
- [ ] Performance testing completed
- [ ] Code review completed

### References
- Source report: 15.2.1.md
- Merged from: ASVS-1521-LOW-001

### Priority
**Low** - Unmaintained dependency with no known active vulnerabilities

---
## Issue: FINDING-026 - ObjectMBean convertValue returns full collection contents without field filtering
**Labels:** bug, security, priority:low
**Description:**
### Summary
When a bean property is a Collection or Map, all elements are serialized and returned through JMX. There is no filtering of individual elements or fields within collection items. If a managed object's collection contains items with mixed-sensitivity fields, all fields of all items are exposed.

### Details
- **ASVS:** 15.3.1 (Level L1)
- **Affected Files:**
  - `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/ObjectMBean.java`

### Remediation
Consider adding element-level filtering or size limits for collection attributes exposed via JMX.

### Acceptance Criteria
- [ ] Fixed: Collection element filtering mechanism added
- [ ] Fixed: Size limits for collection attributes added
- [ ] Test added: Verify filtering works correctly
- [ ] Documentation updated with configuration guidance
- [ ] Code review completed

### References
- Source report: 15.3.1.md
- Merged from: ASVS-1531-LOW-001

### Priority
**Low** - Information disclosure via unfiltered collection exposure