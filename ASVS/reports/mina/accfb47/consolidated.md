# Security Audit Consolidated Report — apache/mina

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/mina |
| Branch | 2.2.X |
| ASVS Level | L1 |
| Severity Threshold | None (all findings included) |
| Commit | accfb47 |
| Date | May 20, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 26 |

## Executive Summary

### Severity Distribution


| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High     | 7 | 28.0% |
| Medium   | 9 | 36.0% |
| Low      | 9 | 36.0% |
| Info     | 0 | 0.0% |

All 26 findings are actionable. The audit was conducted at ASVS Level 1, covering 16 security domains across the repository.

### Level Coverage

This audit evaluated controls at **ASVS L1**, which represents the minimum assurance level suitable for all applications. All findings map to L1 verification requirements, confirming that foundational security controls require attention before progression to higher assurance levels.

### Top Risks

1. **HTTP Response Splitting via Missing CRLF Sanitization (FINDING-004, High)** — The `HttpServerEncoder` does not sanitize header values for CR/LF characters, enabling HTTP response splitting attacks that can lead to cache poisoning, session hijacking, or cross-site scripting.

2. **HTTP Request Smuggling via Missing CRLF Sanitization (FINDING-005, High)** — The `HttpClientEncoder` similarly lacks CRLF sanitization, opening the door to request smuggling attacks against downstream systems.

3. **Unsanitized OGNL Expression Execution (FINDING-006, High)** — The `findAndProcessSessions` method processes user-influenced input as OGNL expressions without sanitization, creating a remote code execution vector through the JMX management interface.

4. **End-of-life Log4j 1.x Dependency (FINDING-008, High)** — The project declares a dependency on Log4j 1.x, which has reached end-of-life and contains known critical CVEs (including CVE-2019-17571), exposing deployments to deserialization-based remote code execution.

### Positive Controls Observed

| Control | Evidence | Files |
|---------|----------|-------|
| Buffer layer correctly delegates size enforcement to codec implementations as per documented architecture | Architecture design pattern observed in buffer infrastructure | `mina-core/src/main/java/org/apache/mina/core/buffer/IoBuffer.java`, `mina-core/src/main/java/org/apache/mina/core/buffer/CachedBufferAllocator.java` |
| IoSessionFinder character-level validation for query parameter | The query parameter (params[0]) is properly validated through IoSessionFinder character-level validation | `mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java` |

These positive controls demonstrate that the project does apply defensive patterns in specific areas; however, they are not uniformly applied across the codebase, as evidenced by the findings in adjacent components.

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

### 3.2 High

#### FINDING-002: 🟠 ConnectionThrottleFilter Fails to Block Event Propagation After Throttle Detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-367 |
| **ASVS Section(s)** | 6.3.1 |
| **File(s)** | mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java |
| **Source Report(s)** | 6.3.1.md |
| **Related Finding(s)** | None |

**Description:**

In ConnectionThrottleFilter.sessionCreated(), after detecting a rate violation and calling session.closeNow(), the method unconditionally calls nextFilter.sessionCreated(session), allowing the session event to propagate through the entire filter chain. This defeats the purpose of the throttle as downstream handlers still process the connection.

**Remediation:**

Add `return` after `session.closeNow()` in `sessionCreated()` to prevent filter chain propagation. Mirror BlacklistFilter's correct if/else pattern.

---

#### FINDING-003: 🟠 Unbounded Header Accumulation Enables Memory Exhaustion DoS

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1, 2.1.1 |
| **File(s)** | mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Report(s)** | 2.2.1.md, 2.1.1.md |
| **Related Finding(s)** | FINDING-024 |

**Description:**

When the decoder receives a partial HTTP head (no `\r\n\r\n` terminator found), it accumulates the data in a session attribute (`PARTIAL_HEAD_ATT`) without any maximum size enforcement. An attacker can send an arbitrarily large stream of bytes without the header terminator, causing unbounded heap allocation until the JVM runs out of memory.

**Remediation:**

Add a MAX_HEAD_SIZE constant (default 8KB) and check accumulated size in the HEAD state before storing partial buffers. Reject requests exceeding the limit with 431 Request Header Fields Too Large.

---

#### FINDING-004: 🟠 HTTP Response Splitting via Missing CRLF Sanitization in HttpServerEncoder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-113 |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | mina-http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| **Source Report(s)** | 1.2.1.md |
| **Related Finding(s)** | FINDING-005, FINDING-012 |

**Description:**

Application-supplied header values are concatenated into the HTTP response without CRLF filtering. The encoder is the last point before wire emission, and per the project's documented scope, 'When the encoder serializes application-supplied header values verbatim and the application has no opportunity to sanitize between construction and wire emission, the encoder owns sanitization.'

**Remediation:**

Strip or reject \r and \n characters in header names and header values before serialization in HttpServerEncoder.encode().

---

#### FINDING-005: 🟠 HTTP Request Smuggling via Missing CRLF Sanitization in HttpClientEncoder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-113 |
| **ASVS Section(s)** | 1.2.1 |
| **File(s)** | mina-http/src/main/java/org/apache/mina/http/HttpClientEncoder.java |
| **Source Report(s)** | 1.2.1.md |
| **Related Finding(s)** | FINDING-004, FINDING-012 |

**Description:**

Application-supplied request path, query string, and header values are concatenated into the HTTP request without CRLF filtering. Both the request line components (path, query string) and all header names/values are emitted without structural encoding, enabling HTTP request smuggling.

**Remediation:**

Strip or reject \r and \n characters in header names, header values, request paths, and query strings before serialization in HttpClientEncoder.encode().

---

#### FINDING-006: 🟠 Unsanitized OGNL Expression Execution in findAndProcessSessions

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-94 |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java |
| **Source Report(s)** | 1.3.2.md |
| **Related Finding(s)** | None |

**Description:**

The `findAndProcessSessions` JMX operation accepts an OGNL command expression (params[1]) that is passed directly to Ognl.parseExpression() and Ognl.getValue() without any sanitization or validation. While the query parameter (params[0]) is properly validated through IoSessionFinder character-level validation, the command parameter bypasses all controls, creating a remote code execution vulnerability accessible to any JMX client with access to the MBean.

**Remediation:**

Apply the same character validation as IoSessionFinder to the command parameter, or implement OGNL MemberAccess restrictions, or (preferred) replace with specific named JMX operations that don't require arbitrary expression evaluation.

---

#### FINDING-007: 🟠 Thread-Local Event Queue Not Cleared on Exception — Stale Events Processed Out of Order

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-362 |
| **ASVS Section(s)** | 2.3.1 |
| **File(s)** | mina-statemachine/src/main/java/org/apache/mina/statemachine/StateMachine.java |
| **Source Report(s)** | 2.3.1.md |
| **Related Finding(s)** | |

**Description:**

When a transition handler calls `StateControl.breakAndReturnNow()`, the framework catches `BreakAndReturnException` and pops the call stack. However, there is no validation that the call stack is non-empty before calling `pop()`. If `breakAndReturnNow()` is called without a matching prior `breakAndCall*`, the `pop()` operation throws an unchecked `NoSuchElementException` that propagates out of `processEvents()`, triggering the stale queue issue and leaving the state machine in an inconsistent state. This allows business logic flows to be corrupted and processed out of expected sequential order.

**Remediation:**

Check callStack.isEmpty() before calling pop() in the BreakAndReturnException handler. Throw a descriptive IllegalStateException rather than allowing NoSuchElementException to corrupt processing state.

---

#### FINDING-008: 🟠 End-of-life Log4j 1.x dependency with known critical CVEs in dependency management

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **File(s)** | pom.xml |
| **Source Report(s)** | 15.2.1.md |
| **Related Finding(s)** | None |

**Description:**

Log4j 1.2.17 reached End of Life in August 2015. It has multiple known CVEs including CVE-2019-17571 (CVSS 9.8), CVE-2021-4104 (CVSS 7.5), CVE-2022-23302 (CVSS 8.8), CVE-2022-23305 (CVSS 9.8), CVE-2022-23307 (CVSS 8.8). While the project uses slf4j-reload4j as its actual logging backend, having log4j:log4j:1.2.17 in &lt;dependencyManagement&gt; means any transitive dependency pulling log4j:log4j will resolve to this critically vulnerable version.

**Remediation:**

Either exclude log4j:log4j entirely or add an explicit ban via maven-enforcer-plugin bannedDependencies rule.

---

### 3.3 Medium

#### FINDING-009: Production module ships BogusTrustManagerFactory that accepts all certificates without any guard against accidental use

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 12.2.2 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/ssl/BogusTrustManagerFactory.java |
| **Source Reports** | 12.2.2.md |
| **Related** | - |

**Description:**

BogusTrustManagerFactory in mina-core production module disables all certificate validation. It lives in the same package as legitimate SSL classes, making accidental use trivially easy via IDE autocomplete. No compile-time annotation, no runtime warning, and no mechanism to prevent use in non-test environments. The profile acknowledges this as a 'real foot-gun in a production module' that remains in scope.

**Remediation:**

Add runtime detection and logging to prevent silent production misuse. Consider @Deprecated(forRemoval = true) annotation and a system property gate that must be explicitly set to allow use outside test contexts.

---

#### FINDING-010: ConnectionThrottleFilter Cleanup Thread Executes Only Once, Leading to Unbounded State Growth

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-401 |
| **ASVS sections** | 6.3.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java |
| **Source Reports** | 6.3.1.md |
| **Related** | - |

**Description:**

The ExpiredSessionThread.run() method sleeps once and performs a single cleanup pass, then the thread terminates. No further cleanup ever occurs, causing the clients ConcurrentHashMap to grow without bound over the server's lifetime, leading to memory leak and potential OutOfMemoryError.

**Remediation:**

Wrap the sleep-and-cleanup logic in a `while (!Thread.currentThread().isInterrupted())` loop. Use `iterator.remove()` instead of `clients.remove()` to avoid ConcurrentModificationException.

---

#### FINDING-011: ObjectSerializationDecoder Defaults to Permissive Deserialization When No ClassNameMatcher Is Configured

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-502 |
| **ASVS sections** | 1.5.1, 5.2.2 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationDecoder.java, mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationCodecFactory.java |
| **Source Reports** | 1.5.1.md, 5.2.2.md |
| **Related** | - |

**Description:**

The `acceptMatchers` list initializes empty, meaning when no `accept()` calls are made, `getObject()` proceeds without class filtering, accepting arbitrary classes for deserialization. Network wire bytes → IoBuffer → doDecode() → setMatchers(empty list) → getObject(classLoader) → unrestricted class instantiation. Remote code execution via Java deserialization gadget chains. The class name filtering mechanism (ClassNameMatcher) exists but is not enforced when the acceptMatchers list is empty (the default). Without configured matchers, any class type is accepted regardless of whether it matches what the application expects, enabling deserialization of arbitrary classes.

**Remediation:**

The framework should adopt a default-deny posture. If no matchers are configured, deserialization should be rejected rather than allowed. Add an IllegalStateException when acceptMatchers is empty, or ship with a minimal safe-by-default allowlist that only permits JDK primitive wrapper types. Factory should require explicit type configuration via a constructor that mandates a ClassNameMatcher parameter, or add a default-deny guard in doDecode() that throws IllegalStateException when acceptMatchers is empty.

---

#### FINDING-012: HTTP Response Encoder Does Not Validate Header Values for CRLF Injection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-113 |
| **ASVS sections** | 2.2.1 |
| **Files** | mina-http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-004, FINDING-005 |

**Description:**

The `HttpServerEncoder` serializes response headers by concatenating application-supplied header names and values directly into the output buffer without validating that they do not contain CR or LF characters. Per the project security profile: 'When the encoder serializes application-supplied header values verbatim and the application has no opportunity to sanitize between construction and wire emission, the encoder owns sanitization.'

**Remediation:**

Reject or strip CR/LF characters in header names and values during encoding. Throw ProtocolEncoderException if CRLF is detected in header name or value.

---

#### FINDING-013: Decoder Validation Gaps at the Trusted Service Layer Allow Malformed Input to Reach Application Logic

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS sections** | 2.2.2, 2.2.1 |
| **Files** | mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| **Source Reports** | 2.2.2.md, 2.2.1.md |
| **Related** | - |

**Description:**

The `HttpServerDecoder` operates within MINA's filter chain (`ProtocolCodecFilter`) which is the trusted server-side input validation boundary — the correct architectural position. However, several categories of malformed input pass through this layer without rejection, reaching application `IoHandler` implementations as seemingly-valid `HttpRequest` objects. This includes requests with invalid header name characters, negative or extremely large content-length values, and malformed request lines.

**Remediation:**

Ensure the decoder rejects all protocol-violating input with appropriate HttpException or ProtocolDecoderException before outputting message objects. Only valid, validated requests should reach the application IoHandler.

---

#### FINDING-014: No Structural Validation of Request-URI Components in HttpClientEncoder

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-116 |
| **ASVS sections** | 1.2.2 |
| **Files** | mina-http/src/main/java/org/apache/mina/http/HttpClientEncoder.java |
| **Source Reports** | 1.2.2.md |
| **Related** | - |

**Description:**

Application-supplied path (getRequestPath()) and query string (getQueryString()) are directly concatenated into request-URI with no percent-encoding of reserved/unsafe characters and no validation that the path is a valid absolute-path per RFC 7230 §5.3. Malformed request-URIs can cause divergent parsing by proxies and servers.

**Remediation:**

At minimum, reject characters that break HTTP message structure (\r, \n, space) in request path and query string before serialization.

---

#### FINDING-015: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.1.1 |
| **Files** | pom.xml |
| **Source Reports** | 15.1.1.md |
| **Related** | - |

**Description:**

The project's pom.xml manages 30+ third-party dependencies via &lt;dependencyManagement&gt; but no companion document, POM property, or comment defines: 1. Maximum acceptable time to remediate critical/high/medium/low vulnerabilities in dependencies 2. General update cadence for libraries 3. Classification of components as "risky" or containing "dangerous functionality"

**Remediation:**

Create a dependency management policy (e.g., DEPENDENCY_POLICY.md or in project wiki) that defines remediation timeframes by vulnerability severity and a general update policy.

---

#### FINDING-016: Obsolete Spring Framework 2.5.6 dependency declared in dependency management

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.2.1 |
| **Files** | pom.xml |
| **Source Reports** | 15.2.1.md |
| **Related** | - |

**Description:**

Spring Framework 2.5.6 (released ~2008) is far beyond End of Life and has numerous known critical vulnerabilities. While this appears to be used by the mina-integration-xbean module, the monolithic spring artifact from 2008 introduces significant attack surface.

**Remediation:**

Migrate the xbean integration to use the modern Spring Framework version already declared (7.0.7) or remove the integration if it's no longer actively maintained.

---

#### FINDING-017: JMX ObjectMBean exposes all bean properties by default using denylist approach

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.3.1 |
| **Files** | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/ObjectMBean.java |
| **Source Reports** | 15.3.1.md |
| **Related** | - |

**Description:**

When an IoService, IoSession, or custom handler is wrapped in ObjectMBean, all its JavaBean properties are automatically exposed through JMX. Only 7 specific properties are excluded via a denylist. The denylist approach means new properties added to managed objects are automatically exposed without explicit security review. Applications using this integration may unintentionally expose sensitive operational data to JMX clients.

**Remediation:**

Consider switching to an allowlist (opt-in) approach or documenting the exposure clearly. Provide an annotation-based or constructor-parameter-based allowlist mechanism.

### 3.4 Low

#### FINDING-018: SslFilter does not enforce AEAD cipher suite requirement (AES-GCM or ChaCha20-Poly1305) 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 11.3.2, 11.3.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java |
| **Source Reports** | 11.3.2.md, 11.3.1.md |
| **Related** | FINDING-021, FINDING-022 |

**Description:**

When enabledCipherSuites is not explicitly configured by the application, the SSLEngine may negotiate cipher suites using RSA key exchange with PKCS#1 v1.5 padding, which is known to be vulnerable to padding oracle attacks. On modern JDKs, these suites are typically de-prioritized but not disabled. Per project security guidance, this is a defense-in-depth finding rated Low because the application is expected to configure cipher suites explicitly, and modern JDKs provide reasonable defaults.

**Remediation:**

Provide a recommended cipher suite list constant or log a warning when no cipher suite allowlist is configured.

---

#### FINDING-019: SslFilter does not enforce minimum TLS version and documents deprecated protocols as valid options 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 12.1.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java |
| **Source Reports** | 12.1.1.md |
| **Related** | - |

**Description:**

The documentation lists SSLv2Hello, SSLv3, and TLSv1/TLSv1.1 as valid protocol options without deprecation warnings. If an application configures `setEnabledProtocols("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2")`, the SslFilter would enable these deprecated protocols without warning. While modern JDKs (11+) disable TLS 1.0/1.1 at the JRE level, applications running on older JDKs or those that have re-enabled deprecated protocols would be vulnerable.

**Remediation:**

1. Update Javadoc to mark SSLv2Hello, SSLv3, TLSv1, and TLSv1.1 as deprecated/insecure. 2. Consider logging a warning when deprecated protocols are configured.

---

#### FINDING-020: SslFilter does not enable hostname verification by default for client-mode connections 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 12.2.2 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java |
| **Source Reports** | 12.2.2.md |
| **Related** | - |

**Description:**

Without endpoint identification (hostname verification), a TLS client will accept a valid certificate issued for any domain, not just the domain it's connecting to. The identificationAlgorithm field defaults to null, so hostname verification is not set unless the application explicitly configures it. Per project security guidance, rated Low as defense-in-depth since applications can configure via setEndpointIdentificationAlgorithm("HTTPS").

**Remediation:**

For client-mode connections, default to HTTPS hostname verification when no explicit algorithm is set.

---

#### FINDING-021: HTTP Digest authentication handler explicitly rejects SHA-256 algorithm, limiting to MD5 only 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 11.4.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/HttpDigestAuthLogicHandler.java |
| **Source Reports** | 11.4.1.md |
| **Related** | FINDING-018, FINDING-022 |

**Description:**

When a proxy server offers HTTP Digest authentication with SHA-256 (as defined in RFC 7616), the client throws a ProxyAuthException and cannot authenticate. This forces connections to only succeed with servers offering MD5-based digest, preventing adoption of approved hash functions even when the server supports them.

**Remediation:**

Add SHA-256 and SHA-256-sess support per RFC 7616 to HttpDigestAuthLogicHandler and DigestUtilities.

---

#### FINDING-022: DigestUtilities hardcodes a shared static MD5 MessageDigest instance with no support for alternative algorithms 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-327 |
| **ASVS Section(s)** | 11.4.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/DigestUtilities.java |
| **Source Reports** | 11.4.1.md |
| **Related** | FINDING-018, FINDING-021 |

**Description:**

The utility class architecturally prevents the use of any hash algorithm other than MD5 for HTTP Digest authentication. The algorithm is hardcoded at class-load time and shared across all sessions. Even if HttpDigestAuthLogicHandler were updated to accept SHA-256, DigestUtilities.computeResponseValue() would still use MD5 for all hash computations.

**Remediation:**

Parameterize the hash algorithm in DigestUtilities.computeResponseValue() to accept an algorithm parameter instead of hardcoding MD5.

---

#### FINDING-023: ProtocolDecoder Interface Lacks Guidance on Validation Responsibilities 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/filter/codec/ProtocolDecoder.java |
| **Source Reports** | 2.1.1.md |
| **Related** | - |

**Description:**

The `ProtocolDecoder` interface Javadoc states implementations should throw exceptions "if the read data violated protocol specification" but provides no guidance on what validation rules implementations should document or enforce. For a framework that expects applications to implement custom decoders for untrusted network input, this is a gap in communicating the validation expectations.

**Remediation:**

Enhance interface Javadoc to document validation expectations including enforcing maximum message sizes, validating field formats, and rejecting malformed input early.

---

#### FINDING-024: No Maximum Allocation Size in Buffer Infrastructure 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | mina-core/src/main/java/org/apache/mina/core/buffer/IoBuffer.java, mina-core/src/main/java/org/apache/mina/core/buffer/CachedBufferAllocator.java |
| **Source Reports** | 5.2.1.md |
| **Related** | FINDING-003 |

**Description:**

The buffer infrastructure provides no configurable maximum allocation size. While the buffer layer correctly delegates size enforcement to codec implementations (as documented), there is no defense-in-depth mechanism to prevent a single codec with missing bounds checks from causing process-wide denial of service. This creates a risk where unbounded memory allocations could lead to performance degradation or denial of service if codecs fail to implement proper size validation.

**Remediation:**

Add defense-in-depth capabilities to the buffer infrastructure: Option 1: Add configurable max to IoBufferAllocator interface (setMaxAllocationSize). Option 2: Add max capacity to IoBuffer (setMaxCapacity) that auto-expansion would respect. This will provide a safety net even when individual codecs fail to implement proper bounds checking.

---

#### FINDING-025: Unmaintained jzlib dependency (last release 2013) 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 15.2.1 |
| **Files** | pom.xml, mina-filter-compression/pom.xml |
| **Source Reports** | 15.2.1.md |
| **Related** | - |

**Description:**

jzlib 1.1.3 was last released in 2013 and the project appears unmaintained. While no critical CVEs are currently known, unmaintained compression libraries handling untrusted network data represent an elevated risk over time.

**Remediation:**

Consider migrating to java.util.zip (built-in JDK deflate/inflate) or a maintained alternative like Apache Commons Compress.

---

#### FINDING-026: ObjectMBean convertValue returns full collection contents without field filtering 🔵

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/ObjectMBean.java |
| **Source Reports** | 15.3.1.md |
| **Related** | - |

**Description:**

When a bean property is a Collection or Map, all elements are serialized and returned through JMX. There is no filtering of individual elements or fields within collection items. If a managed object's collection contains items with mixed-sensitivity fields, all fields of all items are exposed.

**Remediation:**

Consider adding element-level filtering or size limits for collection attributes exposed via JMX.

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Buffer Memory Management | Buffer layer correctly delegates size enforcement to codec implementations as per documented architecture | Architecture design pattern observed in buffer infrastructure | mina-core/src/main/java/org/apache/mina/core/buffer/IoBuffer.java, mina-core/src/main/java/org/apache/mina/core/buffer/CachedBufferAllocator.java |
| Output Encoding Injection | IoSessionFinder character-level validation for query parameter | The query parameter (params[0]) is properly validated through IoSessionFinder character-level validation | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Fail** | See FINDING-004, FINDING-005 |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Fail** | See FINDING-014 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** | |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** | |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** | |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** | |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Fail** | See FINDING-006 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Fail** | See FINDING-011 |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Fail** | See FINDING-003, FINDING-023 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Fail** | See FINDING-003, FINDING-012, FINDING-013 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Partial** | See FINDING-013 |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Fail** | See FINDING-007 |
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
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **N/A** | |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **Pass** | |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Partial** | See FINDING-024 |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **Partial** | See FINDING-011 |
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
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. | **Fail** | See FINDING-002, FINDING-010 |
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
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **N/A** | |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **N/A** | |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **N/A** | |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. | **N/A** | |
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
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **Partial** | See FINDING-018 |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **Partial** | See FINDING-018 |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **Partial** | See FINDING-021, FINDING-022 |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **Partial** | See FINDING-019 |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** | |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **Partial** | See FINDING-009, FINDING-020 |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** | |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **N/A** | |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** | |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Fail** | See FINDING-015 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Fail** | See FINDING-008, FINDING-016, FINDING-025 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Fail** | See FINDING-017, FINDING-026 |

**Summary Statistics:**
- **Pass**: 1 requirements (1.4%)
- **Partial**: 8 requirements (11.4%)
- **N/A**: 50 requirements (71.4%)
- **Fail**: 11 requirements (15.7%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-002 | High | 6.3.1 | — | mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java |
| FINDING-003 | High | 2.2.1, 2.1.1 | FINDING-024 | mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-004 | High | 1.2.1 | FINDING-005, FINDING-012 | mina-http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| FINDING-005 | High | 1.2.1 | FINDING-004, FINDING-012 | mina-http/src/main/java/org/apache/mina/http/HttpClientEncoder.java |
| FINDING-006 | High | 1.3.2 | — | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/IoServiceMBean.java |
| FINDING-007 | High | 2.3.1 | | mina-statemachine/src/main/java/org/apache/mina/statemachine/StateMachine.java |
| FINDING-008 | High | 15.2.1 | — | pom.xml |
| FINDING-009 | Medium | 12.2.2 | — | mina-core/src/main/java/org/apache/mina/filter/ssl/BogusTrustManagerFactory.java |
| FINDING-010 | Medium | 6.3.1 | — | mina-core/src/main/java/org/apache/mina/filter/firewall/ConnectionThrottleFilter.java |
| FINDING-011 | Medium | 1.5.1, 5.2.2 | — | mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationDecoder.java, mina-core/src/main/java/org/apache/mina/filter/codec/serialization/ObjectSerializationCodecFactory.java |
| FINDING-012 | Medium | 2.2.1 | FINDING-004, FINDING-005 | mina-http/src/main/java/org/apache/mina/http/HttpServerEncoder.java |
| FINDING-013 | Medium | 2.2.2, 2.2.1 | — | mina-http/src/main/java/org/apache/mina/http/HttpServerDecoder.java |
| FINDING-014 | Medium | 1.2.2 | — | mina-http/src/main/java/org/apache/mina/http/HttpClientEncoder.java |
| FINDING-015 | Medium | 15.1.1 | — | pom.xml |
| FINDING-016 | Medium | 15.2.1 | — | pom.xml |
| FINDING-017 | Medium | 15.3.1 | — | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/ObjectMBean.java |
| FINDING-018 | Low | 11.3.2, 11.3.1 | FINDING-021, FINDING-022 | mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java |
| FINDING-019 | Low | 12.1.1 | — | mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java |
| FINDING-020 | Low | 12.2.2 | — | mina-core/src/main/java/org/apache/mina/filter/ssl/SslFilter.java |
| FINDING-021 | Low | 11.4.1 | FINDING-018, FINDING-022 | mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/HttpDigestAuthLogicHandler.java |
| FINDING-022 | Low | 11.4.1 | FINDING-018, FINDING-021 | mina-core/src/main/java/org/apache/mina/proxy/handlers/http/digest/DigestUtilities.java |
| FINDING-023 | Low | 2.1.1 | — | mina-core/src/main/java/org/apache/mina/filter/codec/ProtocolDecoder.java |
| FINDING-024 | Low | 5.2.1 | FINDING-003 | mina-core/src/main/java/org/apache/mina/core/buffer/IoBuffer.java, mina-core/src/main/java/org/apache/mina/core/buffer/CachedBufferAllocator.java |
| FINDING-025 | Low | 15.2.1 | — | pom.xml, mina-filter-compression/pom.xml |
| FINDING-026 | Low | 15.3.1 | — | mina-integration-jmx/src/main/java/org/apache/mina/integration/jmx/ObjectMBean.java |

**Total Unique Findings**: 26 (1 Critical, 7 High, 9 Medium, 9 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 26 |

**Total consolidated findings: 26**

*End of Consolidated Security Audit Report*
