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
| Total Findings | 25 |

## Executive Summary

### Severity Distribution


| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High     | 0 | 0.0% |
| Medium   | 2 | 8.3% |
| Low      | 22 | 91.7% |
| Info     | 0 | 0.0% |

### Level Coverage

All 25 findings are mapped to **ASVS Level 1 (L1)** controls. The audit scope was limited to L1 verification, covering fundamental security hygiene across 15 directories of the repository.

### Top 5 Risks


2. **[Medium] FINDING-002: No upper bounds validation on pattern formatting width values enabling potential DoS** — Pattern format specifiers accept arbitrarily large width values that could trigger excessive memory allocation and string operations, creating a denial-of-service vector when log pattern strings are influenced by untrusted input. (ASVS 2.2.1)

3. **[Medium] FINDING-003: ToFileSize performs unchecked multiplication potentially causing silent integer overflow** — File size parsing logic multiplies parsed values without overflow checking, which may result in silent wraparound to small or negative values, undermining intended file size constraints. (ASVS 2.2.1)

4. **[Low] FINDING-004: No Type Whitelist or Assembly Restriction on Dynamic Instantiation** — The configuration loading infrastructure instantiates types by fully-qualified name from XML configuration without restricting which assemblies or type namespaces are permitted, broadening the attack surface if configuration files are attacker-controlled. (ASVS 1.3.2)

5. **[Low] FINDING-009: No upper bound validation on BufferSize allows excessive memory allocation** — The buffering appender accepts arbitrary buffer size values without ceiling validation, enabling memory exhaustion if configuration is tampered with. (ASVS 5.2.1)

### Positive Controls

The audit identified several design-level security controls that reduce the overall attack surface of the library:

| # | Control | Domain |
|---|---------|--------|
| 1 | **No OS command execution anywhere in the codebase** — Functionality is achieved without shell commands or process execution, eliminating command injection by design. | configuration_loading |
| 2 | **TLS version selection delegated to .NET runtime** — The library does not hardcode TLS versions, allowing deployment infrastructure to enforce current standards. | network_appenders |
| 3 | **Deserialization trust boundary is a deployment concern** — The library assumes serialized streams originate from trusted remoting sources, with security enforced at the transport layer. | input_validation |
| 4 | **Variable substitution dictionaries sourced within trust boundary** — Substitution values come from system properties and configuration, not from external untrusted input. | input_validation |
| 5 | **FixFlags mechanism controls data capture at source** — The `FixFlags` parameter and `FixFlags.Partial` default limit which environmental data is captured before serialization, reducing unintentional sensitive data exposure. | serialization |
| 6 | **Explicit Clear()/Remove() methods for thread context** — Scoped cleanup responsibility is intentionally delegated to consuming applications with clear API support. | thread_context |
| 7 | **Active vulnerability management with VDR** — The project maintains a Vulnerability Disclosure Report at `https://logging.apache.org/cyclonedx/vdr.xml` demonstrating ongoing dependency risk management. | component_security |

---


> **Note:** 1 Critical finding has been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

### 3.3 Medium

#### FINDING-002: No upper bounds validation on pattern formatting width values enabling potential DoS

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS sections** | 2.2.1 |
| **Files** | src/log4net/Util/PatternParser.cs |
| **Source Reports** | 2.2.1.md |
| **Related** | FINDING-009, FINDING-010, FINDING-011, FINDING-012, FINDING-018 |

**Description:**

DOWNGRADED from High: Configuration/pattern strings typically come from trusted administrators per the project's threat model, reducing exploitation likelihood. However, unbounded integer parsing with no cap on formattingInfo.Min/Max remains a defense-in-depth concern. A pattern like '%999999999message' sets Min=999999999, potentially allocating ~1GB for a single formatted field. Integer overflow is also possible with unchecked multiplication on long digit sequences.

**Remediation:**

Cap formattingInfo.Min and formattingInfo.Max at a reasonable upper bound (e.g., 10000) and log an error when exceeded.

---

#### FINDING-003: ToFileSize performs unchecked multiplication potentially causing silent integer overflow

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-190 |
| **ASVS sections** | 2.2.1 |
| **Files** | src/log4net/Util/OptionConverter.cs |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

The ToFileSize method performs unchecked longVal * multiplier which can overflow long.MaxValue, resulting in a negative or unexpected value. This could cause RollingFileAppender to never rotate (disk exhaustion) or rotate on every write.

**Remediation:**

Use checked(longVal * multiplier) or explicit overflow validation, returning defaultValue on overflow.

### 3.4 Low

#### FINDING-004: No Type Whitelist or Assembly Restriction on Dynamic Instantiation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-470 |
| **ASVS Section(s)** | 1.3.2 |
| **Files** | src/log4net/Repository/Hierarchy/XmlHierarchyConfigurator.cs, src/log4net/Util/OptionConverter.cs |
| **Source Reports** | 1.3.2.md |
| **Related Findings** | FINDING-005 |

**Description:**

DOWNGRADED from Medium: The AdoNetAppender and configuration system allow instantiation of any type implementing required interfaces from any loaded assembly via Activator.CreateInstance(). No type whitelist or assembly restriction exists. However, exploitation requires attacker control of configuration files, which is the acknowledged trust boundary for this logging framework. This is a defense-in-depth gap, not an exploitable vulnerability under the project's threat model.

**Remediation:**

Add an opt-in type whitelist mechanism that consumers can enable to restrict which types can be instantiated from configuration, providing defense-in-depth without breaking backwards compatibility.

---

#### FINDING-005: Reflection-Based Parse Method Invocation Without Method Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-470 |
| **ASVS Section(s)** | 1.3.2 |
| **Files** | src/log4net/Util/OptionConverter.cs |
| **Source Reports** | 1.3.2.md |
| **Related Findings** | FINDING-004 |

**Description:**

The OptionConverter.ConvertStringTo() method discovers and invokes arbitrary static Parse methods via reflection. The target type is determined by the property type (compile-time defined on appender/layout classes), so the type itself is not directly attacker-controllable in the normal flow. However, the value parameter comes from configuration (with environment variable substitution applied). Risk is mitigated because the target type is property-defined, not configuration-defined (except when type attribute overrides) and standard .NET types have well-behaved Parse methods.

**Remediation:**

Consider adding validation that the target type is from a known-safe assembly before invoking its Parse method.

---

#### FINDING-006: DtdProcessing.Ignore Used Instead of DtdProcessing.Prohibit

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-611 |
| **ASVS Section(s)** | 1.5.1 |
| **Files** | src/log4net/Config/XmlConfigurator.cs |
| **Source Reports** | 1.5.1.md |
| **Related Findings** | |

**Description:**

While DtdProcessing.Ignore combined with XmlResolver = null effectively prevents XXE exploitation (entities are never resolved), using DtdProcessing.Prohibit would provide defense-in-depth by rejecting documents containing DTD declarations entirely. The current setting silently ignores DTDs rather than failing fast. Additionally, the inline comment 'Allow the DTD to specify entity includes' is misleading and contradicts the actual behavior.

**Remediation:**

Replace DtdProcessing.Ignore with DtdProcessing.Prohibit and fix the misleading comment to accurately describe the secure behavior.

---

#### FINDING-007: Environment variable expansion in file paths introduces indirect path manipulation without subsequent canonicalization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **Files** | src/log4net/Appender/FileAppender.cs |
| **Source Reports** | 5.3.2.md |
| **Related Findings** | FINDING-008 |

**Description:**

Environment.ExpandEnvironmentVariables() is called on file paths without subsequent canonicalization. In environments where process environment variables can be influenced by less-trusted actors, log files could be written to unintended locations. Note: configuration is the project's trust boundary; exploitation requires environment variable control in the same process.

**Remediation:**

After Environment.ExpandEnvironmentVariables(), apply Path.GetFullPath() to canonicalize the path and optionally compare it against expected boundaries.

---

#### FINDING-008: Path validation check in OpenFile() is non-enforcing (detection only)

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **Files** | src/log4net/Appender/FileAppender.cs |
| **Source Reports** | 5.3.2.md |
| **Related Findings** | FINDING-007 |

**Description:**

Path.IsPathRooted() check in OpenFile() logs an error but does not prevent the file from being opened with a non-rooted path. This is a defense-in-depth gap.

**Remediation:**

Convert the check from advisory to enforcing by returning early or throwing when a non-rooted path is detected.

---

#### FINDING-009: No upper bound validation on BufferSize allows excessive memory allocation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | src/log4net/Appender/BufferingAppenderSkeleton.cs |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | FINDING-002, FINDING-010, FINDING-011, FINDING-012, FINDING-018 |

**Description:**

DOWNGRADED from Medium. No upper bound check on BufferSize property allows excessive memory allocation via configuration. Since configuration is the project's documented trust boundary, exploitation requires a privileged actor modifying config, reducing practical severity.

**Remediation:**

Add an optional upper bound check or emit a warning in ActivateOptions() when BufferSize exceeds a reasonable threshold (e.g., 10,000).

---

#### FINDING-010: Negative MaxSizeRollBackups allows unbounded disk space consumption

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | src/log4net/Appender/RollingFileAppender.cs |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | FINDING-002, FINDING-009, FINDING-011, FINDING-012, FINDING-018 |

**Description:**

DOWNGRADED from Medium. MaxSizeRollBackups=-1 allows infinite backup files and potential disk exhaustion. Since configuration is the project's documented trust boundary, this is an intentional feature for unlimited rolling. Severity reduced as exploitation requires configuration access.

**Remediation:**

Emit a warning via ErrorHandler during ActivateOptions() when MaxSizeRollBackups < 0, explaining the disk exhaustion risk. Consider documenting recommended limits.

---

#### FINDING-011: No individual log message size limit in buffering path

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | src/log4net/Appender/BufferingAppenderSkeleton.cs |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | FINDING-002, FINDING-009, FINDING-010, FINDING-012, FINDING-018 |

**Description:**

No size check on individual LoggingEvent objects before buffering. If an application logs user-controlled input, memory pressure grows proportional to message size × buffer capacity.

**Remediation:**

Provide an optional MaxEventSize property. Applications should truncate messages before logging.

---

#### FINDING-012: MaxFileSize accepts unrestricted long values including effectively unlimited sizes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 5.2.1 |
| **Files** | src/log4net/Appender/RollingFileAppender.cs |
| **Source Reports** | 5.2.1.md |
| **Related Findings** | FINDING-002, FINDING-009, FINDING-010, FINDING-011, FINDING-018 |

**Description:**

MaxFileSize can be set to effectively unlimited values, disabling size-based rolling and allowing single log files to grow until disk is full.

**Remediation:**

Document recommended MaxFileSize limits and consider emitting a warning for extremely large values.

---

#### FINDING-013: Security Context Framework Lacks Formal Authorization Policy Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 8.1.1 |
| **Files** | src/log4net/Core/SecurityContextProvider.cs, src/log4net/Util/WindowsSecurityContext.cs |
| **Source Reports** | 8.1.1.md |
| **Related Findings** | |

**Description:**

The SecurityContext framework provides XML doc comments describing behavior but lacks formal authorization documentation that defines: which components are authorized to set SecurityContextProvider.DefaultProvider, what criteria determine when impersonation should be granted vs. denied, rules for which appenders may use elevated security contexts vs. NullSecurityContext, and what permissions a consumer must hold to invoke SecurityContext.Impersonate().

**Remediation:**

Add formal security documentation (e.g., a SECURITY.md or doc comments) that specifies: the principle of least privilege for SecurityContext assignment, that only trusted configuration sources should be able to set the DefaultProvider, and that WindowsSecurityContext credentials should use least-privilege service accounts.

---

#### FINDING-014: `SecurityContextProvider.DefaultProvider` Setter Has No Permission Check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 8.2.1 |
| **Files** | src/log4net/Core/SecurityContextProvider.cs |
| **Source Reports** | 8.2.1.md |
| **Related Findings** | |

**Description:**

Any code in the application process can replace the global DefaultProvider, potentially installing a provider that grants elevated privileges to all appenders. However, this is within the same process trust boundary, and log4net is a library designed to be configured by its host application. An attacker who can execute arbitrary code within the process could install a custom SecurityContextProvider that always returns an elevated security context, but such an attacker already has code execution within the process, making this a post-compromise concern rather than a privilege escalation vector.

**Remediation:**

Consider adding a thread-safety mechanism and/or a seal-once pattern that allows the provider to be set once during initialization and then sealed against further modification.

---

#### FINDING-015: Missing formal documentation of input validation rules for pattern string format

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | src/log4net/Util/PatternString.cs, src/log4net/Util/PatternParser.cs |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: Configuration inputs come from trusted administrators per the project's threat model, reducing the security impact of missing formal validation documentation. Original: The pattern string format has implicit validation rules embedded in parsing logic but no formal documentation defining maximum acceptable values, allowed characters, maximum length, or complexity limits.

**Remediation:**

Create formal documentation defining the pattern string grammar with explicit bounds for min_width, max_width, name, and option fields.

---

#### FINDING-016: Missing documented validation rules for file size string format

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | src/log4net/Util/OptionConverter.cs |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: Configuration inputs come from trusted administrators per the project's threat model, reducing the security impact of missing formal validation documentation. Original: The ToFileSize method accepts a file size string but has no documented validation ruleset specifying valid numeric ranges, overflow behavior, or whitespace rules.

**Remediation:**

Document expected ranges, e.g., 'Value must be between 0 and [max_file_size]. Values resulting in overflow return defaultValue.'

---

#### FINDING-017: Missing documented validation rules for variable substitution format

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | src/log4net/Util/OptionConverter.cs |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | |

**Description:**

The ${key} substitution format has one documented rule (balanced braces) but lacks formal documentation of maximum key length, allowed key characters, nested substitution support, and maximum expansion depth/size.

**Remediation:**

Document the substitution format constraints including maximum key length, allowed characters, and expansion limits.

---

#### FINDING-018: Pattern option strings extracted without length or content validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-770 |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | src/log4net/Util/PatternParser.cs |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | FINDING-002, FINDING-009, FINDING-010, FINDING-011, FINDING-012 |

**Description:**

DOWNGRADED from Medium: Configuration inputs come from trusted administrators per the project's threat model. The option string within pattern {braces} is passed to converters without length or content validation. While the practical impact is limited in the trusted configuration context, adding a length cap would provide defense-in-depth.

**Remediation:**

Add a maximum length constraint (e.g., 256 characters) for option strings extracted during pattern parsing.

---

#### FINDING-019: PatternString.ConversionPattern property accepts input without validation before parsing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 2.2.2 |
| **Files** | src/log4net/Util/PatternString.cs |
| **Source Reports** | 2.2.2.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: Configuration inputs come from trusted administrators per the project's threat model, significantly reducing exploitation likelihood. The ConversionPattern property accepts any string without pre-validation (no length check, no structural validation) before passing to the parser. Adding a length cap would provide defense-in-depth.

**Remediation:**

Add a maximum length validation (e.g., 4096 characters) in ActivateOptions before parsing.

---

#### FINDING-020: GetObjectData Serializes All Fields Without Field-Level Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | src/log4net/Core/LoggingEvent.cs |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: The FixFlags mechanism is an intentional design control that limits what data is captured into the event. The report itself lists FixFlags and lazy field population as positive security patterns. Serializing all *captured* fields is consistent with this design - the control point is at capture time, not serialization time. StreamingContext is unused but serialization is already framework-version-gated (disabled on modern .NET).

**Remediation:**

Consider adding a configurable field filter mechanism (e.g., SerializableFields flags) to control which fields are included in GetObjectData output, particularly for cross-boundary serialization scenarios.

---

#### FINDING-021: GetLoggingEventData Returns Complete Data Structure Without Field Selection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | src/log4net/Core/LoggingEvent.cs |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: The FixFlags parameter intentionally controls which fields are populated from the environment. Returning the struct with only populated fields (others remain null/default) is by design. The FixFlags.Partial default already avoids capturing all sensitive data unnecessarily, as noted in the report's positive patterns.

**Remediation:**

Provide a field-selective overload for GetLoggingEventData that allows callers to specify which fields they need returned.

---

#### FINDING-022: No Documented Risk-Based Remediation Time Frames for Third-Party Components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 15.1.1 |
| **Files** | src/log4net/LogManager.cs, src/log4net/Repository/ILoggerRepository.cs |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: Project maintains a VDR (https://logging.apache.org/cyclonedx/vdr.xml) demonstrating active vulnerability management. Finding is about absence of explicit SLA timeframes in source code, which is a documentation gap rather than a code-level vulnerability.

**Remediation:**

Add a SECURITY.md or equivalent policy document to the project that defines severity-based remediation time frames, supported version policy, and plugin/extension security guidance.

---

#### FINDING-023: No Mechanism to Communicate Component Risk Classification to Consumers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 15.1.1 |
| **Files** | src/log4net/Repository/ILoggerRepository.cs |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | |

**Description:**

The ILoggerRepository interface exposes PluginMap and GetAppenders() for managing extensible components, but provides no metadata, attributes, or documentation identifying which components constitute dangerous functionality or risky components as defined by ASVS 15.1.

**Remediation:**

Consider adding XML documentation or a risk classification attribute to appender base classes indicating their security profile.

---

#### FINDING-024: No Runtime or Design-Time Mechanism for Component Version Tracking or Staleness Detection

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 15.2.1 |
| **Files** | src/log4net/LogManager.cs, src/log4net/Repository/ILoggerRepository.cs |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | |

**Description:**

DOWNGRADED from Medium: This is a feature request for dependency-scanning capabilities within a logging library. The project maintains a VDR for its own vulnerability tracking. Expecting a logging framework to implement runtime staleness detection for loaded plugins exceeds typical library responsibility.

**Remediation:**

Consider adding optional version metadata and health-check capabilities such as a ComponentVersionInfo accessor.

---

#### FINDING-025: No Architectural Isolation Mechanism for Risky Components

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | |
| **ASVS Section(s)** | 15.2.1 |
| **Files** | src/log4net/Repository/ILoggerRepository.cs |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | |

**Description:**

The ILoggerRepository interface provides no isolation boundaries between plugins loaded via PluginMap and the host application. All plugins run in the same trust domain. This is an acknowledged architectural limitation of .NET in-process libraries.

**Remediation:**

Document recommended deployment patterns for high-risk appenders (e.g., running network appenders in a separate process/container).

---

# 4. Positive Security Controls

| Domain | Control | Evidence Source | Supporting Files |
|--------|---------|-----------------|------------------|
| Configuration Loading | No OS command execution anywhere in the codebase; functionality achieved without shell commands or process execution, eliminating this attack vector by design. | Report positive pattern | — |
| Network Appenders | TLS version selection is intentionally delegated to the .NET runtime/deployment infrastructure | source: Dropped finding ASVS-1211-LOW-001 | — |
| Input Validation | Deserialization trust boundary is a deployment concern; the library assumes serialized streams come from trusted remoting sources | Dropped finding ASVS-221-LOW-001 | — |
| Input Validation | Variable substitution dictionaries are sourced from within the trust boundary (system properties, configuration) | Dropped finding ASVS-222-LOW-001 | — |
| Serialization | FixFlags mechanism controls data capture at source | FixFlags parameter in GetLoggingEventData and lazy field population limits captured data before serialization | src/log4net/Core/LoggingEvent.cs |
| Serialization | FixFlags.Partial default prevents excessive data capture | Default configuration avoids capturing all sensitive environmental data unnecessarily | src/log4net/Core/LoggingEvent.cs |
| Thread Context | Library provides explicit Clear() and Remove() methods for thread context properties; scoped cleanup responsibility is intentionally delegated to consuming applications | Promoted from dropped finding ASVS-1431-LOW-001 | — |
| Component Security | Active vulnerability management with VDR | Project maintains a VDR at https://logging.apache.org/cyclonedx/vdr.xml demonstrating active vulnerability management | — |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **Pass** | |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **N/A** | |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** | |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **Fail** | See  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** | |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** | |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Partial** | See FINDING-004, FINDING-005 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **Pass** | See FINDING-006 |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-015, FINDING-016, FINDING-017 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-002, FINDING-003, FINDING-018 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Partial** | See FINDING-019 |
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
| 4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". | **N/A** | |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. | **N/A** | |
| **V5: File Handling** | | | |
| 5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. | **Partial** | See FINDING-009, FINDING-010, FINDING-011, FINDING-012 |
| 5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. | **N/A** | |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. | **N/A** | |
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Partial** | See FINDING-007, FINDING-008 |
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
| 8.1.1 | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. | **Partial** | See FINDING-013 |
| 8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. | **Partial** | See FINDING-014 |
| 8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). | **N/A** | |
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
| 11.3.1 | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. | **N/A** | |
| 11.3.2 | Verify that only approved ciphers and modes such as AES with GCM are used. | **N/A** | |
| 11.4.1 | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. | **N/A** | |
| **V12: Secure Communication** | | | |
| 12.1.1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the TLS protocol must be the preferred option. | **N/A** | |
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **N/A** | |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** | |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **N/A** | |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **N/A** | |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** | |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Fail** | See FINDING-022, FINDING-023 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Fail** | See FINDING-024, FINDING-025 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Partial** | See FINDING-020, FINDING-021 |

**Summary Statistics:**
- **Pass**: 3 requirements (4.3%)
- **Partial**: 9 requirements (12.9%)
- **N/A**: 55 requirements (78.6%)
- **Fail**: 3 requirements (4.3%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-002 | Medium | 2.2.1 | FINDING-009, FINDING-010, FINDING-011, FINDING-012, FINDING-018 | src/log4net/Util/PatternParser.cs |
| FINDING-003 | Medium | 2.2.1 | — | src/log4net/Util/OptionConverter.cs |
| FINDING-004 | Low | 1.3.2 | FINDING-005 | src/log4net/Repository/Hierarchy/XmlHierarchyConfigurator.cs, src/log4net/Util/OptionConverter.cs |
| FINDING-005 | Low | 1.3.2 | FINDING-004 | src/log4net/Util/OptionConverter.cs |
| FINDING-006 | Low | 1.5.1 | — | src/log4net/Config/XmlConfigurator.cs |
| FINDING-007 | Low | 5.3.2 | FINDING-008 | src/log4net/Appender/FileAppender.cs |
| FINDING-008 | Low | 5.3.2 | FINDING-007 | src/log4net/Appender/FileAppender.cs |
| FINDING-009 | Low | 5.2.1 | FINDING-002, FINDING-010, FINDING-011, FINDING-012, FINDING-018 | src/log4net/Appender/BufferingAppenderSkeleton.cs |
| FINDING-010 | Low | 5.2.1 | FINDING-002, FINDING-009, FINDING-011, FINDING-012, FINDING-018 | src/log4net/Appender/RollingFileAppender.cs |
| FINDING-011 | Low | 5.2.1 | FINDING-002, FINDING-009, FINDING-010, FINDING-012, FINDING-018 | src/log4net/Appender/BufferingAppenderSkeleton.cs |
| FINDING-012 | Low | 5.2.1 | FINDING-002, FINDING-009, FINDING-010, FINDING-011, FINDING-018 | src/log4net/Appender/RollingFileAppender.cs |
| FINDING-013 | Low | 8.1.1 | — | src/log4net/Core/SecurityContextProvider.cs, src/log4net/Util/WindowsSecurityContext.cs |
| FINDING-014 | Low | 8.2.1 | — | src/log4net/Core/SecurityContextProvider.cs |
| FINDING-015 | Low | 2.1.1 | — | src/log4net/Util/PatternString.cs, src/log4net/Util/PatternParser.cs |
| FINDING-016 | Low | 2.1.1 | — | src/log4net/Util/OptionConverter.cs |
| FINDING-017 | Low | 2.1.1 | — | src/log4net/Util/OptionConverter.cs |
| FINDING-018 | Low | 2.2.1 | FINDING-002, FINDING-009, FINDING-010, FINDING-011, FINDING-012 | src/log4net/Util/PatternParser.cs |
| FINDING-019 | Low | 2.2.2 | — | src/log4net/Util/PatternString.cs |
| FINDING-020 | Low | 15.3.1 | — | src/log4net/Core/LoggingEvent.cs |
| FINDING-021 | Low | 15.3.1 | — | src/log4net/Core/LoggingEvent.cs |
| FINDING-022 | Low | 15.1.1 | — | src/log4net/LogManager.cs, src/log4net/Repository/ILoggerRepository.cs |
| FINDING-023 | Low | 15.1.1 | — | src/log4net/Repository/ILoggerRepository.cs |
| FINDING-024 | Low | 15.2.1 | — | src/log4net/LogManager.cs, src/log4net/Repository/ILoggerRepository.cs |
| FINDING-025 | Low | 15.2.1 | — | src/log4net/Repository/ILoggerRepository.cs |

**Total Unique Findings**: 25 (1 Critical, 0 High, 2 Medium, 22 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 25 |

**Total consolidated findings: 25**

*End of Consolidated Security Audit Report*