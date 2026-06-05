# Security Audit Consolidated Report — apache/mahout

## Report Metadata

| Field | Value |
|-------|-------|
| Repository | apache/mahout |
| ASVS Level | L1 |
| Severity Threshold | none (all findings included) |
| Commit | 38916d3 |
| Date | Jun 05, 2026 |
| Auditor | Tooling Agents |
| Source Reports | 70 |
| Total Findings | 14 |

## Executive Summary

### Severity Distribution

| Severity | Count |
|----------|-------|
| Critical | 0     |
| High     | 0     |
| Medium   | 5     |
| Low      | 9     |
| Info     | 0     |

### ASVS Level Coverage

This audit was conducted against ASVS Level 1 (L1) verification requirements across the in-scope directories, covering general security, dependency management, cloud backend and storage integration, GPU/quantum kernel execution, and data-format input handling. All findings identified fall within the L1 scope and reflect baseline security expectations for the assessed components.

### Top 5 Risks

1. **Cloud storage client does not enforce HTTPS** [Medium] — The `AWS_ALLOW_HTTP` environment variable permits a plaintext transport downgrade, exposing cloud traffic to interception (ASVS 12.2.1).
2. **Parameter values not validated as numeric before binding** [Medium] — Values are bound without numeric validation, risking malformed or unexpected input propagation (ASVS 2.3.1).
3. **num_qubits not bounds-checked at encoding entry point** [Medium] — Unvalidated `num_qubits` drives `1 << num_qubits` and CUDA grid-dimension computation, risking overflow or invalid kernel dimensions (ASVS 1.3.2).
4. **int gridSize truncation in single-shot launch functions** [Medium] — The truncation pattern lacks a defensive upper-bound check, allowing potentially invalid launch dimensions (ASVS 1.3.2).
5. **state_len <= 2^30 invariant undocumented in C launch contracts** [Medium] — The required invariant is not documented in the C launch function contracts, increasing the risk of unsafe usage (ASVS 1.3.2).

### Positive Controls Observed

- None observed.

---

## 3. Findings

### 3.3 Medium

#### FINDING-001: Cloud storage client does not enforce HTTPS; AWS_ALLOW_HTTP env var permits plaintext transport downgrade

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-319 |
| **ASVS Section(s)** | 12.2.1 |
| **File(s)** | qdp/qdp-core/src/remote.rs |
| **Source Report(s)** | 12.2.1.md |
| **Related** | None |

**Description:**

In `build_store`, both `AmazonS3Builder::from_env()` and `GoogleCloudStorageBuilder::from_env()` are constructed without disabling plaintext HTTP. `from_env()` honors `AWS_ALLOW_HTTP`; when set truthy (as in the project's own MinIO test docs), requests — including SigV4-signed Authorization headers and downloaded payloads — transit over cleartext HTTP. There is no `.with_allow_http(false)` call nor any assertion that the resolved endpoint is `https://`. Default (env unset) negotiates HTTPS, so reaching the insecure state requires an explicit, unusual configuration; severity is bounded to Medium.

**Remediation:**

Explicitly forbid plaintext transport in production builds by calling `.with_allow_http(false)` on both builders, gating any plaintext-HTTP allowance behind a dedicated non-default cargo feature (e.g., `insecure-http-testing`). Additionally validate that any configured `AWS_ENDPOINT` begins with `https://` before building the store, and confirm the insecure-HTTP testing feature can never leak into release/production binaries.

---

#### FINDING-002: Parameter values are not validated as numeric before binding

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | None |
| **ASVS Section(s)** | 2.3.1 |
| **File(s)** | qumat/qumat.py |
| **Source Report(s)** | 2.3.1.md |
| **Related** | None |

**Description:**

The `bind_parameters()` method validates that parameter names exist in the circuit but never validates that the provided values are numeric. This allows non-numeric values (strings, lists, objects) to be bound as parameter values and forwarded to backend execution layers. In Cirq, the string `"x**2"` flows into `ParamResolver`, where it may be interpreted symbolically rather than rejected. In Qiskit/Braket, this produces an opaque downstream error rather than a clear validation error at the API boundary. A required step (parameter binding) completes with semantically invalid data, defeating the intent of sequential-flow input validation. In the trusted-local-caller model, the impact is limited to incorrect computation results, inconsistent cross-backend error behavior, and unclear error messages.

**Remediation:**

Add numeric type validation in `bind_parameters()`: check `isinstance(value, numbers.Real)` and reject booleans, raising a `TypeError` with a clear message; centralizing this validation ensures consistent enforcement across all three backends (Qiskit, Cirq, Braket).

---

#### FINDING-003: num_qubits is not bounds-checked at the encoding entry point before driving 1 << num_qubits and CUDA grid-dimension computation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-190 |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | qdp/qdp-core/src/encoding/mod.rs |
| **Source Report(s)** | 1.3.2.md |
| **Related** | FINDING-007 |

**Description:**

The codebase has a documented design limit of 30 qubits to prevent exponential memory exhaustion (2^30 complex128 values ≈ 16 GB). However, the stream_encode function—the core dispatcher for Parquet-based encoding—does not enforce this limit on the num_qubits parameter before using it to compute state_len = 1 << num_qubits. Data flow: Source: num_qubits: usize parameter (trusted caller, but no enforcement of documented invariant). Sinks: let state_len = 1 << num_qubits (for num_qubits >= 64: shift overflow, panic in debug, wraparound in release); GpuStateVector::new_batch attempts allocation of 2^num_qubits complex128 values; C launch functions compute int gridSize = (state_len + blockSize - 1) / blockSize, which truncates size_t to int; unbounded state_len → negative/zero/garbage grid size. Impact: Denial of Service from memory exhaustion; Undefined Behavior from invalid CUDA launch geometry from int truncation; Panic across FFI boundary for num_qubits >= 64 in debug builds.

**Remediation:**

Enforce the documented limit before any use of num_qubits: const MAX_QUBITS: usize = 30; validate num_qubits == 0 || num_qubits > MAX_QUBITS and return error; use checked_shl to catch implementation errors. Ideally validate centrally in encode_from_parquet (and any sibling entry points) so the invariant cannot be bypassed.

---

#### FINDING-004: int gridSize truncation pattern in single-shot launch functions lacks defensive upper-bound check

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-681 |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | qdp/qdp-kernels/src/amplitude.cu, qdp/qdp-kernels/src/angle.cu, qdp/qdp-kernels/src/basis.cu |
| **Source Report(s)** | 1.3.2.md |
| **Related** | None |

**Description:**

The single-shot launch functions compute CUDA grid dimensions by dividing state_len (a size_t) by blockSize and casting the result to int. While the batch launch functions clamp the computed grid size to device limits before truncation, the single-shot functions rely entirely on the Rust caller to ensure state_len <= 2^30 (the documented limit). Data flow: Source: state_len parameter (should be 1 << num_qubits with num_qubits <= 30); Truncation point: (state_len + blockSize - 1) / blockSize computed in size_t then implicitly cast to int; Risk: if state_len > INT_MAX * blockSize (≈ 2^39 for blockSize=256), gridSize wraps to negative/zero/garbage. Impact: Invalid CUDA launch geometry if upstream validation fails; Inconsistency with batch paths, which defensively clamp grid size.

**Remediation:**

Add a defensive upper-bound check matching the batch-path pattern: compute blocks_needed, clamp to get_max_grid_dim_1d()/MAX_GRID_BLOCKS before int cast, and return on overflow. Alternatively document the state_len <= 2^30 contract explicitly and rely on ENCODING-1's fix; defense-in-depth suggests the kernel layer should fail safe even if the Rust layer has a bug.

---

#### FINDING-005: state_len <= 2^30 invariant not documented in C launch function contracts

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-1059 |
| **ASVS Section(s)** | 1.3.2 |
| **File(s)** | qdp/qdp-kernels/src/*.cu |
| **Source Report(s)** | 1.3.2.md |
| **Related** | None |

**Description:**

The C launch functions assume state_len <= 2^30 (to fit in int gridSize after division by 256), but this precondition is not documented in comments. This increases the risk that future Rust callers will violate the invariant.

**Remediation:**

Add contract documentation to all launch_*_encode functions stating preconditions: state_len must be <= 2^30 (enforced by Rust MAX_QUBITS=30), state_len must be a power of 2, inv_norm must be finite and positive (amplitude encoding only).

### 3.4 Low

#### FINDING-006: Input Validation Documentation Incomplete and Inconsistent

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.1.1 |
| **File(s)** | qdp/qdp-core/src/preprocessing.rs, qdp/qdp-core/src/gpu/encodings.rs |
| **Source Report(s)** | 2.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The single most important business-logic limit — the maximum qubit count and its derived constraint `sample_size <= 2^num_qubits` — is referenced but the authoritative definition (`validate_qubit_count`, `MAX_QUBITS`) lives outside the audited files, and the doc-comments are internally inconsistent: the comment in `validate_input` says "max MAX_QUBITS = 16GB GPU memory" while the domain context and false-positive list cite 30 qubits / 8GB. There is no single documented specification stating the validation rules (allowed rank, dtype, dimension limits, qubit ceiling) that every reader path must satisfy. This is a documentation deficiency, not an exploitable defect.

**Remediation:**

Add a module-level doc block (e.g., in `reader.rs`) that enumerates the canonical input-validation contract every `DataReader` implementation must uphold (allowed dtype = f64, rank 1D/2D, dimensions > 0, single-column for columnar formats, sample-size consistency) and the downstream business limits (`1 <= num_qubits <= 30`, `sample_size <= 2^num_qubits`), and reconcile the "16GB"/"8GB" comments with the actual `MAX_QUBITS` value.

---

#### FINDING-007: Unchecked Multiplication in ParquetReader::read_batch Capacity Computation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-190 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | qdp/qdp-core/src/readers/parquet.rs |
| **Source Report(s)** | 2.2.1.md |
| **Related Finding(s)** | FINDING-003 |

**Description:**

ParquetReader::read_batch computes the pre-allocation size with an *unchecked* multiplication, whereas the sibling ArrowIPCReader::read_batch and TensorFlowReader::new consistently use checked_mul with an InvalidInput error on overflow. A Parquet file with a large declared list length and total_rows can drive this product to overflow: in debug builds this panics; in release builds it wraps to an undersized reserve (functionally harmless but inconsistent). This is a Type B gap — the overflow control exists in the codebase but is not applied at this entry point.

**Remediation:**

Use checked_mul for the capacity computation and return MahoutError::InvalidInput on overflow; apply the same to the FixedSizeList branch using batch.num_rows().

---

#### FINDING-008: Inconsistent Single-Column Schema Enforcement in ArrowIPCReader

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.1 |
| **File(s)** | qdp/qdp-core/src/readers/arrow_ipc.rs |
| **Source Report(s)** | 2.2.1.md |
| **Related Finding(s)** | FINDING-009 |

**Description:**

ParquetReader::new enforces a strict allow-list of *exactly one column* (schema.fields().len() != 1), but ArrowIPCReader only rejects zero-column batches and silently uses column(0), ignoring any additional columns. The structural validation is therefore inconsistent across reader paths for what should be the same logical contract ("one Float64 list column per sample"). Multi-column Arrow files are accepted with extra columns silently dropped rather than rejected.

**Remediation:**

Mirror the Parquet check before reading: validate batch.schema().fields().len() == 1 (or the file schema) and return MahoutError::InvalidInput otherwise.

---

#### FINDING-009: Business-Limit Validation Not Enforced at Uniform Reader Choke Point

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-20 |
| **ASVS Section(s)** | 2.2.2 |
| **File(s)** | qdp/qdp-core/src/readers/*, qdp/qdp-core/src/preprocessing.rs |
| **Source Report(s)** | 2.2.2.md |
| **Related Finding(s)** | FINDING-008 |

**Description:**

Each reader independently validates structural rules (dtype/rank/dims/consistency) but none enforces the *business* limits (`1 <= num_qubits <= 30`, `sample_size <= 2^num_qubits`); those are enforced only when `Preprocessor::validate_batch`/`validate_input` is invoked downstream. Because the qubit ceiling is the resource-exhaustion guard and it is enforced at a *different* layer than the reader, the safety of every reader path depends on every encoding entry point routing reader output through the preprocessing validators. The encoding dispatch glue is not present in the audited files, so a confirmed bypass cannot be demonstrated here; this is flagged as a defense-in-depth/architecture concern (Type B candidate) rather than a proven gap. The structural-validation inconsistency between readers (see ASVS-221-LOW-002 / LOW-001) means the trusted layer's guarantees are not uniform across formats.

**Remediation:**

Centralize the business-limit checks so they are unconditionally applied to *every* reader output before GPU dispatch — e.g., have the encoder constructor call `Preprocessor::validate_batch(...)` on `(num_samples, sample_size, num_qubits)` regardless of source format, and add an integration test that drives each reader (Parquet, Arrow, NumPy, TF, PyTorch) through the same validation choke point with an over-limit `sample_size` to prove no path bypasses it.

---

#### FINDING-010: Rotation-gate angle is not validated as numeric when supplied as a literal

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

Rotation gate methods (`apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`) and the universal gate (`apply_u_gate`) accept angle parameters that can be either symbolic (string parameter names) or literal numeric values. The `_handle_parameter` method branches on string vs non-string types but never validates that non-string literals are actually numeric. The `apply_u_gate` method passes `theta`, `phi`, and `lambda` arguments directly to the backend with no validation. Invalid step input is accepted at the API boundary and only fails (opaquely) later in the backend. Given the trusted-local-caller threat model, the impact is limited to poor developer experience, inconsistent error behavior across backends, and potential debugging confusion.

**Remediation:**

Add numeric validation to literal angle arguments via a `_validate_numeric_parameter` helper that allows strings (parameter names) and real numbers but rejects other types/booleans; apply to `apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`, and all three angle parameters (`theta`, `phi`, `lambda`) in `apply_u_gate`.

---

#### FINDING-011: Path traversal possible if untrusted filenames are forwarded to readers/writers

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **File(s)** | qdp/qdp-core/src/io.rs, qdp/qdp-core/src/readers/torch.rs |
| **Source Report(s)** | 5.3.2.md |
| **Related Finding(s)** | None |

**Description:**

Readers/writers perform file operations on caller-supplied paths via the type-safe AsRef&lt;Path&gt; API with no string concatenation, joining of untrusted segments, or URL fetching (no SSRF surface). Trust is delegated to the caller. If an embedder forwards untrusted filenames, no canonicalization/base-directory containment is enforced. An optional resolve_within(base, user_path) helper is recommended for embedders that must accept untrusted filenames.

**Remediation:**

Document the trusted-caller path contract at each public reader/writer new() and at the io.rs wrapper functions; provide an optional resolve_within(base, user_path) helper that canonicalizes and contains paths within a base directory and rejects symlinks for embedders accepting untrusted filenames.

---

#### FINDING-012: Risk-Based Remediation Time Frame Documentation Missing

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **File(s)** | qdp/qdp-core/Cargo.toml, qdp/qdp-python/Cargo.toml, website/package.json |
| **Source Report(s)** | 15.1.1.md |
| **Related Finding(s)** | None |

**Description:**

The project declares numerous 3rd party components — including native, cross-language-boundary dependencies explicitly flagged as higher-risk in the domain context (`cudarc`, `pyo3 = "0.27"`, `tch`, `arrow`, `parquet`, `prost`) and the Node.js documentation stack (`@docusaurus/* 3.10.1`) — but no documentation defining risk-based remediation time frames accompanies these manifests. There is no stated policy for: How quickly a known-vulnerable component must be patched (e.g., Critical CVE within N days); A general cadence for updating libraries regardless of known CVEs; A differentiated time frame for native/FFI dependencies (CUDA, PyO3, tch) versus the development-only Node.js stack.

**Remediation:**

Add a dependency-management policy to project documentation (e.g., `SECURITY.md` or `docs/dependency-policy.md`) that specifies risk-based remediation windows with stricter windows for native/FFI components, a general library refresh cadence, EOL replacement triggers, and a CI gate (`cargo audit` / `npm audit`) that fails the build on findings exceeding the windows.

---

#### FINDING-013: Component Version Compliance Unverifiable Due to Missing Lockfiles and Documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **File(s)** | qdp/qdp-core/Cargo.toml |
| **Source Report(s)** | 15.2.1.md |
| **Related Finding(s)** | None |

**Description:**

The most exploit-prone dependencies — those crossing the native/FFI boundary as called out in the domain context (`cudarc`, `tch`, `prost`/`prost-build` deserialization, `parquet`/`arrow` binary parsing) — defer their version entirely to the workspace (`{ workspace = true }`). Because the workspace manifest and lockfile are not present, there is no way within the audited artifacts to confirm these components are within any support/remediation window. Without 15.1.1's documented time frame and without a committed lockfile in scope, 15.2.1 compliance is unverifiable for the highest-risk components. This is a verification/traceability gap rather than a proven outdated-component.

**Remediation:**

Commit `Cargo.lock` and `package-lock.json` and audit them in CI. Add `cargo audit` (RustSec advisory DB) and `npm audit` as required CI gates so 15.2.1 is enforced mechanically against the 15.1.1 time frames. Record the pinned native-dependency versions in the dependency policy and review against RustSec/NVD on the documented cadence.

---

#### FINDING-014: transformLinks() lacks negative protocol screening (javascript:, data:) for markdown link targets

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 1.2.2 |
| **File(s)** | website/scripts/sync-docs.js |
| **Source Report(s)** | 1.2.2.md |
| **Related Finding(s)** | None |

**Description:**

Data flow: source = markdown link targets in /docs (version control) → sink = rewritten markdown passed to Docusaurus → missing control = no allow-list of safe protocols (javascript:, data: are neither blocked nor distinguished from relative links). Attacker capability required: Commit access to the version-controlled /docs tree (privileged/trusted contributor). A purely remote unauthenticated attacker cannot reach this code path. Impact on success: A malicious link such as [click](javascript:alert(1)) would pass through unchanged; whether it becomes executable depends entirely on the downstream Docusaurus/React link renderer, which sanitizes URL protocols by default. No direct C/I/A impact in the default configuration. Why LOW (not higher): The input is trusted version-controlled content (explicit false-positive pattern), exploitation requires a malicious commit passing review, and the downstream renderer (React/Docusaurus) is the actual control that neutralizes dangerous protocols. This is a defense-in-depth gap, not an exploitable path.

**Remediation:**

If the function is intended to vet links, add explicit protocol screening: const SAFE_RELATIVE = url => !/^[a-z][a-z0-9+.-]*:/i.test(url) || /^https?:/i.test(url); if (!SAFE_RELATIVE(url)) { console.warn(`Skipping unsafe link protocol: ${url}`); return `[${text}](#)`; }

---

# 4. Positive Security Controls

*No positive controls recorded for this audit.*

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Notes |
|---------|-------------------|--------|-------|
| **V1: Encoding and Sanitization** | | | |
| 1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. | **N/A** |  |
| 1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). | **Partial** | See FINDING-014 |
| 1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). | **N/A** |  |
| 1.2.4 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. | **N/A** |  |
| 1.2.5 | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. | **N/A** |  |
| 1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. | **N/A** |  |
| 1.3.2 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. | **Fail** | See FINDING-003, FINDING-004, FINDING-005 |
| 1.5.1 | Verify that the application configures XML parsers to use a restrictive configuration and that unsafe features such as resolving external entities are disabled to prevent XML eXternal Entity (XXE) attacks. | **N/A** |  |
| **V2: Validation and Business Logic** | | | |
| 2.1.1 | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. | **Partial** | See FINDING-006 |
| 2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. | **Partial** | See FINDING-007, FINDING-008 |
| 2.2.2 | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. | **Partial** | See FINDING-009 |
| 2.3.1 | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. | **Partial** | See FINDING-002, FINDING-010 |
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
| 5.3.2 | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. | **Partial** | See FINDING-011 |
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
| 12.2.1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. | **Fail** | See FINDING-001 |
| 12.2.2 | Verify that external facing services use publicly trusted TLS certificates. | **N/A** |  |
| **V13: Configuration** | | | |
| 13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. | **Pass** |  |
| **V14: Data Protection** | | | |
| 14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. | **Pass** |  |
| 14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. | **N/A** |  |
| **V15: Secure Coding and Architecture** | | | |
| 15.1.1 | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. | **Fail** | See FINDING-012 |
| 15.2.1 | Verify that the application only contains components which have not breached the documented update and remediation time frames. | **Fail** | See FINDING-013 |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. | **Pass** |  |

**Summary Statistics:**
- **Pass**: 3 requirements (4.3%)
- **Partial**: 6 requirements (8.6%)
- **N/A**: 57 requirements (81.4%)
- **Fail**: 4 requirements (5.7%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |
|------------|----------|-------------------|------------------|---------------------|
| FINDING-001 | Medium | 12.2.1 | — | qdp/qdp-core/src/remote.rs |
| FINDING-002 | Medium | 2.3.1 | — | qumat/qumat.py |
| FINDING-003 | Medium | 1.3.2 | FINDING-007 | qdp/qdp-core/src/encoding/mod.rs |
| FINDING-004 | Medium | 1.3.2 | — | qdp/qdp-kernels/src/amplitude.cu, qdp/qdp-kernels/src/angle.cu, qdp/qdp-kernels/src/basis.cu |
| FINDING-005 | Medium | 1.3.2 | — | qdp/qdp-kernels/src/*.cu |
| FINDING-006 | Low | 2.1.1 | — | qdp/qdp-core/src/preprocessing.rs, qdp/qdp-core/src/gpu/encodings.rs |
| FINDING-007 | Low | 2.2.1 | FINDING-003 | qdp/qdp-core/src/readers/parquet.rs |
| FINDING-008 | Low | 2.2.1 | FINDING-009 | qdp/qdp-core/src/readers/arrow_ipc.rs |
| FINDING-009 | Low | 2.2.2 | FINDING-008 | qdp/qdp-core/src/readers/*, qdp/qdp-core/src/preprocessing.rs |
| FINDING-010 | Low | 2.3.1 | — | qumat/qumat.py |
| FINDING-011 | Low | 5.3.2 | — | qdp/qdp-core/src/io.rs, qdp/qdp-core/src/readers/torch.rs |
| FINDING-012 | Low | 15.1.1 | — | qdp/qdp-core/Cargo.toml, qdp/qdp-python/Cargo.toml, website/package.json |
| FINDING-013 | Low | 15.2.1 | — | qdp/qdp-core/Cargo.toml |
| FINDING-014 | Low | 1.2.2 | — | website/scripts/sync-docs.js |

**Total Unique Findings**: 14 (0 Critical, 0 High, 5 Medium, 9 Low, 0 Info)

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 14 |

**Total consolidated findings: 14**

*End of Consolidated Security Audit Report*