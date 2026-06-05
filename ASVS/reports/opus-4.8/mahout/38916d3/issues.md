# Security Issues

---
## Issue: FINDING-001 - Cloud storage client does not enforce HTTPS; AWS_ALLOW_HTTP env var permits plaintext transport downgrade
**Labels:** bug, security, priority:medium
**Description:**
### Summary
In `build_store`, both `AmazonS3Builder::from_env()` and `GoogleCloudStorageBuilder::from_env()` are constructed without disabling plaintext HTTP. `from_env()` honors `AWS_ALLOW_HTTP`; when set truthy (as in the project's own MinIO test docs), requests — including SigV4-signed Authorization headers and downloaded payloads — transit over cleartext HTTP. There is no `.with_allow_http(false)` call nor any assertion that the resolved endpoint is `https://`. Default (env unset) negotiates HTTPS, so reaching the insecure state requires an explicit, unusual configuration; severity is bounded to Medium.

### Details
- **CWE:** CWE-319
- **ASVS:** 12.2.1 (L1)
- **Affected files:** `qdp/qdp-core/src/remote.rs`
- **Related findings:** None

### Remediation
Explicitly forbid plaintext transport in production builds by calling `.with_allow_http(false)` on both builders, gating any plaintext-HTTP allowance behind a dedicated non-default cargo feature (e.g., `insecure-http-testing`). Additionally validate that any configured `AWS_ENDPOINT` begins with `https://` before building the store, and confirm the insecure-HTTP testing feature can never leak into release/production binaries.

### Acceptance Criteria
- [ ] `.with_allow_http(false)` added to S3 and GCS builders in production code
- [ ] Optional `insecure-http-testing` feature gate implemented for test scenarios
- [ ] `AWS_ENDPOINT` protocol validation added (must start with `https://`)
- [ ] Test added verifying production builds reject HTTP endpoints
- [ ] Documentation updated explaining secure defaults and test-only override

### References
- Source report: 12.2.1.md
- Merged from: ASVS-1221-MED-001

### Priority
Medium

---
## Issue: FINDING-002 - Parameter values are not validated as numeric before binding
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `bind_parameters()` method validates that parameter names exist in the circuit but never validates that the provided values are numeric. This allows non-numeric values (strings, lists, objects) to be bound as parameter values and forwarded to backend execution layers. In Cirq, the string `"x**2"` flows into `ParamResolver`, where it may be interpreted symbolically rather than rejected. In Qiskit/Braket, this produces an opaque downstream error rather than a clear validation error at the API boundary. A required step (parameter binding) completes with semantically invalid data, defeating the intent of sequential-flow input validation. In the trusted-local-caller model, the impact is limited to incorrect computation results, inconsistent cross-backend error behavior, and unclear error messages.

### Details
- **CWE:** Not assigned
- **ASVS:** 2.3.1 (L1)
- **Affected files:** `qumat/qumat.py`
- **Related findings:** None

### Remediation
Add numeric type validation in `bind_parameters()`: check `isinstance(value, numbers.Real)` and reject booleans, raising a `TypeError` with a clear message; centralizing this validation ensures consistent enforcement across all three backends (Qiskit, Cirq, Braket).

### Acceptance Criteria
- [ ] Numeric validation added to `bind_parameters()` using `isinstance(value, numbers.Real)`
- [ ] Boolean values explicitly rejected
- [ ] Clear `TypeError` raised with descriptive message for invalid types
- [ ] Test added covering string, list, dict, and boolean rejection
- [ ] Test confirms numeric values (int, float) are accepted
- [ ] Validation applied consistently across Qiskit, Cirq, and Braket backends

### References
- Source report: 2.3.1.md
- Merged from: ASVS-231-MED-001

### Priority
Medium

---
## Issue: FINDING-003 - num_qubits is not bounds-checked at the encoding entry point before driving 1 << num_qubits and CUDA grid-dimension computation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The codebase has a documented design limit of 30 qubits to prevent exponential memory exhaustion (2^30 complex128 values ≈ 16 GB). However, the stream_encode function—the core dispatcher for Parquet-based encoding—does not enforce this limit on the num_qubits parameter before using it to compute state_len = 1 << num_qubits. Data flow: Source: num_qubits: usize parameter (trusted caller, but no enforcement of documented invariant). Sinks: let state_len = 1 << num_qubits (for num_qubits >= 64: shift overflow, panic in debug, wraparound in release); GpuStateVector::new_batch attempts allocation of 2^num_qubits complex128 values; C launch functions compute int gridSize = (state_len + blockSize - 1) / blockSize, which truncates size_t to int; unbounded state_len → negative/zero/garbage grid size. Impact: Denial of Service from memory exhaustion; Undefined Behavior from invalid CUDA launch geometry from int truncation; Panic across FFI boundary for num_qubits >= 64 in debug builds.

### Details
- **CWE:** CWE-190
- **ASVS:** 1.3.2 (L1)
- **Affected files:** `qdp/qdp-core/src/encoding/mod.rs`
- **Related findings:** FINDING-007

### Remediation
Enforce the documented limit before any use of num_qubits: const MAX_QUBITS: usize = 30; validate num_qubits == 0 || num_qubits > MAX_QUBITS and return error; use checked_shl to catch implementation errors. Ideally validate centrally in encode_from_parquet (and any sibling entry points) so the invariant cannot be bypassed.

### Acceptance Criteria
- [ ] `MAX_QUBITS` constant defined (value: 30)
- [ ] Bounds validation added to `stream_encode` entry point
- [ ] Validation returns clear error for `num_qubits == 0` or `num_qubits > MAX_QUBITS`
- [ ] `checked_shl` used for shift operations with overflow handling
- [ ] Test added verifying rejection of num_qubits = 0, 31, 64
- [ ] Test confirms accepted range 1..=30
- [ ] Integration test verifies all encoding entry points enforce limit

### References
- Source report: 1.3.2.md
- Merged from: ASVS-132-MED-001, ENCODING-3, ENCODING-5

### Priority
Medium

---
## Issue: FINDING-004 - int gridSize truncation pattern in single-shot launch functions lacks defensive upper-bound check
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The single-shot launch functions compute CUDA grid dimensions by dividing state_len (a size_t) by blockSize and casting the result to int. While the batch launch functions clamp the computed grid size to device limits before truncation, the single-shot functions rely entirely on the Rust caller to ensure state_len <= 2^30 (the documented limit). Data flow: Source: state_len parameter (should be 1 << num_qubits with num_qubits <= 30); Truncation point: (state_len + blockSize - 1) / blockSize computed in size_t then implicitly cast to int; Risk: if state_len > INT_MAX * blockSize (≈ 2^39 for blockSize=256), gridSize wraps to negative/zero/garbage. Impact: Invalid CUDA launch geometry if upstream validation fails; Inconsistency with batch paths, which defensively clamp grid size.

### Details
- **CWE:** CWE-681
- **ASVS:** 1.3.2 (L1)
- **Affected files:** `qdp/qdp-kernels/src/amplitude.cu`, `qdp/qdp-kernels/src/angle.cu`, `qdp/qdp-kernels/src/basis.cu`
- **Related findings:** None

### Remediation
Add a defensive upper-bound check matching the batch-path pattern: compute blocks_needed, clamp to get_max_grid_dim_1d()/MAX_GRID_BLOCKS before int cast, and return on overflow. Alternatively document the state_len <= 2^30 contract explicitly and rely on ENCODING-1's fix; defense-in-depth suggests the kernel layer should fail safe even if the Rust layer has a bug.

### Acceptance Criteria
- [ ] Defensive grid size clamping added to single-shot launch functions
- [ ] Grid size computation uses blocks_needed pattern from batch functions
- [ ] Overflow check added before int cast
- [ ] Error returned on grid size exceeding device limits
- [ ] Test added verifying safe handling of large state_len values
- [ ] Consistency achieved with batch-path validation pattern

### References
- Source report: 1.3.2.md
- Merged from: ASVS-132-MED-002

### Priority
Medium

---
## Issue: FINDING-005 - state_len <= 2^30 invariant not documented in C launch function contracts
**Labels:** documentation, priority:medium
**Description:**
### Summary
The C launch functions assume state_len <= 2^30 (to fit in int gridSize after division by 256), but this precondition is not documented in comments. This increases the risk that future Rust callers will violate the invariant.

### Details
- **CWE:** CWE-1059
- **ASVS:** 1.3.2 (L1)
- **Affected files:** `qdp/qdp-kernels/src/*.cu`
- **Related findings:** None

### Remediation
Add contract documentation to all launch_*_encode functions stating preconditions: state_len must be <= 2^30 (enforced by Rust MAX_QUBITS=30), state_len must be a power of 2, inv_norm must be finite and positive (amplitude encoding only).

### Acceptance Criteria
- [ ] Contract documentation added to all `launch_*_encode` functions
- [ ] `state_len <= 2^30` precondition documented
- [ ] Power-of-2 requirement for `state_len` documented
- [ ] `inv_norm` constraints documented for amplitude encoding
- [ ] Documentation references Rust-side `MAX_QUBITS` enforcement
- [ ] Code review confirms all launch functions have complete contracts

### References
- Source report: 1.3.2.md
- Merged from: ASVS-132-MED-004

### Priority
Medium

---
## Issue: FINDING-006 - Input Validation Documentation Incomplete and Inconsistent
**Labels:** documentation, priority:low
**Description:**
### Summary
The single most important business-logic limit — the maximum qubit count and its derived constraint `sample_size <= 2^num_qubits` — is referenced but the authoritative definition (`validate_qubit_count`, `MAX_QUBITS`) lives outside the audited files, and the doc-comments are internally inconsistent: the comment in `validate_input` says "max MAX_QUBITS = 16GB GPU memory" while the domain context and false-positive list cite 30 qubits / 8GB. There is no single documented specification stating the validation rules (allowed rank, dtype, dimension limits, qubit ceiling) that every reader path must satisfy. This is a documentation deficiency, not an exploitable defect.

### Details
- **CWE:** Not assigned
- **ASVS:** 2.1.1 (L1)
- **Affected files:** `qdp/qdp-core/src/preprocessing.rs`, `qdp/qdp-core/src/gpu/encodings.rs`
- **Related findings:** None

### Remediation
Add a module-level doc block (e.g., in `reader.rs`) that enumerates the canonical input-validation contract every `DataReader` implementation must uphold (allowed dtype = f64, rank 1D/2D, dimensions > 0, single-column for columnar formats, sample-size consistency) and the downstream business limits (`1 <= num_qubits <= 30`, `sample_size <= 2^num_qubits`), and reconcile the "16GB"/"8GB" comments with the actual `MAX_QUBITS` value.

### Acceptance Criteria
- [ ] Module-level documentation added defining complete validation contract
- [ ] Canonical `MAX_QUBITS` value and memory implications documented
- [ ] Memory limit comments reconciled (16GB vs 8GB inconsistency resolved)
- [ ] Allowed dtype, rank, and dimension constraints enumerated
- [ ] Sample-size consistency requirements documented
- [ ] Documentation cross-references authoritative validation functions

### References
- Source report: 2.1.1.md
- Merged from: ASVS-211-LOW-001

### Priority
Low

---
## Issue: FINDING-007 - Unchecked Multiplication in ParquetReader::read_batch Capacity Computation
**Labels:** bug, security, priority:low
**Description:**
### Summary
ParquetReader::read_batch computes the pre-allocation size with an *unchecked* multiplication, whereas the sibling ArrowIPCReader::read_batch and TensorFlowReader::new consistently use checked_mul with an InvalidInput error on overflow. A Parquet file with a large declared list length and total_rows can drive this product to overflow: in debug builds this panics; in release builds it wraps to an undersized reserve (functionally harmless but inconsistent). This is a Type B gap — the overflow control exists in the codebase but is not applied at this entry point.

### Details
- **CWE:** CWE-190
- **ASVS:** 2.2.1 (L1)
- **Affected files:** `qdp/qdp-core/src/readers/parquet.rs`
- **Related findings:** FINDING-003

### Remediation
Use checked_mul for the capacity computation and return MahoutError::InvalidInput on overflow; apply the same to the FixedSizeList branch using batch.num_rows().

### Acceptance Criteria
- [ ] `checked_mul` used for capacity computation in `ParquetReader::read_batch`
- [ ] `MahoutError::InvalidInput` returned on overflow
- [ ] FixedSizeList branch updated with `checked_mul` for `batch.num_rows()`
- [ ] Test added verifying overflow detection with large list length × rows
- [ ] Consistency achieved with ArrowIPCReader and TensorFlowReader patterns

### References
- Source report: 2.2.1.md
- Merged from: ASVS-221-LOW-001

### Priority
Low

---
## Issue: FINDING-008 - Inconsistent Single-Column Schema Enforcement in ArrowIPCReader
**Labels:** bug, priority:low
**Description:**
### Summary
ParquetReader::new enforces a strict allow-list of *exactly one column* (schema.fields().len() != 1), but ArrowIPCReader only rejects zero-column batches and silently uses column(0), ignoring any additional columns. The structural validation is therefore inconsistent across reader paths for what should be the same logical contract ("one Float64 list column per sample"). Multi-column Arrow files are accepted with extra columns silently dropped rather than rejected.

### Details
- **CWE:** CWE-20
- **ASVS:** 2.2.1 (L1)
- **Affected files:** `qdp/qdp-core/src/readers/arrow_ipc.rs`
- **Related findings:** FINDING-009

### Remediation
Mirror the Parquet check before reading: validate batch.schema().fields().len() == 1 (or the file schema) and return MahoutError::InvalidInput otherwise.

### Acceptance Criteria
- [ ] Single-column validation added to ArrowIPCReader matching ParquetReader
- [ ] `batch.schema().fields().len() == 1` check implemented
- [ ] `MahoutError::InvalidInput` returned for multi-column schemas
- [ ] Test added verifying rejection of 0-column and 2+ column Arrow files
- [ ] Test confirms single-column files are accepted
- [ ] Validation consistency achieved across Parquet and Arrow readers

### References
- Source report: 2.2.1.md
- Merged from: ASVS-221-LOW-002

### Priority
Low

---
## Issue: FINDING-009 - Business-Limit Validation Not Enforced at Uniform Reader Choke Point
**Labels:** bug, architecture, priority:low
**Description:**
### Summary
Each reader independently validates structural rules (dtype/rank/dims/consistency) but none enforces the *business* limits (`1 <= num_qubits <= 30`, `sample_size <= 2^num_qubits`); those are enforced only when `Preprocessor::validate_batch`/`validate_input` is invoked downstream. Because the qubit ceiling is the resource-exhaustion guard and it is enforced at a *different* layer than the reader, the safety of every reader path depends on every encoding entry point routing reader output through the preprocessing validators. The encoding dispatch glue is not present in the audited files, so a confirmed bypass cannot be demonstrated here; this is flagged as a defense-in-depth/architecture concern (Type B candidate) rather than a proven gap. The structural-validation inconsistency between readers (see ASVS-221-LOW-002 / LOW-001) means the trusted layer's guarantees are not uniform across formats.

### Details
- **CWE:** CWE-20
- **ASVS:** 2.2.2 (L1)
- **Affected files:** `qdp/qdp-core/src/readers/*`, `qdp/qdp-core/src/preprocessing.rs`
- **Related findings:** FINDING-008

### Remediation
Centralize the business-limit checks so they are unconditionally applied to *every* reader output before GPU dispatch — e.g., have the encoder constructor call `Preprocessor::validate_batch(...)` on `(num_samples, sample_size, num_qubits)` regardless of source format, and add an integration test that drives each reader (Parquet, Arrow, NumPy, TF, PyTorch) through the same validation choke point with an over-limit `sample_size` to prove no path bypasses it.

### Acceptance Criteria
- [ ] Centralized business-limit validation choke point implemented
- [ ] All encoder constructors call `Preprocessor::validate_batch` unconditionally
- [ ] `num_qubits` range (1..=30) enforced before GPU dispatch
- [ ] `sample_size <= 2^num_qubits` constraint enforced
- [ ] Integration test added covering all reader formats (Parquet, Arrow, NumPy, TF, PyTorch)
- [ ] Test verifies over-limit `sample_size` is rejected for each format
- [ ] Architecture documentation updated showing validation flow

### References
- Source report: 2.2.2.md
- Merged from: ASVS-222-LOW-001

### Priority
Low

---
## Issue: FINDING-010 - Rotation-gate angle is not validated as numeric when supplied as a literal
**Labels:** bug, priority:low
**Description:**
### Summary
Rotation gate methods (`apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`) and the universal gate (`apply_u_gate`) accept angle parameters that can be either symbolic (string parameter names) or literal numeric values. The `_handle_parameter` method branches on string vs non-string types but never validates that non-string literals are actually numeric. The `apply_u_gate` method passes `theta`, `phi`, and `lambda` arguments directly to the backend with no validation. Invalid step input is accepted at the API boundary and only fails (opaquely) later in the backend. Given the trusted-local-caller threat model, the impact is limited to poor developer experience, inconsistent error behavior across backends, and potential debugging confusion.

### Details
- **CWE:** Not assigned
- **ASVS:** 2.3.1 (L1)
- **Affected files:** `qumat/qumat.py`
- **Related findings:** None

### Remediation
Add numeric validation to literal angle arguments via a `_validate_numeric_parameter` helper that allows strings (parameter names) and real numbers but rejects other types/booleans; apply to `apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`, and all three angle parameters (`theta`, `phi`, `lambda`) in `apply_u_gate`.

### Acceptance Criteria
- [ ] `_validate_numeric_parameter` helper function implemented
- [ ] Helper allows strings (parameter names) and real numbers
- [ ] Helper rejects booleans, lists, dicts, and other non-numeric types
- [ ] Validation applied to `apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`
- [ ] Validation applied to all three parameters in `apply_u_gate` (theta, phi, lambda)
- [ ] Test added verifying rejection of invalid types for each gate method
- [ ] Test confirms strings and numeric values are accepted

### References
- Source report: 2.3.1.md
- Merged from: ASVS-231-LOW-001

### Priority
Low

---
## Issue: FINDING-011 - Path traversal possible if untrusted filenames are forwarded to readers/writers
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Readers/writers perform file operations on caller-supplied paths via the type-safe AsRef&lt;Path&gt; API with no string concatenation, joining of untrusted segments, or URL fetching (no SSRF surface). Trust is delegated to the caller. If an embedder forwards untrusted filenames, no canonicalization/base-directory containment is enforced. An optional resolve_within(base, user_path) helper is recommended for embedders that must accept untrusted filenames.

### Details
- **CWE:** CWE-22
- **ASVS:** 5.3.2 (L1)
- **Affected files:** `qdp/qdp-core/src/io.rs`, `qdp/qdp-core/src/readers/torch.rs`
- **Related findings:** None

### Remediation
Document the trusted-caller path contract at each public reader/writer new() and at the io.rs wrapper functions; provide an optional resolve_within(base, user_path) helper that canonicalizes and contains paths within a base directory and rejects symlinks for embedders accepting untrusted filenames.

### Acceptance Criteria
- [ ] Trusted-caller path contract documented in all reader/writer `new()` functions
- [ ] Documentation added to `io.rs` wrapper functions
- [ ] Optional `resolve_within(base, user_path)` helper function implemented
- [ ] Helper canonicalizes paths and enforces base directory containment
- [ ] Helper rejects symlinks
- [ ] Example usage of `resolve_within` added to documentation
- [ ] Security guidance added for embedders accepting untrusted filenames

### References
- Source report: 5.3.2.md
- Merged from: ASVS-532-LOW-001

### Priority
Low

---
## Issue: FINDING-012 - Risk-Based Remediation Time Frame Documentation Missing
**Labels:** documentation, dependency, priority:low
**Description:**
### Summary
The project declares numerous 3rd party components — including native, cross-language-boundary dependencies explicitly flagged as higher-risk in the domain context (`cudarc`, `pyo3 = "0.27"`, `tch`, `arrow`, `parquet`, `prost`) and the Node.js documentation stack (`@docusaurus/* 3.10.1`) — but no documentation defining risk-based remediation time frames accompanies these manifests. There is no stated policy for: How quickly a known-vulnerable component must be patched (e.g., Critical CVE within N days); A general cadence for updating libraries regardless of known CVEs; A differentiated time frame for native/FFI dependencies (CUDA, PyO3, tch) versus the development-only Node.js stack.

### Details
- **CWE:** Not assigned
- **ASVS:** 15.1.1 (L1)
- **Affected files:** `qdp/qdp-core/Cargo.toml`, `qdp/qdp-python/Cargo.toml`, `website/package.json`
- **Related findings:** None

### Remediation
Add a dependency-management policy to project documentation (e.g., `SECURITY.md` or `docs/dependency-policy.md`) that specifies risk-based remediation windows with stricter windows for native/FFI components, a general library refresh cadence, EOL replacement triggers, and a CI gate (`cargo audit` / `npm audit`) that fails the build on findings exceeding the windows.

### Acceptance Criteria
- [ ] Dependency management policy document created (SECURITY.md or docs/dependency-policy.md)
- [ ] Risk-based remediation windows defined (e.g., Critical: 7 days, High: 30 days)
- [ ] Stricter windows documented for native/FFI dependencies
- [ ] General library refresh cadence specified
- [ ] EOL component replacement triggers defined
- [ ] `cargo audit` CI gate added with configurable thresholds
- [ ] `npm audit` CI gate added for documentation dependencies
- [ ] Policy differentiates production vs development-only dependencies

### References
- Source report: 15.1.1.md
- Merged from: ASVS-1511-LOW-001

### Priority
Low

---
## Issue: FINDING-013 - Component Version Compliance Unverifiable Due to Missing Lockfiles and Documentation
**Labels:** dependency, priority:low
**Description:**
### Summary
The most exploit-prone dependencies — those crossing the native/FFI boundary as called out in the domain context (`cudarc`, `tch`, `prost`/`prost-build` deserialization, `parquet`/`arrow` binary parsing) — defer their version entirely to the workspace (`{ workspace = true }`). Because the workspace manifest and lockfile are not present, there is no way within the audited artifacts to confirm these components are within any support/remediation window. Without 15.1.1's documented time frame and without a committed lockfile in scope, 15.2.1 compliance is unverifiable for the highest-risk components. This is a verification/traceability gap rather than a proven outdated-component.

### Details
- **CWE:** Not assigned
- **ASVS:** 15.2.1 (L1)
- **Affected files:** `qdp/qdp-core/Cargo.toml` (lines 8-25)
- **Related findings:** None

### Remediation
Commit `Cargo.lock` and `package-lock.json` and audit them in CI. Add `cargo audit` (RustSec advisory DB) and `npm audit` as required CI gates so 15.2.1 is enforced mechanically against the 15.1.1 time frames. Record the pinned native-dependency versions in the dependency policy and review against RustSec/NVD on the documented cadence.

### Acceptance Criteria
- [ ] `Cargo.lock` committed to version control
- [ ] `package-lock.json` committed to version control
- [ ] `cargo audit` added as required CI gate
- [ ] `npm audit` added as required CI gate
- [ ] CI fails build on vulnerabilities exceeding policy thresholds
- [ ] Pinned versions of native/FFI dependencies documented in policy
- [ ] Scheduled review process established for RustSec/NVD advisories
- [ ] Workspace manifest versions made visible to audit tooling

### References
- Source report: 15.2.1.md
- Merged from: ASVS-1521-LOW-001

### Priority
Low

---
## Issue: FINDING-014 - transformLinks() lacks negative protocol screening (javascript:, data:) for markdown link targets
**Labels:** security, documentation, priority:low
**Description:**
### Summary
Data flow: source = markdown link targets in /docs (version control) → sink = rewritten markdown passed to Docusaurus → missing control = no allow-list of safe protocols (javascript:, data: are neither blocked nor distinguished from relative links). Attacker capability required: Commit access to the version-controlled /docs tree (privileged/trusted contributor). A purely remote unauthenticated attacker cannot reach this code path. Impact on success: A malicious link such as [click](javascript:alert(1)) would pass through unchanged; whether it becomes executable depends entirely on the downstream Docusaurus/React link renderer, which sanitizes URL protocols by default. No direct C/I/A impact in the default configuration. Why LOW (not higher): The input is trusted version-controlled content (explicit false-positive pattern), exploitation requires a malicious commit passing review, and the downstream renderer (React/Docusaurus) is the actual control that neutralizes dangerous protocols. This is a defense-in-depth gap, not an exploitable path.

### Details
- **CWE:** Not assigned
- **ASVS:** 1.2.2 (L1)
- **Affected files:** `website/scripts/sync-docs.js` (lines 138-156)
- **Related findings:** None

### Remediation
If the function is intended to vet links, add explicit protocol screening: const SAFE_RELATIVE = url => !/^[a-z][a-z0-9+.-]*:/i.test(url) || /^https?:/i.test(url); if (!SAFE_RELATIVE(url)) { console.warn(`Skipping unsafe link protocol: ${url}`); return `[${text}](#)`; }

### Acceptance Criteria
- [ ] Protocol validation added to `transformLinks()` function
- [ ] `SAFE_RELATIVE` check implemented allowing only relative URLs and https?://
- [ ] Dangerous protocols (javascript:, data:, file:) rejected
- [ ] Warning logged for rejected unsafe protocols
- [ ] Rejected links replaced with safe placeholder (e.g., `#`)
- [ ] Test added verifying javascript: and data: links are neutralized
- [ ] Test confirms http://, https://, and relative links pass through

### References
- Source report: 1.2.2.md
- Merged from: ASVS-122-LOW-001

### Priority
Low