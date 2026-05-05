# Security Audit Consolidated Report

## Apache Mahout (QuMat / QDP)

---

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | `245aad3` |
| **Date** | May 05, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 13 |

---

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High | 1 | 7.7% |
| Medium | 10 | 76.9% |
| Low | 2 | 15.4% |
| Info | 0 | 0.0% |

### Level Coverage

This audit evaluated controls at **ASVS Level 1 (L1)** — the minimum assurance level covering essential application security verification requirements. All 13 findings fall within the L1 scope, indicating that foundational input validation, configuration hygiene, and third-party component governance require attention before progressing to higher assurance levels.

### Top 5 Risks

1. **[High] FINDING-001 — `num_qubits` parameter lacks validation for type, sign, and upper bound (ASVS 2.2.1)**
   The core quantum circuit initialization parameter accepts arbitrary values without enforcing type constraints, non-negativity, or a documented upper bound. Malformed values could trigger undefined behavior in downstream backend modules or unbounded resource allocation.

2. **[Medium] FINDING-006 — Backend modules receive full configuration object instead of required fields (ASVS 15.3.1)**
   Passing the entire configuration dictionary to backend adapters violates the principle of least privilege. A compromised or poorly-written backend plugin gains access to credentials, paths, or settings outside its operational scope.

3. **[Medium] FINDING-011 — `path_from_py` accepts user-supplied file paths with no validation or sanitization (ASVS 5.3.2)**
   The Rust/Python boundary function accepts arbitrary filesystem paths without canonicalization or traversal checks. In deployment contexts where user-supplied paths reach this function, path traversal or symlink-based attacks become feasible.

4. **[Medium] FINDING-004 / FINDING-005 — No documented remediation timeframes for third-party vulnerabilities (ASVS 15.1.1, 15.2.1)**
   The absence of a risk-based policy defining maximum acceptable time-to-patch for dependencies of varying severity means that known vulnerabilities in transitive dependencies may persist indefinitely without a governance trigger for remediation.

5. **[Medium] FINDING-010 — Stale parameter state persists across circuit resets (ASVS 2.3.1)**
   When a quantum circuit is reset, previously bound parameter values remain in the instance state. Subsequent circuit executions may unintentionally inherit parameters from a prior computation, leading to silent correctness errors in quantum simulations.

### Positive Controls Observed

The audit identified **25 positive security controls** that demonstrate defense-in-depth practices across the codebase:

| Category | Representative Controls |
|----------|------------------------|
| **Memory Safety** | Double-free prevention via consumed flag; RAII `Drop` implementations for deterministic GPU resource cleanup; DLPack single-consume enforcement; null pointer checks on all entry paths |
| **Injection Prevention** | Compile-time constant capsule names; strongly-typed FFI interfaces eliminating shell injection structurally; Rust type system preventing text-based injection classes |
| **Input Validation** | Centralized `_validate_qubit_index` function with type/sign/range checks; allowlist pattern for enum inputs (`parse_null_handling`); defense-in-depth validation at both Python API and Rust core layers |
| **Attack Surface Reduction** | Feature-gated remote IO requiring explicit opt-in; URL query/fragment rejection preventing credential leakage via URL parameters; minimal DLPack interface exposure |
| **Governance & Release** | Apache PMC voting as structured release gate; GPG signing and checksum verification in release process; documented security practices for token management |

These controls indicate a security-aware development culture, particularly in the Rust/GPU interop layer where memory safety concerns are most acute. The findings in this report primarily address gaps in the Python orchestration layer and governance documentation rather than fundamental architectural weaknesses.

---

## 3. Findings

### 3.2 High

#### FINDING-001: num_qubits parameter lacks validation for type, sign, and upper bound

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 2.2.1 |
| **Files** | `qumat/qumat.py:82-85` |
| **Source Reports** | 2.2.1.md |
| **Related** | None |

**Description:**

The `num_qubits` parameter is not validated for type, sign, or upper bound. It is stored directly and used in subsequent range checks for qubit indices. An invalid value (float, negative, extremely large, or non-numeric) produces undefined behavior downstream. User input (`num_qubits`) is stored as `self.num_qubits`, used in `_validate_qubit_index` comparisons, and passed to backend `create_empty_circuit`. This can lead to resource exhaustion (DoS) with large values, logic errors with non-integer types, and confusing error messages with unsupported types. The QDP documentation specifies 1–30 as the valid range, but `qumat.py` enforces no upper bound.

**Remediation:**

Add validation to check that num_qubits is an integer, non-negative, and within reasonable bounds before storing and using it. Implement type checking with isinstance, validate non-negativity, and optionally enforce the documented 1-30 range constraint.

---

### 3.3 Medium

#### FINDING-002: Remote IO feature lacks visible TLS certificate validation configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 12.2.2 |
| **Files** | `qdp/qdp-core/src/lib.rs:24`&lt;br&gt;`docs/qdp/api.md`&lt;br&gt;`docs/qdp/getting-started.md` |
| **Source Reports** | 12.2.2.md |
| **Related Findings** | None |

**Description:**

User-supplied S3/GCS URL → QdpEngine.encode() → remote module (not provided) → external cloud storage. The remote-io feature conditionally enables cloud object storage access. The implementation of the remote module is not included in the audit scope, so verification of TLS certificate validation is impossible. If the remote module does not enforce publicly trusted TLS certificates or allows insecure connections, data in transit to/from S3/GCS could be intercepted via man-in-the-middle attacks. Since the data loaded may include training datasets or model parameters, integrity and confidentiality could be compromised.

**Remediation:**

Verify the remote module (not provided) enforces TLS 1.2+ with publicly trusted certificates. Ensure no VERIFY_SSL=false or equivalent bypass is available. Document TLS requirements for remote IO connections. Example implementation:
```rust
let client = reqwest::Client::builder()
    .min_tls_version(reqwest::tls::Version::TLS_1_2)
    .use_rustls_tls()
    .build()?;
```

---

#### FINDING-003: No deployment configuration to exclude source control metadata from production artifacts

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 13.4.1 |
| **Files** | `docs/qdp/getting-started.md`&lt;br&gt;`dev/release.md` |
| **Source Reports** | 13.4.1.md |
| **Related Findings** | None |

**Description:**

If the application is deployed from a git checkout (e.g., in a container built from the repository clone, or served via a web-accessible directory), the `.git` folder could expose: Full repository history including potentially sensitive commits, Internal developer information (email addresses, commit messages), Configuration details that aid reconnaissance. Data flow: Source repository (`.git/`) → development/build environment → packaged artifact → deployment

**Remediation:**

Add `.dockerignore` or equivalent build exclusion rules containing: `.git`, `.svn`, `.gitignore`, `dev/`. For Python packages distributed via PyPI (the documented release path), `maturin build` and `uv build` produce wheel/sdist artifacts that do not include `.git` — this is a positive pattern. Document deployment best practices that explicitly exclude VCS metadata.

---

#### FINDING-004: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.1.1 |
| **Files** | `dev/release.md` (entire file) |
| **Source Reports** | 15.1.1.md |
| **Related Findings** | None |

**Description:**

The application documentation does not define risk-based remediation time frames for 3rd party component versions with vulnerabilities or for updating libraries in general. Without defined remediation timeframes, known vulnerabilities in dependencies (cudarc, thiserror, arrow, parquet, CUDA runtime, PyTorch) may persist indefinitely with no consistent standard for when updates must be applied, increasing the window of exposure for supply chain attacks and resulting in inconsistent risk treatment across the project.

**Remediation:**

Create a SECURITY.md or docs/security/dependency-policy.md defining:

```markdown
# Dependency Vulnerability Management Policy

## Remediation Timeframes

| Severity | Definition | Remediation SLA |
|----------|-----------|-----------------|
| Critical (CVSS ≥ 9.0) | RCE, data exfiltration, privilege escalation | 7 calendar days |
| High (CVSS 7.0–8.9) | Significant impact vulnerabilities | 30 calendar days |
| Medium (CVSS 4.0–6.9) | Limited impact vulnerabilities | 90 calendar days |
| Low (CVSS < 4.0) | Minimal impact | Next scheduled release |

## General Update Policy
- All dependencies reviewed quarterly
- cargo audit / pip-audit run in CI on every PR
- SBOM generated with each release

## Dangerous Components
- qdp_kernels: CUDA FFI — unsafe operations, direct memory manipulation
- cudarc: CUDA driver bindings — GPU memory allocation, raw pointers
- Parquet/Arrow readers: Binary data parsing from untrusted files
```

---

#### FINDING-005: Unable to verify component currency without documented remediation timeframes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.2.1 |
| **Files** | `qdp/qdp-core/src/gpu/memory.rs`&lt;br&gt;`qdp/qdp-core/src/error.rs`&lt;br&gt;`dev/release.md` |
| **Source Reports** | 15.2.1.md |
| **Related Findings** | None |

**Description:**

Without ASVS 15.1.1 compliance (documented timeframes), compliance with 15.2.1 is structurally impossible to verify. The following risks exist: Dependencies may contain known CVEs without a mechanism to detect or track them; No Cargo.lock or requirements.txt freeze file was provided for audit, preventing version verification; The qdp_kernels crate (likely internal) contains unsafe CUDA FFI that requires careful version management; Parquet/Arrow file parsers handle untrusted input and are a common source of vulnerabilities.

**Remediation:**

1. Implement the policy from ASVS-1511-MED-001
2. Add automated dependency scanning to CI (cargo audit and pip-audit)
3. Include Cargo.lock in the repository for reproducible builds and auditability
4. Add a dependency review step to the release process in dev/release.md with pre-release dependency audit steps including cargo audit, pip-audit, verification of remediation timeframes, and SBOM generation

---

#### FINDING-006: Backend modules receive full configuration object instead of required fields

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 15.3.1 |
| **Files** | `qumat/qumat.py:243-262`&lt;br&gt;`qumat/qumat.py:283-302` |
| **Source Reports** | 15.3.1.md |
| **Related Findings** | None |

**Description:**

The entire `self.backend_config` dictionary is passed to backend modules, and is also mutated to accumulate state between calls. The `backend_config` contains all constructor-supplied configuration (including `backend_name`, `backend_options` with `simulator_type`, `shots`, etc.) plus injected `parameter_values`. Backend functions receive the full configuration object rather than only the fields they need. Backend modules receive more configuration data than required for their specific operation. If a backend module logs, serializes, or exposes this config (e.g., in error messages), fields that should be scoped differently could leak. The mutation pattern also creates implicit coupling between sequential calls.

**Remediation:**

Pass only what the backend needs. For example, in execute_circuit, create a scoped execution_config dictionary containing only parameter_values and shots, rather than passing the entire backend_config. Example:
```python
execution_config = {
    "parameter_values": bound_parameters,
    "shots": self.backend_config["backend_options"].get("shots", 1024)
}
```
Use this scoped config when calling `backend_module.execute_circuit(self.circuit, self.backend, execution_config)`.

---

#### FINDING-007: QuMat class lacks structured documentation defining input validation rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.1.1 |
| **Files** | `qumat/qumat.py` |
| **Source Reports** | 2.1.1.md |
| **Related Findings** | None |

**Description:**

The QuMat class lacks structured documentation defining input validation rules for its parameters. While docstrings describe parameter types, they do not specify valid ranges, allowed values, or expected structures as formal validation rules. Contrast this with the QDP API documentation which explicitly specifies ranges (e.g., num_qubits 1–30) and allowed encoding methods. Specific gaps in qumat.py: create_empty_circuit(num_qubits) has no documented valid range for num_qubits; apply_rx_gate(qubit_index, angle) has no documented valid range or constraints for angle (e.g., finite-only, radian range); apply_u_gate(qubit_index, theta, phi, lambd) has no documented constraints on rotation angles; backend_config has no schema or structural validation rules documented beyond required keys. Developers implementing backends or consuming the API lack clear guidance on what constitutes valid input, leading to inconsistent validation across backends and potential runtime failures with unclear error messages.

**Remediation:**

Add a validation rules section to the QuMat class docstring specifying: num_qubits as int, range [1, 30] (or backend-specific maximum); qubit_index as int, range [0, num_qubits - 1]; angle (rotation gates) as float, must be finite (no NaN/Inf); backend_name as str, one of {"qiskit", "cirq", "amazon_braket"}; backend_options as dict with required key "simulator_type" (str) and optional "shots" (int, >= 1).

---

#### FINDING-008: Rotation angle parameters lack validation for finiteness and type

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | `qumat/qumat.py:303`&lt;br&gt;`qumat/qumat.py:321`&lt;br&gt;`qumat/qumat.py:339`&lt;br&gt;`qumat/qumat.py:356` |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None |

**Description:**

When rotation angles are provided as floats, no validation is performed for finiteness (NaN, Inf) or type correctness. While `_handle_parameter` registers string parameter names, float values pass through unchecked. The QDP documentation explicitly requires finite values for similar parameters. This affects `apply_rx_gate()` (line ~303), `apply_ry_gate()` (line ~321), `apply_rz_gate()` (line ~339), and `apply_u_gate()` (line ~356). User input (angle/theta/phi/lambd) passes directly to backend module with no validation. NaN or Inf values produce mathematically undefined quantum states. Backends may silently produce incorrect results rather than raising errors, leading to data integrity issues in quantum computations.

**Remediation:**

Create a `_validate_angle` helper function that validates angle parameters are numeric types and finite (not NaN or Inf). Apply this validation to all rotation gate methods before passing values to backend modules.

---

#### FINDING-009: backend_options and backend_name lack structure and allow-list validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.2.1 |
| **Files** | `qumat/qumat.py:53-75` |
| **Source Reports** | 2.2.1.md |
| **Related Findings** | None |

**Description:**

The `backend_options` value is checked for existence but not validated for type or structure. The `backend_name` is not validated against an allow list of known backends, relying solely on `import_module` to fail for unknown names. The `backend_config` flows to `backend_name` used in `import_module` f-string for module loading, and `backend_options` is stored and used later without structure checks. This results in unclear error messages for misconfigured backends and implicit validation through ImportError rather than explicit business rule check. The relative import (`package='qumat'`) limits the attack surface of the module loading to within the `qumat` package.

**Remediation:**

Add type validation to ensure backend_options is a dictionary. Create an allow-list of valid backend names (qiskit, cirq, amazon_braket) and validate backend_name against this list before attempting module import. Provide clear error messages for invalid configurations.

---

#### FINDING-010: Stale Parameter State Persists Across Circuit Resets

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | `qumat/qumat.py:82-85` |
| **Source Reports** | 2.3.1.md |
| **Related Findings** | None |

**Description:**

When `create_empty_circuit` is called again on an existing `QuMat` instance, it resets `self.circuit` and `self.num_qubits` but does **not** reset `self.parameters`. This allows stale parameter registrations and bound values from a previous circuit to persist and be injected into the new circuit's execution via `backend_config["parameter_values"]`. This can lead to incorrect quantum computation results due to stale parameter state. In scientific computing contexts, silent corruption of computation parameters could lead to invalid experimental results. The unbound parameter check in `execute_circuit` only catches parameters with `None` values — fully bound stale parameters pass through silently.

**Remediation:**

Reset the parameters dictionary when creating a new circuit:
```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
    self.parameters = {}  # Reset parameter registry for new circuit
```

---

#### FINDING-011: `path_from_py` accepts user-supplied file paths with no validation or sanitization

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-22 |
| **ASVS Section(s)** | 5.3.2 |
| **Files** | `qdp/qdp-python/src/loader.rs:109-113` |
| **Source Reports** | 5.3.2.md |
| **Related Findings** | None |

**Description:**

The `path_from_py` function in the Rust extension accepts file paths from Python callers without any validation or sanitization. It extracts a string from Python input (either a string or pathlib.Path object) and passes it directly to downstream file I/O operations. No checks are performed for path traversal sequences (../, ..\\, encoded variants), null byte injection, scheme validation, or canonicalization. The function serves as a chokepoint for multiple entry points (encode_from_parquet, encode_from_arrow_ipc, encode_from_numpy, encode_from_torch, encode_from_tensorflow) that all accept user-controlled paths. When the remote-io feature is enabled, this also creates an SSRF attack surface as the library can access s3:// and gs:// URLs without scheme validation. If integrated into a service where file paths originate from untrusted user input, an attacker could perform path traversal to read arbitrary files, conduct SSRF attacks targeting internal infrastructure, or cause information disclosure of sensitive configuration and credentials.

**Remediation:**

Implement path validation and sanitization in the path_from_py function. The remediation should include: (1) Reject null bytes in the path string, (2) Canonicalize the path to resolve symlinks and ../ sequences using Path::canonicalize(), (3) Enforce that the resolved path is within an allowed base directory using starts_with(), (4) Add URL scheme validation when remote-io is enabled to allowlist only permitted schemes (s3://, gs://) and reject unexpected ones (file://, http://, ftp://), (5) Optionally add file extension validation to ensure the path ends with a supported extension (.parquet, .arrow, .feather, .npy, .pt, .pth, .pb). A reference implementation is provided in the report showing how to create a path_from_py function that takes an allowed_base parameter and performs these validations.

### 3.4 Low

#### FINDING-012: Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 14.2.1 |
| **Files** | `qdp/qdp-core/src/lib.rs` (encode_from_parquet function)&lt;br&gt;`docs/qdp/getting-started.md` (remote URL examples)&lt;br&gt;`error.rs` (MahoutError::Io(String) variant) |
| **Source Reports** | 14.2.1.md |
| **Related** | None |

**Description:**

User-supplied URL strings for S3/GCS bucket names and object key paths passed as function arguments could appear in error messages or logs. Object keys may contain sensitive identifiers (customer IDs, dataset names, internal project names). The MahoutError::Io(String) variant could propagate these paths. While query strings are explicitly rejected (positive pattern), the path components themselves may leak sensitive information through error messages.

**Remediation:**

Sanitize file paths in error messages to redact bucket names or keys. Consider structured logging that separates path components for selective redaction. Example implementation: create a sanitize_remote_path function that redacts bucket and key information for s3:// and gs:// URLs, replacing sensitive path components with `<redacted>` placeholder.

---

#### FINDING-013: All instance attributes are public and freely accessible

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.3.1 |
| **Files** | `qumat/qumat.py` |
| **Source Reports** | 15.3.1.md |
| **Related** | None |

**Description:**

All instance attributes (`backend_config`, `backend_module`, `backend`, `circuit`, `parameters`) are public Python attributes. While Python convention doesn't enforce access control, sensitive internal state (raw backend handles, full configuration) is freely accessible to any consumer of a `QuMat` instance. Low risk in a library context, but consumers could inadvertently depend on or expose internal state such as the raw `backend_config` dictionary.

**Remediation:**

Use underscore-prefixed attributes for internal state (_backend_config, _backend_module) and provide explicit accessor properties for fields consumers legitimately need.

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Implementation Files | ASVS Mapping |
|------------|-------------------|----------|---------------------|--------------|
| PSC-001 | Static capsule name using compile-time constant | `DLTENSOR_NAME: &[u8] = b"dltensor\0"` is a compile-time constant, eliminating any possibility of injection into the PyCapsule name | tensor.rs | 1.2.5 |
| PSC-002 | Double-free prevention via consumed flag | consumed flag checked before both PyCapsule creation and Drop execution | tensor.rs | 2.2.1 |
| PSC-003 | Null pointer checks on entry paths | Null pointer checks on all entry paths before dereferencing self.ptr | tensor.rs | 2.2.1 |
| PSC-004 | Strongly-typed interfaces prevent text-based injection | Rust's type system prevents all text-based injection classes structurally | tensor.rs | 1.2.5, 2.2.1 |
| PSC-005 | Typed FFI calls only | All external calls use strongly-typed function signatures (PyCapsule_New, synchronize_stream, dlpack_stream_to_cuda), making shell injection structurally impossible | Multiple | 1.2.5 |
| PSC-006 | Feature-gated remote IO | Remote storage access requires explicit opt-in via the remote-io Cargo feature flag, reducing default attack surface | qdp/qdp-core/src/lib.rs:24 | 12.2.2 |
| PSC-007 | URL fragment/query rejection | Documentation explicitly states Remote URL query/fragment is not supported (?versionId=..., #...), which limits URL complexity and potential for parameter injection | docs/qdp/api.md, docs/qdp/getting-started.md | 14.2.1 |
| PSC-008 | Package-based distribution | The release process builds wheels and sdist via `uv build` and `maturin build`, which inherently exclude `.git` directories from distribution artifacts | dev/release.md | 13.4.1 |
| PSC-009 | Query string/fragment rejection | The API explicitly documents and rejects query strings and fragments in remote URLs, preventing credential leakage via URL parameters like ?AWSAccessKeyId=... | api.md, getting-started.md | 14.2.1 |
| PSC-010 | DLPack single-consume enforcement | free_dlpack_tensor() in dlpack.rs uses deleter that takes ownership, preventing double-use of GPU memory handles | dlpack.rs | 2.2.1 |
| PSC-011 | RAII Drop implementations for deterministic resource cleanup | PinnedHostBuffer, PipelineContext, and OverlapTracker all implement Drop traits for deterministic cleanup of GPU memory and resources | memory.rs, pipeline.rs, overlap_tracker.rs | 2.2.1 |
| PSC-012 | Apache release governance with PMC voting | The ATR (Apache Trusted Releases) process with PMC voting provides a structured release gate where dependency issues could be caught | dev/release.md | 15.1.1, 15.2.1 |
| PSC-013 | QuantumTensor minimal DLPack interface | Exposes only __dlpack__ and __dlpack_device__ methods | tensor.rs | 15.3.1 |
| PSC-014 | QDP API validation rules documented with clear types, ranges, and encoding methods | QDP API documentation provides clear, structured validation rules including: num_qubits range 1–30, explicit encoding method allow-lists, supported data types and shapes, NaN/Inf rejection rules per encoding method, and file format constraints | website/.../api.md, website/.../python-api.md | 2.1.1 |
| PSC-015 | _validate_qubit_index function provides centralized validation | Checks type (isinstance), sign (non-negative), and range (within circuit bounds). Consistently called from every gate method with no gaps in application. | qumat/qumat.py:97-112 | 2.2.1 |
| PSC-016 | _ensure_circuit_initialized provides prerequisite check | Reliable check applied consistently to all gate and execute methods before any operation. | qumat/qumat.py:87-95 | 2.3.1 |
| PSC-017 | Constructor validates backend_config is a dictionary with required keys | Proper isinstance check and key existence validation with clear error messages. | qumat/qumat.py:57-60, 62-75 | 2.2.1 |
| PSC-018 | No client-side-only validation | All validation in qumat.py runs in the same process as the computation — there is no untrusted client layer | qumat/qumat.py | 2.2.2, 8.3.1 |
| PSC-019 | Defense-in-depth in QDP | Validation occurs at both the Python API layer and the Rust core layer, with the Rust layer being authoritative | qumat/qumat.py, qdp-core | 2.2.2 |
| PSC-020 | Unbound parameter check | Prevents execution with None-valued parameters in both execute_circuit and get_final_state_vector | qumat.py:253-260, 290-297 | 2.2.1 |
| PSC-021 | Whitelist pattern for enum inputs | The parse_null_handling function demonstrates proper allowlist validation for string inputs, rejecting unknown values with descriptive errors | qdp/qdp-python/src/loader.rs:76-84 | 2.2.1 |
| PSC-022 | Type-safe null handling | Using Rust String type (not CString) avoids null-byte-in-middle issues at the Rust/OS boundary for most standard library I/O operations | qdp/qdp-python/src/loader.rs:109-113 | 2.2.1 |
| PSC-023 | Documentation of supported formats | API documentation clearly specifies allowed file extensions and URL schemes, providing a basis for implementing validation | api.md, getting-started.md | 2.1.1 |
| PSC-024 | Strong validation for numeric and enum inputs | Codebase demonstrates validation for encoding methods, qubit ranges, and GPU pointer validity via cudaPointerGetAttributes | Multiple | 2.2.1 |
| PSC-025 | Security documentation practices for release process | The dev/release.md documentation demonstrates good security documentation practices including GPG signing, checksum verification, and token management with chmod 600 | dev/release.md | 15.1.1 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Findings | Notes |
|---------|-------|--------|----------|-------|
| 1.2.1 | Output Encoding for HTTP Response / HTML / XML / CSS | N/A | - | Not a web application |
| 1.2.2 | URL Encoding and Safe URL Protocols | N/A | - | No URL construction |
| 1.2.3 | JavaScript / JSON Output Encoding | N/A | - | No JavaScript/JSON output |
| 1.2.4 | Parameterized Queries / SQL Injection | N/A | - | No database interaction |
| 1.2.5 | OS Command Injection | **Pass** | - | Typed FFI calls only; no shell invocation (PSC-004, PSC-005) |
| 1.3.1 | HTML Sanitization for WYSIWYG / Rich Input | N/A | - | No HTML processing |
| 1.3.2 | Avoid eval() or Dynamic Code Execution | N/A | - | No dynamic code execution |
| 1.5.1 | XML Parser Configuration - XXE Prevention | N/A | - | No XML parsing |
| 2.1.1 | Validation and Business Logic Documentation | **Partial** | FINDING-007 | QDP documented (PSC-014, PSC-023); QuMat lacks structured validation docs |
| 2.2.1 | Input Validation | **Fail** | FINDING-001, FINDING-008, FINDING-009 | Strong validation for qubit indices (PSC-015, PSC-017, PSC-021, PSC-024); gaps in num_qubits, rotation angles, backend options |
| 2.2.2 | Server-Side Input Validation | **Pass** | - | All validation server-side; no client-side bypass (PSC-018, PSC-019) |
| 2.3.1 | Business Logic Sequential Flow | **Partial** | FINDING-010 | Strong prerequisite checks (PSC-016); stale parameter state issue |
| 3.2.1 | Unintended Content Interpretation | N/A | - | No content rendering |
| 3.2.2 | Safe text rendering to prevent unintended HTML/JavaScript execution | N/A | - | No HTML/JS rendering |
| 3.3.1 | Cookie Security Attributes | N/A | - | No cookies |
| 3.4.1 | HTTP Strict Transport Security (HSTS) Policy | N/A | - | Not a web server |
| 3.4.2 | Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin Validation | N/A | - | Not a web API |
| 3.5.1 | Cross-Origin Request Validation | N/A | - | Not a web application |
| 3.5.2 | CORS Preflight Bypass Prevention | N/A | - | Not a web application |
| 3.5.3 | HTTP Method Validation for Sensitive Functionality | N/A | - | Not a web application |
| 4.1.1 | HTTP Response Content-Type Header Verification | N/A | - | No HTTP responses |
| 4.4.1 | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections | N/A | - | No WebSocket usage |
| 5.2.1 | File Size Validation | N/A | - | No file upload functionality |
| 5.2.2 | File Upload Validation | N/A | - | No file upload functionality |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request | N/A | - | No file upload or public folder |
| 5.3.2 | File Storage — Path Traversal Protection | **Fail** | FINDING-011 | path_from_py accepts unsanitized paths |
| 6.1.1 | Authentication Documentation | N/A | - | No authentication |
| 6.2.1 | Password Minimum Length | N/A | - | No password authentication |
| 6.2.2 | Password Change Capability | N/A | - | No password authentication |
| 6.2.3 | Password Change Requires Current and New Password | N/A | - | No password authentication |
| 6.2.4 | Common Password Check | N/A | - | No password authentication |
| 6.2.5 | Password Composition Rules | N/A | - | No password authentication |
| 6.2.6 | Password Input Field Masking | N/A | - | No password fields |
| 6.2.7 | Paste functionality, browser password helpers, and external password managers | N/A | - | No password fields |
| 6.2.8 | Password Verification Without Modification | N/A | - | No password authentication |
| 6.3.1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation | N/A | - | No authentication |
| 6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled | N/A | - | No user accounts |
| 6.4.1 | Secure Initial Password/Activation Code Generation | N/A | - | No password generation |
| 6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present | **Pass** | - | No knowledge-based auth |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service | N/A | - | No session management |
| 7.2.2 | Session Management - Dynamic Token Generation | N/A | - | No session tokens |
| 7.2.3 | Reference Token Uniqueness and Entropy | N/A | - | No session tokens |
| 7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token | N/A | - | No session management |
| 7.4.1 | Session Termination and Invalidation | N/A | - | No sessions |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company) | N/A | - | No user accounts |
| 8.1.1 | Authorization documentation for function-level and data-specific access | N/A | - | No authorization layer |
| 8.2.1 | Function-level access control | N/A | - | No authorization |
| 8.2.2 | Data-specific access restriction and IDOR/BOLA mitigation | N/A | - | No authorization |
| 8.3.1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript | N/A | - | No authorization layer |
| 9.1.1 | Verify that self-contained tokens are validated using their digital signature or MAC to protect against tampering before accepting the token's contents | N/A | - | No token usage |
| 9.1.2 | Token Algorithm Allowlist Verification | N/A | - | No token usage |
| 9.1.3 | Verify that key material that is used to validate self-contained tokens is from trusted pre-configured sources for the token issuer | N/A | - | No token usage |
| 9.2.1 | Token Validity Time Span Verification | N/A | - | No token usage |
| 10.4.1 | Authorization Server Redirect URI Validation | N/A | - | No OAuth |
| 10.4.2 | Authorization Code Single Use Verification | N/A | - | No OAuth |
| 10.4.3 | Authorization Code Lifetime | N/A | - | No OAuth |
| 10.4.4 | Authorization Server Grant Type Restrictions | N/A | - | No OAuth |
| 10.4.5 | Refresh Token Replay Attack Mitigation | N/A | - | No OAuth |
| 11.3.1 | Insecure Block Modes and Weak Padding Schemes | N/A | - | No cryptographic operations |
| 11.3.2 | Approved Ciphers and Modes | N/A | - | No cryptographic operations |
| 11.4.1 | Approved Hash Functions for Cryptographic Use | N/A | - | No cryptographic hashing |
| 12.1.1 | TLS Protocol Version Requirements | N/A | - | Not a TLS server |
| 12.2.1 | TLS for all connectivity between client and external facing HTTP-based services | N/A | - | No external HTTP services |
| 12.2.2 | HTTPS Communication with External Facing Services | **Partial** | FINDING-002 | Remote IO feature-gated (PSC-006); TLS cert validation not visible |
| 13.4.1 | Unintended Information Leakage — Source Control Metadata | **Partial** | FINDING-003 | Package distribution excludes .git (PSC-008); no deployment config |
| 14.2.1 | General Data Protection — Sensitive Data in URLs | **Partial** | FINDING-012 | Query/fragment rejection (PSC-007, PSC-009); bucket names may appear in logs |
| 14.3.1 | Client-side Data Protection — Clearing Authenticated Data | N/A | - | No client-side storage |
| 15.1.1 | Secure Coding and Architecture Documentation — Remediation Timeframes | **Fail** | FINDING-004 | Release governance exists (PSC-012); no documented remediation timeframes |
| 15.2.1 | Security Architecture and Dependencies — Component Currency | **Fail** | FINDING-005 | Cannot verify without remediation policy |
| 15.3.1 | Defensive Coding — Return Only Required Field Subset | **Partial** | FINDING-006, FINDING-013 | Minimal DLPack interface (PSC-013); backend receives full config; public attributes |

**Summary Statistics:**
- **Pass**: 3
- **Partial**: 7
- **Fail**: 5
- **N/A**: 70
- **Total Applicable**: 15

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Controls | Positive Controls | Affected Components |
|------------|----------|---------------|-------------------|---------------------|
| FINDING-001 | High | 2.2.1 | PSC-015, PSC-024 | qumat/qumat.py (constructor) |
| FINDING-002 | Medium | 12.2.2 | PSC-006 | qdp/qdp-core (remote-io feature) |
| FINDING-003 | Medium | 13.4.1 | PSC-008 | Build/deployment configuration |
| FINDING-004 | Medium | 15.1.1 | PSC-012, PSC-025 | Security documentation |
| FINDING-005 | Medium | 15.2.1 | PSC-012 | Dependency management process |
| FINDING-006 | Medium | 15.3.1 | PSC-013 | qumat/qumat.py (backend initialization) |
| FINDING-007 | Medium | 2.1.1 | PSC-014, PSC-023 | qumat/qumat.py (class documentation) |
| FINDING-008 | Medium | 2.2.1 | PSC-015, PSC-024 | qumat/qumat.py (rotation gate methods) |
| FINDING-009 | Medium | 2.2.1 | PSC-017, PSC-021 | qumat/qumat.py (constructor) |
| FINDING-010 | Medium | 2.3.1 | PSC-016, PSC-020 | qumat/qumat.py (reset_circuit method) |
| FINDING-011 | Medium | 5.3.2 | PSC-022, PSC-023 | qdp/qdp-python/src/loader.rs |
| FINDING-012 | Low | 14.2.1 | PSC-007, PSC-009 | Remote URL handling, logging |
| FINDING-013 | Low | 15.3.1 | PSC-013 | qumat/qumat.py (all attributes) |

## Control Coverage by Component

| Component | Positive Controls | Findings | ASVS Coverage |
|-----------|-------------------|----------|---------------|
| tensor.rs | PSC-001, PSC-002, PSC-003, PSC-004, PSC-013 | None | 1.2.5, 2.2.1, 15.3.1 |
| qumat/qumat.py | PSC-015, PSC-016, PSC-017, PSC-018, PSC-019, PSC-020 | FINDING-001, FINDING-006, FINDING-007, FINDING-008, FINDING-009, FINDING-010, FINDING-013 | 2.1.1, 2.2.1, 2.2.2, 2.3.1, 15.3.1 |
| qdp-core | PSC-006, PSC-019 | FINDING-002 | 2.2.2, 12.2.2 |
| qdp-python/loader.rs | PSC-021, PSC-022 | FINDING-011 | 2.2.1, 5.3.2 |
| dlpack.rs | PSC-010 | None | 2.2.1 |
| memory.rs / pipeline.rs | PSC-011 | None | 2.2.1 |
| Documentation | PSC-007, PSC-009, PSC-014, PSC-023, PSC-025 | FINDING-012 | 2.1.1, 14.2.1, 15.1.1 |
| Build/Release | PSC-008, PSC-012 | FINDING-003, FINDING-004, FINDING-005 | 13.4.1, 15.1.1, 15.2.1 |

## ASVS Control to Finding/PSC Mapping

| ASVS Control | Status | Findings | Positive Controls |
|--------------|--------|----------|-------------------|
| 1.2.5 | Pass | - | PSC-001, PSC-004, PSC-005 |
| 2.1.1 | Partial | FINDING-007 | PSC-014, PSC-023 |
| 2.2.1 | Fail | FINDING-001, FINDING-008, FINDING-009 | PSC-002, PSC-003, PSC-004, PSC-010, PSC-011, PSC-015, PSC-017, PSC-020, PSC-021, PSC-022, PSC-024 |
| 2.2.2 | Pass | - | PSC-018, PSC-019 |
| 2.3.1 | Partial | FINDING-010 | PSC-016, PSC-020 |
| 5.3.2 | Fail | FINDING-011 | PSC-022, PSC-023 |
| 12.2.2 | Partial | FINDING-002 | PSC-006 |
| 13.4.1 | Partial | FINDING-003 | PSC-008 |
| 14.2.1 | Partial | FINDING-012 | PSC-007, PSC-009 |
| 15.1.1 | Fail | FINDING-004 | PSC-012, PSC-025 |
| 15.2.1 | Fail | FINDING-005 | PSC-012 |
| 15.3.1 | Partial | FINDING-006, FINDING-013 | PSC-013 |

## Risk Heat Map

| Severity | Count | ASVS Controls Affected | Components Affected |
|----------|-------|------------------------|---------------------|
| High | 1 | 2.2.1 | qumat/qumat.py |
| Medium | 10 | 2.1.1, 2.2.1, 2.3.1, 5.3.2, 12.2.2, 13.4.1, 15.1.1, 15.2.1, 15.3.1 | qumat/qumat.py, qdp-core, loader.rs, documentation, build |
| Low | 2 | 14.2.1, 15.3.1 | URL handling, qumat/qumat.py |

**Total Findings**: 13  
**Total Positive Controls**: 25  
**ASVS Controls Assessed**: 85  
**Applicable ASVS Controls**: 15

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 13 |

**Total consolidated findings: 13**

*End of Consolidated Security Audit Report*