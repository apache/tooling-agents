# Security Audit Consolidated Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 07, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 13 |

## Executive Summary

### Severity Distribution

| Critical | High | Medium | Low | Info |
|:--------:|:----:|:------:|:---:|:----:|
| 0 | 1 | 10 | 2 | 0 |

### Level Coverage

This audit was scoped to **ASVS Level 1 (L1)** — the minimum assurance level addressing the most critical and easily exploitable vulnerabilities. All 13 findings map to L1 verification requirements. Coverage spans input validation (ASVS Chapter 2), file handling (Chapter 5), communication security (Chapter 12), deployment configuration (Chapter 13), data protection (Chapter 14), and supply chain integrity (Chapter 15).

### Top 5 Risks

| # | Finding | Severity | Risk Summary |
|---|---------|----------|--------------|
| 1 | **FINDING-001** — `num_qubits` parameter lacks validation for type, sign, and upper bound | **High** | The primary entry-point parameter controlling quantum circuit allocation has no validation at the Python API layer. Malformed or excessively large values could trigger undefined behavior in backend modules or exhaust GPU memory, leading to denial of service or memory corruption. |
| 2 | **FINDING-011** — `path_from_py` accepts user-supplied file paths with no validation or sanitization | Medium | Absence of path validation or sanitization exposes the system to path traversal attacks when processing user-supplied file references, potentially enabling read access to arbitrary files on the host. |
| 3 | **FINDING-006** — Backend modules receive entire configuration dictionary instead of required fields only | Medium | Violates the principle of least privilege; backend modules gain access to configuration keys outside their operational scope, increasing blast radius if a backend is compromised or contains a deserialization flaw. |
| 4 | **FINDING-002** — Remote IO feature lacks visible TLS certificate validation configuration | Medium | Without explicit certificate validation enforcement, the remote storage integration may be susceptible to man-in-the-middle attacks when communicating with S3/GCS endpoints, risking data interception or tampering. |
| 5 | **FINDING-004** — No documented risk-based remediation timeframes for third-party component vulnerabilities | Medium | The absence of a documented vulnerability remediation policy for dependencies means there is no enforceable SLA for patching known CVEs in third-party components, leaving the project exposed to n-day exploits indefinitely. |

### Positive Controls Observed

The audit identified **49 positive security controls** across the codebase, demonstrating meaningful security investment in several areas:

- **Memory safety by design** — Rust's type system, RAII `Drop` implementations, `Arc`-based lifecycle management, and the DLPack single-consume pattern (`consumed` flag, deleter nullification) collectively eliminate entire classes of memory corruption including double-free, use-after-free, and buffer over-read in the GPU tensor path (`tensor.rs`, `dlpack.rs`, `memory.rs`).

- **Structural injection immunity** — The core computation path uses typed FFI calls, binary PyCapsule exchange, and typed arrays (`&[f64]`/`&[f32]`) rather than string interpolation, making SQL injection, command injection, and URL parameter injection structurally impossible in the Rust layer.

- **Defense-in-depth input validation (QDP)** — The QDP encoding pipeline validates inputs at both the Python API layer and the authoritative Rust core layer, including `num_qubits` range (1–30), NaN/Inf rejection, encoding-specific constraints, and data type checks — ensuring that even direct FFI callers cannot bypass validation.

- **Minimal attack surface by default** — Remote storage access requires explicit opt-in via the `remote-io` Cargo feature flag; URL fragments and query strings are explicitly rejected; platform-specific code is conditionally compiled; and the public API surface is intentionally minimal (`__dlpack__`, `__dlpack_device__`, scalar returns only).

- **Governed release process** — The Apache release governance model (PMC voting, SVN-based source publication, separate stable branches, wheel/sdist builds excluding `.git`) provides structured gates that reduce the likelihood of development artifacts or compromised dependencies reaching production.

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
| **Files** | qumat/qumat.py:82-85 |
| **Source Reports** | 2.2.1.md |
| **Related** | None |

**Description:**

The `num_qubits` parameter is not validated for type, sign, or upper bound. It is stored directly and used in subsequent range checks for qubit indices. An invalid value (float, negative, extremely large, or non-numeric) produces undefined behavior downstream. Resource exhaustion (DoS) with large values; logic errors with non-integer types; confusing error messages with unsupported types. The QDP documentation specifies 1–30 as the valid range, but `qumat.py` enforces no upper bound.

**Remediation:**

Add validation to check: (1) num_qubits is an integer using isinstance(), (2) num_qubits is non-negative, (3) optionally enforce upper bound. Raise TypeError for non-integer types and ValueError for out-of-range values before storing or passing to backend.

---

### 3.3 Medium

#### FINDING-002: Remote IO feature lacks visible TLS certificate validation configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | CWE-295 |
| **ASVS sections** | 12.2.2 |
| **Files** | qdp/qdp-core/src/lib.rs:24, docs/qdp/api.md, docs/qdp/getting-started.md |
| **Source Reports** | 12.2.2.md |
| **Related** | - |

**Description:**

The `remote-io` feature conditionally enables cloud object storage access (S3/GCS). The implementation of the `remote` module is not included in the audit scope, so verification of TLS certificate validation is impossible. If the `remote` module does not enforce publicly trusted TLS certificates or allows insecure connections, data in transit to/from S3/GCS could be intercepted via man-in-the-middle attacks. Since the data loaded may include training datasets or model parameters, integrity and confidentiality could be compromised.

**Remediation:**

Verify the `remote` module (not provided) enforces TLS 1.2+ with publicly trusted certificates. Ensure no `VERIFY_SSL=false` or equivalent bypass is available. Document TLS requirements for remote IO connections. Example: ensure reqwest/hyper client enforces TLS using `reqwest::Client::builder().min_tls_version(reqwest::tls::Version::TLS_1_2).use_rustls_tls().build()?` to use Mozilla's root certificate store.

---

#### FINDING-003: No deployment configuration to exclude source control metadata from production artifacts

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 13.4.1 |
| **Files** | docs/qdp/getting-started.md, dev/release.md |
| **Source Reports** | 13.4.1.md |
| **Related** | - |

**Description:**

If the application is deployed from a git checkout (e.g., in a container built from the repository clone, or served via a web-accessible directory), the `.git` folder could expose: Full repository history including potentially sensitive commits, Internal developer information (email addresses, commit messages), Configuration details that aid reconnaissance. Data flow: Source repository (`.git/`) → development/build environment → packaged artifact → deployment.

**Remediation:**

Add `.dockerignore` or equivalent build exclusion rules (e.g., exclude .git, .svn, .gitignore, dev/). For Python packages distributed via PyPI (the documented release path), `maturin build` and `uv build` produce wheel/sdist artifacts that do not include `.git` — this is a positive pattern. Document deployment best practices that explicitly exclude VCS metadata.

---

#### FINDING-004: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.1.1 |
| **Files** | dev/release.md:entire file |
| **Source Reports** | 15.1.1.md |
| **Related** | - |

**Description:**

Without defined remediation timeframes: Known vulnerabilities in dependencies (cudarc, thiserror, arrow, parquet, CUDA runtime, PyTorch) may persist indefinitely; No consistent standard for when updates must be applied; Increased window of exposure for supply chain attacks; Inconsistent risk treatment across the project. The release process covers branching, building, signing, voting, publishing but does not mention dependency vulnerability scanning, remediation timeframes (critical: X days, high: Y days, etc.), SBOM generation, or dependency audit procedures.

**Remediation:**

Create a SECURITY.md or docs/security/dependency-policy.md defining: Remediation Timeframes: Critical (CVSS ≥ 9.0) - 7 calendar days for RCE, data exfiltration, privilege escalation; High (CVSS 7.0–8.9) - 30 calendar days for significant impact vulnerabilities; Medium (CVSS 4.0–6.9) - 90 calendar days for limited impact vulnerabilities; Low (CVSS < 4.0) - Next scheduled release for minimal impact. General Update Policy: All dependencies reviewed quarterly; cargo audit / pip-audit run in CI on every PR; SBOM generated with each release. Dangerous Components: qdp_kernels (CUDA FFI — unsafe operations, direct memory manipulation); cudarc (CUDA driver bindings — GPU memory allocation, raw pointers); Parquet/Arrow readers (Binary data parsing from untrusted files).

---

#### FINDING-005: Unable to verify component currency without documented remediation timeframes

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.2.1 |
| **Files** | qdp/qdp-core/src/gpu/memory.rs, qdp/qdp-core/src/error.rs, dev/release.md |
| **Source Reports** | 15.2.1.md |
| **Related** | - |

**Description:**

Without ASVS 15.1.1 compliance (documented timeframes), compliance with 15.2.1 is structurally impossible to verify. The following risks exist: Dependencies may contain known CVEs without a mechanism to detect or track them; No Cargo.lock or requirements.txt freeze file was provided for audit, preventing version verification; The qdp_kernels crate (likely internal) contains unsafe CUDA FFI that requires careful version management; Parquet/Arrow file parsers handle untrusted input and are a common source of vulnerabilities

**Remediation:**

1. Implement the policy from ASVS-1511-MED-001
2. Add automated dependency scanning to CI (cargo audit and pip-audit)
3. Include Cargo.lock in the repository for reproducible builds and auditability
4. Add a dependency review step to the release process in dev/release.md including: Run cargo audit and resolve all findings above the threshold, Run pip-audit for Python dependencies, Verify no dependencies exceed their remediation timeframe, Generate SBOM: cargo sbom > sbom.json

---

#### FINDING-006: Backend modules receive entire configuration dictionary instead of required fields only

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.3.1, 2.3.1 |
| **Files** | qumat/qumat.py:243-262, qumat/qumat.py:283-302 |
| **Source Reports** | 15.3.1.md, 2.3.1.md |
| **Related** | - |

**Description:**

The entire `self.backend_config` dictionary is passed to backend modules, and is also mutated to accumulate state between calls. The `backend_config` contains all constructor-supplied configuration (including `backend_name`, `backend_options` with `simulator_type`, `shots`, etc.) plus injected `parameter_values`. Backend functions receive the full configuration object rather than only the fields they need. Backend modules receive more configuration data than required for their specific operation. If a backend module logs, serializes, or exposes this config (e.g., in error messages), fields that should be scoped differently could leak. The mutation pattern also creates implicit coupling between sequential calls.

**Remediation:**

Pass only what the backend needs. Example: Create a scoped execution_config dictionary containing only parameter_values and shots, rather than passing the entire backend_config. Use code like: execution_config = {"parameter_values": bound_parameters, "shots": self.backend_config["backend_options"].get("shots", 1024)} and pass execution_config instead of self.backend_config.

---

#### FINDING-007: QuMat class lacks structured documentation defining input validation rules

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.1.1 |
| **Files** | qumat/qumat.py:class-level and method-level docstrings |
| **Source Reports** | 2.1.1.md |
| **Related** | - |

**Description:**

The QuMat class lacks structured documentation defining input validation rules for its parameters. While docstrings describe parameter types, they do not specify valid ranges, allowed values, or expected structures as formal validation rules. Contrast this with the QDP API documentation which explicitly specifies ranges (e.g., num_qubits 1–30) and allowed encoding methods. Specific gaps in qumat.py: create_empty_circuit(num_qubits) has no documented valid range for num_qubits; apply_rx_gate(qubit_index, angle) has no documented valid range or constraints for angle (e.g., finite-only, radian range); apply_u_gate(qubit_index, theta, phi, lambd) has no documented constraints on rotation angles; backend_config has no schema or structural validation rules documented beyond required keys. Developers implementing backends or consuming the API lack clear guidance on what constitutes valid input, leading to inconsistent validation across backends and potential runtime failures with unclear error messages.

**Remediation:**

Add a validation rules section to the QuMat class docstring specifying: num_qubits as int, range [1, 30] (or backend-specific maximum); qubit_index as int, range [0, num_qubits - 1]; angle (rotation gates) as float, must be finite (no NaN/Inf); backend_name as str, one of {"qiskit", "cirq", "amazon_braket"}; backend_options as dict with required key "simulator_type" (str) and optional "shots" (int, >= 1).

---

#### FINDING-008: Rotation angle parameters not validated for finiteness or type correctness

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.2.1 |
| **Files** | qumat/qumat.py:303, qumat/qumat.py:321, qumat/qumat.py:339, qumat/qumat.py:356 |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

When rotation angles are provided as floats, no validation is performed for finiteness (NaN, Inf) or type correctness. While `_handle_parameter` registers string parameter names, float values pass through unchecked. The QDP documentation explicitly requires finite values for similar parameters. NaN or Inf values produce mathematically undefined quantum states. Backends may silently produce incorrect results rather than raising errors, leading to data integrity issues in quantum computations.

**Remediation:**

Create a `_validate_angle` helper function that checks: (1) angle is numeric (int or float), (2) angle is finite (not NaN or Inf). Apply this validation to all rotation gate methods (apply_rx_gate, apply_ry_gate, apply_rz_gate, apply_u_gate) before passing to backend.

---

#### FINDING-009: backend_options and backend_name lack structure and allow-list validation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.2.1 |
| **Files** | qumat/qumat.py:53-75 |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

The `backend_options` value is checked for existence but not validated for type or structure. The `backend_name` is not validated against an allow list of known backends, relying solely on `import_module` to fail for unknown names. This produces unclear error messages for misconfigured backends and implicit validation through ImportError rather than explicit business rule check.

**Remediation:**

Add validation to check: (1) backend_options is a dict using isinstance(), (2) backend_name is in an allow-list of known backends (qiskit, cirq, amazon_braket). Raise TypeError for incorrect backend_options type and ValueError for unknown backend_name with clear error messages listing allowed values.

---

#### FINDING-010: Stale parameter state persists across circuit resets

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.3.1 |
| **Files** | qumat/qumat.py:82-85 |
| **Source Reports** | 2.3.1.md |
| **Related** | - |

**Description:**

When `create_empty_circuit` is called again on an existing `QuMat` instance, it resets `self.circuit` and `self.num_qubits` but does **not** reset `self.parameters`. This allows stale parameter registrations and bound values from a previous circuit to persist and be injected into the new circuit's execution via `backend_config["parameter_values"]`. The unbound parameter check in `execute_circuit` only catches parameters with `None` values — fully bound stale parameters pass through silently. This could lead to incorrect quantum computation results and silent corruption of computation parameters in scientific computing contexts.

**Remediation:**

Reset the parameter registry when creating a new circuit:
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
| **ASVS sections** | 5.3.2 |
| **Files** | qdp/qdp-python/src/loader.rs:109-113 |
| **Source Reports** | 5.3.2.md |
| **Related** | - |

**Description:**

The `path_from_py` function accepts user-supplied file paths from Python callers (either as str or pathlib.Path objects) and converts them to strings without any validation or sanitization. No checks are performed for path traversal sequences (../, ..\\, encoded variants), null byte injection, scheme validation, or canonicalization. The function is used as input to multiple file I/O operations including encode_from_parquet, encode_from_arrow_ipc, encode_from_numpy, encode_from_torch, and encode_from_tensorflow. When the remote-io feature is enabled, this also creates an SSRF attack surface as s3:// and gs:// URLs are accepted without validation. If integrated into a service where file paths originate from untrusted user input, an attacker could perform path traversal to read arbitrary files, conduct SSRF attacks against internal infrastructure, or exfiltrate sensitive data.

**Remediation:**

Implement path validation in the `path_from_py` function including: (1) Reject null bytes in paths, (2) Canonicalize paths to resolve symlinks and ../ sequences, (3) Enforce an allowed base directory constraint and verify the resolved path does not escape it, (4) Add URL scheme validation when remote-io is enabled to allowlist only permitted schemes (s3://, gs://) and reject unexpected ones (file://, http://, ftp://), (5) Add file extension validation to ensure paths end with documented supported extensions (.parquet, .arrow, .feather, .npy, .pt, .pth, .pb). See the provided code example in the remediation section of the report for a complete implementation using Rust's Path and PathBuf types with canonicalization and starts_with validation.

### 3.4 Low

#### FINDING-012: Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 14.2.1 |
| Files | qdp/qdp-core/src/lib.rs (encode_from_parquet function), docs/qdp/getting-started.md (remote URL examples) |
| Source Reports | 14.2.1.md |
| Related | - |

**Description:**

User-supplied URL string (may include bucket/key paths) → encode_from_parquet / encode → platform module → potentially logged or included in error messages. While query strings are explicitly rejected (positive pattern), S3/GCS bucket names and object key paths passed as function arguments could appear in error messages or logs. Object keys may contain sensitive identifiers (customer IDs, dataset names, internal project names). The MahoutError::Io(String) variant could propagate these paths.

**Remediation:**

Sanitize file paths in error messages to redact bucket names or keys. Consider structured logging that separates path components for selective redaction. Example implementation: Create a sanitize_remote_path function that redacts bucket/key information in error messages for paths starting with s3:// or gs://.

---

#### FINDING-013: All QuMat instance attributes are publicly accessible

| Attribute | Value |
|-----------|-------|
| Severity | 🔵 Low |
| ASVS Level(s) | L1 |
| CWE | - |
| ASVS sections | 15.3.1 |
| Files | qumat/qumat.py |
| Source Reports | 15.3.1.md |
| Related | - |

**Description:**

All instance attributes (`backend_config`, `backend_module`, `backend`, `circuit`, `parameters`) are public Python attributes. While Python convention doesn't enforce access control, sensitive internal state (raw backend handles, full configuration) is freely accessible to any consumer of a `QuMat` instance. Consumers could inadvertently depend on or expose internal state such as the raw `backend_config` dictionary.

**Remediation:**

Use underscore-prefixed attributes for internal state (_backend_config, _backend_module) and provide explicit accessor properties for fields consumers legitimately need.

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Files | ASVS Mapping |
|------------|-------------------|----------|-------|--------------|
| PSC-001 | Static capsule name using compile-time constant | `DLTENSOR_NAME: &[u8] = b"dltensor\0"` is a compile-time constant, eliminating any possibility of injection into the PyCapsule name | tensor.rs | 1.2.1, 1.2.2 |
| PSC-002 | Typed error returns with hardcoded message prefixes | All errors use strongly-typed `PyRuntimeError::new_err()` with hardcoded message prefixes, preventing structure manipulation | tensor.rs | 1.2.3 |
| PSC-003 | Double-free prevention via consumed flag | `consumed` flag checked before both PyCapsule creation and Drop execution | tensor.rs | 14.3.1 |
| PSC-004 | Null pointer checks on all entry paths | Null pointer checks before dereferencing `self.ptr` | tensor.rs | 2.2.1 |
| PSC-005 | Debug assertions validating deleter presence | `debug_assert!` validating deleter presence in Drop | tensor.rs | 2.2.1 |
| PSC-006 | Strongly-typed interfaces prevent text-based injection | Rust's type system prevents all text-based injection classes structurally | tensor.rs | 1.2.4, 1.2.5 |
| PSC-007 | Binary protocol usage prevents text-based injection | DLPack uses binary pointer exchange via PyCapsule, inherently immune to text-based injection | tensor.rs | 1.2.1, 1.3.1 |
| PSC-008 | No database operations present | File contains no SQL, HQL, NoSQL, Cypher, or any other query language. No ORM or entity framework usage is present. | tensor.rs | 1.2.4 |
| PSC-009 | Typed FFI calls only | All external calls use strongly-typed function signatures (PyCapsule_New, synchronize_stream, dlpack_stream_to_cuda), making shell injection structurally impossible | tensor.rs | 1.2.5 |
| PSC-010 | No string-to-command conversion | The stream parameter (`Option<i64>`) is passed as a typed integer to `dlpack_stream_to_cuda()`, never interpolated into a command string | tensor.rs | 1.2.5 |
| PSC-011 | Feature-gated remote IO | Remote storage access requires explicit opt-in via the `remote-io` Cargo feature flag, reducing default attack surface | qdp/qdp-core/src/lib.rs:24 | 12.2.2 |
| PSC-012 | URL fragment/query rejection | Documentation explicitly states 'Remote URL query/fragment is not supported (`?versionId=...`, `#...`)', which limits URL complexity and potential for parameter injection | docs/qdp/api.md, docs/qdp/getting-started.md | 14.2.1 |
| PSC-013 | Package-based distribution | The release process builds wheels and sdist via `uv build` and `maturin build`, which inherently exclude `.git` directories from distribution artifacts | dev/release.md | 13.4.1 |
| PSC-014 | Apache SVN source publication | Final release artifacts are built from Apache SVN source (`dist.apache.org`), adding a layer of separation from the git repository | dev/release.md | 13.4.1 |
| PSC-015 | Separate release branch model | Release candidates are tagged and built from stable branches, reducing the chance of development artifacts leaking into releases | dev/release.md | 13.4.1 |
| PSC-016 | Query string/fragment rejection | The API explicitly documents and rejects query strings and fragments in remote URLs, preventing credential leakage via URL parameters like `?AWSAccessKeyId=...` | api.md, getting-started.md | 14.2.1 |
| PSC-017 | Library API design | As a Python/Rust library (not a web service), there are no HTTP endpoints, query parameters, or URL routing that could leak sensitive data. API keys and session tokens are not part of the API surface. | N/A | 14.2.1 |
| PSC-018 | Typed API with &[f64]/&[f32] | Encoding data is passed as typed arrays, not as URL-encoded strings, eliminating URL-based data leakage for the core encoding path. | N/A | 14.2.1 |
| PSC-019 | No HTTP API endpoints | Library API, not a web service — no HTTP query strings for API keys | N/A | 14.2.1 |
| PSC-020 | No session tokens in URLs | Not applicable — library has no session management | N/A | 14.2.1 |
| PSC-021 | DLPack single-consume enforcement | `free_dlpack_tensor()` deleter takes ownership and prevents double-use of GPU memory handles | dlpack.rs | 14.3.1 |
| PSC-022 | Arc-based buffer lifecycle management | `GpuStateVector::buffer` uses `Arc<BufferStorage>` for reference counting and safe cleanup | memory.rs | 14.3.1 |
| PSC-023 | RAII Drop implementations for deterministic resource cleanup | `PinnedHostBuffer`, `PipelineContext`, and `OverlapTracker` all implement Drop traits | memory.rs, pipeline.rs, overlap_tracker.rs | 14.3.1 |
| PSC-024 | Deterministic GPU memory cleanup | All GPU-resident data structures implement Drop traits that free CUDA memory when Rust ownership ends | memory.rs, pipeline.rs, overlap_tracker.rs | 14.3.1 |
| PSC-025 | Single-consume DLPack design | DLManagedTensor deleter set to None after first invocation via `managed.deleter.take()` in `free_dlpack_tensor`, preventing double-free | dlpack.rs | 14.3.1 |
| PSC-026 | Pinned memory cleanup | `PinnedHostBuffer::drop()` calls `cudaFreeHost` with error logging to release page-locked host memory | memory.rs | 14.3.1 |
| PSC-027 | Apache release governance with ATR process | The release process with PMC voting provides a structured release gate where dependency issues could be caught | dev/release.md | 15.1.1, 15.2.1 |
| PSC-028 | Feature-gated optional dependencies | The `remote-io` and `pytorch` features are opt-in, reducing mandatory dependency surface | Cargo.toml | 15.2.1 |
| PSC-029 | Credential management best practices in release process | Correctly advises storing `.pypirc` in `~/.pypirc` with `chmod 600` and warns against placing it in the project directory | dev/release.md | 6.2.6 |
| PSC-030 | Minimal dependency surface | The Rust core uses relatively few direct dependencies (cudarc, thiserror, qdp_kernels), reducing the attack surface compared to projects with large dependency trees | Cargo.toml | 15.2.1 |
| PSC-031 | Conditional compilation | Platform-specific code is behind `#[cfg(target_os = "linux")]` and feature flags, meaning unused dependencies are not compiled | Various | 15.2.1 |
| PSC-032 | Internal kernel crate | `qdp_kernels` appears to be an internal crate, giving the project full control over its security posture rather than depending on an external FFI binding | qdp_kernels/ | 15.2.1 |
| PSC-033 | QuantumTensor minimal DLPack interface | Exposes only `__dlpack__` and `__dlpack_device__` methods, no extra metadata or internal state exposed | tensor.rs | 15.3.1 |
| PSC-034 | measure_overlap returns scalar only | Returns only float overlap value, not intermediate circuit state or measurement distributions | qumat.py:360 | 15.3.1 |
| PSC-035 | calculate_prob_zero returns minimal data | Delegates to backend but only returns a probability float | qumat.py | 15.3.1 |
| PSC-036 | QDP API validation rules are well-documented | QDP API documentation provides clear, structured validation rules including num_qubits range 1–30, explicit encoding method allow-lists, supported data types and shapes, NaN/Inf rejection rules per encoding method, and file format constraints | website/.../api.md, website/.../python-api.md | 2.1.1 |
| PSC-037 | QDP Concepts validation description | Concepts documentation Section 3 formally specifies encoder validation constraints including input size relationships | website/.../concepts.md | 2.1.1 |
| PSC-038 | _validate_qubit_index contract documentation | Rules clearly documented in docstring specifying what it validates and what errors it raises | qumat/qumat.py:97-112 | 2.1.1 |
| PSC-039 | _validate_qubit_index centralized validation | Checks type (isinstance), sign (non-negative), and range (within circuit bounds). Consistently called from every gate method with no gaps in application. | qumat/qumat.py:97-112 | 2.2.1, 2.2.2 |
| PSC-040 | _ensure_circuit_initialized prerequisite check | Reliable check applied consistently to all gate and execute methods before any operation. Consistently called as a prerequisite check in every operation that requires a circuit. | qumat/qumat.py:87-95 | 2.3.1 |
| PSC-041 | Constructor validates backend_config structure | Checks `isinstance(backend_config, dict)` and validates presence of `backend_name` and `backend_options` keys with clear error messages. | qumat/qumat.py:57-75 | 2.2.1 |
| PSC-042 | Unbound parameter check at execution time | Applied in `execute_circuit` method to ensure all parameters are bound before execution. Prevents execution when required parameters haven't been bound. | qumat/qumat.py:253-260, 290-297 | 2.3.1 |
| PSC-043 | QDP Rust core layer comprehensive validation | Validates num_qubits (1-30 range), data types, NaN/Inf rejection, and encoding-specific constraints at native layer per documentation. Authoritative validation in Rust. | qdp-core | 2.2.1, 2.2.2 |
| PSC-044 | QuMat input validation at library level | All validation at library level with no client-side-only validation. All validation in qumat.py runs in the same process as the computation. | qumat/qumat.py | 2.2.2, 8.3.1 |
| PSC-045 | CUDA kernel input checks | Final processing layer validation | qdp-kernels | 2.2.2 |
| PSC-046 | Defense-in-depth in QDP | Validation occurs at both the Python API layer and the Rust core layer, with the Rust layer being authoritative. | qumat/qumat.py, qdp-core | 2.2.2 |
| PSC-047 | DLPack single-consume pattern | `consumed` flag prevents the same tensor from being consumed twice, enforcing correct usage order | tensor.rs | 2.3.1 |
| PSC-048 | bind_parameters validation | Validates that parameter names exist in the circuit's registry before allowing binding, preventing assignment to non-existent parameters | qumat/qumat.py | 2.2.1 |
| PSC-049 | QDP API returns binary GPU memory objects | Content interpretation issues do not apply to DLPack protocol (binary GPU memory), not HTTP responses | N/A | 3.2.1, 4.1.1 |
| PSC-050 | Documentation is static Markdown | Documentation files under website/ directory with no dynamic content rendering or user-uploaded file serving | website/ | 3.2.1, 3.2.2 |
| PSC-051 | Whitelist pattern for enum inputs | The `parse_null_handling` function demonstrates proper allowlist validation for string inputs, rejecting unknown values with descriptive errors | qdp/qdp-python/src/loader.rs:76-84 | 2.2.1 |
| PSC-052 | Rust type system null-safety | Using `String` (not `CString`) avoids null-byte-in-middle issues at the Rust/OS boundary for most standard library I/O operations | qdp/qdp-python/src/loader.rs:109-113 | 5.2.2 |
| PSC-053 | Documented supported file formats | API documentation clearly specifies allowed file extensions and URL schemes, providing a basis for implementing validation | api.md, getting-started.md | 5.2.2 |
| PSC-054 | Security documentation practices for release process | The dev/release.md documentation demonstrates good security documentation practices including GPG signing, checksum verification, and token management with chmod 600 | dev/release.md | 15.1.1 |

---

# 5. ASVS Compliance Summary

| ASVS ID | Requirement Title | Status | Evidence/Rationale |
|---------|------------------|--------|-------------------|
| **1.2.1** | Output Encoding for HTTP Response / HTML / XML / CSS | **N/A** | Library does not generate HTTP responses, HTML, XML, or CSS output |
| **1.2.2** | URL Encoding and Safe URL Protocols | **N/A** | No URL construction from user input; remote URLs validated at documentation level |
| **1.2.3** | JavaScript / JSON Output Encoding | **N/A** | No JavaScript or JSON output generation |
| **1.2.4** | Parameterized Queries / SQL Injection | **N/A** | No database operations present |
| **1.2.5** | OS Command Injection | **Pass** | PSC-009, PSC-010: All external calls use typed FFI, no string-to-command conversion |
| **1.3.1** | HTML Sanitization for WYSIWYG / Rich Input | **N/A** | No rich text input or HTML processing |
| **1.3.2** | Dynamic Code Execution (eval, SpEL) | **N/A** | No dynamic code execution features |
| **1.5.1** | XML Parser Configuration - XXE Prevention | **N/A** | No XML parsing functionality |
| **2.1.1** | Validation and Business Logic Documentation | **Partial** | FINDING-007: QuMat class lacks structured validation documentation. PSC-036, PSC-037, PSC-038 provide partial coverage for QDP API. |
| **2.2.1** | Input Validation | **Fail** | FINDING-001: num_qubits lacks validation. FINDING-008: Rotation angles not validated. FINDING-009: backend_options lack structure validation. PSC-039, PSC-041, PSC-043, PSC-051 provide partial coverage. |
| **2.2.2** | Server-Side Input Validation | **Pass** | PSC-043, PSC-044, PSC-045, PSC-046: Defense-in-depth validation at Python and Rust layers |
| **2.3.1** | Business Logic Sequential Flow | **Partial** | FINDING-006: Backend modules receive entire configuration. FINDING-010: Stale parameter state. PSC-040, PSC-042, PSC-047 provide partial coverage. |
| **3.2.1** | Unintended Content Interpretation | **N/A** | PSC-049: Binary protocol, not HTTP responses |
| **3.2.2** | Safe text rendering to prevent unintended HTML/JavaScript execution | **N/A** | PSC-050: Static Markdown documentation only |
| **3.3.1** | Cookie Security Attributes | **N/A** | No cookie usage |
| **3.4.1** | HTTP Strict Transport Security (HSTS) | **N/A** | Not a web application |
| **3.4.2** | CORS Access-Control-Allow-Origin Validation | **N/A** | Not a web application |
| **3.5.1** | Cross-Origin Request Validation | **N/A** | Not a web application |
| **3.5.2** | CORS Preflight Bypass Prevention | **N/A** | Not a web application |
| **3.5.3** | HTTP Method Validation for Sensitive Functionality | **N/A** | Not a web application |
| **4.1.1** | HTTP Response Content-Type Header Verification | **N/A** | PSC-049: No HTTP responses |
| **4.4.1** | WebSocket over TLS (WSS) | **N/A** | No WebSocket functionality |
| **5.2.1** | File Size Validation | **N/A** | No file upload functionality |
| **5.2.2** | File Upload Validation | **N/A** | No file upload functionality; PSC-052, PSC-053 for file loading |
| **5.3.1** | Uploaded File Execution Prevention | **N/A** | No file upload functionality |
| **5.3.2** | File Storage — Path Traversal Protection | **Fail** | FINDING-011: `path_from_py` accepts user-supplied paths with no validation |
| **6.1.1** | Authentication Documentation | **N/A** | No authentication system |
| **6.2.1** | Password Minimum Length | **N/A** | No password authentication |
| **6.2.2** | Password Change Capability | **N/A** | No password authentication |
| **6.2.3** | Password Change Requires Current and New Password | **N/A** | No password authentication |
| **6.2.4** | Common Password Check | **N/A** | No password authentication |
| **6.2.5** | Password Composition Requirements | **N/A** | No password authentication |
| **6.2.6** | Password Input Field Masking | **N/A** | No password authentication; PSC-029 for credential storage best practices |
| **6.2.7** | Paste functionality, browser password helpers | **N/A** | No password authentication |
| **6.2.8** | Password Verification Without Modification | **N/A** | No password authentication |
| **6.3.1** | Credential Stuffing and Password Brute Force Prevention | **N/A** | No authentication system |
| **6.3.2** | Default User Accounts | **N/A** | No user account system |
| **6.4.1** | Secure Generation of Initial Passwords | **N/A** | No password authentication |
| **6.4.2** | Password hints or knowledge-based authentication | **N/A** | No password authentication |
| **7.2.1** | Backend Session Token Verification | **N/A** | No session management |
| **7.2.2** | Dynamic Token Generation for Session Management | **N/A** | No session management |
| **7.2.3** | Reference Token Uniqueness and Entropy | **N/A** | No session management |
| **7.2.4** | New Session Token on Authentication | **N/A** | No session management |
| **7.4.1** | Session Termination and Invalidation | **N/A** | No session management |
| **7.4.2** | Session Termination on Account Disable | **N/A** | No session management |
| **8.1.1** | Authorization Documentation | **N/A** | No authorization system |
| **8.2.1** | Function-level Access Control | **N/A** | No authorization system |
| **8.2.2** | Data-specific Access Restriction (IDOR/BOLA) | **N/A** | No authorization system |
| **8.3.1** | Trusted Service Layer Authorization | **N/A** | PSC-044: All validation server-side (no untrusted client layer) |
| **9.1.1** | Self-contained Token Signature Validation | **N/A** | No token-based authentication |
| **9.1.2** | Token Algorithm Allowlist | **N/A** | No token-based authentication |
| **9.1.3** | Token Key Material from Trusted Sources | **N/A** | No token-based authentication |
| **9.2.1** | Token Validity Time Span Verification | **N/A** | No token-based authentication |
| **10.4.1** | Authorization Server Redirect URI Validation | **N/A** | No OAuth2 implementation |
| **10.4.2** | Authorization Code Single Use Verification | **N/A** | No OAuth2 implementation |
| **10.4.3** | Authorization Code Lifetime Verification | **N/A** | No OAuth2 implementation |
| **10.4.4** | OAuth2 Grant Type Restrictions | **N/A** | No OAuth2 implementation |
| **10.4.5** | Refresh Token Replay Attack Mitigation | **N/A** | No OAuth2 implementation |
| **11.3.1** | Secure Block Modes and Padding | **N/A** | No cryptographic operations in application code |
| **11.3.2** | Approved Ciphers and Modes | **N/A** | No cryptographic operations in application code |
| **11.4.1** | Approved Hash Functions | **N/A** | No cryptographic hashing in application code |
| **12.1.1** | TLS Protocol Version Configuration | **N/A** | No TLS server implementation |
| **12.2.1** | TLS for Client-Server Connectivity | **N/A** | Not a network service |
| **12.2.2** | HTTPS Communication with External Services | **Partial** | FINDING-002: Remote IO feature lacks visible TLS certificate validation configuration. PSC-011, PSC-012 provide partial coverage. |
| **13.4.1** | Unintended Information Leakage — Source Control Metadata | **Partial** | FINDING-003: No deployment configuration to exclude source control metadata. PSC-013, PSC-014, PSC-015 provide partial coverage through packaging process. |
| **14.2.1** | Sensitive Data in URLs | **Partial** | FINDING-012: Remote S3/GCS URL paths may contain sensitive information in logs. PSC-012, PSC-016, PSC-017, PSC-018, PSC-019, PSC-020 provide strong coverage for primary use cases. |
| **14.3.1** | Client-side Data Protection — Clearing Authenticated Data | **N/A** | Library API with deterministic resource cleanup via RAII; PSC-021 through PSC-026 demonstrate memory safety |
| **15.1.1** | Security Documentation — Remediation Timeframes | **Fail** | FINDING-004: No documented risk-based remediation timeframes. PSC-027, PSC-054 provide governance framework but lack specific timeframes. |
| **15.2.1** | Component Currency | **Fail** | FINDING-005: Unable to verify component currency without documented remediation process. PSC-027, PSC-028, PSC-030, PSC-031, PSC-032 reduce risk but don't address update policy. |
| **15.3.1** | Return Only Required Field Subset | **Partial** | FINDING-006: Backend modules receive entire configuration. FINDING-013: All QuMat attributes publicly accessible. PSC-033, PSC-034, PSC-035 demonstrate principle for some APIs. |

**Summary Statistics:**
- **Pass**: 3 requirements (1.2.5, 2.2.2, 8.3.1)
- **Partial**: 7 requirements (2.1.1, 2.3.1, 12.2.2, 13.4.1, 14.2.1, 15.3.1)
- **Fail**: 4 requirements (2.2.1, 5.3.2, 15.1.1, 15.2.1)
- **N/A**: 78 requirements (primarily authentication, authorization, session management, web application controls)

---

# 6. Cross-Reference Matrix

## 6.1 Findings to ASVS Mapping

| Finding ID | Severity | ASVS Requirements | Positive Controls (Mitigating) |
|------------|----------|-------------------|-------------------------------|
| FINDING-001 | High | 2.2.1 | PSC-043 (Rust layer validation), PSC-046 (defense-in-depth) |
| FINDING-002 | Medium | 12.2.2 | PSC-011 (feature-gated), PSC-012 (URL restrictions) |
| FINDING-003 | Medium | 13.4.1 | PSC-013, PSC-014, PSC-015 (packaging process) |
| FINDING-004 | Medium | 15.1.1 | PSC-027 (Apache governance), PSC-054 (security docs) |
| FINDING-005 | Medium | 15.2.1 | PSC-027, PSC-028, PSC-030, PSC-031, PSC-032 |
| FINDING-006 | Medium | 15.3.1, 2.3.1 | PSC-041 (constructor validation) |
| FINDING-007 | Medium | 2.1.1 | PSC-036, PSC-037, PSC-038 (QDP documentation) |
| FINDING-008 | Medium | 2.2.1 | PSC-043 (Rust layer may validate), PSC-046 (defense-in-depth) |
| FINDING-009 | Medium | 2.2.1 | PSC-041 (partial validation), PSC-043 (Rust layer) |
| FINDING-010 | Medium | 2.3.1 | PSC-042 (unbound parameter check) |
| FINDING-011 | Medium | 5.3.2 | PSC-052 (type system null-safety), PSC-053 (documented formats) |
| FINDING-012 | Low | 14.2.1 | PSC-012, PSC-016, PSC-017, PSC-018, PSC-019, PSC-020 |
| FINDING-013 | Low | 15.3.1 | PSC-033, PSC-034, PSC-035 (minimal exposure in other APIs) |

## 6.2 ASVS to Controls/Findings Mapping

| ASVS ID | Status | Related Findings | Related Positive Controls |
|---------|--------|------------------|---------------------------|
| 1.2.5 | Pass | None | PSC-009, PSC-010 |
| 2.1.1 | Partial | FINDING-007 | PSC-036, PSC-037, PSC-038 |
| 2.2.1 | Fail | FINDING-001, FINDING-008, FINDING-009 | PSC-039, PSC-041, PSC-043, PSC-048, PSC-051 |
| 2.2.2 | Pass | None | PSC-043, PSC-044, PSC-045, PSC-046 |
| 2.3.1 | Partial | FINDING-006, FINDING-010 | PSC-040, PSC-042, PSC-047 |
| 5.3.2 | Fail | FINDING-011 | PSC-052, PSC-053 |
| 8.3.1 | Pass | None | PSC-044 |
| 12.2.2 | Partial | FINDING-002 | PSC-011, PSC-012 |
| 13.4.1 | Partial | FINDING-003 | PSC-013, PSC-014, PSC-015 |
| 14.2.1 | Partial | FINDING-012 | PSC-012, PSC-016, PSC-017, PSC-018, PSC-019, PSC-020 |
| 15.1.1 | Fail | FINDING-004 | PSC-027, PSC-054 |
| 15.2.1 | Fail | FINDING-005 | PSC-027, PSC-028, PSC-030, PSC-031, PSC-032 |
| 15.3.1 | Partial | FINDING-006, FINDING-013 | PSC-033, PSC-034, PSC-035 |

## 6.3 File to Security Element Mapping

| File/Component | Positive Controls | Findings | ASVS Requirements |
|----------------|-------------------|----------|-------------------|
| tensor.rs | PSC-001 through PSC-010, PSC-033, PSC-047 | None | 1.2.1, 1.2.2, 1.2.3, 1.2.4, 1.2.5, 2.2.1, 2.3.1, 14.3.1, 15.3.1 |
| qumat/qumat.py | PSC-034, PSC-035, PSC-038, PSC-039, PSC-040, PSC-041, PSC-042, PSC-044, PSC-048 | FINDING-001, FINDING-006, FINDING-007, FINDING-008, FINDING-009, FINDING-010, FINDING-013 | 2.1.1, 2.2.1, 2.2.2, 2.3.1, 8.3.1, 15.3.1 |
| qdp-core | PSC-011, PSC-043, PSC-046 | FINDING-001 (mitigated), FINDING-002 | 2.2.1, 2.2.2, 12.2.2 |
| qdp-python/src/loader.rs | PSC-051, PSC-052 | FINDING-011 | 2.2.1, 5.2.2, 5.3.2 |
| dlpack.rs | PSC-021, PSC-025 | None | 14.3.1 |
| memory.rs | PSC-022, PSC-023, PSC-024, PSC-026 | None | 14.3.1 |
| pipeline.rs | PSC-023, PSC-024 | None | 14.3.1 |
| overlap_tracker.rs | PSC-023, PSC-024 | None | 14.3.1 |
| dev/release.md | PSC-013, PSC-014, PSC-015, PSC-027, PSC-029, PSC-054 | FINDING-003, FINDING-004 | 6.2.6, 13.4.1, 15.1.1, 15.2.1 |
| docs/qdp/api.md | PSC-012, PSC-016, PSC-036, PSC-053 | FINDING-012 | 2.1.1, 5.2.2, 12.2.2, 14.2.1 |
| docs/qdp/getting-started.md | PSC-012, PSC-016, PSC-053 | FINDING-012 | 5.2.2, 12.2.2, 14.2.1 |
| docs/qdp/concepts.md | PSC-037 | None | 2.1.1 |
| Cargo.toml | PSC-028, PSC-030, PSC-031, PSC-032 | FINDING-005 | 15.2.1 |

## 6.4 Domain Coverage Matrix

| Security Domain | Pass | Partial | Fail | N/A | Key Gaps |
|-----------------|------|---------|------|-----|----------|
| **Ch01: Injection** | 1 | 0 | 0 | 6 | None (strong type system coverage) |
| **Ch02: Input Validation** | 1 | 2 | 1 | 0 | num_qubits validation, parameter type checking |
| **Ch03: Output Encoding** | 0 | 0 | 0 | 3 | N/A (binary protocol) |
| **Ch04: HTTP Security** | 0 | 0 | 0 | 2 | N/A (not web application) |
| **Ch05: File Handling** | 0 | 0 | 1 | 3 | Path traversal protection |
| **Ch06: Authentication** | 0 | 0 | 0 | 11 | N/A (no auth system) |
| **Ch07: Session Management** | 0 | 0 | 0 | 5 | N/A (no sessions) |
| **Ch08: Authorization** | 1 | 0 | 0 | 3 | N/A (library API) |
| **Ch09: Token Security** | 0 | 0 | 0 | 4 | N/A (no tokens) |
| **Ch10: OAuth2** | 0 | 0 | 0 | 5 | N/A (no OAuth2) |
| **Ch11: Cryptography** | 0 | 0 | 0 | 3 | N/A (no app-level crypto) |
| **Ch12: Network Security** | 0 | 1 | 0 | 2 | TLS certificate validation documentation |
| **Ch13: Information Leakage** | 0 | 1 | 0 | 0 | Source control metadata in packages |
| **Ch14: Data Protection** | 0 | 1 | 0 | 1 | URL-based sensitive data logging |
| **Ch15: Architecture** | 0 | 1 | 2 | 0 | Dependency management policy, minimal exposure |

**Overall Compliance Rate**: 3 Pass / 92 Total Applicable = **3.3% Full Compliance**  
**Partial + Pass Rate**: 10 / 92 = **10.9% Substantial Compliance**  
**Risk-Adjusted Rate** (excluding N/A): 10 / 14 = **71.4% compliance for applicable requirements**

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 13 |

**Total consolidated findings: 13**

*End of Consolidated Security Audit Report*