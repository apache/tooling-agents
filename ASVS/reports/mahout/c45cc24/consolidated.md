# Security Audit Consolidated Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | May 06, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 13 |

## Executive Summary

This consolidated report synthesizes findings from 70 individual source reports covering all directories within the `apache/tooling-runbooks` repository, evaluated against OWASP ASVS Level 1 controls. The audit identified **13 findings** across multiple security domains, with no critical-severity issues discovered.

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | 0 | 0.0% |
| High | 1 | 7.7% |
| Medium | 10 | 76.9% |
| Low | 2 | 15.4% |
| Info | 0 | 0.0% |

### Level Coverage

All 13 findings map to **ASVS Level 1** controls, confirming that the audit scope was fully exercised. The findings span the following ASVS requirement families:

- **V2 – Input Validation** (7 findings): 2.1.1, 2.2.1 ×3, 2.3.1 ×2
- **V5 – Validation, Sanitization & Encoding** (1 finding): 5.3.2
- **V12 – Files & Resources** (1 finding): 12.2.2
- **V13 – API & Web Service** (1 finding): 13.4.1
- **V14 – Configuration** (1 finding): 14.2.1
- **V15 – Supply Chain** (2 findings): 15.1.1, 15.2.1

### Top 5 Risks

1. **Unvalidated `num_qubits` parameter (FINDING-001, High)** – The primary constructor parameter for quantum circuit initialization lacks type checking, sign validation, and upper-bound enforcement. An attacker or erroneous caller could trigger unbounded memory allocation, denial of service, or undefined behavior in downstream GPU operations.

2. **Missing TLS certificate validation configuration for remote IO (FINDING-002, Medium)** – The remote storage feature (S3/GCS) exposes no visible or documented TLS certificate pinning or validation configuration, potentially allowing man-in-the-middle attacks when fetching data from cloud object stores.

3. **No documented remediation timeframes for third-party vulnerabilities (FINDING-004, Medium)** – The absence of a risk-based policy for patching third-party component vulnerabilities leaves the project without a measurable SLA for addressing known CVEs in dependencies.

4. **Backend modules receive full configuration objects (FINDING-006, Medium)** – Passing the entire configuration structure to backend modules violates the principle of least privilege, expanding the data surface accessible to each component and increasing the blast radius of any single-module compromise.

5. **User-supplied file paths accepted without validation (FINDING-011, Medium)** – The `path_from_py` utility accepts arbitrary user-supplied file paths with no sanitization, canonicalization, or allowlist enforcement, creating a potential path traversal vector.

### Positive Controls Observed

The audit identified **33 positive security controls** already implemented across the codebase, demonstrating meaningful defense-in-depth:

| Category | Representative Controls |
|----------|------------------------|
| **Memory Safety** | Double-free prevention via consumed flag; Arc-based buffer lifecycle; RAII Drop implementations for deterministic resource cleanup; null pointer checks on all entry paths |
| **Injection Prevention** | Static capsule name using compile-time constant; strongly-typed FFI calls; binary DLPack protocol inherently immune to text-based injection; Rust type system structurally prevents injection classes |
| **Input Validation** | `_validate_qubit_index` centralized validation applied to every gate method; `parse_null_handling` allowlist pattern; QDP Rust encoder authoritative validation; documented API validation rules |
| **Attack Surface Reduction** | Feature-gated remote IO (opt-in via Cargo feature flag); URL fragment/query rejection; minimal dependency surface; QuantumTensor minimal DLPack interface |
| **Supply Chain & Release** | Apache release governance with ATR process and PMC voting; GPG signing and checksum verification; package-based distribution excluding `.git` metadata; Apache SVN source publication separation |
| **State Management** | `_ensure_circuit_initialized` enforces create-before-operate sequencing; unbound parameter check prevents execution with None-valued parameters; DLPack single-consume enforcement |

These controls significantly mitigate risk in areas such as memory corruption, injection, and supply chain integrity, and reflect a security-conscious engineering culture particularly within the Rust FFI and GPU memory management layers.

---

## 3. Findings

### 3.2 High

#### FINDING-001: num_qubits parameter lacks validation for type, sign, and upper bound

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS Sections** | 2.2.1 |
| **Files** | qumat/qumat.py:82-85 |
| **Source Reports** | 2.2.1.md |
| **Related** | - |

**Description:**

The `num_qubits` parameter is not validated for type, sign, or upper bound. It is stored directly and used in subsequent range checks for qubit indices. An invalid value (float, negative, extremely large, or non-numeric) produces undefined behavior downstream. The QDP documentation specifies 1–30 as the valid range, but `qumat.py` enforces no upper bound. This can lead to resource exhaustion (DoS) with large values, logic errors with non-integer types, and confusing error messages with unsupported types.

**Remediation:**

Add validation to check that num_qubits is an integer, non-negative, and within a reasonable upper bound. Example implementation:
```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    if num_qubits is not None:
        if not isinstance(num_qubits, int):
            raise TypeError(
                f"num_qubits must be an integer, got {type(num_qubits).__name__}"
            )
        if num_qubits < 0:
            raise ValueError(f"num_qubits must be non-negative, got {num_qubits}")
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
```

---

### 3.3 Medium

#### FINDING-002: Remote IO feature lacks visible TLS certificate validation configuration

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 12.2.2 |
| **Files** | qdp/qdp-core/src/lib.rs:24, docs/qdp/api.md, docs/qdp/getting-started.md |
| **Source Reports** | 12.2.2.md |
| **Related** | - |

**Description:**

The `remote-io` feature conditionally enables cloud object storage access (S3/GCS) through a `remote` module. The implementation of the `remote` module is not included in the audit scope, making verification of TLS certificate validation impossible. If the `remote` module does not enforce publicly trusted TLS certificates or allows insecure connections, data in transit to/from S3/GCS could be intercepted via man-in-the-middle attacks. Since the data loaded may include training datasets or model parameters, integrity and confidentiality could be compromised.

**Remediation:**

Verify the `remote` module (not provided) enforces TLS 1.2+ with publicly trusted certificates. Ensure no `VERIFY_SSL=false` or equivalent bypass is available. Document TLS requirements for remote IO connections. Example: ensure reqwest/hyper client enforces TLS using `reqwest::Client::builder().min_tls_version(reqwest::tls::Version::TLS_1_2).use_rustls_tls().build()?;` to use Mozilla's root certificate store.

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

If the application is deployed from a git checkout (e.g., in a container built from the repository clone, or served via a web-accessible directory), the `.git` folder could expose: Full repository history including potentially sensitive commits, Internal developer information (email addresses, commit messages), Configuration details that aid reconnaissance. The data flow is: Source repository (`.git/`) → development/build environment → packaged artifact → deployment.

**Remediation:**

Add `.dockerignore` or equivalent build exclusion rules (e.g., .git, .svn, .gitignore, dev/). For Python packages distributed via PyPI, continue using `maturin build` and `uv build` which produce wheel/sdist artifacts that do not include `.git` by default. Document deployment best practices that explicitly exclude VCS metadata.

---

#### FINDING-004: No documented risk-based remediation timeframes for third-party component vulnerabilities

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.1.1 |
| **Files** | dev/release.md |
| **Source Reports** | 15.1.1.md |
| **Related** | - |

**Description:**

Without defined remediation timeframes: Known vulnerabilities in dependencies (cudarc, thiserror, arrow, parquet, CUDA runtime, PyTorch) may persist indefinitely; No consistent standard for when updates must be applied; Increased window of exposure for supply chain attacks; Inconsistent risk treatment across the project. The release process covers branching, building, signing, voting, and publishing but does not mention dependency vulnerability scanning, remediation timeframes (critical: X days, high: Y days, etc.), SBOM generation, or dependency audit procedures.

**Remediation:**

Create a SECURITY.md or docs/security/dependency-policy.md defining: Remediation Timeframes (Critical CVSS ≥ 9.0: 7 calendar days, High CVSS 7.0–8.9: 30 calendar days, Medium CVSS 4.0–6.9: 90 calendar days, Low CVSS < 4.0: Next scheduled release); General Update Policy (All dependencies reviewed quarterly, cargo audit / pip-audit run in CI on every PR, SBOM generated with each release); Dangerous Components (qdp_kernels: CUDA FFI — unsafe operations, direct memory manipulation; cudarc: CUDA driver bindings — GPU memory allocation, raw pointers; Parquet/Arrow readers: Binary data parsing from untrusted files)

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

1. Implement the policy from ASVS-1511-MED-001. 2. Add automated dependency scanning to CI (cargo audit for Rust, pip-audit for Python). 3. Include Cargo.lock in the repository for reproducible builds and auditability. 4. Add a dependency review step to the release process in dev/release.md that includes running cargo audit, pip-audit, verifying no dependencies exceed remediation timeframe, and generating SBOM.

---

#### FINDING-006: Backend modules receive entire configuration object instead of required fields subset

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 15.3.1 |
| **Files** | qumat/qumat.py:243-262, qumat/qumat.py:283-302 |
| **Source Reports** | 15.3.1.md |
| **Related** | - |

**Description:**

The entire `self.backend_config` dictionary is passed to backend modules, and is also mutated to accumulate state between calls. The `backend_config` contains all constructor-supplied configuration (including `backend_name`, `backend_options` with `simulator_type`, `shots`, etc.) plus injected `parameter_values`. Backend functions receive the full configuration object rather than only the fields they need. User-supplied `backend_config` (constructor) → accumulated `parameter_values` injected → entire dict passed to backend module → backend receives fields beyond its operational need (e.g., `execute_circuit` receives `backend_name`, full `backend_options` including `simulator_type` that is only needed at init time). Backend modules receive more configuration data than required for their specific operation. If a backend module logs, serializes, or exposes this config (e.g., in error messages), fields that should be scoped differently could leak. The mutation pattern also creates implicit coupling between sequential calls.

**Remediation:**

Pass only what the backend needs. Example: def execute_circuit(self, parameter_values=None): self._ensure_circuit_initialized(); execution_config = {"parameter_values": bound_parameters, "shots": self.backend_config["backend_options"].get("shots", 1024)}; return self.backend_module.execute_circuit(self.circuit, self.backend, execution_config)

---

#### FINDING-007: QuMat class lacks structured input validation documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | - |
| **ASVS sections** | 2.1.1 |
| **Files** | qumat/qumat.py |
| **Source Reports** | 2.1.1.md |
| **Related** | - |

**Description:**

The `QuMat` class lacks structured documentation defining input validation rules for its parameters. While docstrings describe parameter types, they do not specify valid ranges, allowed values, or expected structures as formal validation rules. Contrast this with the QDP API documentation which explicitly specifies ranges (e.g., `num_qubits` 1–30) and allowed encoding methods. Specific gaps in `qumat.py`: `create_empty_circuit(num_qubits)` has no documented valid range for `num_qubits`; `apply_rx_gate(qubit_index, angle)` has no documented valid range or constraints for `angle` (e.g., finite-only, radian range); `apply_u_gate(qubit_index, theta, phi, lambd)` has no documented constraints on rotation angles; `backend_config` has no schema or structural validation rules documented beyond required keys. Developers implementing backends or consuming the API lack clear guidance on what constitutes valid input, leading to inconsistent validation across backends and potential runtime failures with unclear error messages.

**Remediation:**

Add a validation rules section to the `QuMat` class docstring specifying: `num_qubits`: int, range [1, 30] (or backend-specific maximum); `qubit_index`: int, range [0, num_qubits - 1]; `angle` (rotation gates): float, must be finite (no NaN/Inf); `backend_name`: str, one of {"qiskit", "cirq", "amazon_braket"}; `backend_options`: dict with required key "simulator_type" (str) and optional "shots" (int, >= 1).

---

#### FINDING-008: Rotation angle parameters lack validation for finiteness and type correctness

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

When rotation angles are provided as floats in methods like `apply_rx_gate()`, `apply_ry_gate()`, `apply_rz_gate()`, and `apply_u_gate()`, no validation is performed for finiteness (NaN, Inf) or type correctness. While `_handle_parameter` registers string parameter names, float values pass through unchecked. The QDP documentation explicitly requires finite values for similar parameters. NaN or Inf values produce mathematically undefined quantum states. Backends may silently produce incorrect results rather than raising errors, leading to data integrity issues in quantum computations.

**Remediation:**

Add a validation helper function to check that angles are finite numbers and apply it to all rotation gate methods:
```python
def _validate_angle(self, angle: float, param_name: str = "angle") -> None:
    """Validate that a gate angle is a finite number."""
    if not isinstance(angle, (int, float)):
        raise TypeError(f"{param_name} must be a number, got {type(angle).__name__}")
    if math.isnan(angle) or math.isinf(angle):
        raise ValueError(f"{param_name} must be finite, got {angle}")
```

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

The `backend_options` value is checked for existence but not validated for type or structure. The `backend_name` is not validated against an allow list of known backends, relying solely on `import_module` to fail for unknown names. This results in unclear error messages for misconfigured backends and implicit validation through ImportError rather than explicit business rule check. While the relative import (`package="qumat"`) limits the attack surface of the module loading to within the `qumat` package, the lack of explicit validation provides poor user experience.

**Remediation:**

Add explicit validation for backend_options type and backend_name against an allow list:
```python
_ALLOWED_BACKENDS = frozenset({"qiskit", "cirq", "amazon_braket"})

def __init__(self, backend_config):
    # ... existing dict/key checks ...
    
    if not isinstance(backend_config["backend_options"], dict):
        raise TypeError("backend_options must be a dictionary")
    
    if backend_config["backend_name"] not in self._ALLOWED_BACKENDS:
        raise ValueError(
            f"Unknown backend '{backend_config['backend_name']}'. "
            f"Allowed backends: {sorted(self._ALLOWED_BACKENDS)}"
        )
```

---

#### FINDING-010: Stale Parameter State Persists Across Circuit Resets

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

When create_empty_circuit is called again on an existing QuMat instance, it resets self.circuit and self.num_qubits but does not reset self.parameters. This allows stale parameter registrations and bound values from a previous circuit to persist and be injected into the new circuit's execution via backend_config["parameter_values"]. This can lead to incorrect quantum computation results due to stale parameter state. In scientific computing contexts, silent corruption of computation parameters could lead to invalid experimental results. The unbound parameter check in execute_circuit only catches parameters with None values — fully bound stale parameters pass through silently.

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
| **ASVS sections** | 5.3.2 |
| **Files** | qdp/qdp-python/src/loader.rs:109-113 |
| **Source Reports** | 5.3.2.md |
| **Related** | - |

**Description:**

The `path_from_py` function accepts user-supplied file paths from Python callers and performs I/O operations with no path validation. No validation or sanitization is applied. Specifically absent are: Path traversal sequence rejection (`../`, `..\\`, encoded variants), Null byte injection checks, Allowlist of permitted base directories, Canonicalization (resolve symlinks, normalize `.`/`..`), Scheme validation (no check preventing `file://`, `http://`, etc. when `remote-io` is disabled). If this library is integrated into a service where file paths originate from untrusted user input, an attacker could: (1) Path traversal: Read arbitrary files on the server accessible to the process. (2) SSRF (with `remote-io` feature): Supply `s3://` or `gs://` URLs targeting internal infrastructure resources. (3) Information disclosure: Exfiltrate sensitive configuration, credentials, or data.

**Remediation:**

Implement path validation in `path_from_py` with: (1) Null byte rejection, (2) Canonicalization to resolve symlinks and ../ sequences, (3) Base directory constraint to ensure resolved path stays within allowed directory, (4) UTF-8 validation. Add URL scheme validation when `remote-io` is enabled to validate against an allowlist of permitted schemes. Add file extension validation to enforce documented supported extensions. Document security boundaries for file path inputs in API documentation.

### 3.4 Low

#### FINDING-012: Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 14.2.1 |
| **Files** | qdp/qdp-core/src/lib.rs (encode_from_parquet function), docs/qdp/getting-started.md (remote URL examples) |
| **Source Reports** | 14.2.1.md |
| **Related** | None |

**Description:**

While query strings are explicitly rejected (positive pattern), S3/GCS bucket names and object key paths passed as function arguments could appear in error messages or logs. Object keys may contain sensitive identifiers (customer IDs, dataset names, internal project names). The MahoutError::Io(String) variant could propagate these paths. User-supplied URL string (may include bucket/key paths) flows through encode_from_parquet / encode to platform module and potentially gets logged or included in error messages.

**Remediation:**

Sanitize file paths in error messages to redact bucket names or keys. Consider structured logging that separates path components for selective redaction. Example implementation: Create a sanitize_remote_path function that redacts bucket/key information for s3:// and gs:// URLs, replacing sensitive portions with &lt;redacted&gt;.

---

#### FINDING-013: Backend Configuration Mutated In Place During Execution

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Section(s)** | 2.3.1 |
| **Files** | qumat/qumat.py (243-262) |
| **Source Reports** | 2.3.1.md |
| **Related** | None |

**Description:**

The execute_circuit method mutates self.backend_config in place by setting self.backend_config["parameter_values"]. This means the configuration object carries state from one execution to the next. If execute_circuit is called without parameters after a previous call with parameters, the old parameter_values key remains in backend_config. The mutation pattern violates the principle of keeping configuration immutable and could lead to subtle bugs if backend modules cache or reference the config dict.

**Remediation:**

Pass a copy or a purpose-built execution context rather than mutating the shared config:

```python
exec_config = {**self.backend_config, "parameter_values": bound_parameters}
return self.backend_module.execute_circuit(self.circuit, self.backend, exec_config)
```

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Affected Files | Domain |
|-----------|-------------------|----------|----------------|---------|
| PSC-001 | Static capsule name using compile-time constant | `DLTENSOR_NAME: &[u8] = b"dltensor\0"` is a compile-time constant, eliminating any possibility of injection into the PyCapsule name | tensor.rs | Injection Prevention |
| PSC-002 | Typed error returns with hardcoded message prefixes | All errors use strongly-typed `PyRuntimeError::new_err()` with hardcoded message prefixes, preventing structure manipulation | tensor.rs | Injection Prevention |
| PSC-003 | Double-free prevention via consumed flag | consumed flag checked before both PyCapsule creation and Drop execution | tensor.rs, dlpack.rs | Memory Safety |
| PSC-004 | Null pointer checks on all entry paths | Null pointer checks on all entry paths before dereferencing self.ptr | tensor.rs | Memory Safety |
| PSC-005 | Debug assertion validating deleter presence | `debug_assert!` validating deleter presence in Drop | tensor.rs | Memory Safety |
| PSC-006 | Strongly-typed interfaces | Rust's type system prevents all text-based injection classes structurally | tensor.rs | Type Safety |
| PSC-007 | Binary protocol usage | DLPack uses binary pointer exchange via PyCapsule, inherently immune to text-based injection. Methods `__dlpack__` and `__dlpack_device__` return binary data (PyCapsule) and typed integer tuples, not text content | tensor.rs | Protocol Security |
| PSC-008 | No database operations present | Code is a low-level Rust FFI library for GPU memory management via DLPack protocol with no SQL, HQL, NoSQL, Cypher, or ORM usage | tensor.rs | Architecture |
| PSC-009 | Typed FFI calls only | All external calls use strongly-typed function signatures (PyCapsule_New, synchronize_stream, dlpack_stream_to_cuda), making shell injection structurally impossible | Multiple | Injection Prevention |
| PSC-010 | Feature-gated remote IO | Remote storage access requires explicit opt-in via the `remote-io` Cargo feature flag, reducing default attack surface | qdp/qdp-core/src/lib.rs:24 | Attack Surface Reduction |
| PSC-011 | URL fragment/query rejection | Documentation explicitly states 'Remote URL query/fragment is not supported (`?versionId=...`, `#...`)', which limits URL complexity and potential for parameter injection | docs/qdp/api.md, docs/qdp/getting-started.md | Input Validation |
| PSC-012 | Package-based distribution | The release process builds wheels and sdist via `uv build` and `maturin build`, which inherently exclude `.git` directories from distribution artifacts | dev/release.md | Deployment Security |
| PSC-013 | Apache SVN source publication | Final release artifacts are built from Apache SVN source (dist.apache.org), adding a layer of separation from the git repository | N/A | Supply Chain |
| PSC-014 | Query string/fragment rejection | The API explicitly documents and rejects query strings and fragments in remote URLs, preventing credential leakage via URL parameters like ?AWSAccessKeyId=... | api.md, getting-started.md | Information Disclosure Prevention |
| PSC-015 | DLPack single-consume enforcement | `free_dlpack_tensor()` in dlpack.rs, deleter takes ownership | dlpack.rs | Memory Safety |
| PSC-016 | Arc-based buffer lifecycle | `GpuStateVector::buffer: Arc<BufferStorage>` in memory.rs | memory.rs | Memory Safety |
| PSC-017 | RAII Drop implementations | PinnedHostBuffer, PipelineContext, OverlapTracker implement Drop for deterministic resource cleanup | memory.rs, pipeline.rs, overlap_tracker.rs | Resource Management |
| PSC-018 | Apache release governance | ATR (Apache Trusted Releases) process and PMC voting provides a structured release gate where dependency issues could be caught | dev/release.md | Supply Chain |
| PSC-019 | Minimal dependency surface | The Rust core uses relatively few direct dependencies (cudarc, thiserror, qdp_kernels), reducing the attack surface compared to projects with large dependency trees | qdp/qdp-core/src/gpu/memory.rs, qdp/qdp-core/src/error.rs | Attack Surface Reduction |
| PSC-020 | QuantumTensor minimal DLPack interface | Exposes only `__dlpack__` and `__dlpack_device__` methods | tensor.rs | Attack Surface Reduction |
| PSC-021 | QDP API validation rules | Well-documented types, ranges, encoding methods | website/.../api.md | Documentation |
| PSC-022 | `_validate_qubit_index` centralized validation | Centralized validation function checking type, sign, and range, consistently applied to every gate method | qumat/qumat.py:97-112 | Input Validation |
| PSC-023 | `_ensure_circuit_initialized` prerequisite check | Consistently applied to all gate and execute methods | qumat/qumat.py:87-95 | State Management |
| PSC-024 | QuMat input validation | All validation at library level | qumat/qumat.py | Input Validation |
| PSC-025 | QDP Rust encoder validation | Authoritative validation in Rust | qdp-core | Input Validation |
| PSC-026 | No client-side-only validation | All validation in qumat.py runs in the same process as the computation — there is no untrusted client layer | qumat/qumat.py | Architecture |
| PSC-027 | `_ensure_circuit_initialized` enforces create-before-operate | Consistently called as a prerequisite check in every operation that requires a circuit, correctly enforcing the sequential requirement that create_empty_circuit must precede gate application and execution | qumat.py:87-95 | State Management |
| PSC-028 | Unbound parameter check | Prevents execution when required parameters haven't been bound in both execute_circuit and get_final_state_vector | qumat.py:253-260, qumat.py:290-297 | State Management |
| PSC-029 | Whitelist of null-handling values | The `parse_null_handling` function demonstrates a proper allowlist pattern for string inputs, rejecting unknown values with a descriptive error | qdp/qdp-python/src/loader.rs:76-84 | Input Validation |
| PSC-030 | Rust's type system avoids null-byte issues | Using `String` (not `CString`) avoids null-byte-in-middle issues at the Rust/OS boundary for most standard library I/O operations | N/A | Type Safety |
| PSC-031 | Documentation lists supported formats | The API documentation clearly specifies allowed file extensions and URL schemes | api.md, getting-started.md | Documentation |
| PSC-032 | Strong validation for numeric/enum inputs | The codebase demonstrates strong validation for numeric/enum inputs (e.g., `parse_null_handling` rejects unknown values, encoding methods are validated, qubit ranges are checked, GPU pointer validity is verified via `cudaPointerGetAttributes`) | Multiple | Input Validation |
| PSC-033 | Security documentation practices | The dev/release.md documentation demonstrates good security documentation practices including GPG signing, checksum verification, and token management with chmod 600 | dev/release.md | Documentation |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Justification |
|---------|-------|--------|---------------|
| 1.2.1 | Output Encoding for HTTP Response / HTML / XML / CSS | **N/A** | Not a web application; no HTTP response generation |
| 1.2.2 | URL Encoding and Safe URL Protocols | **N/A** | No URL generation for user-facing contexts |
| 1.2.3 | JavaScript / JSON Output Encoding | **N/A** | No JavaScript or JSON output generation |
| 1.2.4 | Parameterized Queries / SQL Injection | **N/A** | No database operations present |
| 1.2.5 | OS Command Injection | **Pass** | Uses typed FFI calls only; no shell command construction |
| 1.3.1 | HTML Sanitization for WYSIWYG / Rich Input | **N/A** | No HTML processing or rich text input |
| 1.3.2 | Dynamic Code Execution Prevention | **N/A** | No eval() or dynamic code execution features |
| 1.5.1 | XML Parser Configuration - XXE Prevention | **N/A** | No XML parsing functionality |
| 2.1.1 | Validation and Business Logic Documentation | **Partial** | FINDING-007: QuMat class lacks structured validation documentation |
| 2.2.1 | Input Validation | **Fail** | FINDING-001: num_qubits lacks validation; FINDING-008: Rotation angles lack validation; FINDING-009: backend_options lack validation |
| 2.2.2 | Server-Side Input Validation | **Pass** | All validation occurs in same process as computation; no client/server split |
| 2.3.1 | Business Logic Sequential Flow | **Partial** | FINDING-010: Stale parameter state persists; FINDING-013: Backend config mutation; PSC-027/028 provide partial mitigation |
| 3.2.1 | Unintended Content Interpretation | **N/A** | No content rendering functionality |
| 3.2.2 | Safe Rendering Functions | **N/A** | No HTML/JavaScript rendering |
| 3.3.1 | Cookie Security Attributes | **N/A** | No cookie usage |
| 3.4.1 | HTTP Strict Transport Security (HSTS) | **N/A** | Not a web application |
| 3.4.2 | CORS Access-Control-Allow-Origin Validation | **N/A** | No CORS headers |
| 3.5.1 | Cross-Origin Request Validation | **N/A** | No cross-origin request handling |
| 3.5.2 | CORS Preflight Bypass Prevention | **N/A** | No CORS functionality |
| 3.5.3 | HTTP Method Verification | **N/A** | No HTTP method handling |
| 4.1.1 | HTTP Response Content-Type Header Validation | **N/A** | No HTTP response generation |
| 4.4.1 | WebSocket over TLS (WSS) | **N/A** | No WebSocket functionality |
| 5.2.1 | File Size Validation | **N/A** | No file upload functionality |
| 5.2.2 | File Upload Validation | **N/A** | No file upload functionality |
| 5.3.1 | Uploaded File Execution Prevention | **N/A** | No file upload functionality |
| 5.3.2 | File Storage — Path Traversal Protection | **Fail** | FINDING-011: path_from_py accepts unsanitized user paths |
| 6.1.1 | Authentication Documentation | **N/A** | No authentication functionality |
| 6.2.1 | Password Minimum Length | **N/A** | No password functionality |
| 6.2.2 | Password Change Capability | **N/A** | No password functionality |
| 6.2.3 | Password Change Requirements | **N/A** | No password functionality |
| 6.2.4 | Common Password Check | **N/A** | No password functionality |
| 6.2.5 | Password Composition Rules | **N/A** | No password functionality |
| 6.2.6 | Password Input Field Masking | **N/A** | No password functionality |
| 6.2.7 | Password Manager Support | **N/A** | No password functionality |
| 6.2.8 | Password Verification Without Modification | **N/A** | No password functionality |
| 6.3.1 | Credential Stuffing Prevention | **N/A** | No authentication functionality |
| 6.3.2 | Default Account Prevention | **N/A** | No user account functionality |
| 6.4.1 | Secure Initial Passwords | **N/A** | No password functionality |
| 6.4.2 | Password Hints Prevention | **N/A** | No password functionality |
| 7.2.1 | Backend Session Token Verification | **N/A** | No session management |
| 7.2.2 | Dynamic Session Token Generation | **N/A** | No session management |
| 7.2.3 | Session Token Entropy | **N/A** | No session management |
| 7.2.4 | Session Token Regeneration | **N/A** | No session management |
| 7.4.1 | Session Termination and Invalidation | **N/A** | No session management |
| 7.4.2 | Session Termination on Account Changes | **N/A** | No session management |
| 8.1.1 | Authorization Documentation | **N/A** | No authorization functionality |
| 8.2.1 | Function-level Access Control | **N/A** | No authorization functionality |
| 8.2.2 | Data-specific Access Restriction | **N/A** | No authorization functionality |
| 8.3.1 | Trusted Service Layer Authorization | **N/A** | No authorization functionality |
| 9.1.1 | Self-contained Token Validation | **N/A** | No token functionality |
| 9.1.2 | Token Algorithm Allowlist | **N/A** | No token functionality |
| 9.1.3 | Token Key Material Validation | **N/A** | No token functionality |
| 9.2.1 | Token Validity Time Span | **N/A** | No token functionality |
| 10.4.1 | OAuth Redirect URI Validation | **N/A** | No OAuth functionality |
| 10.4.2 | Authorization Code Single Use | **N/A** | No OAuth functionality |
| 10.4.3 | Authorization Code Lifetime | **N/A** | No OAuth functionality |
| 10.4.4 | Grant Type Restrictions | **N/A** | No OAuth functionality |
| 10.4.5 | Refresh Token Replay Prevention | **N/A** | No OAuth functionality |
| 11.3.1 | Secure Block Modes | **N/A** | No cryptographic operations |
| 11.3.2 | Approved Ciphers | **N/A** | No cryptographic operations |
| 11.4.1 | Approved Hash Functions | **N/A** | No cryptographic operations |
| 12.1.1 | TLS Protocol Version Requirements | **N/A** | No TLS server functionality |
| 12.2.1 | TLS for HTTP-based Services | **N/A** | Not a web service |
| 12.2.2 | HTTPS Communication with External Services | **Partial** | FINDING-002: Remote IO lacks visible TLS certificate validation configuration |
| 13.4.1 | Source Control Metadata Exclusion | **Partial** | FINDING-003: No deployment configuration to exclude .git from production; PSC-012/013 provide partial mitigation |
| 14.2.1 | Sensitive Data in URLs | **Partial** | FINDING-012: S3/GCS URLs may contain sensitive bucket/key names; PSC-011/014 provide partial mitigation |
| 14.3.1 | Client-side Data Protection | **N/A** | No client-side storage |
| 15.1.1 | Remediation Timeframes | **Fail** | FINDING-004: No documented risk-based remediation timeframes |
| 15.2.1 | Component Currency | **Fail** | FINDING-005: Unable to verify component currency without remediation timeframes |
| 15.3.1 | Return Only Required Field Subset | **Partial** | FINDING-006: Backend modules receive entire configuration object |
| 2.1.1 | Validation Documentation | **Partial** | FINDING-007: QuMat lacks structured validation documentation |

**Summary Statistics:**
- **Pass**: 2 (3.2%)
- **Fail**: 5 (8.1%)
- **Partial**: 7 (11.3%)
- **N/A**: 48 (77.4%)

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Requirements | Positive Controls | Affected Components |
|-----------|----------|-------------------|-------------------|---------------------|
| FINDING-001 | High | 2.2.1 | PSC-022, PSC-024, PSC-025, PSC-032 | qumat/qumat.py:create_empty_circuit |
| FINDING-002 | Medium | 12.2.2 | PSC-010, PSC-011 | qdp-python (remote-io feature) |
| FINDING-003 | Medium | 13.4.1 | PSC-012, PSC-013 | Build/deployment pipeline |
| FINDING-004 | Medium | 15.1.1 | PSC-018, PSC-019, PSC-033 | Project governance |
| FINDING-005 | Medium | 15.2.1 | PSC-018, PSC-019 | Dependency management |
| FINDING-006 | Medium | 15.3.1 | PSC-021, PSC-025 | qumat/qumat.py:execute_circuit, get_final_state_vector |
| FINDING-007 | Medium | 2.1.1 | PSC-021, PSC-022, PSC-023, PSC-024 | qumat/qumat.py (class-level) |
| FINDING-008 | Medium | 2.2.1 | PSC-024, PSC-025, PSC-032 | qumat/qumat.py:rx, ry, rz, u1, u2, u3, crx, cry, crz, cu1, cu2, cu3 |
| FINDING-009 | Medium | 2.2.1 | PSC-024, PSC-025, PSC-029, PSC-031 | qumat/qumat.py:execute_circuit, get_final_state_vector |
| FINDING-010 | Medium | 2.3.1 | PSC-023, PSC-027, PSC-028 | qumat/qumat.py:create_empty_circuit, set_parameters |
| FINDING-011 | Medium | 5.3.2 | PSC-030, PSC-031 | qdp/qdp-python/src/loader.rs:path_from_py |
| FINDING-012 | Low | 14.2.1 | PSC-011, PSC-014, PSC-031 | qdp-python (remote-io feature) |
| FINDING-013 | Low | 2.3.1 | PSC-021, PSC-025, PSC-026 | qumat/qumat.py:execute_circuit, get_final_state_vector |

## Control Effectiveness Analysis

### Strong Control Areas
1. **Memory Safety** (PSC-003, PSC-004, PSC-005, PSC-015, PSC-016, PSC-017): Comprehensive RAII patterns, null checks, and ownership enforcement prevent memory corruption
2. **Injection Prevention** (PSC-001, PSC-002, PSC-006, PSC-007, PSC-009): Type system and binary protocols structurally eliminate injection vectors
3. **State Management** (PSC-023, PSC-027, PSC-028): Prerequisite checks and initialization enforcement prevent invalid state transitions

### Control Gaps
1. **Input Validation** (FINDING-001, FINDING-008, FINDING-009): Numeric parameters lack comprehensive validation despite strong qubit index validation (PSC-022)
2. **Path Handling** (FINDING-011): No sanitization despite type safety controls (PSC-030)
3. **Supply Chain** (FINDING-004, FINDING-005): Process controls exist (PSC-018) but lack documented remediation timeframes

### Defense-in-Depth Layers
| Layer | Controls | Gaps |
|-------|----------|------|
| **Language/Type System** | PSC-006, PSC-030 | N/A |
| **Input Validation** | PSC-022, PSC-029, PSC-032 | FINDING-001, FINDING-008, FINDING-009, FINDING-011 |
| **State Management** | PSC-023, PSC-027, PSC-028 | FINDING-010, FINDING-013 |
| **Memory Safety** | PSC-003, PSC-004, PSC-005, PSC-015, PSC-016, PSC-017 | N/A |
| **Attack Surface** | PSC-010, PSC-019, PSC-020 | N/A |
| **Supply Chain** | PSC-012, PSC-013, PSC-018 | FINDING-004, FINDING-005 |
| **Documentation** | PSC-021, PSC-031, PSC-033 | FINDING-007 |

---

**End of Security Assessment Report**

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 13 |

**Total consolidated findings: 13**

*End of Consolidated Security Audit Report*