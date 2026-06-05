# Security Audit Consolidated Report

## Report Metadata

| Field | Value |
|-------|-------|
| **Repository** | `apache/tooling-runbooks` |
| **ASVS Level** | L1 |
| **Severity Threshold** | None (all findings included) |
| **Commit** | N/A |
| **Date** | Jun 05, 2026 |
| **Auditor** | Tooling Agents |
| **Source Reports** | 70 |
| **Total Findings** | 15 |

## Executive Summary

### Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------| Medium | 6 | 40.0% | Info | 0 | 0.0% |

### Level Coverage

All 15 findings are mapped to **ASVS Level 1 (L1)** controls, representing the minimum baseline security posture. The audit scope was constrained to L1 requirements across five domain directories: `general_security`, `aws_braket_cloud_integration`, `build_and_dependency_management`, `data_serialization_formats`, and `quantum_circuit_input_validation`.

### Top 5 Risks

1. **[Critical] : Complete absence of documented risk-based remediation time frames for third-party dependencies (ASVS 15.1.1)** — The project lacks any documented policy defining acceptable remediation windows for known vulnerabilities in dependencies. Without defined SLAs, critical vulnerabilities in transitive dependencies may persist indefinitely without triggering organizational response.

2. **[Critical] : No automated vulnerability scanning in CI/CD pipeline to detect components breaching remediation timeframes (ASVS 15.2.1)** — Neither `cargo audit` nor any equivalent Python dependency scanner (e.g., `pip-audit`, `safety`) is integrated into CI workflows. This means known-vulnerable dependencies can be merged and released without automated detection, negating the value of lock files and version pinning already in place.

3. **[High] FINDING-003: No classification of "dangerous functionality" or "risky components" in project documentation (ASVS 15.1.1)** — The project performs dynamic module imports, FFI boundary crossings (PyO3/CUDA), and cloud credential handling, yet none of these are formally classified as high-risk areas requiring enhanced review. This absence undermines prioritization of security effort.

4. **[High] FINDING-004: No Dependabot or Renovate configuration for automated dependency update tracking (ASVS 15.2.1)** — Without automated dependency update tooling, the project relies entirely on manual monitoring for new releases and security patches across both the Rust (Cargo) and Python (pip/uv) ecosystems — an unsustainable approach given the dependency graph breadth.

5. **[Medium] FINDING-005: Missing `sample_size > 0` validation allows panic via zero-sized chunk operation (ASVS 2.1.1, 2.2.1)** — A zero-value `sample_size` parameter can propagate to chunk/division operations causing a panic (Rust) or unhandled exception, representing a denial-of-service vector accessible from the Python API surface.

### Positive Controls

The audit identified **47 positive security controls** across all five domains, demonstrating significant security-conscious engineering practices already embedded in the codebase:

- **Defense-in-depth validation architecture**: The project implements a two-stage validation model where CPU-side Rust preprocessing validates all inputs before GPU transfer, and CUDA kernels independently re-validate on-device. This ensures a bug in any single validation layer cannot silently corrupt computation.

- **Strong supply chain controls (partial)**: Release-critical GitHub Actions (`pypa/gh-action-pypi-publish`, `Jimver/cuda-toolkit`) are pinned to full commit SHAs, and PyPI publication uses OIDC trusted publishing with environment protection — eliminating long-lived API tokens and mitigating tag-mutation attacks for the most sensitive workflow paths.

- **Memory safety by design**: The DLPack/tensor interop layer employs consumed flags for double-free prevention, null pointer checks on all entry paths, `Option::take()` semantics, and Arc reference counting. Rust's type system structurally eliminates entire classes of text-based injection vulnerabilities.

- **Transport security defaults**: Cloud integrations leverage `object_store` with `rustls` (TLS 1.2/1.3 only) and `boto3` (HTTPS-only endpoints by default). No certificate verification bypass exists in production code, and URL parsing rejects query/fragment injection attempts.

- **Workspace dependency centralization**: Cargo workspace dependencies and `pyproject.toml` override mechanisms ensure consistent version resolution across workspace members, with upper bounds preventing unintended major version drift.

These controls establish a solid foundation; the findings in this report primarily address **process-level gaps** (dependency governance, vulnerability scanning automation) and **edge-case input validation omissions** rather than fundamental architectural weaknesses.

---


> **Note:** 2 Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list.


## 3. Findings

## 3.2 High

#### FINDING-003: 🟠 No classification of "dangerous functionality" or "risky components" in project documentation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.1.1 |
| **Files** | qdp/Cargo.toml:14-41, pyproject.toml:48-54 |
| **Source Reports** | 15.1.1.md |
| **Related** | None |

**Description:**

Components performing deserialization, raw data parsing, dynamic code execution, or direct memory manipulation are not explicitly documented. The project uses components with dangerous functionality including cudarc (direct memory manipulation), prost (deserialization of untrusted data), tch (raw binary data parsing, FFI), and object_store (network I/O to external services) without documenting them as such. Without this classification: developers may not apply additional scrutiny to these components during updates, security reviewers cannot prioritize audit effort, and incident responders cannot quickly assess blast radius when a CVE is published.

**Remediation:**

Add a docs/component-risk-register.md categorizing each dependency by risk level. Document dangerous components (cudarc, prost, tch) and risky components (object_store) with justification for their use and additional controls applied. Include a table with columns for Component, Category, Justification, and Additional Controls. Apply halved remediation windows for components performing dangerous functionality.

---

#### FINDING-004: 🟠 No Dependabot or Renovate configuration for automated dependency update tracking

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟠 High |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS Sections** | 15.2.1 |
| **Files** | Project root (missing .github/dependabot.yml or renovate.json) |
| **Source Reports** | 15.2.1.md |
| **Related** | None |

**Description:**

The project lacks automated dependency update tracking through Dependabot or Renovate. Without this, new security patches may go unnoticed for extended periods. The gap between vulnerability disclosure and developer awareness is undefined and potentially unbounded. Even with documented timeframes (15.1.1), enforcement requires detection mechanisms.

**Remediation:**

Create .github/dependabot.yml with configurations for cargo, pip, and github-actions ecosystems. Set weekly schedule intervals with appropriate open-pull-requests-limit values.

### 3.3 Medium

#### FINDING-005: Missing `sample_size > 0` validation allows panic via zero-sized chunk operation

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 2.1.1, 2.2.1 |
| **Files** | qdp/qdp-core/src/preprocessing.rs:93, qdp/qdp-core/src/preprocessing.rs:93-125, qdp/qdp-core/src/preprocessing.rs:129-162 |
| **Source Reports** | 2.1.1.md, 2.2.1.md |
| **Related** | None |

**Description:**

The `validate_batch` function checks that `num_samples > 0` but does not validate that `sample_size > 0`. When `sample_size=0`, the validation passes (since 0 × N = 0 matches an empty batch_data array), but the subsequent call to `calculate_batch_l2_norms` invokes `par_chunks(0)`, which panics. A user can trigger this by passing a numpy array with shape (N, 0) from Python. PyO3 catches the panic and converts it to a PanicException, but this bypasses normal error handling and can degrade service reliability in production. Additionally, the documentation does not specify that `sample_size` must be > 0, creating incomplete specification of validation rules.

**Remediation:**

Add documentation to the function specifying: "All of `num_samples`, `sample_size`, and `num_qubits` must be greater than zero." Additionally, implement the validation check: if sample_size == 0 { return Err(MahoutError::InvalidInput("sample_size must be greater than 0".to_string())); }

---

#### FINDING-006: No allowlist validation for `backend_name` in QuMat dynamic module import

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 2.2.1 |
| **Files** | qumat/qumat.py:67 |
| **Source Reports** | 2.2.1.md |
| **Related** | None |

**Description:**

The QuMat `__init__` method accepts a user-controlled `backend_name` from `backend_config` and uses it directly in a dynamic module import via `import_module(f".{self.backend_name}_backend", package="qumat")`. While constrained by the `package="qumat"` parameter and `_backend` suffix pattern, any module matching this pattern within the qumat package would be loaded and its `initialize_backend` function called. This violates positive validation principles (ASVS 2.2.1 requires allowlist validation for security-relevant inputs) and could load unintended modules including development modules, future modules, or package extensions.

**Remediation:**

Implement an allowlist of supported backends:
```python
_SUPPORTED_BACKENDS = frozenset({"qiskit", "cirq", "amazon_braket"})

def __init__(self, backend_config: Mapping[str, Any] | None) -> None:
    # ... existing checks ...
    self.backend_name = self.backend_config["backend_name"]
    if self.backend_name not in _SUPPORTED_BACKENDS:
        raise ValueError(
            f"Unsupported backend '{self.backend_name}'. "
            f"Supported backends: {sorted(_SUPPORTED_BACKENDS)}"
        )
    self.backend_module = import_module(
        f".{self.backend_name}_backend", package="qumat"
    )
```

---

#### FINDING-007: `from_env()` Allows HTTP Fallback via Environment Variables Without Code-Level Guard

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 12.2.1 |
| **Files** | qdp/qdp-core/src/remote.rs:66-76 |
| **Source Reports** | 12.2.1.md |
| **Related** | None |

**Description:**

The `AmazonS3Builder::from_env()` method reads ALL supported environment variables, including `AWS_ALLOW_HTTP`. If this variable is set to `true` in a production deployment (e.g., leftover from testing, misconfiguration, or compromise of environment), the S3 client will permit plaintext HTTP connections. The test documentation explicitly references this pattern. There is no code-level enforcement that overrides this setting. The same applies to `GoogleCloudStorageBuilder::from_env()` which may respect similar HTTP-allowance settings. This is a Type A gap (Entry point with NO control) where the `build_store` function creates clients capable of HTTP communication with no explicit HTTPS enforcement. If `AWS_ALLOW_HTTP=true` is set in the production environment, all S3/GCS data transfers could occur over unencrypted HTTP, exposing authentication headers and downloaded data to network-level attackers.

**Remediation:**

Explicitly disable HTTP after loading environment configuration by adding `.with_allow_http(false)` to the S3 builder: `let store = object_store::aws::AmazonS3Builder::from_env().with_bucket_name(bucket).with_allow_http(false).build()`. Alternatively, add a runtime check that returns an error if `AWS_ALLOW_HTTP` is set to true in non-test builds using `#[cfg(not(test))]` guards. Verify the GCS builder API for similar controls. Add integration tests that verify TLS is actually used for S3/GCS connections. Consider implementing a wrapper around `ObjectStore` construction that enforces organizational TLS policies.

---

#### FINDING-008: Inconsistent GitHub Action version pinning between workflows creates supply chain drift risk

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 15.2.1 |
| **Files** | .github/workflows/release.yml:16, .github/workflows/release.yml:17, .github/workflows/release.yml:23, .github/workflows/release.yml:32, .github/workflows/release.yml:42, .github/workflows/release.yml:59, .github/workflows/release.yml:61, .github/workflows/release.yml:69, .github/workflows/release.yml:73, .github/workflows/release.yml:77, .github/workflows/release.yml:85, .github/workflows/release.yml:89 |
| **Source Reports** | 15.2.1.md |
| **Related** | None |

**Description:**

The release workflow uses mutable tag references (e.g., @v6, @v5) for GitHub Actions instead of commit hash pins, while the testing workflow properly pins actions to commit hashes. The release workflow has id-token: write permission and publishes to PyPI, making it a higher-value target. A compromised upstream action repository could inject malicious code into the release build.

**Remediation:**

Pin all actions in release.yml to commit hashes following the pattern used in python-testing.yml. Include version comment for maintainability.

---

#### FINDING-009: PyO3/maturin-action@v1 used without commit hash pin in both CI workflows

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 15.2.1 |
| **Files** | .github/workflows/python-testing.yml:80, .github/workflows/release.yml:85 |
| **Source Reports** | 15.2.1.md |
| **Related** | None |

**Description:**

The PyO3/maturin-action is used with a mutable v1 tag in both testing and release workflows without commit hash pinning. This third-party action compiles and links native code, making it a high-value supply chain target. A compromised version could inject backdoors into compiled wheels. Unlike other actions in python-testing.yml which are properly pinned, this action remains unpinned.

**Remediation:**

Pin PyO3/maturin-action to a specific commit hash in both workflows.

---

#### FINDING-010: Full Quantum State Vector Returned Without Subsetting Capability

| Attribute | Value |
|-----------|-------|
| **Severity** | 🟡 Medium |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 15.3.1 |
| **Files** | qumat/qumat.py:332-368 |
| **Source Reports** | 15.3.1.md |
| **Related** | None |

**Description:**

The get_final_state_vector() method unconditionally returns the entire state vector (2^N complex amplitudes) without any mechanism to request specific amplitudes, qubit subsets, or size limits. For N=30 qubits, this results in approximately 8GB of data. The API provides no way to request amplitudes for specific basis states by index, request a partial trace (reduced density matrix for a qubit subset), limit the number of returned amplitudes (e.g., top-k by magnitude), or return summary statistics instead of the raw vector. This can cause memory and network exhaustion, particularly as qubit counts grow exponentially.

**Remediation:**

Add subsetting parameters while preserving backward compatibility. Implement optional parameters: indices (list[int] | None) for specific basis state indices, top_k (int | None) to return only the top-k amplitudes by magnitude, and qubit_subset (list[int] | None) to return reduced state for specific qubits only. When indices is provided, return full_state[indices]. When top_k is provided, use numpy to compute magnitudes and return only the top-k entries. Default behavior should return the full vector for backward compatibility.

### 3.4 Low

#### FINDING-011: No validation of rotation gate angles for finiteness in QuMat

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 2.2.1, 2.2.2, 2.1.1 |
| **Files** | qumat/qumat.py:366-457 |
| **Source Reports** | 2.2.1.md, 2.2.2.md, 2.1.1.md |
| **Related** | None |

**Description:**

The QuMat rotation gate functions (`apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`, `apply_u_gate`) accept angle parameters but do not validate that numeric angles are finite. The `_handle_parameter` method only registers string parameters but performs no numeric validation. Non-finite angles (NaN or Inf) passed to quantum backends produce mathematically undefined rotation matrices, leading to garbage quantum state vectors. While not a memory safety issue, this violates the business expectation that quantum computations produce valid results and could lead to incorrect downstream decisions if the calling application doesn't validate results. This also represents inconsistent validation at the trusted service layer: qubit indices are validated before backend delegation, but angles are not.

**Remediation:**

Add angle validation at the QuMat trusted layer:
```python
def _validate_angle(self, angle: float | str, param_name: str = "angle") -> None:
    """Validate that a numeric angle is finite."""
    if isinstance(angle, (int, float)) and not isinstance(angle, bool):
        import math
        if math.isnan(angle) or math.isinf(angle):
            raise ValueError(
                f"{param_name} must be finite, got {angle}"
            )
    elif not isinstance(angle, str):
        raise TypeError(
            f"{param_name} must be a float or string parameter name, "
            f"got {type(angle).__name__}"
        )
```

Apply this validation to all rotation gate methods before passing angles to the backend. Consider implementing a shared ValidatedAngle type in QuMat - a newtype wrapper that guarantees finiteness at construction time would make it impossible to pass invalid angles to backends.

---

#### FINDING-012: `create_empty_circuit` does not validate `num_qubits` parameter

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 2.2.1 |
| **Files** | qumat/qumat.py:72-82 |
| **Source Reports** | 2.2.1.md |
| **Related** | None |

**Description:**

The `create_empty_circuit` function accepts a `num_qubits` parameter but performs no validation on it. Any value (negative int, float, string, etc.) is stored as `self.num_qubits` and passed directly to the backend. Negative or non-integer qubit counts bypass the `_validate_qubit_index` upper bound check (which uses `self.num_qubits`) and may cause unexpected behavior in backends. The impact is mitigated because most backends would reject invalid values themselves, but this violates input validation best practices.

**Remediation:**

Add validation to `create_empty_circuit`:
```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    if num_qubits is not None:
        if not isinstance(num_qubits, int) or isinstance(num_qubits, bool):
            raise TypeError(f"num_qubits must be an integer, got {type(num_qubits).__name__}")
        if num_qubits < 0:
            raise ValueError(f"num_qubits cannot be negative, got {num_qubits}")
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
```

---

#### FINDING-013: No Explicit TLS Protocol Version Configuration for Cloud Storage Connections

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 12.1.1 |
| **Files** | qdp/qdp-core/src/remote.rs:62-95, qumat/amazon_braket_backend.py:33-36 |
| **Source Reports** | 12.1.1.md |
| **Related** | None |

**Description:**

Neither the Rust `object_store` client nor the Python `boto3` client explicitly configures minimum TLS protocol versions. The behavior depends on: (1) Rust (`object_store`): Uses `reqwest` which typically compiles with `rustls` (supporting only TLS 1.2/1.3) or `native-tls` (platform-dependent, may support TLS 1.0/1.1). (2) Python (`boto3`): Uses system OpenSSL via `urllib3`. While modern OpenSSL versions (1.1.1+) default to TLS 1.2 minimum, this is system-configuration-dependent. If compiled with `native-tls` on a system with an older TLS library, or if the Python runtime uses an older OpenSSL, TLS 1.0/1.1 connections could theoretically be negotiated. This is mitigated by AWS and GCP endpoints only accepting TLS 1.2+, but this represents defense-in-depth reliance on server-side enforcement rather than client-side control.

**Remediation:**

For Rust, ensure `rustls` feature is explicitly enabled (enforces TLS 1.2+ at compile time): Add to Cargo.toml: `object_store = { version = "...", features = ["aws", "gcp"], default-features = false }` and `reqwest = { version = "...", features = ["rustls-tls"], default-features = false }`. For Python, configure `boto3` with explicit TLS version if needed: Create an SSL context with `ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` and set `ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2` at application startup.

---

#### FINDING-014: Cargo workspace uses semver ranges without cargo audit enforcement

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 15.2.1 |
| **Files** | qdp/Cargo.toml:14-41 |
| **Source Reports** | 15.2.1.md |
| **Related** | None |

**Description:**

The Cargo workspace dependencies use appropriate semver ranges and Cargo.lock ensures reproducible builds, but there is no evidence that cargo audit is run against the lockfile to check for known vulnerabilities in resolved versions. Without auditing, compliance with ASVS 15.2.1 cannot be verified.

**Remediation:**

Add cargo audit to CI workflow as described in CRIT-001 remediation.

---

#### FINDING-015: Full Measurement Results Returned Without Filtering

| Attribute | Value |
|-----------|-------|
| **Severity** | 🔵 Low |
| **ASVS Level(s)** | L1 |
| **CWE** | N/A |
| **ASVS sections** | 15.3.1 |
| **Files** | qumat/qumat.py:265-310 |
| **Source Reports** | 15.3.1.md |
| **Related** | None |

**Description:**

The execute_circuit() method returns the complete measurement distribution without filtering options. While measurement results are naturally sparser than state vectors, for circuits approaching uniform distributions, the result dictionary can approach 2^N entries. There is no option to filter results by minimum count threshold, request only the top-k most probable states, or limit the total number of entries returned. For circuits with 20 qubits and uniform distributions, this can result in dictionaries with up to 2^20 entries.

**Remediation:**

Add optional filtering parameters to execute_circuit(): min_count (int | None) for minimum count threshold to filter returned results, and top_k (int | None) to return only the top-k most frequent results. When min_count is provided, filter the results dictionary to only include entries with counts >= min_count. When top_k is provided, sort results by count in descending order and return only the top-k entries. Default behavior should return full results for backward compatibility.

---

# 4. Positive Security Controls

| Control ID | Control Description | Evidence | Affected Files | Domain |
|------------|-------------------|----------|----------------|---------|
| PSC-001 | Comprehensive error messages as documentation | The validation functions in preprocessing.rs and validation.rs produce detailed error messages that effectively serve as documentation of validation rules | `qdp/qdp-core/src/preprocessing.rs`, `qdp/qdp-core/src/validation.rs` | quantum_circuit_input_validation |
| PSC-002 | Bitmask error constants with comments | The validation.cu file defines BASIS_IDX_ERR_* constants with clear names that document what constitutes invalid input | `validation.cu` | quantum_circuit_input_validation |
| PSC-003 | Type-safe enum for encoding methods | Using Encoding enum rather than stringly-typed validation ensures the set of valid encoding methods is documented by the type system itself | `qdp_core::Encoding` | quantum_circuit_input_validation |
| PSC-004 | Domain-specific constraint documentation | The MAX_QUBITS constant and its relationship to GPU memory (2^30 = 8GB) documents the rationale for the limit, not just the limit itself | `qdp/qdp-core/src/preprocessing.rs` | quantum_circuit_input_validation |
| PSC-005 | Two-stage validation architecture with CPU preprocessing in Rust | CPU preprocessing validates in Rust before GPU transfer. GPU kernels then re-validate on-device for defense-in-depth | `preprocessing.rs`, `validation.cu` | quantum_circuit_input_validation |
| PSC-006 | Overflow-safe arithmetic using checked_mul | checked_mul in validate_batch prevents integer overflow that could lead to undersized buffer allocation | `preprocessing.rs:100` | quantum_circuit_input_validation |
| PSC-007 | Defensive GPU output with safe defaults | validate_and_cast_basis_indices_kernel_f32 kernel writes indices_out[idx] = 0 for invalid entries to bound downstream kernel memory access | `validation.cu` | quantum_circuit_input_validation |
| PSC-008 | Atomic error flag accumulation using atomicOr | Using atomicOr with bitmasks provides detailed error diagnostics while remaining thread-safe across thousands of GPU threads | `validation.cu` | quantum_circuit_input_validation |
| PSC-009 | File extension positive matching | encode_from_file function uses explicit ends_with() checks against a known set of extensions | `engine.rs` | quantum_circuit_input_validation |
| PSC-010 | Rust as the security boundary | All user data entering from Python crosses through PyO3 bindings where Rust's type system provides hard enforcement. The usize type for qubit counts prevents negative values from ever reaching validation logic. | N/A | quantum_circuit_input_validation |
| PSC-011 | GPU validation as defense-in-depth | Even after CPU-side Rust validation, GPU kernels independently re-validate data. This means a bug in CPU validation cannot silently corrupt downstream GPU computation. | N/A | quantum_circuit_input_validation |
| PSC-012 | Consistent error propagation pattern | All validation layers (Python PyO3, Rust preprocessing, CUDA kernels) use the same error type hierarchy (MahoutError::InvalidInput) and return errors before performing side effects | N/A | quantum_circuit_input_validation |
| PSC-013 | Qubit index type and bounds validation for all gate operations | qumat.py:_validate_qubit_index enforced before backend delegation | `qumat/qumat.py` | quantum_circuit_input_validation |
| PSC-014 | Library choice provides reasonable defaults | The `object_store` crate when compiled with `rustls` (common default) inherently only supports TLS 1.2 and 1.3, with TLS 1.3 preferred | `qdp/qdp-core/src/remote.rs:62-95` | aws_braket_cloud_integration |
| PSC-015 | No explicit TLS downgrade configuration | Neither file explicitly configures weaker TLS versions or disables modern protocols | `qdp/qdp-core/src/remote.rs:62-95`, `qumat/amazon_braket_backend.py:33-36` | aws_braket_cloud_integration |
| PSC-016 | Cloud provider enforcement | AWS and GCP endpoints enforce TLS 1.2+ server-side, providing a compensating control regardless of client configuration | N/A | aws_braket_cloud_integration |
| PSC-017 | Python boto3 defaults to HTTPS | The amazon_braket_backend.py file creates sessions using boto3.Session(region_name=region) without exposing custom endpoint configuration. All AWS API calls go through HTTPS endpoints by default. | `amazon_braket_backend.py:initialize_backend` | aws_braket_cloud_integration |
| PSC-018 | URL scheme whitelist | The REMOTE_SCHEMES constant restricts recognized cloud URLs to s3:// and gs://, preventing arbitrary URL schemes from being processed. | `remote.rs:is_remote_path` | aws_braket_cloud_integration |
| PSC-019 | Query/fragment rejection in URL parsing | The parse_url function explicitly rejects URLs containing ? or #, preventing parameter injection that could alter connection behavior. | `remote.rs:parse_url` | aws_braket_cloud_integration |
| PSC-020 | Certificate validation (Rust) | object_store crate internals - uses webpki-roots (Mozilla CA bundle) or native-tls (system CA store) | `remote.rs` | aws_braket_cloud_integration |
| PSC-021 | Certificate validation (Python) | boto3/botocore internals - uses certifi CA bundle or system CA store | `amazon_braket_backend.py` | aws_braket_cloud_integration |
| PSC-022 | No certificate verification bypass | Neither file contains code to disable TLS certificate verification (no verify=False in Python, no .with_allow_invalid_certificates(true) in Rust) | `remote.rs`, `amazon_braket_backend.py` | aws_braket_cloud_integration |
| PSC-023 | Standard CA bundles | Both libraries use well-maintained CA bundles (webpki-roots/certifi) that contain only publicly trusted root certificates | `remote.rs`, `amazon_braket_backend.py` | aws_braket_cloud_integration |
| PSC-024 | No self-signed certificate accommodation in production code | Production code paths don't configure custom CAs for self-signed certificates (test configuration uses AWS_ENDPOINT=http://localhost:9123 for MinIO only) | `remote.rs`, `amazon_braket_backend.py` | aws_braket_cloud_integration |
| PSC-025 | AWS/GCP use publicly trusted certificates | All AWS Braket, S3, and GCS endpoints use certificates issued by publicly trusted CAs (Amazon Trust Services, Google Trust Services) | `remote.rs`, `amazon_braket_backend.py` | aws_braket_cloud_integration |
| PSC-026 | Version range constraints for all dependencies | All dependencies use semantic version ranges (e.g., >=2.2.0,&lt;3.0.0) limiting exposure to breaking/vulnerable versions | `pyproject.toml`, `qdp/Cargo.toml` | build_and_dependency_management |
| PSC-027 | Workspace dependency centralization | qdp/Cargo.toml uses [workspace.dependencies] ensuring consistent versions across workspace members | `qdp/Cargo.toml` | build_and_dependency_management |
| PSC-028 | Dependency override mechanism | pyproject.toml uses [tool.uv] override-dependencies to force newer versions of transitive dependencies with known issues (numba/llvmlite) | `pyproject.toml` | build_and_dependency_management |
| PSC-029 | Cargo resolver v2 | Using resolver = "2" which provides better feature unification and reduces unnecessary feature activation | `qdp/Cargo.toml` | build_and_dependency_management |
| PSC-030 | Lock file for reproducible builds | Cargo.lock referenced in domain context for reproducible builds | `Cargo.lock`, `qdp/Cargo.lock` | build_and_dependency_management |
| PSC-031 | Hash-pinned actions in testing workflow | actions/checkout, actions/setup-python, and dtolnay/rust-toolchain are pinned to specific commit SHAs in python-testing.yml, preventing tag-mutation attacks | `.github/workflows/python-testing.yml` | build_and_dependency_management |
| PSC-032 | Pinned release-critical actions | pypa/gh-action-pypi-publish and Jimver/cuda-toolkit are properly pinned in the release workflow | `.github/workflows/release.yml` | build_and_dependency_management |
| PSC-033 | Trusted publishing | PyPI publication uses OIDC id-token: write with environment protection (name: pypi), eliminating long-lived API tokens | `.github/workflows/release.yml` | build_and_dependency_management |
| PSC-034 | Upper version bounds | Dependencies use upper bounds (e.g., <3.0.0, <2.0) preventing unintended major version upgrades that could introduce vulnerabilities | `pyproject.toml`, `qdp/Cargo.toml` | build_and_dependency_management |
| PSC-035 | Static capsule name prevents injection | DLTENSOR_NAME: &[u8] = b"dltensor\0" is a compile-time constant | `tensor.rs` | general_security |
| PSC-036 | Typed error returns with hardcoded message prefixes | All errors use strongly-typed PyRuntimeError::new_err() with hardcoded message prefixes, preventing structure manipulation | `tensor.rs` | general_security |
| PSC-037 | Double-free prevention via consumed flag | consumed flag checked before both PyCapsule creation and Drop execution | `tensor.rs`, `dlpack.rs` | general_security |
| PSC-038 | Null pointer checks on entry paths | Null pointer checks on all entry paths before dereferencing self.ptr | `tensor.rs` | general_security |
| PSC-039 | Debug assertions for deleter presence | debug_assert! validating deleter presence in Drop | `tensor.rs` | general_security |
| PSC-040 | Strongly-typed interfaces prevent text-based injection | Rust's type system prevents all text-based injection classes structurally | `tensor.rs` | general_security |
| PSC-041 | Binary protocol usage prevents text-based injection | DLPack uses binary pointer exchange via PyCapsule, inherently immune to text-based injection | N/A | general_security |
| PSC-042 | Typed FFI calls only | All external calls use strongly-typed function signatures (PyCapsule_New, synchronize_stream, dlpack_stream_to_cuda), making shell injection structurally impossible | N/A | general_security |
| PSC-043 | No string-to-command conversion | The stream parameter (Option<i64&gt;) is passed as a typed integer to dlpack_stream_to_cuda(), never interpolated into a command string | N/A | general_security |
| PSC-044 | No dynamic code execution primitives | Entire file - Inherent to Rust language design | Entire file | general_security |
| PSC-045 | Function pointers are statically defined | dlpack_deleter function is compile-time fixed extern C function | `file:143` | general_security |
| PSC-046 | FFI calls to pre-compiled CUDA library | synchronize_stream uses pre-compiled native library calls, not dynamic execution | `file:47` | general_security |
| PSC-047 | Static dispatch for deleter callback | The dlpack_deleter function is statically-defined extern C function assigned at compile time in to_dlpack(). Cannot be replaced with arbitrary code at runtime. | `file:143` | general_security |
| PSC-048 | No custom cryptographic primitives implemented | The library correctly focuses on its computational domain (quantum state encoding) without implementing custom or ad-hoc cryptographic primitives | N/A | general_security |
| PSC-049 | Memory safety patterns for computational library domain | Code in dlpack.rs uses appropriate patterns (null checks, Option::take(), Arc reference counting) for memory safety including use-after-free prevention, double-free prevention, CUDA resource cleanup | `dlpack.rs` | general_security |
| PSC-050 | Input validation and resource limits | Documentation describes security-relevant behaviors including single-consume DLPack, num_qubits ≤ 30 limit, OOM pre-flight checks, input validation | N/A | general_security |
| PSC-051 | No deprecated or custom encryption implementations | No cipher algorithms or encryption modes are implemented in the codebase. The codebase exclusively handles GPU memory allocation, quantum state vector encoding, DLPack protocol, and CUDA FFI operations. | N/A | general_security |
| PSC-052 | Appropriate delegation of encryption-at-rest to storage/infrastructure layer | The library appropriately delegates security concerns like encryption-at-rest to the storage/infrastructure layer | N/A | general_security |
| PSC-053 | No misuse of hash functions for non-cryptographic numerical computation | The codebase does not misuse hash functions for non-cryptographic numerical computation | N/A | general_security |
| PSC-054 | No insecure hash algorithms (MD5, SHA-1) present | No MD5 or SHA-1 usage exists that could be confused for cryptographic purposes | N/A | general_security |
| PSC-055 | Appropriate use of mathematical operations for quantum encoding | Mathematical operations in QDP are L2 normalization, trigonometric functions, and phase calculations - none are cryptographic hash operations | N/A | general_security |
| PSC-056 | Clear separation between development and production installation methods | Documentation separates development setup (git clone for source builds) from production installation (pip install qumat[qdp]) | `getting-started.md` | general_security |
| PSC-057 | No query string/fragment support for remote URLs | Documented behavior in api.md and getting-started.md | `api.md`, `getting-started.md` | general_security |
| PSC-058 | AWS SDK standard credential chain | Credentials loaded via IAM/env/config files, not URLs | `amazon_braket_backend.py` | general_security |
| PSC-059 | Remote URL support explicitly excludes query strings and fragments | Prevents patterns like s3://bucket/key?aws_access_key_id=... from being possible | N/A | general_security |
| PSC-060 | Cloud SDK credential chains used instead of URL-embedded credentials | Library relies on cloud SDK credential chains rather than URL-embedded credentials | N/A | general_security |
| PSC-061 | DLPack single-consume pattern ensures GPU memory containing quantum state vectors is freed exactly once | Option::take() in free_dlpack_tensor | `dlpack.rs` | general_security |
| PSC-062 | GpuStateVector uses Arc&lt;BufferStorage&gt; with RAII semantics | Arc reference counting for GPU buffer lifetime | `dlpack.rs` | general_security |
| PSC-063 | Scalar extraction from full results | measure_overlap() returns single float overlap value instead of full circuit results, demonstrating exemplary data minimization | `qumat.py:505-547` | general_security |
| PSC-064 | Probability extraction | calculate_prob_zero() extracts single probability from measurement results | `qumat.py:549-565` | general_security |
| PSC-065 | Status-only returns | run_dual_stream_pipeline() returns Result<()> with pipeline status only, no internal buffers or state exposed | `pipeline.rs:280` | general_security |
| PSC-066 | Single-value L2 norm | calculate_l2_norm() returns single f64 norm, not intermediate squared values or per-element contributions | `preprocessing.rs:54` | general_security |
| PSC-067 | Batch norms without raw data | calculate_batch_l2_norms() returns Vec&lt;f64&gt; norms only, one scalar per sample, not the sample data itself | `preprocessing.rs:111` | general_security |
| PSC-068 | Input validation returns | validate_input() and validate_batch() return only Result<()> validity status, not echoing back input data | `preprocessing.rs:29`, `preprocessing.rs:81` | general_security |
| PSC-069 | Memory lifecycle ordering enforced by design | free_dlpack_tensor uses Option::take() to ensure the deleter can only be called once, preventing double-free | N/A | general_security |
| PSC-070 | Arc reference counting for GPU buffer lifetime management | GPU buffer lifetime is managed through reference counting, ensuring deallocation only occurs after all consumers release their reference | N/A | general_security |
| PSC-071 | Appropriate architectural separation of concerns for computational library | The library correctly delegates access control and security responsibilities to the consuming application | N/A | general_security |
| PSC-072 | No false sense of security from partial authorization controls | No false sense of security is created by partial or incomplete authorization controls within the library | N/A | general_security |
| PSC-073 | Process-level ownership enforcement via Arc&lt;BufferStorage&gt; | GPU memory buffers use Arc&lt;BufferStorage&gt; reference counting, which enforces ownership at the process/thread level | `dlpack.rs` | general_security |
| PSC-074 | Single-consume pattern for tensor handles | DLPack single-consume pattern using Option::take() in free_dlpack_tensor prevents re-use of already-consumed tensor handles | `dlpack.rs` | general_security |
| PSC-075 | All memory management and resource control logic executes within the Rust runtime | All memory management and resource control logic executes within the Rust runtime with no pathway for external untrusted consumer manipulation | `dlpack.rs` | general_security |
| PSC-076 | No cryptographic token processing code exists | No token creation, verification, or cryptographic signing operations exist in the codebase. This eliminates key confusion and untrusted key injection attack surface. | N/A | general_security |

---

# 5. ASVS Compliance Summary

| ASVS ID | Title | Status | Justification |
|---------|-------|--------|---------------|
| 2.1.1 | Validation and Business Logic Documentation | **Partial** | Error messages serve as inline documentation (PSC-001), but formal validation documentation is incomplete. See FINDING-005, FINDING-011, FINDING-012. |
| 2.2.1 | Input Validation | **Partial** | Strong validation exists for quantum circuit parameters (PSC-005, PSC-006, PSC-013), but gaps remain. See FINDING-005, FINDING-006, FINDING-011, FINDING-012. |
| 2.2.2 | Input Validation at Trusted Service Layer | **Partial** | Two-stage validation architecture (PSC-005) provides defense-in-depth, but some edge cases remain. See FINDING-011. |
| 12.1.1 | General TLS Security Guidance | **Partial** | Library defaults provide TLS 1.2+ (PSC-014, PSC-015), but no explicit configuration exists. See FINDING-013. |
| 12.2.1 | HTTPS Communication with External Facing Services | **Fail** | Python boto3 defaults to HTTPS (PSC-017), but `from_env()` allows HTTP fallback via environment variables. See FINDING-007. |
| 12.2.2 | Publicly Trusted TLS Certificates | **Pass** | Certificate validation enabled by default (PSC-020, PSC-021, PSC-022), standard CA bundles used (PSC-023), AWS/GCP use publicly trusted CAs (PSC-025). |
| 1.5.1 | XML Parser Configuration - XXE Prevention | **Pass** | No XML parsing functionality exists in the codebase. |
| 15.1.1 | Risk-Based Remediation Time Frames Documentation | **Fail** | No documented remediation time frames exist. See FINDING-003. |
| 15.2.1 | Components Within Documented Remediation Time Frames | **Fail** | No automated vulnerability scanning or dependency update tracking. See FINDING-004, FINDING-008, FINDING-009, FINDING-014. |
| 1.2.1 | Output Encoding for HTTP Response / HTML / XML / CSS | **N/A** | Computational library with no web output generation. |
| 1.2.2 | URL Encoding and Safe URL Protocols | **N/A** | URL scheme whitelist exists (PSC-018) but only for cloud storage, not user-facing web content. |
| 1.2.3 | JavaScript / JSON Output Encoding | **N/A** | No JavaScript/JSON output generation. |
| 1.2.4 | Parameterized Queries / SQL Injection | **N/A** | No database interaction. |
| 1.2.5 | OS Command Injection | **Pass** | Typed FFI calls only (PSC-042), no string-to-command conversion (PSC-043), no dynamic code execution primitives (PSC-044). |
| 1.3.1 | HTML Sanitization for WYSIWYG / Rich Input | **N/A** | No HTML processing. |
| 1.3.2 | Sanitization — Dynamic Code Execution | **Pass** | No dynamic code execution primitives (PSC-044), function pointers are statically defined (PSC-045), static dispatch for callbacks (PSC-047). |
| 10.4.1 | Authorization server validates redirect URIs based on client-specific allowlist | **N/A** | Not an OAuth authorization server. |
| 10.4.2 | Authorization Code Single Use Validation | **N/A** | Not an OAuth authorization server. |
| 10.4.3 | Authorization code lifetime verification | **N/A** | Not an OAuth authorization server. |
| 10.4.4 | Authorization server grant type restrictions | **N/A** | Not an OAuth authorization server. |
| 10.4.5 | Authorization Server Refresh Token Replay Attack Mitigation | **N/A** | Not an OAuth authorization server. |
| 11.3.1 | Encryption Algorithms - Insecure Block Modes and Padding | **N/A** | No encryption implementation (PSC-048, PSC-051). |
| 11.3.2 | Encryption Algorithms - Approved Ciphers and Modes | **N/A** | No encryption implementation (PSC-048, PSC-051). |
| 11.4.1 | Hashing and Hash-based Functions - Approved Hash Functions | **N/A** | No cryptographic hashing (PSC-053, PSC-054, PSC-055). |
| 13.4.1 | Unintended Information Leakage - Source Control Metadata | **N/A** | Computational library, not a deployed web application. |
| 14.2.1 | General Data Protection - Sensitive Data in URLs | **N/A** | Query/fragment rejection exists (PSC-019, PSC-057) but for cloud storage URLs, not user-facing web URLs. |
| 14.3.1 | Client-side Data Protection - Clear Authenticated Data | **N/A** | Not a web application with client-side storage. |
| 15.3.1 | Verify that the application only returns the required subset of fields from a data object | **Fail** | Strong data minimization patterns exist (PSC-063 through PSC-068), but full state vectors returned without subsetting. See FINDING-010, FINDING-015. |
| 2.3.1 | Business Logic Security — Sequential Step Order | **N/A** | Memory lifecycle ordering enforced by design (PSC-069, PSC-070) but not multi-step business logic. |
| 3.2.1 | Unintended Content Interpretation — Browser Rendering Controls | **N/A** | Not a web application. |
| 3.2.2 | Unintended Content Interpretation — Safe Text Rendering | **N/A** | Not a web application. |
| 3.3.1 | Cookie Setup — Secure Attribute and Prefix | **N/A** | Not a web application. |
| 3.4.1 | Browser Security Mechanism Headers — HSTS | **N/A** | Not a web application. |
| 3.4.2 | Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin Validation | **N/A** | Not a web application. |
| 3.5.1 | Cross-Origin Request Validation | **N/A** | Not a web application. |
| 3.5.2 | CORS Preflight Mechanism Verification | **N/A** | Not a web application. |
| 3.5.3 | HTTP Method Validation for Sensitive Functionality | **N/A** | Not a web application. |
| 4.1.1 | HTTP Response Content-Type Header Validation | **N/A** | Not a web application. |
| 4.4.1 | WebSocket over TLS (WSS) | **N/A** | No WebSocket functionality. |
| 5.2.1 | File Size Validation | **N/A** | File processing exists but for local/cloud data files, not user uploads in a web context. |
| 5.2.2 | File upload validation - extension and content type verification | **N/A** | File extension validation exists (PSC-009) but for local/cloud data files, not user uploads. |
| 5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code | **N/A** | Not a web application with file uploads. |
| 5.3.2 | File Path Construction from User Input | **N/A** | Cloud storage path parsing exists but uses strict validation (PSC-018, PSC-019), not general file path construction. |
| 6.1.1 | Documentation of rate limiting, anti-automation, and adaptive response controls | **N/A** | Not an authentication system. |
| 6.2.1 | User Password Minimum Length | **N/A** | Not an authentication system. |
| 6.2.2 | Verify that users can change their password | **N/A** | Not an authentication system. |
| 6.2.3 | Password change functionality requires current and new password | **N/A** | Not an authentication system. |
| 6.2.4 | Password Dictionary Check | **N/A** | Not an authentication system. |
| 6.2.5 | Password Composition Requirements | **N/A** | Not an authentication system. |
| 6.2.6 | Password Input Field Masking | **N/A** | Not an authentication system. |
| 6.2.7 | Paste functionality, browser password helpers, and external password managers are permitted | **N/A** | Not an authentication system. |
| 6.2.8 | Password Verification Without Modification | **N/A** | Not an authentication system. |
| 6.3.1 | Credential Stuffing and Password Brute Force Prevention | **N/A** | Not an authentication system. |
| 6.3.2 | Verify that default user accounts are not present in the application or are disabled | **N/A** | Not an authentication system. |
| 6.4.1 | Secure Initial Passwords and Activation Codes | **N/A** | Not an authentication system. |
| 6.4.2 | Password hints or knowledge-based authentication | **N/A** | Not an authentication system. |
| 7.2.1 | Verify that the application performs all session token verification using a trusted, backend service | **N/A** | Not a session management system. |
| 7.2.2 | Dynamic Session Token Generation | **N/A** | Not a session management system. |
| 7.2.3 | Session Token Entropy and CSPRNG Requirements | **N/A** | Not a session management system. |
| 7.2.4 | Session token regeneration on authentication | **N/A** | Not a session management system. |
| 7.4.1 | Session Termination and Invalidation | **N/A** | Not a session management system. |
| 7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted | **N/A** | Not a session management system. |
| 8.1.1 | Authorization documentation defines rules for restricting function-level and data-specific access | **N/A** | Appropriate architectural separation (PSC-071) - computational library delegates authorization to consuming application. |
| 8.2.1 | Function-Level Access Control | **N/A** | Appropriate architectural separation (PSC-071) - computational library delegates authorization to consuming application. |
| 8.2.2 | Data-Specific Access Control (IDOR/BOLA Prevention) | **N/A** | Process-level ownership enforcement (PSC-073) prevents object reference manipulation, but this is memory safety, not application-level authorization. |
| 8.3.1 | Authorization at Trusted Service Layer | **N/A** | Appropriate architectural separation (PSC-071) - computational library delegates authorization to consuming application. |
| 9.1.1 | Self-Contained Token Signature Validation | **N/A** | No cryptographic token processing (PSC-076). |
| 9.1.2 | Algorithm Allowlist for Token Creation/Verification | **N/A** | No cryptographic token processing (PSC-076). |
| 9.1.3 | Key Material from Trusted Pre-Configured Sources | **N/A** | No cryptographic token processing (PSC-076). |
| 9.2.1 | Token Validity Time Span Verification | **N/A** | No cryptographic token processing (PSC-076). |

---

# 6. Cross-Reference Matrix

| Finding ID | Severity | ASVS Controls | Positive Controls | Related Findings |
|------------|----------|---------------|-------------------|------------------|
| FINDING-003 | High | 15.1.1 | PSC-026, PSC-027, PSC-028, PSC-029, PSC-030, PSC-034 | |
| FINDING-004 | High | 15.2.1 | PSC-026, PSC-027, PSC-028, PSC-029, PSC-030, PSC-031, PSC-032, PSC-034 | FINDING-008, FINDING-009, FINDING-014 |
| FINDING-005 | Medium | 2.1.1, 2.2.1 | PSC-001, PSC-005, PSC-006, PSC-010, PSC-011, PSC-012 | FINDING-011, FINDING-012 |
| FINDING-006 | Medium | 2.2.1 | PSC-003, PSC-009, PSC-010, PSC-013 | FINDING-005, FINDING-011, FINDING-012 |
| FINDING-007 | Medium | 12.2.1 | PSC-014, PSC-015, PSC-016, PSC-017, PSC-018, PSC-019, PSC-020, PSC-021, PSC-022, PSC-023, PSC-024, PSC-025 | FINDING-013 |
| FINDING-008 | Medium | 15.2.1 | PSC-031, PSC-032, PSC-033 | FINDING-004, FINDING-009, FINDING-014 |
| FINDING-009 | Medium | 15.2.1 | PSC-031, PSC-032, PSC-033 | FINDING-004, FINDING-008, FINDING-014 |
| FINDING-010 | Medium | 15.3.1 | PSC-063, PSC-064, PSC-065, PSC-066, PSC-067, PSC-068 | FINDING-015 |
| FINDING-011 | Low | 2.2.1, 2.2.2, 2.1.1 | PSC-001, PSC-005, PSC-010, PSC-011, PSC-012, PSC-013 | FINDING-005, FINDING-006, FINDING-012 |
| FINDING-012 | Low | 2.2.1 | PSC-001, PSC-005, PSC-010, PSC-011, PSC-012, PSC-013 | FINDING-005, FINDING-006, FINDING-011 |
| FINDING-013 | Low | 12.1.1 | PSC-014, PSC-015, PSC-016, PSC-017, PSC-018, PSC-019, PSC-020, PSC-021, PSC-022, PSC-023, PSC-024, PSC-025 | FINDING-007 |
| FINDING-014 | Low | 15.2.1 | PSC-026, PSC-027, PSC-028, PSC-029, PSC-030, PSC-031, PSC-032, PSC-034 | FINDING-004, FINDING-008, FINDING-009 |
| FINDING-015 | Low | 15.3.1 | PSC-063, PSC-064, PSC-065, PSC-066, PSC-067, PSC-068 | FINDING-010 |

**Matrix Interpretation Guide:**

- **ASVS Controls**: Lists the OWASP ASVS requirements that the finding relates to (either as a gap or partial implementation)
- **Positive Controls**: References the security controls (from Section 4) that provide context or partial mitigation for the finding
- **Related Findings**: Groups findings that share common root causes, affected domains, or remediation strategies

**Key Relationships:**

1. **Dependency Management Cluster** (002, 003, 004, 008, 009, 014): All relate to third-party dependency security, vulnerability tracking, and supply chain integrity
2. **Input Validation Cluster** (FINDING-005, 006, 011, 012): All relate to gaps in input validation despite strong baseline controls
3. **TLS Configuration Cluster** (FINDING-007, 013): Both relate to TLS/HTTPS configuration and enforcement
4. **Data Minimization Cluster** (FINDING-010, 015): Both relate to returning more data than necessary from operations

## 7. Level Coverage Analysis


**Audit scope:** up to L1

| Level | Sections Audited | Findings Found |
|-------|-----------------|----------------|
| L1 | 70 | 15 |

**Total consolidated findings: 15**

*End of Consolidated Security Audit Report*