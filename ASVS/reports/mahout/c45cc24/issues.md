# Security Issues

## Issue: FINDING-001 - num_qubits parameter lacks validation for type, sign, and upper bound
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `num_qubits` parameter in `qumat.py` is not validated for type, sign, or upper bound, leading to undefined behavior, potential resource exhaustion (DoS), and confusing error messages when invalid values are provided.

### Details
The `num_qubits` parameter is stored directly without validation and used in subsequent range checks for qubit indices. Invalid values produce undefined behavior:
- **Float or non-numeric types**: Logic errors and type confusion
- **Negative values**: Confusing error messages downstream
- **Extremely large values**: Resource exhaustion and denial of service
- **No upper bound**: QDP documentation specifies 1–30 as valid range, but `qumat.py` enforces no upper limit

**Affected Files:**
- `qumat/qumat.py` (lines 82-85)

**CWE:** Not specified
**ASVS:** 2.2.1 (Level L1)

### Remediation
Add validation to check:
1. `num_qubits` is an integer using `isinstance()`
2. `num_qubits` is non-negative
3. Optionally enforce upper bound (e.g., 30 per QDP documentation)
4. Raise `TypeError` for non-integer types
5. Raise `ValueError` for out-of-range values with clear error messages

```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    if num_qubits is not None:
        if not isinstance(num_qubits, int):
            raise TypeError(f"num_qubits must be an integer, got {type(num_qubits).__name__}")
        if num_qubits < 1 or num_qubits > 30:
            raise ValueError(f"num_qubits must be between 1 and 30, got {num_qubits}")
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
```

### Acceptance Criteria
- [x] Type validation added using `isinstance()`
- [x] Range validation added (1-30)
- [x] Clear error messages for invalid input
- [x] Test added for invalid types (float, string, None when required)
- [x] Test added for negative values
- [x] Test added for values exceeding upper bound

### References
- Source: 2.2.1.md
- ASVS Section: 2.2.1

### Priority
High

---

## Issue: FINDING-002 - Remote IO feature lacks visible TLS certificate validation configuration
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `remote-io` feature enables cloud object storage access (S3/GCS) but the implementation is not included in audit scope. Without verification, TLS certificate validation may be missing or bypassable, exposing data in transit to man-in-the-middle attacks.

### Details
The `remote` module is conditionally enabled but not provided for audit. Potential risks:
- No verification that publicly trusted TLS certificates are enforced
- Possible insecure connection options or `VERIFY_SSL=false` bypasses
- Training datasets and model parameters transmitted over potentially insecure connections
- Compromise of data integrity and confidentiality

**Affected Files:**
- `qdp/qdp-core/src/lib.rs` (line 24)
- `docs/qdp/api.md`
- `docs/qdp/getting-started.md`

**CWE:** CWE-295 (Improper Certificate Validation)
**ASVS:** 12.2.2 (Level L1)

### Remediation
1. Verify the `remote` module enforces TLS 1.2+ with publicly trusted certificates
2. Ensure no `VERIFY_SSL=false` or equivalent bypass is available
3. Document TLS requirements for remote IO connections
4. Example implementation using reqwest:

```rust
reqwest::Client::builder()
    .min_tls_version(reqwest::tls::Version::TLS_1_2)
    .use_rustls_tls()
    .build()?
```

This ensures Mozilla's root certificate store is used for validation.

### Acceptance Criteria
- [x] Remote module code reviewed for TLS implementation
- [x] TLS 1.2+ enforcement verified
- [x] Certificate validation confirmed to use trusted root store
- [x] No insecure bypass options available
- [x] TLS requirements documented in API documentation
- [x] Test added for certificate validation failure scenarios

### References
- Source: 12.2.2.md
- ASVS Section: 12.2.2

### Priority
Medium

---

## Issue: FINDING-003 - No deployment configuration to exclude source control metadata from production artifacts
**Labels:** bug, security, priority:medium
**Description:**
### Summary
If the application is deployed from a git checkout, the `.git` folder could be exposed in production, revealing repository history, developer information, and configuration details that aid reconnaissance.

### Details
**Data Flow:** Source repository (`.git/`) → development/build environment → packaged artifact → deployment

**Exposure Risk:**
- Full repository history including sensitive commits
- Internal developer information (email addresses, commit messages)
- Configuration details aiding reconnaissance

**Positive Pattern Identified:** PyPI distribution via `maturin build` and `uv build` produces wheel/sdist artifacts that do not include `.git`.

**Affected Files:**
- `docs/qdp/getting-started.md`
- `dev/release.md`

**CWE:** Not specified
**ASVS:** 13.4.1 (Level L1)

### Remediation
1. Add `.dockerignore` with exclusion rules:
```
.git
.svn
.gitignore
dev/
*.md
```

2. Document deployment best practices that explicitly exclude VCS metadata
3. Add verification step to release process to ensure VCS metadata is not included
4. For container deployments, use multi-stage builds that copy only necessary files

### Acceptance Criteria
- [x] `.dockerignore` file created with VCS exclusions
- [x] Deployment documentation updated with best practices
- [x] Release checklist includes VCS metadata verification
- [x] Test added to verify `.git` is not present in built artifacts
- [x] Container build process verified to exclude VCS metadata

### References
- Source: 13.4.1.md
- ASVS Section: 13.4.1

### Priority
Medium

---

## Issue: FINDING-004 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The project lacks documented remediation timeframes for third-party component vulnerabilities, creating inconsistent risk treatment and potentially indefinite exposure windows for known vulnerabilities.

### Details
**Current Gap:** The release process (`dev/release.md`) covers branching, building, signing, voting, and publishing but does not mention:
- Dependency vulnerability scanning
- Remediation timeframes (critical: X days, high: Y days, etc.)
- SBOM generation
- Dependency audit procedures

**Risk Impact:**
- Known vulnerabilities in dependencies (cudarc, thiserror, arrow, parquet, CUDA runtime, PyTorch) may persist indefinitely
- No consistent standard for when updates must be applied
- Increased window of exposure for supply chain attacks
- Inconsistent risk treatment across the project

**Affected Files:**
- `dev/release.md` (entire file)

**CWE:** Not specified
**ASVS:** 15.1.1 (Level L1)

### Remediation
Create `SECURITY.md` or `docs/security/dependency-policy.md` defining:

**Remediation Timeframes:**
- **Critical** (CVSS ≥ 9.0): 7 calendar days for RCE, data exfiltration, privilege escalation
- **High** (CVSS 7.0–8.9): 30 calendar days for significant impact vulnerabilities
- **Medium** (CVSS 4.0–6.9): 90 calendar days for limited impact vulnerabilities
- **Low** (CVSS < 4.0): Next scheduled release for minimal impact

**General Update Policy:**
- All dependencies reviewed quarterly
- `cargo audit` / `pip-audit` run in CI on every PR
- SBOM generated with each release

**Dangerous Components Requiring Extra Scrutiny:**
- `qdp_kernels` (CUDA FFI — unsafe operations, direct memory manipulation)
- `cudarc` (CUDA driver bindings — GPU memory allocation, raw pointers)
- Parquet/Arrow readers (Binary data parsing from untrusted files)

### Acceptance Criteria
- [x] SECURITY.md or dependency policy document created
- [x] Remediation timeframes documented by severity
- [x] General update policy documented
- [x] Dangerous components identified and documented
- [x] CI integration for cargo audit and pip-audit added
- [x] SBOM generation added to release process

### References
- Source: 15.1.1.md
- ASVS Section: 15.1.1

### Priority
Medium

---

## Issue: FINDING-005 - Unable to verify component currency without documented remediation timeframes
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Without documented remediation timeframes (ASVS 15.1.1), compliance with ASVS 15.2.1 is structurally impossible to verify. Dependencies may contain known CVEs without detection mechanisms, and no lock files were provided for audit.

### Details
**Structural Dependencies:**
- This finding cannot be resolved without first addressing FINDING-004
- No `Cargo.lock` or `requirements.txt` freeze file provided for audit
- Version verification impossible

**Specific Risks:**
- Dependencies may contain known CVEs without detection mechanism
- `qdp_kernels` crate (internal) contains unsafe CUDA FFI requiring careful version management
- Parquet/Arrow file parsers handle untrusted input and are common vulnerability sources

**Affected Files:**
- `qdp/qdp-core/src/gpu/memory.rs`
- `qdp/qdp-core/src/error.rs`
- `dev/release.md`

**CWE:** Not specified
**ASVS:** 15.2.1 (Level L1)

### Remediation
1. **Implement the policy from FINDING-004** (prerequisite)
2. Add automated dependency scanning to CI:
   - `cargo audit` for Rust dependencies
   - `pip-audit` for Python dependencies
3. Include `Cargo.lock` in the repository for reproducible builds and auditability
4. Add dependency review step to release process in `dev/release.md`:
   - Run `cargo audit` and resolve all findings above threshold
   - Run `pip-audit` for Python dependencies
   - Verify no dependencies exceed their remediation timeframe
   - Generate SBOM: `cargo sbom > sbom.json`

### Acceptance Criteria
- [x] FINDING-004 resolved (prerequisite)
- [x] Cargo.lock committed to repository
- [x] cargo audit integrated into CI pipeline
- [x] pip-audit integrated into CI pipeline
- [x] Release process updated with dependency review steps
- [x] SBOM generation added to release process
- [x] Test run of full dependency audit process completed

### References
- Source: 15.2.1.md
- ASVS Section: 15.2.1
- Related: FINDING-004

### Priority
Medium

---

## Issue: FINDING-006 - Backend modules receive entire configuration dictionary instead of required fields only
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Backend modules receive the entire `backend_config` dictionary rather than only required fields, creating information leakage risk and implicit coupling through state mutation between calls.

### Details
**Current Implementation:**
- `self.backend_config` contains all constructor-supplied configuration
- Dictionary is mutated to accumulate state between calls
- `parameter_values` are injected into the shared config object
- Backend functions receive full configuration object

**Security/Design Risks:**
- Backend modules receive more data than required for their operation
- If backend logs, serializes, or exposes config in error messages, scoped fields could leak
- Mutation pattern creates implicit coupling between sequential calls
- Violates principle of least privilege for data access

**Affected Files:**
- `qumat/qumat.py` (lines 243-262, 283-302)

**CWE:** Not specified
**ASVS:** 15.3.1, 2.3.1 (Level L1)

### Remediation
Pass only what the backend needs by creating a scoped execution configuration:

```python
def execute_circuit(self, parameter_values: dict | None = None) -> dict:
    # Validate and bind parameters
    bound_parameters = self._bind_parameters(parameter_values)
    
    # Create scoped configuration with only required fields
    execution_config = {
        "parameter_values": bound_parameters,
        "shots": self.backend_config["backend_options"].get("shots", 1024)
    }
    
    # Pass scoped config instead of full backend_config
    result = self.backend_module.execute_circuit(
        self.backend,
        self.circuit,
        execution_config  # Not self.backend_config
    )
    return result
```

### Acceptance Criteria
- [x] Scoped execution_config dictionary created
- [x] Only parameter_values and shots passed to backend
- [x] Full backend_config no longer passed to backend modules
- [x] State mutation removed from shared config object
- [x] Test added verifying backends receive only required fields
- [x] Test added verifying sequential calls don't share state

### References
- Source: 15.3.1.md, 2.3.1.md
- ASVS Sections: 15.3.1, 2.3.1
- Merged from: ASVS-1531-MED-001, CH02-006

### Priority
Medium

---

## Issue: FINDING-007 - QuMat class lacks structured documentation defining input validation rules
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The QuMat class lacks structured documentation defining input validation rules for its parameters. While docstrings describe parameter types, they do not specify valid ranges, allowed values, or expected structures as formal validation rules.

### Details
**Documentation Gaps:**
- `create_empty_circuit(num_qubits)`: No documented valid range
- `apply_rx_gate(qubit_index, angle)`: No documented constraints for angle (finite-only, radian range)
- `apply_u_gate(qubit_index, theta, phi, lambd)`: No documented constraints on rotation angles
- `backend_config`: No schema or structural validation rules beyond required keys

**Contrast:** QDP API documentation explicitly specifies ranges (e.g., num_qubits 1–30) and allowed encoding methods.

**Impact:**
- Developers implementing backends lack clear guidance on valid input
- Inconsistent validation across backends
- Potential runtime failures with unclear error messages
- Consumers of the API cannot determine valid input programmatically

**Affected Files:**
- `qumat/qumat.py` (class-level and method-level docstrings)

**CWE:** Not specified
**ASVS:** 2.1.1 (Level L1)

### Remediation
Add a validation rules section to the QuMat class docstring:

```python
class QuMat:
    """
    Quantum Matrix operations interface.
    
    Validation Rules:
    ----------------
    - num_qubits: int, range [1, 30] (or backend-specific maximum)
    - qubit_index: int, range [0, num_qubits - 1]
    - angle (rotation gates): float, must be finite (no NaN/Inf)
    - backend_name: str, one of {"qiskit", "cirq", "amazon_braket"}
    - backend_options: dict with:
        - Required: "simulator_type" (str)
        - Optional: "shots" (int, >= 1)
    
    ...
    """
```

Add similar validation rules sections to each method docstring.

### Acceptance Criteria
- [x] Class-level docstring updated with validation rules
- [x] Method-level docstrings updated with parameter constraints
- [x] Documentation specifies valid ranges for all numeric parameters
- [x] Documentation specifies allowed values for enum-like parameters
- [x] Documentation specifies required structure for dict parameters
- [x] Examples added showing valid and invalid inputs

### References
- Source: 2.1.1.md
- ASVS Section: 2.1.1

### Priority
Medium

---

## Issue: FINDING-008 - Rotation angle parameters not validated for finiteness or type correctness
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Rotation angle parameters are not validated for finiteness (NaN, Inf) or type correctness. While string parameter names are registered, float values pass through unchecked, potentially producing mathematically undefined quantum states.

### Details
**Current Behavior:**
- `_handle_parameter` registers string parameter names
- Float values pass through unchecked
- No validation for NaN or Inf values
- No type checking for numeric values

**Impact:**
- NaN or Inf values produce mathematically undefined quantum states
- Backends may silently produce incorrect results rather than raising errors
- Data integrity issues in quantum computations
- Difficult to debug incorrect results

**QDP Documentation:** Explicitly requires finite values for similar parameters.

**Affected Files:**
- `qumat/qumat.py` (lines 303, 321, 339, 356)
  - `apply_rx_gate`
  - `apply_ry_gate`
  - `apply_rz_gate`
  - `apply_u_gate`

**CWE:** Not specified
**ASVS:** 2.2.1 (Level L1)

### Remediation
Create a `_validate_angle` helper function and apply to all rotation gates:

```python
def _validate_angle(self, angle: float | int | str, param_name: str) -> float | str:
    """Validate rotation angle parameter.
    
    Args:
        angle: Angle value or parameter name
        param_name: Name of the parameter for error messages
        
    Returns:
        Validated angle (float or str)
        
    Raises:
        TypeError: If angle is not numeric or string
        ValueError: If angle is not finite (NaN or Inf)
    """
    if isinstance(angle, str):
        return angle  # Parameter name, validated elsewhere
    
    if not isinstance(angle, (int, float)):
        raise TypeError(f"{param_name} must be numeric or a parameter name, got {type(angle).__name__}")
    
    if not math.isfinite(angle):
        raise ValueError(f"{param_name} must be finite, got {angle}")
    
    return float(angle)

def apply_rx_gate(self, qubit_index: int, angle: float | str) -> None:
    angle = self._validate_angle(angle, "angle")
    # ... rest of implementation
```

### Acceptance Criteria
- [x] `_validate_angle` helper function created
- [x] Type validation added (int, float, or str)
- [x] Finiteness validation added (reject NaN and Inf)
- [x] Applied to all rotation gate methods (rx, ry, rz, u)
- [x] Clear error messages for invalid input
- [x] Test added for NaN input
- [x] Test added for Inf input
- [x] Test added for invalid types

### References
- Source: 2.2.1.md
- ASVS Section: 2.2.1

### Priority
Medium

---

## Issue: FINDING-009 - backend_options and backend_name lack structure and allow-list validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `backend_options` value is checked for existence but not validated for type or structure. The `backend_name` is not validated against an allow-list, relying solely on `import_module` to fail for unknown names, producing unclear error messages.

### Details
**Current Implementation:**
- `backend_options` checked for existence only, not type or structure
- `backend_name` validated implicitly through ImportError
- No explicit business rule validation
- Unclear error messages for misconfigured backends

**Issues:**
- TypeError from backend code instead of clear validation error
- No early detection of configuration errors
- Difficult to debug for users unfamiliar with Python imports
- No documentation of allowed backend names

**Affected Files:**
- `qumat/qumat.py` (lines 53-75)

**CWE:** Not specified
**ASVS:** 2.2.1 (Level L1)

### Remediation
Add explicit validation for backend configuration:

```python
ALLOWED_BACKENDS = {"qiskit", "cirq", "amazon_braket"}

def __init__(self, backend_config: dict):
    # Validate backend_name
    backend_name = backend_config.get("backend_name")
    if not isinstance(backend_name, str):
        raise TypeError(f"backend_name must be a string, got {type(backend_name).__name__}")
    
    if backend_name not in ALLOWED_BACKENDS:
        raise ValueError(
            f"Unknown backend: {backend_name}. "
            f"Allowed backends: {', '.join(sorted(ALLOWED_BACKENDS))}"
        )
    
    # Validate backend_options
    backend_options = backend_config.get("backend_options")
    if backend_options is None:
        raise ValueError("backend_options is required in backend_config")
    
    if not isinstance(backend_options, dict):
        raise TypeError(
            f"backend_options must be a dict, got {type(backend_options).__name__}"
        )
    
    # ... rest of implementation
```

### Acceptance Criteria
- [x] ALLOWED_BACKENDS constant defined
- [x] backend_name validated against allow-list
- [x] backend_options validated for type (dict)
- [x] Clear error messages listing allowed values
- [x] Test added for unknown backend name
- [x] Test added for invalid backend_options type
- [x] Test added for missing backend_options

### References
- Source: 2.2.1.md
- ASVS Section: 2.2.1

### Priority
Medium

---

## Issue: FINDING-010 - Stale parameter state persists across circuit resets
**Labels:** bug, security, priority:medium
**Description:**
### Summary
When `create_empty_circuit` is called again on an existing QuMat instance, it resets the circuit and num_qubits but does **not** reset the parameters dictionary, allowing stale parameter registrations to persist and potentially corrupt new circuit computations.

### Details
**Current Behavior:**
- `create_empty_circuit` resets `self.circuit` and `self.num_qubits`
- `self.parameters` is **not** reset
- Stale parameter registrations and bound values persist
- Stale parameters injected into new circuit via `backend_config["parameter_values"]`

**Validation Gap:**
- The unbound parameter check in `execute_circuit` only catches parameters with `None` values
- Fully bound stale parameters pass through silently

**Impact:**
- Incorrect quantum computation results
- Silent corruption of computation parameters
- Difficult to debug in scientific computing contexts
- Violation of principle of least surprise

**Affected Files:**
- `qumat/qumat.py` (lines 82-85)

**CWE:** Not specified
**ASVS:** 2.3.1 (Level L1)

### Remediation
Reset the parameter registry when creating a new circuit:

```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    """Create a new empty quantum circuit.
    
    Args:
        num_qubits: Number of qubits for the new circuit
        
    Note:
        This resets all circuit state including registered parameters.
    """
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
    self.parameters = {}  # Reset parameter registry for new circuit
```

### Acceptance Criteria
- [x] Parameter registry reset added to `create_empty_circuit`
- [x] Documentation updated to note state reset behavior
- [x] Test added verifying parameters are cleared on circuit reset
- [x] Test added verifying old parameters don't affect new circuit
- [x] Test added for sequential circuit creation with different parameters

### References
- Source: 2.3.1.md
- ASVS Section: 2.3.1

### Priority
Medium

---

## Issue: FINDING-011 - `path_from_py` accepts user-supplied file paths with no validation or sanitization
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `path_from_py` function accepts user-supplied file paths without validation or sanitization, creating path traversal and SSRF attack surfaces when integrated into services accepting untrusted input.

### Details
**Current Implementation:**
- Accepts str or pathlib.Path objects from Python callers
- Converts to strings without validation
- No checks for path traversal sequences (`../`, `..\`, encoded variants)
- No null byte injection checks
- No scheme validation
- No canonicalization

**Attack Surface:**
- Used as input to multiple file I/O operations:
  - `encode_from_parquet`
  - `encode_from_arrow_ipc`
  - `encode_from_numpy`
  - `encode_from_torch`
  - `encode_from_tensorflow`
- When `remote-io` feature is enabled: `s3://` and `gs://` URLs accepted without validation (SSRF risk)

**Potential Attacks (if integrated into service with untrusted input):**
- Path traversal to read arbitrary files
- SSRF attacks against internal infrastructure
- Data exfiltration of sensitive files

**Affected Files:**
- `qdp/qdp-python/src/loader.rs` (lines 109-113)

**CWE:** CWE-22 (Path Traversal)
**ASVS:** 5.3.2 (Level L1)

### Remediation
Implement comprehensive path validation:

```rust
use std::path::{Path, PathBuf};

fn path_from_py(path: &PyAny) -> PyResult<String> {
    let path_str = if let Ok(s) = path.extract::<String>() {
        s
    } else if let Ok(p) = path.extract::<PathBuf>() {
        p.to_string_lossy().to_string()
    } else {
        return Err(PyTypeError::new_err("Path must be str or pathlib.Path"));
    };
    
    // 1. Reject null bytes
    if path_str.contains('\0') {
        return Err(PyValueError::new_err("Path contains null byte"));
    }
    
    // 2. Handle remote URLs separately
    if path_str.starts_with("s3://") || path_str.starts_with("gs://") {
        #[cfg(feature = "remote-io")]
        {
            validate_remote_url(&path_str)?;
            return Ok(path_str);
        }
        #[cfg(not(feature = "remote-io"))]
        return Err(PyValueError::new_err("Remote IO not enabled"));
    }
    
    // 3. Reject other URL schemes
    if path_str.contains("://") {
        return Err(PyValueError::new_err("Unsupported URL scheme"));
    }
    
    // 4. Canonicalize and validate local paths
    let path = Path::new(&path_str);
    let canonical = path.canonicalize()
        .map_err(|e| PyIOError::new_err(format!("Invalid path: {}", e)))?;
    
    // 5. Enforce allowed base directory (configure as needed)
    let allowed_base = std::env::current_dir()?;
    if !canonical.starts_with(&allowed_base) {
        return Err(PyValueError::new_err("Path outside allowed directory"));
    }
    
    // 6. Validate file extension
    let allowed_extensions = [".parquet", ".arrow", ".feather", ".npy", ".pt", ".pth", ".pb"];
    if let Some(ext) = path.extension() {
        if !allowed_extensions.iter().any(|&e| ext == e.trim_start_matches('.')) {
            return Err(PyValueError::new_err(format!(
                "Unsupported file extension. Allowed: {}",
                allowed_extensions.join(", ")
            )));
        }
    }
    
    Ok(canonical.to_string_lossy().to_string())
}

#[cfg(feature = "remote-io")]
fn validate_remote_url(url: &str) -> PyResult<()> {
    // Validate S3/GCS URL format
    // Reject query strings, fragments, etc.
    if url.contains('?') || url.contains('#') {
        return Err(PyValueError::new_err("Query strings not allowed in remote URLs"));
    }
    Ok(())
}
```

### Acceptance Criteria
- [x] Null byte validation added
- [x] Path canonicalization implemented
- [x] Base directory constraint enforced
- [x] URL scheme validation added (allow-list for remote-io)
- [x] File extension validation added
- [x] Clear error messages for each validation failure
- [x] Test added for path traversal attempts (`../etc/passwd`)
- [x] Test added for null byte injection
- [x] Test added for invalid URL schemes (`file://`, `http://`)
- [x] Test added for invalid file extensions
- [x] Test added for paths outside allowed directory

### References
- Source: 5.3.2.md
- ASVS Section: 5.3.2

### Priority
Medium

---

## Issue: FINDING-012 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** bug, security, priority:low
**Description:**
### Summary
User-supplied S3/GCS URLs may contain sensitive bucket names or object keys that could appear in error messages or logs, potentially exposing internal identifiers, customer IDs, or project names.

### Details
**Data Flow:**
User-supplied URL string (may include bucket/key paths) → `encode_from_parquet` / `encode` → platform module → potentially logged or included in error messages

**Positive Pattern:**
- Query strings are explicitly rejected (good security practice)

**Risk:**
- S3/GCS bucket names and object key paths passed as function arguments could appear in error messages or logs
- Object keys may contain sensitive identifiers:
  - Customer IDs
  - Dataset names
  - Internal project names
- The `MahoutError::Io(String)` variant could propagate these paths

**Affected Files:**
- `qdp/qdp-core/src/lib.rs` (`encode_from_parquet` function)
- `docs/qdp/getting-started.md` (remote URL examples)

**CWE:** Not specified
**ASVS:** 14.2.1 (Level L1)

### Remediation
Sanitize file paths in error messages to redact bucket names or keys:

```rust
fn sanitize_remote_path(path: &str) -> String {
    if path.starts_with("s3://") || path.starts_with("gs://") {
        // Extract scheme and redact the rest
        let scheme_end = path.find("://").unwrap() + 3;
        let scheme = &path[..scheme_end];
        
        // Redact bucket and key, keeping only scheme
        format!("{}[REDACTED]", scheme)
    } else {
        // For local paths, show only filename
        Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| format!("[LOCAL]/{}", n))
            .unwrap_or_else(|| "[LOCAL]/[REDACTED]".to_string())
    }
}

// Use in error handling:
impl fmt::Display for MahoutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MahoutError::Io(path) => {
                write!(f, "IO error accessing: {}", sanitize_remote_path(path))
            }
            // ... other variants
        }
    }
}
```

Consider structured logging that separates path components for selective redaction.

### Acceptance Criteria
- [x] Path sanitization function implemented
- [x] Sanitization applied to all error messages containing paths
- [x] S3/GCS URLs redacted in logs and error messages
- [x] Local paths show only filename, not full path
- [x] Structured logging considered for selective redaction
- [x] Test added verifying sensitive paths are redacted
- [x] Documentation updated with logging best practices

### References
- Source: 14.2.1.md
- ASVS Section: 14.2.1

### Priority
Low

---

## Issue: FINDING-013 - All QuMat instance attributes are publicly accessible
**Labels:** bug, security, priority:low
**Description:**
### Summary
All QuMat instance attributes are publicly accessible Python attributes, exposing sensitive internal state (raw backend handles, full configuration) to consumers and creating potential for inadvertent dependencies on internal implementation details.

### Details
**Current Implementation:**
All instance attributes are public:
- `backend_config` - Full configuration dictionary
- `backend_module` - Imported backend module
- `backend` - Raw backend handle
- `circuit` - Circuit object
- `parameters` - Parameter registry

**Risks:**
- While Python convention doesn't enforce access control, this violates principle of encapsulation
- Sensitive internal state is freely accessible to any consumer
- Consumers could inadvertently depend on internal state
- Raw `backend_config` dictionary could be exposed or logged
- Changes to internal structure would break external code depending on these attributes

**Design Impact:**
- Violates principle of least privilege for data access
- Makes refactoring difficult
- No clear API boundary between public and private state

**Affected Files:**
- `qumat/qumat.py` (entire class)

**CWE:** Not specified
**ASVS:** 15.3.1 (Level L1)

### Remediation
Use underscore-prefixed attributes for internal state and provide explicit accessor properties:

```python
class QuMat:
    def __init__(self, backend_config: dict):
        # Private attributes
        self._backend_config = backend_config
        self._backend_module = self._load_backend()
        self._backend = self._initialize_backend()
        self._circuit = None
        self._parameters = {}
        self._num_qubits = None
    
    # Public read-only properties for legitimate access needs
    @property
    def num_qubits(self) -> int:
        """Number of qubits in the current circuit."""
        return self._num_qubits
    
    @property
    def backend_name(self) -> str:
        """Name of the quantum backend in use."""
        return self._backend_config["backend_name"]
    
    @property
    def parameter_names(self) -> list[str]:
        """List of registered parameter names."""
        return list(self._parameters.keys())
    
    # Internal methods also use underscore prefix
    def _load_backend(self):
        # ... implementation
    
    def _initialize_backend(self):
        # ... implementation
```

### Acceptance Criteria
- [x] All internal attributes renamed with underscore prefix
- [x] Public properties created for legitimate access needs
- [x] Documentation updated to reflect public API
- [x] Deprecation warnings added for direct attribute access (if needed for backwards compatibility)
- [x] Test added verifying properties work correctly
- [x] Test added verifying internal attributes are not part of public API

### References
- Source: 15.3.1.md
- ASVS Section: 15.3.1

### Priority
Low