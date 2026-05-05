# Security Issues

## Issue: FINDING-001 - num_qubits parameter lacks validation for type, sign, and upper bound
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `num_qubits` parameter in the QuMat class is not validated for type, sign, or upper bound, which can lead to resource exhaustion (DoS), logic errors, and confusing error messages.

### Details
The `num_qubits` parameter is stored directly without validation and used in subsequent range checks for qubit indices. Invalid values (float, negative, extremely large, or non-numeric) produce undefined behavior downstream. User input is stored as `self.num_qubits`, used in `_validate_qubit_index` comparisons, and passed to backend `create_empty_circuit`. The QDP documentation specifies 1–30 as the valid range, but `qumat.py` enforces no upper bound.

**Affected Files:**
- `qumat/qumat.py` (lines 82-85)

**ASVS Reference:** 2.2.1 (Level L1)

### Remediation
Add validation to check that `num_qubits` is an integer, non-negative, and within reasonable bounds before storing and using it:
- Implement type checking with `isinstance(num_qubits, int)`
- Validate non-negativity: `num_qubits > 0`
- Enforce the documented 1-30 range constraint: `1 <= num_qubits <= 30`

### Acceptance Criteria
- [ ] Type validation added for `num_qubits` parameter
- [ ] Range validation (1-30) implemented
- [ ] Clear error messages for invalid inputs
- [ ] Unit tests added for edge cases (negative, zero, > 30, float, non-numeric)
- [ ] Documentation updated to reflect validation rules

### References
- Source Report: 2.2.1.md
- CWE: None specified
- Related: FINDING-007 (documentation of validation rules)

### Priority
**High** - Can lead to DoS through resource exhaustion and logic errors

---

## Issue: FINDING-002 - Remote IO feature lacks visible TLS certificate validation configuration
**Labels:** security, priority:medium, network
**Description:**
### Summary
The remote-io feature for S3/GCS access lacks verifiable TLS certificate validation, potentially exposing data in transit to man-in-the-middle attacks.

### Details
User-supplied S3/GCS URLs flow through `QdpEngine.encode()` to a remote module (not provided in audit scope). The implementation of the remote module cannot be verified for TLS certificate validation. If the remote module does not enforce publicly trusted TLS certificates or allows insecure connections, data in transit (training datasets, model parameters) could be intercepted or tampered with via MITM attacks.

**Affected Files:**
- `qdp/qdp-core/src/lib.rs` (line 24)
- `docs/qdp/api.md`
- `docs/qdp/getting-started.md`

**ASVS Reference:** 12.2.2 (Level L1)

### Remediation
1. Verify the remote module enforces TLS 1.2+ with publicly trusted certificates
2. Ensure no `VERIFY_SSL=false` or equivalent bypass is available
3. Document TLS requirements for remote IO connections

Example implementation:
```rust
let client = reqwest::Client::builder()
    .min_tls_version(reqwest::tls::Version::TLS_1_2)
    .use_rustls_tls()
    .build()?;
```

### Acceptance Criteria
- [ ] Remote module code reviewed for TLS validation
- [ ] TLS 1.2+ enforcement verified
- [ ] Certificate validation confirmed (no bypass options)
- [ ] Documentation updated with TLS requirements
- [ ] Integration tests added for remote IO over TLS

### References
- Source Report: 12.2.2.md
- Related: FINDING-012 (sensitive URL logging)

### Priority
**Medium** - Data confidentiality and integrity risk, but requires MITM position

---

## Issue: FINDING-003 - No deployment configuration to exclude source control metadata from production artifacts
**Labels:** security, priority:medium, deployment
**Description:**
### Summary
Deployment from git checkouts may expose `.git` folder contents, revealing repository history, developer information, and configuration details.

### Details
If the application is deployed from a git checkout (e.g., in a container built from repository clone or web-accessible directory), the `.git` folder could expose:
- Full repository history including potentially sensitive commits
- Internal developer information (email addresses, commit messages)
- Configuration details that aid reconnaissance

**Affected Files:**
- `docs/qdp/getting-started.md`
- `dev/release.md`

**ASVS Reference:** 13.4.1 (Level L1)

### Remediation
1. Add `.dockerignore` with exclusion rules:
   ```
   .git
   .svn
   .gitignore
   dev/
   ```
2. Document deployment best practices that explicitly exclude VCS metadata
3. Note: PyPI distribution via `maturin build` and `uv build` already excludes `.git` (positive pattern)

### Acceptance Criteria
- [ ] `.dockerignore` file created with VCS exclusions
- [ ] Deployment documentation updated with security best practices
- [ ] Build process verified to exclude `.git` directory
- [ ] Container image tested to confirm no VCS metadata present

### References
- Source Report: 13.4.1.md

### Priority
**Medium** - Information disclosure risk in misconfigured deployments

---

## Issue: FINDING-004 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** security, priority:medium, dependencies, policy
**Description:**
### Summary
The project lacks documented risk-based remediation timeframes for third-party component vulnerabilities, potentially allowing known vulnerabilities to persist indefinitely.

### Details
Without defined remediation timeframes, known vulnerabilities in dependencies (cudarc, thiserror, arrow, parquet, CUDA runtime, PyTorch) may persist with no consistent standard for when updates must be applied. This increases the window of exposure for supply chain attacks and results in inconsistent risk treatment across the project.

**Affected Files:**
- `dev/release.md` (entire file)

**ASVS Reference:** 15.1.1 (Level L1)

### Remediation
Create a `SECURITY.md` or `docs/security/dependency-policy.md` defining:

| Severity | Definition | Remediation SLA |
|----------|-----------|-----------------|
| Critical (CVSS ≥ 9.0) | RCE, data exfiltration, privilege escalation | 7 calendar days |
| High (CVSS 7.0–8.9) | Significant impact vulnerabilities | 30 calendar days |
| Medium (CVSS 4.0–6.9) | Limited impact vulnerabilities | 90 calendar days |
| Low (CVSS < 4.0) | Minimal impact | Next scheduled release |

**General Update Policy:**
- All dependencies reviewed quarterly
- `cargo audit` / `pip-audit` run in CI on every PR
- SBOM generated with each release

### Acceptance Criteria
- [ ] Security policy document created
- [ ] Remediation timeframes defined by severity
- [ ] Policy integrated into release process
- [ ] Dangerous components documented (qdp_kernels, cudarc, Parquet/Arrow)
- [ ] Team trained on policy requirements

### References
- Source Report: 15.1.1.md
- Related: FINDING-005 (component currency verification)

### Priority
**Medium** - Policy gap, no immediate exploit but increases long-term risk

---

## Issue: FINDING-005 - Unable to verify component currency without documented remediation timeframes
**Labels:** security, priority:medium, dependencies, automation
**Description:**
### Summary
Without documented remediation timeframes (FINDING-004), verifying component currency is structurally impossible, and dependencies may contain undetected CVEs.

### Details
Risks include:
- Dependencies may contain known CVEs without detection/tracking mechanism
- No `Cargo.lock` or `requirements.txt` freeze file provided for audit
- The `qdp_kernels` crate (unsafe CUDA FFI) requires careful version management
- Parquet/Arrow file parsers handle untrusted input and are common vulnerability sources

**Affected Files:**
- `qdp/qdp-core/src/gpu/memory.rs`
- `qdp/qdp-core/src/error.rs`
- `dev/release.md`

**ASVS Reference:** 15.2.1 (Level L1)

### Remediation
1. Implement the policy from FINDING-004
2. Add automated dependency scanning to CI:
   - `cargo audit` for Rust dependencies
   - `pip-audit` for Python dependencies
3. Include `Cargo.lock` in repository for reproducible builds
4. Add dependency review step to release process:
   ```markdown
   ## Pre-Release Dependency Audit
   - [ ] Run `cargo audit`
   - [ ] Run `pip-audit`
   - [ ] Verify remediation timeframes compliance
   - [ ] Generate SBOM
   ```

### Acceptance Criteria
- [ ] Dependency policy implemented (FINDING-004)
- [ ] `cargo audit` integrated into CI pipeline
- [ ] `pip-audit` integrated into CI pipeline
- [ ] `Cargo.lock` committed to repository
- [ ] Release process updated with audit steps
- [ ] SBOM generation automated

### References
- Source Report: 15.2.1.md
- Depends on: FINDING-004

### Priority
**Medium** - Blocks verification of security posture, requires process changes

---

## Issue: FINDING-006 - Backend modules receive full configuration object instead of required fields
**Labels:** bug, security, priority:medium, architecture
**Description:**
### Summary
Backend modules receive the entire `backend_config` dictionary instead of only required fields, potentially exposing sensitive configuration data through error messages or logs.

### Details
The entire `self.backend_config` dictionary is passed to backend modules and mutated to accumulate state between calls. The config contains all constructor-supplied configuration (including `backend_name`, `backend_options` with `simulator_type`, `shots`, etc.) plus injected `parameter_values`. If a backend module logs, serializes, or exposes this config (e.g., in error messages), fields that should be scoped differently could leak. The mutation pattern also creates implicit coupling between sequential calls.

**Affected Files:**
- `qumat/qumat.py` (lines 243-262, 283-302)

**ASVS Reference:** 15.3.1 (Level L1)

### Remediation
Pass only what the backend needs. Example for `execute_circuit`:

```python
execution_config = {
    "parameter_values": bound_parameters,
    "shots": self.backend_config["backend_options"].get("shots", 1024)
}
backend_module.execute_circuit(self.circuit, self.backend, execution_config)
```

### Acceptance Criteria
- [ ] Scoped configuration objects created for each backend operation
- [ ] Only required fields passed to backend modules
- [ ] Mutation of shared config eliminated
- [ ] Unit tests verify config isolation
- [ ] Backend interface documented with required fields

### References
- Source Report: 15.3.1.md
- Related: FINDING-013 (public attributes)

### Priority
**Medium** - Information disclosure risk, architectural improvement needed

---

## Issue: FINDING-007 - QuMat class lacks structured documentation defining input validation rules
**Labels:** documentation, priority:medium
**Description:**
### Summary
The QuMat class lacks structured documentation defining input validation rules, leading to inconsistent validation across backends and unclear error messages.

### Details
While docstrings describe parameter types, they do not specify valid ranges, allowed values, or expected structures as formal validation rules. Specific gaps:
- `create_empty_circuit(num_qubits)`: no documented valid range
- `apply_rx_gate(qubit_index, angle)`: no documented constraints for angle
- `apply_u_gate(qubit_index, theta, phi, lambd)`: no documented rotation angle constraints
- `backend_config`: no schema or structural validation rules beyond required keys

Contrast with QDP API documentation which explicitly specifies ranges (e.g., num_qubits 1–30).

**Affected Files:**
- `qumat/qumat.py`

**ASVS Reference:** 2.1.1 (Level L1)

### Remediation
Add a validation rules section to the QuMat class docstring:

```python
"""
Validation Rules:
- num_qubits: int, range [1, 30]
- qubit_index: int, range [0, num_qubits - 1]
- angle (rotation gates): float, must be finite (no NaN/Inf)
- backend_name: str, one of {"qiskit", "cirq", "amazon_braket"}
- backend_options: dict with required key "simulator_type" (str)
                   and optional "shots" (int, >= 1)
"""
```

### Acceptance Criteria
- [ ] Validation rules section added to class docstring
- [ ] All parameters documented with type, range, and constraints
- [ ] Examples provided for valid and invalid inputs
- [ ] Documentation published and accessible
- [ ] Related findings (FINDING-001, FINDING-008) reference this documentation

### References
- Source Report: 2.1.1.md
- Related: FINDING-001, FINDING-008, FINDING-009

### Priority
**Medium** - Documentation gap affecting developer experience and security

---

## Issue: FINDING-008 - Rotation angle parameters lack validation for finiteness and type
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Rotation angle parameters (rx, ry, rz, u gates) lack validation for finiteness (NaN, Inf) and type correctness, potentially producing mathematically undefined quantum states.

### Details
When rotation angles are provided as floats, no validation is performed. While `_handle_parameter` registers string parameter names, float values pass through unchecked. User input passes directly to backend modules without validation. NaN or Inf values produce mathematically undefined quantum states. Backends may silently produce incorrect results rather than raising errors, leading to data integrity issues in quantum computations.

**Affected Files:**
- `qumat/qumat.py` (lines 303, 321, 339, 356)

**ASVS Reference:** 2.2.1 (Level L1)

### Remediation
Create a `_validate_angle` helper function:

```python
def _validate_angle(self, angle: float, param_name: str) -> None:
    """Validate that angle is numeric and finite."""
    if not isinstance(angle, (int, float)):
        raise ValueError(f"{param_name} must be numeric, got {type(angle)}")
    if not math.isfinite(angle):
        raise ValueError(f"{param_name} must be finite (not NaN or Inf)")
```

Apply to all rotation gate methods before passing to backend modules.

### Acceptance Criteria
- [ ] `_validate_angle` helper function implemented
- [ ] Validation applied to `apply_rx_gate`, `apply_ry_gate`, `apply_rz_gate`, `apply_u_gate`
- [ ] Clear error messages for invalid angles
- [ ] Unit tests for NaN, Inf, and non-numeric inputs
- [ ] Documentation updated with angle constraints

### References
- Source Report: 2.2.1.md
- Related: FINDING-007 (documentation)

### Priority
**Medium** - Data integrity risk in quantum computations

---

## Issue: FINDING-009 - backend_options and backend_name lack structure and allow-list validation
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `backend_options` value is not validated for type or structure, and `backend_name` is not validated against an allow list, resulting in unclear error messages and implicit validation.

### Details
`backend_options` is checked for existence but not validated for type or structure. `backend_name` is not validated against an allow list of known backends, relying solely on `import_module` to fail for unknown names. This results in:
- Unclear error messages for misconfigured backends
- Implicit validation through ImportError rather than explicit business rule check

The relative import (`package='qumat'`) limits attack surface to within the `qumat` package (positive pattern).

**Affected Files:**
- `qumat/qumat.py` (lines 53-75)

**ASVS Reference:** 2.2.1 (Level L1)

### Remediation
1. Add type validation for `backend_options`:
   ```python
   if not isinstance(backend_options, dict):
       raise TypeError("backend_options must be a dictionary")
   ```

2. Create allow-list for `backend_name`:
   ```python
   VALID_BACKENDS = {"qiskit", "cirq", "amazon_braket"}
   if backend_name not in VALID_BACKENDS:
       raise ValueError(f"Invalid backend: {backend_name}. Must be one of {VALID_BACKENDS}")
   ```

### Acceptance Criteria
- [ ] Type validation added for `backend_options`
- [ ] Allow-list validation added for `backend_name`
- [ ] Clear error messages for invalid configurations
- [ ] Unit tests for invalid backend names and options
- [ ] Documentation updated with valid backend list

### References
- Source Report: 2.2.1.md
- Related: FINDING-007 (documentation)

### Priority
**Medium** - User experience and validation clarity

---

## Issue: FINDING-010 - Stale Parameter State Persists Across Circuit Resets
**Labels:** bug, security, priority:medium, data-integrity
**Description:**
### Summary
When `create_empty_circuit` is called on an existing QuMat instance, stale parameter registrations from the previous circuit persist and can corrupt new circuit execution.

### Details
`create_empty_circuit` resets `self.circuit` and `self.num_qubits` but **not** `self.parameters`. Stale parameter registrations and bound values from a previous circuit persist and are injected into the new circuit's execution via `backend_config["parameter_values"]`. This leads to:
- Incorrect quantum computation results due to stale parameter state
- Silent corruption of computation parameters in scientific computing contexts
- Invalid experimental results

The unbound parameter check in `execute_circuit` only catches parameters with `None` values—fully bound stale parameters pass through silently.

**Affected Files:**
- `qumat/qumat.py` (lines 82-85)

**ASVS Reference:** 2.3.1 (Level L1)

### Remediation
Reset the parameters dictionary when creating a new circuit:

```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
    self.parameters = {}  # Reset parameter registry for new circuit
```

### Acceptance Criteria
- [ ] Parameters dictionary reset in `create_empty_circuit`
- [ ] Unit test verifying stale parameters are cleared
- [ ] Integration test with multiple circuit creations
- [ ] Documentation updated to clarify circuit lifecycle
- [ ] Regression test added

### References
- Source Report: 2.3.1.md

### Priority
**Medium** - Data integrity issue affecting scientific computation accuracy

---

## Issue: FINDING-011 - path_from_py accepts user-supplied file paths with no validation or sanitization
**Labels:** bug, security, priority:medium, cwe-22
**Description:**
### Summary
The `path_from_py` function accepts file paths from Python callers without validation, enabling path traversal attacks, SSRF (with remote-io), and arbitrary file access.

### Details
`path_from_py` extracts a string from Python input (string or pathlib.Path) and passes it directly to downstream file I/O operations. No checks are performed for:
- Path traversal sequences (`../`, `..\`, encoded variants)
- Null byte injection
- Scheme validation
- Canonicalization

The function serves as a chokepoint for multiple entry points (encode_from_parquet, encode_from_arrow_ipc, encode_from_numpy, encode_from_torch, encode_from_tensorflow). With `remote-io` enabled, this creates an SSRF attack surface (s3://, gs:// URLs without scheme validation).

**Attack scenarios:**
- Path traversal to read arbitrary files: `../../etc/passwd`
- SSRF targeting internal infrastructure: `http://169.254.169.254/latest/meta-data/`
- Information disclosure of sensitive configuration and credentials

**Affected Files:**
- `qdp/qdp-python/src/loader.rs` (lines 109-113)

**ASVS Reference:** 5.3.2 (Level L1)  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

### Remediation
Implement path validation and sanitization:

```rust
fn path_from_py(path: &PyAny, allowed_base: &Path) -> PyResult<PathBuf> {
    let path_str: String = /* extract string */;
    
    // 1. Reject null bytes
    if path_str.contains('\0') {
        return Err(PyValueError::new_err("Path contains null byte"));
    }
    
    // 2. Validate scheme for remote paths
    if path_str.starts_with("s3://") || path_str.starts_with("gs://") {
        // Allow only these schemes when remote-io enabled
        return Ok(PathBuf::from(path_str));
    } else if path_str.contains("://") {
        return Err(PyValueError::new_err("Unsupported URL scheme"));
    }
    
    // 3. Canonicalize and validate local paths
    let path = Path::new(&path_str).canonicalize()
        .map_err(|e| PyValueError::new_err(format!("Invalid path: {}", e)))?;
    
    if !path.starts_with(allowed_base) {
        return Err(PyValueError::new_err("Path outside allowed directory"));
    }
    
    Ok(path)
}
```

### Acceptance Criteria
- [ ] Path validation implemented with null byte rejection
- [ ] Canonicalization enforced for local paths
- [ ] Base directory restriction implemented
- [ ] URL scheme allowlist for remote-io
- [ ] File extension validation (optional but recommended)
- [ ] Unit tests for path traversal attempts
- [ ] Unit tests for null byte injection
- [ ] Unit tests for scheme validation
- [ ] Security documentation updated

### References
- Source Report: 5.3.2.md
- CWE-22: https://cwe.mitre.org/data/definitions/22.html

### Priority
**Medium** - Path traversal and SSRF risk in service integration scenarios

---

## Issue: FINDING-012 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** security, priority:low, logging
**Description:**
### Summary
User-supplied S3/GCS URLs may expose sensitive bucket names or object keys through error messages and logs.

### Details
User-supplied URL strings for S3/GCS bucket names and object key paths passed as function arguments could appear in error messages or logs. Object keys may contain sensitive identifiers (customer IDs, dataset names, internal project names). The `MahoutError::Io(String)` variant could propagate these paths.

While query strings are explicitly rejected (positive pattern), the path components themselves may leak sensitive information through error messages.

**Affected Files:**
- `qdp/qdp-core/src/lib.rs` (encode_from_parquet function)
- `docs/qdp/getting-started.md` (remote URL examples)
- `error.rs` (MahoutError::Io(String) variant)

**ASVS Reference:** 14.2.1 (Level L1)

### Remediation
Sanitize file paths in error messages:

```rust
fn sanitize_remote_path(path: &str) -> String {
    if path.starts_with("s3://") || path.starts_with("gs://") {
        let parts: Vec<&str> = path.splitn(4, '/').collect();
        if parts.len() >= 4 {
            return format!("{}://<redacted>/<redacted>", parts[0].trim_end_matches(':'));
        }
    }
    path.to_string()
}

// Use in error handling:
MahoutError::Io(format!("Failed to read: {}", sanitize_remote_path(&path)))
```

Consider structured logging that separates path components for selective redaction.

### Acceptance Criteria
- [ ] Path sanitization function implemented
- [ ] Sensitive paths redacted in error messages
- [ ] Structured logging with selective redaction
- [ ] Unit tests for sanitization logic
- [ ] Documentation on logging best practices

### References
- Source Report: 14.2.1.md
- Related: FINDING-002 (remote IO TLS)

### Priority
**Low** - Information disclosure through logs, limited impact

---

## Issue: FINDING-013 - All instance attributes are public and freely accessible
**Labels:** enhancement, priority:low, architecture
**Description:**
### Summary
All QuMat instance attributes are public Python attributes, allowing free access to sensitive internal state such as raw backend handles and full configuration.

### Details
All instance attributes (`backend_config`, `backend_module`, `backend`, `circuit`, `parameters`) are public Python attributes. While Python convention doesn't enforce access control, sensitive internal state is freely accessible to any consumer of a `QuMat` instance.

**Risks (low in library context):**
- Consumers could inadvertently depend on internal state
- Raw `backend_config` dictionary could be exposed or modified
- Internal implementation details become implicit API surface

**Affected Files:**
- `qumat/qumat.py`

**ASVS Reference:** 15.3.1 (Level L1)

### Remediation
Use underscore-prefixed attributes for internal state and provide explicit accessor properties:

```python
class QuMat:
    def __init__(self, backend_config):
        self._backend_config = backend_config
        self._backend_module = None
        self._backend = None
        self._circuit = None
        self._parameters = {}
    
    @property
    def num_qubits(self):
        return self._num_qubits
    
    # Expose only what consumers need
```

### Acceptance Criteria
- [ ] Internal attributes prefixed with underscore
- [ ] Public accessor properties defined for legitimate API surface
- [ ] Documentation clarifies public vs. internal API
- [ ] Backward compatibility considered (or breaking change documented)
- [ ] Unit tests updated for new attribute names

### References
- Source Report: 15.3.1.md
- Related: FINDING-006 (configuration scoping)

### Priority
**Low** - API design improvement, low security impact in library context