# Security Issues

## Issue: FINDING-001 - num_qubits parameter lacks validation for type, sign, and upper bound
**Labels:** bug, security, priority:high
**Description:**
### Summary
The `num_qubits` parameter in `qumat.py` accepts any value without validation for type, sign, or upper bounds, potentially leading to resource exhaustion (DoS), logic errors, and confusing error messages.

### Details
The `num_qubits` parameter is stored directly without validation at lines 82-85 of `qumat/qumat.py`. While QDP documentation specifies a valid range of 1–30 qubits, the implementation enforces no such constraints. This allows:
- Non-integer types (float, string) to pass through unchecked
- Negative values that violate quantum computing semantics
- Extremely large values that could exhaust system resources
- Non-numeric types that produce undefined behavior

**ASVS Reference:** 2.2.1 (Level 1)

### Remediation
Add comprehensive validation to the `create_empty_circuit` method:

```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    if num_qubits is not None:
        if not isinstance(num_qubits, int):
            raise TypeError(
                f"num_qubits must be an integer, got {type(num_qubits).__name__}"
            )
        if num_qubits < 0:
            raise ValueError(f"num_qubits must be non-negative, got {num_qubits}")
        if num_qubits > 30:  # or backend-specific maximum
            raise ValueError(f"num_qubits must be <= 30, got {num_qubits}")
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
```

### Acceptance Criteria
- [ ] Type validation added (must be int)
- [ ] Range validation added (0 <= num_qubits <= 30)
- [ ] Clear error messages for each validation failure
- [ ] Unit tests added for invalid inputs (negative, float, string, > 30)
- [ ] Documentation updated with valid range

### References
- Source: 2.2.1.md
- CWE: Not specified
- Related: FINDING-007

### Priority
**High** - Input validation failure at L1 ASVS level; potential DoS vector

---

## Issue: FINDING-002 - Remote IO feature lacks visible TLS certificate validation configuration
**Labels:** security, priority:medium, needs-verification
**Description:**
### Summary
The `remote-io` feature enables S3/GCS access through an out-of-scope `remote` module with no verifiable TLS certificate validation, risking man-in-the-middle attacks on data in transit.

### Details
At line 24 of `qdp/qdp-core/src/lib.rs`, the `remote-io` feature conditionally enables cloud storage access. The implementation is not included in the audit scope, preventing verification of:
- TLS 1.2+ enforcement
- Certificate validation against trusted CA roots
- Prevention of insecure connection fallback

If the `remote` module allows insecure connections or bypasses certificate validation, attackers could intercept or modify training datasets and model parameters in transit.

**ASVS Reference:** 12.2.2 (Level 1)

### Remediation
1. Verify the `remote` module enforces TLS 1.2+ with publicly trusted certificates
2. Ensure no `VERIFY_SSL=false` or equivalent bypass exists
3. Document TLS requirements in API documentation
4. Example Rust implementation using reqwest:

```rust
reqwest::Client::builder()
    .min_tls_version(reqwest::tls::Version::TLS_1_2)
    .use_rustls_tls()  // Uses Mozilla's root certificate store
    .build()?
```

### Acceptance Criteria
- [ ] Remote module TLS implementation verified
- [ ] Certificate validation confirmed enabled by default
- [ ] No insecure connection bypass available
- [ ] TLS requirements documented in docs/qdp/api.md
- [ ] Integration test added for TLS enforcement

### References
- Source: 12.2.2.md
- Files: qdp/qdp-core/src/lib.rs:24, docs/qdp/api.md, docs/qdp/getting-started.md

### Priority
**Medium** - Security control verification required; mitigated by limited scope

---

## Issue: FINDING-003 - No deployment configuration to exclude source control metadata from production artifacts
**Labels:** security, priority:medium, deployment
**Description:**
### Summary
Deployment from git checkouts could expose `.git` folder containing repository history, developer information, and configuration details that aid reconnaissance.

### Details
If the application is deployed from a git checkout (e.g., in containers built from repository clones), the `.git` directory could expose:
- Full repository history including potentially sensitive commits
- Internal developer information (emails, commit messages)
- Configuration details aiding reconnaissance

The deployment documentation in `docs/qdp/getting-started.md` and `dev/release.md` does not specify exclusion of version control metadata.

**ASVS Reference:** 13.4.1 (Level 1)

### Remediation
1. Add `.dockerignore` with VCS exclusions:
```
.git
.svn
.gitignore
.github
dev/
```

2. Document deployment best practices explicitly excluding VCS metadata

3. For Python packages via PyPI: continue using `maturin build` and `uv build` (already excludes `.git` by default)

4. Add verification step to release checklist ensuring no VCS metadata in artifacts

### Acceptance Criteria
- [ ] .dockerignore created with VCS exclusions
- [ ] Deployment documentation updated with security best practices
- [ ] Release checklist includes VCS metadata verification
- [ ] CI pipeline test verifies artifacts exclude .git
- [ ] Container image build tested with exclusions

### References
- Source: 13.4.1.md
- Files: docs/qdp/getting-started.md, dev/release.md

### Priority
**Medium** - Information disclosure risk; requires deployment configuration changes

---

## Issue: FINDING-004 - No documented risk-based remediation timeframes for third-party component vulnerabilities
**Labels:** security, priority:medium, policy, dependencies
**Description:**
### Summary
The project lacks documented remediation timeframes for dependency vulnerabilities, potentially allowing known CVEs to persist indefinitely and increasing supply chain attack exposure.

### Details
The release process in `dev/release.md` covers building, signing, and publishing but omits:
- Dependency vulnerability scanning procedures
- Risk-based remediation timeframes (critical: X days, high: Y days)
- SBOM generation
- Dependency audit requirements

Critical dependencies include:
- `qdp_kernels`: CUDA FFI with unsafe operations
- `cudarc`: GPU memory allocation with raw pointers
- Parquet/Arrow: Binary data parsing from untrusted files
- PyTorch, CUDA runtime

**ASVS Reference:** 15.1.1 (Level 1)

### Remediation
Create `SECURITY.md` or `docs/security/dependency-policy.md` defining:

**Remediation Timeframes:**
- Critical (CVSS ≥ 9.0): 7 calendar days
- High (CVSS 7.0–8.9): 30 calendar days
- Medium (CVSS 4.0–6.9): 90 calendar days
- Low (CVSS < 4.0): Next scheduled release

**Update Policy:**
- All dependencies reviewed quarterly
- `cargo audit` / `pip-audit` run in CI on every PR
- SBOM generated with each release

**High-Risk Components:**
- `qdp_kernels`: CUDA FFI — unsafe operations, direct memory manipulation
- `cudarc`: CUDA driver bindings — GPU memory allocation, raw pointers
- Parquet/Arrow readers: Binary data parsing from untrusted files

### Acceptance Criteria
- [ ] SECURITY.md created with remediation timeframes
- [ ] Dependency policy documented
- [ ] High-risk components identified
- [ ] Policy approved by security team
- [ ] Release process updated to reference policy

### References
- Source: 15.1.1.md
- Files: dev/release.md
- Related: FINDING-005

### Priority
**Medium** - Policy gap; foundational for supply chain security

---

## Issue: FINDING-005 - Unable to verify component currency without documented remediation timeframes
**Labels:** security, priority:medium, dependencies, ci
**Description:**
### Summary
Without documented vulnerability remediation timeframes (FINDING-004), it is impossible to verify that dependencies are current and free of known vulnerabilities, particularly for high-risk components handling unsafe operations.

### Details
Structural verification gaps:
- No `Cargo.lock` or `requirements.txt` provided for audit
- No automated dependency scanning in CI
- Cannot verify absence of known CVEs
- Cannot track remediation of discovered vulnerabilities

High-risk components requiring version management:
- `qdp_kernels`: Internal crate with unsafe CUDA FFI
- Parquet/Arrow: File parsers handling untrusted input
- `cudarc`: GPU memory allocation with raw pointers

**ASVS Reference:** 15.2.1 (Level 1)  
**Depends on:** FINDING-004

### Remediation
1. **Implement policy from FINDING-004**

2. **Add automated scanning to CI:**
```yaml
# .github/workflows/security.yml
- name: Rust dependency audit
  run: cargo audit
- name: Python dependency audit
  run: pip-audit
```

3. **Include Cargo.lock in repository** for reproducible builds

4. **Add dependency review to release process** in `dev/release.md`:
   - Run `cargo audit` and `pip-audit`
   - Verify no dependencies exceed remediation timeframe
   - Generate SBOM with `cargo-sbom` or `cyclonedx-bom`

### Acceptance Criteria
- [ ] Cargo.lock committed to repository
- [ ] cargo audit added to CI pipeline
- [ ] pip-audit added to CI pipeline
- [ ] Release checklist includes dependency review
- [ ] SBOM generation automated
- [ ] CI fails on vulnerabilities exceeding policy timeframes

### References
- Source: 15.2.1.md
- Files: qdp/qdp-core/src/gpu/memory.rs, qdp/qdp-core/src/error.rs, dev/release.md
- Depends on: FINDING-004

### Priority
**Medium** - Cannot verify compliance without policy foundation

---

## Issue: FINDING-006 - Backend modules receive entire configuration object instead of required fields subset
**Labels:** bug, security, priority:medium, refactoring
**Description:**
### Summary
Backend modules receive the entire `backend_config` dictionary containing all configuration fields, violating the principle of least privilege and risking information leakage through logs or error messages.

### Details
At lines 243-262 and 283-302 of `qumat/qumat.py`, the entire `self.backend_config` is passed to backend modules. This includes:
- `backend_name` (only needed at initialization)
- Full `backend_options` including `simulator_type` (only needed at init)
- `shots` configuration
- Accumulated `parameter_values` from previous operations

**Risks:**
- Backend modules receive data beyond operational need
- Configuration fields may leak in error messages or logs
- Mutation pattern creates implicit coupling between calls
- Violates principle of least privilege

**ASVS Reference:** 15.3.1 (Level 1)

### Remediation
Pass only required fields to backend methods:

```python
def execute_circuit(self, parameter_values=None):
    self._ensure_circuit_initialized()
    
    # Prepare minimal execution config
    execution_config = {
        "parameter_values": bound_parameters,
        "shots": self.backend_config["backend_options"].get("shots", 1024)
    }
    
    return self.backend_module.execute_circuit(
        self.circuit, 
        self.backend, 
        execution_config
    )
```

### Acceptance Criteria
- [ ] Backend methods receive only required configuration fields
- [ ] Execution config separated from initialization config
- [ ] No mutation of shared backend_config during execution
- [ ] Unit tests verify minimal config passing
- [ ] Backend interface documented with required fields
- [ ] Refactoring does not break existing backends

### References
- Source: 15.3.1.md
- Files: qumat/qumat.py:243-262, 283-302
- Merged from: ASVS-1531-MED-001, ALL-012

### Priority
**Medium** - Information disclosure risk; requires refactoring

---

## Issue: FINDING-007 - QuMat class lacks structured input validation documentation
**Labels:** documentation, priority:medium
**Description:**
### Summary
The `QuMat` class lacks formal documentation of input validation rules, leading to inconsistent validation across backends and unclear error messages for invalid inputs.

### Details
While docstrings describe parameter types, they do not specify:
- Valid ranges for `num_qubits` (QDP docs specify 1–30)
- Constraints on rotation angles (finite-only, radian range)
- Structure requirements for `backend_config`
- Allowed values for `backend_name`

**Specific gaps:**
- `create_empty_circuit(num_qubits)`: No documented valid range
- `apply_rx_gate(qubit_index, angle)`: No angle constraints
- `apply_u_gate(qubit_index, theta, phi, lambd)`: No rotation angle constraints
- `backend_config`: No schema or structural validation rules

This contrasts with QDP API documentation which explicitly specifies ranges and allowed values.

**ASVS Reference:** 2.1.1 (Level 1)

### Remediation
Add validation rules section to `QuMat` class docstring:

```python
class QuMat:
    """
    Quantum circuit interface supporting multiple backends.
    
    Validation Rules:
    ----------------
    - num_qubits: int, range [1, 30] (or backend-specific maximum)
    - qubit_index: int, range [0, num_qubits - 1]
    - angle (rotation gates): float, must be finite (no NaN/Inf)
    - backend_name: str, one of {"qiskit", "cirq", "amazon_braket"}
    - backend_options: dict with required key "simulator_type" (str)
                       and optional "shots" (int, >= 1)
    """
```

### Acceptance Criteria
- [ ] Validation rules section added to QuMat docstring
- [ ] All parameters documented with valid ranges/constraints
- [ ] Examples added showing valid and invalid inputs
- [ ] API documentation updated with validation rules
- [ ] Docstring examples tested with doctest

### References
- Source: 2.1.1.md
- Files: qumat/qumat.py
- Related: FINDING-001, FINDING-008, FINDING-009

### Priority
**Medium** - Documentation gap affecting developer experience

---

## Issue: FINDING-008 - Rotation angle parameters lack validation for finiteness and type correctness
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Rotation gate methods accept angle parameters without validating for NaN, Infinity, or type correctness, potentially producing mathematically undefined quantum states and silent computation errors.

### Details
Methods affected (lines 303, 321, 339, 356 in `qumat/qumat.py`):
- `apply_rx_gate(qubit_index, angle)`
- `apply_ry_gate(qubit_index, angle)`
- `apply_rz_gate(qubit_index, angle)`
- `apply_u_gate(qubit_index, theta, phi, lambd)`

While `_handle_parameter` registers string parameter names, float values pass through unchecked. NaN or Inf values:
- Produce mathematically undefined quantum states
- May silently propagate through backends without errors
- Lead to data integrity issues in quantum computations

**ASVS Reference:** 2.2.1 (Level 1)

### Remediation
Add validation helper and apply to all rotation gates:

```python
import math

def _validate_angle(self, angle: float, param_name: str = "angle") -> None:
    """Validate that a gate angle is a finite number."""
    if not isinstance(angle, (int, float)):
        raise TypeError(
            f"{param_name} must be a number, got {type(angle).__name__}"
        )
    if math.isnan(angle) or math.isinf(angle):
        raise ValueError(f"{param_name} must be finite, got {angle}")

def apply_rx_gate(self, qubit_index: int, angle: float) -> None:
    self._validate_qubit_index(qubit_index)
    if not isinstance(angle, str):  # Skip validation for parameter names
        self._validate_angle(angle, "angle")
    # ... rest of implementation
```

### Acceptance Criteria
- [ ] `_validate_angle` helper method implemented
- [ ] Validation added to all rotation gate methods
- [ ] Type checking for int/float
- [ ] Finiteness checking for NaN/Inf
- [ ] Unit tests for NaN, Inf, and non-numeric inputs
- [ ] Error messages clearly indicate validation failure

### References
- Source: 2.2.1.md
- Files: qumat/qumat.py:303, 321, 339, 356
- Related: FINDING-001, FINDING-007

### Priority
**Medium** - Data integrity risk; affects computation correctness

---

## Issue: FINDING-009 - backend_options and backend_name lack structure and allow-list validation
**Labels:** bug, priority:medium
**Description:**
### Summary
The `backend_options` value is not validated for type or structure, and `backend_name` is not validated against an allow-list, resulting in unclear error messages and implicit validation through ImportError.

### Details
At lines 53-75 of `qumat/qumat.py`:
- `backend_options` is checked for existence but not validated as a dict
- `backend_name` relies on `import_module` to fail for unknown backends
- No explicit business rule validation

While the relative import (`package="qumat"`) limits attack surface, the lack of explicit validation provides poor user experience:
- Unclear error messages for misconfigured backends
- No guidance on valid backend names
- Type errors delayed until backend module access

**ASVS Reference:** 2.2.1 (Level 1)

### Remediation
Add explicit validation:

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
    
    # ... continue with import_module ...
```

### Acceptance Criteria
- [ ] Allow-list constant defined for valid backends
- [ ] Type validation added for backend_options
- [ ] Allow-list validation added for backend_name
- [ ] Clear error messages for invalid inputs
- [ ] Unit tests for invalid backend names and options
- [ ] Documentation updated with valid backend names

### References
- Source: 2.2.1.md
- Files: qumat/qumat.py:53-75
- Related: FINDING-007

### Priority
**Medium** - User experience issue; validation gap

---

## Issue: FINDING-010 - Stale Parameter State Persists Across Circuit Resets
**Labels:** bug, security, priority:medium
**Description:**
### Summary
Calling `create_empty_circuit` again on an existing `QuMat` instance resets the circuit but not the parameters dictionary, allowing stale parameter values to silently corrupt new circuit executions.

### Details
At lines 82-85 of `qumat/qumat.py`, `create_empty_circuit` resets:
- ✓ `self.circuit`
- ✓ `self.num_qubits`
- ✗ `self.parameters` (NOT reset)

**Attack scenario:**
1. Create circuit with parameterized gates, bind parameters
2. Call `create_empty_circuit()` to start new circuit
3. Old parameter values persist in `self.parameters`
4. New circuit execution receives stale `parameter_values` via `backend_config`

**Impact:**
- Silent corruption of quantum computation results
- Invalid experimental results in scientific computing
- The unbound parameter check only catches `None` values — fully bound stale parameters pass through

**ASVS Reference:** 2.3.1 (Level 1)

### Remediation
Reset parameters dictionary when creating new circuit:

```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
    self.parameters = {}  # Reset parameter registry for new circuit
```

### Acceptance Criteria
- [ ] Parameters dictionary reset in create_empty_circuit
- [ ] Unit test verifying parameters cleared on circuit reset
- [ ] Integration test for sequential circuit creation
- [ ] Test verifies no parameter leakage between circuits
- [ ] Documentation updated noting state reset behavior

### References
- Source: 2.3.1.md
- Files: qumat/qumat.py:82-85
- Related: FINDING-013

### Priority
**Medium** - Data integrity issue; silent corruption risk

---

## Issue: FINDING-011 - path_from_py accepts user-supplied file paths with no validation or sanitization
**Labels:** bug, security, priority:medium, cwe-22
**Description:**
### Summary
The `path_from_py` function accepts user-supplied file paths with no validation, enabling path traversal attacks, SSRF (with `remote-io`), and information disclosure.

### Details
At lines 109-113 of `qdp/qdp-python/src/loader.rs`, `path_from_py` accepts paths with no validation:

**Missing protections:**
- Path traversal sequence rejection (`../`, `..\\`, encoded variants)
- Null byte injection checks
- Allowlist of permitted base directories
- Canonicalization (resolve symlinks, normalize `.`/`..`)
- Scheme validation (no check preventing `file://`, `http://` when `remote-io` disabled)

**Attack vectors:**
1. **Path traversal:** `../../../etc/passwd` → Read arbitrary server files
2. **SSRF (with remote-io):** `s3://internal-bucket/secrets` → Target internal infrastructure
3. **Information disclosure:** Exfiltrate credentials, configuration, sensitive data

**ASVS Reference:** 5.3.2 (Level 1)  
**CWE:** CWE-22 (Path Traversal)

### Remediation
Implement comprehensive path validation:

```rust
use std::path::{Path, PathBuf};

fn validate_path(path_str: &str) -> Result<PathBuf, String> {
    // 1. Null byte rejection
    if path_str.contains('\0') {
        return Err("Path contains null byte".to_string());
    }
    
    // 2. Canonicalize to resolve symlinks and ../
    let path = Path::new(path_str)
        .canonicalize()
        .map_err(|e| format!("Invalid path: {}", e))?;
    
    // 3. Base directory constraint
    let allowed_base = Path::new("/allowed/data/directory").canonicalize()?;
    if !path.starts_with(&allowed_base) {
        return Err("Path outside allowed directory".to_string());
    }
    
    // 4. File extension validation
    match path.extension().and_then(|s| s.to_str()) {
        Some("parquet") | Some("arrow") => Ok(path),
        _ => Err("Unsupported file extension".to_string()),
    }
}
```

Add URL scheme validation for `remote-io` feature.

### Acceptance Criteria
- [ ] Path validation function implemented
- [ ] Null byte injection prevented
- [ ] Path traversal sequences rejected
- [ ] Base directory constraint enforced
- [ ] File extension allowlist applied
- [ ] URL scheme validation added (remote-io)
- [ ] Unit tests for attack vectors (../, null bytes, invalid schemes)
- [ ] Security boundaries documented in API docs

### References
- Source: 5.3.2.md
- Files: qdp/qdp-python/src/loader.rs:109-113
- CWE: CWE-22

### Priority
**Medium** - Path traversal vulnerability; requires trust boundary analysis

---

## Issue: FINDING-012 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** security, priority:low, logging
**Description:**
### Summary
S3/GCS bucket names and object key paths passed as function arguments could leak in error messages or logs, potentially exposing sensitive identifiers.

### Details
While query strings are explicitly rejected (positive pattern), bucket names and object keys may contain:
- Customer IDs
- Dataset names
- Internal project names
- Organizational structure information

The `MahoutError::Io(String)` variant could propagate these paths through:
- User-supplied URL → `encode_from_parquet` / `encode` → platform module → error messages/logs

Example sensitive paths:
- `s3://customer-12345-data/project-secret/dataset.parquet`
- `gs://internal-research-2024/confidential-model/train.arrow`

**ASVS Reference:** 14.2.1 (Level 1)

### Remediation
Sanitize file paths in error messages:

```rust
fn sanitize_remote_path(url: &str) -> String {
    if url.starts_with("s3://") || url.starts_with("gs://") {
        let parts: Vec<&str> = url.splitn(4, '/').collect();
        if parts.len() >= 3 {
            format!("{}://<redacted>/{}", 
                parts[0].trim_end_matches(':'), 
                parts.get(3).unwrap_or(&"<redacted>"))
        } else {
            "<redacted>".to_string()
        }
    } else {
        url.to_string()
    }
}

// In error handling:
Err(MahoutError::Io(format!("Failed to load: {}", 
    sanitize_remote_path(&original_path))))
```

Consider structured logging with selective redaction.

### Acceptance Criteria
- [ ] Path sanitization function implemented
- [ ] Bucket names redacted in error messages
- [ ] Object keys redacted or truncated in logs
- [ ] Structured logging reviewed for path exposure
- [ ] Unit tests verify redaction
- [ ] Documentation updated with logging practices

### References
- Source: 14.2.1.md
- Files: qdp/qdp-core/src/lib.rs (encode_from_parquet), docs/qdp/getting-started.md

### Priority
**Low** - Information disclosure risk; depends on logging configuration

---

## Issue: FINDING-013 - Backend Configuration Mutated In Place During Execution
**Labels:** bug, priority:low, refactoring
**Description:**
### Summary
The `execute_circuit` method mutates `self.backend_config` in place by setting `parameter_values`, causing state to persist between executions and violating immutability principles.

### Details
At lines 243-262 of `qumat/qumat.py`, `execute_circuit` mutates shared configuration:

```python
self.backend_config["parameter_values"] = bound_parameters
```

**Problems:**
- Configuration carries state from one execution to the next
- Old `parameter_values` key remains if next call has no parameters
- Violates principle of immutable configuration
- Could cause bugs if backend modules cache the config dict
- Makes debugging harder due to implicit state

**ASVS Reference:** 2.3.1 (Level 1)

### Remediation
Pass a copy or purpose-built execution context:

```python
def execute_circuit(self, parameter_values=None):
    self._ensure_circuit_initialized()
    
    # Create execution-specific config without mutating shared state
    exec_config = {
        **self.backend_config, 
        "parameter_values": bound_parameters
    }
    
    return self.backend_module.execute_circuit(
        self.circuit, 
        self.backend, 
        exec_config
    )
```

### Acceptance Criteria
- [ ] Execution context created as new dict
- [ ] No mutation of self.backend_config during execution
- [ ] Unit test verifies config immutability
- [ ] Test verifies no state leakage between calls
- [ ] Refactoring does not break existing backends

### References
- Source: 2.3.1.md
- Files: qumat/qumat.py:243-262
- Related: FINDING-006, FINDING-010

### Priority
**Low** - Code quality issue; potential for subtle bugs