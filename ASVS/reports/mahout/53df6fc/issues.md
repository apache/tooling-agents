# Security Issues

## Issue: FINDING-001 - Missing documented remediation timeframes for third-party component vulnerabilities
**Labels:** security, documentation, priority:medium
**Description:**
### Summary
The project lacks documented policies for managing third-party dependency vulnerabilities, including remediation timeframes, update cadence, and component risk classification.

### Details
The project uses numerous third-party dependencies (Rust crates and Python packages) but provides no documentation defining:
- Risk-based remediation timeframes for known vulnerabilities in dependencies
- Update cadence expectations for third-party libraries
- Classification of components by risk level
- Dangerous functionality components tracking

**ASVS Reference:** 15.1.1 (Level 1)  
**Severity:** Medium  
**Affected Files:** `dev/release.md`, Project-wide

### Remediation
Create a `SECURITY.md` or `docs/security-policy.md` document that defines:
1. Remediation timeframes by severity level (e.g., Critical: 7 days, High: 30 days, Medium: 90 days)
2. List of components with dangerous functionality requiring heightened monitoring
3. Expected update cadence for dependencies
4. Process for tracking and reviewing risky components

### Acceptance Criteria
- [ ] Fixed - Security policy document created with remediation timeframes
- [ ] Test added - Policy reviewed and approved by security team
- [ ] Documentation includes severity-based SLAs
- [ ] Process for tracking vulnerable dependencies defined

### References
- ASVS 15.1.1
- Source: 15.1.1.md

### Priority
Medium - Foundational security documentation required for L1 compliance

---

## Issue: FINDING-002 - Path traversal not validated in encode_from_file
**Labels:** bug, security, priority:medium
**Description:**
### Summary
The `encode_from_file` function does not validate path strings against traversal patterns or null bytes before file I/O operations, potentially allowing access to unintended filesystem locations.

### Details
The `encode_from_file` function validates file extensions but does not validate the `path` string against:
- Path traversal patterns (`../`, `..\\`)
- Null bytes (`\0`)
- Absolute paths outside expected directories

While this is a library (not a web endpoint), the `encode()` function accepts arbitrary strings and routes them to file operations based on duck-typing heuristics, creating potential for misuse in applications that pass user-controlled input.

**CWE:** CWE-22 (Path Traversal)  
**ASVS Reference:** 2.2.1, 5.3.2 (Level 1)  
**Severity:** Medium  
**Affected Files:** `qdp/qdp-python/src/engine.rs`  
**Related:** FINDING-004

### Remediation
1. Add optional path sanitization to reject paths containing:
   - Null bytes (`\0`)
   - Path traversal sequences (`../`, `..\\`)
2. Document that applications accepting user-provided paths must validate/restrict them before passing to `encode()`
3. Consider adding optional `allowed_paths` or `base_directory` parameter for path restriction

### Acceptance Criteria
- [ ] Fixed - Path validation implemented in encode_from_file
- [ ] Test added - Unit tests for path traversal attempts
- [ ] Test added - Null byte injection tests
- [ ] Documentation updated with security guidance for path handling

### References
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- ASVS 2.2.1, 5.3.2
- Source: 2.2.1.md, 5.3.2.md

### Priority
Medium - Input validation gap with potential for unauthorized file access

---

## Issue: FINDING-003 - No explicit file size limit before parsing input files
**Labels:** bug, security, priority:medium
**Description:**
### Summary
File-based encoding paths accept files without explicit size limits, risking host memory exhaustion during parsing before GPU memory checks are performed.

### Details
The file encoding paths lack explicit pre-processing size limits:
- No file size check before opening, reading, and parsing file content
- `ensure_device_memory_available` validates GPU memory for OUTPUT allocation only
- No corresponding check on INPUT file size before parsing begins
- Denial of service possible through host memory exhaustion during file parsing

The vulnerability exists in the window between file open and GPU memory validation, where large files can consume host resources during parsing operations.

**CWE:** CWE-400 (Uncontrolled Resource Consumption)  
**ASVS Reference:** 5.2.1 (Level 1)  
**Severity:** Medium  
**Affected Files:** `qdp/qdp-python/src/engine.rs`, `qdp/qdp-core/src/lib.rs`

### Remediation
1. Add a `max_file_size` parameter or configuration setting
2. Implement a Rust-level `validate_file_size` function that:
   - Checks file metadata before parsing begins
   - Rejects files exceeding the configured limit
   - Provides clear error messages indicating size limit exceeded
3. Document the size limit in user-facing documentation

### Acceptance Criteria
- [ ] Fixed - File size validation implemented before parsing
- [ ] Test added - Test with file exceeding size limit
- [ ] Test added - Test with file at boundary of size limit
- [ ] Configuration parameter added for max_file_size
- [ ] Documentation updated with size limit information

### References
- CWE-400: Uncontrolled Resource Consumption
- ASVS 5.2.1
- Source: 5.2.1.md

### Priority
Medium - Resource exhaustion vulnerability requiring input validation

---

## Issue: FINDING-004 - No path traversal prevention in QuantumDataLoader.source_file()
**Labels:** bug, security, priority:medium
**Description:**
### Summary
User-provided path strings in `QuantumDataLoader.source_file()` are passed directly to file operations without path traversal sanitization, enabling potential arbitrary file reads.

### Details
The `source_file()` method stores user input directly in `self._file_path` and passes it to:
- `os.path.exists()`
- `torch.load()`
- `np.load()`
- Rust `create_file_loader`

No validation is performed against:
- Path traversal sequences (`../`, `..\\`)
- Symbolic links
- Absolute paths
- Path canonicalization

An attacker could read arbitrary files on the filesystem (with supported extensions) when the library is used in contexts where file paths originate from external input.

**CWE:** CWE-22 (Path Traversal)  
**ASVS Reference:** 5.3.2 (Level 1)  
**Severity:** Medium  
**Affected Files:** `qdp/qdp-python/qumat_qdp/loader.py`  
**Related:** FINDING-002

### Remediation
1. Canonicalize paths using `os.path.realpath(os.path.abspath(path))`
2. Reject paths containing traversal sequences (`..`)
3. Optionally restrict to allowed base directories via configuration
4. Validate resolved path is within expected boundaries

Example implementation:
```python
def _sanitize_path(self, path: str, base_dir: Optional[str] = None) -> str:
    real_path = os.path.realpath(os.path.abspath(path))
    if '..' in path:
        raise ValueError("Path traversal sequences not allowed")
    if base_dir and not real_path.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path outside allowed directory")
    return real_path
```

### Acceptance Criteria
- [ ] Fixed - Path sanitization implemented in source_file()
- [ ] Test added - Path traversal attack tests
- [ ] Test added - Symbolic link handling tests
- [ ] Optional base_dir restriction parameter added
- [ ] Documentation updated with security guidance

### References
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- ASVS 5.3.2
- Source: 5.3.2.md

### Priority
Medium - Path traversal vulnerability requiring input validation

---

## Issue: FINDING-005 - Unable to verify component freshness due to missing remediation policy and dependency manifests
**Labels:** security, documentation, tooling, priority:low
**Description:**
### Summary
Cannot verify dependency freshness and vulnerability status due to missing remediation policy (FINDING-001) and lack of automated vulnerability scanning in CI pipeline.

### Details
The project lacks mechanisms to verify component security posture:
- No documented remediation timeframes (see FINDING-001)
- No `cargo audit` or `cargo deny` output provided
- No CI configuration for automated vulnerability scanning
- No evidence of dependency vulnerability monitoring

Without these controls, it's impossible to verify:
- Whether dependencies comply with remediation timeframes
- Current vulnerability status of dependencies
- Whether dependencies are kept up-to-date

**ASVS Reference:** 15.2.1 (Level 1)  
**Severity:** Low  
**Affected Files:** Project-wide

### Remediation
1. Add `cargo audit` to CI pipeline for Rust dependencies
2. Add `cargo deny` for license and vulnerability checking
3. Configure automated dependency scanning (e.g., Dependabot, Renovate)
4. Once FINDING-001 is addressed, verify all dependencies comply with documented timeframes
5. Generate and maintain SBOM (Software Bill of Materials)

Example CI configuration:
```yaml
- name: Security audit
  run: |
    cargo install cargo-audit
    cargo audit
    cargo install cargo-deny
    cargo deny check
```

### Acceptance Criteria
- [ ] Fixed - cargo audit integrated into CI pipeline
- [ ] Fixed - cargo deny integrated into CI pipeline
- [ ] Fixed - Automated dependency scanning configured
- [ ] Test added - CI fails on high/critical vulnerabilities
- [ ] Documentation added for dependency management process
- [ ] SBOM generation automated

### References
- ASVS 15.2.1
- Source: 15.2.1.md
- Dependency: FINDING-001

### Priority
Low - Requires foundational policy (FINDING-001) but improves security posture

---

## Issue: FINDING-006 - QuMat class exposes internal implementation details as public attributes
**Labels:** bug, security, priority:low
**Description:**
### Summary
The `QuMat` class exposes internal implementation details as public attributes, violating the principle of minimal exposure and risking information disclosure.

### Details
The following internal attributes are exposed as public:
- `backend_config` - Full backend configuration dictionary
- `backend_module` - Raw backend module reference
- `backend` - Backend instance
- `circuit` - Circuit object
- `parameters` - Internal parameters dictionary

Any code holding a reference to a `QuMat` instance can access these internal details. While this is a library (not a web service), it violates minimal exposure principles and could leak configuration details if:
- The instance is inadvertently serialized
- The instance is logged
- The instance is passed to untrusted code

**ASVS Reference:** 15.3.1 (Level 1)  
**Severity:** Low  
**Affected Files:** `qumat/qumat.py`

### Remediation
1. Use Python name-mangling (double underscore prefix) for internal attributes:
   - `backend_config` → `__backend_config`
   - `backend_module` → `__backend_module`
   - `backend` → `__backend`
   - `circuit` → `__circuit`
   - `parameters` → `__parameters`

2. Expose only necessary read-only properties:
```python
@property
def backend_name(self) -> str:
    """Public read-only access to backend name."""
    return self.__backend_config.get('name')
```

3. Update documentation to reflect the public API surface

### Acceptance Criteria
- [ ] Fixed - Internal attributes use name-mangling
- [ ] Fixed - Public properties defined for necessary read-only access
- [ ] Test added - Verify private attributes not directly accessible
- [ ] Test added - Verify public properties work correctly
- [ ] Documentation updated to reflect public API
- [ ] Backward compatibility strategy documented if needed

### References
- ASVS 15.3.1
- Source: 15.3.1.md
- Python name mangling: https://docs.python.org/3/tutorial/classes.html#private-variables

### Priority
Low - Information disclosure risk with limited impact in library context

---

## Issue: FINDING-007 - Incomplete documentation of input validation rules per encoding method
**Labels:** documentation, priority:low
**Description:**
### Summary
The `encode` method's docstring documents accepted input types but does not specify numerical constraints and validation rules for each encoding method.

### Details
The `encode()` method enforces validation rules in the core but does not document them at the API boundary. Missing documentation includes:

**Amplitude encoding:**
- Requires non-zero L2 norm
- No NaN or Inf values allowed

**Angle encoding:**
- Requires exactly `num_qubits` features per sample
- Valid range constraints

**Basis encoding:**
- Requires integer-valued indices
- Values must be in range `[0, 2^num_qubits)`

**IQP and IQP-Z encodings:**
- Specific constraints not documented

Users discover these rules only through runtime errors, reducing API usability and potentially causing confusion.

**ASVS Reference:** 2.1.1 (Level 1)  
**Severity:** Low  
**Affected Files:** `qdp/qdp-python/src/engine.rs`

### Remediation
Expand the `encode()` method docstring to include a validation rules section:

```python
"""
Encode classical data into quantum states.

Args:
    data: Input data (numpy array, list, or file path)
    encoding_method: Encoding method to use
    num_qubits: Number of qubits

Validation Rules by Encoding Method:
    amplitude:
        - L2 norm must be non-zero
        - No NaN or Inf values
        - Data will be normalized
    
    angle:
        - Exactly num_qubits features per sample required
        - Values should be in range [0, 2π]
    
    basis:
        - Integer values required
        - Values must be in range [0, 2^num_qubits)
    
    iqp, iqp-z:
        - [Document specific constraints]

Raises:
    ValueError: If input violates encoding-specific constraints
"""
```

### Acceptance Criteria
- [ ] Fixed - Docstring updated with validation rules for all encoding methods
- [ ] Test added - Documentation tests verify examples are correct
- [ ] Documentation includes constraint ranges
- [ ] Documentation includes example error cases
- [ ] User guide updated with validation rules

### References
- ASVS 2.1.1
- Source: 2.1.1.md

### Priority
Low - Documentation improvement to enhance API usability

---

## Issue: FINDING-008 - No dimension validation after loading torch files
**Labels:** bug, priority:low
**Description:**
### Summary
The PyTorch loader does not validate tensor dimensions after loading `.pt`/`.pth` files, potentially causing confusing errors downstream during encoding.

### Details
When using the PyTorch backend fallback, the loader:
1. Calls `torch.load(path, weights_only=True)`
2. Checks the result is a `torch.Tensor`
3. Does NOT validate:
   - Tensor has compatible dimensions (1D or 2D)
   - Feature dimension matches `num_qubits` requirements
   - Tensor shape is compatible with selected `encoding_method`

This can lead to:
- Confusing error messages during encoding (far from the root cause)
- Wasted computation before validation occurs
- Unclear failure modes for users

**ASVS Reference:** 2.2.1 (Level 1)  
**Severity:** Low  
**Affected Files:** `qdp/qdp-python/qumat_qdp/loader.py`

### Remediation
Add dimension validation immediately after loading:

```python
def _load_torch_file(self, path: str) -> torch.Tensor:
    tensor = torch.load(path, weights_only=True)
    
    if not isinstance(tensor, torch.Tensor):
        raise ValueError(f"Expected torch.Tensor, got {type(tensor)}")
    
    # Validate dimensions
    if tensor.ndim not in [1, 2]:
        raise ValueError(
            f"Expected 1D or 2D tensor, got {tensor.ndim}D tensor with shape {tensor.shape}"
        )
    
    # Validate feature dimension compatibility
    feature_dim = tensor.shape[-1] if tensor.ndim == 2 else len(tensor)
    if self.encoding_method == 'angle' and feature_dim != self.num_qubits:
        raise ValueError(
            f"Angle encoding requires exactly {self.num_qubits} features, "
            f"got {feature_dim}"
        )
    
    return tensor
```

### Acceptance Criteria
- [ ] Fixed - Dimension validation added after torch.load()
- [ ] Test added - Test with incompatible tensor dimensions
- [ ] Test added - Test with incompatible feature dimensions for angle encoding
- [ ] Test added - Test with valid 1D and 2D tensors
- [ ] Error messages provide clear guidance to users

### References
- ASVS 2.2.1
- Source: 2.2.1.md

### Priority
Low - Improves error handling and user experience

---

## Issue: FINDING-009 - measure_overlap does not enforce expected circuit state precondition
**Labels:** bug, priority:low
**Description:**
### Summary
The `measure_overlap` method does not verify the circuit is in the expected initial state before applying the swap test protocol, potentially producing incorrect results.

### Details
The `measure_overlap` method:
- Appends gates to the current circuit state
- Assumes the circuit starts in a specific clean state
- Does not verify the circuit state precondition
- Will produce incorrect (but not obviously erroneous) results if called on a circuit with existing gates

The swap test protocol requires:
- Ancilla qubit in |0⟩ state
- Data qubits in specific prepared states
- No prior gates that would interfere with the protocol

If called on a circuit with existing gates, the measurement results will be mathematically incorrect but may appear valid, leading to subtle bugs.

**ASVS Reference:** 2.3.1 (Level 1)  
**Severity:** Low  
**Affected Files:** `qumat/qumat.py`

### Remediation
Option 1 - Add precondition check:
```python
def measure_overlap(self, other: 'QuMat') -> float:
    if len(self.circuit.data) > 0:
        raise ValueError(
            "measure_overlap requires circuit in initial state. "
            "Circuit already has gates applied."
        )
    # ... proceed with swap test
```

Option 2 - Document precondition clearly:
```python
def measure_overlap(self, other: 'QuMat') -> float:
    """
    Measure overlap between two quantum states using swap test.
    
    Preconditions:
        - Circuit must be in initial state (no gates applied)
        - Both QuMat instances must have compatible dimensions
    
    Raises:
        ValueError: If circuit is not in expected initial state
    """
```

Option 3 - Reset circuit automatically:
```python
def measure_overlap(self, other: 'QuMat') -> float:
    # Create fresh circuit for swap test
    swap_circuit = self._create_swap_test_circuit(other)
    # ... measure
```

### Acceptance Criteria
- [ ] Fixed - Precondition validation or documentation added
- [ ] Test added - Test calling measure_overlap on circuit with existing gates
- [ ] Test added - Test valid measure_overlap on clean circuit
- [ ] Documentation clarifies circuit state requirements
- [ ] Decision documented on which remediation option chosen

### References
- ASVS 2.3.1
- Source: 2.3.1.md

### Priority
Low - Correctness issue with limited impact in typical usage

---

## Issue: FINDING-010 - No explicit magic byte verification before dispatching to format-specific parsers
**Labels:** bug, security, priority:low
**Description:**
### Summary
The library validates file extensions but does not perform magic byte verification before dispatching to format-specific parsers, creating a minor content validation gap.

### Details
Current validation flow:
1. Validate file extension against allowlist ✓
2. Dispatch to format-specific parser based on extension
3. Parser validates content during parsing ✓

Missing validation:
- No explicit magic byte verification before parser dispatch
- A file named `malicious.parquet` containing non-Parquet content would be passed to the Parquet parser
- Parser would eventually reject invalid content, but only after beginning to process it

**Impact is LOW because:**
- Parsing libraries provide content validation by failing on invalid format
- This is a local library (not processing untrusted uploads)
- No code execution occurs from file content
- File extension allowlist prevents most format confusion attacks

**CWE:** CWE-434 (Unrestricted Upload of File with Dangerous Type)  
**ASVS Reference:** 5.2.2 (Level 1)  
**Severity:** Low  
**Affected Files:** `qdp/qdp-python/src/engine.rs`, `qdp/qdp-core/src/lib.rs`

### Remediation
Implement lightweight magic byte verification before dispatching to parsers:

```rust
fn verify_magic_bytes(path: &Path, expected_format: &str) -> Result<(), Error> {
    let mut file = File::open(path)?;
    let mut magic = vec![0u8; 8];
    file.read_exact(&mut magic)?;
    
    match expected_format {
        "parquet" => {
            if &magic[0..4] != b"PAR1" {
                return Err(Error::InvalidFormat("Not a Parquet file"));
            }
        }
        "npy" => {
            if &magic[0..6] != b"\x93NUMPY" {
                return Err(Error::InvalidFormat("Not a NumPy file"));
            }
        }
        // Add other formats as needed
        _ => {}
    }
    
    Ok(())
}
```

### Acceptance Criteria
- [ ] Fixed - Magic byte verification implemented for well-known formats
- [ ] Test added - Test with mismatched extension and content
- [ ] Test added - Test with valid magic bytes
- [ ] Test added - Test with corrupted magic bytes
- [ ] Documentation updated with supported formats and validation
- [ ] Performance impact measured and acceptable

### References
- CWE-434: Unrestricted Upload of File with Dangerous Type
- ASVS 5.2.2
- Source: 5.2.2.md
- File signatures: https://en.wikipedia.org/wiki/List_of_file_signatures

### Priority
Low - Defense-in-depth improvement with minimal security impact