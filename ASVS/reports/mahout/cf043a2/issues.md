# Security Issues

## Issue: FINDING-003 - No classification of "dangerous functionality" or "risky components" in project documentation
**Labels:** security, priority:high, ASVS-15.1.1, documentation
**Description:**
### Summary
Components performing deserialization, raw data parsing, dynamic code execution, or direct memory manipulation are not explicitly documented as dangerous or risky.

### Details
The project uses components with dangerous functionality without documenting them:
- **cudarc**: direct memory manipulation
- **prost**: deserialization of untrusted data
- **tch**: raw binary data parsing, FFI
- **object_store**: network I/O to external services

Without this classification:
- Developers may not apply additional scrutiny during updates
- Security reviewers cannot prioritize audit effort
- Incident responders cannot quickly assess blast radius when a CVE is published

**Affected files:**
- `qdp/Cargo.toml` (lines 14-41)
- `pyproject.toml` (lines 48-54)

### Remediation
Add `docs/component-risk-register.md`:

```markdown
# Component Risk Register

## Dangerous Components
Components performing memory-unsafe operations or parsing untrusted data.
**Remediation window: 50% of standard timeframe**

| Component | Risk Category | Justification | Additional Controls |
|-----------|--------------|---------------|---------------------|
| cudarc | Dangerous | Direct GPU memory manipulation | Code review required for updates |
| prost | Dangerous | Protobuf deserialization | Input validation at boundaries |
| tch | Dangerous | PyTorch FFI, binary parsing | Sandboxed execution where possible |

## Risky Components
Components with elevated attack surface.

| Component | Risk Category | Justification | Additional Controls |
|-----------|--------------|---------------|---------------------|
| object_store | Risky | Network I/O to cloud services | TLS enforcement, credential rotation |
```

### Acceptance Criteria
- [ ] Component risk register created
- [ ] All dangerous components documented
- [ ] Justification and controls specified for each
- [ ] Halved remediation windows applied to dangerous components
- [ ] Register reviewed in security meetings
- [ ] Test: Verify register is complete and accessible

### References
- ASVS 15.1.1
- Source: `15.1.1.md`

### Priority
**High** - Impacts security review and incident response effectiveness

---

## Issue: FINDING-004 - No Dependabot or Renovate configuration for automated dependency update tracking
**Labels:** security, priority:high, ASVS-15.2.1, dependencies
**Description:**
### Summary
The project lacks automated dependency update tracking through Dependabot or Renovate, meaning new security patches may go unnoticed for extended periods.

### Details
The gap between vulnerability disclosure and developer awareness is undefined and potentially unbounded. Even with documented timeframes (FINDING-001), enforcement requires detection mechanisms. Without automated tracking:
- Security patches may be available but unknown to the team
- Manual monitoring is error-prone and doesn't scale
- No systematic process for evaluating updates

**Affected files:**
- Project root (missing `.github/dependabot.yml` or `renovate.json`)

### Remediation
Create `.github/dependabot.yml`:

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/qdp"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "rust"

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "python"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    labels:
      - "dependencies"
      - "github-actions"
```

### Acceptance Criteria
- [ ] Dependabot configuration file created
- [ ] Configuration covers cargo, pip, and github-actions
- [ ] Weekly schedule configured
- [ ] Appropriate PR limits set
- [ ] Test: Verify Dependabot creates PRs for outdated dependencies
- [ ] Team process established for reviewing Dependabot PRs

### References
- ASVS 15.2.1
- Source: `15.2.1.md`
- Related: FINDING-001, FINDING-002

### Priority
**High** - Essential for timely vulnerability detection

---

## Issue: FINDING-005 - Missing `sample_size > 0` validation allows panic via zero-sized chunk operation
**Labels:** bug, security, priority:medium, ASVS-2.1.1, ASVS-2.2.1, input-validation
**Description:**
### Summary
The `validate_batch` function checks `num_samples > 0` but does not validate `sample_size > 0`, allowing panics when `sample_size=0` is passed.

### Details
When `sample_size=0`:
1. Validation passes (0 × N = 0 matches empty batch_data)
2. Subsequent `calculate_batch_l2_norms` calls `par_chunks(0)`
3. `par_chunks(0)` panics
4. PyO3 catches panic and converts to PanicException

A user can trigger this by passing a numpy array with shape (N, 0) from Python. While PyO3 catches the panic, this:
- Bypasses normal error handling
- Can degrade service reliability in production
- Creates inconsistent error reporting

Documentation does not specify that `sample_size` must be > 0, creating incomplete specification.

**Affected files:**
- `qdp/qdp-core/src/preprocessing.rs` (lines 93, 93-125, 129-162)

### Remediation
1. **Add documentation:**
```rust
/// Validates batch dimensions.
///
/// # Requirements
/// All of `num_samples`, `sample_size`, and `num_qubits` must be greater than zero.
```

2. **Add validation:**
```rust
if sample_size == 0 {
    return Err(MahoutError::InvalidInput(
        "sample_size must be greater than 0".to_string()
    ));
}
```

### Acceptance Criteria
- [ ] Validation check added for `sample_size > 0`
- [ ] Documentation updated with requirements
- [ ] Test added: pass (N, 0) array, verify error not panic
- [ ] Test added: pass (0, M) array, verify existing validation
- [ ] Test: Verify error message is user-friendly

### References
- ASVS 2.1.1, 2.2.1
- Source: `2.1.1.md`, `2.2.1.md`

### Priority
**Medium** - Causes service degradation but has workaround

---

## Issue: FINDING-006 - No allowlist validation for `backend_name` in QuMat dynamic module import
**Labels:** security, priority:medium, ASVS-2.2.1, input-validation
**Description:**
### Summary
The QuMat `__init__` method accepts user-controlled `backend_name` and uses it directly in dynamic module import without allowlist validation.

### Details
The code performs:
```python
import_module(f".{self.backend_name}_backend", package="qumat")
```

While constrained by `package="qumat"` and `_backend` suffix pattern, ANY module matching this pattern would be loaded and its `initialize_backend` function called. This could load:
- Development/debug modules
- Future modules not yet production-ready
- Package extensions
- Modules added by compromised dependencies

This violates ASVS 2.2.1 requirement for allowlist validation of security-relevant inputs.

**Affected files:**
- `qumat/qumat.py` (line 67)

### Remediation
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

### Acceptance Criteria
- [ ] Allowlist of supported backends implemented
- [ ] Validation added before module import
- [ ] Clear error message for unsupported backends
- [ ] Test: Valid backend names accepted
- [ ] Test: Invalid backend names rejected with clear error
- [ ] Test: Verify error message includes list of supported backends

### References
- ASVS 2.2.1
- Source: `2.2.1.md`

### Priority
**Medium** - Defense-in-depth violation with limited attack surface

---

## Issue: FINDING-007 - `from_env()` Allows HTTP Fallback via Environment Variables Without Code-Level Guard
**Labels:** security, priority:medium, ASVS-12.2.1, tls, aws-braket
**Description:**
### Summary
The `AmazonS3Builder::from_env()` method reads `AWS_ALLOW_HTTP` environment variable without code-level enforcement, potentially allowing plaintext HTTP connections in production.

### Details
If `AWS_ALLOW_HTTP=true` is set in production environment (leftover from testing, misconfiguration, or compromise), the S3 client will permit plaintext HTTP connections. This is a Type A gap (entry point with NO control).

Impact if exploited:
- All S3/GCS data transfers occur over unencrypted HTTP
- Authentication headers exposed to network attackers
- Downloaded quantum circuit data exposed to eavesdropping
- Man-in-the-middle attacks possible

The same applies to `GoogleCloudStorageBuilder::from_env()`.

**Affected files:**
- `qdp/qdp-core/src/remote.rs` (lines 66-76)

### Remediation
**Option 1 (Recommended): Explicit disable after env load**
```rust
let store = object_store::aws::AmazonS3Builder::from_env()
    .with_bucket_name(bucket)
    .with_allow_http(false)  // Explicit override
    .build()
```

**Option 2: Runtime check**
```rust
#[cfg(not(test))]
{
    if std::env::var("AWS_ALLOW_HTTP").unwrap_or_default() == "true" {
        return Err(MahoutError::InvalidInput(
            "AWS_ALLOW_HTTP=true is not allowed in production".to_string()
        ));
    }
}
```

**Additional:**
- Verify GCS builder API for similar controls
- Add integration tests that verify TLS is actually used
- Consider wrapper around `ObjectStore` construction enforcing TLS policies

### Acceptance Criteria
- [ ] `.with_allow_http(false)` added to S3 builder
- [ ] Similar control added for GCS builder
- [ ] Integration test verifies TLS enforcement
- [ ] Test: Verify `AWS_ALLOW_HTTP=true` does not enable HTTP
- [ ] Documentation updated with TLS requirements

### References
- ASVS 12.2.1
- Source: `12.2.1.md`

### Priority
**Medium** - Mitigated by server-side enforcement but violates defense-in-depth

---

## Issue: FINDING-008 - Inconsistent GitHub Action version pinning between workflows creates supply chain drift risk
**Labels:** security, priority:medium, ASVS-15.2.1, ci-cd, supply-chain
**Description:**
### Summary
The release workflow uses mutable tag references (@v6, @v5) for GitHub Actions instead of commit hash pins, while the testing workflow properly pins actions to commit hashes.

### Details
The release workflow:
- Has `id-token: write` permission
- Publishes to PyPI
- Is a higher-value target than testing workflow

A compromised upstream action repository could inject malicious code into the release build, potentially:
- Stealing PyPI publish tokens
- Injecting backdoors into published wheels
- Exfiltrating source code or secrets

**Affected files:**
- `.github/workflows/release.yml` (lines 16, 17, 23, 32, 42, 59, 61, 69, 73, 77, 85, 89)

### Remediation
Pin all actions in `release.yml` to commit hashes following the pattern used in `python-testing.yml`:

```yaml
# Before:
- uses: actions/checkout@v6

# After:
- uses: actions/checkout@a1b2c3d4e5f6...  # v6.0.0
```

Include version comments for maintainability. Use Dependabot (FINDING-004) to keep pins updated.

### Acceptance Criteria
- [ ] All actions in release.yml pinned to commit hashes
- [ ] Version comments added for each pin
- [ ] Dependabot configured to update action pins
- [ ] Test: Verify release workflow executes successfully
- [ ] Documentation added explaining pinning policy

### References
- ASVS 15.2.1
- Source: `15.2.1.md`
- Related: FINDING-004

### Priority
**Medium** - Supply chain risk in release pipeline

---

## Issue: FINDING-009 - PyO3/maturin-action@v1 used without commit hash pin in both CI workflows
**Labels:** security, priority:medium, ASVS-15.2.1, ci-cd, supply-chain
**Description:**
### Summary
The PyO3/maturin-action is used with a mutable v1 tag in both testing and release workflows without commit hash pinning.

### Details
This third-party action:
- Compiles and links native code
- Is a high-value supply chain target
- Could inject backdoors into compiled wheels if compromised

Unlike other actions in `python-testing.yml` which are properly pinned, this action remains unpinned in both workflows. A compromised version could:
- Inject malicious code during compilation
- Steal secrets from the build environment
- Modify wheel contents before packaging

**Affected files:**
- `.github/workflows/python-testing.yml` (line 80)
- `.github/workflows/release.yml` (line 85)

### Remediation
Pin PyO3/maturin-action to a specific commit hash in both workflows:

```yaml
# Before:
- uses: PyO3/maturin-action@v1

# After:
- uses: PyO3/maturin-action@<commit-hash>  # v1.x.y
```

Research the latest stable version and pin to its commit hash. Add version comment for maintainability.

### Acceptance Criteria
- [ ] maturin-action pinned in python-testing.yml
- [ ] maturin-action pinned in release.yml
- [ ] Version comments added
- [ ] Test: Verify both workflows execute successfully
- [ ] Dependabot configured to update this pin

### References
- ASVS 15.2.1
- Source: `15.2.1.md`
- Related: FINDING-004, FINDING-008

### Priority
**Medium** - High-value supply chain target in build process

---

## Issue: FINDING-010 - Full Quantum State Vector Returned Without Subsetting Capability
**Labels:** security, priority:medium, ASVS-15.3.1, resource-exhaustion
**Description:**
### Summary
The `get_final_state_vector()` method unconditionally returns the entire state vector (2^N complex amplitudes) without any mechanism to request specific amplitudes, qubit subsets, or size limits.

### Details
For N=30 qubits, this results in approximately 8GB of data. The API provides no way to:
- Request amplitudes for specific basis states by index
- Request a partial trace (reduced density matrix for a qubit subset)
- Limit the number of returned amplitudes (e.g., top-k by magnitude)
- Return summary statistics instead of raw vector

This can cause:
- Memory exhaustion on client
- Network bandwidth exhaustion
- Denial of service as qubit counts grow exponentially
- Unnecessary data transfer costs

**Affected files:**
- `qumat/qumat.py` (lines 332-368)

### Remediation
Add subsetting parameters while preserving backward compatibility:

```python
def get_final_state_vector(
    self,
    indices: list[int] | None = None,
    top_k: int | None = None,
    qubit_subset: list[int] | None = None
) -> np.ndarray:
    """Get state vector with optional subsetting.
    
    Args:
        indices: Specific basis state indices to return
        top_k: Return only top-k amplitudes by magnitude
        qubit_subset: Return reduced state for specific qubits only
    """
    full_state = self.backend_module.get_final_state_vector(self.circuit)
    
    if indices is not None:
        return full_state[indices]
    
    if top_k is not None:
        magnitudes = np.abs(full_state)
        top_indices = np.argpartition(magnitudes, -top_k)[-top_k:]
        return full_state[top_indices]
    
    if qubit_subset is not None:
        # Implement partial trace logic
        pass
    
    return full_state  # Backward compatibility
```

### Acceptance Criteria
- [ ] Subsetting parameters added to method signature
- [ ] `indices` parameter implemented
- [ ] `top_k` parameter implemented
- [ ] Backward compatibility maintained (default returns full vector)
- [ ] Test: Verify subsetting works correctly
- [ ] Test: Verify backward compatibility
- [ ] Documentation updated with examples

### References
- ASVS 15.3.1
- Source: `15.3.1.md`

### Priority
**Medium** - Resource exhaustion risk increases with qubit count

---

## Issue: FINDING-011 - No validation of rotation gate angles for finiteness in QuMat
**Labels:** bug, security, priority:low, ASVS-2.2.1, ASVS-2.2.2, ASVS-2.1.1, input-validation
**Description:**
### Summary
The QuMat rotation gate functions accept angle parameters but do not validate that numeric angles are finite (not NaN or Inf).

### Details
Affected functions:
- `apply_rx_gate`
- `apply_ry_gate`
- `apply_rz_gate`
- `apply_u_gate`

The `_handle_parameter` method only registers string parameters but performs no numeric validation. Non-finite angles produce:
- Mathematically undefined rotation matrices
- Garbage quantum state vectors
- Incorrect downstream decisions if results aren't validated

This represents inconsistent validation: qubit indices are validated before backend delegation, but angles are not.

**Affected files:**
- `qumat/qumat.py` (lines 366-457)

### Remediation
```python
def _validate_angle(self, angle: float | str, param_name: str = "angle") -> None:
    """Validate that a numeric angle is finite.
    
    Args:
        angle: Angle value or parameter name
        param_name: Name for error messages
        
    Raises:
        ValueError: If angle is NaN or Inf
        TypeError: If angle is not float or str
    """
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

# Apply to all rotation gates:
def apply_rx_gate(self, qubit: int, angle: float | str) -> None:
    self._validate_angle(angle, "angle")
    # ... rest of implementation
```

**Future enhancement:** Consider a `ValidatedAngle` newtype wrapper that guarantees finiteness at construction time.

### Acceptance Criteria
- [ ] `_validate_angle` helper method implemented
- [ ] Validation applied to all rotation gate methods
- [ ] Test: NaN angle rejected with clear error
- [ ] Test: Inf angle rejected with clear error
- [ ] Test: Valid angles accepted
- [ ] Test: String parameter names still work
- [ ] Documentation updated

### References
- ASVS 2.2.1, 2.2.2, 2.1.1
- Source: `2.2.1.md`, `2.2.2.md`, `2.1.1.md`

### Priority
**Low** - Produces incorrect results but no memory safety issue

---

## Issue: FINDING-012 - `create_empty_circuit` does not validate `num_qubits` parameter
**Labels:** bug, security, priority:low, ASVS-2.2.1, input-validation
**Description:**
### Summary
The `create_empty_circuit` function accepts a `num_qubits` parameter but performs no validation on it before storing and passing to the backend.

### Details
Any value (negative int, float, string, etc.) is:
- Stored as `self.num_qubits`
- Passed directly to the backend
- Used in `_validate_qubit_index` upper bound checks

Negative or non-integer qubit counts:
- Bypass the `_validate_qubit_index` upper bound check
- May cause unexpected backend behavior
- Violate input validation best practices

Impact is mitigated because most backends would reject invalid values, but this represents incomplete input validation at the trusted service layer.

**Affected files:**
- `qumat/qumat.py` (lines 72-82)

### Remediation
```python
def create_empty_circuit(self, num_qubits: int | None = None) -> None:
    """Create an empty quantum circuit.
    
    Args:
        num_qubits: Number of qubits (must be non-negative integer)
        
    Raises:
        TypeError: If num_qubits is not an integer
        ValueError: If num_qubits is negative
    """
    if num_qubits is not None:
        if not isinstance(num_qubits, int) or isinstance(num_qubits, bool):
            raise TypeError(
                f"num_qubits must be an integer, got {type(num_qubits).__name__}"
            )
        if num_qubits < 0:
            raise ValueError(
                f"num_qubits cannot be negative, got {num_qubits}"
            )
    
    self.num_qubits = num_qubits
    self.circuit = self.backend_module.create_empty_circuit(num_qubits)
```

### Acceptance Criteria
- [ ] Type validation added for `num_qubits`
- [ ] Range validation added (non-negative)
- [ ] Test: Negative value rejected
- [ ] Test: Float value rejected
- [ ] Test: String value rejected
- [ ] Test: Valid integer accepted
- [ ] Test: None value accepted (if allowed)

### References
- ASVS 2.2.1
- Source: `2.2.1.md`

### Priority
**Low** - Mitigated by backend validation

---

## Issue: FINDING-013 - No Explicit TLS Protocol Version Configuration for Cloud Storage Connections
**Labels:** security, priority:low, ASVS-12.1.1, tls, aws-braket
**Description:**
### Summary
Neither the Rust `object_store` client nor the Python `boto3` client explicitly configures minimum TLS protocol versions, relying on library defaults and server-side enforcement.

### Details
**Rust (`object_store`):**
- Uses `reqwest` which typically compiles with `rustls` (supports only TLS 1.2/1.3) or `native-tls` (platform-dependent, may support TLS 1.0/1.1)
- Behavior depends on compile-time features

**Python (`boto3`):**
- Uses system OpenSSL via `urllib3`
- Modern OpenSSL (1.1.1+) defaults to TLS 1.2 minimum
- Older systems may allow TLS 1.0/1.1

While AWS and GCP endpoints only accept TLS 1.2+, this represents reliance on server-side enforcement rather than client-side control (defense-in-depth gap).

**Affected files:**
- `qdp/qdp-core/src/remote.rs` (lines 62-95)
- `qumat/amazon_braket_backend.py` (lines 33-36)

### Remediation
**Rust: Ensure rustls feature**
```toml
# Cargo.toml
object_store = { version = "...", features = ["aws", "gcp"], default-features = false }
reqwest = { version = "...", features = ["rustls-tls"], default-features = false }
```

**Python: Configure boto3 SSL context**
```python
import ssl
import boto3

# At application startup:
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

# Pass to boto3 if API supports (may require custom urllib3 config)
```

### Acceptance Criteria
- [ ] Rust: rustls feature explicitly enabled
- [ ] Rust: native-tls disabled in production builds
- [ ] Python: TLS 1.2 minimum configured if supported by boto3 API
- [ ] Test: Verify TLS 1.2+ is actually used (integration test)
- [ ] Documentation updated with TLS requirements
- [ ] Build verification that rustls is used

### References
- ASVS 12.1.1
- Source: `12.1.1.md`

### Priority
**Low** - Mitigated by server-side enforcement, but violates defense-in-depth

---

## Issue: FINDING-014 - Cargo workspace uses semver ranges without cargo audit enforcement
**Labels:** security, priority:low, ASVS-15.2.1, dependencies, rust
**Description:**
### Summary
The Cargo workspace dependencies use appropriate semver ranges and Cargo.lock ensures reproducible builds, but there is no evidence that `cargo audit` is run against the lockfile to check for known vulnerabilities.

### Details
Without auditing:
- Known vulnerabilities in resolved versions go undetected
- Compliance with ASVS 15.2.1 cannot be verified
- No systematic process for identifying vulnerable dependencies

The Cargo.lock file provides reproducibility but not security validation.

**Affected files:**
- `qdp/Cargo.toml` (lines 14-41)

### Remediation
Add `cargo audit` to CI workflow (see FINDING-002 for complete implementation):

```yaml
# .github/workflows/python-testing.yml
- name: Run cargo audit
  working-directory: qdp
  run: |
    cargo install cargo-audit
    cargo audit --deny warnings
```

Also add to scheduled weekly scans.

### Acceptance Criteria
- [ ] cargo audit integrated into CI (see FINDING-002)
- [ ] Scheduled weekly audit configured
- [ ] Test: Introduce test advisory, verify CI fails
- [ ] Test: Verify audit runs on every PR
- [ ] Documentation updated

### References
- ASVS 15.2.1
- Source: `15.2.1.md`
- Related: FINDING-002

### Priority
**Low** - Covered by FINDING-002 implementation

---

## Issue: FINDING-015 - Full Measurement Results Returned Without Filtering
**Labels:** security, priority:low, ASVS-15.3.1, resource-exhaustion
**Description:**
### Summary
The `execute_circuit()` method returns the complete measurement distribution without filtering options, potentially returning up to 2^N entries for circuits with uniform distributions.

### Details
For circuits with 20 qubits and uniform distributions, result dictionaries can contain up to 2^20 (1,048,576) entries. There is no option to:
- Filter results by minimum count threshold
- Request only the top-k most probable states
- Limit the total number of entries returned

While measurement results are naturally sparser than state vectors, this can still cause:
- Excessive memory usage for uniform distributions
- Unnecessary network bandwidth
- Processing overhead for large result sets

**Affected files:**
- `qumat/qumat.py` (lines 265-310)

### Remediation
```python
def execute_circuit(
    self,
    num_shots: int = 1024,
    min_count: int | None = None,
    top_k: int | None = None
) -> dict[str, int]:
    """Execute circuit and return measurement results.
    
    Args:
        num_shots: Number of measurement shots
        min_count: Minimum count threshold for returned results
        top_k: Return only top-k most frequent results
        
    Returns:
        Dictionary mapping basis states to counts
    """
    results = self.backend_module.execute_circuit(
        self.circuit, num_shots
    )
    
    if min_count is not None:
        results = {
            state: count 
            for state, count in results.items() 
            if count >= min_count
        }
    
    if top_k is not None:
        sorted_results = sorted(
            results.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        results = dict(sorted_results[:top_k])
    
    return results
```

### Acceptance Criteria
- [ ] `min_count` parameter added
- [ ] `top_k` parameter added
- [ ] Backward compatibility maintained (default returns all results)
- [ ] Test: min_count filtering works correctly
- [ ] Test: top_k filtering works correctly
- [ ] Test: Combined filtering works correctly
- [ ] Test: Default behavior unchanged
- [ ] Documentation updated with examples

### References
- ASVS 15.3.1
- Source: `15.3.1.md`
- Related: FINDING-010

### Priority
**Low** - Impact limited to specific circuit types (uniform distributions)