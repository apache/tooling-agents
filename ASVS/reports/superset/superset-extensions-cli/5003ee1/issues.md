# Security Issues

---

## Issue: FINDING-001 - Path traversal via unvalidated glob patterns in `copy_backend_files`

**Labels:** bug, security, priority:medium

**Description:**

### Summary
The `copy_backend_files` function in the Superset Extensions CLI is vulnerable to path traversal attacks through unvalidated glob patterns. On Python 3.10-3.12, an attacker controlling a malicious extension's `pyproject.toml` can use `..` components in glob patterns to include sensitive files from outside the intended `backend_dir`, potentially exfiltrating credentials, SSH keys, or other sensitive data into the distributed `.supx` archive.

### Details
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **ASVS:** 5.3.2 (Level L1)
- **Affected File:** `superset-extensions-cli/src/superset_extensions_cli/cli.py`

The vulnerability exists because glob patterns from `pyproject.toml` are used directly with `Path.glob()` without validation. In Python 3.10-3.12, `Path.glob()` allows patterns containing `..` path components, enabling traversal outside the intended directory boundary.

**Attack Scenario:**
A supply chain attacker could create a malicious extension project with a `pyproject.toml` containing:
```toml
[tool.superset-extensions]
backend_files = ["../../.ssh/*", "../../../.env"]
```

When a developer builds this extension, sensitive files would be copied into the build output and bundled into the distributed archive.

### Remediation
Implement the following security controls in `copy_backend_files`:

1. **Pattern Validation:** Reject any glob patterns containing `..` components before processing
2. **Path Resolution:** Use `Path.resolve()` to get absolute paths of matched files
3. **Boundary Check:** Verify all resolved paths remain within `backend_dir` using `Path.is_relative_to(backend_dir)` (Python 3.9+)
4. **Fail Securely:** Raise an exception if any file falls outside the allowed directory

Example implementation:
```python
def copy_backend_files(backend_dir: Path, patterns: list[str]):
    backend_dir = backend_dir.resolve()
    for pattern in patterns:
        if '..' in pattern.split('/'):
            raise ValueError(f"Invalid pattern containing '..': {pattern}")
        for file in backend_dir.glob(pattern):
            resolved = file.resolve()
            if not resolved.is_relative_to(backend_dir):
                raise ValueError(f"Path traversal detected: {file}")
            # proceed with copy
```

### Acceptance Criteria
- [ ] Pattern validation added to reject `..` components in glob patterns
- [ ] Path resolution and boundary checking implemented using `Path.resolve()` and `Path.is_relative_to()`
- [ ] Security exception raised when path traversal attempt is detected
- [ ] Unit tests added covering malicious patterns (e.g., `../../.ssh/*`, `../config`)
- [ ] Integration test verifies legitimate nested patterns still work (e.g., `subdir/**/*.py`)
- [ ] Documentation updated to describe allowed pattern syntax

### References
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
- ASVS 5.3.2: Verify that file and other resource limits are enforced
- Source Report: 5.3.2.md

### Priority
**Medium** - This is a supply chain security vulnerability that requires social engineering (convincing a developer to build a malicious extension) but could lead to credential theft and unauthorized access to sensitive systems.