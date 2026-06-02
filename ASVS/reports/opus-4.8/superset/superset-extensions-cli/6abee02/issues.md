# Security Issues

*1 actionable finding(s). 12 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---

## Issue: FINDING-001 - Unbounded/unpinned first-party-named dependency with no index or integrity pinning

**Labels:** security, priority:low, dependency-management, CWE-1104, ASVS-15.2.4

**Description:**

### Summary
The `apache-superset-core` runtime dependency in `pyproject.toml` is declared without version bounds, index pinning, or hash/lockfile integrity verification. If the distribution name is unclaimed on the index a developer's resolver uses, a third party could publish a malicious package, yielding arbitrary code execution in the developer's environment at install/import time.

### Details
- **CWE:** CWE-1104 (Use of Unmaintained Third Party Components)
- **ASVS:** 15.2.4 (Level 3)
- **Severity:** Low

The CLI imports `superset_core.extensions.*` at startup, creating a potential supply chain attack vector. While the npm scoped `@apache-superset/core` is protected by scope ownership, the Python package lacks similar protections.

Exploitability depends on:
- The first-party name being unclaimed on the target index
- In practice, ASF (Apache Software Foundation) controls the namespace
- No concrete proof of unclaimed-name vulnerability exists

This represents an exception to the dev-only carve-out because the CLI fetches remote dependency content without integrity verification, where tampering could compromise the developer's workstation.

**Affected Files:**
- `superset-extensions-cli/pyproject.toml`
- `superset-extensions-cli/src/superset_extensions_cli/templates/frontend/package.json.j2`

### Remediation
1. Pin version floor and ceiling constraints once a stable `apache-superset-core` release exists
2. Ship a hash-pinned lockfile using `pip install --require-hashes`
3. Document and recommend installation from the explicit expected package index
4. Reserve `apache-superset-core` and `@apache-superset/*` names on public registries (PyPI, npm) to prevent namespace squatting

### Acceptance Criteria
- [ ] Version bounds added to `apache-superset-core` dependency specification
- [ ] Hash-pinned lockfile generated and committed
- [ ] Documentation updated with recommended installation practices
- [ ] Package names reserved on PyPI and npm registries
- [ ] Test added to verify dependency integrity checks
- [ ] Security review completed

### References
- Source Report: `15.2.4.md`
- Related IDs: ASVS-1524-LOW-001, DEPENDENCY_MANAGEMENT-1
- CWE-1104: https://cwe.mitre.org/data/definitions/1104.html
- ASVS 15.2.4: Configuration verification requirements

### Priority
**Low** - Exploitability is limited by ASF namespace control, but proactive hardening is recommended for defense-in-depth.