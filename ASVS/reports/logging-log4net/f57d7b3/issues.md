# Security Issues

## Issue: FINDING-001 - No documented risk-based remediation time frames for third-party component vulnerabilities
**Labels:** bug, security, priority:low

**Description:**

### Summary
The project lacks documented risk-based remediation time frames for addressing vulnerabilities in third-party components, representing a documentation gap in the security governance process (ASVS 15.1.1, Level L1).

### Details
While the project is a library with minimal third-party dependencies governed by ASF release processes and publishes a CycloneDX VDR, there is no explicit Service Level Agreement (SLA) or documented policy defining time frames for remediating vulnerabilities based on their severity. This is a documentation gap rather than a material security risk given the project's minimal external dependencies.

**Severity:** Low  
**CWE:** N/A  
**ASVS Section:** 15.1.1 (Level L1)  
**Affected:** Repository-level documentation gap

### Remediation
Consider documenting remediation time frames in SECURITY.md or equivalent documentation, aligned with ASF security response processes. The policy should define clear SLAs for addressing vulnerabilities based on severity levels (e.g., Critical, High, Medium, Low).

### Acceptance Criteria
- [ ] Fixed: Remediation time frame policy documented in SECURITY.md or equivalent
- [ ] Test added: Documentation reviewed and approved by security team
- [ ] Policy aligned with ASF security response processes
- [ ] SLAs defined for each vulnerability severity level

### References
- Source Report: 15.1.1.md
- ASVS 15.1.1: Dependency Management Requirements
- Related: FINDING-002 (dependency update compliance)

### Priority
**Low** - Documentation gap in a library with minimal dependencies and existing ASF governance

---

## Issue: FINDING-002 - Unable to verify component update compliance due to absence of dependency manifest and remediation policy
**Labels:** bug, security, priority:low

**Description:**

### Summary
The absence of a documented remediation policy makes it technically impossible to verify whether components are updated within acceptable time frames, representing a governance gap in dependency management (ASVS 15.2.1, Level L1).

### Details
Without a documented remediation policy (prerequisite from ASVS 15.1.1 / FINDING-001), there is no baseline to assess whether any component has breached acceptable update time frames. This is a governance and verification gap rather than evidence of known vulnerable components.

**Severity:** Low  
**CWE:** N/A  
**ASVS Section:** 15.2.1 (Level L1)  
**Affected:** Repository-level assessment

### Remediation
1. Establish the remediation time frame policy referenced in FINDING-001
2. Add automated dependency scanning to CI/CD pipeline (e.g., OWASP Dependency-Check, Snyk, or GitHub Dependabot)
3. Configure alerts for components exceeding remediation time frames
4. Document the dependency management and update process

### Acceptance Criteria
- [ ] Fixed: Automated dependency scanning integrated into CI/CD
- [ ] Test added: Verification that scanning runs on each build/PR
- [ ] Remediation policy from FINDING-001 implemented
- [ ] Alerts configured for policy violations
- [ ] Dependency update process documented

### References
- Source Report: 15.2.1.md
- ASVS 15.2.1: Dependency Update Requirements
- Prerequisite: FINDING-001 (remediation time frame policy)

### Priority
**Low** - Governance gap; requires FINDING-001 resolution as prerequisite