# Security Audit Tooling

This page provides an overview of the goals for security audit tooling in ATR: 

- [Motivation](#motivation)
- [Available toolsets](#available-toolsets)
- [Needs for ATR](#needs-for-atr)
- [Approaches](#approaches)
- [Phases](#phases)

## Motivation

Apache Trusted Releases (ATR) is a release management tool for verifying and distributing Apache releases securely. As such there is a need for all code, configuration, and workflows in ATR to comply with high standards for security. The Tooling team have adopted the [Application Security Verification
Standard (ASVS) v5.0.0](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) from the [Open Worldwide Application Security Project (OWASP)](https://owasp.org) as our standard.

The ASVS defines three levels of security verification, with L1 comprising the highest priority and most critical requirements, L2 including defenses against less common threats, and L3 rounding out the highest level of compliance. Requirements in L1 are about 20% of the spec, in L2 about 50%, and in L3 about 30%. For the beta release of ATR in early 2026 the target is to fulfill all requirements in L1 and the bulk of L2, noting that some of the requirements will need infrastructure changes, so compliance with those is out of Tooling's control.

To accelerate this goal the Tooling team is planning an internal pilot of automated code auditing, to work through the requirements while maintaining momentum on ATR feature development. We are assessing existing third-party tools and considering their viability along with what to build in-house to satisfy the security requirements for ATR.

## Available toolsets

### GitHub organization security settings

- [Managing security settings for your organization](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization)
- [Dependabot](https://github.com/orgs/apache/security/metrics/dependabot): already in use
- [Code scanning](https://github.com/orgs/apache/security/alerts/code-scanning): already in use
- [Secret scanning](https://github.com/orgs/apache/security/alerts/secret-scanning): already in use

### OpenSSF Scorecard

[Scorecard](https://securityscorecards.dev) is a security checklist tool which provides two approaches:
- [CLI](https://github.com/ossf/scorecard?tab=readme-ov-file#scorecard-command-line-interface)
- [GitHub Action](https://github.com/marketplace/actions/ossf-scorecard-action)

This tool does simple overall reporting, with a weighted score along with justification for component scores. Each component of the review and its mitigation steps is detailed in the page for [Checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md).

Example output from the CLI [here (default summary)](scorecard-atr.md) and [with details here](scorecard-atr-details.md).

### OpenAI Aardvark

In private beta, ASF has applied to join the [beta program](https://openai.com/index/introducing-aardvark/).

### Alpha-Omega VEX

[VEX](https://github.com/vex-generation-toolset) is an agent-driven audit tool in pilot phase with Apache Solr, providing root cause analysis, call graphs, and reporting for anything identified as related to a given CVE. Looks potentially adaptable as a quick path toward ASVS L1 compliance with changes to prompts in the code.

### AI Alliance Gofannon

[Gofannon](https://github.com/The-AI-Alliance/gofannon) is a generated agent and application builder useful for prototyping and application development. It allows users to prompt application requirements and agents in a simple workflow, deploys API endpoints for agents, and deploys a hosted running application along with the front-end code for the user to export as needed.

## Needs for ATR

- Immediate need for streamlining of ASVS L1 compliance
  - [Categories of L1 criteria](https://github.com/apache/tooling-trusted-releases/issues/334)
    1. Evaluate ASVS v5.0.0 compliance: server side execution [#397](https://github.com/apache/tooling-trusted-releases/issues/397)
      - 1.2.4, 1.2.5, 1.3.2, 5.2.2, 5.3.1, 5.3.2, 15.2.1
    2. Evaluate ASVS v5.0.0 compliance: cross site scripting [#398](https://github.com/apache/tooling-trusted-releases/issues/398)
      - 1.2.1, 1.2.2, 1.2.3, 1.3.1, 3.2.1, 3.2.2, 4.1.1
    3. Evaluate ASVS v5.0.0 compliance: weak cryptography [#399](https://github.com/apache/tooling-trusted-releases/issues/399)
      - 3.4.1, 4.4.1, 11.3.1, 11.3.2, 11.4.1, 12.1.1, 12.2.1, 12.2.2
    4. Evaluate ASVS v5.0.0 compliance: external access [#400](https://github.com/apache/tooling-trusted-releases/issues/400)
      - 3.4.2, 3.5.1, 3.5.2, 3.5.3, 10.4.1, 14.2.1
    5. Evaluate ASVS v5.0.0 compliance: universal spoofing [#401](https://github.com/apache/tooling-trusted-releases/issues/401)
      - 7.3.2, 9.1.1, 9.1.2, 10.4.2, 10.4.5
    6. Evaluate ASVS v5.0.0 compliance: internal access [#402](https://github.com/apache/tooling-trusted-releases/issues/402)
      - 2.2.1, 2.2.2, 2.3.1, 8.2.1, 8.3.1, 10.4.4
    7. Evaluate ASVS v5.0.0 compliance: credential stealing [#403](https://github.com/apache/tooling-trusted-releases/issues/403)
      - 3.3.1, 7.2.2, 7.2.3, 7.2.4, 7.4.2, 9.1.3, 9.2.1, 10.4.3, 14.3.1
    8. Evaluate ASVS v5.0.0 compliance: basic access [#404](https://github.com/apache/tooling-trusted-releases/issues/404)
      - 8.2.2, 13.4.1, 15.3.1
    9. Evaluate ASVS v5.0.0 compliance: brute force identification [#405](https://github.com/apache/tooling-trusted-releases/issues/405)
      - 6.2.1, 6.2.4, 6.3.1, 6.3.2, 6.4.1
    10. Evaluate ASVS v5.0.0 compliance: credential integrity [#406](https://github.com/apache/tooling-trusted-releases/issues/406)
      - 6.2.2, 6.2.3, 6.2.5, 6.2.6, 6.2.7, 6.2.8, 6.4.2, 7.4.1
    11. Evaluate ASVS v5.0.0 compliance: denial of service [#407](https://github.com/apache/tooling-trusted-releases/issues/407)
      - 1.5.1, 5.2.1
    12. Evaluate ASVS v5.0.0 compliance: documentation [#408](https://github.com/apache/tooling-trusted-releases/issues/408)
      - 2.1.1, 6.1.1, 8.1.1, 15.1.1
- Short-term need for ASVS L2 compliance
- Long-term need for automated repo and commit scanning

## Approaches

- ASVS-oriented automated auditing as standalone tool
- Page on ATR for audit suites including ASVS compliance
- GitHub Action (audit on demand/commit, reporting, etc.) for ASF projects

## Phases

### Research

- Inital requirements and assessment for ASVS compliance
  - Underway
  - Remaining: further tool evaluations and decisions on approaches
- Tool evaluation
  - Assessment of gaps and viability for ATR

### Design and prototyping

### Integration and build

- Integration and extension of viable tooling
- Build of new tooling

### Pilot

- First with ATR codebase
- Selected project codebases

### General availability

