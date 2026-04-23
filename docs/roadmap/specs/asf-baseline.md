# ASF Security Baseline

## Overview

No external security standard covers ASF-specific concerns: release signing, NOTICE file compliance, Apache OAuth integration patterns, committer vs PMC authorization models, or ASF infrastructure conventions. The ASF Security Baseline is a custom spec that captures institutional knowledge about what "secure" means specifically for ASF projects.

This is the spec that answers questions like:
- "Is this project following the ASF release process correctly?"
- "Are committer permissions properly scoped?"
- "Does the project handle Apache OAuth delegation securely?"
- "Are secrets stored according to ASF infrastructure conventions?"

## Requirements

Draft requirements, organized by category. These should be developed collaboratively with ASF Infrastructure and Security teams.

### Release Integrity

| ID | Requirement | Level |
|---|---|---|
| ASF-REL-1 | Release artifacts MUST be signed with a key in the project's KEYS file | L1 |
| ASF-REL-2 | Release artifacts MUST have SHA-512 checksums published alongside them | L1 |
| ASF-REL-3 | The build process MUST be reproducible from source in the tagged release | L2 |
| ASF-REL-4 | Release branches MUST NOT contain binary artifacts not built from source | L1 |
| ASF-REL-5 | Release votes MUST reference specific commit hashes, not branch names | L2 |

### License and Notice Compliance

| ID | Requirement | Level |
|---|---|---|
| ASF-LIC-1 | All source files MUST contain the Apache License header | L1 |
| ASF-LIC-2 | The NOTICE file MUST be present and list required attributions | L1 |
| ASF-LIC-3 | Dependencies MUST NOT include Category X (GPL, AGPL) licenses for binary releases | L1 |
| ASF-LIC-4 | Dependencies with Category B licenses MUST be documented in LICENSE | L2 |
| ASF-LIC-5 | Generated code MUST preserve license headers from source templates | L2 |

### Authentication and Authorization

| ID | Requirement | Level |
|---|---|---|
| ASF-AUTH-1 | Projects using OAuth MUST delegate to `oauth.apache.org`, not implement their own OAuth server | L1 |
| ASF-AUTH-2 | Committer vs PMC member authorization MUST be enforced for privileged operations | L1 |
| ASF-AUTH-3 | Session tokens MUST NOT be logged or included in error responses | L1 |
| ASF-AUTH-4 | API keys and tokens MUST be loaded from environment or secrets management, never hardcoded | L1 |
| ASF-AUTH-5 | Projects exposing admin interfaces MUST restrict access to PMC members or designated administrators | L2 |

### Infrastructure Conventions

| ID | Requirement | Level |
|---|---|---|
| ASF-INFRA-1 | Projects MUST NOT commit secrets, tokens, or credentials to version control | L1 |
| ASF-INFRA-2 | GitHub Actions MUST pin external actions to commit SHAs per ASF policy | L1 |
| ASF-INFRA-3 | Projects SHOULD use ASF-managed secrets (GitHub org secrets) instead of repo-level secrets | L2 |
| ASF-INFRA-4 | Automated publishing workflows MUST use trusted publishing (OIDC) where available | L2 |
| ASF-INFRA-5 | Docker images used in CI MUST be pinned to digest, not floating tag | L2 |

### Vulnerability Management

| ID | Requirement | Level |
|---|---|---|
| ASF-VULN-1 | Projects MUST have a SECURITY.md file with reporting instructions | L1 |
| ASF-VULN-2 | Projects MUST have automated dependency scanning enabled (Dependabot or Renovate) | L1 |
| ASF-VULN-3 | Known vulnerable dependencies MUST be updated within 30 days of disclosure for Critical, 90 days for High | L2 |
| ASF-VULN-4 | Projects SHOULD participate in the ASF coordinated disclosure process | L2 |

## Relationship to Apache Trusted Releases (ATR)

ATR already verifies many of the same properties — release signing, checksums, license compliance — at distribution time. The ASF Baseline checks these at development time, in the source code and CI configuration that produces the release.

| Concern | ATR (runtime) | ASF Baseline (source) |
|---|---|---|
| Release signing | "Is this artifact signed with a KEYS-listed key?" | "Does the release workflow include a signing step?" |
| Checksums | "Does this artifact have a published SHA-512?" | "Does the CI generate checksums before upload?" |
| License headers | "Does the source archive contain Apache headers?" | "Do all source files have headers? Is the check in CI?" |
| NOTICE file | "Is NOTICE present in the release?" | "Is NOTICE maintained in source and updated with deps?" |
| Dependency licenses | "Does the binary release include Category X deps?" | "Does the CI check license compatibility before merge?" |

This is belt-and-suspenders: ATR is the gate that catches problems at release time, ASF Baseline is the shift-left check that catches them during development so they never reach the gate. A project passing ASF Baseline should have a smooth ATR release process. A project failing ASF Baseline will hit friction at release time that ATR surfaces.

For projects already using ATR, the ASF Baseline findings are mostly informational ("you'll pass ATR because your CI already handles this"). For projects not yet using ATR, the ASF Baseline tells them what to fix before they try to release.

## How This Differs from Other Specs

| Concern | ASVS | Scorecard | ATR | ASF Baseline |
|---|---|---|---|---|
| Release signing | No | Partial | ✅ Verifies at release | Checks source/CI for signing steps |
| Checksums | No | No | ✅ Verifies at release | Checks CI generates them |
| License compliance | No | No | ✅ Verifies in archive | Checks source files + CI enforcement |
| ASF OAuth | No | No | No | Yes |
| Committer/PMC authz | No | No | No | Yes |
| GHA SHA pinning | No | Partial | No | Full (per ASF policy) |
| SECURITY.md | No | Yes | No | Yes (aligned) |
| Dependency scanning | No | Yes | No | Yes (aligned, adds SLA) |

The ASF Baseline is complementary to ASVS, Scorecard, and ATR. It covers the development-time layer that none of them address.

## Data Store Schema

```
Namespace: asf-baseline
Key: asf-baseline:requirements:ASF-REL-1

{
  "id": "ASF-REL-1",
  "title": "Release artifacts must be signed",
  "description": "Release artifacts distributed through ASF mirrors MUST be signed with a GPG/PGP key that is published in the project's KEYS file on dist.apache.org.",
  "level": 1,
  "category": "release_integrity",
  "spec": "asf-baseline",
  "spec_version": "1.0",
  "evidence": [
    "KEYS file exists in repository or is referenced in README",
    "Release scripts or CI workflows include signing steps",
    "Published releases on dist.apache.org have .asc signature files"
  ],
  "references": [
    "https://infra.apache.org/release-signing.html",
    "https://www.apache.org/legal/release-policy.html"
  ],
  "cross_references": {}
}
```

## Discovery Agent Integration

The ASF Baseline applies to all ASF projects regardless of type. The discovery agent should always recommend it:

```python
recommended_specs.append({
    "spec": "asf-baseline",
    "coverage": "full",
    "reason": "ASF project — baseline requirements always apply"
})
```

For ASF Baseline specifically, the discovery agent should also check for:
- Presence of NOTICE, LICENSE, KEYS files
- Presence of SECURITY.md
- Presence of .github/dependabot.yml or renovate.json
- GitHub Actions workflow files (for INFRA requirements)

These can be checked deterministically (file exists or not) without LLM analysis, making ASF Baseline partially a static check rather than pure LLM audit.

## Hybrid Approach: Static + LLM

Some ASF Baseline requirements can be evaluated without an LLM:

| Requirement | Method | LLM Needed? |
|---|---|---|
| ASF-LIC-1 (license headers) | Regex scan for Apache header | No |
| ASF-LIC-2 (NOTICE file) | File existence check | No |
| ASF-VULN-1 (SECURITY.md) | File existence check | No |
| ASF-VULN-2 (dependency scanning) | Check for dependabot.yml | No |
| ASF-INFRA-2 (SHA-pinned actions) | Parse workflow YAML | No (our GHA pipeline does this) |
| ASF-AUTH-1 (OAuth delegation) | Code analysis | Yes |
| ASF-AUTH-2 (committer/PMC authz) | Code analysis | Yes |
| ASF-REL-3 (reproducible build) | Build system analysis | Yes |

The audit agent could have a fast path for static checks (no LLM call, instant result) and only invoke the LLM for requirements that need code reasoning.

## Collaboration

This spec should be developed with input from:
- **ASF Infrastructure**: INFRA requirements, GHA policy alignment
- **ASF Security**: VULN requirements, disclosure process
- **ASF Legal**: LIC requirements, license compatibility rules
- **PMC chairs**: AUTH requirements, committer/PMC authorization patterns

Draft the initial spec based on existing ASF policy documents, then iterate through community review.

## Estimated Effort

| Task | Effort | Dependencies |
|---|---|---|
| Draft requirements (from ASF policy docs) | 2 days | Community input |
| Write ingest script | Half day | Draft requirements |
| Implement static checks (no-LLM fast path) | 2 days | [Phase 0](../multi-spec-architecture.md) |
| Write audit prompts for LLM-required checks | 1 day | Draft requirements |
| Community review and iteration | 2 weeks | Draft complete |
| Integrate with discovery agent | Half day | [Phase 0](../multi-spec-architecture.md) |
| **Total (engineering)** | **~6 days** | |
| **Total (with review)** | **~3 weeks** | |