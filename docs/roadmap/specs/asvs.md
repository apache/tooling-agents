# OWASP ASVS v5.0.0

**Status: Implemented and in production.**

This is the founding spec of the pipeline. All other specs build on the architecture established here.

## Overview

The [OWASP Application Security Verification Standard v5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) defines 345 security requirements across 17 chapters, organized into three levels of increasing rigor. It's designed for web applications with HTTP endpoints, authentication, session management, and user-facing interfaces.

See [ASVS Applicability](../asvs-applicability.md) for where this spec fits well and where it doesn't.

## Implementation

| Component | Status |
|---|---|
| Requirements in data store | ✅ `asvs` namespace, 345 entries |
| Ingest script | ✅ `ingest_asvs_standard` |
| Audit prompt | ✅ In `run_asvs_security_audit` |
| Discovery integration | ✅ Domain mapping by ASVS chapter |
| Consolidation | ✅ Dedup within and across domains |
| Level filtering (L1/L2/L3) | ✅ Orchestrator `level` input |
| Severity threshold | ✅ Orchestrator `severityThreshold` input |
| Audit guidance | ✅ Per-project false positive reduction |
| Pipeline documentation | ✅ [ASVS/README.md](../../../ASVS/README.md) |
| QA tooling | ✅ `rerun-sections.sh` |

## Data Store Schema

```
Namespace: asvs
Key: asvs:requirements:6.1.1

{
  "id": "6.1.1",
  "title": "Password Security",
  "description": "Verify that user-set passwords are at least 8 characters in length...",
  "level": 1,
  "chapter": 6,
  "section_name": "Credential & Secret Management",
  "spec": "asvs",
  "spec_version": "5.0.0"
}
```

## Coverage by Level

| Level | Requirements | Scope |
|---|---|---|
| L1 | 70 | Critical baseline — highest priority requirements |
| L2 | 183 | Standard security — defenses against common threats |
| L3 | 92 | Advanced — complete coverage for high-value targets |
| **Total** | **345** | |

## Production Runs

| Project | Commit | Level | Sections | Findings | Report |
|---|---|---|---|---|---|
| ATR | da901ba | L1+L2 | 253 | 137 consolidated | [consolidated-L1-L2.md](../../../ASVS/reports/tooling-trusted-releases/da901ba/consolidated-L1-L2.md) |
| Steve v3 | d0aa7e9 | L3 | 340/345 | 235 consolidated | [consolidated.md](../../../ASVS/reports/steve/v3/d0aa7e9/consolidated.md) |

## Cross-References

When additional specs are added, ASVS requirements will gain `cross_references` fields mapping to equivalent requirements in other specs:

```json
{
  "id": "1.2.1",
  "cross_references": {
    "cwe-top-25": ["CWE-79"],
    "api-top-10": ["API3"]
  }
}
```

This enables the consolidator to merge findings that flag the same vulnerability from multiple specs.

## Lessons Learned

Building the pipeline against ASVS taught us what the multi-spec architecture needs:

1. **Discovery is essential.** Without architecture-aware domain scoping, the LLM wastes tokens analyzing irrelevant files and produces more false positives.

2. **Audit guidance reduces noise.** LLMs consistently misinterpret certain patterns (reverse proxy auth, framework-specific session handling). Per-project guidance documents and inline `# audit_guidance` comments fix this.

3. **"Not applicable" is a valid result.** Many ASVS sections don't apply to a given codebase. The audit agent needs to say so cleanly instead of hallucinating findings.

4. **Extraction is fragile.** Reports with extensive code blocks cause Sonnet to return malformed JSON or echo report content instead of extracting findings. Anchored regex, balanced brace parsing, and `ast.literal_eval` fallbacks handle most cases. Very large reports occasionally still fail — the consolidated report now links to the raw per-section report when extraction fails.

5. **Consolidation at scale needs batching.** Domain groups with 25+ reports need sub-batching to avoid timeouts. Issue formatting needs batches of ~40 findings to avoid token limit truncation.

These lessons directly informed the [multi-spec architecture](../multi-spec-architecture.md) design.