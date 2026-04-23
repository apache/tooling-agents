# CWE Top 25 Integration

## Overview

The [CWE/SANS Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/) covers vulnerability classes that affect all software, not just web applications. It's the primary gap-filler for libraries, backend services, and any project where ASVS has limited coverage.

## Why CWE Top 25

| What ASVS misses | CWE that covers it |
|---|---|
| Buffer overflow | CWE-787 (Out-of-bounds Write), CWE-125 (Out-of-bounds Read) |
| Use-after-free | CWE-416 |
| Integer overflow | CWE-190 |
| Race conditions | CWE-362 |
| NULL pointer dereference | CWE-476 |
| Deserialization | CWE-502 |
| Command injection (non-web) | CWE-78 |
| Path traversal (non-web) | CWE-22 |

ASVS and CWE Top 25 overlap on web-specific issues (XSS → CWE-79, SQLi → CWE-89). The consolidator deduplicates these using `cross_references`.

## Requirements

The CWE Top 25 (2024 edition) contains 25 entries. Each maps to a CWE ID with a description, extended description, common consequences, and detection methods.

### Data Store Schema

```
Namespace: cwe-top-25
Key: cwe-top-25:requirements:CWE-79

{
  "id": "CWE-79",
  "title": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
  "description": "The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
  "level": 1,
  "category": "injection",
  "languages": ["all"],
  "detection_methods": [
    "Automated Static Analysis",
    "Manual Review",
    "Dynamic Analysis"
  ],
  "common_consequences": ["confidentiality", "integrity", "availability"],
  "spec": "cwe-top-25",
  "spec_version": "2024",
  "cross_references": {
    "asvs": ["1.2.1", "1.2.2", "1.2.3", "5.1.1"]
  }
}
```

### Level Mapping

CWE entries don't have ASVS-style levels. Map using the CWE Top 25 ranking:

| Level | CWE Rank | Count | Rationale |
|---|---|---|---|
| L1 | 1–10 | 10 | Most dangerous, always audit |
| L2 | 11–20 | 10 | Important, audit for mature projects |
| L3 | 21–25 | 5 | Complete coverage |

### Language Filtering

Some CWEs are language-specific. The discovery agent's language detection determines which CWEs to include:

| CWE | Languages | Skip for |
|---|---|---|
| CWE-787 (Out-of-bounds Write) | C, C++, Rust (unsafe) | Python, Java, Go, JS |
| CWE-416 (Use After Free) | C, C++ | All managed languages |
| CWE-190 (Integer Overflow) | C, C++, Java (partially) | Python (arbitrary precision) |
| CWE-502 (Deserialization) | Java, Python, PHP, .NET | C, Rust |
| CWE-79 (XSS) | All with web output | Pure libraries without rendering |

## Ingest Script

```python
# ingest_cwe_top_25.py
#
# Fetches CWE Top 25 entries from cwe.mitre.org and loads into data store.
# Similar to ingest_asvs_standard but parses CWE XML/JSON format.

async def run(input_dict, tools):
    # 1. Fetch CWE Top 25 list from MITRE
    # 2. For each entry, fetch full CWE details
    # 3. Map to data store schema with cross-references to ASVS
    # 4. Store in cwe-top-25 namespace
    pass
```

## Audit Prompt Adaptation

The ASVS audit prompt references ASVS-specific concepts (sections, levels, compliance status). The CWE audit prompt focuses on vulnerability patterns:

```
You are a security auditor analyzing code for {cwe_id}: {cwe_title}.

{cwe_description}

Detection approach:
{detection_methods}

Analyze the provided source code for instances of this weakness. For each instance found:
1. Identify the specific code location (file, function, line)
2. Explain the vulnerability and how it could be exploited
3. Assess severity (Critical/High/Medium/Low) based on exploitability and impact
4. Provide specific remediation with corrected code

If this weakness is not applicable to the codebase (e.g., memory safety CWE in a Python project), state "Not applicable" with a brief explanation.
```

## Discovery Agent Changes

The discovery agent adds CWE-specific domain mapping:

```python
# For CWE Top 25, domains are organized by weakness category:
CWE_DOMAINS = {
    "injection": {
        "cwes": ["CWE-79", "CWE-89", "CWE-78", "CWE-77"],
        "description": "Input neutralization and injection prevention"
    },
    "memory_safety": {
        "cwes": ["CWE-787", "CWE-125", "CWE-416", "CWE-476", "CWE-190"],
        "description": "Memory management and bounds checking",
        "languages": ["c", "cpp"]
    },
    "auth_access": {
        "cwes": ["CWE-862", "CWE-863", "CWE-306", "CWE-798"],
        "description": "Authentication and authorization"
    },
    "data_handling": {
        "cwes": ["CWE-502", "CWE-434", "CWE-611", "CWE-918"],
        "description": "Serialization, file handling, SSRF"
    },
    "crypto_random": {
        "cwes": ["CWE-327", "CWE-330"],
        "description": "Cryptographic and randomness weaknesses"
    }
}
```

## Cross-Reference Deduplication

When both ASVS and CWE Top 25 are selected, the consolidator uses cross-references to merge findings:

```python
# During consolidation, if FINDING-A (from ASVS 1.2.1) and FINDING-B (from CWE-79)
# reference the same file and line, check cross_references:
#
# ASVS 1.2.1 cross_references: {"cwe-top-25": ["CWE-79"]}
# CWE-79 cross_references: {"asvs": ["1.2.1", "1.2.2", "1.2.3"]}
#
# → Merge into single finding, note both specs in the report:
#   "This finding violates ASVS 1.2.1 and CWE-79"
```

## Estimated Effort

| Task | Effort | Dependencies |
|---|---|---|
| Write ingest script for CWE data | 1 day | None |
| Build cross-reference mapping (CWE ↔ ASVS) | 1 day | Ingest script |
| Adapt audit prompt template for CWE format | Half day | None |
| Add language filtering to discovery agent | Half day | [Phase 0](../multi-spec-architecture.md) |
| Update consolidator for cross-spec dedup | 1 day | [Phase 0](../multi-spec-architecture.md) |
| Test with library fixture | 1 day | Eval framework |
| **Total** | **~5 days** | |