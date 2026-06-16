# CWE Top 25 Integration

## Overview

The [CWE/SANS Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/) covers vulnerability classes that affect all software, not just web applications. It's the primary gap-filler for libraries, backend services, and any project where ASVS has limited coverage.

## The 25 Requirements + On the Cusp

The [CWE Top 25](https://cwe.mitre.org/top25/) is the primary list. The [On the Cusp](https://cwe.mitre.org/top25/archive/2025/2025_onthecusp_list.html) list (ranks 26–40) adds weaknesses that nearly made the cut. Rankings shift year to year — a few CWEs appear in both the 2024 Top 25 and the 2025 On the Cusp as the lists evolve.

| Rank | CWE | Name | List | ASVS Overlap | Unique Value |
|---|---|---|---|---|---|
| 1 | CWE-79 | Cross-site Scripting | Top 25 | 1.2.x, 5.1.x | — (ASVS covers well) |
| 2 | CWE-787 | Out-of-bounds Write | Top 25 | None | Memory safety — C/C++ buffer overflows |
| 3 | CWE-89 | SQL Injection | Top 25 | 1.2.x, 1.3.x | — (ASVS covers well) |
| 4 | CWE-352 | Cross-Site Request Forgery | Top 25 | 3.5.x | — (ASVS covers well) |
| 5 | CWE-22 | Path Traversal | Top 25 | 1.4.x (partial) | Non-web path traversal (CLI tools, libraries) |
| 6 | CWE-125 | Out-of-bounds Read | Top 25 | None | Memory read overflows, info leaks — C/C++ |
| 7 | CWE-78 | OS Command Injection | Top 25 | 1.2.x (partial) | Non-web command injection (scripts, backend) |
| 8 | CWE-416 | Use After Free | Top 25 | None | Memory safety — C/C++ only |
| 9 | CWE-862 | Missing Authorization | Top 25 | 4.x, 10.x | API-level object authorization (overlaps API Top 10) |
| 10 | CWE-434 | Unrestricted Upload | Top 25 | 1.4.x | — (ASVS covers well) |
| 11 | CWE-94 | Code Injection | Top 25 | 1.2.x (partial) | Template injection, eval-based injection |
| 12 | CWE-20 | Improper Input Validation | Top 25 | 1.x (broad) | Generic validation — ASVS is more specific |
| 13 | CWE-77 | Command Injection | Top 25 | 1.2.x (partial) | Argument injection vs shell injection distinction |
| 14 | CWE-287 | Improper Authentication | Top 25 | 2.x, 7.x | — (ASVS covers well) |
| 15 | CWE-269 | Improper Privilege Management | Top 25 | 4.x, 10.x | Privilege escalation patterns |
| 16 | CWE-502 | Deserialization | Top 25 | 1.x (minimal) | Java/Python deserialization gadgets |
| 17 | CWE-200 | Exposure of Sensitive Info | Top 25 | 8.x, 17.x | Broader than ASVS — any info leak channel |
| 18 | CWE-863 | Incorrect Authorization | Top 25 | 4.x, 10.x | Subtle authz logic bugs vs missing authz |
| 19 | CWE-918 | Server-Side Request Forgery | Top 25 | 1.x (partial) | SSRF in non-web contexts (internal services) |
| 20 | CWE-119 | Buffer Overflow (generic) | Top 25 | None | Parent class of CWE-787/125 — C/C++ |
| 21 | CWE-476 | NULL Pointer Dereference | Top 25 | None | Availability impact — C/C++, Rust (unsafe) |
| 22 | CWE-190 | Integer Overflow | Top 25 | None | Arithmetic overflow — C/C++, Java (partial) |
| 23 | CWE-362 | Race Condition | Top 25 | None | TOCTOU, concurrent state — all languages |
| 24 | CWE-306 | Missing Authentication | Top 25 | 2.x | — (ASVS covers well) |
| 25 | CWE-295 | Improper Certificate Validation | Top 25 | 12.x | TLS certificate pinning, chain validation |
| 26 | CWE-266 | Incorrect Privilege Assignment | On the Cusp | 4.x (partial) | Multi-role apps (Steve, Airflow) |
| 27 | CWE-276 | Incorrect Default Permissions | On the Cusp | None | File/config permission handling |
| 28 | CWE-288 | Auth Bypass via Alternate Path | On the Cusp | 2.x (partial) | 6 CVEs in CISA KEV — high real-world impact |
| 29 | CWE-400 | Uncontrolled Resource Consumption | On the Cusp | 2.4.x (partial) | DoS via APIs, unbounded queries, memory exhaustion |
| 30 | CWE-798 | Use of Hard-coded Credentials | On the Cusp | 6.x | All projects — secrets in source |
| 31 | CWE-401 | Memory Leak | On the Cusp | None | C/C++ libraries (trending upward) |
| 32 | CWE-601 | Open Redirect | On the Cusp | 1.x (partial) | Web apps — redirect-based phishing |

Note: A few On the Cusp CWEs omitted — PHP-specific or overlap with existing Top 25 entries. CWE-269, CWE-287, CWE-190, and CWE-362 appear in both the 2024 Top 25 and 2025 On the Cusp due to year-over-year ranking shifts; they're listed under Top 25 above.

Of the Top 25, roughly 10 have strong ASVS overlap (web-focused CWEs), 7 have partial overlap, and 8 have no ASVS coverage at all (memory safety, race conditions, integer overflow). The On the Cusp entries add coverage for privilege assignment, resource exhaustion, and auth bypass patterns that ASVS touches only lightly.

The consolidator deduplicates overlapping entries using `cross_references` — when ASVS 1.2.1 and CWE-79 flag the same XSS issue, they merge into a single finding.

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
| Memory leak | CWE-401 (On the Cusp) |
| Resource exhaustion | CWE-400 (On the Cusp) |
| Hard-coded credentials | CWE-798 (On the Cusp) |

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

CWE entries don't have ASVS-style levels. Map using the ranking from the combined table above:

| Level | CWE Rank | Count | Rationale |
|---|---|---|---|
| L1 | 1–10 (Top 25) | 10 | Most dangerous, always audit |
| L2 | 11–20 (Top 25) | 10 | Important, audit for mature projects |
| L3 | 21–25 (Top 25) | 5 | Complete Top 25 coverage |
| L3+ | 26–32 (On the Cusp) | 7 | Extended coverage for high-assurance projects |

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
| Write ingest script for CWE data (Top 25 + On the Cusp) | 1 day | None |
| Build cross-reference mapping (CWE ↔ ASVS) | 1 day | Ingest script |
| Adapt audit prompt template for CWE format | Half day | None |
| Add language filtering to discovery agent | Half day | [Phase 0](../multi-spec-architecture.md) |
| Update consolidator for cross-spec dedup | 1 day | [Phase 0](../multi-spec-architecture.md) |
| Test with library fixture | 1 day | Eval framework |
| **Total** | **~5 days** | |