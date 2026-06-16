# OWASP WSTG Integration

## Overview

The [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) is a methodology document covering 125 web application security tests across 12 categories. Unlike ASVS (which states what requirements an app must meet) or CWE Top 25 (which catalogues weakness classes), WSTG describes *how to test* for issues — its content is framed for testers running probes against a deployed application.

That framing creates an architectural mismatch with the static-review pipeline: a meaningful portion of WSTG entries fundamentally need a live target. The implementation in [wstg/](wstg/) handles this by tagging each entry with a `static_review_applicable` flag — 115 of 125 entries translate cleanly to source-code review; the remaining 10 stay in the catalog for a future runtime/DAST audit agent but are excluded from the static pipeline.

WSTG complements ASVS rather than replacing it. ASVS is the verification list; WSTG is the methodology for finding violations. For most web apps, the recommendation is to run both — ASVS as primary, WSTG as a supplement for business-logic and client-side coverage where ASVS is thin.

## Status

Spec data is built and ready to ingest. Pipeline integration (orchestrator `specs` input, discovery agent recommendation, audit prompt adaptation) is pending [Phase 0](../multi-spec-architecture.md).

| Component | Status |
|---|---|
| Catalog of 125 tests with metadata | ✅ [wstg/wstg_catalog.py](wstg/wstg_catalog.py) |
| Build script producing namespace JSON | ✅ [wstg/build_spec.py](wstg/build_spec.py) |
| Generated dataset (full, 125) | ✅ [wstg/out/wstg-spec.json](wstg/out/wstg-spec.json) |
| Generated dataset (static-only, 115) | ✅ [wstg/out/wstg-spec-static.json](wstg/out/wstg-spec-static.json) |
| Curated cross-references to ASVS / CWE / API Top 10 | ✅ 39 mappings |
| Ingest script | Pending — straightforward `for entry in json: spec_ns.set(...)` loop |
| Audit prompt adaptation | Pending |
| Discovery agent recommendation logic | Pending |

## Coverage

| | |
|---|---|
| Total tests | 125 |
| Static-review applicable | 115 |
| Runtime-only (excluded from static audit) | 10 |
| With curated cross-references | 39 |

By level:

| Level | Count | Rationale |
|---|---|---|
| L1 | 41 | Baseline — every web app should pass: injection, XSS, basic authz, error handling, CSRF, session cookie attributes, TLS, common headers |
| L2 | 66 | Standard — apps with auth/sessions/sensitive data: MFA, OAuth, JWT, CORS, advanced authz, business logic |
| L3 | 18 | Advanced — niche or specialist scenarios: MS Access SQLi, padding oracle, session puzzling, RIA cross-domain, payment-specific logic |

By category (all 12 WSTG sections preserved):

| Category | Tests |
|---|---|
| Input validation | 30 |
| Client-side | 16 |
| Configuration and deployment management | 14 |
| Authentication | 11 |
| Session management | 11 |
| Business logic | 10 |
| Information gathering | 10 |
| Authorization | 7 |
| API | 5 |
| Identity management | 5 |
| Cryptography | 4 |
| Error handling | 2 |

## Static vs Runtime Split

The `static_review_applicable` flag is the architectural mitigation for the testing-methodology-vs-static-review mismatch. The 10 entries currently filtered out:

| WSTG ID | Title | Why runtime-only |
|---|---|---|
| WSTG-INFO-01 | Conduct Search Engine Discovery Reconnaissance | Search engine probing |
| WSTG-INFO-02 | Fingerprint Web Server | Live server banner inspection |
| WSTG-INFO-08 | Fingerprint Web Application Framework | Live framework probing |
| WSTG-INFO-09 | Fingerprint Web Application | Live application probing |
| WSTG-CONF-01 | Test Network Infrastructure Configuration | Network-level scanning |
| WSTG-CONF-10 | Test for Subdomain Takeover | DNS reconnaissance |
| WSTG-CONF-11 | Test Cloud Storage | Live S3/GCS endpoint probing |
| WSTG-ATHN-03 | Testing for Weak Lock Out Mechanism | Actually trying to lock out accounts |
| WSTG-SESS-09 | Testing for Session Hijacking | Runtime token capture |
| WSTG-CRYP-01 | Testing for Weak Transport Layer Security | Live TLS handshake probing |

The static orchestrator should load `wstg-spec-static.json` (or filter on the flag at ingestion). The full `wstg-spec.json` remains useful as the source of truth for a future runtime audit agent.

## Data Store Schema

```
Namespace: wstg
Key: wstg:requirements:WSTG-INPV-05

{
  "id": "WSTG-INPV-05",
  "title": "Testing for SQL Injection",
  "description": "OWASP WSTG: Testing for SQL Injection. Full methodology at canonical_url.",
  "level": 1,
  "spec": "wstg",
  "spec_version": "latest",
  "category": "input validation",
  "languages": ["all"],
  "cross_references": {
    "asvs": ["5.3.4", "5.3.5"],
    "cwe-top-25": ["CWE-89"],
    "api-top-10": ["API8"]
  },
  "detection_methods": [
    "Find query construction with string interpolation/concatenation. Flag .format/f-strings/% with user input, raw cursor.execute, ORM raw()."
  ],
  "static_review_applicable": true,
  "canonical_url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
  "source_url": "https://github.com/OWASP/www-project-web-security-testing-guide/blob/master/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md",
  "section_path": "4.7.5"
}
```

WSTG-specific fields beyond the base schema (additive — won't break existing consumers):

| Field | Purpose |
|---|---|
| `static_review_applicable` | Filter for static pipeline. False for the 10 runtime-only entries. |
| `parent_id` | Set on sub-tests like `WSTG-INPV-05.1` (Oracle SQLi variant). |
| `canonical_url` | OWASP page — where the audit agent should fetch full guidance. |
| `source_url` | GitHub markdown source. |
| `section_path` | Original numeric path: `4.7.5` or `4.7.5.1`. |

The `description` field is a one-line pointer, not the full methodology. The audit agent should fetch `canonical_url` for detailed guidance. A `--enrich` build flag could pre-fetch and inline the Summary + How-to-Test sections, at the cost of ~10× namespace bloat. Left optional.

## ID Derivation

WSTG IDs are deterministic from the section number — confirmed by the `WSTG-INPV-05` ID rendered on the SQL Injection page (section 4.7.5). The catalog uses this without per-page lookup:

```
section "4.X.Y"   →  "WSTG-{PREFIX}-{Y:02d}"
section "4.X.Y.Z" →  "WSTG-{PREFIX}-{Y:02d}.{Z}"
```

Section prefixes (stable across WSTG versions):

| Section | Prefix | Section | Prefix |
|---|---|---|---|
| 4.1 Information Gathering | INFO | 4.7 Input Validation | INPV |
| 4.2 Configuration | CONF | 4.8 Error Handling | ERRH |
| 4.3 Identity Management | IDNT | 4.9 Cryptography | CRYP |
| 4.4 Authentication | ATHN | 4.10 Business Logic | BUSL |
| 4.5 Authorization | ATHZ | 4.11 Client-side | CLNT |
| 4.6 Session Management | SESS | 4.12 API | APIT |

## Cross-References

Curated mapping covering 39 of 125 entries. Strategy: include only where the WSTG test and the foreign-spec requirement describe the same vulnerability with no scope mismatch.

| Foreign spec | Mapped entries | Notes |
|---|---|---|
| ASVS v5.0 | ~35 | Highest overlap — injection, XSS, IDOR, SSRF, JWT, CSRF, session, crypto |
| CWE Top 25 (2024) | ~15 | Direct CWE matches for the most common WSTG findings |
| API Top 10 (2023) | ~8 | Authorization, mass assignment, SSRF, security misconfig |

Why this isn't exhaustive: the WSTG `latest/` tree dropped the v4.x cross-reference appendix; OWASP maintains a separate WSTG↔ASVS mapping project but it lags behind. The `CROSS_REFERENCES` dict in [wstg/wstg_catalog.py](wstg/wstg_catalog.py) is hand-curated for the high-confidence pairs.

Missing entries don't break the consolidator — they just mean WSTG and ASVS findings on those entries won't auto-merge. After a few end-to-end runs, look at the consolidator's "potential dedup candidates" output and add high-confidence pairs back to the catalog.

## Cross-Reference Deduplication

When `wstg` runs alongside `asvs` (the common case), the consolidator merges findings on the same file/line where cross-references match:

```python
# WSTG-INPV-05 cross_references: {"asvs": ["5.3.4", "5.3.5"], ...}
# ASVS 5.3.4   cross_references: {"wstg": ["WSTG-INPV-05"], ...}
#
# → Merge into single finding:
#   "Specs violated: ASVS 5.3.4, WSTG-INPV-05"
```

WSTG findings often have more methodology-flavored language ("test for X by sending Y"). For source-code findings the ASVS phrasing is usually clearer; the consolidator should prefer ASVS as the primary citation when both fire on the same finding, and list WSTG as a secondary reference. This is the inverse of the API Top 10 dedup rule (which prefers API3 over ASVS for object property authorization).

## Discovery Agent Changes

WSTG is web-app-specific. Suggested addition to the discovery agent's default mapping:

| Project type | Recommend WSTG? | Coverage |
|---|---|---|
| `web_app` | ✅ Yes | `supplement` — methodology depth beyond ASVS verification, especially business logic and client-side |
| `library` | ❌ No | Web-only |
| `cli_tool` | ❌ No | Web-only |
| `backend_service` | ⚠️ Conditional | If HTTP endpoints exposed: API + auth + session subset |
| `build_tool` | ❌ No | Web-only |

The discovery agent should also surface a level recommendation. For most ASF web apps, L1+L2 is the right starting point (107 tests). L3 adds 18 specialist tests that produce noise on most projects.

## Audit Prompt

The WSTG audit prompt differs from the ASVS prompt in two ways: it pulls full methodology from `canonical_url` at audit time (the namespace entry only carries a one-line description), and it explicitly translates the "test for" framing into "find this in code":

```
You are a security auditor analyzing source code against WSTG test {wstg_id}: {title}.

Methodology (fetched from canonical_url):
{full_wstg_page_content}

The WSTG describes how to TEST for this issue against a running application.
Your job is to translate that into a SOURCE CODE REVIEW: identify code patterns
in the provided files that would make the application vulnerable to the test
described above.

Detection focus (catalog hints):
{detection_methods}

For each instance found:
1. Identify the specific code location (file, function, line)
2. Explain the vulnerability with reference to the WSTG methodology
3. Assess severity (Critical/High/Medium/Low)
4. Provide remediation specific to the framework in use

If this WSTG test is not applicable to the codebase as static review
(e.g., requires runtime probing only), state "Not applicable for static review"
with a brief explanation.
```

The "translate testing methodology into static review" instruction is the key prompt-engineering piece. Without it, the model produces findings phrased as test plans ("send a request with payload X") rather than code-level findings.

## Versioning Caveat

`spec_version: "latest"` because that's literally the source — the WSTG `latest/` tree gets edited continuously and OWASP doesn't tag stable releases for it. For reproducible audits, replace `"latest"` with a Git commit SHA from the OWASP repo and have `build_spec.py` accept it as a flag. Without pinning, a finding could appear or disappear between runs because OWASP edited the test page. Recommended before promoting WSTG audits to the same standing as ASVS audits.

## Estimated Effort

Spec data is done. Remaining work to wire WSTG into the live pipeline:

| Task | Effort | Dependencies |
|---|---|---|
| Catalog of 125 tests with metadata | ✅ Done | — |
| Build script + JSON datasets | ✅ Done | — |
| Curated cross-references (high-confidence subset) | ✅ Done | — |
| Write ingest script (load JSON into `wstg` namespace) | Half day | None |
| Adapt audit prompt template (testing-methodology translation) | 1 day | None |
| Add WSTG recommendation to discovery agent | Half day | [Phase 0](../multi-spec-architecture.md) |
| Add WSTG↔ASVS dedup rules to consolidator | Half day | [Phase 0](../multi-spec-architecture.md) |
| Test against ATR or Steve | 1 day | All of the above |
| Pin `spec_version` to a commit SHA, expand cross-references from run output | Half day | First production run |
| **Remaining** | **~3.5 days** | |

Lower than CWE Top 25 (~5 days) or SLSA (~6 days) because the catalog and cross-references already exist; what's left is integration glue.
