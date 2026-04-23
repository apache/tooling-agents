# Security Pipeline Roadmap

Planning documents for the security audit pipeline — where it's headed, how we'll get there, and how we'll know it's working.

For the current pipeline and how to use it, see the [ASVS pipeline documentation](../../ASVS/README.md). For a comparison of external tools in this space, see [tooling](../tooling/).

## Contents

### [ASVS Applicability](asvs-applicability.md)

Where ASVS fits (web apps like ATR and Steve) and where it doesn't (libraries, backend services, infrastructure). Includes a chapter-by-chapter breakdown of applicability by project type, alternative standards for non-web projects, and guidance on how to frame the pipeline when offering it to ASF projects.

### [Eval Framework](eval-framework.md)

Test harness design for measuring pipeline quality and operating at scale. Covers fixtures (known codebases with known vulns), metrics (recall, precision, false positive rate), LLM-as-judge for semantic comparison, auto-filed GitHub issues for novel errors, and operational dashboards. The ATR da901ba L1+L2 run serves as the regression baseline.

### [Multi-Spec Architecture](multi-spec-architecture.md)

Implementation plan for Phase 0: renaming the pipeline from ASVS to security, making agents spec-agnostic, adding the `spec` input parameter, data store schema per spec, spec selection modes, cross-spec deduplication, and migration path. This is the prerequisite for all spec additions below.

### Multi-Spec Expansion

The pipeline currently audits against OWASP ASVS only. These plans extend it to additional security specifications, with automatic spec selection based on project type.

| Phase | Spec | Best For | Effort | Plan |
|---|---|---|---|---|
| **Done** | [OWASP ASVS v5.0.0](specs/asvs.md) | Web applications | Complete | In production — ATR and Steve audited |
| **0** | [Rename ASVS → security](multi-spec-architecture.md) | All | 4 days | Agent renames, `spec` input, cross-spec dedup |
| **1** | [CWE Top 25](specs/cwe-top-25.md) | Libraries, any code | ~5 days | Memory safety, injection, race conditions |
| **1** | [OWASP API Top 10](specs/api-top-10.md) | API-heavy projects | ~2.5 days | IDOR, mass assignment, rate limiting |
| **2** | [ASF Security Baseline](specs/asf-baseline.md) | All ASF projects | ~6 days + review | Release signing, license compliance, ASF auth patterns |
| **2** | [SLSA Build Levels](specs/slsa.md) | Publishing projects | ~6 days | Provenance, reproducibility, artifact signing |
| **3** | Community-contributed | Any | Ongoing | Load requirements into data store, no code changes |

After [Phase 0](multi-spec-architecture.md), adding a new spec requires no agent code changes — just requirements in the data store, an optional prompt template, and an update to the discovery agent's project type mapping.

### How Specs Combine

The discovery agent classifies the project and recommends specs:

| Project Type | Recommended Specs |
|---|---|
| Web app (ATR, Steve, Superset) | ASVS + API Top 10 + ASF Baseline |
| Library (Commons, Arrow, Parquet) | CWE Top 25 + ASF Baseline |
| API service (Solr, CouchDB) | ASVS + API Top 10 + CWE Top 25 + ASF Baseline |
| Publishing project (Kafka, Airflow) | All of the above + SLSA |

The consolidator deduplicates across specs using cross-references — when ASVS 1.2.1 and CWE-79 flag the same XSS issue, the consolidated report merges them and notes both specs.