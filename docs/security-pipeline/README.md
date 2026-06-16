# Security Pipeline

The security audit pipeline ingests a codebase, assesses it, and triages
vulnerabilities using LLMs, producing consolidated findings and GitHub issues. It
began under ASF Security and scales with Tooling support, and relates to the
broader [Responsible AI Initiative](../rai/README.md).

This section is the pipeline's roadmap and reference: where it's headed, how it's
evaluated, and which security specifications it covers.

## Roadmap

### [ASVS applicability](asvs-applicability.md)

Where ASVS fits (web apps like ATR and Steve) and where it doesn't (libraries,
backend services, infrastructure) — a chapter-by-chapter breakdown by project
type, alternative standards for non-web projects, and how to frame the pipeline
when offering it to ASF projects.

### [Eval framework](eval-framework.md)

Test harness for measuring pipeline quality at scale: fixtures, metrics (recall,
precision, false positive rate), LLM-as-judge for semantic comparison, auto-filed
issues for novel errors, and operational dashboards. The ATR da901ba L1+L2 run is
the regression baseline.

### [Multi-spec architecture](multi-spec-architecture.md)

Implementation plan for making the pipeline spec-agnostic: the `spec` input
parameter, per-spec data store schema, spec selection modes, and cross-spec
deduplication. This is the prerequisite for every spec addition below.

## Spec coverage

The pipeline audits against a growing set of security specifications, with
automatic spec selection based on project type.

| Status | Spec | Best for |
|---|---|---|
| In production | [OWASP ASVS v5.0.0](specs/asvs.md) | Web applications |
| Planned | [CWE Top 25](specs/cwe-top-25.md) | Libraries, any code |
| Planned | [OWASP API Top 10](specs/api-top-10.md) | API-heavy projects |
| Planned | [ASF Security Baseline](specs/asf-baseline.md) | All ASF projects |
| Planned | [SLSA build levels](specs/slsa.md) | Publishing projects |
| Reference | [WSTG](specs/wstg.md) | Web security testing guide |

After the multi-spec work, adding a spec requires no agent code changes — just
requirements in the data store, an optional prompt template, and a discovery-agent
mapping update.

### [How tooling-agents complements ATR](specs/atr-integration.md)

How the portfolio — ASVS audit, GHA review, ASF Baseline, SLSA — fills gaps ATR
can't cover, and how ATR covers the distribution layer the pipeline doesn't: the
three-layer model of source/CI security, build integrity, and release
verification.

## Reference

- [Tooling landscape](tooling-landscape.md) — how the pipeline compares to and
  complements external tools (Scorecard, OSS-CRS, Strix, zizmor, and others).
