# Security Audit Tooling

This page provides an overview of the goals, tooling, and current state of security audit automation for ATR.

- [Motivation](#motivation)
- [Current state](#current-state)
- [Approaches](#approaches)
- [Phases](#phases)

## Motivation

Apache Trusted Releases (ATR) is a release management tool for verifying and distributing Apache releases securely. As such there is a need for all code, configuration, and workflows in ATR to comply with high standards for security. The Tooling team have adopted the [Application Security Verification Standard (ASVS) v5.0.0](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) from the [Open Worldwide Application Security Project (OWASP)](https://owasp.org) as our standard.

The ASVS defines three levels of security verification, with L1 comprising the highest priority and most critical requirements, L2 including defenses against less common threats, and L3 rounding out the highest level of compliance. Requirements in L1 are about 20% of the spec, in L2 about 50%, and in L3 about 30%. For the beta release of ATR in early 2026 the target is to fulfill all requirements in L1 and the bulk of L2, noting that some of the requirements will need infrastructure changes, so compliance with those is out of Tooling's control.

To accelerate this goal the Tooling team is running an internal pilot of automated code auditing, to work through the requirements while maintaining momentum on ATR feature development.

## Current state

### What has been built

A complete ASVS security audit pipeline using Gofannon, consisting of 9 agents that automate the end-to-end process of analyzing ATR source code against individual ASVS requirements. The pipeline uses Claude Sonnet for high-throughput parallel work (relevance filtering, code inventory, formatting, extraction, consolidation) and Claude Opus for deep security analysis where reasoning quality matters most.

The pipeline agents, their code, prompts, and operational runbook are in [`repos/tooling-trusted-releases/ASVS/`](../../repos/tooling-trusted-releases/ASVS/).

The core pipeline flow:

1. **Data setup** — ASVS requirements ingested from the v5.0.0 spec into CouchDB. Source code from ATR and its dependencies (asfquart, asfpy) downloaded into the same store, along with relevant `infrastructure-p6` configs, open Issues, and `audit_guidance` documentation.
2. **Per-requirement audit** — for each ASVS requirement, an audit agent reads the codebase, filters for relevant files , builds a code inventory, runs deep analysis, and produces a structured markdown report.
3. **Orchestration** — an orchestrator loops over comma-separated sections, runs the audit for each, and pushes individual reports to GitHub.
4. **Consolidation** — a consolidation agent reads all individual reports from one or more ASVS level directories, extracts and deduplicates findings, and produces a consolidated report with an issues file.

### What has been run

Audit runs completed against ATR at a few snapshots, latest is commit `da901ba`:

- **L1 run**: 70 ASVS requirements covering the highest-priority security controls
- **L2 run**: 183 ASVS requirements covering the broader L2 defenses

Individual reports are pushed to GitHub organized by commit hash and ASVS level. Consolidated reports and issues files are generated at the parent level. See [`repos/tooling-trusted-releases/ASVS/reports/`](../../repos/tooling-trusted-releases/ASVS/reports/) for report structure.

### Results and ground truth

ATR has [137 filed GitHub issues](https://github.com/apache/tooling-trusted-releases/issues?q=is%3Aissue%20label%3AASVS) from this security review. The pipeline's consolidated reports identify findings across all severity levels with deduplication tracking which ASVS sections and levels flagged each issue. So far about [thirty issues](https://github.com/apache/tooling-trusted-releases/issues?q=is%3Aissue%20label%3AASVS%20label%3Allm) were directly fed back into this audit system with linter-style `audit_guidance` inline comments as well as overall guidance in separate files to filter out false positive results.

### Key technical decisions

- **Opus tuning**: `reasoning_effort=medium`, `max_tokens=64000` — reduced from `high`/`128000` after analysis showed failures correlated with batch count (each call at high reasoning took 20-30 min, increasing Bedrock disconnect probability)
- **Context loading**: local data store reads for code, config, audit_guidance, and open Issues
- **Inventory capping**: always limited to 15% of safe Opus context limit to prevent excessive batch counts
- **Retry logic**: 3 retries on Opus (15s/30s/45s backoff), 2 retries on all Sonnet calls

## Approaches

- ASVS-oriented automated auditing as standalone tool — **implemented** (see [pipeline runbook](../../repos/tooling-trusted-releases/ASVS/))
- Page on ATR for audit suites including ASVS compliance
- GitHub Action (audit on demand/commit, reporting, etc.) for ASF projects

## Phases

### Research

- Initial requirements and assessment for ASVS compliance
- Tool evaluation (Scorecard, VEX, Gofannon)
- Identified gaps: no existing tool covers deep ASVS-per-requirement code analysis

### Initial build

- Built 9-agent pipeline on Gofannon with CouchDB persistence
- Tuned Opus analysis parameters for Bedrock reliability
- Multi-level consolidation with deduplication and level tracking
- ✅ L1 run (~70 sections) against ATR codebase
- ✅ L2 run (~183 sections) against ATR codebase
- ✅ Consolidated report and issues file generation

### Next steps

- Pipeline piloted with other ASF projects
- Interactive triage
  - Marking issues with triage decision
  - Auto-filed Issues to GitHub
  - Automatic PR generation
- CI/CD integration for commit and PR security reviews
