# Security Tooling Landscape

Research and evaluation of automated security tooling for open source projects. This directory tracks tools we've evaluated, how they compare to what we've built, and where they complement each other.

## Our Tools

We maintain two pipelines, both running on the [Gofannon](../gofannon/) agent platform:

**ASVS Security Audit Pipeline** ([ASVS/](../../ASVS/)) — LLM-driven code analysis against OWASP ASVS v5.0.0 requirements. Uses architecture-aware domain scoping to audit 345 requirements across 3 levels. Produces per-requirement reports, consolidated findings, and GitHub issues. In production, piloted on ATR and Apache Steve.

**GitHub Actions Security Review** ([gha-review/](../../gha-review/)) — Automated analysis of GHA workflows across an entire GitHub organization. Combines LLM classification (which repos publish what, where) with static pattern matching (12 check types from CRITICAL to INFO). Scanned 2,500+ Apache repos, found 22 CRITICAL findings across publishing pipelines. Six agents: pre-fetch, publishing, security, review, brief, JSON export.

## External Tools

### Code and Application Security

| | **OpenSSF Scorecard** | **OSS-CRS** | **Strix** | **Brief** | **Scrutineer** |
|---|---|---|---|---|---|
| **What it does** | Scores project security posture (practices, not code) | Autonomous bug-finding and patching via fuzzing + LLM | AI pentest agents that exploit and validate vulns with PoCs | Detects project toolchain, config, and conventions | Automated penetration testing with modular LLM skills |
| **Approach** | 20+ automated heuristic checks | Cyber Reasoning Systems: fuzz → find → confirm → patch | Multi-agent exploitation: recon, browser, proxy, terminal, code analysis | Single-binary CLI, static file detection, structured JSON/markdown output | Containerized Go tool, skill-based testing via LLM |
| **What it finds** | Missing branch protection, no SAST, unpinned deps, no SECURITY.md | Memory safety bugs, crashes, confirmed with PoV + patches | XSS, IDOR, SQLi, CSRF, auth bypass — validated with proof-of-concept | Languages, frameworks, package managers, CI config, conventions | TBD |
| **Language support** | Language-agnostic (checks practices, not code) | C, C++, Java (OSS-Fuzz format required) | Any (runs apps dynamically in Docker sandbox) | 35+ package managers, any language | TBD |
| **LLM usage** | None | Optional: LLM-augmented fuzz harness generation | Core: LLM plans and drives attack tools | None | Core: LLM skills for analysis |
| **Maturity** | Mature, widely adopted | Sandbox stage at OpenSSF (Apr 2026) | Active, 20k+ stars, 319 commits | Early (26 commits, 1 star) | Very early (2 commits) |
| **Origin** | OpenSSF / Google | DARPA AIxCC → OpenSSF | usestrix (Apache-2.0) | git-pkgs | Alpha-Omega |
| **URL** | [scorecard.dev](https://scorecard.dev) | [ossf/oss-crs](https://github.com/ossf/oss-crs) | [usestrix/strix](https://github.com/usestrix/strix) | [git-pkgs/brief](https://github.com/git-pkgs/brief) | [alpha-omega-security/scrutineer](https://github.com/alpha-omega-security/scrutineer) |

### CI/CD and Workflow Security

| | **Our GHA Review Pipeline** | **ASF infrastructure-actions** | **zizmor** |
|---|---|---|---|
| **What it does** | Org-wide GHA security audit: finds exploitable workflows across all repos | Allowlist governance: controls which external actions ASF projects can use | Per-repo static analysis of workflow YAML for security issues |
| **Scope** | All repos in a GitHub org (scanned 2,500+ Apache repos) | All apache/* repos (policy enforcement) | Single repo or directory of workflows |
| **What it finds** | `pull_request_target` + checkout exploits, unpinned actions, broad permissions, supply chain risks (12 check types) | N/A — it's a gate, not a scanner. `utils/action-usage.sh` checks if an action is still used org-wide | Injection via `${{ }}` interpolation, unpinned actions, excessive permissions, cache poisoning, known vulnerable actions |
| **Approach** | LLM classification (publishing analysis) + static pattern matching (security scan), org-wide | Curated allowlist (`actions.yml`) with security review for each action/version. Dependabot updates pinned SHAs | Rust-based static analysis of workflow YAML, SARIF output for GitHub code scanning |
| **LLM usage** | Yes (Sonnet for publishing classification) | None | None |
| **Output** | Executive brief, combined review, per-repo security findings, JSON export | Allowlist config, action usage reports | SARIF findings, annotations, human-readable reports |
| **Maturity** | In production | In production (ASF Infra) | Mature, adopted by Grafana Labs and others at scale |
| **URL** | [gha-review/](../../gha-review/) | [apache/infrastructure-actions](https://github.com/apache/infrastructure-actions) | [docs.zizmor.sh](https://docs.zizmor.sh) |

## How They Relate to What We Built

**Scorecard** checks whether you have good security practices (branch protection, dependency management, SAST enabled) but never reads your code. Complementary to our ASVS pipeline, which does the opposite: deep code analysis against a formal standard. We ran Scorecard on ATR and scored 6.2/10 — the findings (missing SAST, branch protection gaps) were entirely disjoint from what our ASVS audit found (missing rate limiting, session fixation, weak crypto).

**OSS-CRS** finds memory safety bugs through fuzzing and generates patches. Completely different class of vulnerability from what ASVS covers. Requires OSS-Fuzz-compatible build configuration, so it's limited to projects already set up for fuzzing. The 20-40% semantically incorrect patch rate underscores the need for human review.

**Strix** is the closest analog to our ASVS pipeline in terms of ambition — it also uses LLMs to find security issues in application code. But the approach is fundamentally different: Strix acts as a pentester (running code, probing endpoints, exploiting vulns) while our pipeline acts as an auditor (reading code against a compliance standard). Strix finds exploitable runtime vulnerabilities with PoCs; our pipeline finds architectural gaps and missing controls against ASVS requirements. Both are valuable, and they'd find different things on the same codebase.

**Brief** is interesting as a potential complement to our `discover_codebase_architecture` agent. Brief does static project structure detection (languages, frameworks, package managers, CI config) as a fast Go binary. Our discover agent uses an LLM to map code into ASVS-relevant security domains. Brief could provide the initial inventory that the LLM then reasons about, potentially reducing token usage and improving accuracy.

**Scrutineer** is early but likely headed toward automated pentesting, similar to Strix. The Alpha-Omega team's focus is finding real vulnerabilities in critical OSS projects, and the repo structure (Go binary, modular skills, Docker runner) suggests a tool for active security testing rather than static analysis. Worth monitoring — Alpha-Omega has the funding and OSS relationships to make this impactful.

**Our GHA review pipeline** is unique among these tools — none of the others analyze CI/CD workflow security at the organization level. It complements two tools already in use at ASF:

**ASF infrastructure-actions** is the governance layer: it maintains an allowlist of approved actions and requires security review before any external action can be used. `utils/action-usage.sh` checks whether an action is still used anywhere across the org. This is policy enforcement — it controls what _can_ run but doesn't audit what _is_ running. Our GHA review pipeline fills that gap by scanning all 2,500+ repos to find exploitable patterns in the workflows themselves.

**zizmor** is the per-repo static scanner recommended by ASF Infra. It's excellent for individual repos — it finds injection via `${{ }}` interpolation, unpinned actions, cache poisoning, and known vulnerable actions, and outputs SARIF for GitHub code scanning. Our pipeline operates at a different level: org-wide risk assessment, cross-referencing security findings with publishing analysis to identify which vulnerable repos actually push packages to public registries. zizmor tells you "this workflow has an injection"; our pipeline tells you "this repo publishes to PyPI AND has a CRITICAL injection — this is your P0."

## Evaluation Results

| Tool | Project | Date | Report location |
|------|---------|------|-----------------|
| Scorecard | ATR | Jan 2026 | [tooling-runbooks ASVS/archived](https://github.com/apache/tooling-runbooks) (private) |
| ASVS Pipeline (L1+L2) | ATR (da901ba) | Mar 2026 | [ASVS/reports/tooling-trusted-releases/da901ba/](../../ASVS/reports/tooling-trusted-releases/da901ba/) |
| ASVS Pipeline (L3) | Steve v3 (d0aa7e9) | Apr 2026 | [ASVS/reports/steve/v3/d0aa7e9/](../../ASVS/reports/steve/v3/d0aa7e9/) |
| GHA Review | Apache org | Apr 2026 | [gha-review/reports/](../../gha-review/reports/) |

## Links

- [OWASP ASVS v5.0.0 PDF](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf)
- [OpenSSF Scorecard documentation](https://github.com/ossf/scorecard)
- [OSS-CRS paper](https://arxiv.org/abs/2603.08566)
- [Strix documentation](https://docs.strix.ai)
- [Brief / git-pkgs](https://git-pkgs.dev)
- [Alpha-Omega project](https://alpha-omega.dev)
- [OpenSSF Security Baseline (OSPS)](https://baseline.openssf.org/)
- [zizmor documentation](https://docs.zizmor.sh)
- [ASF GitHub Actions Policy](https://infra.apache.org/github-actions-policy.html)
- [ASF GitHub Actions Security Guide](https://cwiki.apache.org/confluence/display/BUILDS/GitHub+Actions+Security)