# GitHub Actions Security Review

Automated scan of GitHub Actions workflows across a GitHub organization to identify security vulnerabilities in CI/CD pipelines, classify publishing workflows, verify published artifacts, and flag ASF policy violations.

Built on [Gofannon](https://github.com/The-AI-Alliance/gofannon) — see [docs/gofannon](../docs/gofannon/) for platform setup.

## What It Does

The pipeline scans all `.github/` directories across an organization's repositories, caches the workflow YAML, and runs four analysis passes:

- **Publishing classification** — LLM-classifies each workflow as release, snapshot, CI, or docs
- **Security analysis** — pattern-matches 12 security checks against workflow YAML
- **Publishing detail** — parses cached YAML for action SHAs, secrets, target URLs; calls GitHub API for run history; generates per-channel reports and dangerous-patterns analysis
- **Artifact verification** — queries package registry APIs (PyPI, npm, Maven Central, Docker Hub, crates.io) to confirm what's actually published and feeds an Apache Trusted Releases catalog

## Pipeline

```
gha_orchestrator
  │
  ├──▸ gha_prefetch              (caches workflow YAML from GitHub API)
  │
  ├──▸ gha_publishing            (LLM-classifies workflows)
  ├──▸ gha_security              (pattern-matching security checks)
  │
  ├──▸ gha_publishing_detail     (YAML parsing + GitHub API run history)
  ├──▸ gha_artifact_verify       (registry API queries + ATR catalog)
  │
  ├──▸ gha_review                (combined risk assessment report)
  ├──▸ gha_brief                 (executive action plan)
  └──▸ gha_json_export           (machine-readable structured export)
```

## Quick Start

Run the `gha_orchestrator` agent with:

| Input | Value |
|---|---|
| `github_owner` | `apache` |
| `read_pat` | `ghp_...` (read access to org repos) |
| `write_repo` | `apache/tooling-agents-private` |
| `write_directory` | `gha-review` |
| `write_pat` | `ghp_...` (write access to write_repo) |

The orchestrator runs two phases: prefetch (GitHub API), then all analysis agents with reports pushed to the target repo as each completes.

## Reports

| Report | Format | Source Agent | Description |
|---|---|---|---|
| `gha_brief.md` | Markdown | gha_brief | One-page executive action plan |
| `gha_review.md` | Markdown | gha_review | Combined risk assessment with per-repo breakdown |
| `gha_publishing.md` | Markdown | gha_publishing | Workflow classification results |
| `gha_security.md` | Markdown | gha_security | Detailed security findings |
| `gha_publishing_detail.md` | Markdown | gha_publishing_detail | Enriched analysis: secrets, action SHAs, triggers, run history |
| `gha_publishing_risks.md` | Markdown | gha_publishing_detail | Dangerous patterns analysis |
| `gha_channel_pypi.md` | Markdown | gha_publishing_detail | Per-channel detail (one per active channel) |
| `gha_channel_npm.md` | Markdown | gha_publishing_detail | |
| `gha_channel_maven_central.md` | Markdown | gha_publishing_detail | |
| `gha_channel_docker_hub.md` | Markdown | gha_publishing_detail | |
| ...× N channels | Markdown | gha_publishing_detail | |
| `gha_artifact_verification.md` | Markdown | gha_artifact_verify | Registry cross-reference: verified, phantom, orphaned |
| `gha_atr_catalog.json` | JSON | gha_artifact_verify | Apache Trusted Releases feed |
| `gha_json_export.json` | JSON | gha_json_export | Machine-readable structured export |

## Security Checks

12 checks covering the most common GitHub Actions attack patterns:

| Check | Severity | What It Detects |
|---|---|---|
| `prt_checkout` | CRITICAL–INFO | `pull_request_target` + checkout of PR head |
| `self_hosted_runner` | HIGH–INFO | Self-hosted runners exposed to PR triggers |
| `run_block_injection` | LOW–CRITICAL | `${{ }}` interpolation in run blocks |
| `unpinned_actions` | MEDIUM | Third-party actions referenced by mutable tags |
| `broad_permissions` | LOW–HIGH | GITHUB_TOKEN with excessive scopes |
| `missing_codeowners` | LOW | No CODEOWNERS file |
| `missing_dependency_updates` | LOW | No dependabot.yml or renovate.json |
| `composite_action_unpinned` | MEDIUM | Unpinned actions in composites |
| `composite_action_input_injection` | MEDIUM | Input interpolation in composites |
| `composite_action_injection` | LOW | Interpolation in composite run blocks |
| `cache_poisoning` | INFO | `actions/cache` with PR trigger |
| `third_party_actions` | INFO | Actions outside trusted namespaces |

See [agents/README.md](agents/README.md) for severity matrices, caching details, ASF policy integration, and the full agent reference.