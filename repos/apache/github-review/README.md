# GitHub Actions Security Review

Automated scan of GitHub Actions workflows across a GitHub organization to identify security vulnerabilities in CI/CD pipelines, classify publishing workflows, and flag ASF policy violations.

Built on [Gofannon](https://github.com/The-AI-Alliance/gofannon) — see [docs/gofannon](../docs/gofannon/) for platform setup.

## What It Does

The pipeline scans all `.github/` directories across an organization's repositories, caches the workflow YAML, and runs two analysis passes:

- **Publishing classification** — LLM-classifies each workflow as release, snapshot, CI, or docs
- **Security analysis** — pattern-matches 12 security checks against workflow YAML

The output is a set of reports covering the full organization, with findings at configurable severity levels and support for private/public split reporting (redact high-severity findings from public reports).

## Pipeline Flow

```
orchestrator
  │
  ├──▶ pre-fetch        (caches workflow YAML from GitHub API)
  │
  ├──▶ publishing       (LLM-classifies workflows)
  ├──▶ security         (pattern-matching security checks)
  │
  ├──▶ review           (combined risk assessment report)
  ├──▶ brief            (executive action plan)
  └──▶ json-export      (machine-readable structured export)
```

## Quick Start

Run the `orchestrator` agent with:

| Input | Value |
|---|---|
| `github_owner` | `apache` |
| `read_pat` | `ghp_...` |
| `write_private_repo` | `apache/tooling-agents-private` |
| `write_private_directory` | `gha-review` |
| `write_private_pat` | `ghp_...` |
| `write_public_repo` | `apache/tooling-agents` |
| `write_public_directory` | `gha-review/reports` |
| `write_public_pat` | `ghp_...` |

The orchestrator runs three phases automatically: prefetch (GitHub API), private reports (full findings), public reports (redacted).

## Reports

| Report | Format | Description |
|---|---|---|
| `review.md` | Markdown | Combined risk assessment with per-repo breakdown |
| `brief.md` | Markdown | One-page executive action plan |
| `security.md` | Markdown | Detailed security findings |
| `publishing.md` | Markdown | Workflow classification results |
| `json-export.json` | JSON | Machine-readable structured export |

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