# GHA Review Agents

[Gofannon](https://github.com/The-AI-Alliance/gofannon) agents that scan a GitHub organization's Actions workflows to identify which repos publish packages to registries, verify what's actually published, and flag security risks in those pipelines.

Reports are documented separately — see the README bundled with each report run.

## Project Structure

```
├── gha_orchestrator.py        Runs full pipeline, pushes reports to GitHub
├── gha_prefetch.py            Caches workflow YAML + composite actions from GitHub
├── gha_publishing.py          LLM-classifies workflows (release, snapshot, CI, docs)
├── gha_security.py            Pattern-matching security checks on cached YAML
├── gha_publishing_detail.py   Enriched YAML parsing + GitHub API run history
├── gha_artifact_verify.py     Registry API queries + ATR catalog generation
├── gha_review.py              Combined risk assessment report (markdown)
├── gha_brief.py               One-page executive action plan (markdown)
├── gha_json_export.py         Machine-readable structured export (JSON)
├── README.md                  ← you are here
└── tests/
    ├── README.md              Test suite docs
    ├── security_checks.py     Extracted check functions (keep in sync with gha_security.py)
    ├── test_security_checks.py
    └── fixtures/
        ├── synthetic/         Minimal YAML snippets for each check pattern
        └── real-world/        Actual workflows, manually verified
```

## Architecture

Nine agents share data via CouchDB namespaces. All agents use flat string key-value `input_dict` pairs (no `inputText` wrapping). Only `gha_publishing` uses the LLM.

```
gha_orchestrator ── runs all agents below, pushes reports to GitHub
       │
gha_prefetch ────▸  ci-workflows:{owner}             (YAML cache + composites + extras)
       │
gha_publishing ──▸  ci-classification:{owner}         (LLM classifications)
       │             ci-report:{owner}                 (report + stats)
       │
gha_security ────▸  ci-security:{owner}               (findings + stats)
       │
gha_publishing_detail ▸  ci-publishing-detail:{owner}  (enriched data + per-channel reports)
       │
gha_artifact_verify ──▸  ci-artifact-verify:{owner}   (registry verification + ATR catalog)
       │
gha_review ──────▸  ci-combined:{owner}               (combined report)
       │
gha_brief ───────▸  ci-combined:{owner}               (executive brief)
       │
gha_json_export ─▸  ci-combined:{owner}               (JSON export)
```

**Dependency order:** gha_prefetch → gha_publishing + gha_security → gha_publishing_detail → gha_artifact_verify → gha_review + gha_brief + gha_json_export

Only gha_prefetch and gha_publishing_detail call the GitHub API. Only gha_artifact_verify calls external registry APIs. Only gha_publishing uses the LLM.

## How to Run

All agents run inside gofannon. Input fields are all type `"string"`. Agent names in gofannon match filenames without `.py`: `gha_prefetch`, `gha_publishing`, etc.

### Orchestrator (recommended)

The orchestrator runs the full pipeline and pushes reports to a GitHub repo:

```
gha_orchestrator    github_owner: apache
                    read_pat: ghp_...
                    write_repo: apache/tooling-agents-private
                    write_directory: gha-review
                    write_pat: ghp_...
                    skip_prefetch: false
```

This runs two phases:

```
Phase 1: Prefetch (caches workflow YAML from GitHub API)
         Skipped when skip_prefetch is true.

Phase 2: Analysis + Reports (8 agents in dependency order)
         ▸ gha_publishing             → gha_publishing.md
         ▸ gha_security               → gha_security.md
         ▸ gha_publishing_detail      → gha_publishing_detail.md
                                        gha_publishing_risks.md
                                        gha_channel_*.md (per channel)
         ▸ gha_artifact_verify        → gha_artifact_verification.md
                                        gha_atr_catalog.json
         ▸ gha_review                 → gha_review.md
         ▸ gha_brief                  → gha_brief.md
         ▸ gha_json_export            → gha_json_export.json
```

Each file is pushed to the target repo immediately after generation.

### Manual run

```
1. gha_prefetch              github_owner: apache    read_pat: ghp_...
2. gha_publishing            github_owner: apache
3. gha_security              github_owner: apache
4. gha_publishing_detail     github_owner: apache    read_pat: ghp_...
5. gha_artifact_verify       github_owner: apache
6. gha_review                github_owner: apache
7. gha_brief                 github_owner: apache
8. gha_json_export           github_owner: apache
```

Prefetch takes ~30–60 min for ~2,500 repos. Publishing takes hours (LLM calls). Security takes ~30–60 min. Publishing detail takes ~10–15 min (GitHub API for run history). Artifact verify takes ~5 min (registry API queries). Steps 6–8 take seconds each.

## Agent Reference

### Input Schemas

| Agent | Required Inputs | Optional Inputs |
|-------|----------------|-----------------|
| gha_prefetch | `github_owner`, `read_pat` | `rescan` |
| gha_publishing | `github_owner` | `redacted_severity` |
| gha_security | `github_owner` | `redacted_severity` |
| gha_publishing_detail | `github_owner`, `read_pat` | `repos`, `channels` |
| gha_artifact_verify | `github_owner` | `repos`, `channels` |
| gha_review | `github_owner` | `redacted_severity` |
| gha_brief | `github_owner` | `redacted_severity` |
| gha_json_export | `github_owner` | `redacted_severity` |
| gha_orchestrator | `github_owner`, `read_pat`, `write_repo`, `write_directory`, `write_pat` | `skip_prefetch` |

### Output Conventions

Most agents return `outputText` as a single markdown string. Two agents return multi-file JSON:

**gha_publishing_detail** and **gha_artifact_verify** return:

```json
{"files": {"publishing-detail.md": "...", "channel-pypi.md": "...", ...}}
```

The orchestrator's `push_multi_file_output()` parses this, adds a `gha_` prefix with underscore normalization to each filename, and pushes each file individually.

### LLM Usage

| Agent | LLM | Provider | Model | Params |
|-------|-----|----------|-------|--------|
| gha_publishing | Yes | `bedrock` | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | `temperature=0, reasoning_effort=disable, max_tokens=2048` |
| All others | No | — | — | — |

### CouchDB Namespaces

| Namespace | Writer | Readers |
|-----------|--------|---------|
| `ci-workflows:{owner}` | gha_prefetch | gha_publishing, gha_security, gha_publishing_detail, gha_artifact_verify |
| `ci-classification:{owner}` | gha_publishing | gha_publishing_detail, gha_json_export |
| `ci-report:{owner}` | gha_publishing | gha_review, gha_brief, gha_json_export |
| `ci-security:{owner}` | gha_security | gha_review, gha_brief, gha_json_export |
| `ci-publishing-detail:{owner}` | gha_publishing_detail | gha_artifact_verify |
| `ci-artifact-verify:{owner}` | gha_artifact_verify | — |
| `ci-combined:{owner}` | gha_review, gha_brief, gha_json_export | — |

### Framework Globals

Available to all agents without import:

| Global | Purpose |
|--------|---------|
| `data_store` | CouchDB access: `data_store.use_namespace(name)` → `.get()`, `.set()`, `.list_keys()` |
| `gofannon_client` | Call other agents: `gofannon_client.call(agent_name=, input_dict=)` |
| `count_tokens(text, provider, model)` | Token counting for context management |
| `get_context_window(provider, model)` | Get model's context window size |

### Push Utility

The orchestrator pushes files via `add_markdown_file_to_github_directory`, which uses a **different calling convention** from the analysis agents:

```python
gofannon_client.call(
    agent_name="add_markdown_file_to_github_directory",
    input_dict={
        "inputText": json.dumps({"repo": "...", "token": "...", "filePath": "..."}),
        "commitMessage": "...",
        "fileContents": "...",
    }
)
```

## rescan (prefetch only)

When `rescan: true`, prefetch ignores all cache keys and re-fetches everything from GitHub. When `false` (default), it skips repos that already have `__prefetch__`, `__composites__`, and `__extras__` cache keys — a fully cached repo costs zero API calls.

The orchestrator does not pass `rescan` to prefetch, so it always uses cache-skip mode. Run prefetch manually with `rescan: true` when you need a full refresh.

## redacted_severity

`redacted_severity` is accepted by gha_publishing, gha_security, gha_review, gha_brief, and gha_json_export. The orchestrator does not pass it — all reports are full/unredacted. It exists for manual runs where you want filtered output.

It works as a **threshold** — it removes findings at that severity **and above**:

- `redacted_severity: CRITICAL` → removes CRITICAL only
- `redacted_severity: HIGH` → removes HIGH and CRITICAL
- Empty (default) → all findings included

Every agent uses the same `is_severity_redacted(sev)` function that compares against `SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]`. When `redacted_severity` is set, agents skip CouchDB writes to preserve full data.

## Caching

All data persists in CouchDB across runs.

- **gha_prefetch** writes `__prefetch__:{repo}`, `__composites__:{repo}`, and `__extras__:{repo}` meta keys plus individual YAML content. Skips repos already cached unless `rescan: true`.
- **gha_publishing** writes `__meta__:{repo}` plus per-workflow classification keys. Skips workflows already classified.
- **gha_security** writes `findings:{repo}` per repo.

The `__extras__:{repo}` key stores two booleans — `has_codeowners` and `has_dependency_updates` — extracted from the repo's file tree during prefetch (zero extra API calls, reuses the tree response). The security agent reads these for `missing_codeowners` and `missing_dependency_updates` findings.

### Useful CouchDB queries

```bash
# Count docs by namespace
for ns in ci-workflows ci-classification ci-report ci-security \
          ci-publishing-detail ci-artifact-verify ci-combined; do
  count=$(curl -s "http://admin:password@localhost:5984/agent_data_store/_find" \
    -H "Content-Type: application/json" \
    -d "{\"selector\":{\"namespace\":\"${ns}:apache\"},\"fields\":[\"key\"],\"limit\":99999}" \
    | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('docs',[])))")
  echo "$ns: $count docs"
done
```

## ASF Policy Integration

The security checks incorporate guidance from three ASF sources:

- [GitHub Actions Security](https://cwiki.apache.org/confluence/display/BUILDS/GitHub+Actions+Security) — practical advice on dangerous workflows
- [GitHub Actions Policy](https://infra.apache.org/github-actions-policy.html) — formal rules (MUST/SHOULD requirements)
- [Automated Release Signing](https://infra.apache.org/release-signing.html#automated-release-signing) — CI signing key requirements

Two material policy integrations:

**ASF-exempt action namespaces.** ASF policy says actions in `actions/*`, `github/*`, and `apache/*` MAY be used without restrictions. The `ASF_EXEMPT_ORGS` constant excludes these from `unpinned_actions` and `composite_action_unpinned` checks — only third-party actions outside these namespaces are flagged. The broader `TRUSTED_ORGS` set (which also includes docker, gradle, pypa, etc.) is still used for the informational `third_party_actions` check.

**Mandatory dependency management.** ASF policy says "All repositories using GitHub Actions **must** have automatic dependency management." `missing_dependency_updates` is therefore LOW severity (policy violation), not just informational.

## Security Checks Reference

The security agent runs 12 checks. When adding a new check, also update `ATTACK_SCENARIOS` in `gha_review.py` and `check_definitions` in `gha_json_export.py`.

| Check | Severity | What It Detects |
|-------|----------|-----------------| 
| `prt_checkout` | CRITICAL–INFO | `pull_request_target` + checkout of PR head. Severity uses a 2×2 matrix (see below). |
| `self_hosted_runner` | HIGH–INFO | Self-hosted runners exposed to PR triggers. Severity uses same 2×2 matrix as prt_checkout. |
| `unpinned_actions` | MEDIUM | Third-party actions (outside `actions/*`, `github/*`, `apache/*`) referenced by mutable tags instead of SHA pins |
| `composite_action_unpinned` | MEDIUM | Third-party unpinned actions inside composite actions (same ASF exemption) |
| `composite_action_input_injection` | MEDIUM | Composite action interpolates `inputs.*` in run blocks — latent injection surface |
| `run_block_injection` | LOW–CRITICAL | `${{ }}` interpolation in run blocks. CRITICAL for `pull_request_target`, LOW for `pull_request`. |
| `composite_action_injection` | LOW | Interpolation in composite action run blocks |
| `broad_permissions` | LOW–HIGH | GITHUB_TOKEN with excessive scopes |
| `missing_codeowners` | LOW | No CODEOWNERS file |
| `missing_dependency_updates` | LOW | No dependabot.yml or renovate.json (ASF policy violation) |
| `cache_poisoning` | INFO | `actions/cache` with PR trigger |
| `third_party_actions` | INFO | Actions from outside `actions/*`, `github/*`, `apache/*` namespaces |

### Line numbers

Each finding includes a `line` field (integer, nullable) pointing to the relevant line in the workflow YAML. When deduplication collapses multiple findings, a `lines` list replaces the single `line` field. Repo-wide findings (`unpinned_actions`, `third_party_actions`, `missing_codeowners`, etc.) have `line: null`.

In the markdown security report, line numbers render as `filename:LINE` (e.g., `renovate-changelog.yml:47`).

In the JSON export, findings look like:

```json
{
  "severity": "CRITICAL",
  "check": "prt_checkout",
  "file": "renovate-changelog.yml",
  "detail": "pull_request_target trigger with checkout of PR head code...",
  "line": 47
}
```

### prt_checkout severity matrix

When `pull_request_target` checks out PR head code, severity depends on two factors:

|                        | Broad permissions | Limited permissions |
|------------------------|-------------------|---------------------|
| **Auto-trigger** (opened, synchronize) | **CRITICAL** | **MEDIUM** |
| **Maintainer-gated** (labeled, assigned) | **MEDIUM** | **LOW** |

- **Broad permissions**: no explicit `permissions:` block, or includes `contents: write`, `packages: write`, `id-token: write`, or `actions: write`
- **Limited permissions**: explicit `permissions:` block with only non-dangerous scopes (e.g., `pull-requests: write`)
- **Maintainer-gated**: all `pull_request_target` types are in `{labeled, unlabeled, assigned, unassigned, review_requested, review_request_removed}`
- Default checkout (no `ref:` parameter) → INFO (safe, checks out base branch)
- Explicit base ref checkout → INFO (safe)

### self_hosted_runner severity matrix

Same 2×2 as prt_checkout but with HIGH ceiling instead of CRITICAL:

|                        | Broad permissions | Limited permissions |
|------------------------|-------------------|---------------------|
| **Auto-trigger** (opened, synchronize) | **HIGH** | **MEDIUM** |
| **Maintainer-gated** (labeled, assigned) | **MEDIUM** | **LOW** |

No PR trigger → INFO (runners used for scheduled/manual workflows only).

### run_block_injection trigger awareness

Interpolation of PR-related values (`event.pull_request.title`, `.body`, `.head.ref`, etc.) in `run:` blocks:

- **`pull_request_target` trigger** → CRITICAL (fork PRs get base repo secrets)
- **`pull_request` trigger** → LOW (fork PRs do NOT get secrets)
- **No PR trigger** → CRITICAL (conservative default)

### ASF_EXEMPT_ORGS vs TRUSTED_ORGS

Two org sets serve different purposes:

- **`ASF_EXEMPT_ORGS`** = `{"actions", "github", "apache"}` — per ASF policy, actions in these namespaces need not be SHA-pinned. Used by `unpinned_actions` and `composite_action_unpinned`.
- **`TRUSTED_ORGS`** — broader set including docker, gradle, pypa, codecov, etc. Used only for the informational `third_party_actions` check (which flags actions outside this set for awareness, not as a policy violation).

## Adding a New Check

When you add a check to `gha_security.py`:

1. **Add the check function** — return `(severity, detail, line_num)` tuples. Use `enumerate(content.split("\n"), 1)` to track 1-indexed line numbers.
2. **Call it in the main scan loop** — capture the `line` field: `"line": result[2] if len(result) > 2 else None`
3. **Update `gha_review.py`**: add entry to `ATTACK_SCENARIOS` dict with label, severity, description, attack, and example
4. **Update `gha_json_export.py`**: add entry to `check_definitions` dict
5. **Update `tests/security_checks.py`**: add the function (note: test module still uses 2-tuples for backward compatibility)
6. **Update `tests/test_security_checks.py`**: add handler in `run_check()`, create fixtures, add test cases
7. **Run tests**: `python3 tests/test_security_checks.py`

## Test Suite

Run before deploying any security agent changes:

```bash
python3 tests/test_security_checks.py
```

19 tests covering the prt_checkout severity matrix, trigger-aware injection, self-hosted runners, cache poisoning, broad permissions, and three real-world regression cases (Beam, OpenDAL, Texera).

See `tests/README.md` for details on adding tests and fixtures.

## Limitations

- **LLM classification accuracy**: gha_publishing uses Sonnet to classify workflows. The `confidence` field in the JSON indicates certainty.
- **Static analysis only**: gha_security pattern-matches on YAML text. Does not resolve reusable workflow inputs, evaluate conditional expressions, or trace data flow across jobs.
- **Composite action nesting**: Only top-level `.github/actions/*/action.yml` are checked — composites calling other composites are not recursively analyzed.
- **No runtime verification**: Does not verify whether secrets are configured, branch protection rules exist, or GITHUB_TOKEN permissions are effective given org-level settings.
- **Org-level security models**: Some projects (e.g., Apache Beam) scope publishing secrets to manual/scheduled workflows only. The scanner cannot detect these policies and may overstate risk.
- **Conditional gates not evaluated**: Workflows with access control checks (e.g., `github.event.pull_request.user.login == 'renovate[bot]'`) are flagged based on the dangerous pattern even if the gate prevents exploitation. These appear as mitigated findings in the report.
- **Package name discovery**: gha_artifact_verify uses naming conventions and manifest files to guess package names. Repos with non-standard names may show as "phantom workflows" — the package exists but the name doesn't match.