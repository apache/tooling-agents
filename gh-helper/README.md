# GitHub Issue Triage Agent (gofannon)

A gofannon agent that reads open issues for any GitHub repository, builds a structured understanding of the codebase, and posts per-issue triage comments that cite real code with line ranges and propose grounded patches.

This is the **read-and-comment** iteration. The next iteration will open PRs.

## What it does

For each repo (cached per HEAD SHA, run once and shared across all issues):

1. **Downloads the repo as a tarball** and caches files in `data_store`. Re-runs at the same SHA skip the download.
2. **Architecture discovery** — one Sonnet call produces a structured codebase map: framework, language, purpose, auth systems, API layers, data layer, execution model, key subsystems, trust model.
3. **Domain partitioning** — one Sonnet call groups the codebase into 4–12 named application areas (e.g., `vote_management`, `release_lifecycle`). Each file lands in exactly one domain.
4. **File inventory** — Sonnet, batched, builds a per-file structured catalog: purpose, public API with line ranges, concerns. Cache namespace `audit-cache:inventory:{file-set-hash}` is shared with `asvs_audit`, so a repo already audited gets free hits here, and vice versa.
5. **Open-PR scan** — one `/search/issues` call enumerates open PRs and parses titles + bodies for close-keywords (`fixes #N`, `closes #N`, `resolves #N`). Builds a map of issues that already have someone working on them.
6. **Issue clustering** — one LLM call groups open issues into duplicate/related clusters. Cached by issue-corpus content.

Then for each issue:

1. **Sentinel and PR-link checks** — skip issues already triaged by this agent, or skip with classification `pr_in_progress` if a PR is linked.
2. **Domain classification** — one Haiku call routes the issue to 1–3 application domains. Narrows the relevance-search to those domains.
3. **Relevance scoring** — Haiku, batched, scores files against the issue using *inventory entries* (not raw previews). Returns 0–10 per file. Top-K (default 8) selected with threshold ≥4, falling back to ≥2 if too few clear the bar.
4. **Deep analysis** — Opus, with the full structured context: architecture object, domain context, inventory entries for the picked files, full source of those files. Produces a structured JSON triage with classification, summary, existing-code citations (path + symbol + line range + verbatim snippet + role), new-code locations, approach, diffs, and open questions.
5. **Comment** — renders all of the above as a markdown comment. Posts to GitHub (or returns the draft if `dry_run` is true).
6. **Label** — applies the configured label to the issue (creates the label in the repo on first run if missing).

Each comment is tagged with `<!-- gofannon-issue-triage-bot v2 -->` so subsequent runs can skip already-triaged issues.

## Setup

### 1. Create the agent in gofannon

Create a new agent in the gofannon UI with name `read_and_triage` (or similar). Paste `issue_triage_agent.py` into the **Code** field.

### 2. GitHub token

You need a fine-grained Personal Access Token with **Issues: Read & Write** on the target repo (or org-wide). Read-only is not enough — the agent posts comments and applies labels.

### 3. Invokable models (Bedrock)

The v2 pipeline uses three model tiers. Add all three to the agent's **Invokable Models**:

| Tier | Model string | Used for |
|---|---|---|
| Opus | `us.anthropic.claude-opus-4-6-v1` | Deep analysis (per issue) |
| Sonnet | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | Architecture, domains, inventory (one-time per SHA) |
| Haiku | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | Relevance scoring, issue clustering, domain classification |

If you only have Haiku registered, you can run the whole thing on Haiku by overriding `model_name` and `discovery_model` in the input — quality drops noticeably for deep analysis but cost is minimal. Useful for first-pass testing.

### 4. Input schema

Paste this as the **Input Schema**:

```json
{
  "repo": "string",
  "github_token": "string",
  "model_provider": "string",
  "model_name": "string",
  "relevance_provider": "string",
  "relevance_model": "string",
  "discovery_provider": "string",
  "discovery_model": "string",
  "dry_run": "boolean",
  "max_issues": "integer",
  "issue_numbers": "list",
  "max_files_per_issue": "integer",
  "skip_already_triaged": "boolean",
  "branch": "string",
  "force_redownload": "boolean",
  "assignee": "string",
  "skip_when_pr_open": "boolean",
  "detect_related_issues": "boolean",
  "label": "string"
}
```

### 5. Output schema

Paste this as the **Output Schema**:

```json
{
  "outputText": "string",
  "repo": "string",
  "branch": "string",
  "head_sha": "string",
  "issues_processed": "integer",
  "issues_commented": "integer",
  "issues_skipped": "integer",
  "errors": "list",
  "results": "list"
}
```

### 6. Data stores

Declare these in the agent's **Data Stores** field (optional but recommended — it gives the data-store viewer attribution):

| Namespace | Contents |
|---|---|
| `files:{repo}` | full source files at the canonical snapshot |
| `meta:{repo}` | `head_sha` and `file_count` for the freshness check |
| `discovery:{repo}@{sha7}` | architecture object and domains object |
| `audit-cache:inventory:{file-set-hash}` | per-file structured inventory; shared with asvs_audit |
| `triage-cache:domain:{repo}@{sha7}` | per-issue domain classification |
| `triage-cache:relevance:{repo}@{sha7}` | per-issue relevance scores |
| `triage-cache:related:{repo}` | issue-clustering result keyed by corpus hash |

The `files:{repo}` and `audit-cache:inventory:*` namespaces match what the ASVS pipeline produces, so cross-pipeline cache hits work in both directions.

## Inputs reference

| Input | Required | Default | What it does |
|---|---|---|---|
| `repo` | yes | — | `owner/name`, e.g. `apache/tooling-trusted-releases` |
| `github_token` | yes | — | PAT with Issues: Read & Write |
| `model_provider` | no | `bedrock` | provider for deep analysis |
| `model_name` | no | `us.anthropic.claude-opus-4-6-v1` | model for deep analysis (Opus tier) |
| `relevance_provider` | no | `bedrock` | provider for relevance, clustering, domain classification |
| `relevance_model` | no | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | model for those three cheap-batch passes (Haiku tier) |
| `discovery_provider` | no | `bedrock` | provider for architecture, domain partitioning, file inventory |
| `discovery_model` | no | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | model for the one-time-per-SHA structural passes (Sonnet tier) |
| `dry_run` | no | `false` | if true, runs the full pipeline but posts zero comments and applies zero labels; comment text appears in `results[].comment_body` for inspection |
| `max_issues` | no | `0` | cap on issues processed; `0` = no cap. Applied after PR-filtering and `issue_numbers` |
| `issue_numbers` | no | `[]` | restrict to specific issue numbers; `[]` = all |
| `max_files_per_issue` | no | `8` | cap on files passed to deep analysis (cost control on the Opus prompt) |
| `skip_already_triaged` | no | `true` | skip issues that already contain the v2 sentinel; set false to re-comment |
| `branch` | no | `""` | branch to read code from; empty string = repo default |
| `force_redownload` | no | `false` | bypass the SHA freshness check and re-fetch the tarball |
| `assignee` | no | `""` | filter to issues assigned to this GitHub username; `*` = any assignee, `none` = unassigned only, empty = no filter |
| `skip_when_pr_open` | no | `true` | skip issues with open PRs that close-keyword-link them; classification `pr_in_progress` |
| `detect_related_issues` | no | `true` | run the cross-issue clustering pass; false saves one LLM call per corpus |
| `label` | no | `gh-helper` | label applied to every examined issue; created in the repo if missing; empty disables labeling |

## Outputs reference

The agent returns a structured dict matching the output schema. Key fields:

- `outputText` — short prose summary suitable for the gofannon UI
- `repo`, `branch`, `head_sha` — what was analyzed
- `issues_processed` — how many issues entered the per-issue loop
- `issues_commented` — how many comments were actually posted
- `issues_skipped` — sentinel-skipped + pr_in_progress combined
- `errors` — list of `{issue_number, error}` for issues that hit an exception
- `results` — list, one entry per processed issue. Each entry:

| Field | Type | Notes |
|---|---|---|
| `number` | int | issue number |
| `title` | string | issue title |
| `classification` | string | one of `actionable`, `no_action`, `unrelated`, `skipped`, `pr_in_progress`, `error` |
| `summary` | string | the agent's understanding of the issue, or skip-reason text |
| `files_examined` | list of string | repo-relative paths the deep-analysis pass saw |
| `comment_body` | string | full markdown of the comment, posted or not |
| `comment_url` | string | GitHub permalink to the posted comment, empty if not posted |
| `posted` | bool | whether the comment was actually POSTed |
| `linked_prs` | list of int | open PR numbers close-keyword-linked to this issue |
| `related_issues` | list of int | other issue numbers in the same duplicate/related cluster |

## Comment format

Triage comments include these sections:

- **Type / Classification / Confidence** — bug_fix / new_feature / refactor / documentation / question / discussion / unrelated / unclear; classification of actionable / no_action / unrelated; confidence high/medium/low
- **Application domain(s)** — which area(s) of the codebase
- **Summary** — what the issue asks, what was found
- **Where this lives in the code today** — for each cited piece of existing code: file path, symbol name, line range, role (currently does this / needs modification / extension point), explanation, and a verbatim code snippet
- **Where new code would go** (only for new-feature issues) — file + anchor + rationale
- **Proposed approach** — paragraph
- **Suggested patches** — diffs anchored to real files
- **Open questions** — things the agent does not understand
- **Files examined** — full list
- **Related issues** — cross-references when applicable

## Why this architecture

A naive design would send the full code base as a single prompt. Most repos are too large for that; even after filtering, the contents would be many millions of tokens. The pipeline instead:

1. **Tarball download** — one HTTP call per repo per SHA (~1MB compressed). Replaces N `contents/{path}` calls. SHA-tagged so re-runs skip the download.
2. **Architecture + domains + inventory** — three structural passes that build the agent's mental model. Cached per SHA. The next iteration's audit on the same repo gets free inventory hits.
3. **Per-issue: domain classification → scoped relevance → deep analysis with cited grounding**. Each pass uses a model tier appropriate for its job (Haiku for cheap-batch, Sonnet for structural, Opus for deep reasoning).

The cost shape: discovery is roughly 1–3 minutes per SHA on first encounter, then zero. Per-issue cost on the same SHA is dominated by the Opus deep-analysis call. Re-runs at the same SHA on already-triaged issues are essentially free thanks to the sentinel.

## Operational notes

- **Filtering noise.** If your repo has paths that should never be analyzed (generated SBOMs, build artifacts), add them to the `SKIP_DIRS`, `SKIP_FILES`, or `SKIP_EXTENSIONS` sets near the top of `run()`. The current lists are lifted from the ASVS pipeline.
- **Issue volume.** The agent processes issues serially in Phase 1. ~30 issues at full pipeline cost is roughly 10–15 minutes wall-clock with Opus deep analysis. The cross-issue passes (PR scan, clustering) are one-time per run regardless of issue count.
- **Sentinel bumping.** v1 → v2 means existing v1 comments do NOT block re-triage. If you want to keep v1 comments and only triage new issues, set `skip_already_triaged: false` once, eyeball the v2 output in dry-run, then re-enable.
- **Cache invalidation.** Bumping the HEAD SHA invalidates everything cleanly. To force a fresh discovery without bumping the SHA (e.g., to test a prompt tweak), pass `force_redownload: true` — discovery and inventory will then re-run because they look for cache by SHA.
- **Per-user runs.** Pass `assignee` with a GitHub username to triage only that user's assigned issues. Combine with `dry_run: true` for a personal sanity check before the bot posts anywhere.

## Roadmap

This is **Phase 1** of three.

**Phase 2 — multi-agent split.** Refactor into four agents wired through the data store:
- `download_repo` — drop-in reuse of `asvs_download_repo`
- `discover_architecture` — adapted from `asvs_discover` (architecture + domains + inventory)
- `triage_issue` — per-issue analyzer; pure function over data store, returns structured triage
- `triage_orchestrator` — user-facing entry point; does GitHub I/O, fans out triage_issue calls under a semaphore for parallelism

The orchestrator's input/output schemas remain compatible with this Phase 1 agent so it's a drop-in upgrade. The split exists for failure isolation, faster iteration on individual stages, and reusability of the discovery/inventory primitives across other agents.

**Phase 3 — PR-writer.** A separate agent that:
1. Reads comments left by this triage pipeline (filtering by sentinel)
2. Parses the structured triage payload to recover `existing_code` citations and `diffs`
3. Creates a feature branch, applies the diffs (with retry-on-409 / fresh-SHA refetch like `asvs_push_github`)
4. Opens a draft PR linking back to the triage comment

The v2 comment format (with verbatim snippets and structured citations) is designed to make Phase 3's pickup straightforward — the PR-writer can match snippets against current source to determine where each diff applies.