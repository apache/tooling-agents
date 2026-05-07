# GitHub Issue Triage Agent (gofannon)

A gofannon agent that reads open issues for any GitHub repository, comprehends the code at HEAD, and posts a per-issue triage comment with either a draft fix (files + diffs) or an honest "no action" note.

This is the **read-and-comment** iteration. The next iteration will open PRs.

## What it does

For each open issue in the target repo:

1. **Downloads the repo as a tarball** at the current HEAD commit, on the first run only — re-runs at the same SHA skip the download. Files are cached in `data_store` and tagged with the source SHA.
2. **Scans open PRs** at the start of the run for close-keywords (`fixes #N`, `closes #N`, `resolves #N`) and builds a map of issues that already have someone working on them. One search query, regardless of issue count.
3. **Clusters open issues** in a single LLM call to find duplicates and related groups. Results cached by the issue corpus content, so re-runs with unchanged issues skip this call.
4. **Scores file relevance** for each non-skipped issue using a Haiku-class model against 200-line previews of every text file. Returns a 0–10 integer per file. Cached per issue per SHA.
5. **Reads the top-scoring files** (≥4, with fallback to ≥2 if fewer than 3 files clear the bar) into the deep-analysis pass.
6. **Classifies** the issue as one of:
   - `actionable` — understands the problem, can propose a concrete change. Posts a comment with summary, files examined, unified diffs, and any related-issue cross-references.
   - `no_action` — reviewed but cannot propose a concrete change.
   - `unrelated` — not about this repo's code/docs.
   - `pr_in_progress` — an open PR appears to address this issue (close-keyword link). Skips triage, but on a wet run still posts a small "see also #X" comment if the issue is part of a duplicate cluster and that cross-ref hasn't been posted yet.
   - `skipped` — already triaged by this agent (sentinel found). Same cross-ref posting rule as above.
7. **Posts the comment** (or returns the draft if `dry_run` is true).

Two sentinel markers track posted comments independently:
- `<!-- gofannon-issue-triage-bot v1 -->` for triage comments
- `<!-- gofannon-issue-triage-bot v1 related -->` for standalone "see also" cross-references on issues we don't actively triage

## Files in this bundle

- `issue_triage_agent.py` — the full agent. The `async def run(input_dict, tools)` function is at the top; module-level helpers follow.
- `README.md` — this file.

## Setup in gofannon

### 1. Create a new agent

In the gofannon webapp, create a new agent. The fastest path is to skip the composer entirely: create an empty agent and paste the contents of `issue_triage_agent.py` directly into the **Code** field. (The composer is for generating new agents from a description; you don't need it when you already have the code.)

### 2. Input schema

Paste this JSON into the **Input Schema** field:

```json
{
  "repo": "string",
  "github_token": "string",
  "model_provider": "string",
  "model_name": "string",
  "relevance_provider": "string",
  "relevance_model": "string",
  "dry_run": "boolean",
  "max_issues": "integer",
  "issue_numbers": "list",
  "max_files_per_issue": "integer",
  "skip_already_triaged": "boolean",
  "branch": "string",
  "force_redownload": "boolean",
  "skip_when_pr_open": "boolean",
  "detect_related_issues": "boolean"
}
```

| Field | Required | Default | Notes |
| --- | --- | --- | --- |
| `repo` | yes | — | `"owner/name"`, e.g. `"apache/tooling-trusted-releases"`. |
| `github_token` | yes | — | Personal access token; see scopes below. |
| `model_provider` | no | `"bedrock"` | Used for deep analysis. Must be one of your configured `invokable_models`. |
| `model_name` | no | `"us.anthropic.claude-opus-4-6-v1"` | Same. |
| `relevance_provider` | no | `""` (= same as `model_provider`) | Cheap-and-fast model for the relevance + clustering passes. Recommended: a Haiku-class model. |
| `relevance_model` | no | `""` (= same as `model_name`) | Same. |
| `dry_run` | no | `false` | If true, no comments are posted; the comment text appears in `results[].comment_body`. |
| `max_issues` | no | `0` (= no cap) | Useful for testing. |
| `issue_numbers` | no | `[]` (= all) | Restrict to specific issue numbers. |
| `max_files_per_issue` | no | `8` | Hard cap on files passed to deep analysis (cost control). |
| `skip_already_triaged` | no | `true` | Skip issues that already contain the triage sentinel marker. Set to `false` to re-comment. |
| `branch` | no | `""` (= default branch) | Branch to read code from. |
| `force_redownload` | no | `false` | Force a fresh tarball fetch even if the stored SHA matches HEAD. |
| `skip_when_pr_open` | no | `true` | Skip triage on issues that have an open PR with `fixes/closes/resolves #N`. Set to `false` to triage anyway (e.g., to second-guess a stalled PR). |
| `detect_related_issues` | no | `true` | Run a single LLM call to cluster open issues into duplicate/related groups. Set to `false` to skip the extra call. |

### 3. Output schema

Paste this JSON into the **Output Schema** field:

```json
{
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

Each entry in `results` is a dict with keys: `number`, `title`, `classification`, `summary`, `files_examined`, `comment_body`, `comment_url`, `posted`, `linked_prs`, `related_issues`. The last two are new in Phase 1: `linked_prs` lists open PR numbers that close-keyword-link to this issue (empty if none); `related_issues` lists other open issue numbers in the same duplicate/related cluster (empty if none).

### 4. Invokable models

Add at least Opus and Haiku to **Invokable Models**. The defaults assume Bedrock:

- **Bedrock** `us.anthropic.claude-opus-4-6-v1` (Opus, deep analysis)
- **Bedrock** `us.anthropic.claude-haiku-4-5-20251001-v1:0` (Haiku, relevance scoring + clustering)

For the cost win, also add a Haiku-class model and set `relevance_provider`/`relevance_model` in the input. Recommended:

(Already covered above — both are required for the default config.)

The relevance pass runs against 200-line previews of every text file in the repo. With Opus alone, that's expensive on large repos. With Haiku for relevance and Opus for deep analysis, the per-issue cost drops by roughly 5–10×. Without setting these fields the agent falls back to using the primary model for relevance — works fine, just costs more.

For each model, set `temperature` to `0.1`–`0.3` or omit (the agent passes appropriate values per stage).

**LLM call counts per issue:**
- 1 call to deep analysis (Opus)
- 1+ batch calls to relevance scoring (Haiku) — usually 1 batch for repos under ~150 source files; 2-3 batches for ATR-sized repos. Cached after the first run of an issue.

For ~30 open issues on a fresh ATR run: roughly 30 Opus calls + 30–60 Haiku calls. On re-runs at the same SHA, just the Opus calls (relevance is cached).

### 5. Composer model

The composer model config is what gofannon uses if you ever ask it to regenerate the code from a description. It's not used at runtime. Set it to whatever you want — it doesn't affect this agent.

### 6. Data store

The agent uses four namespaces, all keyed by repo:

- `files:owner/name` — full source files at the current snapshot. One canonical entry per repo, replaced when HEAD moves.
- `meta:owner/name` — metadata sidecar with `head_sha` and `file_count`. The freshness check on every run compares stored `head_sha` to the live HEAD; if they match, the tarball download is skipped.
- `triage-cache:relevance:owner/name@<sha7>` — per-issue relevance scores at a specific SHA.
- `triage-cache:related:owner/name` — duplicate/related issue clusters, keyed by a stable hash of the open-issue corpus. Invalidates automatically when any issue body changes or new issues appear.

You don't need to declare these in the data-store config UI — the agent creates them on demand. Declaring them is helpful so the data-store viewer knows which agent owns them.

These namespaces are **compatible with the ASVS pipeline**: `files:owner/name` matches what `asvs_download_repo` produces, so a repo already downloaded by ASVS will have a cache hit here without re-downloading.

## GitHub token scopes

The token needs:

- **Issues:** Read & Write (to list issues and post comments)
- **Contents:** Read (to fetch the tree and file contents)
- **Metadata:** Read (granted automatically with any other permission)

A **fine-grained PAT** is the safest choice — scope it to just the target repo. A classic PAT works too if you give it `repo` (which is broader than needed).

For the apache/tooling-trusted-releases test, a contributor would need to have appropriate access to that repo or fork it first.

## Running it (example: ATR)

To run a **safe dry-run** against the ATR repo, processing only issue numbers you want to inspect:

```json
{
  "repo": "apache/tooling-trusted-releases",
  "github_token": "github_pat_...",
  "dry_run": true,
  "max_issues": 3,
  "model_provider": "bedrock",
  "model_name": "us.anthropic.claude-opus-4-6-v1"
}
```

Read the `results[].comment_body` to see what the agent would post. If you like what you see, set `dry_run: false` and re-run.

To process every open issue and actually post:

```json
{
  "repo": "apache/tooling-trusted-releases",
  "github_token": "github_pat_...",
  "dry_run": false,
  "skip_already_triaged": true
}
```

Idempotent across runs — already-triaged issues are skipped.

## Why this architecture

A naive design would send the full code base as a single prompt. ATR is roughly 600+ source files; the contents would be many millions of tokens. The pipeline:

1. **Tarball download** (one HTTP call per repo per SHA, ~1 MB compressed). Replaces N `contents/{path}` calls for ~600 files. SHA-tagged so re-runs skip the download.
2. **Relevance pass** sees 200-line previews of every text file, batched under 40% of the relevance model's context window, dispatched in parallel. Returns numerical 0–10 scores per file. Cached per issue per SHA. Cheap when run on a Haiku-class model.
3. **Deep analysis** sees the full source of the top-scoring files only (≥4, with fallback to ≥2). The cap (`max_files_per_issue`, default 8) prevents runaway prompts on issues that match many files.

The relevance pass is the part that scales: it lets the agent look at every file in the repo *for every issue*, rather than blindly picking from path lists, while keeping cost bounded by Haiku pricing × the few times you actually re-triage.

## What the agent does NOT do

- It does not run tests or otherwise verify diffs apply cleanly. The diffs are drafts for human review.
- It does not open pull requests. Branch creation, PR creation, and CI integration are the next iteration.
- It does not write code that depends on a shared SDK — it talks to the GitHub REST API directly via the sandbox's `http_client`.
- It does not retry on rate-limit failures. With a normal token (5,000 GitHub API calls/hr authenticated) and reasonable cost ceilings, the volume here is well below that. If you do hit a rate limit, the run partially completes and reports the failure in `errors`.

## Roadmap

This is **Phase 1** of three. Each phase ships independently and can be tested before moving on.

**Phase 2 — multi-agent split.** Refactor into four agents wired through `data_store`:
- `download_repo` — tarball fetch + extract (drop-in reuse of `asvs_download_repo`)
- `discover_architecture` — produces a structured codebase summary (framework, auth systems, API layers, security-relevant areas) cached at `discovery:owner/name`
- `triage_issue` — the per-issue analyzer; pure function over data_store, returns comment_body plus a structured `files_for_pr` field for Phase 3 consumption
- `triage_orchestrator` — the user-facing entry point; does all GitHub I/O (issue listing, sentinel checks, comment posting), fans out per-issue work in parallel under a semaphore

The orchestrator's input/output schemas match this Phase 1 agent so it remains a drop-in upgrade. The split exists for failure isolation, faster re-runs (skip download/discovery if SHA hasn't moved), and reusability of the download/discovery primitives across other agents.

**Phase 3 — PR-writer.** A separate agent that:
1. Reads the comments this triage pipeline left (filtering by sentinel)
2. For each `actionable` triage, parses the structured `files_for_pr` payload from the comment metadata
3. Creates a feature branch, applies the diffs (with retry-on-409 / fresh-SHA refetch like `asvs_push_github`)
4. Opens a draft PR linking back to the triage comment

The diff format and the `<!-- gofannon-issue-triage-bot v1 -->` sentinel are designed to make Phase 3's pickup straightforward.

## Operational notes

- **Cost cap.** Use `max_issues` and `dry_run` for the first run on any repo. After that you have a baseline for cost-per-issue.
- **Re-triaging.** To force re-triage of every issue (e.g., after improving the prompt), set `skip_already_triaged: false`. To re-triage only specific issues, list them in `issue_numbers`.
- **Bumping the sentinel.** If you change the prompts substantially, bump the version in the `SENTINEL` constant in `issue_triage_agent.py`. Old comments stay; new runs ignore them and re-triage everything.
- **Filtering noise.** If your repo has paths the agent shouldn't ever look at (e.g., generated SBOM files), add patterns to the `SKIP_DIRS`, `SKIP_FILES`, or `SKIP_EXTENSIONS` sets near the bottom of `issue_triage_agent.py`. The current lists are lifted from the ASVS pipeline and cover `node_modules`, `.venv`, `dist`, `build`, common lockfiles, binary extensions, and minified/CSS assets.