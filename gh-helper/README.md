# GitHub Issue Triage Agent (gofannon)

A gofannon agent that reads open issues for any GitHub repository, builds a structured understanding of the codebase, and posts per-issue triage comments that cite real code with line ranges, propose grounded patches, and flag stale issues for closure.

This is the **read-and-comment** iteration. The next iteration will open PRs.

## What it does

For each repo (cached per HEAD SHA, run once and shared across all issues):

1. **Downloads the repo as a tarball** and caches files in `data_store`. Re-runs at the same SHA skip the download.
2. **Architecture discovery** — one Sonnet call produces a structured codebase map: framework, language, purpose, auth systems, API layers, data layer, execution model, key subsystems, trust model. Files are sorted by architectural informativeness (configs, entry points, then keyword matches) so the budget always covers the most signal-dense files.
3. **Domain partitioning** — one Sonnet call groups the codebase into application areas. The target range scales with file count (3–6 for small codebases, up to 12–30 for very large ones), so a 600-file repo gets ~7–14 domains while a 5,000-file monorepo gets ~10–20.
4. **File inventory** — Sonnet, batched, builds a per-file structured catalog: purpose, public API with line ranges, concerns. Cache namespace `audit-cache:inventory:{file-set-hash}` is shared with `asvs_audit`, so a repo already audited gets free hits here, and vice versa.
5. **Open-PR scan** — one `/search/issues` call enumerates open PRs and parses titles + bodies for close-keywords (`fixes #N`, `closes #N`, `resolves #N`). Builds a map of issues that already have someone working on them.
6. **Issue clustering** — one LLM call groups open issues into duplicate/related clusters. Cached by issue-corpus content.

Then for each issue:

1. **Sentinel and PR-link checks** — skip issues already triaged by this agent, or skip with classification `pr_in_progress` if a PR is linked.
2. **Domain classification** — one Haiku call routes the issue to 1–3 application domains. Narrows the relevance-search to those domains.
3. **Relevance scoring** — Haiku, batched, scores files against the issue using *inventory entries* (not raw previews). Returns 0–10 per file. Top-K (8) selected with threshold ≥4, falling back to ≥2 if too few clear the bar.
4. **Staleness metrics** — computed locally from issue timestamps and comment activity. No LLM cost. Captures: days since created, days since last update, days since last comment, days since last *human* comment (skips bots and the agent's own comments), human comment count.
5. **Deep analysis** — Opus, with the full structured context: architecture, domain context, inventory entries, full source of picked files, and the staleness metrics. Produces structured JSON: classification, summary, existing-code citations, new-code locations, approach, diffs, open questions, and a staleness assessment with `recommend_close`.
6. **Citation grounding** — every existing-code citation has its line range computed from the actual source by anchor-matching. The model's claimed line range is replaced with the real one. Citations whose snippets don't appear in the cited file at all (genuine hallucinations) are dropped.
7. **Comment** — renders all of the above as markdown with sections for Where this lives, Where new code would go, Approach, Suggested patches, Open questions, Staleness assessment (only when applicable). Posts to GitHub or returns the draft if `dry_run` is true.
8. **Label** — applies the configured label to the issue (creates the label in the repo on first run if missing).

Each comment is tagged with `<!-- gofannon-issue-triage-bot v2 -->` so subsequent runs skip already-triaged issues.

## Setup

### 1. Create the agent in gofannon

Create a new agent in the gofannon UI with name `read_and_triage` (or similar). Paste `issue_triage_agent.py` into the **Code** field.

### 2. GitHub token

You need a fine-grained Personal Access Token with **Issues: Read & Write** on the target repo (or org-wide). Read-only is not enough — the agent posts comments and applies labels.

### 3. Invokable models (Bedrock)

The pipeline uses three model tiers. Add all three to the agent's **Invokable Models**:

| Tier | Model string | Used for | Recommended UI parameters |
|---|---|---|---|
| **Opus** | `us.anthropic.claude-opus-4-6-v1` | Deep analysis (per issue) | `temperature: 1`, `reasoning_effort: high`, `max_tokens: 32768` |
| **Sonnet** | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | Architecture, domains, inventory (one-time per SHA) | `temperature: 0.2`, `max_tokens: 16384` |
| **Haiku** | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | Relevance, clustering, domain classification | `temperature: 0.3`, `max_tokens: 4096` |

Per-model parameters set in the gofannon UI take precedence over what the agent passes. The `temperature: 1` on Opus is required when `reasoning_effort` is enabled (Anthropic constraint). The 32K `max_tokens` on Opus leaves room for thinking budget plus the structured JSON output (citations + snippets + diffs + staleness assessment).

If you only have Haiku registered for cost reasons, the agent will still run — quality drops noticeably for deep analysis but the rest of the pipeline functions.

### 4. Inputs and outputs

Add the input and output fields one at a time through the gofannon UI. See the [**Inputs reference**](#inputs-reference) and [**Outputs reference**](#outputs-reference) tables below for the exact field names and types.

The agent uses several `data_store` namespaces internally (architecture cache, inventory cache, per-issue caches, etc.), but you don't need to declare them anywhere — they're created on first write. See [**Caches and namespaces**](#caches-and-namespaces) below for what's stored where.

## Quickstart

Five worked examples, ordered roughly by what you'd run first to last.

### 1. First-time smoke test

You've never run the agent on this repo. Verify everything's wired correctly before any comments go up.

```json
{
  "repo": "your-org/your-repo",
  "github_token": "github_pat_...",
  "dry_run": true
}
```

Runs the full pipeline against every open issue and returns the generated comments in `results[].comment_body` without posting anything to GitHub. Cost: one Sonnet pass for discovery (~1–2 min) + one Opus deep-analysis call per issue. If this works, the rest will work.

### 2. Triage your own issues

You're a maintainer and only want to triage issues assigned to you, not the whole project.

```json
{
  "repo": "your-org/your-repo",
  "github_token": "github_pat_...",
  "assignee": "your-github-username",
  "dry_run": true
}
```

Filters server-side via `/issues?assignee=USERNAME`. Combined with `dry_run: true`, this is a sanity check before any comments go up. Drop the `dry_run` flag once you're satisfied with the output.

### 3. Triage everyone's assigned issues

Anyone with an assignment, but skip unassigned tickets.

```json
{
  "repo": "your-org/your-repo",
  "github_token": "github_pat_...",
  "assignee": "*",
  "dry_run": true
}
```

`*` is GitHub's special value meaning any assignee. Useful when you have a triage party and want to cover only issues someone has already claimed. Use `none` instead for the inverse — only unassigned issues.

### 4. Production run

You've reviewed dry-run output and you're ready to post.

```json
{
  "repo": "your-org/your-repo",
  "github_token": "github_pat_..."
}
```

That's it. All defaults: full Opus/Sonnet/Haiku tier pipeline, every open un-triaged issue gets a comment plus the `gh-helper` label, related-issues clustering active, PR-linked issues skipped with classification `pr_in_progress`, stale issues flagged with close recommendations. The discovery passes will hit cache from your earlier dry-run if the HEAD SHA hasn't moved.

### 5. Re-triage after a prompt change

You tweaked the agent code (e.g., adjusted the analysis system prompt or the staleness criteria) and want to re-triage existing issues with the updated logic.

```json
{
  "repo": "your-org/your-repo",
  "github_token": "github_pat_...",
  "skip_already_triaged": false,
  "force_redownload": true,
  "dry_run": true
}
```

`skip_already_triaged: false` bypasses the sentinel — issues with existing v2 comments will get re-analyzed. `force_redownload: true` clears the tarball cache and re-fetches the repo. Note that this re-fetches files but does NOT clear the architecture/inventory caches (they're keyed by SHA, and the SHA hasn't changed). If you want to force discovery to re-run on the same SHA, manually clear the `discovery:{repo}@{sha7}` and `audit-cache:inventory:*` namespaces from the data-store viewer.

Always run with `dry_run: true` first when re-triaging — the existing comments don't get replaced, they just get a new comment alongside them, and you want to verify the new output before doubling up on every issue.

## When to use which inputs

A few practical notes on the more nuanced flags:

- **`force_redownload`**: rarely needed. The agent checks `meta:{repo}/head_sha` against GitHub's current HEAD on every run and re-downloads automatically if they differ. Use this when you suspect a corrupt cache.
- **`skip_already_triaged`**: leave true for normal operation. Only set false when intentionally re-triaging (after a prompt change). Even then, run with `dry_run` first — re-triaged issues get a *new* comment alongside the old one, not a replacement.
- **`skip_when_pr_open`**: keep true unless you want to re-evaluate issues that already have an open PR. With true, those issues get classification `pr_in_progress` and a small "see also" comment only if related-issue clustering finds duplicates.
- **`detect_related_issues`**: keep true. The cluster pass costs about one Haiku call per issue corpus and pays for itself by finding duplicates the per-issue analysis can't see.
- **`label`**: set to `""` to disable labeling entirely. Otherwise the agent ensures the label exists in the repo and applies it to every examined issue.

## Inputs reference

| Input | UI Type | Required | Default | What it does |
|---|---|---|---|---|
| `repo` | string | yes | — | `owner/name`, e.g. `apache/tooling-trusted-releases` |
| `github_token` | string | yes | — | PAT with Issues: Read & Write |
| `dry_run` | boolean | no | `false` | if true, runs the full pipeline but posts zero comments and applies zero labels; comment text appears in `results[].comment_body` for inspection |
| `skip_already_triaged` | boolean | no | `true` | skip issues that already contain the v2 sentinel; set false to re-comment |
| `branch` | string | no | `""` | branch to read code from; empty = repo default |
| `force_redownload` | boolean | no | `false` | bypass the SHA freshness check and re-fetch the tarball |
| `assignee` | string | no | `""` | filter to issues assigned to this GitHub username; `*` = any assignee, `none` = unassigned only, empty = no filter |
| `skip_when_pr_open` | boolean | no | `true` | skip issues with open PRs that close-keyword-link them; classification `pr_in_progress` |
| `detect_related_issues` | boolean | no | `true` | run the cross-issue clustering pass; false saves one LLM call per corpus |
| `label` | string | no | `gh-helper` | label applied to every examined issue; created in the repo if missing; empty disables labeling |

Ten inputs total: 2 required, 8 optional. Model selection, cost limits (max issues, max files per issue), and reasoning configuration are all hardcoded internally — model identities match the Invokable Models registration, and per-model parameters (temperature, max_tokens, reasoning_effort) are configured in the gofannon UI.

## Outputs reference

| Field | UI Type | Notes |
|---|---|---|
| `outputText` | string | short prose summary suitable for the gofannon UI |
| `repo` | string | what was analyzed |
| `branch` | string | branch read from |
| `head_sha` | string | full HEAD SHA |
| `issues_processed` | integer | how many issues entered the per-issue loop |
| `issues_commented` | integer | how many comments were actually posted |
| `issues_skipped` | integer | sentinel-skipped + pr_in_progress combined |
| `errors` | list | `{issue_number, error}` for issues that hit an exception |
| `results` | list | one entry per processed issue, structure below |

Each `results[]` entry:

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
| `is_stale` | bool | model assessed the issue as stale |
| `recommend_close` | bool | model recommends closing the issue |

`is_stale` and `recommend_close` make the staleness signal machine-discoverable — useful for downstream automation that wants to filter to "issues the agent recommends closing" without parsing the comment body.

## Comment format

Triage comments include these sections, in order:

- **Type / Classification / Confidence** — bug_fix / new_feature / refactor / documentation / question / discussion / unrelated / unclear; classification of actionable / no_action / unrelated; confidence high/medium/low. **Stale flag** (⚠️ Stale — consider closing) appears in this header line when the agent recommends closing.
- **Application domain(s)** — which area(s) of the codebase
- **Summary** — what the issue asks, what was found
- **Where this lives in the code today** — for each cited piece of existing code: file path, symbol name, line range (computed from actual source by snippet match), role (currently does this / needs modification / extension point), explanation, and a verbatim code snippet
- **Where new code would go** (only for new-feature issues) — file + anchor + rationale
- **Proposed approach** — paragraph
- **Suggested patches** — diffs anchored to real files
- **Open questions** — things the agent does not understand
- **Staleness assessment** (only when `is_stale` or `recommend_close` is true) — age and activity summary, rationale for the staleness assessment, explicit close recommendation when warranted
- **Files examined** — full list
- **Related issues** — cross-references when applicable

## Why this architecture

A naive design would send the full code base as a single prompt. Most repos are too large for that; even after filtering, the contents would be many millions of tokens. The pipeline instead:

1. **Tarball download** — one HTTP call per repo per SHA (~1MB compressed). Replaces N `contents/{path}` calls. SHA-tagged so re-runs skip the download.
2. **Architecture + domains + inventory** — three structural passes that build the agent's mental model. Cached per SHA.
3. **Per-issue: domain classification → scoped relevance → deep analysis with cited grounding + staleness assessment**. Each pass uses a model tier appropriate for its job.

The cost shape: discovery is roughly 1–3 minutes per SHA on first encounter, then zero. Per-issue cost on the same SHA is dominated by the Opus deep-analysis call. Re-runs at the same SHA on already-triaged issues are essentially free thanks to the sentinel.

The staleness check piggybacks on the deep-analysis call — no extra LLM round-trip. Age metrics are computed locally from data already in scope (issue timestamps, comment timestamps from the sentinel-check fetch). The model integrates these signals with its code analysis to assess whether an issue's premise still holds.

## Caches and namespaces

The agent uses these `data_store` namespaces. They're created on first write — you don't need to declare them anywhere. Worth knowing for debugging or manual cache clearing through the gofannon data-store viewer:

| Namespace | Contents |
|---|---|
| `files:{repo}` | full source files at the canonical snapshot |
| `meta:{repo}` | `head_sha` and `file_count` for the freshness check |
| `discovery:{repo}@{sha7}` | architecture object and domains object |
| `audit-cache:inventory:{file-set-hash}` | per-file structured inventory; shared with asvs_audit |
| `triage-cache:domain:{repo}@{sha7}` | per-issue domain classification |
| `triage-cache:relevance:{repo}@{sha7}` | per-issue relevance scores |
| `triage-cache:related:{repo}` | issue-clustering result keyed by corpus hash |

The `files:{repo}` and `audit-cache:inventory:*` namespaces match what `asvs_audit` produces, so cross-pipeline cache hits work in both directions.

## Operational notes

- **Filtering noise.** If your repo has paths that should never be analyzed (generated SBOMs, build artifacts), add them to the `SKIP_DIRS`, `SKIP_FILES`, or `SKIP_EXTENSIONS` sets near the top of `run()`. The current lists are lifted from the ASVS pipeline.
- **Issue volume.** The agent processes issues serially. ~30 issues at full pipeline cost is roughly 10–15 minutes wall-clock with Opus deep analysis. The cross-issue passes (PR scan, clustering) are one-time per run regardless of issue count.
- **Sentinel bumping.** v1 → v2 means existing v1 comments do NOT block re-triage. If you want to keep v1 comments and only triage new issues, run once with `skip_already_triaged: false` + `dry_run: true` to see what re-triage would produce, then decide.
- **Staleness signals.** The agent skips its own comments and other bots when computing "last human activity" — so the agent's own re-triage doesn't reset the staleness clock. Activity by named human accounts is what counts.
- **Recommended close ≠ auto-close.** The agent only *recommends* closure in the comment body and surfaces `recommend_close: true` in the result row. The agent never closes issues programmatically. A maintainer reading the comment makes the call.
- **Per-user runs.** Pass `assignee` with a GitHub username to triage only that user's assigned issues. Combined with `dry_run: true` for a personal sanity check before the bot posts anywhere.

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

The v2 comment format with grounded citations (verbatim snippets and computed line ranges) is designed to make Phase 3's pickup straightforward — the PR-writer can match snippets against current source to determine where each diff applies.

**Phase 3 also enables auto-close suggestions for stale issues** by running through `recommend_close: true` results, opening lightweight PRs that close the issues with the agent's rationale as the closing comment, gated behind maintainer review.