# ASVS Security Audit Pipeline

Automated [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) compliance auditing for any GitHub-hosted codebase. The pipeline downloads source code, auto-discovers the architecture, runs per-requirement security analysis with Claude, triages findings against the project's own security policies, and produces a consolidated report with deduplicated findings and ready-to-file GitHub issues.

Built on [Gofannon](https://github.com/The-AI-Alliance/gofannon) — see [docs/gofannon](../docs/gofannon/) for platform setup.

## Pipeline flow

```
asvs_orchestrate                       (single entry point)
  │
  ├──▶ asvs_download_repo              (once — fetches source code)
  │
  ├──▶ asvs_discover                   (once — generates audit plan; level-pre-filtered)
  │
  ├──▶ asvs_audit  / asvs_bundle       (× N — bundle when sections share scope)
  │     per-section reports → CouchDB  (audit-reports:{output_dir} namespace)
  │
  ├──▶ asvs_relevance_filter           (once — false-positive triage against project policy)
  │     ├──▶ _security_profile.md
  │     ├──▶ _filter_drop_log.md
  │     ├──▶ _review_queue.md
  │     └──▶ _suggested_audit_guidance.md
  │
  ├──▶ asvs_consolidate                (once — final report)
  │     ├──▶ consolidated.md           → private repo
  │     └──▶ issues.md                 → private repo
  │
  └──▶ redact + publish                (if privateRepo is set)
        ├──▶ read full reports from consolidation:* namespace
        ├──▶ strip Critical findings
        ├──▶ check for residual leaks
        │   ├──▶ clean    → push redacted reports to public repo
        │   └──▶ leak     → quarantine: leaky+banner to private,
        │                                clean placeholder to public
        └──▶ email Critical summary to PMC
```

Two peer agents (not invoked by the orchestrator) populate the audit-guidance namespace that `asvs_relevance_filter` consumes:

- `asvs_guidance_ingest` — fetches a file from a GitHub repo and stores it
- `asvs_guidance_upload` — stores text directly (no GitHub round-trip)

Both write into `audit_guidance:{repo}` keyed by filename. See [Audit guidance](#audit-guidance) below.

The orchestrator routes audit work between two agents:

- **`asvs_audit`** — single-section audit (one ASVS requirement at a time)
- **`asvs_bundle`** — multi-section audit (multiple ASVS requirements sharing a file scope, in one Opus pass)

When `asvs_discover` produces a domain pass with several sections targeting the same files, the orchestrator chunks them and routes each chunk to `asvs_bundle` instead of making N separate `asvs_audit` calls. This is the largest single performance optimization in the pipeline.

Pre-requisites (one-time, outside the pipeline):

- ASVS requirements loaded into the `asvs` data store namespace via the `asvs_load_data` agent
- Optionally: project policy docs uploaded to `audit_guidance:{repo}` via `asvs_guidance_upload` or `asvs_guidance_ingest` — these power the relevance filter's drop reasoning

## Quick start

Run `asvs_orchestrate` with:

| Input | Value |
|---|---|
| `sourceRepo` | `apache/airflow` |
| `outputRepo` | `apache/tooling-agents` |
| `outputToken` | `ghp_...` |
| `outputDirectory` | `ASVS/reports` |
| `level` | `L2` |
| `severityThreshold` | `HIGH` |
| `supplementalData` | `audit_guidance:airflow` (if you've uploaded any) |
| `privateRepo` | `apache/tooling-runbooks` (optional, enables carve-out + filter) |
| `privateToken` | `ghp_...` (required if `privateRepo` is set) |

The orchestrator downloads the code, fetches the latest commit hash, discovers the architecture, runs all audits, triages findings through the relevance filter, and consolidates. The output directory is automatically extended with the repo name and commit hash: `ASVS/reports/airflow/da901ba`.

To audit a subdirectory of a large repo:

| Input | Value |
|---|---|
| `sourceRepo` | `apache/airflow/airflow-core/src` |

This downloads only files under `airflow-core/src/`.

## Reports

Per-section reports live in CouchDB (namespace `audit-reports:{output_directory}`) rather than GitHub. Only the final artifacts go to GitHub:

```
reports/
└── airflow/
    └── task-sdk/
        └── 6431cd1/
            ├── consolidated.md                    ← THE REPORT (private full, public redacted)
            ├── issues.md                          ← GitHub issues, one per actionable finding
            ├── _security_profile.md               ← filter Phase 1 output (trust boundaries,
            │                                        delegated controls, documented decisions)
            ├── _filter_drop_log.md                ← every dropped finding with reasoning
            ├── _review_queue.md                   ← medium/low-confidence drops needing eyeballs
            └── _suggested_audit_guidance.md       ← recurring drop patterns to codify
```

Per-section reports moved off GitHub because each per-section commit surfaced on the public `commits@tooling.apache.org` mailing list — often with finding titles in the diff. CouchDB storage keeps the working state private; only consolidated.md, issues.md, and the filter's diagnostic artifacts ever appear in git history.

Filter artifacts are pushed to the private repo only when `privateRepo` is set; they contain raw finding reasoning and would expose Critical content if pushed to the public repo.

## Inputs reference

### Level system

| `level` value | Requirements audited |
|---|---|
| `L1` | L1 only |
| `L2` | L1 + L2 |
| `L3` | L1 + L2 + L3 (all) |
| (empty) | L1 + L2 + L3 (all) |

The orchestrator now passes `level` to `asvs_discover` so above-level sections are filtered out before the Sonnet classification call. An L1 run no longer pays the cost of Sonnet classifying ~215 above-L1 sections only to throw them away.

### Severity threshold

| `severityThreshold` value | Findings included |
|---|---|
| `CRITICAL` | Critical only |
| `HIGH` | Critical + High |
| `MEDIUM` | Critical + High + Medium |
| (empty) | All findings |

### Cache control

`clearCache` (default `"true"`) controls cache wiping at the start of a run. When `"true"`, the orchestrator wipes:

- `files:{source}` — the source-code namespace
- `audit-reports:{output_dir}` and `audit-reports-filtered:{output_dir}` — per-section reports
- `audit-cache:relevance:*` and `audit-cache:analysis:*` matching the current source namespace — Haiku and Opus result caches keyed by file-set hash
- `consolidation:{push_repo}/...` and `extraction:*` matching this run — consolidation intermediates and finding-extraction cache

Preserved across runs regardless of `clearCache`:

- `audit-cache:inventory:*` — Sonnet inventory cache, content-hashed (safe to reuse)
- `relevance-filter-cache:*` — filter results keyed by file-set hash + policy profile hash
- `audit_guidance:*` — uploaded project policy docs (managed by you, not by the orchestrator)

`clearCache="false"` skips Step 1 entirely. The orchestrator sanity-checks the namespace is non-empty before proceeding; if empty it returns an error pointing at either flipping `clearCache="true"` or running `asvs_download_repo` manually first.

### Stale report cleanup

`cleanStaleReports` (default `"false"`) is an opt-in destructive cleanup that runs after the audit phase succeeds. When `"true"`, the orchestrator lists keys in the `audit-reports:{output_dir}` CouchDB namespace and deletes any whose pass-prefix isn't part of the current run.

Why it exists: discovery's domain naming is non-deterministic (Sonnet at temperature 0.7), so re-running against the same commit can produce different domain names (`auth_identity` vs `session_management`, `aws_cloud_integration` vs `cloud_integration_aws`). Keys from previous runs accumulate in their old pass-prefix and pollute consolidate-only reruns or QA tooling.

What's safe:

- Only deletes keys whose pass-prefix isn't in the current run's `report_directories`
- Skipped entirely if there were any audit failures (don't compound a partial run by deleting things)
- Cleanup failures are caught and logged but don't block consolidation

When NOT to use:

- If you have manual annotations stored alongside auto-generated reports in the same namespace (rare; would need a separate workflow)

## Audit guidance

The relevance filter triages findings against a project security profile synthesized from the project's own policy docs (SECURITY.md, AGENTS.md, threat-model documents, and any custom files you upload). When a finding aligns with a documented delegation, trust-boundary statement, or out-of-scope category, the filter drops it and cites the policy source.

Guidance lives in CouchDB under `audit_guidance:{repo}`, where `{repo}` is the repo's short name. Each key is a filename; the value is markdown text. The filter merges all entries with the GitHub-resident policy docs (SECURITY.md from repo root) into a single profile per run.

### Uploading guidance

Two peer agents populate this namespace.

**`asvs_guidance_upload`** — store text directly. Use when the guidance doesn't live in a file in the repo (e.g. you're writing a new policy clarification specifically for the audit).

```
inputText:    {"repo": "airflow", "filename": "dag_authors_trusted.md"}
fileContents: <markdown body>
```

Namespace defaults to `audit_guidance:{repo}`; pass `"namespace"` in the JSON to override.

**`asvs_guidance_ingest`** — fetch a file from a GitHub repo and store it. Use when the policy already lives in a doc you want to keep in sync.

```
repo:     apache/airflow
filename: docs/security-model.md
token:    ghp_... (optional, for private repos or rate-limit headroom)
```

### Wiring guidance into a run

Pass the namespace via `supplementalData`:

```
supplementalData: audit_guidance:airflow
```

The filter discovers all keys in the namespace and includes them in profile synthesis. The audit/bundle agents also see the namespace and treat its files as guidance (force-included, not relevance-scored — they shouldn't compete with code for Haiku's attention).

### Example: airflow

Four files uploaded for `apache/airflow`:

| Filename | Applies to ASVS | Codifies |
|---|---|---|
| `delegated_infrastructure_controls.md` | 3.2.1, 3.2.2, 3.4.1, 3.4.2, 4.4.1, 6.1.1, 11.3.2, 12.1.1, 12.2.1, 12.2.2 | TLS/HSTS/CORS/rate-limiting/payload-size delegated to Deployment Manager |
| `simpleauthmanager_dev_only.md` | 6.2.1, 6.2.2, 6.2.3, 6.2.4, 6.4.1 | Dev-only auth; production must use FAB/Keycloak |
| `dag_authors_trusted.md` | 5.2.1, 5.3.2 | DAG authors trusted for arbitrary code; sub-RCE threats out of scope |
| `dependency_cve_policy.md` | 15.1.1, 15.2.1 | No fixed remediation SLAs; dependency CVE timing per ASF Severity Rating |

Each file is short — a title, an "Applies to ASVS sections:" line, and a policy paragraph quoting the project's own docs verbatim. The filter's profile hash changes when this set changes, invalidating the relevance-filter cache so the next run sees the new policy.

## Architecture

The pipeline uses three Claude models, each chosen for what it's best at:

- **Sonnet** — high-throughput parallel work (code inventory, formatting, extraction, consolidation)
- **Haiku** — cheap classification (relevance filtering during audit)
- **Opus** — deep security analysis where reasoning quality matters most (audit, filter triage, consolidation polish)

The discovery agent scans the codebase architecture and generates security domains — groupings of ASVS requirements by the code area they test (e.g., `auth_identity`, `secrets_crypto`, `web_input_validation`). Each domain gets its own file list, so the audit agents only analyze relevant code. ASVS sections not assigned by discovery are caught by a fallback that groups them by ASVS chapter.

When a domain has multiple sections sharing the same file scope, the orchestrator dispatches them as a bundle to `asvs_bundle`. Bundling produces one Opus reasoning trace covering all requirements in the bundle, then splits the response into per-section reports for downstream consolidation. The audit phase as a whole runs with bounded parallelism — multiple sections/bundles in flight at once via `PASS_CONCURRENCY` (default 4).

The relevance filter (Step 3.7) reads per-section reports from CouchDB, synthesizes a project profile from policy docs, triages findings per ASVS chapter against the profile, and writes filtered reports to `audit-reports-filtered:{output_dir}`. Consolidation reads from the filtered namespace, so dropped findings never reach the final report. Four diagnostic artifacts are pushed to the private repo so you can see exactly what the filter did and why.

The consolidation agent reads filtered per-section reports, extracts findings into structured JSON, deduplicates within and across domains, generates deterministic cross-references, ASVS compliance summary, and positive controls section, and produces the final consolidated report with executive summary and issues file. Sections 4 through 6 of the consolidated report (positive controls, ASVS compliance summary, cross-reference matrix) are built deterministically from data-store ASVS metadata — chapter names, requirement text, and file paths are sourced from the extracted finding objects rather than re-generated by an LLM that would hallucinate them.

## Critical finding carve-out

When `privateRepo` is set, Critical findings never touch the public repo — not even in git history. The flow is:

1. All per-section reports are kept in CouchDB only
2. Consolidated report and issues are pushed to the **private** repo
3. The orchestrator reads them back from the `consolidation:*` namespace (mirrored by the consolidator to avoid a GitHub round-trip)
4. Critical findings are stripped from the consolidated report and issues file
5. The redactor checks for residual leaks — content that survived structured stripping
6. **Clean path**: redacted versions are pushed to the **public** repo with a notice
7. **Leak path**: a `_redaction_warning_consolidated.md` quarantine file goes to the private repo, and a clean placeholder ("report under review") goes to the public repo
8. A summary of Critical findings is emailed to the PMC's private mailing list (if `notifyEmail` is set)

The public report normally includes a notice: "N Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list."

When `privateRepo` is absent, all reports go directly to `outputRepo` (no redaction, no filter artifacts pushed).

### Redaction internals

The redactor uses **structured severity detection**, not bare-word matching. A finding is treated as Critical only when its Finding ID token (`ASVS-{section}-CRIT-NNN`), severity heading (`#### CRITICAL`), `**Severity:**` field, or `🔴 Critical` marker says so. The word "critical" appearing in prose (descriptions, gap classifications, impact analysis) does NOT trigger redaction.

After structured stripping, three sweeps run as defense-in-depth:

- **Cross-reference row drop** — finds Cross-Reference Matrix rows whose Finding ID cell is now empty after redaction and drops the entire row. Uses `re.MULTILINE` anchor and `[ \t]+` (not `\s+`) so it can't cross newlines.
- **Severity Distribution table regen** — finds the heading and replaces the entire following table block with regenerated counts (Critical → 0, Total decremented). The old approach was field-by-field substitution and missed unusual table layouts.
- **Title-based leak scrub** — extracts each Critical finding's title at block-detection time, then walks the doc line-by-line dropping any line that still contains a redacted title. This catches references in Top Risks lists or narrative prose that the per-block strippers missed.

After all three sweeps, the redactor runs a final scan for residual leaks (severity tokens, Finding IDs, titles). If anything still leaks, the quarantine path fires.

## Environment configuration

All performance knobs are environment variables read by the agents at runtime. Defaults are calibrated to work safely against typical hosted Bedrock + GitHub account quotas — you shouldn't need to tune anything to get started.

These are NOT gofannon framework features. They are `os.environ.get(VAR, default)` reads in the agent code, set on the gofannon worker process (e.g. for Docker deployments, the `api` container's environment).

| Agent | Env var | Default | What it controls |
|---|---|---|---|
| `asvs_orchestrate` | `PASS_CONCURRENCY` | `4` | Max audit calls in flight (sections + bundles). Top-level orchestrator parallelism. |
| `asvs_orchestrate` | `BUNDLE_MAX_SECTIONS` | `6` | Max sections per `asvs_bundle` call. Set to `1` to disable bundling entirely. |
| `asvs_orchestrate` | `BUNDLE_MIN_SECTIONS` | `2` | Below this, a pass falls back to single-section `asvs_audit` calls. |
| `asvs_orchestrate` | `TINY_REPO_LOC_THRESHOLD` | `30000` | Skip `asvs_discover` for repos under this LOC (small-repo single-pass mode). |
| `asvs_orchestrate` | `GITHUB_PUSH_CONCURRENCY` | `1` | Max simultaneous PUTs to GitHub. Default `1` (serialized) avoids 409 conflicts on the branch HEAD — GitHub's contents API serializes commits, so concurrent pushes race even when targeting different files. Raising to `2-3` is possible (push agent retries on 409) but anything higher starts losing pushes after retries. |
| `asvs_audit` | `OPUS_CONCURRENCY` | `4` | Max concurrent Opus deep-analysis calls within one audit. |
| `asvs_audit` | `SONNET_CONCURRENCY` | `5` | Max concurrent Sonnet inventory and format calls. |
| `asvs_bundle` | `OPUS_CONCURRENCY` | `4` | Same as audit's, scoped to a bundled-pass run. |
| `asvs_bundle` | `SONNET_CONCURRENCY` | `5` | Same as audit's, scoped to a bundled-pass run. |

Defaults are conservative. Teams with elevated quotas can bump `OPUS_CONCURRENCY` and `PASS_CONCURRENCY` higher. Lower `GITHUB_PUSH_CONCURRENCY` if you see push failures with empty error messages or 403/422 responses (those are abuse-detection drops).

## Agent reference

All gofannon inputs are strings.

### Prerequisite: load ASVS data

Before running any audit, ASVS requirements must be loaded into the `asvs` data store namespace. The `asvs_load_data` agent fetches the canonical CSV from the OWASP/ASVS GitHub repo and populates `asvs:chapters:`, `asvs:sections:`, and `asvs:requirements:` keys. Run once per ASVS version. Optionally enriches with chapter control objectives and section descriptions parsed from the markdown files. v5.x only.

### asvs_orchestrate

The main entry point. Calls all other agents.

| Input | Required | Description |
|---|---|---|
| `sourceRepo` | yes | Source code to audit. Accepts `owner/repo`, `owner/repo/subdir`, or full GitHub URL like `https://github.com/owner/repo/tree/branch/subdir` |
| `sourceToken` | no | PAT for private source repos |
| `supplementalData` | no | Extra data store namespaces, comma-separated (e.g., `audit_guidance:airflow`) |
| `outputRepo` | yes | GitHub repo for public reports (`owner/repo`) |
| `outputToken` | yes | PAT with write access to output repo |
| `outputDirectory` | yes | Base directory — repo name and commit hash are appended automatically |
| `discover` | no | `"true"` or `"false"` (default `"true"`) |
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default empty, treated as L3 — use `"L1"` for a quick baseline audit) |
| `severityThreshold` | no | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or empty |
| `consolidate` | no | `"true"` or `"false"` (default `"true"`) |
| `clearCache` | no | `"true"` or `"false"` (default `"true"`). When `"true"`, wipes the derived caches for this run; see [Cache control](#cache-control). |
| `cleanStaleReports` | no | `"true"` or `"false"` (default `"false"`). When `"true"`, deletes keys in `audit-reports:*` whose pass-prefix isn't part of this run. See [Stale report cleanup](#stale-report-cleanup). |
| `privateRepo` | no | Private repo for full unredacted reports (enables carve-out + leak quarantine) |
| `privateToken` | no | PAT with write access to private repo (required when `privateRepo` is set) |
| `notifyEmail` | no | Email address for Critical findings (e.g., `private@steve.apache.org`) |

**Output:** `outputText` — combined audit results.

**Namespace derivation:** The orchestrator parses `sourceRepo` to derive the code namespace automatically. `apache/airflow` → `files:apache/airflow`. If `supplementalData` is `audit_guidance:airflow`, the namespace list becomes `["files:apache/airflow", "audit_guidance:airflow"]`.

**Agents called:**

1. `asvs_download_repo` — downloads source code (skipped if `clearCache=false`)
2. `asvs_discover` — generates audit plan (if `discover="true"` and the repo isn't tiny)
3. `asvs_audit` — once per ASVS section that's not bundled
4. `asvs_bundle` — once per bundle of sections sharing a file scope
5. `asvs_relevance_filter` — triages findings against project profile (Step 3.7)
6. `asvs_consolidate` — final report (if `consolidate="true"`)
7. `asvs_push_github` — for consolidated.md, issues.md, and filter artifacts

### asvs_download_repo

Downloads a GitHub repo (or subdirectory) into the data store.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | `owner/repo` or `owner/repo/subdir`, optional token on next line |

**Output:** `outputText` — download summary.

Stores files in namespace `files:{owner}/{repo}`. When a path prefix is included (e.g., `apache/airflow/airflow-core/src`), only files under that path are downloaded. File paths in the data store are preserved as full repo-relative paths.

Uses GitHub's tarball endpoint for the download (one HTTP call) — much faster than per-file fetches and uses far less of the GitHub API quota.

### asvs_discover

Scans codebase, generates domains + file lists + false positive guidance.

| Input | Required | Description |
|---|---|---|
| `inputNamespace` | yes | Data store namespace(s) with code, comma-separated |
| `level` | no | `"L1"`, `"L2"`, `"L3"`. Pre-filters ASVS sections before classification so we don't waste a Sonnet call on above-level requirements. |

**Output:** `outputText` — JSON passConfig containing `passes`, `domain_groups`, `false_positive_guidance`.

Each pass in the output describes a group of ASVS sections that share a file scope. The orchestrator uses these passes to route work to either `asvs_audit` (single) or `asvs_bundle` (multi).

The agent shows the model the full ASVS section list (no truncation) and validates the model's output against the authoritative `valid_section_ids` set built from the `asvs` data store namespace. Hallucinated section IDs are dropped with a warning before they reach the audit phase.

### asvs_audit

Audits code against a single ASVS requirement. Used for one-off audits and for sections that don't fit into a bundle.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON string (see fields below) |

JSON fields inside `inputText`:

| Field | Required | Description |
|---|---|---|
| `namespaces` | yes | Array of data store namespaces (singular `namespace` also accepted). Files from any `audit_guidance:*` namespace are force-included as guidance — they're not relevance-scored. |
| `asvs` | yes | ASVS section (e.g., `"6.1.1"`) — alias `asvs_section` also accepted |
| `includeFiles` | no | Array of file glob patterns — skips relevance filtering. If patterns match zero keys in the namespace (hallucinated paths or repo layout drift), falls back to the unfiltered key list with a warning. |
| `domainContext` | no | Architecture context for Opus prompt |
| `severityThreshold` | no | Minimum severity to report |
| `falsePositiveGuidance` | no | Array of patterns to suppress |

If `inputText` isn't valid JSON, the agent falls back to regex-parsing `namespace:` and `asvs:` keys out of free-form text.

**Output:** `outputText` — markdown audit report.

**Note:** If you pass `asvs_sections` as a list with more than one entry, this agent will return an error directing you to use `asvs_bundle` instead.

### asvs_bundle

Audits code against MULTIPLE ASVS requirements in a single Opus deep-analysis call. Used by the orchestrator whenever a domain pass has 2+ sections sharing the same file scope.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON string (see fields below) |

JSON fields inside `inputText`:

| Field | Required | Description |
|---|---|---|
| `namespaces` | yes | Array of data store namespaces. Guidance namespaces force-included. |
| `asvs_sections` | yes | Array of ASVS section IDs (e.g., `["5.1.1", "5.1.2", "5.1.3"]`) |
| `includeFiles` | no | Array of file glob patterns — same fallback behavior as `asvs_audit` when patterns match zero keys |
| `domainContext` | no | Architecture context for Opus prompt (shared across all sections) |
| `severityThreshold` | no | Minimum severity to report |
| `falsePositiveGuidance` | no | Array of patterns to suppress |

**Output:** `outputText` — JSON envelope with the structure:

```json
{
  "mode": "bundled",
  "asvs_sections": ["5.1.1", "5.1.2", "..."],
  "per_section": {
    "5.1.1": {
      "report": "<full markdown report for this section>",
      "findings": {"Critical": 2, "High": 5, "Medium": 8, "Low": 1},
      "files_analyzed": 42,
      "files_total": 187,
      "files_skipped": 12
    }
  },
  "raw_consolidated": "<full markdown before splitting>",
  "metadata": {"files_analyzed": 42, "opus_batches": 3}
}
```

The orchestrator decodes this envelope and stores `per_section[X].report` in CouchDB as `{pass_name}/{section_id}.md` (one key per section, same as for `asvs_audit`). Downstream `asvs_relevance_filter` and `asvs_consolidate` see the same per-section layout regardless of which agent produced them.

**How it works:** One Opus call with a system prompt listing all bundled ASVS reqs. Opus is instructed to use `## ASVS-{section}: <name>` headers per requirement. The agent splits the response on those headers; cross-cutting "Architecture Observations" and "Recommendations" sections at the end get attached to each per-section report. If Opus skips a section, the splitter emits a stub explaining that no findings were produced for it.

### asvs_relevance_filter

Triages per-section findings against a synthesized project security profile. Drops findings that align with documented delegations, trust boundaries, or out-of-scope categories. Emits four diagnostic artifacts.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | Multi-line: `owner_repo:`, `source_namespace:`, `reports_namespace:`, `output_directory:`, `private_repo:`, `pat:`, and optionally `guidance_namespaces:` |

**Output:** `outputText` — filter summary (counts, profile hash, push status).

Pushes four artifacts to `{privateRepo}/{outputDirectory}/`:

| Artifact | Purpose |
|---|---|
| `_security_profile.md` | Synthesized profile: trust boundaries, delegated controls, dev-only components, documented decisions, out-of-scope categories, severity policy |
| `_filter_drop_log.md` | Every dropped finding with confidence, drop reason, and policy source |
| `_review_queue.md` | Medium/low-confidence drops — filter dropped them but the profile didn't explicitly authorize the drop, only implied it |
| `_suggested_audit_guidance.md` | Recurring drop patterns clustered by underlying policy, recommended for codification into AGENTS.md / SECURITY.md / a new guidance file |

**Phase 1 — Project profile** — discovers candidate docs in the source namespace, fetches root-level SECURITY.md / AGENTS.md from GitHub, merges in any uploaded `audit_guidance:{repo}` files. One Opus call synthesizes a structured profile.

**Phase 2 — Per-chapter triage** — groups per-section reports by ASVS chapter, one Opus call per chapter to triage all findings against the profile.

**Phase 3 — Write filtered reports** — writes triaged reports to `audit-reports-filtered:{output_directory}`. Findings with `dropped: true` are excluded from the report body but retained in the drop log.

**Phase 4 — Push artifacts** — pushes the four diagnostic files to the private repo.

The profile hash (computed from the assembled doc set) is part of the filter cache key, so any change to uploaded guidance invalidates cached triage results.

### asvs_consolidate

Reads per-section reports from CouchDB (`audit-reports-filtered:*` if the filter ran, otherwise `audit-reports:*`), deduplicates, produces consolidated report + issues. Mirrors the final outputs to `consolidation:{push_repo}/...` for the redactor.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | Multi-line: `repo:`, `pat:`, `directories:`, `output:`, `sections:`, `source:`, `reports_namespace:` |
| `domainGroups` | no | JSON string mapping domain names to ASVS section arrays |
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default `"L3"`) |
| `severityThreshold` | no | Included in report metadata when provided |

**Output:** `outputText` — summary. Pushes `consolidated.md` and `issues.md` to GitHub and mirrors to CouchDB.

Sections 4–6 of the consolidated report (positive controls, ASVS compliance summary, cross-reference matrix) are built deterministically rather than by an LLM tail-prompt that historically hallucinated file paths, mixed v4/v5 ASVS labels, miscounted totals by one, and invented "notes" prose. Chapter names and requirement text come from the `asvs` data store; affected files come from the finding objects verbatim.

When the report contains Informational-severity findings, the metadata table gains an "Actionable Issues" row and the cross-reference footer surfaces the actionable count, so the discrepancy with issues.md (which only opens actionable findings) is explained inline rather than left to the reader to figure out.

### asvs_push_github

Pushes a markdown file to a GitHub directory. Used by every other agent in the pipeline that needs to write reports.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON with `repo`, `token`, `directory`, `filename` (see optional fields below) |
| `commitMessage` | no | Git commit message (default: `"Add markdown file"`) |
| `fileContents` | yes | Markdown content |

Optional fields inside `inputText`:

| Field | Description |
|---|---|
| `branch` | Target branch (defaults to the repo's default branch) |
| `filePath` | Full repo-relative path as an alternative to `directory` + `filename` |
| `apiBase` | GitHub API base URL (default `https://api.github.com`; set for GitHub Enterprise) |

**Output:** `outputText` — GitHub API response (JSON envelope on success, or error body on failure).

This agent does NOT raise on GitHub errors — it returns the error body in `outputText`. The orchestrator inspects the response to detect rate-limit drops, abuse-detection 422s, and other non-2xx responses.

### asvs_guidance_upload

Stores text directly in `audit_guidance:{repo}` without a GitHub round-trip. Peer agent — invoked directly by the operator, not by the orchestrator.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON: `{"repo": "<short-name>", "filename": "<file>.md", "namespace": "<optional override>"}` |
| `fileContents` | yes | Markdown content |

**Output:** `outputText` — `Stored {namespace} → {key} ({N} chars). ...` or `Error: <message>`.

Namespace defaults to `audit_guidance:{repo}`; the `namespace` field overrides if you want a non-standard layout.

### asvs_guidance_ingest

Fetches a file from a GitHub repo and stores it under `audit_guidance:{repo}`. Peer agent — invoked directly by the operator.

| Input | Required | Description |
|---|---|---|
| `repo` | yes | `owner/repo`, optionally with `.git` or as a github.com URL |
| `filename` | yes | Path relative to repo root |
| `token` | no | GitHub PAT for private repos / rate-limit headroom |

**Output:** `outputText` — `Stored audit_guidance:{repo} → {filename} ({N} chars). ...` or `Error: <message>`.

Use this when the policy already lives in the repo and you want to keep CouchDB in sync without re-uploading by hand. Re-run after the upstream file changes.

## QA and remediation

### Check for missing reports

Per-section reports live in CouchDB. Compare the audit-reports namespace against the ASVS sections the orchestrator scheduled:

```bash
# 1. List ASVS sections in the data store, filtered to your level
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"asvs","key":{"$regex":"^asvs:requirements:"}}, "fields":["key","value"], "limit":999}' \
  | python3 -c "
import sys, json
docs = json.load(sys.stdin)['docs']
target_level = 1  # L1 -> 1, L2 -> 2, L3 -> 3
sections = sorted([
    d['key'].replace('asvs:requirements:','')
    for d in docs
    if int(d['value'].get('level', 1)) <= target_level
])
with open('/tmp/asvs_sections.txt', 'w') as f:
    for s in sections: f.write(s + '\n')
print(f'Data store (L1-L{target_level}): {len(sections)} sections')
"

# 2. List per-section reports in the audit-reports namespace
NAMESPACE="audit-reports:ASVS/reports/airflow/task-sdk/6431cd1"  # adjust to your run

curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d "{\"selector\":{\"namespace\":\"$NAMESPACE\"}, \"fields\":[\"key\"], \"limit\":999}" \
  | python3 -c "
import sys, json, re
docs = json.load(sys.stdin)['docs']
reports = set()
for d in docs:
    # Key format: {pass_name}/{section_id}.md
    k = d['key']
    if k.endswith('.md'):
        fname = k.split('/')[-1].replace('.md', '')
        if re.match(r'^\d+\.\d+\.\d+$', fname):
            reports.add(fname)
with open('/tmp/reports.txt', 'w') as f:
    for s in sorted(reports): f.write(s + '\n')
print(f'Reports in namespace: {len(reports)} sections')
"

# 3. Show missing
echo "=== Missing reports ==="
comm -23 /tmp/asvs_sections.txt /tmp/reports.txt
```

### Re-run failed sections

Use `rerun-sections.sh` to audit missing sections and/or re-consolidate:

| Mode | Command |
|---|---|
| Audit + consolidate (default) | `./rerun-sections.sh <namespace> <repo> <token> <dir> <section> [section...]` |
| Audit only | `./rerun-sections.sh --no-consolidate <namespace> <repo> <token> <dir> <section> [section...]` |
| Consolidate only | `./rerun-sections.sh --consolidate-only <repo> <token> <dir>` |

Examples:

```bash
# Audit 5 missing sections then consolidate:
./rerun-sections.sh "files:apache/steve" apache/tooling-agents ghp_xxx \
  ASVS/reports/steve/v3/d0aa7e9 1.3.3 1.5.1 1.5.2 1.5.3 3.5.7

# Re-consolidate only (e.g., after deploying a fix to the consolidation agent):
./rerun-sections.sh --consolidate-only apache/tooling-agents ghp_xxx \
  ASVS/reports/steve/v3/d0aa7e9
```

Audited sections are stored under a `rerun/` pass-prefix in CouchDB. The consolidator reads all pass-prefixes and deduplicates findings across them.

`rerun-sections.sh` calls `asvs_audit` directly (one section at a time), bypassing the orchestrator's bundling. This is intentional: when re-running just a few sections, the bundling overhead isn't worth it. If you need to re-run an entire domain, call `asvs_bundle` directly with `asvs_sections` as a list.

### Data store inspection

```bash
# Count sections by level
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"asvs","key":{"$regex":"^asvs:requirements:"}}, "fields":["key","value"], "limit":999}' \
  | python3 -c "
import sys, json
from collections import Counter
docs = json.load(sys.stdin)['docs']
levels = Counter(f'L{d[\"value\"].get(\"level\",\"?\")}' for d in docs)
for lv in ['L1','L2','L3']: print(f'  {lv}: {levels.get(lv,0)}')
print(f'  Total: {sum(levels.values())}')
"

# List all namespaces and document counts
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{},"fields":["namespace"],"limit":99999}' \
  | python3 -c "
import sys, json
from collections import Counter
docs = json.load(sys.stdin)['docs']
for ns, count in sorted(Counter(d['namespace'] for d in docs).items()):
    print(f'  {count}\t{ns}')
"

# List audit guidance uploaded for a repo
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"audit_guidance:airflow"},"fields":["key"],"limit":99}' \
  | python3 -c "
import sys, json
docs = json.load(sys.stdin)['docs']
for d in docs: print(f'  {d[\"key\"]}')
"
```

## Code conventions

These are non-obvious traps that bit us during development. Follow them when modifying agents.

### Helpers must live inside `run()`

Gofannon registers `run` as each agent's entrypoint and executes it in an environment where **module-level names defined alongside it are not in scope**. A helper at module level (e.g. `def _split_output():` at indent 0) will trigger `NameError: name '_split_output' is not defined` when `run` calls it.

All helpers in these agents are defined **inside `run`'s `try:` block at indent 8** — same convention as `parse_llm_json` in `asvs_consolidate`, which has worked correctly in production.

Pre-deploy check:

```bash
grep -cE "^(async )?def _" asvs_*.py | grep -v ":0$"
```

Should return nothing. Any file listed has module-level `_` helpers that will NameError at runtime.

### Discovery output must be validated against the data store

`asvs_discover` has temperature 0.7 for creative domain naming, which means it occasionally hallucinates plausible-looking section IDs (like `2.4.5` when v5 has no such requirement) to satisfy "every section must be assigned" prompt constraints.

Two layers of validation catch this:

1. `asvs_discover` validates the LLM's output against `valid_section_ids` built from the `asvs` data store and drops unrecognized IDs with a warning.
2. `asvs_orchestrate` independently drops any section ID not in `asvs_level_cache` from its work plan, regardless of how it got into the discovery output.

If you change discovery's output format or relax the validation, you risk audits running against nonexistent ASVS requirements (which then waste Opus calls and produce reports that consolidate can't match against the schema).

### Push agents don't raise on GitHub errors

`asvs_push_github` returns GitHub error responses in `outputText` rather than raising exceptions. This is intentional (matches gofannon's general pattern of not raising from agents) but means callers must inspect the response. The orchestrator's `push_one` checks for `"content"` and `"commit"` in the response body to detect actual success vs. a returned error envelope.

### Deterministic data > LLM tail prompts

Sections 4–6 of the consolidated report used to be produced by an LLM "tail prompt" that re-counted findings, named ASVS chapters, and synthesized cross-reference rows. It hallucinated file paths, mixed v4/v5 ASVS labels, and miscounted totals by one. The current implementation builds these sections deterministically from the finding objects and ASVS data-store metadata. When extending, source from data structures, not from LLM re-derivation — chapter names, requirement text, file paths, and counts are all available.

## Troubleshooting

### Setup and inputs

**`"sourceRepo is required"`** — Provide `sourceRepo` as `owner/repo`, `owner/repo/subdir`, or a full GitHub URL.

**`"privateToken is required when privateRepo is set"`** — Provide a PAT with write access to the private repo.

**`"No ASVS sections match level L1"`** — Check that ASVS requirement entries have a `level` field. Run `asvs_load_data` if you haven't yet.

**`"Error: clearCache=false but namespace ... is empty"`** — Either flip `clearCache=true` to download fresh, or run `asvs_download_repo` manually first.

### Performance and scope

**Download takes too long** — Use a path prefix to scope: `apache/airflow/airflow-core/src` instead of `apache/airflow`. The pipeline already uses tarball downloads, so this is rarely an issue, but a tighter scope still saves processing time downstream.

**Too many findings** — Use `severityThreshold="HIGH"` or `"CRITICAL"`. If false positives are the issue rather than severity, upload audit guidance — see [Audit guidance](#audit-guidance).

**Discovery runs Sonnet on far more sections than the level requires** — Confirm the orchestrator is passing `level` down to `asvs_discover`. The log should read `Filtered ASVS sections to level L1: N included, M dropped above L1` before the classification call. If not, the orchestrator-to-discover wiring is missing the level parameter.

### Filter and guidance

**`_review_queue.md` has items you'd expect to be high-confidence drops** — The filter dropped them based on inference rather than an explicit policy statement. Upload a guidance file that explicitly names the policy (see the `apache/airflow` example). Re-running will re-triage and the items should move to high-confidence drops in `_filter_drop_log.md`.

**`_suggested_audit_guidance.md` says "No clusters of size >= 3 found" but you see a pattern repeating across runs** — The filter clusters per-run only. Cross-run patterns won't surface there. Either lower `min_cluster` in `_build_suggested_guidance_md` (more noise) or hand-write the guidance file by observing the review queue across runs.

**Filter cache didn't invalidate after guidance change** — The filter cache key includes the profile hash. If the hash didn't change, the guidance text didn't reach the namespace. Verify the upload landed: `_find` against `audit_guidance:{repo}`. If you uploaded to the wrong namespace name, the filter won't see it.

### Push failures

**Many sections show `stored` in the audit phase but the filter or consolidator can't find them** — Per-section reports are in CouchDB now, not GitHub. Check the `audit-reports:{output_dir}` namespace, not a directory listing on GitHub.

**`push failed: GitHub: is at <SHA1> but expected <SHA2>`** — GitHub's contents API serializes commits to a branch — every commit must reference the current branch HEAD. When two PUTs race, the loser gets 409 Conflict even when targeting different files. The push agent retries up to 5 times with exponential backoff, but at high concurrency the same races repeat across retries. Default `GITHUB_PUSH_CONCURRENCY=1` eliminates the race by serializing all pushes; this adds wall-clock time but is fully deterministic. If you raise this, expect occasional 409s after retries are exhausted.

**`push failed: ConnectTimeout (no detail)`** — TCP connection to GitHub couldn't be established within httpx's connect timeout. The push agent uses 15-second connect timeout and 3 transport-level retries by default, which handles most transient flakiness. If you see persistent ConnectTimeouts, the gofannon worker's network path to api.github.com is the bottleneck — check container DNS, egress proxy, or VPN configuration. Lowering `GITHUB_PUSH_CONCURRENCY` reduces concurrent socket-establishment pressure and usually helps.

**`push failed:` with empty error message** — The httpx layer raised a connection-level exception (typically `RemoteProtocolError`, `ReadError`, `WriteError`) with no useful `str()`. Almost always GitHub abuse detection silently dropping connections under load. Lower `GITHUB_PUSH_CONCURRENCY` until the failures stop.

**`ERROR: <path>` in `asvs_consolidate` push step** — Status code and GitHub error body are logged on the same line. Look for `(403)` or `(422)` from secondary rate-limit / abuse-detection responses, or `(401)` from a missing/invalid token.

**Reports not on GitHub** — Check `outputToken` has write access to `outputRepo`. The orchestrator's completion summary now tracks individual push success, so a missing report should show as an explicit failure rather than a silent miss.

### Audit-phase issues

**Audit runs report way more sections than expected for the requested level** — Discovery may be hallucinating section IDs that pass through a permissive level filter. Both `asvs_discover` and `asvs_orchestrate` should be dropping unknowns; check the validation logs (`dropping N hallucinated section(s)` and `WARNING: dropping N unknown section ID(s)`).

**`WARNING: No data found for asvs:requirements:X.Y.Z` during audit** — A section ID slipped past validation. Check whether ASVS data is fully loaded into the `asvs` namespace, and whether the orchestrator's `dropping unknown section ID` warning fired during work-list construction.

**`include_files filter matched 0 keys, falling back to unfiltered list`** — Discovery emitted patterns that don't match anything in the namespace. Causes: hallucinated paths from Sonnet, wrong path prefix, fnmatch's `**` quirk, or repo-layout drift. The audit/bundle agents fall back to the full file list rather than running on nothing, so the audit still happens, but downstream relevance might be poor. Re-run with `clearCache=true` if the layout changed; otherwise check discovery's pattern emission.

**A bundled report has stub sections saying "no output produced"** — This means `asvs_bundle`'s splitter couldn't find a `## ASVS-{section}:` header for that section in Opus's output. Usually safe to retry; if it persists, the bundle is too large — drop `BUNDLE_MAX_SECTIONS` to 4 or call those sections individually via `asvs_audit`.

**Bundle agent returned an error from `asvs_audit`** — If you tried to call `asvs_audit` with `asvs_sections` as a list of multiple sections, you'll get an error directing you to `asvs_bundle`. Either pass a single section as `asvs` or call `asvs_bundle` instead.

### Consolidation issues

**`Total extracted findings: 0` even though per-section reports clearly contain findings** — Phase 2 of `asvs_consolidate` is failing to extract JSON. Check Phase 2 logs for `WARNING: no JSON found (response begins: ...)`. The first 200 chars of the response are logged when extraction fails. If the response starts with prose preamble or a different JSON shape, the extraction prompt or `_extract_finding_json` schema-keys may need updating.

**`Commit: N/A` in the metadata table** — The commit extractor scans `output_directory` in reverse for a 7+ char hex segment. If the orchestrator didn't pass an output_directory containing the commit (older orchestrator version, or a custom path layout), it stays `N/A`. Confirm the run log shows `Output directory: ASVS/reports/.../{commit_hash}` before consolidate runs.

**Cross-reference matrix file paths look wrong** — The deterministic builder uses `affected_files` from the finding objects verbatim. If they're wrong, the audit agent emitted them incorrectly, not the consolidator. Check the per-section report for the affected file list.

**ASVS chapter labels show v4 names** — Chapter names come from the `asvs` data store. If you're seeing v4 names like "V7: Error Handling and Logging" paired with v5 numbers, run `asvs_load_data` to refresh against v5.0.0.

### Carve-out / redaction

**`_redaction_warning_consolidated.md` appears in the private repo** — Redaction left residual Critical content. The orchestrator detected the leak and routed the leaky-with-banner version to private + a clean placeholder to public. Read the banner at the top of the quarantine file for the specific leak types and contexts. The public report won't expose the leak. The run summary lists this as a failure so it doesn't get hidden.

**Redacted report still shows Critical findings** — The redactor uses structured severity detection (Finding ID token, severity heading, `**Severity:**` field, `🔴 Critical` marker). If the consolidator's output format changed and none of these signals are present, redaction will skip those findings. Inspect the consolidated report for one of the supported severity markers. The post-redaction leak check should catch most format-drift cases and quarantine.

**Redacted report drops too many findings (Mediums and Lows missing)** — Older redaction logic used bare `\bCRITICAL\b` matching, which hit the word "critical" in prose and dropped non-Critical findings. Current implementation uses structured detection only. If you see this symptom, you may be running an older orchestrator — check the redactor regex.

### Code-level errors

**`"name '_X' is not defined"` in agent logs** — Helper at module level instead of inside `run`. Move it inside `run`'s `try:` block. See [Code conventions](#code-conventions) above.

### Email

**Email not delivered** — The email step uses `mail-relay.apache.org`. Only works from ASF infrastructure. Check the logs for SMTP errors.