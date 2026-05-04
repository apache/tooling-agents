# ASVS Security Audit Pipeline

Automated [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) compliance auditing for any GitHub-hosted codebase. The pipeline downloads source code, auto-discovers the architecture, runs per-requirement security analysis with Claude, and produces a consolidated report with deduplicated findings and ready-to-file GitHub issues.

Built on [Gofannon](https://github.com/The-AI-Alliance/gofannon) — see [docs/gofannon](../docs/gofannon/) for platform setup.

## Pipeline Flow

```
asvs_orchestrate                       (single entry point)
  │
  ├──▶ asvs_download_repo              (once — fetches source code)
  │
  ├──▶ asvs_discover                   (once — generates audit plan)
  │
  ├──▶ asvs_audit  / asvs_bundle       (× N — bundle when sections share scope)
  │    └──▶ asvs_push_github           (× N)
  │
  ├──▶ asvs_consolidate                (once — final report)
  │
  └──▶ redact + publish                (if privateRepo is set)
         ├──▶ read full reports from private repo
         ├──▶ strip Critical findings
         ├──▶ push redacted reports to public repo
         └──▶ email Critical summary to PMC
```

The orchestrator routes audit work between two agents:
- **`asvs_audit`** — single-section audit (one ASVS requirement at a time)
- **`asvs_bundle`** — multi-section audit (multiple ASVS requirements sharing a file scope, in one Opus pass)

When `asvs_discover` produces a domain pass with several sections targeting the same files, the orchestrator chunks them and routes each chunk to `asvs_bundle` instead of making N separate `asvs_audit` calls. This is the largest single performance optimization in the pipeline (~5–6× reduction in Opus calls per domain).

Pre-requisites (one-time, outside the pipeline):
- ASVS requirements loaded into the `asvs` data store namespace
- Optionally: audit guidance loaded via `fetch_audit_guidance` (see [`audit_guidance/README.md`](audit_guidance/README.md) for how to write guidance for new projects)

## Quick Start

Run `asvs_orchestrate` with:

| Input | Value |
|---|---|
| `sourceRepo` | `apache/airflow` |
| `outputRepo` | `apache/tooling-agents` |
| `outputToken` | `ghp_...` |
| `outputDirectory` | `ASVS/reports` |
| `level` | `L2` |
| `severityThreshold` | `HIGH` |

That's it. The orchestrator downloads the code, fetches the latest commit hash, discovers the architecture, runs all audits, pushes reports, and consolidates. The output directory is automatically extended with the repo name and commit hash: `ASVS/reports/airflow/da901ba`.

To audit a subdirectory of a large repo:

| Input | Value |
|---|---|
| `sourceRepo` | `apache/airflow/airflow-core/src` |

This downloads only files under `airflow-core/src/`.

## Reports

Reports are organized by project, path (if scoped), and commit hash:

```
reports/
├── tooling-trusted-releases/
│   └── da901ba/
│       ├── consolidated-L1-L2.md
│       └── issues-L1-L2.md
└── steve/
    └── v3/
        └── d0aa7e9/
            ├── auth_identity/
            │   ├── 6.1.1.md
            │   └── 7.1.1.md
            ├── secrets_crypto/
            │   └── 9.1.1.md
            ├── consolidated.md       ← THE REPORT
            └── issues.md             ← GitHub issues, one per finding
```

## Level System

| Input | Requirements audited |
|---|---|
| `L1` | L1 only |
| `L2` | L1 + L2 |
| `L3` | L1 + L2 + L3 (all) |
| (empty) | L1 + L2 + L3 (all) |

## Severity Threshold

| Input | Findings included |
|---|---|
| `CRITICAL` | Critical only |
| `HIGH` | Critical + High |
| `MEDIUM` | Critical + High + Medium |
| (empty) | All findings |

## Architecture

The pipeline uses Claude Sonnet for high-throughput parallel work (code inventory, formatting, extraction, consolidation), Claude Haiku for cheap classification (relevance filtering), and Claude Opus for deep security analysis where reasoning quality matters most.

The discovery agent scans the codebase architecture and generates security domains — groupings of ASVS requirements by the code area they test (e.g., `auth_identity`, `secrets_crypto`, `web_input_validation`). Each domain gets its own file list, so the audit agents only analyze relevant code. ASVS sections not assigned by discovery are caught by a fallback that groups them by ASVS chapter.

When a domain has multiple sections sharing the same file scope, the orchestrator dispatches them as a bundle to `asvs_bundle`. Bundling produces one Opus reasoning trace covering all requirements in the bundle, then splits the response into per-section reports for downstream consolidation. The audit phase as a whole runs with bounded parallelism — multiple sections/bundles in flight at once via `PASS_CONCURRENCY` (default 4).

The consolidation agent reads all per-section reports from GitHub, extracts findings into structured JSON, deduplicates within and across domains, generates deterministic cross-references, and produces the final consolidated report with executive summary and issues file.

## Critical Finding Carve-Out

When `privateRepo` is set, Critical findings never touch the public repo — not even in git history. The flow is:

1. All per-section reports and the consolidated report are pushed to the **private** repo
2. The orchestrator reads everything back from the private repo
3. Critical findings are stripped from the consolidated report, issues file, and per-section reports
4. Redacted versions are pushed to the **public** repo
5. A summary of Critical findings is emailed to the PMC's private mailing list (if `notifyEmail` is set)

The public report includes a notice: "N Critical findings have been redacted from this report and forwarded to the project's PMC private mailing list."

When `privateRepo` is absent, all reports go directly to `outputRepo` (current behavior, no redaction).

---

## Agent Reference

All gofannon inputs are strings.

### 1. asvs_orchestrate

The main entry point. Calls all other agents.

| Input | Required | Description |
|---|---|---|
| `sourceRepo` | yes | Source code to audit. Accepts `owner/repo`, `owner/repo/subdir`, or full GitHub URL like `https://github.com/owner/repo/tree/branch/subdir` |
| `sourceToken` | no | PAT for private source repos |
| `supplementalData` | no | Extra data store namespaces, comma-separated (e.g., `audit_guidance`) |
| `outputRepo` | yes | GitHub repo for public reports (`owner/repo`) |
| `outputToken` | yes | PAT with write access to output repo |
| `outputDirectory` | yes | Base directory — repo name and commit hash are appended automatically |
| `discover` | no | `"true"` or `"false"` (default `"true"`) |
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default empty, treated as L3 — use `"L1"` for a quick baseline audit) |
| `severityThreshold` | no | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or empty |
| `consolidate` | no | `"true"` or `"false"` (default `"true"`) |
| `privateRepo` | no | Private repo for full unredacted reports (enables carve-out) |
| `privateToken` | no | PAT with write access to private repo (required when `privateRepo` is set) |
| `notifyEmail` | no | Email address for Critical findings (e.g., `private@steve.apache.org`) |

**Output:** `outputText` — combined audit results.

**Namespace derivation:** The orchestrator parses `sourceRepo` to derive the code namespace automatically. `apache/airflow` → `files:apache/airflow`. If `supplementalData` is `audit_guidance`, the namespace list becomes `["files:apache/airflow", "audit_guidance"]`.

**Performance knobs (env vars on the orchestrator):**

| Env var | Default | Purpose |
|---|---|---|
| `PASS_CONCURRENCY` | `4` | Max audit calls in flight simultaneously (sections + bundles) |
| `BUNDLE_MAX_SECTIONS` | `6` | Max ASVS sections per `asvs_bundle` call |
| `BUNDLE_MIN_SECTIONS` | `2` | Below this, a pass falls back to single-section `asvs_audit` calls |
| `TINY_REPO_LOC_THRESHOLD` | `30000` | Skip `asvs_discover` for repos under this LOC |

Set `BUNDLE_MAX_SECTIONS=1` to disable bundling entirely (for rollback testing). The `asvs_bundle` agent stays registered but is never called.

**Agents called:**
1. `asvs_download_repo` — downloads source code
2. `asvs_discover` — generates audit plan (if `discover="true"` and the repo isn't tiny)
3. `asvs_audit` — once per ASVS section that's not bundled
4. `asvs_bundle` — once per bundle of sections sharing a file scope
5. `asvs_push_github` — once per section, plus consolidated/issues
6. `asvs_consolidate` — final report (if `consolidate="true"`)

---

### 2. asvs_download_repo

Downloads a GitHub repo (or subdirectory) into the data store.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | `owner/repo` or `owner/repo/subdir`, optional token on next line |

**Output:** `outputText` — download summary.

Stores files in namespace `files:{owner}/{repo}`. When a path prefix is included (e.g., `apache/airflow/airflow-core/src`), only files under that path are downloaded. File paths in the data store are preserved as full repo-relative paths.

Uses GitHub's tarball endpoint for the download (one HTTP call) — much faster than per-file fetches and uses far less of the GitHub API quota.

---

### 3. asvs_discover

Scans codebase, generates domains + file lists + false positive guidance.

| Input | Required | Description |
|---|---|---|
| `inputNamespace` | yes | Data store namespace(s) with code, comma-separated |

**Output:** `outputText` — JSON passConfig containing `passes`, `domain_groups`, `false_positive_guidance`.

Each pass in the output describes a group of ASVS sections that share a file scope. The orchestrator uses these passes to route work to either `asvs_audit` (single) or `asvs_bundle` (multi).

---

### 4. asvs_audit

Audits code against a single ASVS requirement. Used for one-off audits and for sections that don't fit into a bundle.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON string (see fields below) |

JSON fields inside `inputText`:

| Field | Required | Description |
|---|---|---|
| `namespaces` | yes | Array of data store namespaces (singular `namespace` also accepted) |
| `asvs` | yes | ASVS section (e.g., `"6.1.1"`) — alias `asvs_section` also accepted |
| `includeFiles` | no | Array of file glob patterns — skips relevance filtering |
| `domainContext` | no | Architecture context for Opus prompt |
| `severityThreshold` | no | Minimum severity to report |
| `falsePositiveGuidance` | no | Array of patterns to suppress |

If `inputText` isn't valid JSON, the agent falls back to regex-parsing `namespace:` and `asvs:` keys out of free-form text.

**Output:** `outputText` — markdown audit report.

**Note:** If you pass `asvs_sections` as a list with more than one entry, this agent will return an error directing you to use `asvs_bundle` instead.

---

### 5. asvs_bundle

Audits code against MULTIPLE ASVS requirements in a single Opus deep-analysis call. Used by the orchestrator whenever a domain pass has 2+ sections sharing the same file scope.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON string (see fields below) |

JSON fields inside `inputText`:

| Field | Required | Description |
|---|---|---|
| `namespaces` | yes | Array of data store namespaces |
| `asvs_sections` | yes | Array of ASVS section IDs (e.g., `["5.1.1", "5.1.2", "5.1.3"]`) |
| `includeFiles` | no | Array of file glob patterns — skips relevance filtering |
| `domainContext` | no | Architecture context for Opus prompt (shared across all sections) |
| `severityThreshold` | no | Minimum severity to report |
| `falsePositiveGuidance` | no | Array of patterns to suppress |

**Output:** `outputText` — JSON envelope with the structure:

```json
{
  "mode": "bundled",
  "asvs_sections": ["5.1.1", "5.1.2", ...],
  "per_section": {
    "5.1.1": {
      "report": "<full markdown report for this section>",
      "findings": {"Critical": 2, "High": 5, "Medium": 8, "Low": 1},
      "files_analyzed": 42,
      "files_total": 187,
      "files_skipped": 12
    },
    "5.1.2": { ... }
  },
  "raw_consolidated": "<full markdown before splitting>",
  "metadata": { "files_analyzed": 42, "opus_batches": 3, "..." }
}
```

The orchestrator decodes this envelope and pushes `per_section[X].report` to GitHub as `X.md` (one file per section, same as for `asvs_audit`). Downstream `asvs_consolidate` sees the same per-section report layout regardless of which agent produced them.

**How it works:** One Opus call with a system prompt listing all bundled ASVS reqs. Opus is instructed to use `## ASVS-{section}: <name>` headers per requirement. The agent splits the response on those headers; cross-cutting "Architecture Observations" and "Recommendations" sections at the end get attached to each per-section report. If Opus skips a section, the splitter emits a stub explaining that no findings were produced for it.

---

### 6. asvs_consolidate

Reads per-section reports from GitHub, deduplicates, produces consolidated report + issues.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | Multi-line: `repo:`, `pat:`, `directories:`, `output:` |
| `domainGroups` | no | JSON string mapping domain names to ASVS section arrays |
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default `"L3"` — use `"L1"` for a quick baseline audit) |
| `severityThreshold` | no | Included in report metadata when provided |

**Output:** `outputText` — summary. Pushes `consolidated.md` and `issues.md` to GitHub.

---

### 7. asvs_push_github

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

**Output:** `outputText` — GitHub API response.

---

## QA and Remediation

### Check for missing reports

After a run completes, compare the data store against the reports pushed to GitHub:

```bash
# 1. List all ASVS sections in the data store
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"asvs","key":{"$regex":"^asvs:requirements:"}}, "fields":["key"], "limit":999}' \
  | python3 -c "
import sys, json
docs = json.load(sys.stdin)['docs']
sections = sorted([d['key'].replace('asvs:requirements:','') for d in docs])
with open('/tmp/asvs_sections.txt', 'w') as f:
    for s in sections: f.write(s + '\n')
print(f'Data store: {len(sections)} sections')
"

# 2. List all report files on GitHub
REPO="apache/tooling-agents"
DIR="ASVS/reports/steve/v3/d0aa7e9"   # adjust to your run
TOKEN="ghp_..."

curl -s -H "Authorization: token $TOKEN" \
  "https://api.github.com/repos/$REPO/git/trees/main?recursive=1" \
  | python3 -c "
import sys, json, re
tree = json.load(sys.stdin).get('tree', [])
reports = set()
for item in tree:
    p = item.get('path', '')
    if p.startswith('$DIR/') and p.endswith('.md') and item['type'] == 'blob':
        fname = p.split('/')[-1].replace('.md', '')
        if re.match(r'^\d+\.\d+\.\d+$', fname):
            reports.add(fname)
with open('/tmp/github_reports.txt', 'w') as f:
    for s in sorted(reports): f.write(s + '\n')
print(f'GitHub reports: {len(reports)} sections')
"

# 3. Show missing
echo "=== Missing reports ==="
comm -23 /tmp/asvs_sections.txt /tmp/github_reports.txt
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

Audited sections are pushed to a `rerun/` subdirectory. The consolidator reads all subdirectories (including `rerun/`) and deduplicates findings across them.

Note that `rerun-sections.sh` calls `asvs_audit` directly (one section at a time), bypassing the orchestrator's bundling. This is intentional: when re-running just a few sections, the bundling overhead isn't worth it. If you need to re-run an entire domain, call `asvs_bundle` directly with `asvs_sections` as a list.

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
```

---

## Troubleshooting

**"sourceRepo is required"** — Provide `sourceRepo` as `owner/repo`, `owner/repo/subdir`, or a full GitHub URL.

**"privateToken is required when privateRepo is set"** — Provide a PAT with write access to the private repo.

**"No ASVS sections match level L1"** — Check that ASVS requirement entries have a `level` field.

**Download takes too long** — Use a path prefix to scope: `apache/airflow/airflow-core/src` instead of `apache/airflow`. (The pipeline already uses tarball downloads, so this is rarely an issue now — but a tighter scope still saves processing time downstream.)

**Too many findings** — Use `severityThreshold="HIGH"` or `"CRITICAL"`.

**Reports not on GitHub** — Check `outputToken` has write access to `outputRepo`.

**Email not delivered** — The email step uses `mail-relay.apache.org`. Only works from ASF infrastructure. Check the logs for SMTP errors.

**Redacted report still shows Critical findings** — The redaction regex looks for `🔴 Critical` and `CRITICAL` in finding blocks. If the consolidator's output format changed, the regex may need updating.

**Bundle agent returned an error from `asvs_audit`** — If you tried to call `asvs_audit` with `asvs_sections` as a list of multiple sections, you'll get an error directing you to `asvs_bundle`. Either pass a single section as `asvs` or call `asvs_bundle` instead.

**A bundled report has stub sections saying "no output produced"** — This means `asvs_bundle`'s splitter couldn't find a `## ASVS-{section}:` header for that section in Opus's output. Usually safe to retry; if it persists, the bundle is too large — drop `BUNDLE_MAX_SECTIONS` to 4 or call those sections individually via `asvs_audit`.

---

## Code conventions

### Helpers must live inside `run()`

Gofannon registers `run` as each agent's entrypoint and executes it in an environment where **module-level names defined alongside it are not in scope**. A helper at module level (e.g. `def _split_output():` at indent 0) will trigger `NameError: name '_split_output' is not defined` when `run` calls it.

All helpers in these agents are defined **inside `run`'s `try:` block at indent 8** — same convention as `parse_llm_json` in `asvs_consolidate`, which has worked correctly in production. When adding new helpers to any agent, define them inside `run`. Don't reach for module-level functions.

Quick pre-deploy check:

```bash
grep -cE "^(async )?def _" asvs_*.py | grep -v ":0$"
```

This should return nothing. If it lists any files with module-level `_` helpers, those will NameError at runtime.

### Discovery output must be validated against the data store

`asvs_discover` shows the LLM the full ASVS section list (no slicing) and validates the model's output against `valid_section_ids` from the `asvs` data store namespace. Hallucinated section IDs (the model inventing plausible-looking IDs like `2.4.5` to satisfy "every section must be assigned" constraints) are dropped before they reach the audit phase.

`asvs_orchestrate` independently validates: any section ID not in the authoritative ASVS data store is dropped from the audit plan with a warning, regardless of how it got into the discovery output. Belt-and-suspenders.

If you change discovery's output format or relax the validation, you risk audits running against nonexistent ASVS requirements (which then waste Opus calls and produce reports that consolidate can't match against the schema).

---

## More troubleshooting

**"name '_X' is not defined" in agent logs** — Helper at module level instead of inside `run`. Move it inside `run`'s `try:` block.

**Audit runs report way more sections than expected for the requested level** — Discovery may be hallucinating section IDs that pass through a permissive level filter. Both `asvs_discover` and `asvs_orchestrate` should be dropping unknowns; if they aren't, check the validation logs (`dropping N hallucinated section(s)` and `WARNING: dropping N unknown section ID(s)`).

**`Total extracted findings: 0` even though per-section reports clearly contain findings** — Phase 2 of `asvs_consolidate` is failing to extract JSON. Check Phase 2 logs for `WARNING: no JSON found (response begins: ...)`. The first 200 chars of the response are logged when extraction fails. If the response starts with prose preamble or a different JSON shape, the extraction prompt or `_extract_finding_json` schema-keys may need updating.

**`WARNING: No data found for asvs:requirements:X.Y.Z` during audit** — A section ID slipped past the validation. Check whether ASVS data is fully loaded into the `asvs` namespace, and whether the orchestrator's `dropping unknown section ID` warning fired during work-list construction.