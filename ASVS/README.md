# ASVS Security Audit Pipeline

Automated [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) compliance auditing for any GitHub-hosted codebase. The pipeline downloads source code, auto-discovers the architecture, runs per-requirement security analysis with Claude, and produces a consolidated report with deduplicated findings and ready-to-file GitHub issues.

Built on [Gofannon](https://github.com/The-AI-Alliance/gofannon) — see [docs/gofannon](../docs/gofannon/) for platform setup.

## Pipeline Flow

```
orchestrate_asvs_audit_to_github         (single entry point)
  │
  ├──▶ download_github_repo_to_datastore  (once — fetches source code)
  │
  ├──▶ discover_codebase_architecture     (once — generates audit plan)
  │
  ├──▶ run_asvs_security_audit            (× N sections)
  │    └──▶ add_markdown_file_to_github_directory  (× N)
  │
  ├──▶ consolidate_asvs_security_audit_reports  (once — final report)
  │
  └──▶ redact + publish                   (if privateRepo is set)
         ├──▶ read full reports from private repo
         ├──▶ strip Critical findings
         ├──▶ push redacted reports to public repo
         └──▶ email Critical summary to PMC
```

Pre-requisites (one-time, outside the pipeline):
- ASVS requirements loaded into the `asvs` data store namespace
- Optionally: audit guidance loaded via `fetch_audit_guidance` (see [`audit_guidance/README.md`](audit_guidance/README.md) for how to write guidance for new projects)

## Quick Start

Run `orchestrate_asvs_audit_to_github` with:

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

The pipeline uses Claude Sonnet for high-throughput parallel work (relevance filtering, code inventory, formatting, extraction, consolidation) and Claude Opus for deep security analysis where reasoning quality matters most.

The discovery agent scans the codebase architecture and generates security domains — groupings of ASVS requirements by the code area they test (e.g., `auth_identity`, `secrets_crypto`, `web_input_validation`). Each domain gets its own file list, so the audit agent only analyzes relevant code. ASVS sections not assigned by discovery are caught by a fallback that groups them by ASVS chapter.

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

### 1. orchestrate_asvs_audit_to_github

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
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default `"L3"` — use `"L1"` for a quick baseline audit) |
| `severityThreshold` | no | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or empty |
| `consolidate` | no | `"true"` or `"false"` (default `"true"`) |
| `privateRepo` | no | Private repo for full unredacted reports (enables carve-out) |
| `privateToken` | no | PAT with write access to private repo (required when `privateRepo` is set) |
| `notifyEmail` | no | Email address for Critical findings (e.g., `private@steve.apache.org`) |

**Output:** `outputText` — combined audit results.

**Namespace derivation:** The orchestrator parses `sourceRepo` to derive the code namespace automatically. `apache/airflow` → `files:apache/airflow`. If `supplementalData` is `audit_guidance`, the namespace list becomes `["files:apache/airflow", "audit_guidance"]`.

**Agents called:**
1. `download_github_repo_to_datastore` — downloads source code
2. `discover_codebase_architecture` — generates audit plan (if `discover="true"`)
3. `run_asvs_security_audit` — once per ASVS section
4. `add_markdown_file_to_github_directory` — once per section, plus consolidated/issues
5. `consolidate_asvs_security_audit_reports` — final report (if `consolidate="true"`)

---

### 2. download_github_repo_to_datastore

Downloads a GitHub repo (or subdirectory) into the data store.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | `owner/repo` or `owner/repo/subdir`, optional token on next line |

**Output:** `outputText` — download summary.

Stores files in namespace `files:{owner}/{repo}`. When a path prefix is included (e.g., `apache/airflow/airflow-core/src`), only files under that path are downloaded. File paths in the data store are preserved as full repo-relative paths.

---

### 3. discover_codebase_architecture

Scans codebase, generates domains + file lists + false positive guidance.

| Input | Required | Description |
|---|---|---|
| `inputNamespace` | yes | Data store namespace(s) with code, comma-separated |

**Output:** `outputText` — JSON passConfig containing `passes`, `domain_groups`, `false_positive_guidance`.

---

### 4. run_asvs_security_audit

Audits code against a single ASVS requirement.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON string (see fields below) |

JSON fields inside `inputText`:

| Field | Required | Description |
|---|---|---|
| `namespaces` | yes | Array of data store namespaces |
| `asvs` | yes | ASVS section (e.g., `"6.1.1"`) |
| `includeFiles` | no | Array of file glob patterns — skips relevance filtering |
| `domainContext` | no | Architecture context for Opus prompt |
| `severityThreshold` | no | Minimum severity to report |
| `falsePositiveGuidance` | no | Array of patterns to suppress |

**Output:** `outputText` — markdown audit report.

---

### 5. consolidate_asvs_security_audit_reports

Reads per-section reports from GitHub, deduplicates, produces consolidated report + issues.

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | Multi-line: `repo:`, `pat:`, `directories:`, `output:` |
| `domainGroups` | no | JSON string mapping domain names to ASVS section arrays |
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default `"L3"` — use `"L1"` for a quick baseline audit) |
| `severityThreshold` | no | Included in report metadata when provided |

**Output:** `outputText` — summary. Pushes `consolidated.md` and `issues.md` to GitHub.

---

### 6. add_markdown_file_to_github_directory

| Input | Required | Description |
|---|---|---|
| `inputText` | yes | JSON with `repo`, `token`, `directory`, `filename` |
| `commitMessage` | yes | Git commit message |
| `fileContents` | yes | Markdown content |

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

**Download takes too long** — Use a path prefix to scope: `apache/airflow/airflow-core/src` instead of `apache/airflow`.

**Too many findings** — Use `severityThreshold="HIGH"` or `"CRITICAL"`.

**Reports not on GitHub** — Check `outputToken` has write access to `outputRepo`.

**Email not delivered** — The email agent uses `mail-relay.apache.org`. Only works from ASF infrastructure. Check the logs for SMTP errors.

**Redacted report still shows Critical findings** — The redaction regex looks for `🔴 Critical` and `CRITICAL` in finding blocks. If the consolidator's output format changed, the regex may need updating.