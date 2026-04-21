# ASVS Security Audit Pipeline

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
  └──▶ consolidate_asvs_security_audit_reports  (once — final report)
```

Pre-requisites (one-time, outside the pipeline):
- ASVS requirements loaded into the `asvs` data store namespace
- Optionally: audit guidance loaded via `fetch_audit_guidance`

## Quick Start

Run `orchestrate_asvs_audit_to_github` with:

| Input | Value |
|---|---|
| `sourceRepo` | `apache/airflow` |
| `outputRepo` | `apache/tooling-runbooks` |
| `outputToken` | `ghp_...` |
| `outputDirectory` | `ASVS/reports` |
| `level` | `L2` |
| `severityThreshold` | `HIGH` |

That's it. The orchestrator downloads the code, fetches the latest commit
hash, discovers the architecture, runs all audits, pushes reports, and
consolidates. The output directory is automatically extended with the
repo name and commit hash: `ASVS/reports/airflow/da901ba`.

To audit a subdirectory of a large repo:

| Input | Value |
|---|---|
| `sourceRepo` | `apache/airflow/airflow-core/src` |

This downloads only files under `airflow-core/src/`.

## Reports Location

```
ASVS/reports/airflow/da901ba/       ← auto-generated from repo + HEAD commit
├── auth_identity/                  ← per-domain subdirectories
│   ├── 6.1.1.md
│   └── 7.1.1.md
├── secrets_crypto/
│   └── 9.1.1.md
├── consolidated.md                 ← THE REPORT
└── issues.md                       ← GitHub issues, one per finding
```

## Level System

| Input | Requirements audited |
|---|---|
| `L1` | L1 only |
| `L2` | L1 + L2 |
| `L3` | L1 + L2 + L3 (all) |

## Severity Threshold

| Input | Findings included |
|---|---|
| `CRITICAL` | Critical only |
| `HIGH` | Critical + High |
| `MEDIUM` | Critical + High + Medium |
| (empty) | All findings |

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
| `outputRepo` | yes | GitHub repo for reports (`owner/repo`) |
| `outputToken` | yes | PAT with write access to output repo |
| `outputDirectory` | yes | Base directory — repo name and commit hash are appended automatically |
| `discover` | no | `"true"` or `"false"` (default `"true"`) |
| `level` | no | `"L1"`, `"L2"`, or `"L3"` |
| `severityThreshold` | no | `"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, or empty |
| `consolidate` | no | `"true"` or `"false"` (default `"true"`) |

**Output:** `outputText` — combined audit results.

**Namespace derivation:** The orchestrator parses `sourceRepo` to derive the code namespace automatically. `apache/airflow` → `files:apache/airflow`. If `supplementalData` is `audit_guidance`, the namespace list becomes `["files:apache/airflow", "audit_guidance"]`.

**Agents called:**
1. `download_github_repo_to_datastore` — downloads source code
2. `discover_codebase_architecture` — generates audit plan (if `discover="true"`)
3. `run_asvs_security_audit` — once per ASVS section
4. `add_markdown_file_to_github_directory` — once per section
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
| `level` | no | `"L1"`, `"L2"`, or `"L3"` (default `"L3"`) |

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

## Troubleshooting

**"sourceRepo is required"** — Provide `sourceRepo` as `owner/repo`, `owner/repo/subdir`, or a full GitHub URL.

**"No ASVS sections match level L1"** — Check that ASVS requirement entries have a `level` field.

**Download takes too long** — Use a path prefix to scope: `apache/airflow/airflow-core/src` instead of `apache/airflow`.

**Too many findings** — Use `severityThreshold="HIGH"` or `"CRITICAL"`.

**Reports not on GitHub** — Check `outputToken` has write access to `outputRepo`.