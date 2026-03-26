# ASVS Security Audit Pipeline

Automated security auditing of the ATR codebase against [OWASP ASVS v5.0.0](https://owasp.org/www-project-application-security-verification-standard/), built on the [Gofannon](https://github.com/The-AI-Alliance/gofannon) agent framework.

## Table of contents

- [Overview](#overview)
- [Pipeline architecture](#pipeline-architecture)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Agents](#agents)
- [Running the pipeline](#running-the-pipeline)
- [Output structure](#output-structure)
- [Data store reference](#data-store-reference)
- [Cache management](#cache-management)
- [Troubleshooting](#troubleshooting)
- [Operational notes](#operational-notes)

## Overview

The pipeline automates deep security analysis of ATR source code against individual ASVS requirements. For each requirement, an LLM-based agent reads the codebase, filters for relevant files, builds a code inventory, runs deep analysis with Claude Opus, and produces a structured markdown report. Reports are pushed to GitHub, then a consolidation agent merges findings across requirements and ASVS levels into a single report with deduplicated issues.

The pipeline uses two model tiers: Claude Sonnet for high-throughput parallel work (relevance filtering, inventory, formatting, extraction, consolidation) and Claude Opus for deep security analysis where reasoning quality matters most.

### What it produces

For each ASVS requirement (e.g., `7.2.1`), an individual audit report is pushed to a GitHub directory (e.g., `security/ASVS/reports/{commit}/L2/7.2.1.md`). After all individual reports are complete, a consolidation agent reads them all, deduplicates findings across requirements and ASVS levels, and produces:

- **consolidated-L1-L2.md** — full consolidated report with executive summary, all findings by severity, positive controls, ASVS compliance table, and cross-reference matrix
- **issues-L1-L2.md** — GitHub-issue-formatted findings with labels, acceptance criteria, and remediation guidance

## Pipeline architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Orchestrator Agent                        │
│  Loops over comma-separated ASVS sections, calls audit agent,   │
│  then pushes each report to GitHub                               │
└──────────┬──────────────────────────────────────┬───────────────┘
           │ for each section                     │ after analysis
           ▼                                      ▼
┌─────────────────────────┐          ┌─────────────────────────┐
│   Audit Agent            │          │  GitHub Push Agent       │
│   (run_asvs_security_   │          │  (add_markdown_file_to_ │
│    audit)                │          │   github_directory)      │
│                          │          └─────────────────────────┘
│  Step 0: Load ASVS ctx  │
│  Step 1: Read files      │
│  Step 2: Relevance filter│  ← Sonnet (parallel, cached)
│  Step 3: Code inventory  │  ← Sonnet (parallel, cached)
│  Step 4: Deep analysis   │  ← Opus (medium reasoning, cached)
│  Step 5: Consolidate     │  ← Sonnet (if >1 batch)
│  Step 6: Format report   │  ← Sonnet
└─────────────────────────┘

           ┌──────────────────────────────────────┐
           │       Consolidation Agent             │
           │  Reads individual reports from GitHub │
           │  Extracts → Deduplicates → Generates  │
           │  consolidated report + issues file     │
           └──────────────────────────────────────┘
```

### Agents

See [`agents/`](agents/) for the complete list of 9 pipeline agents with their roles and pipeline steps.

## Prerequisites

- A running Gofannon instance (see [Gofannon guide](../../../docs/gofannon/) for setup)
- AWS credentials with Bedrock access (for Claude Sonnet and Opus)
- GitHub Personal Access Token with repo write permissions
- The target repositories must be accessible via GitHub API

## Setup

For Gofannon platform setup (Docker, `.env` configuration, CouchDB, agent creation walkthrough), see the [Gofannon guide](../../../docs/gofannon/).

### Model access

The pipeline uses these Bedrock models:

| Role | Model | Used for |
|------|-------|----------|
| Fast (Sonnet) | `us.anthropic.claude-sonnet-4-5-20250929-v1:0` | Relevance filtering, inventory, formatting, extraction, consolidation |
| Heavy (Opus) | `us.anthropic.claude-opus-4-6-v1` | Deep security analysis (Step 4) |

Ensure your AWS credentials have `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream` permissions for both models.

### Deploy the agents

Agent code and prompts are in the [`agents/`](agents/) directory. For each agent:

1. Create the agent in the Gofannon UI (http://localhost:3000)
2. Paste the contents of `prompt.md` as the description
3. Generate code, then replace it with the contents of `code.py`
4. Deploy

## Agents

### `ingest_asvs_standard`

Fetches ASVS v5.0.0 from `https://cdn.asvs.ee/standards/v5.0.0.json` and ingests all chapters, sections, and requirements into the `asvs` namespace of the data store. Also creates index records for efficient lookup.

**Input:** None (the URL is hardcoded).

**Data store writes:**
- `asvs:chapters:{ch_id}` — chapter metadata (name, control objective, references)
- `asvs:sections:{sec_id}` — section metadata (name, description, parent chapter)
- `asvs:requirements:{req_id}` — requirement details (description, level, parent section/chapter)
- `asvs:section_index:{sec_id}` — list of requirement IDs in a section
- `asvs:chapter_sections_index:{ch_id}` — list of section IDs in a chapter
- `asvs:chapter_reqs_index:{ch_id}` — list of requirement IDs in a chapter

**Notes:**
- The CDN JSON covers ASVS 5.0.0 sections up through 10.4. Sections 10.5 (OIDC Client), 10.6 (OpenID Provider), and 10.7 (Consent Management) are from the bleeding-edge master branch and may require manual ingestion if not yet present in the CDN JSON.
- The agent uses `set_many` so it's safe to re-run — it overwrites existing records.
- After ingestion, verify with: `curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" -H "Content-Type: application/json" -d '{"selector":{"namespace":"asvs","key":{"$regex":"^asvs:requirements:"}},"fields":["key"],"limit":1}' | python3 -c "import sys,json; print(len(json.load(sys.stdin)['docs']), 'requirements')"`

### `download_github_repo_to_datastore`

Downloads all files from a GitHub repository into the data store, organized into a namespace derived from the repo path.

**Input (line-based):**
```
apache/tooling-trusted-releases
ghp_your_github_token
```

**Data store writes:** Files stored in namespace `files:apache/tooling-trusted-releases` with keys being file paths (e.g., `atr/api/__init__.py`).

**Run this for each target repository:**
```
apache/tooling-trusted-releases
apache/infrastructure-asfquart
apache/infrastructure-asfpy
```

### `fetch_audit_guidance`

Downloads a subdirectory from a GitHub repo. Used for loading audit guidance documents and configuration files.

**Input (line-based):**
```
apache/tooling-agents
audit_guidance
ghp_your_github_token
```

**Data store writes:** Files stored in namespace `audit_guidance` with keys being file paths.

### `run_asvs_security_audit` (Audit Agent)

The core analysis agent. For a single ASVS requirement, reads all source code from the data store, identifies relevant files, builds a code inventory, runs deep Opus analysis, and produces a formatted markdown report.

**Input:** The orchestrator passes `asvs`, `repos`, and `namespaces` fields.

**Pipeline steps:**

| Step | Model | Concurrency | Caching | Description |
|------|-------|-------------|---------|-------------|
| 0 | — | — | — | Load ASVS requirement context from data store (`asvs` namespace) |
| 1 | — | — | — | Read all files from data store namespaces |
| 2 | Sonnet | Parallel batches | `audit-cache:relevance:` | Score every file 1-10 for relevance to the ASVS requirement; keep files scoring ≥4 |
| 3 | Sonnet | Parallel batches | `audit-cache:inventory:` | For each relevant file, extract imports, classes, functions, security patterns, routes, config |
| 4 | Opus | Sequential batches | `audit-cache:analysis:` | Deep security analysis with `reasoning_effort=medium`, `max_tokens=64000` |
| 5 | Sonnet | Single call | — | If >1 Opus batch, consolidate results into unified analysis |
| 6 | Sonnet | Single call | — | Format into clean markdown report with metadata header |

**Key tuning parameters:**
- Opus: `reasoning_effort=medium`, `max_tokens=64000` — balances quality against Bedrock timeout risk
- Inventory capping: always limited to 15% of Opus safe context limit (~12,000 tokens)
- Relevance filtering: 2 retries with 5s backoff; on total failure, falls back to score=5 for all files
- Opus analysis: 3 retries with 15s/30s/45s backoff
- Dynamic audit date (from `date.today()`)
- ASVS requirement description included in report output (truncated to 500 chars)
- Report metadata: repo name extracted from data store namespaces, "Tooling Agents" as auditor

### Orchestrator Agent

Loops over a comma-separated list of ASVS sections, calling the audit agent for each, then pushing the resulting report to GitHub.

**Input:**
```
asvs: 1.2.1,1.2.2,1.2.3
repos: apache/tooling-trusted-releases
namespaces: files:apache/tooling-trusted-releases,files:apache/infrastructure-asfquart,files:apache/infrastructure-asfpy,audit_guidance,config,open_issues
token: ghp_your_github_token
owner/repo: apache/tooling-runbooks
directory: security/ASVS/reports/{commit}/L2
```

For each section, the orchestrator:
1. Calls `run_asvs_security_audit` with the section and repo context
2. Calls `add_markdown_file_to_github_directory` to push `{section}.md` to the specified directory
3. Commits with message `Add ASVS audit for section {section}`

### Consolidation Agent

Reads individual audit reports from one or more GitHub directories (one per ASVS level), extracts findings, deduplicates across sections and levels, and generates a consolidated report and issues file.

**Input:**
```
repo: apache/tooling-runbooks
token: ghp_your_github_token
directories: security/ASVS/reports/{commit}/L1, security/ASVS/reports/{commit}/L2
```

**Pipeline phases:**

| Phase | Model | Description |
|-------|-------|-------------|
| 1 | — | Read all `.md` reports from all directories (skips `consolidated*` and `issues*` files) |
| 2 | Sonnet (5 concurrent) | Extract structured findings from each report into JSON |
| 2.5 | — | Enrich findings with ASVS requirement context from data store |
| 3 | Sonnet (3 concurrent) | Domain-grouped consolidation with deduplication |
| 4 | Opus (exec summary) + Sonnet (findings, tail) | Generate final report in batches |
| 4b | Sonnet (batched, 3 retries) | Generate issues file |

**Key features:**
- Multi-directory input with level tracking (`L1:7.2.1.md`, `L2:7.2.1.md`)
- Findings carry `asvs_levels` throughout (e.g., `["L1", "L2"]` or `["L2"]` for L2-only)
- Issues include `asvs-level:L1` / `asvs-level:L2` labels
- Domain grouping with chapter-to-domain fallback for L2/L3 sections not in the explicit L1 map
- Output files named with levels: `consolidated-L1-L2.md`, `issues-L1-L2.md`
- Output directory is one level up from input directories (e.g., `security/ASVS/reports/{commit}/`)
- MAX_FINDINGS_PER_BATCH = 30 for report formatting; ISSUES_BATCH_SIZE = 75
- Quality checks: finding count verification, level analysis, report representation analysis, dedup aggressiveness warning (>20% reduction)

## Running the pipeline

### Step 1: Ingest ASVS requirements

Run the `ingest_asvs_standard` agent (no input needed). Verify:

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"asvs","key":{"$regex":"^asvs:chapters:"}},"fields":["key","value"],"limit":20}' \
  | python3 -c "
import sys, json
docs = json.load(sys.stdin)['docs']
print(f'{len(docs)} chapters ingested')
for d in sorted(docs, key=lambda x: int(x['key'].split(':')[-1])):
    print(f'  {d[\"key\"]}: {d[\"value\"][\"chapter_name\"]}')"
```

### Step 2: Download source code

Run `download_github_repo_to_datastore` three times, once per repository:

```
apache/tooling-trusted-releases
ghp_your_token
```

```
apache/infrastructure-asfquart
ghp_your_token
```

```
apache/infrastructure-asfpy
ghp_your_token
```

Optionally download audit guidance:

```
apache/tooling-agents
audit_guidance
ghp_your_token
```

### Step 3: Run the orchestrator

For L1 requirements (example subset):

```
asvs: 1.2.1,1.2.2,1.2.3,1.2.4,1.2.5,1.3.1,1.3.2,1.5.1,2.1.1,2.2.1,2.2.2,2.3.1,3.2.1,3.2.2,3.3.1,3.4.1,3.4.2,3.5.1,3.5.2,3.5.3,4.1.1,4.4.1,5.2.1,5.2.2,5.3.1,5.3.2,6.1.1,6.2.1,6.2.2,6.2.3,6.2.4,6.2.5,6.2.6,6.2.7,6.2.8,6.3.1,6.3.2,6.4.1,6.4.2,7.2.1,7.2.2,7.2.3,7.2.4,7.4.1,7.4.2,8.1.1,8.2.1,8.2.2,8.3.1,9.1.1,9.1.2,9.1.3,9.2.1,10.4.1,10.4.2,10.4.3,10.4.4,10.4.5,11.3.1,11.3.2,11.4.1,12.1.1,12.2.1,12.2.2,13.4.1,14.2.1,14.3.1,15.1.1,15.2.1,15.3.1
repos: apache/tooling-trusted-releases
namespaces: files:apache/tooling-trusted-releases,files:apache/infrastructure-asfquart,files:apache/infrastructure-asfpy,audit_guidance,config,open_issues
token: ghp_your_token
owner/repo: apache/tooling-runbooks
directory: security/ASVS/reports/{commit}/L1
```

For L2 requirements, use the same format with L2 section IDs and `directory: .../L2`.

**Expect each section to take 5-15 minutes** depending on codebase relevance and number of Opus batches. A full L2 run of ~183 sections takes 24-48 hours.

### Step 4: Run consolidation

After all individual reports are pushed:

```
repo: apache/tooling-runbooks
token: ghp_your_token
directories: security/ASVS/reports/{commit}/L1, security/ASVS/reports/{commit}/L2
```

## Output structure

```
security/ASVS/reports/{commit}/
├── L1/
│   ├── 1.2.1.md
│   ├── 1.2.2.md
│   ├── ...
│   └── 15.3.1.md
├── L2/
│   ├── 1.1.1.md
│   ├── 1.2.6.md
│   ├── ...
│   └── 17.3.2.md
├── consolidated-L1-L2.md
└── issues-L1-L2.md
```

### Individual report format

Each report includes a metadata header (repository, commit, date, auditor, ASVS requirement with description), followed by findings organized by severity with file references, code snippets, CWE identifiers, and remediation recommendations. Reports also note positive security controls observed.

### Consolidated report format

The consolidated report contains: report metadata table, executive summary with severity distribution and systemic risk analysis, level coverage summary, all findings organized by severity with full detail, positive security controls table, ASVS compliance summary table, cross-reference matrix by attack surface, and level coverage analysis.

### Issues format

Each issue includes: descriptive title, labels (`bug`, `security`, `priority:{severity}`, `asvs-level:{level}`), summary, technical details with affected files, recommended remediation with code examples, acceptance criteria, and references to source reports and related findings.

## Data store reference

The Gofannon data store uses CouchDB with a single database (`agent_data_store`). All documents follow this schema:

```json
{
  "_id": "{userId}:{namespace}:{base64(key)}",
  "userId": "local-dev-user",
  "namespace": "asvs",
  "key": "asvs:requirements:10.4.1",
  "value": { ... },
  "metadata": {},
  "createdByAgent": "agent-name",
  "lastAccessedByAgent": "agent-name",
  "accessCount": 4,
  "createdAt": "2026-03-04T01:06:36.525056",
  "updatedAt": "2026-03-04T01:06:36.525056",
  "lastAccessedAt": "2026-03-22T20:58:39.982262"
}
```

### Namespaces

| Namespace | Contents |
|-----------|----------|
| `asvs` | ASVS chapters, sections, requirements, and indexes (double-prefixed keys like `asvs:requirements:10.4.1`) |
| `files:apache/tooling-trusted-releases` | Source code files from ATR repo |
| `files:apache/infrastructure-asfquart` | Source code files from asfquart repo |
| `files:apache/infrastructure-asfpy` | Source code files from asfpy repo |
| `audit_guidance` | Audit guidance documents and config files |
| `config` | Pipeline configuration |
| `open_issues` | Existing GitHub issues (for prior triage awareness) |
| `audit-cache:relevance:asvs-{section}-{...}` | Cached relevance scores per section |
| `audit-cache:inventory:asvs-{section}-{...}` | Cached code inventories per section |
| `audit-cache:analysis:asvs-{section}-{...}` | Cached Opus analysis results per section |
| `extraction:{owner}/{repo}/{dirs_key}` | Consolidation agent: cached finding extractions |
| `consolidation:{owner}/{repo}/{dirs_key}` | Consolidation agent: cached domain consolidations |

### Querying the data store

List all namespaces:

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{},"fields":["namespace"],"limit":10000}' \
  | python3 -c "
import sys, json
from collections import Counter
docs = json.load(sys.stdin)['docs']
for ns, count in sorted(Counter(d['namespace'] for d in docs).items()):
    print(f'  {count}\t{ns}')"
```

Check a specific requirement:

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"asvs","key":"asvs:requirements:7.2.1"},"limit":1}' \
  | python3 -m json.tool
```

Count files in a code namespace:

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"files:apache/tooling-trusted-releases"},"fields":["key"],"limit":10000}' \
  | python3 -c "import sys,json; print(len(json.load(sys.stdin)['docs']), 'files')"
```

## Cache management

The audit agent caches results at three levels: relevance scores, code inventories, and Opus analysis. Caching is keyed on the ASVS section + input namespaces, so changes to source code or ASVS context require cache clearing to take effect.

### When to clear caches

- **After updating agent code that changes prompts or analysis logic** — clear `analysis` and `relevance` caches
- **After updating source code in the data store** — clear all three cache types
- **After fixing ASVS context loading issues** — clear `analysis` caches (Opus needs the updated descriptions)
- **To re-run sections that used stale cached results** — clear `analysis` and `relevance` for those sections

### Clear all analysis and relevance caches

**Important:** Stop the orchestrator batch first. 409 errors mean CouchDB documents are being written concurrently.

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"$or":[{"namespace":{"$regex":"^audit-cache:analysis"}},{"namespace":{"$regex":"^audit-cache:relevance"}}]},"fields":["_id","_rev"],"limit":10000}' \
  | python3 -c "
import sys, json, requests
docs = json.load(sys.stdin).get('docs', [])
print(f'Deleting {len(docs)} docs...')
failed = 0
for d in docs:
    r = requests.delete(f'http://admin:password@localhost:5984/agent_data_store/{d[\"_id\"]}?rev={d[\"_rev\"]}')
    if r.status_code not in (200, 202):
        failed += 1
print(f'Done. Deleted: {len(docs)-failed}, Failed: {failed}')
"
```

### Clear all caches (including inventory)

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":{"$regex":"^audit-cache:"}},"fields":["_id","_rev"],"limit":10000}' \
  | python3 -c "
import sys, json, requests
docs = json.load(sys.stdin).get('docs', [])
print(f'Deleting {len(docs)} docs...')
failed = 0
for d in docs:
    r = requests.delete(f'http://admin:password@localhost:5984/agent_data_store/{d[\"_id\"]}?rev={d[\"_rev\"]}')
    if r.status_code not in (200, 202):
        failed += 1
print(f'Done. Deleted: {len(docs)-failed}, Failed: {failed}')
"
```

### Clear consolidation caches

```bash
curl -s -u admin:password "http://localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"$or":[{"namespace":{"$regex":"^extraction:"}},{"namespace":{"$regex":"^consolidation:"}}]},"fields":["_id","_rev"],"limit":10000}' \
  | python3 -c "
import sys, json, requests
docs = json.load(sys.stdin).get('docs', [])
print(f'Deleting {len(docs)} docs...')
failed = 0
for d in docs:
    r = requests.delete(f'http://admin:password@localhost:5984/agent_data_store/{d[\"_id\"]}?rev={d[\"_rev\"]}')
    if r.status_code not in (200, 202):
        failed += 1
print(f'Done. Deleted: {len(docs)-failed}, Failed: {failed}')
"
```

## Troubleshooting

### 409 Conflict errors when clearing caches

The orchestrator batch is still running and writing to CouchDB. Stop it first (`docker-compose stop api` or Ctrl+C the orchestrator), then retry the cache clear.

### Bedrock disconnects / `APIConnectionError` / `Server disconnected`

Opus calls running 10+ minutes can be disconnected by Bedrock. The audit agent retries 3 times with 15s/30s/45s backoff. If failures persist:

- Check the batch count — sections with 9+ Opus batches have ~50% disconnect probability
- The Opus tuning (`reasoning_effort=medium`, `max_tokens=64000`) was specifically chosen to reduce call duration from 20-30 min to 5-10 min
- Inventory capping at 15% of safe limit prevents excessive batch counts from large inventories

### ASVS description fallback / "ASVS Description length: 69"

The audit agent failed to load ASVS requirement context from the data store. Causes:

- **CouchDB unreachable** — check CouchDB health: `curl http://localhost:5984/`
- **ASVS data not ingested** — run the `ingest_asvs_standard` agent
- **Sections not in CDN JSON** (10.5, 10.6, 10.7) — these require manual ingestion; see below

### Missing ASVS sections (10.5, 10.6)

Sections 10.5 (OIDC Client) and 10.6 (OpenID Provider) are not in the v5.0.0 CDN JSON but exist in the ASVS master branch. They must be manually ingested into CouchDB. See the manual ingestion script in the operational notes of this project's development history.

### Stale cached Opus analysis

If the audit agent code was updated (e.g., ASVS context loading was fixed) but old cached Opus results are still present, sections will use the stale analysis. Symptoms:

- Log shows `Step 0: Loading ASVS requirement context` is missing (no Step 0 = old code)
- All Opus batches show as "cached" with no fresh calls
- `ASVS Description length: 69` in the logs (old 69-char fallback string)

Fix: clear `analysis` and `relevance` caches for the affected sections, then re-run.

### Relevance filtering failures

If relevance filtering fails for all batches, the agent falls back to assigning score=5 to every file. This means Opus analyzes all files instead of a filtered subset, potentially creating 10+ batches. The agent logs this as `WARNING: Batch N defaulting to score=5`. Re-running usually fixes transient failures.

### DNS resolution failures

`[Errno -3] Temporary failure in name resolution` — transient network issue. The Bedrock endpoint was unreachable. Simply re-run the affected sections.

### CouchDB crash ("No DB shards could be opened")

CouchDB had a storage-level failure. Restart CouchDB:

```bash
docker-compose restart couchdb
```

Then re-run the affected sections.

### Double log lines

Gofannon runs uvicorn with `--reload`, which creates two worker processes. Both log the same output. This is cosmetic — there's only one actual execution.

## Operational notes

### Monitoring a batch run

Watch the Docker logs:

```bash
docker-compose logs -f api 2>&1 | grep -E "ASVS:|Step [0-6]|Done:|FAILED|ERROR|WARNING|Opus batch"
```

### Analyzing logs after a batch

To identify which sections had errors, extract section-level summaries:

```bash
docker-compose logs api 2>&1 > batch.log
# Then analyze with grep/python to find:
# - Sections with "FAILED" or "ERROR"
# - Sections without "Done:" (incomplete)
# - Sections with "ASVS Description length: 69" (missing context)
# - Sections with all "cached" Opus batches (stale cache)
```

### Rebuilding after code changes

See [Gofannon guide](../../../docs/gofannon/) for rebuild instructions. CouchDB data persists across rebuilds. Agent code changes take effect immediately due to uvicorn `--reload`.

### Re-running specific sections

The audit agent and GitHub push agent handle overwrites: if a report already exists in the GitHub directory, it fetches the existing SHA and updates in place. You do not need to delete old reports before re-running.

However, you do need to clear stale caches if the agent code has changed, otherwise the cached results from the old code will be reused. Clear `analysis` and `relevance` caches for the sections being re-run.

### Cost and time estimates

| Operation | Time per section | Model cost |
|-----------|-----------------|------------|
| Relevance filtering (Step 2) | 1-3 min | Sonnet, ~5-15 parallel calls |
| Code inventory (Step 3) | 1-3 min | Sonnet, ~5-15 parallel calls |
| Opus analysis (Step 4) | 3-10 min | Opus medium, 1-6 sequential batches |
| Formatting (Step 6) | 30-60 sec | Sonnet, 1 call |
| **Total per section** | **5-15 min** | — |
| **Full L1 run (~70 sections)** | **8-16 hours** | — |
| **Full L2 run (~183 sections)** | **24-48 hours** | — |
| **Consolidation (L1+L2)** | **30-60 min** | Opus (exec summary) + Sonnet (rest) |