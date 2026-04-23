# Multi-Spec Architecture

Implementation plan for expanding the pipeline from ASVS-only to multiple security specifications. This covers the agent renames, data model changes, spec selection logic, and migration path.

## Current Architecture (ASVS-Only)

```
ASVS/
├── agents/
│   ├── orchestrate_asvs_audit_to_github.py
│   ├── discover_codebase_architecture.py
│   ├── run_asvs_security_audit.py
│   └── consolidate_asvs_security_audit_reports.py
├── audit_guidance/
└── reports/
```

Data store: `asvs` namespace with 345 requirements. One spec, one namespace.

## Target Architecture (Multi-Spec)

```
security/
├── agents/
│   ├── orchestrate_security_audit.py
│   ├── discover_codebase_architecture.py
│   ├── run_security_audit.py
│   └── consolidate_security_audit_reports.py
├── specs/
│   ├── asvs/           ← OWASP ASVS v5.0.0 (345 requirements)
│   ├── cwe-top-25/     ← CWE/SANS Top 25 (25 entries)
│   ├── api-top-10/     ← OWASP API Security Top 10 (10 entries)
│   ├── slsa/           ← SLSA v1.0 Build Levels
│   └── asf-baseline/   ← ASF-specific baseline (custom)
├── audit_guidance/
└── reports/
```

Data store: one namespace per spec (`asvs`, `cwe-top-25`, `api-top-10`, `slsa`, `asf-baseline`). Each follows the same schema.

## Phase 0: Rename and Abstract

Before adding any new spec, make the existing pipeline spec-agnostic. This is a backward-compatible rename — the ASVS flow works identically afterward.

### Agent Renames

| Current | New | Deployment aliases |
|---|---|---|
| `orchestrate_asvs_audit_to_github` | `orchestrate_security_audit` | Keep old name as alias |
| `run_asvs_security_audit` | `run_security_audit` | Keep old name as alias |
| `consolidate_asvs_security_audit_reports` | `consolidate_security_audit_reports` | Keep old name as alias |
| `discover_codebase_architecture` | unchanged | — |
| `download_github_repo_to_datastore` | unchanged | — |
| `add_markdown_file_to_github_directory` | unchanged | — |

Old deployment names stay registered in CouchDB, forwarding to the new agents. Remove after all callers migrate.

### Audit Agent: `spec` Input

The audit agent gains a `spec` field in its JSON input:

```json
{
  "namespaces": ["files:apache/steve/v3"],
  "asvs": "6.1.1",
  "spec": "asvs"
}
```

When `spec` is `"asvs"`, look up the requirement in the `asvs` namespace (current behavior). When `spec` is `"cwe-top-25"`, look up in `cwe-top-25`:

```json
{
  "namespaces": ["files:apache/commons-lang"],
  "asvs": "CWE-79",
  "spec": "cwe-top-25"
}
```

The `asvs` field name is a misnomer at this point — it's really `requirement_id`. Rename it internally but accept both for backward compatibility:

```python
requirement_id = input_json.get("requirement_id") or input_json.get("asvs", "")
spec = input_json.get("spec", "asvs")
```

### Orchestrator: `specs` Input

The orchestrator accepts a `specs` input (string, comma-separated):

| Input | Behavior |
|---|---|
| `"asvs"` | Run only ASVS (backward compatible) |
| `"auto"` | Discovery agent recommends specs based on project type |
| `"asvs,cwe-top-25"` | Run specific specs |
| (empty) | Defaults to `"asvs"` initially, `"auto"` later |

The orchestrator loops through specs, loading requirements from each namespace and generating audit tasks:

```python
for spec in selected_specs:
    spec_ns = data_store.use_namespace(spec)
    requirements = spec_ns.list_keys()
    for req_id in requirements:
        # Filter by level, language applicability, etc.
        tasks.append({
            "spec": spec,
            "requirement_id": req_id,
            "namespaces": code_namespaces,
        })
```

### Consolidator: Cross-Spec Awareness

The consolidator already groups findings by domain and deduplicates. The enhancement:

1. Group findings by spec in addition to domain
2. Use `cross_references` from requirement data to merge findings across specs
3. Add a "Specification Coverage" section to the consolidated report

```python
# When merging findings:
if finding_a["spec"] == "asvs" and finding_b["spec"] == "cwe-top-25":
    # Check cross-references
    asvs_req = asvs_ns.get(f"asvs:requirements:{finding_a['requirement_id']}")
    cwe_xrefs = asvs_req.get("cross_references", {}).get("cwe-top-25", [])
    if finding_b["requirement_id"] in cwe_xrefs:
        # Same vulnerability from two specs — merge
        merged = merge_findings(finding_a, finding_b)
        merged["specs_violated"] = ["asvs", "cwe-top-25"]
```

## Data Store Schema

Every spec follows the same schema in its namespace. This is what makes the system extensible — the audit agent doesn't need spec-specific code, just a namespace to look up.

```python
# Namespace: {spec_name}
# Key: {spec_name}:requirements:{requirement_id}

{
  "id": "CWE-79",                    # Unique within this spec
  "title": "Cross-site Scripting",
  "description": "The product does not neutralize...",
  "level": 1,                        # Maps to L1/L2/L3 filtering
  "category": "injection",           # For domain grouping
  "languages": ["all"],              # Or ["c", "cpp"] for memory safety
  "spec": "cwe-top-25",             # Self-reference
  "spec_version": "2024",
  "cross_references": {              # For dedup across specs
    "asvs": ["1.2.1", "1.2.2", "5.1.1"],
    "api-top-10": ["API3"]
  }
}
```

### Required Fields

| Field | Type | Purpose |
|---|---|---|
| `id` | string | Unique requirement identifier |
| `title` | string | Human-readable name |
| `description` | string | What to check for |
| `level` | int (1-3) | Maps to L1/L2/L3 filtering |
| `spec` | string | Namespace name |

### Optional Fields

| Field | Type | Purpose |
|---|---|---|
| `category` | string | Domain grouping hint for discovery agent |
| `languages` | array | Language applicability filter |
| `spec_version` | string | Spec version identifier |
| `cross_references` | object | Map of spec_name → array of requirement_ids |
| `detection_methods` | array | How to look for this issue |
| `evidence` | array | What constitutes a pass/fail |

## Spec Selection: Discovery Agent Enhancement

The discovery agent currently outputs domain-to-file mappings. The enhancement adds project classification and spec recommendations:

```python
# Enhanced discovery output
{
  "project_type": "web_app",
  "languages": ["python"],
  "frameworks": ["quart", "asfquart"],
  "has_http_endpoints": true,
  "has_auth": true,
  "has_api": true,
  "publishes_packages": false,
  
  "recommended_specs": [
    {
      "spec": "asvs",
      "coverage": "full",
      "reason": "Web app with auth, sessions, endpoints"
    },
    {
      "spec": "api-top-10",
      "coverage": "full",
      "reason": "REST API detected"
    },
    {
      "spec": "cwe-top-25",
      "coverage": "supplement",
      "reason": "General code quality baseline"
    }
  ],
  
  "not_recommended": [
    {
      "spec": "slsa",
      "reason": "No package publishing detected"
    }
  ],
  
  "passes": [...]  # Existing domain/file mapping
}
```

### Project Type Detection Signals

| Signal | Detection Method | Project Type |
|---|---|---|
| HTTP framework imports | Code scan | web_app |
| Route decorators (`@app.route`, `@router.get`) | Code scan | web_app |
| `setup.py` / `pyproject.toml` with package config | File check | library |
| CLI entry points (`console_scripts`) | Config check | cli_tool |
| Queue consumers, scheduler imports | Code scan | backend_service |
| Dockerfile + publish workflow | File + GHA check | publishing |

### Default Spec Mapping

| Project Type | Default Specs |
|---|---|
| `web_app` | asvs, api-top-10, asf-baseline |
| `library` | cwe-top-25, asf-baseline |
| `cli_tool` | cwe-top-25, asf-baseline |
| `backend_service` | asvs (partial), cwe-top-25, asf-baseline |
| `build_tool` | asf-baseline, slsa |

When `specs="auto"`, the orchestrator uses these defaults. The user can always override with explicit spec selection.

## Consolidated Report Changes

### Spec Coverage Section

```markdown
## Specification Coverage

| Spec | Version | Requirements Audited | Findings | Pass | Fail | N/A |
|------|---------|---------------------|----------|------|------|-----|
| ASVS v5.0.0 | 5.0.0 | 253 (L1+L2) | 137 | 89 | 137 | 27 |
| CWE Top 25 | 2024 | 25 | 12 | 13 | 12 | 0 |
| API Top 10 | 2023 | 10 | 4 | 6 | 4 | 0 |
```

### Cross-Spec Findings

```markdown
### Cross-Spec Findings

12 findings match requirements in multiple specs:

| Finding | ASVS | CWE | API Top 10 |
|---------|------|-----|------------|
| FINDING-001: Missing rate limiting | 2.4.1 | — | API4 |
| FINDING-015: SQL injection in search | 1.2.1 | CWE-89 | API1 |
| FINDING-023: Missing TLS validation | 12.1.1 | CWE-295 | API7 |
```

### Finding Format

Each finding gains a `specs_violated` field:

```markdown
#### FINDING-042: Missing authorization check on GET /api/elections/{id}/votes

**Specs violated:** ASVS 4.1.1, API1
**Severity:** High
**Files:** v3/server/pages.py:426
```

## Migration Path

### Step 1: Deploy New Agents Alongside Old

Register both names in CouchDB deployments:

```
run_asvs_security_audit → agent_id (existing)
run_security_audit → same agent_id (new alias)
```

The agent code accepts both `asvs` and `requirement_id` fields. When `spec` is absent, defaults to `"asvs"`.

### Step 2: Update Callers

- `rerun-sections.sh` → update agent names
- Orchestrator → already handles the new names
- Any external scripts calling the API

### Step 3: Remove Old Aliases

Delete old deployment entries from CouchDB:

```bash
curl -X DELETE -u admin:password \
  "http://localhost:5984/deployments/run_asvs_security_audit"
```

### Step 4: Repo Restructure

```bash
git mv ASVS/ security/
# Update all READMEs, scripts, docs
```

## Estimated Effort (Phase 0 Only)

| Task | Effort |
|---|---|
| Rename agents, add `spec`/`requirement_id` inputs | 1 day |
| Update orchestrator to accept `specs` input, loop through specs | 1 day |
| Update consolidator for cross-spec grouping and dedup | 1 day |
| Deploy with aliases, test backward compatibility | Half day |
| Update READMEs, `rerun-sections.sh`, docs | Half day |
| **Total** | **~4 days** |

After Phase 0, adding each new spec (CWE, API Top 10, etc.) is a data + prompt exercise — see the individual [spec plans](specs/).