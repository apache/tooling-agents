# gofannon CI Registry Analyzer Agents

[Gofannon](https://github.com/The-AI-Alliance/gofannon) agents that scan a GitHub organization's Actions workflows to identify which repos publish packages to registries and what security risks exist in those pipelines.

Reports are documented separately — see the README bundled with each report run.

## Project structure

```
├── pre-fetch.py               Caches workflow YAML + composite actions from GitHub
├── publishing.py              LLM-classifies workflows (release, snapshot, CI, docs)
├── security.py                Pattern-matching security checks on cached YAML
├── review.py                  Combined risk assessment report (markdown)
├── brief.py                   One-page executive action plan (markdown)
├── json-export.py             Machine-readable structured export (JSON)
├── README.md                  ← you are here
└── tests/
    ├── README.md              Test suite docs
    ├── security_checks.py     Extracted check functions (keep in sync with security.py)
    ├── test_security_checks.py
    └── fixtures/
        ├── synthetic/         Minimal YAML snippets for each check pattern
        └── real-world/        Actual workflows, manually verified
```

## Architecture

Six agents share data via CouchDB namespaces:

```
Pre-fetch ──→   ci-workflows:{owner}        (YAML cache + composite actions)
       │
Publishing ──→  ci-classification:{owner}   (LLM classifications)
       │        ci-report:{owner}           (report + stats)
       │
Security ──→    ci-security:{owner}         (findings + stats)
       │
Review ──→      ci-combined:{owner}         (combined report)
       │
Brief ──→       ci-combined:{owner}         (executive brief)
       │
JSON Export ──→ ci-combined:{owner}         (JSON export)
```

**Run order:** Pre-fetch → Publishing → Security → then any of: Review, Brief, JSON Export

The last three are independent — they read directly from Publishing and Security data, not from each other.

## How to run

All agents run inside gofannon. Input fields are all type `"string"`.

### Full org scan

```
1. Pre-fetch     owner: apache    github_pat: ghp_...    all_repos: true
2. Publishing    owner: apache    github_pat: ghp_...    all_repos: true
3. Security      owner: apache    github_pat: ghp_...    clear_cache: true
4. Brief         owner: apache
5. Review        owner: apache
6. JSON Export   owner: apache
```

Pre-fetch takes ~30-60 min for ~2,500 repos. Publishing takes hours (LLM calls). Security takes ~30-60 min (CouchDB reads). Steps 4-6 take seconds each.

### Subset scan

```
1. Pre-fetch     owner: apache    github_pat: ghp_...    repos: beam,opendal,kafka
2. Publishing    owner: apache    github_pat: ghp_...    repos: beam,opendal,kafka
3. Security      owner: apache    github_pat: ghp_...    repos: beam,opendal,kafka
4. Brief         owner: apache
```

Pre-fetch skips repos already cached. Publishing skips workflows already classified. Only new/changed repos hit GitHub or the LLM.

### Input schemas

| Agent | Inputs |
|-------|--------|
| Pre-fetch | `owner`, `github_pat`, `all_repos` or `repos` (comma-separated), `clear_cache` |
| Publishing | `owner`, `github_pat`, `all_repos` or `repos` (comma-separated), `clear_cache` |
| Security | `owner`, `github_pat`, `repos` (optional, comma-separated), `clear_cache` |
| Review | `owner`, `repos` (optional, comma-separated) |
| Brief | `owner`, `repos` (optional, comma-separated) |
| JSON Export | `owner`, `repos` (optional, comma-separated) |

## Caching

All data persists in CouchDB across runs.

- **Pre-fetch** writes `__prefetch__:{repo}` and `__composites__:{repo}` meta keys plus individual YAML content. Skips repos that already have these keys.
- **Publishing** writes `__meta__:{repo}` plus per-workflow classification keys. Skips repos/workflows that already have them.
- **Security** writes `findings:{repo}` per repo. Reads cached findings unless `clear_cache: true`.

`clear_cache: true` **does not delete documents** — it skips cache reads and overwrites on write. No slow bulk-delete step. Pre-fetch data (`ci-workflows`) is never cleared by any agent.

### Useful CouchDB queries

```bash
# Count docs by namespace
for ns in ci-workflows ci-classification ci-report ci-security ci-combined; do
  count=$(curl -s "http://admin:password@localhost:5984/agent_data_store/_find" \
    -H "Content-Type: application/json" \
    -d "{\"selector\":{\"namespace\":\"${ns}:apache\"},\"fields\":[\"key\"],\"limit\":99999}" \
    | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('docs',[])))")
  echo "$ns: $count docs"
done

# Find workflows that failed LLM classification (gaps)
curl -s "http://admin:password@localhost:5984/agent_data_store/_find" \
  -H "Content-Type: application/json" \
  -d '{"selector":{"namespace":"ci-classification:apache"},"fields":["key","value"],"limit":99999}' \
| python3 -c "
import sys, json
docs = json.load(sys.stdin)['docs']
metas = {}; classifications = set()
for d in docs:
    k = d['key']
    if k.startswith('__meta__:'): metas[k.replace('__meta__:','')] = d.get('value',{}).get('workflows',[])
    else: classifications.add(k)
gaps = [f'{repo}/{wf}' for repo,wfs in sorted(metas.items()) for wf in wfs if f'{repo}:{wf}' not in classifications]
print(f'Missing: {len(gaps)}')
for g in gaps: print(f'  {g}')
"
```

## Security checks reference

The Security agent runs 13 checks. When adding a new check, also update `ATTACK_SCENARIOS` in `review.py` and `check_definitions` in `json-export.py`.

| Check | Severity | What It Detects |
|-------|----------|-----------------|
| `prt_checkout` | CRITICAL–LOW | `pull_request_target` + checkout of PR head. Severity uses a 2×2 matrix (see below). |
| `self_hosted_runner` | HIGH | Self-hosted runners exposed to PR triggers |
| `unpinned_actions` | MEDIUM | Actions referenced by mutable tags instead of SHA pins |
| `composite_action_unpinned` | MEDIUM | Unpinned actions inside composite actions |
| `composite_action_input_injection` | MEDIUM | Composite action interpolates `inputs.*` in run blocks — latent injection surface |
| `run_block_injection` | LOW–CRITICAL | `${{ }}` interpolation in run blocks. CRITICAL for `pull_request_target`, LOW for `pull_request`. |
| `composite_action_injection` | LOW | Interpolation in composite action run blocks |
| `broad_permissions` | LOW–HIGH | GITHUB_TOKEN with excessive scopes |
| `missing_codeowners` | LOW | No CODEOWNERS file |
| `codeowners_gap` | LOW | CODEOWNERS missing `.github/` coverage |
| `cache_poisoning` | INFO | `actions/cache` with PR trigger |
| `third_party_actions` | INFO | Actions from outside `actions/` and `github/` orgs |
| `missing_dependency_updates` | INFO | No dependabot.yml or renovate.json |

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

### run_block_injection trigger awareness

Interpolation of PR-related values (`event.pull_request.title`, `.body`, `.head.ref`, etc.) in `run:` blocks:

- **`pull_request_target` trigger** → CRITICAL (fork PRs get base repo secrets)
- **`pull_request` trigger** → LOW (fork PRs do NOT get secrets)
- **No PR trigger** → CRITICAL (conservative default)

## Adding a new check

When you add a check to `security.py`:

1. **Add the check function** and call it in the main scan loop
2. **Add a comment** referencing the ATTACK_SCENARIOS update (see existing comment above Check 1)
3. **Update `review.py`**: add entry to `ATTACK_SCENARIOS` dict
4. **Update `json-export.py`**: add entry to `check_definitions` dict
5. **Update `tests/security_checks.py`**: add the function
6. **Update `tests/test_security_checks.py`**: add handler in `run_check()`, create fixtures, add test cases
7. **Run tests**: `python3 tests/test_security_checks.py`

## Test suite

Run before deploying any Security agent changes:

```bash
python3 tests/test_security_checks.py
```

16 tests covering the prt_checkout severity matrix, trigger-aware injection, self-hosted runners, cache poisoning, broad permissions, and three real-world regression cases (Beam, OpenDAL, Texera).

See `tests/README.md` for details on adding tests and fixtures.

## Limitations

- **LLM classification accuracy**: Publishing uses Sonnet to classify workflows. The `confidence` field in the JSON indicates certainty.
- **Static analysis only**: Security pattern-matches on YAML text. Does not resolve reusable workflow inputs, evaluate conditional expressions, or trace data flow across jobs.
- **Composite action nesting**: Only top-level `.github/actions/*/action.yml` are checked — composites calling other composites are not recursively analyzed.
- **No runtime verification**: Does not verify whether secrets are configured, branch protection rules exist, or GITHUB_TOKEN permissions are effective given org-level settings.
- **Org-level security models**: Some projects (e.g., Apache Beam) scope publishing secrets to manual/scheduled workflows only. The scanner cannot detect these policies and may overstate risk.