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
├── orchestrator.py            Runs full pipeline, splits private/public output
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

Seven agents share data via CouchDB namespaces:

```
Pre-fetch ──→   ci-workflows:{github_owner}   (YAML cache + composites + extras)
       │
Publishing ──→  ci-classification:{github_owner}   (LLM classifications)
       │        ci-report:{github_owner}           (report + stats)
       │
Security ──→    ci-security:{github_owner}         (findings + stats)
       │
Review ──→      ci-combined:{github_owner}         (combined report)
       │
Brief ──→       ci-combined:{github_owner}         (executive brief)
       │
JSON Export ──→ ci-combined:{github_owner}         (JSON export)

Orchestrator    Runs all of the above, pushes private + public reports to GitHub
```

**Run order:** Pre-fetch → Publishing → Security → then any of: Review, Brief, JSON Export

Only Pre-fetch hits the GitHub API. All other agents are pure CouchDB readers.

## How to run

All agents run inside gofannon. Input fields are all type `"string"`.

### Orchestrator (recommended)

The orchestrator runs the full pipeline and pushes reports to private and public GitHub repos:

```
Orchestrator    github_owner: apache
                read_pat: ghp_...
                write_private_repo: apache/tooling-agents-private
                write_private_directory: repos/apache/github-review
                write_private_pat: ghp_...
                write_public_repo: apache/tooling-agents
                write_public_directory: repos/apache/github-review
                write_public_pat: ghp_...
                redacted_severity: CRITICAL
```

This runs three phases automatically:

```
Phase 1: Prefetch (hits GitHub API, caches all workflow YAML)
Phase 2: Private reports (5 agents, no redaction, pushed immediately)
Phase 3: Public reports (same 5 agents with redacted_severity, pushed immediately)
```

### Manual run

```
1. Pre-fetch     github_owner: apache    read_pat: ghp_...
2. Publishing    github_owner: apache
3. Security      github_owner: apache
4. Review        github_owner: apache
5. Brief         github_owner: apache
6. JSON Export   github_owner: apache
```

Pre-fetch takes ~30-60 min for ~2,500 repos. Publishing takes hours (LLM calls). Security takes ~30-60 min. Steps 4-6 take seconds each.

### Manual private + public split

```
# Phase 1: Prefetch (once)
1. Pre-fetch     github_owner: apache    read_pat: ghp_...

# Phase 2: Private reports (full)
2. Publishing    github_owner: apache
3. Security      github_owner: apache
4. Review        github_owner: apache
5. Brief         github_owner: apache
6. JSON Export   github_owner: apache

# Phase 3: Public reports (redacted)
7. Publishing    github_owner: apache    redacted_severity: CRITICAL
8. Security      github_owner: apache    redacted_severity: CRITICAL
9. Review        github_owner: apache    redacted_severity: CRITICAL
10. Brief        github_owner: apache    redacted_severity: CRITICAL
11. JSON Export  github_owner: apache    redacted_severity: CRITICAL
```

### Input schemas

| Agent | Inputs | Purpose |
|-------|--------|---------|
| Pre-fetch | `github_owner`, `read_pat` | Cache workflow YAML from GitHub |
| Publishing | `github_owner`, `redacted_severity` | LLM-classify workflows |
| Security | `github_owner`, `redacted_severity` | Pattern-match security checks |
| Review | `github_owner`, `redacted_severity` | Combined risk assessment |
| Brief | `github_owner`, `redacted_severity` | Executive action plan |
| JSON Export | `github_owner`, `redacted_severity` | Machine-readable export |
| Orchestrator | `github_owner`, `read_pat`, `write_private_repo`, `write_private_directory`, `write_private_pat`, `write_public_repo`, `write_public_directory`, `write_public_pat`, `redacted_severity` | Full pipeline |

All orchestrator inputs are required. `redacted_severity` defaults to `CRITICAL` on the orchestrator; defaults to empty (no filtering) on individual agents.

### redacted_severity

When set (e.g., `redacted_severity: CRITICAL`), agents exclude findings at that severity before counting and rendering. Everything is consistent by construction — no post-processing.

- **Publishing**: filters `[CRITICAL]` security_notes, strips vulnerability sentences from LLM summaries
- **Security**: reads cached findings, filters, re-renders report without overwriting CouchDB
- **Review**: omits CRITICAL findings from all sections, adjusts counts and rankings
- **Brief**: omits the "Exploitable Now" section and CRITICAL recommendation
- **JSON Export**: filters CRITICAL findings from all repos, adjusts severity counts and worst_severity

When empty (default), all findings are included. When set, agents skip CouchDB writes to preserve the full Phase 2 data.

## Caching

All data persists in CouchDB across runs.

- **Pre-fetch** writes `__prefetch__:{repo}`, `__composites__:{repo}`, and `__extras__:{repo}` meta keys plus individual YAML content. Always rescans — overwrites on every run.
- **Publishing** writes `__meta__:{repo}` plus per-workflow classification keys. Skips workflows already classified (100% cache hit rate on Phase 3 redacted runs).
- **Security** writes `findings:{repo}` per repo. When `redacted_severity` is set, reads cached findings and filters — does not rescan or overwrite.

The `__extras__:{repo}` key stores CODEOWNERS content and dependabot/renovate existence, so the Security agent never needs to call the GitHub API.

When `redacted_severity` is set, no agent overwrites CouchDB data. Phase 3 reads the full data written by Phase 2 and filters in memory.

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

## ASF policy integration

The security checks incorporate guidance from three ASF sources:

- [GitHub Actions Security](https://cwiki.apache.org/confluence/display/BUILDS/GitHub+Actions+Security) — practical advice on dangerous workflows
- [GitHub Actions Policy](https://infra.apache.org/github-actions-policy.html) — formal rules (MUST/SHOULD requirements)
- [Automated Release Signing](https://infra.apache.org/release-signing.html#automated-release-signing) — CI signing key requirements

Two material policy integrations:

**ASF-exempt action namespaces.** ASF policy says actions in `actions/*`, `github/*`, and `apache/*` MAY be used without restrictions. The `ASF_EXEMPT_ORGS` constant excludes these from `unpinned_actions` and `composite_action_unpinned` checks — only third-party actions outside these namespaces are flagged. The broader `TRUSTED_ORGS` set (which also includes docker, gradle, pypa, etc.) is still used for the informational `third_party_actions` check.

**Mandatory dependency management.** ASF policy says "All repositories using GitHub Actions **must** have automatic dependency management." `missing_dependency_updates` is therefore LOW severity (policy violation), not just informational.

## Security checks reference

The Security agent runs 13 checks. When adding a new check, also update `ATTACK_SCENARIOS` in `review.py` and `check_definitions` in `json-export.py`.

| Check | Severity | What It Detects |
|-------|----------|-----------------|
| `prt_checkout` | CRITICAL–INFO | `pull_request_target` + checkout of PR head. Severity uses a 2×2 matrix (see below). |
| `self_hosted_runner` | HIGH–INFO | Self-hosted runners exposed to PR triggers. Severity uses same 2×2 matrix as prt_checkout. |
| `unpinned_actions` | MEDIUM | Third-party actions (outside `actions/*`, `github/*`, `apache/*`) referenced by mutable tags instead of SHA pins |
| `composite_action_unpinned` | MEDIUM | Third-party unpinned actions inside composite actions (same ASF exemption) |
| `composite_action_input_injection` | MEDIUM | Composite action interpolates `inputs.*` in run blocks — latent injection surface |
| `run_block_injection` | LOW–CRITICAL | `${{ }}` interpolation in run blocks. CRITICAL for `pull_request_target`, LOW for `pull_request`. |
| `composite_action_injection` | LOW | Interpolation in composite action run blocks |
| `broad_permissions` | LOW–HIGH | GITHUB_TOKEN with excessive scopes |
| `missing_codeowners` | LOW | No CODEOWNERS file |
| `codeowners_gap` | LOW | CODEOWNERS missing `.github/` coverage |
| `missing_dependency_updates` | LOW | No dependabot.yml or renovate.json (ASF policy violation) |
| `cache_poisoning` | INFO | `actions/cache` with PR trigger |
| `third_party_actions` | INFO | Actions from outside `actions/*`, `github/*`, `apache/*` namespaces |

### Line numbers

Each finding includes a `line` field (integer, nullable) pointing to the relevant line in the workflow YAML. When deduplication collapses multiple findings, a `lines` list replaces the single `line` field. Repo-wide findings (`unpinned_actions`, `third_party_actions`, `missing_codeowners`, etc.) have `line: null`.

In the markdown security report, line numbers render as `filename:LINE` (e.g., `renovate-changelog.yml:47`).

In the JSON export, findings look like:

```json
{
  "severity": "CRITICAL",
  "check": "prt_checkout",
  "file": "renovate-changelog.yml",
  "detail": "pull_request_target trigger with checkout of PR head code...",
  "line": 47
}
```

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

### self_hosted_runner severity matrix

Same 2×2 as prt_checkout but with HIGH ceiling instead of CRITICAL (runner compromise is serious but doesn't directly grant access to base repo secrets like prt_checkout does):

|                        | Broad permissions | Limited permissions |
|------------------------|-------------------|---------------------|
| **Auto-trigger** (opened, synchronize) | **HIGH** | **MEDIUM** |
| **Maintainer-gated** (labeled, assigned) | **MEDIUM** | **LOW** |

No PR trigger → INFO (runners used for scheduled/manual workflows only).

Uses the same `extract_permissions()` and generalized `extract_trigger_event_types()` functions as prt_checkout.

### run_block_injection trigger awareness

Interpolation of PR-related values (`event.pull_request.title`, `.body`, `.head.ref`, etc.) in `run:` blocks:

- **`pull_request_target` trigger** → CRITICAL (fork PRs get base repo secrets)
- **`pull_request` trigger** → LOW (fork PRs do NOT get secrets)
- **No PR trigger** → CRITICAL (conservative default)

### ASF_EXEMPT_ORGS vs TRUSTED_ORGS

Two org sets serve different purposes:

- **`ASF_EXEMPT_ORGS`** = `{"actions", "github", "apache"}` — per ASF policy, actions in these namespaces need not be SHA-pinned. Used by `unpinned_actions` and `composite_action_unpinned`.
- **`TRUSTED_ORGS`** — broader set including docker, gradle, pypa, codecov, etc. Used only for the informational `third_party_actions` check (which flags actions outside this set for awareness, not as a policy violation).

## Adding a new check

When you add a check to `security.py`:

1. **Add the check function** — return `(severity, detail, line_num)` tuples. Use `enumerate(content.split("\n"), 1)` to track 1-indexed line numbers.
2. **Call it in the main scan loop** — capture the `line` field: `"line": result[2] if len(result) > 2 else None`
3. **Update `review.py`**: add entry to `ATTACK_SCENARIOS` dict with label, severity, description, attack, and example
4. **Update `json-export.py`**: add entry to `check_definitions` dict
5. **Update `tests/security_checks.py`**: add the function (note: test module still uses 2-tuples for backward compatibility)
6. **Update `tests/test_security_checks.py`**: add handler in `run_check()`, create fixtures, add test cases
7. **Run tests**: `python3 tests/test_security_checks.py`

## Test suite

Run before deploying any Security agent changes:

```bash
python3 tests/test_security_checks.py
```

19 tests covering the prt_checkout severity matrix, trigger-aware injection, self-hosted runners, cache poisoning, broad permissions, and three real-world regression cases (Beam, OpenDAL, Texera).

See `tests/README.md` for details on adding tests and fixtures.

## Limitations

- **LLM classification accuracy**: Publishing uses Sonnet to classify workflows. The `confidence` field in the JSON indicates certainty.
- **Static analysis only**: Security pattern-matches on YAML text. Does not resolve reusable workflow inputs, evaluate conditional expressions, or trace data flow across jobs.
- **Composite action nesting**: Only top-level `.github/actions/*/action.yml` are checked — composites calling other composites are not recursively analyzed.
- **No runtime verification**: Does not verify whether secrets are configured, branch protection rules exist, or GITHUB_TOKEN permissions are effective given org-level settings.
- **Org-level security models**: Some projects (e.g., Apache Beam) scope publishing secrets to manual/scheduled workflows only. The scanner cannot detect these policies and may overstate risk.
- **Conditional gates not evaluated**: Workflows with access control checks (e.g., `github.event.pull_request.user.login == 'renovate[bot]'`) are flagged based on the dangerous pattern even if the gate prevents exploitation. These appear as mitigated findings in the report.