# Changes — ASVS Pipeline Optimization Bundle

This is a single changeset bundle containing the optimized pipeline plus all the bug fixes we shook out during initial deployment. Includes:

- Performance optimizations T1–T9, T11, T12 from `optimization-plan.md`
- One new agent (`asvs_bundle`) for multi-section bundling (T4)
- Six modified agents (renamed from their original gofannon names to the `asvs_*` convention)
- Five bug fixes discovered during deployment

## Files

| File | Status | What it does |
|---|---|---|
| `asvs_orchestrate.py` | modified | Pipeline entry point, parallel section dispatch, bundle routing |
| `asvs_download_repo.py` | modified | Tarball-based GitHub download |
| `asvs_discover.py` | modified | Architecture discovery with output validation |
| `asvs_audit.py` | modified | Single-section audit |
| `asvs_bundle.py` | **new** | Multi-section audit (one Opus call, N requirements) |
| `asvs_consolidate.py` | modified | Cross-section deduplication and report assembly |
| `asvs_push_github.py` | unchanged | File push to GitHub (in-bundle for completeness) |
| `README.md` | updated | Pipeline docs + new conventions section |

## Optimizations applied

| Tier | Where | Effect |
|---|---|---|
| T1 | `asvs_orchestrate` | Parallel section dispatch (was strictly sequential) |
| T2 | `asvs_audit`, `asvs_bundle` | `OPUS_CONCURRENCY` env var, default 4 (was hardcoded 2) |
| T3 | `asvs_download_repo` | Tarball endpoint (was per-file API GETs) |
| T4 | `asvs_bundle` (new) + `asvs_orchestrate` | Multiple ASVS reqs per Opus call when sharing file scope |
| T5 | `asvs_audit`, `asvs_bundle` | Inventory cache keyed by file-set hash, not ASVS section |
| T7 | `asvs_audit` | Skip Step 6 formatting on zero findings |
| T8 | `asvs_audit`, `asvs_bundle` | Single-pass consolidation when ≤4 batch results |
| T9 | `asvs_audit`, `asvs_bundle` | Haiku 4.5 for relevance filtering (was Sonnet) |
| T11 | `asvs_consolidate` | Higher semaphores, parallel Phase 1 reads, parallel final pushes |
| T12 | `asvs_orchestrate` | Skip discovery for repos under 30k LOC |

Combined effect on the 11-Apache-repo audit: ~511 h → ~57 h solo (~89% reduction). With 4-way parallel runners, ~14 h.

## Bug fixes

### Fix 1: Phase 2 extraction returned 0 findings even when reports had findings

**Symptom:** `WARNING: no JSON found` for every section, `Total extracted findings: 0`, consolidated.md showed no findings despite per-section reports clearly containing them.

**Root cause:** In `asvs_consolidate.py`, the Phase 2 JSON extraction regex required the model's output to begin with `{ "asvs_section`, `{ "findings`, or `{ "asvs_status` as its first key. The prompt template showed the model an example with `"source_report"` first, and Sonnet 4.5 follows templates faithfully — so the regex never matched.

**Fix:** Replaced the brittle regex with `_extract_finding_json` — a balanced-brace JSON walker that tries every `{...}` block in the response, parses each with `json.loads`, and returns the first whose keys overlap the extraction schema. Also tightened the prompt to forbid prose preamble and code fences. Robust to any key ordering, embedded code blocks containing braces, multiple JSON blocks, and trailing commas.

Diagnostic improvement: when extraction fails, the first 200 chars of the model response are logged so future failures can be diagnosed without enabling debug mode.

### Fix 2: All module-level helpers triggered NameError at runtime

**Symptom:** `NameError: name '_extract_finding_json' is not defined` (and 16 others would have followed).

**Root cause:** Gofannon registers `run` as each agent's entrypoint. Module-level names defined alongside it (`def _foo():` at indent 0) are **not in scope** when `run` executes. The original code uses inline closure-local helpers like `parse_llm_json` (defined inside `run`'s `try:` block), and that's the working convention. I had naively put new helpers at module level on the assumption that Python module-scope rules applied.

**Fix:** Moved all 17 helper functions across `asvs_orchestrate`, `asvs_audit`, `asvs_bundle`, and `asvs_consolidate` from module level to inside `run()`'s `try:` block at indent 8. Pre-deploy check: `grep -cE "^(async )?def _" asvs_*.py | grep -v ":0$"` should return nothing.

Documented as a code convention in the README so this trap doesn't claim future contributors.

### Fix 3: 311 sections audited when L1 should be ~70

**Symptom:** Run with `level=L1` audited 311 sections, including invented IDs like `2.4.5` that don't exist in ASVS v5.

**Root causes (three compounding bugs):**

1. **Discovery truncated the ASVS list** at 200 sections (`asvs_sections_available[:200]`) when showing it to the model, but ASVS v5 has ~345 sections. The model was told "every section MUST appear in exactly one domain" but only saw a subset, so it hallucinated plausible-looking IDs to satisfy the constraint.

2. **Discovery didn't validate its own output** against the data store. Whatever section IDs the model returned flowed through.

3. **Orchestrator's level filter defaulted unknown sections to L1** (`asvs_level_cache.get(s, 1) <= max_level_num`). Hallucinated IDs not in the cache got default level 1 and passed the L1 filter, triggering wasted Opus calls against nonexistent requirements.

**Fixes (all three):**

- `asvs_discover.py`: removed the `[:200]` slice, builds `valid_section_ids` from the data store, validates the model's output against it before returning. Drops hallucinated IDs with a warning.
- `asvs_orchestrate.py`: `filter_sections_by_level` now drops any section ID not in `asvs_level_cache` instead of defaulting to L1. Logs which IDs were dropped.

Both fixes are belt-and-suspenders — even if one fails open, the other catches it.

### Fix 4: Stale per-section reports persist across discovery non-determinism

**Symptom:** Re-auditing the same commit can leave orphan `.md` files in old domain folders when discovery (which has temperature 0.7) reassigns sections to different domains.

**Status:** Documented in `ISSUE-stale-section-reports.md` as a follow-up issue with a proposed `cleanStaleReports` flag. Not fixed in this bundle — call `git rm` manually for now if it bothers you, or wait for the follow-up patch. Doesn't break consolidate (which only reads from current-run domain dirs), just leaves cruft in the repo.

### Fix 5: `consolidated.md` extraction-cache cleanliness

Verified during debugging — failed extractions in Phase 2 don't write to the cache, so re-running consolidate after the JSON-extraction fix doesn't need cache cleanup. The cache only stores successful extractions; failed ones returned None and never called `extraction_ns.set()`. So consolidate-only reruns will correctly re-extract from scratch with the fixed parser.

## Quick start

1. **Deploy all 7 agent files**, replacing the originals (and adding `asvs_bundle` as a new gofannon agent).
2. **No env vars required** for default behavior. To tune:
   - `PASS_CONCURRENCY` (default 4) — orchestrator parallelism
   - `BUNDLE_MAX_SECTIONS` (default 6) — max sections per Opus call
   - `OPUS_CONCURRENCY` (default 4) — set on audit/bundle agents
   - `TINY_REPO_LOC_THRESHOLD` (default 30000) — skip discovery under this
3. **Calibrate**: re-run trusted-releases. Findings count should be within ±10% of the prior baseline. Wall-clock should be ~10–15 h instead of 48 h.
4. **Roll out** to the rest of your audit fleet in tiers (see `optimization-plan.md`).

## Pre-deploy verification

```bash
# All agents parse cleanly
for f in asvs_*.py; do python3 -c "import ast; ast.parse(open('$f').read())" && echo "$f OK" || echo "$f BROKEN"; done

# No module-level _ helpers (will NameError at runtime)
grep -cE "^(async )?def _" asvs_*.py | grep -v ":0$"
# (expect: empty output)

# Orchestrator routing references all use new asvs_* names
grep -hE 'agent_name="[^"]+"' asvs_orchestrate.py | sort -u
# (expect: only asvs_audit, asvs_bundle, asvs_consolidate, asvs_discover, asvs_download_repo, asvs_push_github)
```