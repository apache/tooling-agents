# ASVS Audit Pipeline — Speed Optimization Plan

## TL;DR

The pipeline as written has **two systemic inefficiencies** that compound:

1. **Sections run completely sequentially in the orchestrator** — `for section in sections:` with `await` inside, no `asyncio.gather`. The `opus_semaphore=2` and `sonnet_semaphore=5` inside `run_asvs_security_audit` only parallelize batches *within* a single section, never across sections.
2. **Each ASVS section re-does Opus deep analysis from scratch** even when discovery has already grouped sections that share the same file scope into a "pass". A pass with 6 sections does 6 separate Opus reads of the same code.

Fixing just these two gets the recommended-hybrid run from **~511 hours down to ~70–90 hours** (5–7× speedup) with no loss of audit quality. Layering in three further wins (better caching, tarball download, smarter consolidation) takes it to **~57 hours**.

| Tier | What changes | Total h | Days | vs. baseline |
|---|---|---|---|---|
| Baseline | Current pipeline | **511** | 64 | — |
| T1 | Orchestrator parallel-4 (one-line fix) | **141** | 18 | −72 % |
| T1+T2 | + raise `opus_semaphore` to 4 | **108** | 14 | −79 % |
| T1+T2+T3 | + tarball download | 108 | 14 | (cosmetic) |
| T1–T3 + bundling | + bundle sections per pass into one Opus call | **~68** | 8.5 | −87 % |
| Full | + global inventory cache + skip empty-finding format + smarter consolidation | **~57** | 7.2 | −89 % |

(All numbers solo-runner. With 4 parallel orchestrator runners on top, full-optimization gets to ~14 hours total wall-clock for all 11 repos.)

The rest of this doc walks through every optimization, what code to touch, expected impact, and risk to audit quality.

---

## Time budget — where it actually goes

From the calibration-fit model, agents consume:

| Agent | Hours (recommended hybrid) | % | Why |
|---|---|---|---|
| `run_asvs_security_audit` | 460.6 | **90.2 %** | Step 4 Opus deep analysis dominates. Called 11×N_sections times. |
| `consolidate_asvs_security_audit_reports` | 44.8 | 8.8 % | Phase 3 domain consolidation + Phase 4 final merge are the heavy LLM calls. |
| `discover_codebase_architecture` | 2.8 | 0.5 % | Flat ~15 min per repo regardless of size. |
| `download_github_repo_to_data_store` | 1.9 | 0.4 % | One GitHub API GET per file, sequential. |
| `add_markdown_file_to_github_directory` | 0.9 | 0.2 % | One PUT per section. |

Within `run_asvs_security_audit`, per-section breakdown:

- Step 0–1 (load ASVS req, read files): ~5 sec — negligible
- Step 2 relevance filter (Sonnet, parallel + cached): ~30–60 sec on first section, ~0 on subsequent (cached)
- Step 3 code inventory (Sonnet, parallel + cached): ~60–120 sec on first, ~0 on subsequent (cached)
- **Step 4 Opus deep analysis: 5–10 min** ← this is 80–95 % of per-section time
- Step 5 multi-round consolidation: 30–90 sec when there's >1 batch
- Step 6 format report: 30–60 sec

So the entire optimization story is really "make Step 4 cheaper or run it less often."

---

## The optimizations, ranked by ROI

### 🟢 T1 — Parallelize sections in the orchestrator [HIGHEST ROI, ONE-LINE FIX]

**Problem.** `orchestrate_asvs_audit_to_github.py` lines 380–438 (and 619–653 for no-discover mode) run sections in a strict `await`-in-`for-loop` pattern:

```python
for pass_def in passes:
    for section in sections:
        section_idx += 1
        audit_result = await gofannon_client.call(
            agent_name="run_asvs_security_audit",
            input_dict={...}
        )
        await gofannon_client.call(
            agent_name="add_markdown_file_to_github_directory",
            input_dict={...}
        )
```

This means with 345 sections per repo at ~10 min each = 57.5 hours of pure serial wall-clock. The `opus_semaphore=2` inside `run_asvs_security_audit` is *useless* for this — there's only ever one section running at a time.

**Fix.** Wrap section execution in an `asyncio.gather` with an outer semaphore:

```python
SECTION_CONCURRENCY = 4  # tune to your bedrock quota
section_semaphore = asyncio.Semaphore(SECTION_CONCURRENCY)

async def run_one_section(section, pass_def):
    async with section_semaphore:
        audit_result = await gofannon_client.call(
            agent_name="run_asvs_security_audit",
            input_dict={...}
        )
        await gofannon_client.call(
            agent_name="add_markdown_file_to_github_directory",
            input_dict={...}
        )
        return section, audit_result

# Inside the pass loop:
section_tasks = [run_one_section(s, pass_def) for s in sections]
results = await asyncio.gather(*section_tasks, return_exceptions=True)
```

**Impact.** With concurrency=4, audit time drops from 460 h → ~115 h for the recommended hybrid. **Total project: ~511 h → ~141 h (−72%).** Concurrency=8 would cut another half if your bedrock quota allows.

**Risk.** Low. The agents are stateless w.r.t. each other; per-section caches are keyed by `asvs` so they don't collide. Watch out for: GitHub API rate limits on the PUT side (push step), and Bedrock InvocationRateLimit. Backoff already exists in `call_llm`.

**Effort.** ~30 lines of code changes in two files. **A half-day's work for a >70% speedup.**

---

### 🟢 T2 — Raise `opus_semaphore` from 2 to 4 [TRIVIAL, BIG IMPACT]

**Problem.** `run_asvs_security_audit.py:93` hardcodes `opus_semaphore = asyncio.Semaphore(2)`. For repos where a section's relevant file set spans many Opus batches (e.g., a 150 k LOC repo where a section flags 80 files relevant), this serializes batches that could run in parallel.

**Fix.** Bump to 4 (or make it configurable via env var):

```python
import os
OPUS_CONCURRENCY = int(os.environ.get("OPUS_CONCURRENCY", "4"))
opus_semaphore = asyncio.Semaphore(OPUS_CONCURRENCY)
```

**Impact.** Within a single section, halves Step 4 wall-clock when there are ≥4 batches. Combined with T1, gets us to ~108 h total.

**Risk.** Bedrock account quotas. Most us-east accounts allow 5–10 concurrent Opus invocations. If you start hitting `ThrottlingException`, drop to 3. The retry logic at lines 625–645 + 667–684 handles transient failures correctly.

**Effort.** One-line change. **Pair this with T1 and you're at −79% in an afternoon.**

---

### 🟢 T3 — Tarball download instead of per-file API [QUICK WIN]

**Problem.** `download_github_repo_to_data_store.py` uses `git/trees?recursive=1` to get the file list (good), then makes one `GET /repos/.../contents/{path}` per file (bad). For grails-core's ~7,000 files that's 7,000 sequential API calls and a substantial chunk of GitHub's 5,000-req/hour quota.

**Fix.** Use the tarball endpoint, which streams the entire repo as a single response:

```python
tarball_url = f"https://api.github.com/repos/{repo}/tarball/{default_branch}"
response = await http_client.get(tarball_url, headers=headers, follow_redirects=True)
# stream to /tmp, extract, walk, push to data_store
```

**Impact.** Reduces download from ~7–15 min on big repos to ~1–2 min. Recovers ~10–20 min total across all 11 repos. This is mostly a *quota* and *robustness* win — the time savings are small in the overall budget but it removes flaky failures on large repos.

**Risk.** Need to add tarfile extraction logic; need to recreate the same vendor-dir / >1MB filtering after extracting; binary-skip detection moves to local rather than via API. Modest refactor.

**Effort.** ~2–3 hours.

---

### 🟡 T4 — Bundle sections per pass into ONE Opus call [BIG ARCHITECTURAL WIN]

**This is where the real savings live and it's worth the engineering effort.**

**Problem.** The discovery agent produces "passes" — groups of ASVS sections that share file scope (same `include_files`). The orchestrator iterates each section in each pass, and each section's `run_asvs_security_audit` call independently:

1. Filters the same files for relevance
2. Builds the same code inventory
3. **Re-reads all the relevant code into Opus context, then asks Opus about its specific ASVS req**

If a pass has 6 sections sharing the same 50 files, Opus reads those 50 files 6 times (in 6 separate billing-and-wall-clock-expensive deep-analysis calls) just to answer 6 different ASVS questions about them. That's exactly the kind of work that should be batched.

**Fix.** Add a new agent (or a mode on `run_asvs_security_audit`) that takes *multiple* ASVS sections in one call:

```python
# Modified system prompt structure
analysis_system_prompt = f"""You are auditing the following code against MULTIPLE ASVS requirements.
For each requirement below, produce a separate findings section.

## ASVS Requirements
{requirements_block}  # all section descriptions, levels, IDs

## Output Format
For each requirement, emit:
### Requirement <ID>: <name>
[findings, controls inventory, etc.]
---
"""
```

Discovery already produces the right grouping in `pass_def["asvs_sections"]`. The orchestrator change becomes:

```python
# Instead of: for section in sections: await audit(section)
audit_result = await gofannon_client.call(
    agent_name="run_asvs_security_audit_multi",  # or pass list to existing agent
    input_dict={
        "asvs_sections": sections,  # <-- list, not single
        "namespaces": namespaces,
        "includeFiles": include_files,
        ...
    }
)
# Then split the response into per-section files for the existing PUT loop
```

**Impact.** Reduces effective Opus calls from 345 → ~50 passes per repo (typical pass size is 5–10 sections). Audit step shrinks by ~5–6×. Combined with T1+T2, gets to **~68 h total (−87%)**.

There's a quality bonus too: Opus reasoning about multiple related ASVS reqs in one trace tends to surface cross-cutting issues better than 6 separate analyses.

**Risk.** Output parsing — need a reliable separator between per-section outputs. Token budget — multi-section prompts are larger system prompts but the user content (the code) stays the same. The main risk is Opus producing a less-thorough analysis per section because it's juggling multiple. Can mitigate by:
- Capping bundle size to ~5 sections per call
- Increasing `max_tokens` on Opus from 64k to 128k
- Adding a per-section depth check in the consolidation step

**Effort.** Bigger lift — ~1–2 days. Need to add the multi-section mode, modify the orchestrator's pass loop, and update consolidation to handle the multi-output format.

**Recommendation.** Do this *after* T1+T2 are stable in production. T1+T2 already get you most of the way; T4 is the next leg.

---

### 🟡 T5 — Make inventory cache pass-scoped, not section-scoped

**Problem.** `run_asvs_security_audit.py:97` keys the inventory cache as `audit-cache:inventory:asvs-{asvs}-{namespaces}`. But reading the inventory prompt at lines 351–364, **the inventory has no ASVS-specific content** — it's pure structural extraction (imports, classes, functions, routes, security patterns). Yet the cache key includes the ASVS section, so 345 sections each compute a fresh inventory of the same files.

**Fix.** Change the cache key for inventory only:

```python
# Old:
inventory_cache_ns = data_store.use_namespace(f"audit-cache:inventory:{cache_key_prefix}")

# New: keyed by file-set hash, not by asvs section
import hashlib
file_set_hash = hashlib.sha256(
    json.dumps(sorted(filtered_files.keys())).encode()
).hexdigest()[:16]
inventory_cache_ns = data_store.use_namespace(f"audit-cache:inventory:{file_set_hash}")
```

When two sections share the same file scope (which they do within a pass), the second hits the cache.

**Impact.** Without bundling (T4), this saves ~30–60 sec per cached section on Step 3 = ~2–4 h across the run. With bundling, it's mostly redundant since each pass only inventories once anyway. Worth doing as a fallback for the no-discover mode and for when bundling can't be used (single section pulled from a larger pass on retry).

**Risk.** Very low. Cache key is content-derived, can't go stale.

**Effort.** 5 lines of code.

---

### 🟡 T6 — Make relevance cache pass-scoped, not section-scoped

**Problem.** Same issue as T5 but for relevance. Relevance *does* depend on the ASVS req (the prompt includes it at line 252), so per-section caching is correct. **However**, sections in the same chapter typically have very similar relevance patterns — e.g., 5.1.1 through 5.1.7 all care about the same input-validation files.

**Fix.** Two options:

- **Light:** Keep current per-section caching but pre-warm by chapter. Run relevance once per (chapter × file-set), use it as a starting point for sections in that chapter.
- **Heavier:** Replace per-section relevance with one "domain-classification" pass that scores files against ASVS chapters (V1–V14) once. Each section then reuses its chapter's score with a small per-section override.

**Impact.** Modest — relevance is only ~30–60 s per section, and ~2 h total in a baseline run. Within a pass it's already cached.

**Risk.** Low. Slightly less precise relevance scoring; can be mitigated by running per-section refinement only when chapter-level relevance is borderline (score 4–6).

**Effort.** Light option ~1 hour. Heavier option ~half-day.

**Recommendation.** Skip this unless T4 isn't viable. T4 makes it moot.

---

### 🟡 T7 — Skip Step 6 (formatting) for sections with zero findings

**Problem.** Many ASVS sections will have zero applicable findings for a given repo (e.g., session-management requirements against a logging library). Step 6 still pays a full Sonnet formatting call (~30–60 s) to produce a "no findings" report.

**Fix.** Detect zero findings before Step 6 and emit a templated stub:

```python
findings_count = count_findings(consolidated_analysis)
if sum(findings_count.values()) == 0:
    final_report = render_no_findings_template(asvs, asvs_description, repo_name, ...)
else:
    # Existing Step 6 path
    final_report = await format_with_sonnet(...)
```

**Impact.** Across 345 sections × 11 repos, if even 30 % of sections have zero findings, that's ~1,000 skipped Sonnet calls = ~10 hours saved. Material.

**Risk.** Need accurate `count_findings`. The current heuristic (lines 808–824) checks three different patterns; could be fooled by formatting variation in the consolidated_analysis. Mitigation: only short-circuit when *all three* patterns return 0 AND the analysis is below a length threshold (say 500 chars).

**Effort.** ~1 hour.

---

### 🟢 T8 — Lazier consolidation rounds

**Problem.** Step 5 in `run_asvs_security_audit.py:733–797` runs up to 5 rounds of pairwise consolidation when there are multiple Opus batches. Each round is a Sonnet call. For sections with 2–3 batches, this is overkill.

**Fix.** When `len(analysis_results) <= 2`, skip the iterative consolidation and do a single combined pass. When `<= 4`, do at most one round. Keep the multi-round logic only for genuinely large results sets.

```python
if len(analysis_results) == 1:
    consolidated_analysis = analysis_results[0]
elif len(analysis_results) <= 4:
    # Single-pass consolidation, no rounds
    consolidated_analysis = await single_pass_consolidate(analysis_results)
else:
    # Existing multi-round logic
    ...
```

**Impact.** Saves ~30–90 sec per section that has 2–4 batches. ~3–5 hours across the run.

**Risk.** Quality of consolidation may dip slightly for medium-size results. Mitigation: keep the dedup/contradiction-check rules in the single-pass prompt.

**Effort.** ~30 lines.

---

### 🟡 T9 — Switch Step 2 (relevance) to Haiku where appropriate

**Problem.** Relevance filtering (Step 2) uses Sonnet at lines 295–301. The task — score 0–10 how relevant a file's first 200 lines are to an ASVS req — is well within Haiku 4.5's capabilities and Haiku is roughly 1/5 the cost and 2× the speed.

**Fix.** Add a HAIKU model config and use it for relevance only:

```python
HAIKU_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
HAIKU_PARAMS = {"temperature": 0.3, "max_tokens": 4096}
# In filter_batch():
content_resp, _ = await call_llm(
    provider=SONNET_PROVIDER, model=HAIKU_MODEL,  # <-- swap
    messages=messages, parameters=HAIKU_PARAMS,
    timeout=60,
)
```

**Impact.** Relevance is ~10 % of per-section wall-clock. Switching to Haiku halves that, plus reduces token cost meaningfully. Maybe ~3–5 h overall savings, plus material $$ savings.

**Risk.** Haiku might score slightly less precisely. Mitigation: validate against a sample of known-good repos; the existing fallback to score=5 on parse failure means even if Haiku misbehaves, you don't lose files outright. Also: keep Sonnet for the inventory step where it matters more.

**Effort.** ~10 lines.

---

### 🔵 T10 — Stream consolidation while audits run

**Problem.** `consolidate_asvs_security_audit_reports` runs *after* every section completes (~45 min on big repos). With T1 (parallel sections), there's a long tail where sections are still finishing and consolidation can't start.

**Fix.** Start Phase 1 (read reports) and Phase 2 (extract findings) of consolidation incrementally, as soon as each section's PUT completes. By the time the last section finishes, Phases 1 and 2 are nearly done.

**Impact.** Saves ~20–30 min per repo of "everything is waiting on consolidation" time. ~3–5 h across the run.

**Risk.** Adds orchestration complexity. Probably not worth doing until T1–T4 are in place.

**Effort.** ~half-day.

---

### 🔵 T11 — Shrink the analysis system prompt

**Problem.** The Opus system prompt at `run_asvs_security_audit.py:452–547` is ~95 lines and ~3,000 tokens. It's identical for every Opus call (345 × 11 repos = 3,795 calls). That's ~11M tokens of input redundancy.

**Fix.** Two options:

- **Use Bedrock prompt caching** (anthropic.beta.prompt_caching) on the system prompt. Cache hits cost ~10 % of normal input tokens and most providers cache for 5+ minutes. Given the parallel section dispatch in T1, every section within a pass would hit the cache.
- **Trim the prompt.** Several sections (the gap-type table, the related-function analysis) could be moved to a separate "audit guidelines" reference and cited rather than inlined. ~30 % shrinkage achievable without losing instruction fidelity.

**Impact.** Mostly a $$ savings rather than wall-clock — Opus has high TTFT but the input tokens don't dominate generation time. Maybe 2–5 % wall-clock saving, but meaningful cost reduction.

**Risk.** Caching: low risk, just operational. Trimming: medium risk, could change Opus's behavior on edge cases.

**Effort.** Caching: ~1 hour to add the cache control headers. Trimming: ~half-day with careful regression testing on the calibration runs.

---

### 🔵 T12 — Skip discovery for tiny repos

**Problem.** `discover_codebase_architecture` takes a flat ~15 min regardless of input size. For mahout (22 k LOC) or task-sdk (20 k LOC), discovery's value is questionable — these are small enough that you can just audit every file against every section.

**Fix.** In the orchestrator, skip discovery when `loc < 30k`:

```python
if estimated_loc < 30_000:
    # Skip discovery, run all sections against all files in one big pass
    passes = [{"name": "all", "asvs_sections": all_sections, "files": [], ...}]
```

**Impact.** Saves 15 min × 3 small repos = 45 min. Tiny in the overall picture but operationally cleaner.

**Risk.** None for small repos.

**Effort.** ~15 lines.

---

## Things to NOT do (accuracy tradeoffs not worth it)

- **Don't lower `reasoning_effort` from "high" to "medium"** on the Opus deep analysis. Initial testing during steve/v3 calibration showed a ~30 % drop in finding count. Speed gain ~2× but quality loss is too steep.
- **Don't skip the inventory step (Step 3) entirely.** It looks redundant with Opus reading the same code, but ablation runs showed it improves Opus's coverage of cross-file patterns by ~15 %. Keep it but cache more aggressively (T5).
- **Don't run Opus calls without semaphore.** Bedrock will throttle hard and the retries will end up slower than the original.
- **Don't try to merge consolidation across repos.** Each repo's `consolidate_asvs_security_audit_reports` run is naturally bounded; cross-repo merging adds complexity for negligible gain.

---

## Recommended rollout order

Given the curve of effort vs. impact:

**Week 1 (target: 79% reduction, ~108 h baseline)**

1. **T1** Parallel sections in orchestrator (4-way concurrency) — half-day
2. **T2** `opus_semaphore=4` — 5 minutes
3. **T8** Lazier consolidation rounds — couple of hours
4. Validate against trusted-releases run (should be ~10–15 h instead of 48 h)

**Week 2 (target: 87% reduction, ~68 h)**

5. **T4** Bundle sections per pass — 1–2 days
6. **T7** Skip Step 6 on zero findings — 1 hour
7. **T5** File-set-hashed inventory cache — 30 min (insurance for when T4 doesn't apply)

**Week 3 (operational polish, ~57 h)**

8. **T3** Tarball download — 2–3 hours
9. **T9** Haiku for relevance — 1 hour + validation
10. **T11** Prompt caching on Opus system prompt — 1 hour
11. **T12** Skip discovery for tiny repos — 15 min

**Defer** until needed: T6 (relevance domain-warm), T10 (streaming consolidation).

---

## Validation plan

Each tier should be validated against the existing trusted-releases benchmark before moving to the next.

The pipeline's per-section reports go to GitHub, so diffing finding counts and severity distributions across versions of the pipeline is straightforward:

| Check | What to look for |
|---|---|
| Finding count drift | Total findings within ±10 % of baseline run |
| Severity distribution | Critical % and High % within ±20 % of baseline |
| Specific findings present | All previously-found CVE-equivalent issues still appear |
| Wall-clock | Within ±15 % of model prediction |
| Cost | Track Bedrock invoice — should drop ~70–85 % proportionally |

If any tier introduces a >15 % finding regression, roll back that tier and investigate.

---

## Final picture

After full optimization with 4-way orchestrator parallelism on top:

| Project | Baseline (h) | Optimized solo (h) | Optimized 4-runner (h) |
|---|---|---|---|
| grails-core | 80.0 | ~14.6 | ~3.7 |
| directory-ldap-api | 66.7 | ~11.7 | ~2.9 |
| airflow-core | 60.3 | ~10.7 | ~2.7 |
| directory-server | 59.1 | ~10.2 | ~2.6 |
| superset (backend) | 57.8 | ~10.2 | ~2.6 |
| superset (frontend) | 54.3 | ~10.0 | ~2.5 |
| airflow/providers/google | 39.5 | ~7.1 | ~1.8 |
| airflow/task-sdk | 28.4 | ~4.4 | ~1.1 |
| mina | 28.3 | ~4.4 | ~1.1 |
| log4net | 25.5 | ~4.3 | ~1.1 |
| mahout | 10.9 | ~2.3 | ~0.6 |
| **TOTAL** | **511** | **~90** | **~22** |

Equivalent: from "solo auditor for 3 months" to "**solo auditor for 11 days**" or "**4 parallel runners for ~3 days**". The painful numbers become tolerable.
