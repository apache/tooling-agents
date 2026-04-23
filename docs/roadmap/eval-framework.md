# ASVS Pipeline: Eval Framework and Operational QA

Design document for testing, evaluating, and operating the ASVS audit pipeline at scale across hundreds of ASF projects.

## What "Eval" Means Here

In the LLM context, an eval is a repeatable measurement of output quality against known-good answers. For a security audit pipeline, this means:

- **Does the pipeline find known vulnerabilities?** (recall)
- **Are the findings real?** (precision)
- **Does it correctly handle code that's secure?** (false positive rate)
- **Does it gracefully handle edge cases?** (robustness)
- **Do agent changes improve or degrade quality?** (regression)

This is different from traditional unit testing. LLM outputs are non-deterministic — the same input can produce different (but equivalent) findings across runs. Evals need to measure semantic correctness, not string equality.

## Eval Architecture

```
eval/
├── fixtures/                    # Known codebases with expected results
│   ├── webgoat-minimal/         # Small app with intentional vulns
│   │   ├── src/                 # Source code
│   │   ├── expected.json        # Expected findings (section → severity → count)
│   │   └── false_positives.json # Known FP patterns to check for absence
│   ├── secure-app/              # Clean app, should produce few/no findings
│   │   ├── src/
│   │   └── expected.json
│   ├── library-only/            # Pure library, many N/A sections
│   │   ├── src/
│   │   └── expected.json
│   └── edge-cases/
│       ├── empty-repo/
│       ├── binary-only/
│       ├── single-file/
│       └── huge-repo/           # 10k+ files, tests path prefix scoping
├── harness.py                   # Eval runner
├── judge.py                     # LLM-as-judge for semantic comparison
├── metrics.py                   # Scoring functions
├── report.py                    # Eval report generator
└── README.md
```

## Fixtures

### What Makes a Good Fixture

A fixture is a small, stable codebase with documented security properties. Each fixture needs:

1. **Source code** — small enough to audit quickly (< 50 files), large enough to be realistic
2. **Expected findings** — what the pipeline should find, expressed as ranges not exact counts
3. **False positive patterns** — specific things the pipeline should NOT flag
4. **Not-applicable sections** — ASVS sections that don't apply (for library fixtures)

### Fixture Types

**Vulnerability fixtures** — intentionally insecure code targeting specific ASVS sections:

```json
{
  "name": "webgoat-minimal",
  "type": "web_app",
  "framework": "flask",
  "expected_findings": {
    "1.2.1": {"min_severity": "HIGH", "min_count": 1, "category": "XSS"},
    "6.2.1": {"min_severity": "MEDIUM", "min_count": 1, "category": "weak_password"},
    "3.4.1": {"min_severity": "HIGH", "min_count": 1, "category": "insecure_cookie"}
  },
  "expected_na": ["9.1.1", "9.1.2"],
  "false_positive_patterns": [
    {"section": "1.3.1", "pattern": "CSRF on login form", "reason": "Login forms don't need CSRF"}
  ]
}
```

**Clean fixtures** — secure code that should produce minimal findings:

```json
{
  "name": "secure-app",
  "type": "web_app",
  "max_high_findings": 2,
  "max_critical_findings": 0,
  "notes": "If pipeline finds critical issues here, it's probably hallucinating"
}
```

**Edge case fixtures** — test robustness, not finding quality:

```json
{
  "name": "binary-only",
  "type": "edge_case",
  "expected_behavior": "graceful_na",
  "should_not_crash": true,
  "expected_reports": 0
}
```

### Building Fixtures from Real Runs

The best fixtures come from real audits where we've manually verified findings:

1. Take the ATR da901ba L1+L2 run (253 sections, manually reviewed and triaged) — reports at [`ASVS/reports/tooling-trusted-releases/da901ba/`](../../ASVS/reports/tooling-trusted-releases/da901ba/) including [consolidated report](../../ASVS/reports/tooling-trusted-releases/da901ba/consolidated-L1-L2.md), [issues](../../ASVS/reports/tooling-trusted-releases/da901ba/issues-L1-L2.md), and [triage notes](../../ASVS/reports/tooling-trusted-releases/da901ba/triage.txt)
2. Mark each finding as TP (true positive), FP (false positive), or PARTIAL
3. Use this as a regression baseline — future pipeline changes should not lose TPs or reintroduce FPs
4. The audit_guidance documents are effectively the "answer key" for false positive patterns

## Eval Metrics

### Per-Section Metrics

| Metric | How to Measure | Target |
|--------|---------------|--------|
| **Finding recall** | Known vulns found / known vulns in fixture | > 80% |
| **False positive rate** | FP findings / total findings | < 20% |
| **N/A accuracy** | Correctly identified N/A sections / total N/A sections | > 90% |
| **Severity accuracy** | Findings with correct severity / findings with any severity | > 70% |
| **Report completeness** | Reports with all required sections (summary, findings, remediation) | 100% |

### Pipeline Metrics

| Metric | How to Measure | Target |
|--------|---------------|--------|
| **Completion rate** | Sections with reports / total sections attempted | > 98% |
| **Extraction success** | Reports successfully extracted into consolidation | > 95% |
| **Consolidation dedup rate** | Unique findings / raw findings before dedup | 40-70% |
| **Cost per section** | Average token cost per ASVS section audit | Track trend |
| **Time per section** | Average wall clock time per section | Track trend |

### LLM-as-Judge

For semantic comparison (did the pipeline find the same vulnerability, even if described differently), use an LLM judge:

```python
JUDGE_PROMPT = """Compare these two security findings and determine if they describe the same vulnerability.

Expected finding:
{expected}

Actual finding:
{actual}

Respond with JSON: {"match": true/false, "confidence": 0.0-1.0, "reason": "..."}
"""
```

This handles the non-determinism problem — the pipeline might describe a finding differently across runs, but the judge can determine if they're semantically equivalent.

## Eval Runner

```python
# harness.py (sketch)

async def run_eval(fixture_path: str, pipeline_config: dict) -> EvalResult:
    """Run a single fixture through the pipeline and score results."""
    
    fixture = load_fixture(fixture_path)
    
    # 1. Load fixture source into data store
    namespace = f"eval:{fixture.name}"
    load_fixture_code(namespace, fixture.src_path)
    
    # 2. Run pipeline (discovery + audit, no GitHub push)
    results = await run_pipeline_local(
        namespace=namespace,
        level=fixture.level or "L1",
        sections=fixture.target_sections,  # or all if not specified
    )
    
    # 3. Score results
    scores = score_results(fixture, results)
    
    # 4. Generate report
    return EvalResult(
        fixture=fixture.name,
        scores=scores,
        findings=results.findings,
        duration=results.duration,
        cost=results.token_cost,
    )

async def run_eval_suite(suite_path: str) -> EvalSuiteResult:
    """Run all fixtures and produce aggregate scores."""
    fixtures = discover_fixtures(suite_path)
    results = []
    for fixture in fixtures:
        result = await run_eval(fixture)
        results.append(result)
        print(f"  {fixture.name}: recall={result.scores.recall:.0%} "
              f"precision={result.scores.precision:.0%} "
              f"FP={result.scores.false_positive_rate:.0%}")
    return aggregate(results)
```

### Running Evals

```bash
# Run full eval suite
python eval/harness.py eval/fixtures/

# Run single fixture
python eval/harness.py eval/fixtures/webgoat-minimal/

# Compare two pipeline versions
python eval/harness.py eval/fixtures/ --baseline results/v1.json --output results/v2.json
python eval/report.py results/v1.json results/v2.json
```

### Regression Detection

After any agent change (prompt update, model switch, parameter tweak), run the eval suite and compare:

```
Pipeline v1 → v2 Comparison
============================
                    v1        v2        Δ
Finding recall      82%       85%       +3% ✅
False positive rate 18%       12%       -6% ✅
N/A accuracy        91%       93%       +2% ✅
Completion rate     98.5%     99.1%     +0.6% ✅
Extraction success  96%       98%       +2% ✅
Cost per section    $0.42     $0.38     -$0.04 ✅

Regressions:
  (none)

New findings in v2 not in v1:
  webgoat-minimal 3.4.1: Found cookie without Secure flag (HIGH) ← NEW TP
  
Findings in v1 lost in v2:
  (none)
```

## Operational Error Handling at Scale

When running across hundreds of projects, the pipeline will encounter errors it's never seen before. These need to be surfaced automatically, not silently swallowed.

### Error Classification

```python
KNOWN_ERRORS = {
    "litellm.Timeout": {
        "action": "retry",
        "max_retries": 2,
        "escalate_after": 3,  # file issue after 3 occurrences in 24h
    },
    "json.JSONDecodeError": {
        "action": "retry_with_fallback",
        "fallback": "parse_llm_json",
        "escalate_after": 10,
    },
    "httpx.HTTPStatusError:404": {
        "action": "skip",
        "reason": "File not found in repo",
        "escalate_after": None,  # never escalate, expected for some repos
    },
    "httpx.HTTPStatusError:403": {
        "action": "abort",
        "reason": "Rate limited or token expired",
        "escalate_after": 1,
    },
}
```

### Auto-Filing GitHub Issues

When the pipeline encounters an error not in `KNOWN_ERRORS`, or a known error exceeds its escalation threshold:

```python
async def handle_error(error, context):
    """Classify error and optionally file a GitHub issue."""
    
    error_key = classify_error(error)
    
    if error_key in KNOWN_ERRORS:
        config = KNOWN_ERRORS[error_key]
        
        # Track occurrence count
        count = increment_error_count(error_key, window_hours=24)
        
        if config["escalate_after"] and count >= config["escalate_after"]:
            await file_issue(error, context, label="known-error-escalation")
        
        return config["action"]
    else:
        # Unknown error — always file an issue
        await file_issue(error, context, label="unknown-error")
        return "abort"

async def file_issue(error, context, label):
    """File a GitHub issue for an error, deduplicating by error signature."""
    
    signature = error_signature(error)  # e.g., hash of error type + message pattern
    
    # Check if issue already exists
    existing = await search_issues(
        repo="apache/tooling-agents",
        query=f"label:{label} {signature} is:open"
    )
    
    if existing:
        # Add comment to existing issue with new occurrence
        await add_comment(existing[0], format_occurrence(error, context))
        return
    
    # Create new issue
    await create_issue(
        repo="apache/tooling-agents",
        title=f"[Pipeline Error] {error.__class__.__name__}: {str(error)[:80]}",
        labels=[label, "pipeline", context.get("agent_name", "unknown")],
        body=format_issue_body(error, context),
    )
```

### Issue Body Format

```markdown
## Pipeline Error Report

**Error:** `json.JSONDecodeError: Expecting property name enclosed in double quotes`
**Agent:** `consolidate_asvs_security_audit_reports`
**Project:** apache/steve (v3, commit d0aa7e9)
**Section:** 16.3.4
**Signature:** `err_7f3a2b`

### Context
- Report size: 45,231 chars
- Extraction attempt: 2 of 2
- LLM response first 200 chars: `{'timestamp': self.formatTime(record)...`

### Error Classification
- **Type:** Known error exceeding threshold (10 occurrences in 24h)
- **Root cause:** LLM returning Python-style dicts instead of JSON for reports with extensive code blocks
- **Current mitigation:** `parse_llm_json` with regex fallback

### Occurrences (last 24h)
| Time | Project | Section | Attempt |
|------|---------|---------|---------|
| 04:41 | apache/steve | 16.3.4 | 1/2 |
| 04:42 | apache/steve | 16.3.4 | 2/2 |
| ... | ... | ... | ... |
```

### Error Signature Deduplication

The error signature should group related errors without creating duplicate issues:

```python
def error_signature(error, context=None):
    """Generate a stable signature for deduplication."""
    components = [
        error.__class__.__name__,
        # Normalize the message: strip specific values, keep pattern
        re.sub(r'\d+', 'N', str(error)[:100]),
        context.get("agent_name", "") if context else "",
    ]
    return hashlib.sha256("|".join(components).encode()).hexdigest()[:8]
```

This groups "JSONDecodeError at line 2 column 9" and "JSONDecodeError at line 5 column 12" into the same issue (both are JSON parse failures in the same agent), while separating them from a JSONDecodeError in a different agent.

## Operational Dashboard

At scale (hundreds of projects), we need visibility into pipeline health:

### Key Metrics to Track

```
Per-run metrics (stored in data store):
  - project, commit, level, timestamp
  - sections_attempted, sections_completed, sections_failed
  - findings_total, findings_by_severity
  - extraction_success_rate
  - consolidation_success (bool)
  - errors[] (type, agent, section, message)
  - duration_seconds
  - estimated_cost

Aggregate metrics (computed):
  - completion_rate_7d (rolling)
  - error_rate_by_type_7d
  - avg_findings_per_project
  - projects_audited_total
  - sections_audited_total
```

### Run Summary

After each pipeline run, the orchestrator could write a summary to the data store:

```python
run_summary = {
    "project": "apache/steve",
    "commit": "d0aa7e9",
    "level": "L3",
    "started_at": "2026-04-22T04:00:00Z",
    "completed_at": "2026-04-22T06:30:00Z",
    "sections": {"attempted": 345, "completed": 340, "failed": 5},
    "findings": {"critical": 3, "high": 28, "medium": 142, "low": 89},
    "extraction": {"success": 339, "failed": 1, "failed_reports": ["16.3.4.md"]},
    "consolidation": {"success": True, "total_findings": 577},
    "errors": [
        {"type": "timeout", "agent": "run_asvs_security_audit", "section": "1.3.3", "retried": True, "resolved": False},
        {"type": "json_parse", "agent": "consolidate", "section": "16.3.4", "retried": True, "resolved": False},
    ],
}
```

## Implementation Priority

| Phase | What | Why | Effort |
|-------|------|-----|--------|
| **1** | ATR regression fixture from existing verified L1+L2 run | We already have manually reviewed and triaged results — capture them as baseline | Low |
| **2** | Eval harness (run fixture, score, compare) | Enables confident agent changes | Medium |
| **3** | Run summary in data store | Operational visibility for multi-project runs | Low |
| **4** | Error classification + auto-filing | Scales operational support to hundreds of projects | Medium |
| **5** | LLM-as-judge for semantic comparison | Handles non-determinism in eval scoring | Medium |
| **6** | Additional fixtures (clean app, library, edge cases) | Broadens eval coverage | Ongoing |
| **7** | Dashboard / reporting | Aggregate visibility across all projects | Medium |