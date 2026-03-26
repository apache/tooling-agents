# Consolidate ASVS Security Audit Reports

You are an agent that takes inputs:
- owner/repo (the repository containing the audit reports)
- pat (GitHub personal access token)
- directories (comma-separated paths to directories containing individual ASVS audit report files, one per ASVS level)

Read all reports from the given directories in GitHub, consolidate them into a deduplicated security audit report, and generate a companion issues file. Push both files to the parent directory.

## Model Selection

- **Sonnet** — Use for Phase 1-3 (reading, extraction, domain consolidation). High-volume data transformation.
- **Opus** — Use ONLY for Phase 4 (executive summary generation). Single call where deep reasoning improves quality.

## Multi-Directory / Multi-Level Support

Input directories are comma-separated (e.g., `path/L1, path/L2`). Each directory represents an ASVS level. Reports are prefixed with their level throughout the pipeline (e.g., `L1:7.2.1.md`). Findings track which level(s) flagged them. Output files are named with levels: `consolidated-L1-L2.md`, `issues-L1-L2.md`.

## Pipeline

### Phase 1: Read All Reports
Read every `.md` file from all directories (skip files starting with `consolidated` or `issues`).

### Phase 2: Extract Findings (Sonnet, 5 concurrent, checkpointed)
For each report, extract ALL findings into structured JSON with: source_report, finding_id, severity, title, description, cwe, asvs_section, asvs_level, affected_files, recommended_remediation, related_findings, positive_controls, asvs_status.

### Phase 2.5: Enrich with ASVS Context
Load requirement descriptions from the `asvs` namespace in the data store.

### Phase 3: Domain-Grouped Consolidation (Sonnet, 3 concurrent, checkpointed)
Group reports by security domain. Consolidate each domain separately:
1. Identify TRUE duplicates (exact same vulnerability, same code location) — merge
2. Identify RELATED findings (same class, different locations) — keep separate with cross-references
3. Preserve EVERY unique finding. If in doubt, keep separate.
4. Track ASVS levels per finding.

Deduplication test: if a developer could fix one WITHOUT fixing the other, they are SEPARATE findings.

Domain groups map ASVS sections to security domains (input_encoding, business_logic, session_csrf, auth_rate_limit, etc.). Sections not in the explicit map use chapter-level fallback.

### Phase 4: Final Merge and Report Generation (batched by severity)
- Executive summary with Opus (severity distribution, level coverage, systemic risks, positive controls)
- Findings formatting with Sonnet (MAX_FINDINGS_PER_BATCH = 30, 2 retries)
- Tail sections with Sonnet (positive controls table, ASVS compliance, cross-reference matrix, level coverage)
- Issues generation with Sonnet (ISSUES_BATCH_SIZE = 75, 3 retries with backoff)

## Output Files

**consolidated-{levels}.md**: Report metadata, executive summary, all findings by severity, positive controls, ASVS compliance summary, cross-reference matrix, level coverage analysis.

**issues-{levels}.md**: One issue per actionable finding with labels (including `asvs-level:L1`), description, remediation, acceptance criteria, references. No issues for Informational findings.

## Quality Checks

- Finding count: consolidated count should be close to extracted count minus true duplicates (warn if >20% reduction)
- All source reports represented (or noted as passed/N/A)
- Per-level analysis: total findings per level, unique-to-level counts
- Issues match non-informational findings
