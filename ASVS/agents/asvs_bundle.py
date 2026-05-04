# asvs_bundle
#
# Audits multiple ASVS requirements against a SHARED file scope in a single
# Opus deep-analysis call, instead of N independent calls (one per section)
# all re-reading the same code.
#
# This is the T4 win from optimization-plan.md. When discovery groups
# sections into a "pass" sharing the same files, calling this agent once
# replaces N separate asvs_audit calls.
#
# Returns a JSON envelope:
#   {
#     "mode": "bundled",
#     "asvs_sections": ["5.1.1", "5.1.2", ...],
#     "per_section": {
#       "5.1.1": {
#         "report": "<markdown>",
#         "findings": {"Critical": N, "High": N, "Medium": N, "Low": N},
#         "files_analyzed": N, "files_total": N, "files_skipped": N
#       },
#       ...
#     },
#     "raw_consolidated": "<full markdown before splitting>"
#   }
#
# The orchestrator splits per_section[*].report into individual files for
# pushing to GitHub, while asvs_consolidate still sees one report per
# section as before.
#
# Optimizations applied within this agent (cross-ref optimization-plan.md):
#   T2 — opus_semaphore raised from 2 to 4 (env-overridable)
#   T5 — inventory cache keyed by file-set hash, not by ASVS section
#   T8 — single-pass consolidation when ≤4 batch results
#   T9 — Step 2 (relevance) uses Haiku 4.5 instead of Sonnet
#
# Input:
#   {
#     "namespaces": ["files:owner/repo"],
#     "asvs_sections": ["5.1.1", "5.1.2", "5.1.3"],   # required, must be a list
#     "includeFiles": ["src/auth/**", ...],            # optional
#     "domainContext": "...",                          # optional
#     "severityThreshold": "MEDIUM",                   # optional
#     "falsePositiveGuidance": ["..."]                 # optional
#   }

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        def _short_asvs_summary(desc, max_chars=300):
            """Extract a clean one-line summary from the multi-line ASVS context.

            The asvs_description string is built by joining several labeled lines
            (`Description:`, `Level:`, `Section:`, `Section Description:`). For the
            Executive Summary we only want the `Description:` line, truncated at a
            word boundary so we don't end mid-word.
            """
            if not desc:
                return ""
            for line in str(desc).split("\n"):
                if line.startswith("Description: "):
                    text = line[len("Description: "):].strip()
                    if len(text) <= max_chars:
                        return text
                    cutoff = text.rfind(" ", 0, max_chars)
                    if cutoff < 0:
                        cutoff = max_chars
                    return text[:cutoff].rstrip(",.;:") + "\u2026"
            # Fallback: first non-blank line
            for line in str(desc).split("\n"):
                line = line.strip()
                if line:
                    if len(line) <= max_chars:
                        return line
                    cutoff = line.rfind(" ", 0, max_chars)
                    if cutoff < 0:
                        cutoff = max_chars
                    return line[:cutoff].rstrip(",.;:") + "\u2026"
            return ""

        def _count_findings(content):
            """Count findings by severity in a report body.

            Strategy: Finding ID format is the strongest, most consistent signal
            across model outputs (`ASVS-{section}-{SEV}-NNN`). We extract those
            and classify by severity token. Falls back to severity headings or
            inline `**Severity**:` lines if no IDs are present.

            Handles all observed formats:
              - `#### MEDIUM` / `### [HIGH]` / `## Critical` (any heading depth)
              - `**Finding ID:** ASVS-221-MED-001` (CRIT/CRITICAL, MED/MEDIUM)
              - `**Severity:** Medium` / `**Severity**: High`
            """
            import re
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

            # Primary: count Finding IDs and classify each by its severity token
            finding_ids = re.findall(
                r'ASVS-\d+-(CRIT(?:ICAL)?|HIGH|MED(?:IUM)?|LOW)-\d+',
                content, re.IGNORECASE,
            )
            for sev_token in finding_ids:
                token_upper = sev_token.upper()
                if token_upper.startswith("CRIT"):
                    counts["Critical"] += 1
                elif token_upper == "HIGH":
                    counts["High"] += 1
                elif token_upper.startswith("MED"):
                    counts["Medium"] += 1
                elif token_upper == "LOW":
                    counts["Low"] += 1

            if sum(counts.values()) > 0:
                return counts

            # Fallback 1: severity headings at any heading depth, with or without brackets
            for sev_name, key in [("critical", "Critical"), ("high", "High"),
                                   ("medium", "Medium"), ("low", "Low")]:
                pattern = rf'(?im)^#{{1,6}}\s*\[?\s*{sev_name}\s*\]?\s*$'
                counts[key] += len(re.findall(pattern, content))

            if sum(counts.values()) > 0:
                return counts

            # Fallback 2: inline **Severity**: X lines
            counts["Critical"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Critical', content, re.IGNORECASE))
            counts["High"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*High', content, re.IGNORECASE))
            counts["Medium"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Medium', content, re.IGNORECASE))
            counts["Low"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Low', content, re.IGNORECASE))
            return counts

        def _split_bundled_output(consolidated_analysis, asvs_sections, asvs_descriptions,
                                  repo_name, audit_date, n_relevant, n_total, skipped):
            """Split bundled Opus output into per-section reports.

            Opus is instructed to produce `## ASVS-{section}:` headers per section.
            We split on those, attach the cross-cutting tail to each section's report,
            and produce a fully-formed markdown report per section.
            """
            import re

            per_section = {}

            tail_match = re.search(
                r'(##\s*Cross-cutting Architecture Observations[\s\S]*)',
                consolidated_analysis,
            )
            cross_cutting_tail = tail_match.group(1) if tail_match else ""
            body = consolidated_analysis
            if tail_match:
                body = consolidated_analysis[:tail_match.start()]

            section_pattern = re.compile(
                r'##\s*ASVS-(\d+(?:\.\d+)*)[:\s][^\n]*\n([\s\S]*?)(?=##\s*ASVS-\d|\Z)',
                re.MULTILINE,
            )

            found_sections = {}
            for m in section_pattern.finditer(body):
                sid = m.group(1)
                block = m.group(0)
                found_sections[sid] = block

            for sid in asvs_sections:
                section_body = found_sections.get(sid)
                if section_body is None:
                    print(f"    WARNING: No bundled output for section {sid} — emitting empty report", flush=True)
                    section_body = (
                        f"## ASVS-{sid}\n\n"
                        f"_No findings produced by the bundled analysis. This may indicate "
                        f"the section is not applicable to the audited file scope._\n"
                    )

                findings_count = _count_findings(section_body)
                report = _format_section_report(
                    sid, asvs_descriptions.get(sid, f"ASVS Requirement {sid}"),
                    repo_name, audit_date, n_relevant, n_total, skipped,
                    findings_count, section_body, cross_cutting_tail,
                )
                per_section[sid] = {
                    "report": report,
                    "findings": findings_count,
                    "files_analyzed": n_relevant,
                    "files_total": n_total,
                    "files_skipped": skipped,
                }

            return per_section

        def _format_section_report(asvs, asvs_description, repo_name, audit_date,
                                   n_relevant, n_total, skipped,
                                   findings_count, body, cross_cutting_tail):
            return f"""# Security Audit Report: ASVS {asvs}

## Executive Summary

| Field | Value |
|-------|-------|
| **Repository** | {repo_name} |
| **Audit Date** | {audit_date} |
| **Auditor** | Tooling Agents (bundled-pass mode) |
| **ASVS Requirement** | ASVS {asvs} |
| **Files Analyzed** | {n_relevant} relevant / {n_total} total |
| **Files Skipped** | {skipped} |

**Requirement description:** {_short_asvs_summary(asvs_description)}

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {findings_count['Critical']} |
| 🟠 High | {findings_count['High']} |
| 🟡 Medium | {findings_count['Medium']} |
| 🟢 Low | {findings_count['Low']} |

---

{body}

{cross_cutting_tail}
        """

        def _empty_section_report(asvs, asvs_description, repo_name, audit_date,
                                  n_relevant, n_total, skipped):
            return f"""# Security Audit Report: ASVS {asvs}

## Executive Summary

| Field | Value |
|-------|-------|
| **Repository** | {repo_name} |
| **Audit Date** | {audit_date} |
| **Auditor** | Tooling Agents (bundled-pass mode) |
| **ASVS Requirement** | ASVS {asvs} |
| **Files Analyzed** | {n_relevant} relevant / {n_total} total |
| **Files Skipped** | {skipped} |

**Requirement description:** {_short_asvs_summary(asvs_description)}

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 0 |
| 🟡 Medium | 0 |
| 🟢 Low | 0 |

## Result

No relevant files found for ASVS requirement {asvs} within the audited scope.
        """

        async def _single_pass_consolidate(results, asvs_description, provider, model, params):
            """T8: One Sonnet call merges ≤4 batch results — no multi-round loop."""
            prompt = f"""You are consolidating multiple security audit batch results into a single unified analysis.

ASVS Requirements being audited:
{asvs_description}

NOTE: This is a bundled multi-section audit. The output MUST preserve the
per-section structure (## ASVS-{{section}}: ... headers). Do NOT merge findings
across different ASVS sections — only deduplicate WITHIN a section.

## Consolidation Rules:
1. DEDUPLICATE — Within each section, merge findings describing the same vulnerability
2. CHECK CONTRADICTIONS — If something appears as a positive pattern in ANY batch, remove from findings
3. VERIFY DATA ORIGINS — Remove findings where source is database/config without user injection path
4. CONSISTENT SEVERITY — Ensure similar issues have the same severity
5. REMOVE OUT-OF-SCOPE — Exclude test files, dev scripts
6. PRESERVE SPECIFICS — Keep all exact code references, line numbers, and technical details

Consolidate these analysis results into a single report with the per-section structure intact.

BATCH RESULTS TO CONSOLIDATE:
        """ + "\n---\n".join(results)

            messages = [{"role": "user", "content": prompt}]
            consolidation_params = {**params, "max_tokens": 32000}
            for attempt in range(2):
                try:
                    resp, _ = await call_llm(
                        provider=provider, model=model,
                        messages=messages, parameters=consolidation_params, timeout=600,
                    )
                    return resp
                except Exception as e:
                    if attempt == 0:
                        print(f"    Single-pass consolidation attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                        await asyncio.sleep(5)
                    else:
                        print(f"    Single-pass consolidation failed, joining raw: {e}", flush=True)
                        return "\n\n---\n\n".join(results)

        async def _multi_round_consolidate(results, asvs_description, provider, model, params, context_window):
            """Original multi-round behavior, kicks in only for >4 batch results."""
            template = f"""You are consolidating multiple security audit batch results into a single unified analysis.

ASVS Requirements:
{asvs_description}

NOTE: This is a bundled multi-section audit. Preserve per-section structure
(## ASVS-{{section}}: ... headers). Deduplicate WITHIN sections only.

## Consolidation Rules:
1. DEDUPLICATE - Merge findings describing the same vulnerability within a section
2. CHECK CONTRADICTIONS - If something appears as a positive pattern in ANY batch, remove from findings
3. VERIFY DATA ORIGINS - Remove findings where source is database/config without user injection path
4. CONSISTENT SEVERITY - Ensure similar issues have same severity
5. REMOVE OUT-OF-SCOPE - Exclude test files, dev scripts
6. VERIFY COMPLETENESS - For each vulnerability, confirm related functions were checked

BATCH RESULTS TO CONSOLIDATE:
        """
            consolidation_params = {**params, "max_tokens": 16384}
            template_tokens = count_tokens(template, provider, model)
            max_cons_content = int(context_window * 0.40) - template_tokens

            consolidation_round = 0
            MAX_ROUNDS = 5
            batch_results = list(results)

            while len(batch_results) > 1:
                consolidation_round += 1
                prev_count = len(batch_results)
                next_level = []
                group = []
                group_tokens = 0

                for result in batch_results:
                    result_tokens = count_tokens(result, provider, model)
                    if group and (group_tokens + result_tokens) > max_cons_content:
                        merged = await _try_consolidate(template, group, provider, model, consolidation_params)
                        if merged is None:
                            next_level.extend(group)
                        else:
                            next_level.append(merged)
                        group = []
                        group_tokens = 0
                    group.append(result)
                    group_tokens += result_tokens

                if group:
                    if len(group) == 1 and not next_level:
                        next_level.append(group[0])
                    else:
                        merged = await _try_consolidate(template, group, provider, model, consolidation_params)
                        if merged is None:
                            next_level.extend(group)
                        else:
                            next_level.append(merged)

                print(f"    Round {consolidation_round}: {prev_count} -> {len(next_level)}", flush=True)
                batch_results = next_level

                if len(batch_results) >= prev_count:
                    print(f"    No progress, stopping", flush=True)
                    break
                if consolidation_round >= MAX_ROUNDS:
                    print(f"    Max rounds reached", flush=True)
                    break

            return "\n\n---\n\n".join(batch_results)

        async def _try_consolidate(template, group, provider, model, params):
            prompt = template + "\n---\n".join(group)
            for attempt in range(2):
                try:
                    resp, _ = await call_llm(
                        provider=provider, model=model,
                        messages=[{"role": "user", "content": prompt}],
                        parameters=params, timeout=300,
                    )
                    return resp
                except Exception:
                    if attempt == 0:
                        await asyncio.sleep(5)
            return None


        import os
        import json
        import re
        import fnmatch
        import hashlib
        from datetime import date
        audit_date = date.today().strftime("%b %d, %Y")

        # =============================================================
        # Parse input
        # =============================================================
        input_text = input_dict.get("inputText", "")
        params = {}
        if input_text.strip().startswith('{'):
            try:
                params = json.loads(input_text)
            except json.JSONDecodeError:
                pass

        if not params.get('namespace') and not params.get('namespaces'):
            match = re.search(r'(?:namespaces?|ns)[:\s]+([^\n]+?)(?:\s+asvs|$)', input_text, re.IGNORECASE)
            if match:
                raw = match.group(1).strip()
                if ',' in raw:
                    params['namespaces'] = [n.strip() for n in raw.split(',')]
                else:
                    params['namespace'] = raw
            else:
                match = re.search(r'(?:namespace|ns)[:\s]+([^\s,]+)', input_text, re.IGNORECASE)
                if match:
                    params['namespace'] = match.group(1)

        namespaces = params.get('namespaces') or ([params.get('namespace')] if params.get('namespace') else [])

        asvs_sections = params.get('asvs_sections') or []
        if isinstance(asvs_sections, str):
            asvs_sections = [s.strip() for s in asvs_sections.split(',') if s.strip()]
        if not asvs_sections and params.get('asvs'):
            # Tolerate single-section call but warn
            asvs_sections = [params['asvs']]

        include_files = params.get('includeFiles', [])
        severity_threshold = params.get('severityThreshold', '')
        domain_context = params.get('domainContext', '')
        false_positive_guidance = params.get('falsePositiveGuidance', [])

        if not namespaces:
            all_ns = data_store.list_namespaces()
            file_ns = [ns for ns in all_ns if ns.startswith("files:")]
            if file_ns:
                namespaces = file_ns

        if not namespaces:
            return {"outputText": json.dumps({
                "error": f"No namespaces provided. Available: {data_store.list_namespaces()}"
            })}

        if not asvs_sections:
            return {"outputText": json.dumps({
                "error": "No ASVS sections specified. Provide `asvs_sections` as a list."
            })}

        if len(asvs_sections) == 1:
            print(f"WARNING: bundle agent called with 1 section ({asvs_sections[0]}). "
                  f"For single-section audits prefer asvs_audit directly.", flush=True)

        repo_name = "unknown"
        for ns in namespaces:
            if ns.startswith("files:"):
                repo_name = ns.replace("files:", "")
                break

        print(f"Namespaces: {namespaces}", flush=True)
        print(f"ASVS sections (bundled): {asvs_sections}", flush=True)
        if include_files:
            print(f"File scope: {len(include_files)} patterns", flush=True)
        if severity_threshold:
            print(f"Severity threshold: {severity_threshold}", flush=True)

        # =============================================================
        # Model configuration
        # =============================================================
        SONNET_PROVIDER = "bedrock"
        SONNET_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        SONNET_PARAMS = {"temperature": 0.7, "max_tokens": 16384}

        # T9: Haiku for relevance filtering — cheaper and faster
        HAIKU_PROVIDER = "bedrock"
        HAIKU_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        HAIKU_PARAMS = {"temperature": 0.3, "max_tokens": 8192}

        OPUS_PROVIDER = "bedrock"
        OPUS_MODEL = "us.anthropic.claude-opus-4-6-v1"
        # Bundled output is bigger — give Opus more room to write per-section blocks
        OPUS_PARAMS = {"temperature": 1, "reasoning_effort": "high", "max_tokens": 96000}

        SONNET_CONTEXT = get_context_window(SONNET_PROVIDER, SONNET_MODEL)
        HAIKU_CONTEXT = get_context_window(HAIKU_PROVIDER, HAIKU_MODEL)
        OPUS_CONTEXT = get_context_window(OPUS_PROVIDER, OPUS_MODEL)

        # T2: configurable concurrency
        OPUS_CONCURRENCY = int(os.environ.get("OPUS_CONCURRENCY", "4"))
        SONNET_CONCURRENCY = int(os.environ.get("SONNET_CONCURRENCY", "5"))

        sonnet_semaphore = asyncio.Semaphore(SONNET_CONCURRENCY)
        opus_semaphore = asyncio.Semaphore(OPUS_CONCURRENCY)

        # Cache key uses ALL bundled sections so re-runs with same bundle hit cache
        bundle_key = "+".join(sorted(asvs_sections))
        cache_key_prefix = f"bundle-{bundle_key}-{'-'.join(namespaces)}"
        relevance_cache_ns = data_store.use_namespace(f"audit-cache:relevance:{cache_key_prefix}")
        analysis_cache_ns = data_store.use_namespace(f"audit-cache:analysis:{cache_key_prefix}")

        # =============================================================
        # Step 0: Load ASVS context for ALL bundled sections
        # =============================================================
        print("\n=== Step 0: Loading ASVS requirement context ===", flush=True)
        asvs_descriptions = {}  # section_id -> description string
        try:
            asvs_ns = data_store.use_namespace("asvs")
            for section_id in asvs_sections:
                req = asvs_ns.get(f"asvs:requirements:{section_id}")
                if req:
                    parts = [f"ASVS Requirement {section_id}"]
                    if req.get("req_description"):
                        parts.append(f"Description: {req['req_description']}")
                    if req.get("level"):
                        parts.append(f"Level: {req['level']}")
                    sec_id = req.get("section_id", "")
                    if sec_id:
                        sec = asvs_ns.get(f"asvs:sections:{sec_id}")
                        if sec:
                            parts.append(f"Section: {sec.get('section_name', '')}")
                            if sec.get("description"):
                                parts.append(f"Section Description: {sec['description']}")
                    asvs_descriptions[section_id] = "\n".join(parts)
                else:
                    asvs_descriptions[section_id] = f"ASVS Requirement {section_id}"
        except Exception as e:
            print(f"  WARNING: Could not load ASVS requirements: {e}", flush=True)
            for section_id in asvs_sections:
                asvs_descriptions[section_id] = f"ASVS Requirement {section_id}"

        combined_asvs_description = "\n\n".join(
            f"### Requirement {sid}\n{desc}" for sid, desc in asvs_descriptions.items()
        )
        print(f"  Loaded {len(asvs_descriptions)} ASVS requirements", flush=True)

        # =============================================================
        # Step 1: Read & filter files
        # =============================================================
        print("\n=== Step 1: Reading files from data store ===", flush=True)

        all_files = {}
        for ns in namespaces:
            ns_store = data_store.use_namespace(ns)
            keys = ns_store.list_keys()
            if include_files:
                keys = [k for k in keys if any(
                    fnmatch.fnmatch(k, pattern) for pattern in include_files
                )]
                print(f"Namespace '{ns}': {len(keys)} keys (scoped by includeFiles)", flush=True)
            else:
                print(f"Namespace '{ns}': {len(keys)} keys", flush=True)

            file_contents = ns_store.get_many(keys) if keys else {}
            for k, v in file_contents.items():
                if v is not None:
                    content = v if isinstance(v, str) else json.dumps(v, default=str) if v else ""
                    all_files[k] = content

        print(f"Total files loaded: {len(all_files)}", flush=True)

        if not all_files:
            return {"outputText": json.dumps({
                "error": f"No files found in namespaces {namespaces}"
            })}

        SKIP_DIRS = {
            'node_modules', 'vendor', 'third_party', 'third-party',
            'dist', 'build', 'out', 'target',
            '__pycache__', '.pytest_cache', '.mypy_cache', 'coverage', '.next', '.nuxt',
            'assets', 'images', 'img', 'static/images', 'static/fonts', 'static/webfonts',
            'public/images', 'fonts', 'webfonts',
            '.github/workflows',
            'venv', '.venv', 'env', '.env',
            '.git', '.idea', '.vscode',
        }
        SKIP_FILES = {
            'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock',
            'composer.lock', 'pnpm-lock.yaml', 'Gemfile.lock', 'uv.lock',
            'LICENSE', 'LICENSE.md', 'LICENSE.txt',
            'README.md', 'README.rst', 'README.txt', 'README',
            'CHANGELOG.md', 'CHANGELOG', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md',
            '.gitignore', '.dockerignore', '.prettierrc', '.eslintrc', '.editorconfig',
            '.npmrc', '.yarnrc',
        }
        SKIP_EXTENSIONS = {
            '.min.js', '.min.css', '.bundle.js', '.bundle.css',
            '.map', '.css', '.scss', '.less', '.sass', '.styl',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
            '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm', '.ogg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.lock',
            '.exe', '.dll', '.so', '.dylib', '.pyc', '.pyo', '.class', '.o', '.obj',
        }

        def should_skip_file(filepath):
            path_lower = filepath.lower()
            parts = filepath.split('/')
            for part in parts[:-1]:
                if part.lower() in SKIP_DIRS:
                    return True
            filename = parts[-1] if parts else ''
            if filename in SKIP_FILES:
                return True
            for ext in SKIP_EXTENSIONS:
                if path_lower.endswith(ext):
                    return True
            return False

        filtered_files = {}
        skipped_count = 0
        for key, content in all_files.items():
            if should_skip_file(key):
                skipped_count += 1
                continue
            filtered_files[key] = content

        print(f"Filtered: {len(filtered_files)} files to analyze, {skipped_count} skipped", flush=True)

        if not filtered_files:
            return {"outputText": json.dumps({
                "error": f"All {len(all_files)} files filtered out by skip rules"
            })}

        # T5: file-set-hash inventory cache key
        file_set_hash = hashlib.sha256(
            "\n".join(sorted(filtered_files.keys())).encode()
        ).hexdigest()[:16]
        inventory_cache_ns = data_store.use_namespace(f"audit-cache:inventory:{file_set_hash}")

        # =============================================================
        # Step 2: Relevance filtering (Haiku) [T9]
        # =============================================================
        if include_files:
            print("\n=== Step 2: Relevance filtering SKIPPED (includeFiles provided) ===", flush=True)
            relevant_files = filtered_files
            relevance_scores = {path: 10 for path in filtered_files}
            sorted_relevant = sorted(relevant_files.keys())
        else:
            print("\n=== Step 2: Relevance filtering (Haiku, parallel) ===", flush=True)

            cached_relevance = relevance_cache_ns.get("scores")
            if cached_relevance:
                relevance_scores = cached_relevance
                print(f"  Using cached relevance scores for {len(relevance_scores)} files", flush=True)
            else:
                file_previews = {}
                for path, content in filtered_files.items():
                    lines = content.split('\n')
                    file_previews[path] = '\n'.join(lines[:200])

                SAFE_HAIKU_LIMIT = int(HAIKU_CONTEXT * 0.40)

                relevance_prompt_template = f"""You are a security auditor performing file relevance filtering.

ASVS Requirements being audited (a file may be relevant to ANY of them):
{combined_asvs_description}

Below are file paths with previews (first ~200 lines) from a codebase.
Rate each file's relevance to ANY of the ASVS requirements above on a scale of 0-10:
- 10: Directly implements or should implement controls for these requirements
- 7-9: Contains related security controls, data handling, or configuration
- 4-6: May contain relevant patterns indirectly
- 1-3: Unlikely to be relevant
- 0: Definitely not relevant

Return ONLY a JSON object mapping file paths to relevance scores (integer 0-10).
Example: {{"src/auth.py": 9, "src/utils.py": 3}}

FILES TO EVALUATE:
"""

                template_tokens = count_tokens(relevance_prompt_template, HAIKU_PROVIDER, HAIKU_MODEL)
                preview_budget = SAFE_HAIKU_LIMIT - template_tokens

                preview_batches = []
                current_batch = {}
                current_tokens = 0
                for path, preview in file_previews.items():
                    entry = f"\n--- {path} ---\n{preview}\n"
                    entry_tokens = count_tokens(entry, HAIKU_PROVIDER, HAIKU_MODEL)
                    if current_tokens + entry_tokens > preview_budget and current_batch:
                        preview_batches.append(current_batch)
                        current_batch = {}
                        current_tokens = 0
                    current_batch[path] = entry
                    current_tokens += entry_tokens
                if current_batch:
                    preview_batches.append(current_batch)

                print(f"  Relevance filtering: {len(preview_batches)} batches", flush=True)

                relevance_scores = {}

                async def filter_batch(i, batch):
                    async with sonnet_semaphore:
                        entries_text = "".join(batch.values())
                        prompt = relevance_prompt_template + entries_text
                        messages = [{"role": "user", "content": prompt}]
                        for attempt in range(2):
                            try:
                                content_resp, _ = await call_llm(
                                    provider=HAIKU_PROVIDER, model=HAIKU_MODEL,
                                    messages=messages, parameters=HAIKU_PARAMS,
                                    timeout=120,
                                )
                                json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content_resp, re.DOTALL)
                                if json_match:
                                    scores = json.loads(json_match.group())
                                    print(f"    Batch {i+1}: scored {len(scores)} files", flush=True)
                                    return scores
                            except Exception as e:
                                if attempt == 0:
                                    print(f"    Batch {i+1} attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                                    await asyncio.sleep(5)
                                else:
                                    print(f"    Batch {i+1} FAILED: {e}", flush=True)
                        print(f"    WARNING: Batch {i+1} defaulting {len(batch)} files to score=5", flush=True)
                        return {path: 5 for path in batch}

                batch_results = await asyncio.gather(*[
                    filter_batch(i, batch)
                    for i, batch in enumerate(preview_batches)
                ])
                for scores in batch_results:
                    relevance_scores.update(scores)

                relevance_cache_ns.set("scores", relevance_scores)

            relevant_files = {}
            for path, content in filtered_files.items():
                score = relevance_scores.get(path, 5)
                if isinstance(score, (int, float)) and score >= 4:
                    relevant_files[path] = content

            if len(relevant_files) < 3 and filtered_files:
                for path, content in filtered_files.items():
                    score = relevance_scores.get(path, 5)
                    if isinstance(score, (int, float)) and score >= 2:
                        relevant_files[path] = content

            sorted_relevant = sorted(relevant_files.keys(),
                                     key=lambda p: relevance_scores.get(p, 0),
                                     reverse=True)

        print(f"  Relevant files: {len(relevant_files)} (from {len(filtered_files)})", flush=True)

        if not relevant_files:
            return {"outputText": json.dumps({
                "mode": "bundled",
                "asvs_sections": asvs_sections,
                "per_section": {sid: {
                    "report": _empty_section_report(sid, asvs_descriptions.get(sid, ""),
                                                    repo_name, audit_date,
                                                    0, len(filtered_files), skipped_count),
                    "findings": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                    "files_analyzed": 0,
                    "files_total": len(filtered_files),
                    "files_skipped": skipped_count,
                } for sid in asvs_sections},
                "raw_consolidated": "",
            }, default=str)}

        # =============================================================
        # Step 3: Code inventory (Sonnet, file-set-hash cached) [T5]
        # =============================================================
        print("\n=== Step 3: Code inventory (Sonnet, parallel) ===", flush=True)

        cached_inventory = inventory_cache_ns.get("result")
        if cached_inventory:
            code_inventory = cached_inventory
            print(f"  Using cached inventory ({len(code_inventory)} chars) [file-set hash hit]", flush=True)
        else:
            inventory_prompt_template = """You are a security code analyst. Extract a structured code inventory from each file below.

For each file, produce:
1. **Imports** — list all imports (especially security-related: auth, crypto, validators, sanitizers, path handling)
2. **Classes** — name, base classes, key methods with signatures
3. **Functions** — name, parameters (with types if available), decorators, line numbers (approximate)
4. **Security-relevant patterns** — validators, auth checks, path operations, file operations, crypto operations
5. **Routes/endpoints** — any URL routing, decorators like @app.route, @router.get, etc.
6. **Configuration** — security-relevant config values, environment variables

Return the inventory as structured markdown. Be thorough but concise.

FILES:
"""

            SAFE_SONNET_LIMIT_INV = int(SONNET_CONTEXT * 0.40)
            inv_template_tokens = count_tokens(inventory_prompt_template, SONNET_PROVIDER, SONNET_MODEL)
            inv_budget = SAFE_SONNET_LIMIT_INV - inv_template_tokens

            inv_batches = []
            current_batch = {}
            current_tokens = 0
            for path in sorted_relevant:
                content = relevant_files[path]
                entry = f"\n--- {path} ---\n{content}\n"
                entry_tokens = count_tokens(entry, SONNET_PROVIDER, SONNET_MODEL)
                if entry_tokens > inv_budget:
                    if current_batch:
                        inv_batches.append(current_batch)
                        current_batch = {}
                        current_tokens = 0
                    inv_batches.append({path: entry})
                    continue
                if current_tokens + entry_tokens > inv_budget and current_batch:
                    inv_batches.append(current_batch)
                    current_batch = {}
                    current_tokens = 0
                current_batch[path] = entry
                current_tokens += entry_tokens
            if current_batch:
                inv_batches.append(current_batch)

            print(f"  Code inventory: {len(inv_batches)} batches", flush=True)

            async def inventory_batch(i, batch):
                async with sonnet_semaphore:
                    entries_text = "".join(batch.values())
                    prompt = inventory_prompt_template + entries_text
                    messages = [{"role": "user", "content": prompt}]
                    msg_tokens = count_message_tokens(messages, SONNET_PROVIDER, SONNET_MODEL)
                    if msg_tokens > int(SONNET_CONTEXT * 0.80):
                        items = list(batch.items())
                        mid = len(items) // 2
                        results = []
                        for sub_items in [items[:mid], items[mid:]]:
                            sub_text = "".join([v for _, v in sub_items])
                            sub_messages = [{"role": "user", "content": inventory_prompt_template + sub_text}]
                            try:
                                resp, _ = await call_llm(
                                    provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                    messages=sub_messages, parameters=SONNET_PARAMS,
                                    timeout=300,
                                )
                                results.append(resp)
                            except Exception as e:
                                print(f"    Inventory sub-batch failed: {e}", flush=True)
                        return "\n\n".join(results)

                    for attempt in range(2):
                        try:
                            resp, _ = await call_llm(
                                provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                messages=messages, parameters=SONNET_PARAMS,
                                timeout=300,
                            )
                            print(f"    Inventory batch {i+1} complete", flush=True)
                            return resp
                        except Exception as e:
                            if attempt == 0:
                                print(f"    Inventory batch {i+1} attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                                await asyncio.sleep(5)
                            else:
                                print(f"    Inventory batch {i+1} FAILED: {e}", flush=True)
                                return ""

            inventory_results = await asyncio.gather(*[
                inventory_batch(i, batch)
                for i, batch in enumerate(inv_batches)
            ])
            code_inventory = "\n\n---\n\n".join([r for r in inventory_results if r])
            inventory_cache_ns.set("result", code_inventory)

        print(f"  Inventory total: {len(code_inventory)} chars", flush=True)

        # =============================================================
        # Step 4: Bundled deep analysis (Opus)
        # =============================================================
        print(f"\n=== Step 4: Bundled deep analysis (Opus, {OPUS_CONCURRENCY}-way) ===", flush=True)

        requirements_block = "\n\n".join(
            f"### ASVS Requirement {sid}\n{desc}"
            for sid, desc in asvs_descriptions.items()
        )

        analysis_system_prompt = f"""You are an expert application security auditor performing a comprehensive security audit against MULTIPLE ASVS requirements simultaneously.

## ASVS Requirements Under Audit
You are auditing the code below against ALL of the following requirements. For EACH requirement, you must produce a complete findings section.

{requirements_block}
"""

        if domain_context:
            analysis_system_prompt += f"\n## Domain Context\n{domain_context}\n"

        if severity_threshold:
            severity_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            threshold_val = severity_levels.get(severity_threshold.upper(), 0)
            if threshold_val > 0:
                included = [k for k, v in severity_levels.items() if v >= threshold_val]
                analysis_system_prompt += f"\n## Severity Threshold\nOnly report findings at these severity levels: {', '.join(included)}.\nDo not include findings below {severity_threshold.upper()} severity.\n"

        if false_positive_guidance:
            guidance_text = "\n".join(f"- {g}" for g in false_positive_guidance)
            analysis_system_prompt += f"\n## Known False Positive Patterns (DO NOT FLAG)\nThe following patterns are intentional design decisions in this codebase. Do not report them as vulnerabilities:\n{guidance_text}\n"

        analysis_system_prompt += """
## Audit Instructions

Follow ALL of these analysis requirements:

### Core Principle: Existence ≠ Application
For each security control found:
- Document where it's DEFINED
- Map ALL entry points that should use it
- Verify it's actually CALLED at each entry point
- Flag coverage gaps (control exists but not applied = CRITICAL)

### Gap Type Classification
| Gap Type | Description | Severity |
|----------|-------------|----------|
| Type A | Entry point with NO control | Standard vulnerability |
| Type B | Control EXISTS but NOT CALLED | CRITICAL (false confidence) |
| Type C | Control CALLED but RESULT IGNORED | CRITICAL |
| Type D | Control CALLED but AFTER sensitive operation | CRITICAL |

### Related Function Analysis
When you find a vulnerability, IMMEDIATELY search for:
- Singular/plural variants
- Sync/async variants
- Public/private variants
- Same-file functions with similar parameters or operations

### False Positive Prevention
Before finalizing each finding:
1. Where does this input ACTUALLY originate? Is it truly user-controllable?
2. Is there validation applied EARLIER in the call chain?
3. Can an external attacker actually control this value?
4. If you listed something as a positive pattern, don't also list it as a vulnerability

### Exclusions
Do NOT report:
- Database-sourced values without injection path
- Already-validated inputs
- Developer tooling/test code
- Issues requiring prior compromise
- Theoretical issues without specific exploit
- Test/example code

## Output Format — CRITICAL FOR DOWNSTREAM PROCESSING

For EACH ASVS requirement listed above, produce a section with this EXACT header:

```
## ASVS-{section_id}: <name>

### Findings for {section_id}
<all findings for this requirement, grouped by severity Critical → High → Medium → Low>

### Security Controls Inventory for {section_id}
<controls relevant to this requirement, with location and coverage status>

### Positive Patterns for {section_id}
<positive patterns specific to this requirement>
```

Use the EXACT header `## ASVS-{section_id}:` (with the dash and colon) for each requirement section.
This is parsed by automated tooling — deviations break the parser.

If a requirement has no findings, still produce the section with all three subsections,
explicitly stating "No findings detected" or "No applicable controls in this scope."

After ALL per-requirement sections, end with two cross-cutting sections:

```
## Cross-cutting Architecture Observations
<observations that span multiple requirements>

## Cross-cutting Recommendations
<prioritized: Immediate, Short-term, Long-term>
```

For each finding within a section, provide:
- Severity level: CRITICAL, HIGH, MEDIUM, or LOW (in a `### [SEVERITY]` header)
- Finding ID: ASVS-{section_no_dots}-SEV-NNN (e.g. ASVS-512-CRIT-001)
- Exact file location and function name with line numbers
- Vulnerable code quote (a fenced code block)
- Data flow: source → sink → missing control
- Proof of concept: a specific malicious request or input
- Impact description
- Remediation with code example

Be thorough but precise. If something is done correctly, acknowledge it as a positive pattern — don't invent issues."""

        SAFE_OPUS_LIMIT = int(OPUS_CONTEXT * 0.40)
        system_tokens = count_tokens(analysis_system_prompt, OPUS_PROVIDER, OPUS_MODEL)
        inventory_section = f"\n\n## Code Inventory (extracted by pre-analysis)\n\n{code_inventory}\n\n"
        inventory_tokens = count_tokens(inventory_section, OPUS_PROVIDER, OPUS_MODEL)
        user_template = "## Source Code Files\n\nAnalyze the following files for security issues related to ALL the ASVS requirements listed in the system prompt:\n\n"
        user_template_tokens = count_tokens(user_template, OPUS_PROVIDER, OPUS_MODEL)

        max_inv_tokens = int(SAFE_OPUS_LIMIT * 0.15)
        if inventory_tokens > max_inv_tokens:
            print(f"  Truncating inventory from {inventory_tokens} to {max_inv_tokens} tokens", flush=True)
            inv_lines = code_inventory.split('\n')
            truncated_inv = ""
            for line in inv_lines:
                candidate = truncated_inv + line + "\n"
                if count_tokens(candidate, OPUS_PROVIDER, OPUS_MODEL) > max_inv_tokens:
                    break
                truncated_inv = candidate
            inventory_section = f"\n\n## Code Inventory (extracted by pre-analysis, truncated)\n\n{truncated_inv}\n\n"
            inventory_tokens = count_tokens(inventory_section, OPUS_PROVIDER, OPUS_MODEL)

        opus_content_budget = SAFE_OPUS_LIMIT - system_tokens - inventory_tokens - user_template_tokens

        print(f"  Opus content budget: {opus_content_budget} tokens (bundled mode)", flush=True)

        opus_batches = []
        current_batch = {}
        current_tokens = 0
        for path in sorted_relevant:
            content = relevant_files[path]
            entry = f"\n### File: `{path}`\n```\n{content}\n```\n"
            entry_tokens = count_tokens(entry, OPUS_PROVIDER, OPUS_MODEL)
            if entry_tokens > opus_content_budget:
                if current_batch:
                    opus_batches.append(current_batch)
                    current_batch = {}
                    current_tokens = 0
                opus_batches.append({path: entry})
                continue
            if current_tokens + entry_tokens > opus_content_budget and current_batch:
                opus_batches.append(current_batch)
                current_batch = {}
                current_tokens = 0
            current_batch[path] = entry
            current_tokens += entry_tokens
        if current_batch:
            opus_batches.append(current_batch)

        print(f"  Bundled deep analysis: {len(opus_batches)} batches", flush=True)

        async def analyze_batch(i, batch):
            cache_key = f"batch-{i}"
            cached = analysis_cache_ns.get(cache_key)
            if cached:
                print(f"    Opus batch {i+1}: cached", flush=True)
                return cached

            async with opus_semaphore:
                entries_text = "".join(batch.values())
                user_content = user_template + entries_text + inventory_section
                messages = [
                    {"role": "user", "content": analysis_system_prompt + "\n\n" + user_content}
                ]

                msg_tokens = count_message_tokens(messages, OPUS_PROVIDER, OPUS_MODEL)
                limit = int(OPUS_CONTEXT * 0.80)
                print(f"    Opus batch {i+1}/{len(opus_batches)}: {msg_tokens} tokens, {len(batch)} files", flush=True)

                if msg_tokens > limit:
                    items = list(batch.items())
                    if len(items) > 1:
                        mid = len(items) // 2
                        results = []
                        for half_label, half_items in [("a", items[:mid]), ("b", items[mid:])]:
                            half_text = "".join([v for _, v in half_items])
                            half_user = user_template + half_text + inventory_section
                            half_messages = [{"role": "user", "content": analysis_system_prompt + "\n\n" + half_user}]
                            for attempt in range(3):
                                try:
                                    resp, _ = await call_llm(
                                        provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                        messages=half_messages, parameters=OPUS_PARAMS,
                                        timeout=1800,
                                    )
                                    results.append(resp)
                                    print(f"      Sub-batch {half_label} complete", flush=True)
                                    break
                                except Exception as e:
                                    if attempt < 2:
                                        wait = 15 * (attempt + 1)
                                        print(f"      Sub-batch {half_label} attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                                        await asyncio.sleep(wait)
                                    else:
                                        print(f"      Sub-batch {half_label} FAILED: {e}", flush=True)
                                        results.append(f"[Analysis failed for sub-batch {i+1}{half_label}: {str(e)[:200]}]")
                        combined = "\n\n---\n\n".join(results)
                        analysis_cache_ns.set(cache_key, combined)
                        return combined
                    else:
                        key, entry_val = items[0]
                        slim_messages = [{"role": "user", "content": analysis_system_prompt + "\n\n" + user_template + entry_val}]
                        for attempt in range(3):
                            try:
                                resp, _ = await call_llm(
                                    provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                    messages=slim_messages, parameters=OPUS_PARAMS,
                                    timeout=1800,
                                )
                                analysis_cache_ns.set(cache_key, resp)
                                return resp
                            except Exception as e:
                                if attempt < 2:
                                    wait = 15 * (attempt + 1)
                                    print(f"      Single file attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                                    await asyncio.sleep(wait)
                                else:
                                    return f"[Analysis failed for {key}: {str(e)[:200]}]"

                for attempt in range(3):
                    try:
                        resp, _ = await call_llm(
                            provider=OPUS_PROVIDER, model=OPUS_MODEL,
                            messages=messages, parameters=OPUS_PARAMS,
                            timeout=1800,
                        )
                        analysis_cache_ns.set(cache_key, resp)
                        print(f"    Opus batch {i+1} complete", flush=True)
                        return resp
                    except Exception as e:
                        if attempt < 2:
                            wait = 15 * (attempt + 1)
                            print(f"    Opus batch {i+1} attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                            await asyncio.sleep(wait)
                        else:
                            print(f"    Opus batch {i+1} FAILED: {e}", flush=True)
                            return f"[Analysis failed for batch {i+1}: {str(e)[:200]}]"

        analysis_results = await asyncio.gather(*[
            analyze_batch(i, batch)
            for i, batch in enumerate(opus_batches)
        ])

        analysis_results = [r for r in analysis_results if r and not r.startswith("[Analysis failed")]
        print(f"  Analysis complete: {len(analysis_results)} results", flush=True)

        if not analysis_results:
            return {"outputText": json.dumps({
                "error": "All analysis batches failed",
                "asvs_sections": asvs_sections,
            })}

        # =============================================================
        # Step 5: Consolidation across batches [T8 — lazy rounds]
        # =============================================================
        if len(analysis_results) == 1:
            consolidated_analysis = analysis_results[0]
            print(f"\n=== Step 5: Consolidation skipped (1 result) ===", flush=True)
        elif len(analysis_results) <= 4:
            print(f"\n=== Step 5: Single-pass consolidation ({len(analysis_results)} results) ===", flush=True)
            consolidated_analysis = await _single_pass_consolidate(
                analysis_results, combined_asvs_description,
                SONNET_PROVIDER, SONNET_MODEL, SONNET_PARAMS,
            )
        else:
            print(f"\n=== Step 5: Multi-round consolidation ({len(analysis_results)} results) ===", flush=True)
            consolidated_analysis = await _multi_round_consolidate(
                analysis_results, combined_asvs_description,
                SONNET_PROVIDER, SONNET_MODEL, SONNET_PARAMS, SONNET_CONTEXT,
            )

        # =============================================================
        # Step 6: Split bundled output per section
        # =============================================================
        print(f"\n=== Step 6: Splitting bundled output per section ===", flush=True)
        per_section = _split_bundled_output(
            consolidated_analysis, asvs_sections, asvs_descriptions,
            repo_name, audit_date,
            len(relevant_files), len(filtered_files), skipped_count,
        )

        # Persist a summary of each per-section report
        report_ns = data_store.use_namespace("audit-reports")
        for sid, sec_data in per_section.items():
            report_key = f"asvs-{sid}-{'-'.join(namespaces)}"
            report_ns.set(report_key, {
                "asvs": sid,
                "namespaces": namespaces,
                "files_analyzed": sec_data["files_analyzed"],
                "files_total": sec_data["files_total"],
                "files_skipped": sec_data["files_skipped"],
                "findings": sec_data["findings"],
                "report": sec_data["report"][:50000],
                "bundled_with": [s for s in asvs_sections if s != sid],
            })

        envelope = {
            "mode": "bundled",
            "asvs_sections": asvs_sections,
            "per_section": per_section,
            "raw_consolidated": consolidated_analysis,
            "metadata": {
                "files_analyzed": len(relevant_files),
                "files_total": len(filtered_files),
                "files_skipped": skipped_count,
                "opus_batches": len(opus_batches),
                "repo": repo_name,
                "audit_date": audit_date,
            },
        }

        total_findings = sum(
            sum(s["findings"].values()) for s in per_section.values()
        )
        print(f"\n=== Done: {len(asvs_sections)} sections, {total_findings} total findings ===", flush=True)
        return {"outputText": json.dumps(envelope, default=str)}

    finally:
        await http_client.aclose()