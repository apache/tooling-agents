# asvs_audit
#
# Audits a single ASVS requirement against a file scope. The original agent
# with optimizations applied. Bundling (T4) lives in a SEPARATE NEW agent:
# `asvs_bundle`, which the orchestrator calls when a discovery pass has
# multiple sections sharing the same files.
#
# Optimizations applied here (cross-ref optimization-plan.md):
#   T2 — opus_semaphore raised from 2 to 4 (env-overridable)
#   T5 — inventory cache keyed by file-set hash, not by ASVS section
#         (inventory has no ASVS-specific content; was wastefully recomputed)
#   T7 — skip Step 6 formatting for sections with zero findings
#   T8 — single-pass consolidation when ≤4 batch results (no multi-round loop)
#   T9 — Step 2 (relevance) uses Haiku 4.5 instead of Sonnet
#
# Same I/O contract as the original `run_asvs_security_audit` (now renamed
# to `asvs_audit`) — drop-in replacement for single-section calls.

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

        async def _single_pass_consolidate(results, asvs, asvs_description, provider, model, params):
            """T8: One Sonnet call merges ≤4 batch results — no multi-round loop."""
            prompt = f"""You are consolidating multiple security audit batch results into a single unified analysis.

ASVS Requirement: {asvs}
{asvs_description}

## Consolidation Rules:
1. DEDUPLICATE — Merge findings describing the same vulnerability
2. CHECK CONTRADICTIONS — If something appears as a positive pattern in ANY batch, remove from findings
3. VERIFY DATA ORIGINS — Remove findings where source is database/config without user injection path
4. CONSISTENT SEVERITY — Ensure similar issues have same severity
5. REMOVE OUT-OF-SCOPE — Exclude test files, dev scripts
6. PRESERVE SPECIFICS — Keep all exact code references, line numbers, and technical details

Consolidate these analysis results into a single comprehensive security audit report.
Preserve all specific findings with their exact code references, but merge duplicates.

BATCH RESULTS TO CONSOLIDATE:
        """ + "\n---\n".join(results)

            messages = [{"role": "user", "content": prompt}]
            consolidation_params = {**params, "max_tokens": 32000}
            try:
                resp, _ = await call_llm(
                    provider=provider, model=model,
                    messages=messages, parameters=consolidation_params, timeout=600,
                )
                return resp
            except Exception as e:
                # call_llm has exhausted central retries. Fall back to
                # raw-joining rather than losing the batch results.
                print(f"    Single-pass consolidation failed, joining raw: {e}", flush=True)
                return "\n\n---\n\n".join(results)

        async def _multi_round_consolidate(results, asvs, asvs_description, provider, model, params, context_window):
            """Original multi-round behavior; only kicks in for >4 batch results."""
            template = f"""You are consolidating multiple security audit batch results into a single unified analysis.

ASVS Requirement: {asvs}
{asvs_description}

## Consolidation Rules:
1. DEDUPLICATE - Merge findings describing the same vulnerability
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
            try:
                resp, _ = await call_llm(
                    provider=provider, model=model,
                    messages=[{"role": "user", "content": prompt}],
                    parameters=params, timeout=300,
                )
                return resp
            except Exception:
                # Returning None signals caller to fall back to raw-join.
                return None

        def _zero_findings_template(asvs, asvs_description, repo_name, audit_date,
                                    n_relevant, n_total, skipped, file_list):
            """T7: Skip Sonnet format call when no findings present."""
            return f"""# Security Audit Report: ASVS {asvs}

## Executive Summary

| Field | Value |
|-------|-------|
| **Repository** | {repo_name} |
| **Audit Date** | {audit_date} |
| **Auditor** | Tooling Agents |
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

No findings detected for ASVS requirement {asvs} within the audited file scope.

This means one of the following:
- The codebase implements appropriate controls for this requirement
- The requirement is not applicable to this codebase or file scope
- The relevant code is not present in the analyzed file set

## Appendix: Files Analyzed

<details>
<summary>Click to expand ({n_relevant} files)</summary>

{file_list}

</details>
        """

        def _fallback_header(asvs, asvs_description, repo_name, audit_date,
                             n_relevant, n_total, skipped, n_batches, findings_count):
            return f"""# Security Audit Report

## Executive Summary

| Field | Value |
|-------|-------|
| **Repository** | {repo_name} |
| **Audit Date** | {audit_date} |
| **Auditor** | Tooling Agents |
| **ASVS Requirement** | ASVS {asvs} |
| **Files Analyzed** | {n_relevant} relevant / {n_total} total |
| **Files Skipped** | {skipped} |
| **Analysis Batches** | {n_batches} |

**Requirement description:** {_short_asvs_summary(asvs_description)}

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {findings_count['Critical']} |
| 🟠 High | {findings_count['High']} |
| 🟡 Medium | {findings_count['Medium']} |
| 🟢 Low | {findings_count['Low']} |

---

        """

        def _fallback_appendix(n_relevant, file_list):
            return f"""

---

## Appendix: Files Analyzed

<details>
<summary>Click to expand ({n_relevant} files)</summary>

{file_list}

</details>
        """


        import os
        import json
        import re
        import fnmatch
        import hashlib
        from datetime import date
        audit_date = date.today().strftime("%b %d, %Y")

        # =============================================================
        # Parse input (same logic as original)
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

        if not params.get('asvs') and not params.get('asvs_section'):
            match = re.search(r'(?:asvs[-_]?section|asvs)[:\s]+(\d+(?:\.\d+)*)', input_text, re.IGNORECASE)
            if match:
                params['asvs'] = match.group(1)

        namespaces = params.get('namespaces') or ([params.get('namespace')] if params.get('namespace') else [])
        asvs = params.get('asvs') or params.get('asvs_section', '')

        # If a list was passed by mistake, redirect to the bundle agent's contract
        if params.get('asvs_sections') and len(params.get('asvs_sections', [])) > 1:
            return {"outputText": (
                "Error: This agent handles single-section audits only. "
                "For multiple sections sharing a file scope, call "
                "`asvs_bundle` instead with `asvs_sections: [...]`."
            )}

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
            return {"outputText": f"Error: No namespaces provided or found. Available: {data_store.list_namespaces()}"}

        if not asvs:
            return {"outputText": "Error: No ASVS requirement specified. Provide `asvs` parameter (e.g., asvs: 5.3.2)"}

        repo_name = "unknown"
        for ns in namespaces:
            if ns.startswith("files:"):
                repo_name = ns.replace("files:", "")
                break

        print(f"Namespaces: {namespaces}", flush=True)
        print(f"ASVS: {asvs}", flush=True)
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

        # T9: Haiku for relevance filtering (cheap classification)
        HAIKU_PROVIDER = "bedrock"
        HAIKU_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        HAIKU_PARAMS = {"temperature": 0.3, "max_tokens": 8192}

        OPUS_PROVIDER = "bedrock"
        OPUS_MODEL = "us.anthropic.claude-opus-4-8"
        OPUS_PARAMS = {"temperature": 1, "reasoning_effort": "high", "max_tokens": 128000}

        SONNET_CONTEXT = get_context_window(SONNET_PROVIDER, SONNET_MODEL)
        HAIKU_CONTEXT = get_context_window(HAIKU_PROVIDER, HAIKU_MODEL)
        OPUS_CONTEXT = get_context_window(OPUS_PROVIDER, OPUS_MODEL)

        # T2: configurable concurrency (was hardcoded to 2 / 5)
        OPUS_CONCURRENCY = int(os.environ.get("OPUS_CONCURRENCY", "4"))
        SONNET_CONCURRENCY = int(os.environ.get("SONNET_CONCURRENCY", "5"))

        sonnet_semaphore = asyncio.Semaphore(SONNET_CONCURRENCY)
        opus_semaphore = asyncio.Semaphore(OPUS_CONCURRENCY)

        cache_key_prefix = f"asvs-{asvs}-{'-'.join(namespaces)}"
        relevance_cache_ns = data_store.use_namespace(f"audit-cache:relevance:{cache_key_prefix}")
        analysis_cache_ns = data_store.use_namespace(f"audit-cache:analysis:{cache_key_prefix}")

        # =============================================================
        # Step 0: Load ASVS requirement context
        # =============================================================
        print("\n=== Step 0: Loading ASVS requirement context ===", flush=True)
        asvs_description = ""
        try:
            asvs_ns = data_store.use_namespace("asvs")
            req = asvs_ns.get(f"asvs:requirements:{asvs}")
            if req:
                parts = [f"ASVS Requirement {asvs}"]
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
                asvs_description = "\n".join(parts)
            else:
                asvs_description = f"ASVS Requirement {asvs}"
        except Exception as e:
            print(f"  WARNING: Could not load ASVS requirement: {e}", flush=True)
            asvs_description = f"ASVS Requirement {asvs}"

        # =============================================================
        # Step 1: Read & filter files
        # =============================================================
        print("\n=== Step 1: Reading files from data store ===", flush=True)

        # See asvs_bundle.py for the full rationale. Same two-tier
        # supplemental model:
        #   audit_guidance:* namespaces → guidance_keys (authoritative,
        #     rendered as a guidance section, removed from source scope)
        #   other supplemental namespaces → supplemental_keys only
        #     (filter-exempt, rendered as source code in the prompt)
        # Both sets bypass include_files / SKIP / relevance filters.
        all_files = {}
        supplemental_keys = set()
        guidance_keys = set()
        primary_file_count = 0
        for idx, ns in enumerate(namespaces):
            is_primary = (idx == 0)
            is_guidance = (not is_primary) and ns.startswith("audit_guidance:")
            ns_store = data_store.use_namespace(ns)
            keys = ns_store.list_keys()
            if is_primary and include_files:
                pre_filter_count = len(keys)
                filtered_keys = [k for k in keys if any(
                    fnmatch.fnmatch(k, pattern) for pattern in include_files
                )]
                if not filtered_keys and pre_filter_count > 0:
                    # Discovery emitted include_files patterns that match
                    # zero keys in this namespace. Causes: hallucinated
                    # paths from Sonnet, wrong path prefix, fnmatch's
                    # `**` quirk, or repo-layout drift since discovery
                    # last ran. Fall back to the unfiltered key list
                    # rather than aborting with "No files found" and
                    # producing an empty stub — the audit will cost more
                    # tokens but actually produce findings.
                    print(f"Namespace '{ns}' (primary): include_files "
                          f"matched 0 of {pre_filter_count} keys — "
                          f"FALLING BACK to unfiltered. Bad discovery "
                          f"patterns (first 5):", flush=True)
                    for p in include_files[:5]:
                        print(f"  - {p!r}", flush=True)
                    # `keys` left as-is (unfiltered)
                else:
                    keys = filtered_keys
                    print(f"Namespace '{ns}' (primary): {len(keys)} keys (scoped by includeFiles)", flush=True)
            else:
                if is_primary:
                    scope = "primary"
                elif is_guidance:
                    scope = "supplemental-guidance"
                else:
                    scope = "supplemental-code"
                print(f"Namespace '{ns}' ({scope}): {len(keys)} keys", flush=True)

            file_contents = ns_store.get_many(keys) if keys else {}
            for k, v in file_contents.items():
                if v is not None:
                    content = v if isinstance(v, str) else json.dumps(v, default=str) if v else ""
                    all_files[k] = content
                    if is_primary:
                        primary_file_count += 1
                    else:
                        supplemental_keys.add(k)
                        if is_guidance:
                            guidance_keys.add(k)

        print(f"Total files loaded: {len(all_files)}", flush=True)

        if primary_file_count == 0:
            return {"outputText": f"Error: No files found in namespaces {namespaces}"}

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
            # Supplemental files bypass the skip rules. See bundle agent
            # for full rationale; SKIP_FILES would otherwise drop
            # README.md, CONTRIBUTING.md, LICENSE.md if anyone tried to
            # ingest them as guidance.
            if key in supplemental_keys:
                filtered_files[key] = content
                continue
            if should_skip_file(key):
                skipped_count += 1
                continue
            filtered_files[key] = content

        print(f"Filtered: {len(filtered_files)} files to analyze, {skipped_count} skipped", flush=True)

        if not filtered_files:
            return {"outputText": f"Error: All {len(all_files)} files were filtered out."}

        # T5: file-set-hash inventory cache key
        file_set_hash = hashlib.sha256(
            "\n".join(sorted(filtered_files.keys())).encode()
        ).hexdigest()[:16]
        inventory_cache_ns = data_store.use_namespace(f"audit-cache:inventory:{file_set_hash}")

        # =============================================================
        # Step 2: Relevance filtering (Haiku, parallel) [T9]
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
                    # Supplemental files are guidance, not auditable
                    # code — don't waste Haiku tokens scoring them.
                    # They get force-included below regardless.
                    if path in supplemental_keys:
                        continue
                    lines = content.split('\n')
                    file_previews[path] = '\n'.join(lines[:200])

                SAFE_HAIKU_LIMIT = int(HAIKU_CONTEXT * 0.40)

                relevance_prompt_template = f"""You are a security auditor performing file relevance filtering.

ASVS Requirement: {asvs}
{asvs_description}

Below are file paths with previews (first ~200 lines) from a codebase.
Rate each file's relevance to the ASVS requirement above on a scale of 0-10:
- 10: Directly implements or should implement controls for this requirement
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
                        # call_llm handles central retries. On exhaustion,
                        # fall back to score=5 for the whole batch — every
                        # file passes through to analysis rather than being
                        # silently dropped.
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
                # Supplemental files always pass — they weren't scored
                # by Haiku and represent intentionally included context.
                if path in supplemental_keys:
                    relevant_files[path] = content
                    continue
                score = relevance_scores.get(path, 5)
                if isinstance(score, (int, float)) and score >= 4:
                    relevant_files[path] = content

            if len(relevant_files) < 3 and filtered_files:
                for path, content in filtered_files.items():
                    if path in supplemental_keys:
                        continue  # already included above
                    score = relevance_scores.get(path, 5)
                    if isinstance(score, (int, float)) and score >= 2:
                        relevant_files[path] = content

            sorted_relevant = sorted(relevant_files.keys(),
                                     key=lambda p: relevance_scores.get(p, 0),
                                     reverse=True)

        print(f"  Relevant files: {len(relevant_files)} (from {len(filtered_files)})", flush=True)

        # =============================================================
        # Step 3: Code inventory (Sonnet, parallel, file-set-hash cached) [T5]
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

                    # Retries handled centrally. On exhaustion the inventory
                    # entry is dropped; the join filters empty results.
                    try:
                        resp, _ = await call_llm(
                            provider=SONNET_PROVIDER, model=SONNET_MODEL,
                            messages=messages, parameters=SONNET_PARAMS,
                            timeout=300,
                        )
                        print(f"    Inventory batch {i+1} complete", flush=True)
                        return resp
                    except Exception as e:
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
        # Step 4: Deep security analysis (Opus) — single section
        # =============================================================
        print(f"\n=== Step 4: Deep security analysis (Opus, {OPUS_CONCURRENCY}-way concurrent) ===", flush=True)

        analysis_system_prompt = f"""You are an expert application security auditor performing a comprehensive security audit against ASVS requirements.

## ASVS Requirement Under Audit
{asvs_description}
"""

        if domain_context:
            analysis_system_prompt += f"\n## Domain Context\n{domain_context}\n"

        if severity_threshold:
            severity_levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            threshold_val = severity_levels.get(severity_threshold.upper(), 0)
            if threshold_val > 0:
                included = [k for k, v in severity_levels.items() if v >= threshold_val]
                analysis_system_prompt += f"\n## Severity Threshold\nReport findings at these severity levels and ONLY these: {', '.join(included)}.\nFindings at lower severities ({severity_threshold.upper()}-below) should be omitted entirely.\nDo NOT bias toward {severity_threshold.upper()} as the default — CRITICAL findings (Type B/C/D gaps per the rules below) are equally in scope and must be reported as CRITICAL when the gap-type rule applies.\n"

        if false_positive_guidance:
            guidance_text = "\n".join(f"- {g}" for g in false_positive_guidance)
            analysis_system_prompt += f"\n## Known False Positive Patterns (DO NOT FLAG)\nThe following patterns are intentional design decisions in this codebase. Do not report them as vulnerabilities:\n{guidance_text}\n"

        # See asvs_bundle.py for the full rationale. Only guidance_keys
        # (from audit_guidance:* namespaces) get the authoritative-guidance
        # framing; other supplemental files stay in relevant_files and get
        # rendered as source code below.
        if guidance_keys:
            guidance_parts = []
            for k in sorted(guidance_keys):
                if k in relevant_files:
                    guidance_parts.append(f"### {k}\n\n{relevant_files[k]}")
            if guidance_parts:
                guidance_block = "\n\n".join(guidance_parts)
                analysis_system_prompt += (
                    "\n## Project Security Guidance (Authoritative)\n"
                    "The following documents are provided by the project's own maintainers "
                    "as guidance on what this codebase considers a vulnerability versus a "
                    "documented design decision, known limitation, or deployment-manager "
                    "responsibility. Treat this content as AUTHORITATIVE: when a potential "
                    "finding aligns with content marked here as \"by design\", \"not a "
                    "vulnerability\", \"documented limitation\", \"known limitation\", or "
                    "\"deployment-manager responsibility\", do NOT report it as a finding. "
                    "Note it under positive controls instead, or omit it.\n\n"
                    "These documents are INSTRUCTIONS TO YOU about how to interpret the "
                    "source code. They are NOT source code under review. Apply ALL of the "
                    "following rules without exception:\n\n"
                    "1. Do not raise findings against these guidance documents themselves "
                    "(structure, completeness, consolidation, organization, formatting, "
                    "coverage). Observations like \"guidance is scattered across multiple "
                    "files\", \"no consolidated register exists\", \"documentation is "
                    "incomplete\", or \"a dangerous-functionality inventory is missing\" "
                    "are meta-observations on the policy itself, not vulnerabilities in "
                    "the codebase.\n"
                    "2. Do not list any guidance document path in a finding's `files`, "
                    "`affected_files`, `related_files`, `source_reports`, `evidence`, or "
                    "any equivalent field. Guidance documents are never affected components.\n"
                    "3. Do not quote, paraphrase, or cite the guidance document filenames "
                    "in finding descriptions, remediation text, or rationale. If you want "
                    "to say \"this is consistent with documented design\", say so without "
                    "naming the guidance file.\n"
                    "4. If a guidance document acknowledges a known gap (\"we don't enforce "
                    "X at the library layer\"), that acknowledgement IS the resolution. Do "
                    "not raise a finding asking the project to do X. The guidance is the "
                    "answer to that finding.\n\n"
                    f"{guidance_block}\n"
                )

            for k in list(guidance_keys):
                relevant_files.pop(k, None)
            sorted_relevant = [k for k in sorted_relevant if k not in guidance_keys]

        analysis_system_prompt += f"""
## Audit Instructions

Follow ALL of these analysis requirements:

### Scope Check — do this FIRST, before generating any findings

Each ASVS requirement is written assuming the audited code implements a
specific technology, protocol, component role, feature, or data type.
A requirement applies only when the audited code actually meets that
architectural assumption.

For each requirement, before generating any finding:
1. Identify the architectural assumption the requirement embeds — what
   protocol, technology, component role, feature, or data type the
   requirement governs.
2. Verify the audited codebase actually exhibits that assumption.
3. If the assumption is not met, mark the requirement as N/A in the
   coverage table with a one-line reason. Do NOT generate a finding for
   it — absences are not findings, and findings exist only when there
   is concrete code to describe a defect against.

Do not stretch a requirement to fit thematically similar but
architecturally different code. If the audited codebase implements
something adjacent to the requirement's target — a different token
format, a different transport, a different protocol role, a different
component type — the requirement is N/A for the parts of the standard
that target the specific pattern, even when other requirements in the
same control family do apply.

### Core Principle: Existence ≠ Application
For each security control found:
- Document where it's DEFINED
- Map ALL entry points that should use it
- Verify it's actually CALLED at each entry point
- Flag coverage gaps (control exists but not applied = CRITICAL)

### Gap Type Classification — severity is DETERMINED by gap type, not your judgment

For EVERY finding you produce, first classify the gap type, then assign severity
according to the rules below. You do not have discretion to override these.

**Type A — Entry point with NO control**
  Severity: HIGH (or LOW/MEDIUM if impact is minor)
  Finding ID format: `ASVS-{asvs.replace('.', '')}-HIGH-NNN`
  Example: an endpoint accepts user input and concatenates it directly into a
  shell command — no validation anywhere → Type A → HIGH.

**Type B — Control EXISTS but is NOT CALLED at this entry point**
  Severity: **CRITICAL** (false confidence — operators believe protected, aren't)
  Finding ID format: `ASVS-{asvs.replace('.', '')}-CRIT-NNN`
  Example: a login endpoint validates passwords, but a `try: ... except JSONDecodeError: pass`
  block silently skips validation when the body is malformed → control exists,
  not called → **CRITICAL, not High**.
  Example: `is_authorized_pool` exists and works, but the auth check is wrapped in
  `with suppress(JSONDecodeError):` so it's bypassed on parse failure → **CRITICAL**.

**Type C — Control CALLED but RESULT IGNORED**
  Severity: **CRITICAL** (work performed without consequence)
  Finding ID format: `ASVS-{asvs.replace('.', '')}-CRIT-NNN`
  Example: auth backend returns "access denied" but caller treats this identically
  to "not found" and falls through to the next backend → **CRITICAL, not High**.
  Example: token revocation list is checked but the result is logged-only and
  doesn't actually reject the request → **CRITICAL**.

**Type D — Control CALLED but AFTER the sensitive operation**
  Severity: **CRITICAL** (control runs too late to prevent harm)
  Finding ID format: `ASVS-{asvs.replace('.', '')}-CRIT-NNN`
  Example: SQL query is executed and THEN the parameter is validated → **CRITICAL**.
  Example: file is written to disk, then path traversal check runs → **CRITICAL**.

**Hard rule:** If your finding's description includes phrases like "control exists
but not called", "control called but result ignored", "validation skipped",
"check bypassed", "silently fails", "exception suppressed", or "Type B/C/D" —
the Finding ID MUST use the `CRIT` token, NOT `HIGH`. There is no case where
a Type B/C/D gap should be marked HIGH. This is the most common failure mode
in audits and you must guard against it.

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

### Output Requirements
For each finding, provide:
- Severity level (CRITICAL/HIGH/MEDIUM/LOW) — determined by the Gap Type rules above, not your discretion
- Finding ID using ONE of these exact formats based on severity:
  - `ASVS-{asvs.replace('.', '')}-CRIT-NNN` for Critical (Type B/C/D gaps)
  - `ASVS-{asvs.replace('.', '')}-HIGH-NNN` for High
  - `ASVS-{asvs.replace('.', '')}-MED-NNN`  for Medium
  - `ASVS-{asvs.replace('.', '')}-LOW-NNN`  for Low
- Exact file location and function name with line numbers
- Vulnerable code quote
- Data flow (source → sink → missing control)
- Proof of concept (specific malicious request)
- Impact description
- Remediation with code example

### Final Severity Pass — DO THIS BEFORE EMITTING OUTPUT

After you've drafted all findings, walk back through them once more:
1. For each finding marked HIGH, re-read its own description.
2. If the description says or implies the control exists somewhere but is not
   reached, not called, bypassed, suppressed, called-but-ignored, or called-too-late —
   that is a Type B/C/D gap. Change the severity to CRITICAL and the Finding ID
   token from HIGH to CRIT.
3. If the description says no such control exists at all — leave it as HIGH.

This pass is not optional. The most common audit failure is marking Type B/C/D
gaps as HIGH out of caution. Your job is to apply the rule, not to be cautious.

Also provide:
- Security Controls Inventory with coverage analysis
- Critical File Review tables
- Positive Security Patterns
- Architecture Observations
- Prioritized Recommendations

Be thorough but precise. If something is done correctly, acknowledge it as a positive pattern - don't invent issues."""

        SAFE_OPUS_LIMIT = int(OPUS_CONTEXT * 0.40)
        system_tokens = count_tokens(analysis_system_prompt, OPUS_PROVIDER, OPUS_MODEL)
        inventory_section = f"\n\n## Code Inventory (extracted by pre-analysis)\n\n{code_inventory}\n\n"
        inventory_tokens = count_tokens(inventory_section, OPUS_PROVIDER, OPUS_MODEL)
        user_template = "## Source Code Files\n\nAnalyze the following files for security issues related to the ASVS requirement:\n\n"
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

        print(f"  Opus content budget: {opus_content_budget} tokens", flush=True)

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

        print(f"  Deep analysis: {len(opus_batches)} batches", flush=True)

        # Pre-load the analysis cache namespace in one call. Each batch's
        # cache check becomes a dict lookup instead of a sync ns.get()
        # that would block the agent thread's loop during the lookup.
        # With ~30 concurrent gather'd batches and a CouchDB that's
        # itself under load from writes, this saves ~30 sequential
        # blocking reads per audit. Writes stay per-batch to preserve
        # the cache's resumability semantics on a stopped run.
        try:
            analysis_cache_all = analysis_cache_ns.get_all() or {}
        except Exception as e:
            print(f"  WARN: analysis cache pre-load failed, falling back to per-key: {e}", flush=True)
            analysis_cache_all = None

        async def analyze_batch(i, batch):
            cache_key = f"batch-{i}"
            if analysis_cache_all is not None:
                cached = analysis_cache_all.get(cache_key)
            else:
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
                            # Retries handled centrally. On exhaustion
                            # emit a sentinel string so the surviving
                            # half still produces output; the post-gather
                            # filter strips these out.
                            try:
                                resp, _ = await call_llm(
                                    provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                    messages=half_messages, parameters=OPUS_PARAMS,
                                    timeout=1800,
                                )
                                results.append(resp)
                                print(f"      Sub-batch {half_label} complete", flush=True)
                            except Exception as e:
                                print(f"      Sub-batch {half_label} FAILED: {e}", flush=True)
                                results.append(f"[Analysis failed for sub-batch {i+1}{half_label}: {str(e)[:200]}]")
                        combined = "\n\n---\n\n".join(results)
                        analysis_cache_ns.set(cache_key, combined)
                        return combined
                    else:
                        key, entry_val = items[0]
                        slim_messages = [{"role": "user", "content": analysis_system_prompt + "\n\n" + user_template + entry_val}]
                        try:
                            resp, _ = await call_llm(
                                provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                messages=slim_messages, parameters=OPUS_PARAMS,
                                timeout=1800,
                            )
                            analysis_cache_ns.set(cache_key, resp)
                            return resp
                        except Exception as e:
                            return f"[Analysis failed for {key}: {str(e)[:200]}]"

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
                    print(f"    Opus batch {i+1} FAILED: {e}", flush=True)
                    return f"[Analysis failed for batch {i+1}: {str(e)[:200]}]"

        analysis_results = await asyncio.gather(*[
            analyze_batch(i, batch)
            for i, batch in enumerate(opus_batches)
        ])

        analysis_results = [r for r in analysis_results if r and not r.startswith("[Analysis failed")]
        print(f"  Analysis complete: {len(analysis_results)} results", flush=True)

        if not analysis_results:
            if not opus_batches:
                return {"outputText": "Not applicable: no relevant files found for this ASVS requirement."}
            return {"outputText": "Error: All analysis batches failed. No results to report."}

        # =============================================================
        # Step 5: Consolidation [T8 — lazy rounds]
        # =============================================================
        if len(analysis_results) == 1:
            consolidated_analysis = analysis_results[0]
            print(f"\n=== Step 5: Consolidation skipped (1 result) ===", flush=True)
        elif len(analysis_results) <= 4:
            # T8: skip the multi-round loop for small batch counts
            print(f"\n=== Step 5: Single-pass consolidation ({len(analysis_results)} results) ===", flush=True)
            consolidated_analysis = await _single_pass_consolidate(
                analysis_results, asvs, asvs_description,
                SONNET_PROVIDER, SONNET_MODEL, SONNET_PARAMS,
            )
        else:
            print(f"\n=== Step 5: Multi-round consolidation ({len(analysis_results)} results) ===", flush=True)
            consolidated_analysis = await _multi_round_consolidate(
                analysis_results, asvs, asvs_description,
                SONNET_PROVIDER, SONNET_MODEL, SONNET_PARAMS, SONNET_CONTEXT,
            )

        # =============================================================
        # Step 6: Format report (or short-circuit on zero findings) [T7]
        # =============================================================
        print("\n=== Step 6: Formatting report ===", flush=True)

        findings_count = _count_findings(consolidated_analysis)
        total_findings = sum(findings_count.values())
        file_list = "\n".join([f"- `{p}` (relevance: {relevance_scores.get(p, '?')})" for p in sorted_relevant])

        if total_findings == 0:
            # T7: skip the Sonnet format call entirely for empty sections
            print("  No findings detected — using template (T7 short-circuit)", flush=True)
            final_report = _zero_findings_template(
                asvs, asvs_description, repo_name, audit_date,
                len(relevant_files), len(filtered_files), skipped_count, file_list,
            )
        else:
            format_prompt = f"""You are formatting a security audit report into clean, professional markdown.

ASVS Requirement: {asvs}
{asvs_description}

## Formatting Requirements

Format the analysis below into the following structure. Preserve ALL specific findings, code references,
line numbers, and technical details exactly as provided. Do not add, remove, or modify any findings.

Required structure:
1. **Executive Summary** — with these EXACT metadata values (do NOT invent names):
   - **Repository:** {repo_name}
   - **Audit Date:** {audit_date}
   - **Auditor:** Tooling Agents
   - **ASVS Requirement:** ASVS {asvs}
   - **Description:** {_short_asvs_summary(asvs_description)}
   - Files analyzed: {len(relevant_files)} relevant out of {len(filtered_files)} total, {skipped_count} skipped
   - Finding counts table
2. **Security Controls Inventory** — each control with location, purpose, coverage status
3. **Critical File Review** — tables for key files showing all security-sensitive functions reviewed
4. **Findings** — grouped by severity (Critical → High → Medium → Low), each with:
   - ID using one of: `ASVS-{asvs.replace('.', '')}-CRIT-NNN`, `ASVS-{asvs.replace('.', '')}-HIGH-NNN`, `ASVS-{asvs.replace('.', '')}-MED-NNN`, or `ASVS-{asvs.replace('.', '')}-LOW-NNN` (preserve the severity token from the source analysis exactly — do NOT downgrade Critical to High during formatting)
   - Location with file, function, line numbers
   - Related functions checked
   - Description, vulnerable code, data flow, PoC, impact, remediation
5. **Positive Security Patterns** — what's done well, each with a `file:line` reference to the specific code
6. **Architecture Observations**
7. **Recommendations Summary** — Immediate/Short-term/Long-term
8. **Appendix: Files Analyzed** — collapsible list

Finding counts detected: Critical={findings_count['Critical']}, High={findings_count['High']}, Medium={findings_count['Medium']}, Low={findings_count['Low']}

## Files Analyzed
{file_list}

## Analysis to Format

{consolidated_analysis}"""

            format_messages = [{"role": "user", "content": format_prompt}]
            format_tokens = count_message_tokens(format_messages, SONNET_PROVIDER, SONNET_MODEL)
            sonnet_limit = int(SONNET_CONTEXT * 0.80)

            print(f"  Format prompt: {format_tokens} tokens (limit: {sonnet_limit})", flush=True)

            if format_tokens <= sonnet_limit:
                final_report = consolidated_analysis  # default if formatting fails
                # Retries handled centrally. On exhaustion final_report
                # stays as the raw consolidated_analysis from above —
                # less polished but content-complete.
                try:
                    final_report, _ = await call_llm(
                        provider=SONNET_PROVIDER, model=SONNET_MODEL,
                        messages=format_messages, parameters=SONNET_PARAMS,
                        timeout=600,
                    )
                except Exception as e:
                    print(f"  Formatting failed, using raw analysis: {e}", flush=True)
            else:
                print(f"  Format prompt too large, using header + raw", flush=True)
                final_report = _fallback_header(
                    asvs, asvs_description, repo_name, audit_date,
                    len(relevant_files), len(filtered_files), skipped_count,
                    len(opus_batches), findings_count,
                ) + consolidated_analysis + _fallback_appendix(len(relevant_files), file_list)

        report_ns = data_store.use_namespace("audit-reports")
        report_key = f"asvs-{asvs}-{'-'.join(namespaces)}"
        report_ns.set(report_key, {
            "asvs": asvs,
            "namespaces": namespaces,
            "files_analyzed": len(relevant_files),
            "files_total": len(filtered_files),
            "files_skipped": skipped_count,
            "findings": findings_count,
            "report": final_report[:50000],
        })

        print(f"\n=== Done: {len(final_report)} chars ===", flush=True)
        return {"outputText": final_report}

    finally:
        await http_client.aclose()