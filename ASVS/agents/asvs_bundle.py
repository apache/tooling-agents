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
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

            # Primary: count Finding IDs and classify each by its severity token
            finding_ids = re.findall(
                r'ASVS-\d+-(CRIT(?:ICAL)?|HIGH|MED(?:IUM)?|LOW|INFO(?:RMATIONAL)?)-\d+',
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
                elif token_upper.startswith("INFO"):
                    counts["Info"] += 1

            if sum(counts.values()) > 0:
                return counts

            # Fallback 1: severity headings at any heading depth, with or without brackets
            for sev_name, key in [("critical", "Critical"), ("high", "High"),
                                   ("medium", "Medium"), ("low", "Low"),
                                   ("info", "Info"), ("informational", "Info")]:
                pattern = rf'(?im)^#{{1,6}}\s*\[?\s*{sev_name}\s*\]?\s*$'
                counts[key] += len(re.findall(pattern, content))

            if sum(counts.values()) > 0:
                return counts

            # Fallback 2: inline **Severity**: X lines
            counts["Critical"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Critical', content, re.IGNORECASE))
            counts["High"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*High', content, re.IGNORECASE))
            counts["Medium"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Medium', content, re.IGNORECASE))
            counts["Low"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Low', content, re.IGNORECASE))
            counts["Info"] += len(re.findall(r'\*\*Severity:?\*\*:?\s*Info(?:rmational)?', content, re.IGNORECASE))
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

            _bundle_label = asvs_sections[0] if asvs_sections else "?"
            for sid in asvs_sections:
                section_body = found_sections.get(sid)
                if section_body is None:
                    print(f"[bundle {_bundle_label}] WARNING: no bundled output for section {sid} — emitting empty report", flush=True)
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
            # Sonnet 4.6 allows up to 64K output (vs 4.5's 32K).
            # Consolidation is output-heavy; raise to 48000, under the ceiling.
            consolidation_params = {**params, "max_tokens": 48000}
            try:
                resp, _ = await call_llm(
                    provider=provider, model=model,
                    messages=messages, parameters=consolidation_params, timeout=600,
                )
                return resp
            except Exception as e:
                # call_llm has exhausted its centralized retries. Fall
                # back to raw-joining the batch results rather than
                # losing them entirely — the consolidated structure is
                # degraded but the findings are preserved for downstream
                # processing.
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
            # Sonnet 4.6 allows 64K output; raise from 16384 so each round
            # emits more and fewer rounds are needed. Under the ceiling.
            consolidation_params = {**params, "max_tokens": 32768}
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
                # Returning None signals the caller to fall back to its
                # raw-join behavior. call_llm has already done its
                # central backoff and failed; immediate further retry
                # here would be redundant.
                return None


        import os
        import json
        import re
        import fnmatch
        import hashlib
        import random
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

        repo_name = "unknown"
        for ns in namespaces:
            if ns.startswith("files:"):
                repo_name = ns.replace("files:", "")
                break

        # Single identifier line per bundle — first section serves as a
        # short label, and the full section list shows what's in flight.
        # Other startup info (namespaces, file scope, severity threshold)
        # are constant across all bundles in a run; the orchestrator
        # already prints them once. Don't repeat per-bundle.
        bundle_label = asvs_sections[0] if asvs_sections else "?"
        print(f"[bundle {bundle_label}] sections: {asvs_sections}", flush=True)

        if len(asvs_sections) == 1:
            print(f"[bundle {bundle_label}] WARNING: called with 1 section. "
                  f"For single-section audits prefer asvs_audit directly.", flush=True)

        # =============================================================
        # Model configuration
        # =============================================================
        SONNET_PROVIDER = "bedrock"
        # Sonnet 4.6: 1M context (up from 200K) + 64K max output (up from
        # 32K). SONNET_CONTEXT budgets below recompute against 1M via
        # get_context_window. max_tokens 16384 -> 32768 for fatter inventory
        # batches; stays under the 64000 output ceiling.
        SONNET_MODEL = "us.anthropic.claude-sonnet-4-6"
        SONNET_PARAMS = {"temperature": 0.7, "max_tokens": 32768}

        # T9: Haiku for relevance filtering — cheaper and faster
        HAIKU_PROVIDER = "bedrock"
        HAIKU_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
        HAIKU_PARAMS = {"temperature": 0.3, "max_tokens": 8192}

        OPUS_PROVIDER = "bedrock"
        OPUS_MODEL = "us.anthropic.claude-opus-4-8"
        # Bundled output is bigger — give Opus more room to write per-section blocks
        OPUS_PARAMS = {"temperature": 1, "reasoning_effort": "high", "max_tokens": 128000}

        SONNET_CONTEXT = get_context_window(SONNET_PROVIDER, SONNET_MODEL)
        HAIKU_CONTEXT = get_context_window(HAIKU_PROVIDER, HAIKU_MODEL)
        OPUS_CONTEXT = get_context_window(OPUS_PROVIDER, OPUS_MODEL)

        # T2: configurable concurrency
        OPUS_CONCURRENCY = int(os.environ.get("OPUS_CONCURRENCY", "4"))
        SONNET_CONCURRENCY = int(os.environ.get("SONNET_CONCURRENCY", "5"))
        # Haiku relevance-scoring gets its own, low concurrency. It used to
        # borrow sonnet_semaphore (5-wide), which the default Bedrock Haiku
        # per-minute quota cannot sustain across many batches — every call
        # throttled, often to retry 4/5 or 5/5, surviving only via
        # call_llm's backoff. Default 2 keeps it under the default quota.
        # Raise via HAIKU_CONCURRENCY if you get a quota increase.
        HAIKU_CONCURRENCY = int(os.environ.get("HAIKU_CONCURRENCY", "2"))

        sonnet_semaphore = asyncio.Semaphore(SONNET_CONCURRENCY)
        opus_semaphore = asyncio.Semaphore(OPUS_CONCURRENCY)
        haiku_semaphore = asyncio.Semaphore(HAIKU_CONCURRENCY)

        # Cache key uses ALL bundled sections so re-runs with same bundle hit cache
        bundle_key = "+".join(sorted(asvs_sections))
        cache_key_prefix = f"bundle-{bundle_key}-{'-'.join(namespaces)}"
        relevance_cache_ns = data_store.use_namespace(f"audit-cache:relevance:{cache_key_prefix}")
        analysis_cache_ns = data_store.use_namespace(f"audit-cache:analysis:{cache_key_prefix}")

        # =============================================================
        # Step 0: Load ASVS context for ALL bundled sections
        # =============================================================
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
            print(f"[bundle {bundle_label}] WARNING: Could not load ASVS requirements: {e}", flush=True)
            for section_id in asvs_sections:
                asvs_descriptions[section_id] = f"ASVS Requirement {section_id}"

        combined_asvs_description = "\n\n".join(
            f"### Requirement {sid}\n{desc}" for sid, desc in asvs_descriptions.items()
        )

        # =============================================================
        # Step 1: Read & filter files
        # =============================================================

        # The orchestrator's contract: namespaces[0] is the primary
        # source-code namespace and is subject to include_files
        # filtering. Subsequent namespaces (from supplementalData) are
        # supplemental — guidance docs, threat models, vendored libs,
        # config overlays, related-repo code — and should NOT be filtered
        # by patterns that were generated for the source code. They load
        # fully so the model sees them in every Opus call regardless of
        # how discovery scoped the source files.
        #
        # Within supplemental namespaces we distinguish TWO kinds by
        # namespace prefix:
        #   - "audit_guidance:*" → AUTHORITATIVE GUIDANCE
        #     Documents that calibrate which findings are real vs. by-
        #     design (project AGENTS.md, security_model.rst, etc.).
        #     Rendered later in a dedicated "Project Security Guidance
        #     (Authoritative)" prompt section, NOT as source files.
        #   - any other supplemental namespace → SUPPLEMENTAL CODE
        #     Vendored libraries, config files, related-repo overlays.
        #     Rendered as source code in the prompt and audited normally.
        #
        # Both kinds bypass the include_files / SKIP / relevance filters
        # (operator opted them in explicitly). The distinction is purely
        # how they appear in the final Opus prompt.
        all_files = {}
        supplemental_keys = set()  # all non-primary keys (filter-exempt)
        guidance_keys = set()       # subset of supplemental from audit_guidance:* namespaces
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
                    # emitting empty per-section stubs — the audit will
                    # cost more tokens but actually produce findings.
                    print(f"  [bundle] namespace '{ns}' (primary): "
                          f"include_files matched 0 of {pre_filter_count} "
                          f"keys — FALLING BACK to unfiltered. Bad "
                          f"discovery patterns (first 5):", flush=True)
                    for p in include_files[:5]:
                        print(f"    - {p!r}", flush=True)
                    # `keys` left as-is (unfiltered)
                else:
                    keys = filtered_keys
                    print(f"  [bundle] namespace '{ns}' (primary): "
                          f"{len(keys)} keys after include_files filter", flush=True)
            else:
                if is_primary:
                    scope = "primary"
                elif is_guidance:
                    scope = "supplemental-guidance"
                else:
                    scope = "supplemental-code"
                print(f"  [bundle] namespace '{ns}' ({scope}): "
                      f"{len(keys)} keys (no filter)", flush=True)

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

        # Guard checks the primary count specifically. An audit that
        # has zero source files but loaded supplemental docs is still
        # a degenerate case — the audit's job is to look at code, not
        # documentation. Error out the same way as before.
        # Error message text preserved verbatim so existing log/
        # inspection tooling that pattern-matches on it (notably
        # inspect_audit_findings.py looking for the "No files found
        # in namespaces" substring) keeps working.
        if primary_file_count == 0:
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
            # Supplemental files (from supplementalData namespaces) bypass
            # the skip rules entirely. The user explicitly opted in to
            # including them, and the SKIP_FILES list contains things
            # like README.md and CONTRIBUTING.md that are legitimate
            # guidance-doc names — they'd be dropped otherwise.
            if key in supplemental_keys:
                filtered_files[key] = content
                continue
            if should_skip_file(key):
                skipped_count += 1
                continue
            filtered_files[key] = content

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
            relevant_files = filtered_files
            relevance_scores = {path: 10 for path in filtered_files}
            sorted_relevant = sorted(relevant_files.keys())
        else:
            cached_relevance = relevance_cache_ns.get("scores")
            if cached_relevance:
                relevance_scores = cached_relevance
            else:
                file_previews = {}
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

                # Per-file preview cap. A 200-line slice is NOT a safe bound:
                # on huge repos a single file can have 200 lines whose token
                # count exceeds the whole batch budget, and the batcher below
                # cannot split a single entry — so it ships one oversized
                # prompt and Bedrock 400s with "prompt is too long" (observed
                # at 201,122 tokens > 200000). Cap each preview to a fraction
                # of the batch budget so no lone file can blow the window.
                PER_FILE_PREVIEW_TOKEN_CAP = max(1000, preview_budget // 4)

                file_previews = {}
                for path, content in filtered_files.items():
                    # Supplemental files are out-of-scope for relevance
                    # scoring — they're project guidance, not auditable
                    # code. Don't waste Haiku tokens rating them and
                    # don't let a low score drop them downstream; they
                    # get force-included below regardless.
                    if path in supplemental_keys:
                        continue
                    lines = content.split('\n')
                    preview = '\n'.join(lines[:200])
                    if count_tokens(preview, HAIKU_PROVIDER, HAIKU_MODEL) > PER_FILE_PREVIEW_TOKEN_CAP:
                        approx_chars = PER_FILE_PREVIEW_TOKEN_CAP * 3
                        preview = preview[:approx_chars]
                        while (preview and
                               count_tokens(preview, HAIKU_PROVIDER, HAIKU_MODEL)
                               > PER_FILE_PREVIEW_TOKEN_CAP):
                            preview = preview[: int(len(preview) * 0.8)]
                        preview = preview + "\n... [preview truncated for relevance scoring]"
                    file_previews[path] = preview

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

                relevance_scores = {}

                async def filter_batch(i, batch):
                    # Startup stagger BEFORE acquiring the semaphore so a
                    # sleeping coroutine doesn't hold one of the few Haiku
                    # slots. gather() launches every batch at once; without
                    # this the first HAIKU_CONCURRENCY calls hit Bedrock in
                    # the same instant and throttle immediately. Spread the
                    # opening burst across a few seconds.
                    stagger = min(i * 0.15, 3.0) + random.uniform(0, 0.25)
                    if stagger:
                        await asyncio.sleep(stagger)
                    async with haiku_semaphore:
                        entries_text = "".join(batch.values())
                        prompt = relevance_prompt_template + entries_text
                        messages = [{"role": "user", "content": prompt}]
                        # call_llm handles retries with exponential backoff.
                        # If we get here with an exception, retries have been
                        # exhausted (or it's a non-retryable error like a bad
                        # JSON response). Fall back to score=5 for every
                        # file in the batch — the audit will include them
                        # all rather than losing them silently.
                        try:
                            content_resp, _ = await call_llm(
                                provider=HAIKU_PROVIDER, model=HAIKU_MODEL,
                                messages=messages, parameters=HAIKU_PARAMS,
                                timeout=120,
                            )
                            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content_resp, re.DOTALL)
                            if json_match:
                                scores = json.loads(json_match.group())
                                return scores
                        except Exception as e:
                            print(f"[bundle {bundle_label}] relevance batch {i+1} FAILED: {e}", flush=True)
                        print(f"[bundle {bundle_label}] WARNING: relevance batch {i+1} defaulting {len(batch)} files to score=5", flush=True)
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
                # Supplemental files always pass the relevance gate.
                # They weren't scored by Haiku (see exclusion above)
                # and represent intentionally included context.
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
        cached_inventory = inventory_cache_ns.get("result")
        if cached_inventory:
            code_inventory = cached_inventory
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
                    # A single file larger than the batch budget. Isolating
                    # it into its own batch is not enough if it exceeds the
                    # window on its own — truncate the content to fit.
                    # Inventory only needs structure, so a head slice is
                    # acceptable degradation vs dropping the file.
                    approx_chars = inv_budget * 3
                    truncated = content[:approx_chars]
                    while (truncated and
                           count_tokens(
                               f"\n--- {path} ---\n{truncated}\n",
                               SONNET_PROVIDER, SONNET_MODEL) > inv_budget):
                        truncated = truncated[: int(len(truncated) * 0.8)]
                    entry = (f"\n--- {path} ---\n{truncated}\n"
                             f"... [file truncated at {len(truncated)} chars "
                             f"for inventory; full file exceeds model window]\n")
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
                                print(f"[bundle {bundle_label}] inventory sub-batch failed: {e}", flush=True)
                        return "\n\n".join(results)

                    # Retries handled centrally in call_llm. On failure
                    # the inventory entry for this batch is dropped; the
                    # caller filters empty results before joining.
                    try:
                        resp, _ = await call_llm(
                            provider=SONNET_PROVIDER, model=SONNET_MODEL,
                            messages=messages, parameters=SONNET_PARAMS,
                            timeout=300,
                        )
                        return resp
                    except Exception as e:
                        print(f"[bundle {bundle_label}] inventory batch {i+1} FAILED: {e}", flush=True)
                        return ""

            inventory_results = await asyncio.gather(*[
                inventory_batch(i, batch)
                for i, batch in enumerate(inv_batches)
            ])
            code_inventory = "\n\n---\n\n".join([r for r in inventory_results if r])
            inventory_cache_ns.set("result", code_inventory)

        # =============================================================
        # Step 4: Bundled deep analysis (Opus)
        # =============================================================

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
            severity_levels = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1, "INFORMATIONAL": 1}
            threshold_val = severity_levels.get(severity_threshold.upper(), 0)
            if threshold_val > 0:
                included_set = {k for k, v in severity_levels.items() if v >= threshold_val}
                included_set.discard("INFORMATIONAL")
                included = sorted(included_set, key=lambda k: -severity_levels[k])
                analysis_system_prompt += f"\n## Severity Threshold\nOnly report findings at these severity levels: {', '.join(included)}.\nDo not include findings below {severity_threshold.upper()} severity.\n"

        if false_positive_guidance:
            guidance_text = "\n".join(f"- {g}" for g in false_positive_guidance)
            analysis_system_prompt += f"\n## Known False Positive Patterns (DO NOT FLAG)\nThe following patterns are intentional design decisions in this codebase. Do not report them as vulnerabilities:\n{guidance_text}\n"

        # Wire AUDIT GUIDANCE files (from audit_guidance:* namespaces) into
        # the prompt as authoritative project guidance — NOT as source code
        # to audit. This is the final stage of the audit_guidance pipeline:
        #
        #   asvs_guidance_ingest    →  CouchDB audit_guidance:{repo}
        #   orchestrator namespaces →  bundle loads with filter exemption
        #   THIS BLOCK              →  inject as guidance, remove from source scope
        #
        # Other supplemental files (non-audit_guidance:* namespaces — vendored
        # libraries, related-repo overlays, config files) stay in
        # relevant_files and get rendered as source code below. They share the
        # filter exemptions but not the "authoritative, do not flag" framing.
        #
        # Without this, AGENTS.md and similar docs would reach the prompt but
        # Opus would audit them as if they were source code (flagging the
        # existence of AGENTS.md itself as a security issue, ignoring its
        # "What is NOT considered a vulnerability" section, etc.).
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

            # Remove guidance keys from source scope so they aren't also
            # rendered as code-fenced files-to-audit below. Their content is
            # already present in the guidance section above.
            for k in list(guidance_keys):
                relevant_files.pop(k, None)
            sorted_relevant = [k for k in sorted_relevant if k not in guidance_keys]

        analysis_system_prompt += """
## Audit Instructions

Follow ALL of these analysis requirements:

### Scope Check — do this FIRST for EACH requirement, before generating findings

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
- Flag coverage gaps where the control exists but is not applied

### Severity Calibration — Apache Software Foundation criteria

Severity follows the ASF Security Team's published criteria for ASF projects.
These override any default tendency to rate findings by CWE category, ASVS
section, or gap shape alone.

- **Critical** — easily exploited by a remote unauthenticated attacker,
  leads to RCE or full system compromise, no user interaction. NOT
  Critical if exploitation requires authentication, local/physical access,
  unusual configuration, user interaction, or prior compromise.
- **High** (ASF Important) — easily compromises C/I/A under realistic
  conditions: local/auth user gains privileges, unauth remote user views
  authentication-protected resources, auth remote user achieves RCE,
  remote user causes DoS. Requires both a real attacker capability AND
  a real C/I/A impact.
- **Medium** (ASF Moderate) — could compromise C/I/A under certain
  circumstances: more difficult to exploit, unlikely configuration,
  limited scope, or control bypass that requires application-layer
  cooperation to cause real harm. Foot-guns and easy-to-misuse defaults
  belong here.
- **Low** — security-relevant but minimal consequences or unlikely
  circumstances: defense-in-depth gaps where another layer prevents
  exploitation, documentation deficiencies that don't enable exploit,
  dead dependency pins, hardening recommendations without a concrete
  exploit path, nice-to-have library improvements.
- **Informational** — reserved for cases where a real, concrete code
  defect exists with specific file and line references, but no clear
  attack scenario can be constructed. This is the "downgrade-from-Low"
  tier — a real bug without an exploit path. Do NOT use Informational
  for requirements that don't apply to this component type, controls
  delegated to other layers, or absences of features. Those cases are
  N/A coverage, not findings. If your finding body would reasonably
  contain "not applicable", "feature absent", "delegated to", or
  "no [X] in this codebase", it belongs in N/A coverage and should
  not be emitted as a finding.

### Severity calibration — apply per finding

For every finding, answer three questions before assigning severity:
1. **Attacker capability required** — remote unauth (Critical/High) /
   authenticated (High/Medium) / privileged or local (Medium/Low) /
   specific unusual configuration (Medium/Low).
2. **What success achieves** — RCE (Critical/High) / priv esc (High) /
   data access (High/Medium) / DoS (High/Medium) / info disclosure
   (varies by sensitivity) / control bypass with no direct C/I/A impact
   (Medium/Low).
3. **Exploitability in default deployment** — trivially exploitable in
   default config pushes up; requires app-layer cooperation or unusual
   conditions pushes down.

If the answers do not justify Critical or High under ASF criteria, the
severity is lower — even when the finding's shape looks like a control-
flow gap.

### Gap Type Classification — pattern detection, not severity assignment

These shapes help recognize what KIND of finding you have. They do NOT
by themselves determine severity. After classifying the shape, apply the
calibration questions above.

| Gap Type | Description |
|----------|-------------|
| Type A | Entry point with NO control |
| Type B | Control EXISTS but NOT CALLED at this entry point |
| Type C | Control CALLED but RESULT IGNORED |
| Type D | Control CALLED but AFTER the sensitive operation |

Gap shape sets a ceiling on plausibility, not a floor on severity. A
Type B/C/D gap rates Critical only when the calibration questions yield
"remote unauthenticated RCE in default configuration." A Type B/C/D gap
that requires authenticated access and yields only control bypass without
direct C/I/A impact rates Medium at most. Do not auto-elevate gap-shape
findings to Critical without verifying the calibration supports it.

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
For each positive pattern, format as: `- **<short name>**: <what's done correctly> — <file>:<line>`
The trailing file:line reference is required so the consolidated report can cite the specific code under review.
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
- Severity level: CRITICAL, HIGH, MEDIUM, LOW, or INFO (in a `### [SEVERITY]` header) — assigned per the ASF Severity Calibration above
- Finding ID: ASVS-{section_no_dots}-SEV-NNN (e.g. ASVS-512-CRIT-001; SEV token is one of CRIT, HIGH, MED, LOW, INFO matching the assigned severity)
- Exact file location and function name with line numbers
- Vulnerable code quote (a fenced code block)
- Data flow: source → sink → missing control
- Attacker capability required (answer to calibration question 1)
- Impact on success (answer to calibration question 2)
- Proof of concept: a specific malicious request or input — required for Critical and High; if you cannot construct one consistent with the stated attacker capability, downgrade
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
            print(f"[bundle {bundle_label}] truncating inventory from {inventory_tokens} to {max_inv_tokens} tokens", flush=True)
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

        print(f"[bundle {bundle_label}] Opus: {len(opus_batches)} batch(es)", flush=True)

        # Pre-load analysis cache namespace in one bulk call. Each
        # batch's cache lookup below becomes an in-memory dict read
        # instead of a sync CouchDB get that would block the agent
        # thread's loop. Writes stay per-batch so a stopped run
        # preserves its cache progress.
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
                print(f"[bundle {bundle_label}] Opus batch {i+1}: cached", flush=True)
                return cached

            async with opus_semaphore:
                entries_text = "".join(batch.values())
                user_content = user_template + entries_text + inventory_section
                messages = [
                    {"role": "user", "content": analysis_system_prompt + "\n\n" + user_content}
                ]

                msg_tokens = count_message_tokens(messages, OPUS_PROVIDER, OPUS_MODEL)
                limit = int(OPUS_CONTEXT * 0.80)
                print(f"[bundle {bundle_label}] Opus batch {i+1}/{len(opus_batches)}: {msg_tokens} tokens, {len(batch)} files", flush=True)

                if msg_tokens > limit:
                    items = list(batch.items())
                    if len(items) > 1:
                        mid = len(items) // 2
                        results = []
                        for half_label, half_items in [("a", items[:mid]), ("b", items[mid:])]:
                            half_text = "".join([v for _, v in half_items])
                            half_user = user_template + half_text + inventory_section
                            half_messages = [{"role": "user", "content": analysis_system_prompt + "\n\n" + half_user}]
                            # call_llm handles retries (rate-limit and
                            # timeout). On exhaustion we keep a sentinel
                            # string so the bundle still produces output
                            # for the surviving halves; the failed-batch
                            # filter downstream strips these out.
                            try:
                                resp, _ = await call_llm(
                                    provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                    messages=half_messages, parameters=OPUS_PARAMS,
                                    timeout=1800,
                                )
                                results.append(resp)
                                print(f"[bundle {bundle_label}] Opus batch {i+1} sub-{half_label} complete", flush=True)
                            except Exception as e:
                                print(f"[bundle {bundle_label}] Opus batch {i+1} sub-{half_label} FAILED: {e}", flush=True)
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
                    print(f"[bundle {bundle_label}] Opus batch {i+1} complete", flush=True)
                    return resp
                except Exception as e:
                    print(f"[bundle {bundle_label}] Opus batch {i+1} FAILED: {e}", flush=True)
                    return f"[Analysis failed for batch {i+1}: {str(e)[:200]}]"

        # =============================================================
        # GUARDRAIL: distinguish "no work needed" from "all work failed"
        # =============================================================
        # Before this guardrail, a bundle with zero opus_batches (code
        # inventory determined nothing relevant to audit) fell through
        # to the same `analysis_results == []` path as a bundle whose
        # batches all crashed, and both returned the same `error:
        # "All analysis batches failed"` envelope. The orchestrator's
        # parser couldn't recognize the envelope as bundled output,
        # silently attributed the error JSON to the first section,
        # and emitted "did not return per-section output" stubs for
        # the rest. The stored stubs were then read by the consolidator
        # as legitimate N/A.
        #
        # The two cases need different handling:
        #   - 0 batches      => no relevant code; legitimate N/A
        #   - all crashed    => real failure; surface loudly
        if not opus_batches:
            print(
                f"[bundle {bundle_label}] no Opus batches needed (code inventory "
                f"determined no relevant implementation); emitting per-section N/A",
                flush=True,
            )
            per_section_na = {}
            for sid in asvs_sections:
                desc = asvs_descriptions.get(sid, f"ASVS Requirement {sid}")
                na_body = (
                    f"## ASVS-{sid}\n\n"
                    f"**Status:** N/A\n\n"
                    f"**Reason:** Code inventory of the audited scope determined "
                    f"that no implementation relevant to this requirement exists "
                    f"in the repository. The framework does not appear to provide "
                    f"functionality covered by ASVS {sid}.\n"
                )
                report = _format_section_report(
                    sid, desc,
                    repo_name, audit_date,
                    len(relevant_files), len(filtered_files), skipped_count,
                    {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                    na_body, "",
                )
                per_section_na[sid] = {
                    "report": report,
                    "findings": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
                    "files_analyzed": len(relevant_files),
                    "files_total": len(filtered_files),
                    "files_skipped": skipped_count,
                    "status": "N/A",
                    "reason": "no_relevant_code",
                }
            return {"outputText": json.dumps({
                "mode": "bundled",
                "asvs_sections": asvs_sections,
                "per_section": per_section_na,
                "bundle_status": "no_relevant_code",
            })}

        analysis_results = await asyncio.gather(*[
            analyze_batch(i, batch)
            for i, batch in enumerate(opus_batches)
        ])

        attempted = len(opus_batches)
        analysis_results = [r for r in analysis_results if r and not r.startswith("[Analysis failed")]

        if not analysis_results:
            # GUARDRAIL: opus_batches existed (work was attempted) but
            # every batch crashed. Tag the envelope so the orchestrator's
            # parser recognizes this as a real failure rather than a
            # bundled mode-output. See asvs_orchestrate.py
            # `_parse_audit_output` error-envelope branch.
            print(
                f"[bundle {bundle_label}] ALL OPUS BATCHES FAILED "
                f"(attempted={attempted}); returning error envelope",
                flush=True,
            )
            return {"outputText": json.dumps({
                "error": "All analysis batches failed",
                "asvs_sections": asvs_sections,
                "attempted_batches": attempted,
                "bundle_status": "all_batches_failed",
            })}

        # =============================================================
        # Step 5: Consolidation across batches [T8 — lazy rounds]
        # =============================================================
        if len(analysis_results) == 1:
            consolidated_analysis = analysis_results[0]
        elif len(analysis_results) <= 4:
            print(f"[bundle {bundle_label}] consolidating {len(analysis_results)} results (single-pass)", flush=True)
            consolidated_analysis = await _single_pass_consolidate(
                analysis_results, combined_asvs_description,
                SONNET_PROVIDER, SONNET_MODEL, SONNET_PARAMS,
            )
        else:
            print(f"[bundle {bundle_label}] consolidating {len(analysis_results)} results (multi-round)", flush=True)
            consolidated_analysis = await _multi_round_consolidate(
                analysis_results, combined_asvs_description,
                SONNET_PROVIDER, SONNET_MODEL, SONNET_PARAMS, SONNET_CONTEXT,
            )

        # =============================================================
        # Step 6: Split bundled output per section
        # =============================================================
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
        print(f"[bundle {bundle_label}] done: {len(asvs_sections)} sections, {total_findings} findings", flush=True)
        return {"outputText": json.dumps(envelope, default=str)}

    finally:
        await http_client.aclose()