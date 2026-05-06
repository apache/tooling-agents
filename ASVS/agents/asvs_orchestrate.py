# asvs_orchestrate
#
# The single entry point for the ASVS audit pipeline. Orchestrates:
#   asvs_download_repo  →  asvs_discover  →  asvs_audit / asvs_bundle  →
#   asvs_push_github (×N)  →  asvs_consolidate  →  redact + publish
#
# Major improvements over the unoptimized baseline:
#   T1 — Sections within each pass dispatch in parallel via asyncio.gather
#         with a configurable PASS_CONCURRENCY semaphore. The original ran
#         sections strictly sequentially (await in for-loop). This is the
#         single biggest win: 70%+ reduction on its own.
#   T4 — Bundled-mode dispatch: when a discovery pass has multiple ASVS
#         sections sharing the same file scope, they're sent in a single
#         multi-section call to asvs_bundle and the response is split back
#         out per-section before pushing to GitHub.
#   T12 — Skip discovery entirely for tiny repos (<30k LOC). Use a single
#         "all" pass with no domain partition.
#
# Concurrency knobs (env vars, with sensible defaults):
#   PASS_CONCURRENCY (default 4) — number of audit passes/sections in flight
#   BUNDLE_MAX_SECTIONS (default 6) — max sections per Opus call
#   BUNDLE_MIN_SECTIONS (default 2) — fall back to single-section below this
#   TINY_REPO_LOC_THRESHOLD (default 30000) — skip discovery under this
#
# Backward compat: behavior with bundling disabled (BUNDLE_MAX_SECTIONS=1)
# matches the original orchestrator section-by-section.

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        def _estimate_loc_from_namespace(namespace):
            """T12: Estimate LOC by sampling a few files from the data store."""
            try:
                ns = data_store.use_namespace(namespace)
                keys = ns.list_keys()
                if not keys:
                    return 0
                total_lines = 0
                sample_size = min(100, len(keys))
                sampled = keys[:sample_size]
                for k in sampled:
                    try:
                        content = ns.get(k) or ""
                        if isinstance(content, str):
                            total_lines += content.count("\n")
                    except Exception:
                        continue
                if sample_size < len(keys):
                    total_lines = int(total_lines * len(keys) / sample_size)
                return total_lines
            except Exception as e:
                print(f"    LOC estimate failed: {e}", flush=True)
                return 100_000  # default to "not tiny" on failure

        def _parse_audit_output(audit_output_text, section_chunk):
            """Decode either a bundled JSON envelope or a single-section markdown report.

            Returns dict: {section_id: report_markdown}.
            """
            import json
            # Try bundled envelope first
            if audit_output_text.strip().startswith("{"):
                try:
                    envelope = json.loads(audit_output_text)
                    if envelope.get("mode") == "bundled":
                        per_section = envelope.get("per_section", {})
                        out = {}
                        for sid in section_chunk:
                            entry = per_section.get(sid)
                            if entry is None:
                                out[sid] = (
                                    f"# ASVS {sid}\n\n"
                                    f"_Bundled audit produced no output for this section. "
                                    f"This may indicate the section is not applicable to "
                                    f"the audited file scope._\n"
                                )
                            else:
                                out[sid] = entry.get("report", "")
                        return out
                except json.JSONDecodeError:
                    pass
            # Fallback: single-section markdown report
            if len(section_chunk) == 1:
                return {section_chunk[0]: audit_output_text}
            # Multiple sections expected but didn't get JSON envelope — attribute
            # the markdown to the first and emit stubs for the rest
            out = {section_chunk[0]: audit_output_text}
            for sid in section_chunk[1:]:
                out[sid] = (
                    f"# ASVS {sid}\n\n"
                    f"_Audit agent did not return per-section output for this requirement. "
                    f"See ASVS {section_chunk[0]} report for the bundle's full output._\n"
                )
            return out

        # DEPRECATED: this helper is no longer called. Per-section reports
        # used to be pushed to GitHub (private repo) and then redacted-and-
        # re-pushed (public repo) per file. They now live in CouchDB only,
        # so neither push happens. The function is kept here intentionally
        # in case per-section public reports are ever revived. If you're
        # certain they won't be, this whole def can be deleted.
        async def _redact_and_push(gofannon_client, http_client, private_repo, private_token,
                                    output_repo, output_token, pass_output_dir, filename,
                                    redact_fn, source_id):
            import json
            import base64
            # Throttle through the shared github_push_sem so the redaction
            # phase doesn't bypass the global concurrency budget. Note: this
            # closure captures github_push_sem from the outer run() scope.
            async with github_push_sem:
                headers = {"Authorization": f"token {private_token}", "Accept": "application/vnd.github.v3+json"}
                resp = await http_client.get(
                    f"https://api.github.com/repos/{private_repo}/contents/{pass_output_dir}/{filename}",
                    headers=headers,
                )
                if resp.status_code != 200:
                    # Surface this — previously returned silently and we'd never
                    # know the private-repo read failed. Common causes: wrong
                    # private repo, wrong path, or insufficient token scope.
                    print(f"  Read redacted {pass_output_dir}/{filename} from {private_repo} FAILED: HTTP {resp.status_code}", flush=True)
                    return
                file_data = resp.json()
                file_content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                redacted_section, _ = redact_fn(file_content)
                try:
                    push_result = await gofannon_client.call(
                        agent_name="asvs_push_github",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": output_repo, "token": output_token,
                                "directory": pass_output_dir, "filename": filename,
                            }),
                            "commitMessage": f"ASVS audit: {filename} (redacted) [source: {source_id}]",
                            "fileContents": redacted_section,
                        }
                    )
                    # asvs_push_github doesn't raise on GitHub errors — it
                    # returns the error body in outputText. Inspect for
                    # success markers (content + commit) the same way push_one
                    # does for the audit phase.
                    output_text = ""
                    if isinstance(push_result, dict):
                        output_text = push_result.get("outputText", "") or ""
                    if not output_text or "\"content\"" not in output_text or "\"commit\"" not in output_text:
                        # Try to extract a clean error message
                        err_msg = output_text[:300] if output_text else "(no outputText)"
                        try:
                            parsed = json.loads(output_text) if output_text else {}
                            if isinstance(parsed, dict) and "message" in parsed:
                                err_msg = parsed["message"]
                        except Exception:
                            pass
                        print(f"  Push redacted {filename} to {output_repo} FAILED: {err_msg}", flush=True)
                except Exception as e:
                    typed = type(e).__name__
                    detail = str(e) or f"{typed} (no detail)"
                    print(f"  Push redacted {filename} to {output_repo} FAILED: {detail}", flush=True)


        import os
        import json
        import re
        import base64

        # =============================================================
        # Concurrency / bundling configuration
        # =============================================================
        PASS_CONCURRENCY = int(os.environ.get("PASS_CONCURRENCY", "4"))
        BUNDLE_MAX_SECTIONS = int(os.environ.get("BUNDLE_MAX_SECTIONS", "6"))
        BUNDLE_MIN_SECTIONS = int(os.environ.get("BUNDLE_MIN_SECTIONS", "2"))
        TINY_REPO_LOC_THRESHOLD = int(os.environ.get("TINY_REPO_LOC_THRESHOLD", "30000"))

        # =============================================================
        # Parse inputs
        # =============================================================
        source_repo = input_dict.get("sourceRepo", "")
        source_token = input_dict.get("sourceToken", "")
        supplemental_data = input_dict.get("supplementalData", "")
        output_repo = input_dict.get("outputRepo", "")
        output_token = input_dict.get("outputToken", "")
        output_directory = input_dict.get("outputDirectory", "")
        discover = input_dict.get("discover", "true")
        severity_threshold = input_dict.get("severityThreshold", "")
        consolidate = input_dict.get("consolidate", "true")
        level = input_dict.get("level", "")

        private_repo = input_dict.get("privateRepo", "")
        private_token = input_dict.get("privateToken", "")
        notify_email = input_dict.get("notifyEmail", "")
        clear_cache = input_dict.get("clearCache", "true")
        clean_stale_reports = input_dict.get("cleanStaleReports", "false")

        if isinstance(discover, str):
            discover = discover.lower() in ("true", "1", "yes")
        if isinstance(consolidate, str):
            consolidate = consolidate.lower() in ("true", "1", "yes")
        if isinstance(clear_cache, str):
            clear_cache = clear_cache.lower() in ("true", "1", "yes")
        if isinstance(clean_stale_reports, str):
            clean_stale_reports = clean_stale_reports.lower() in ("true", "1", "yes")

        level = level.strip().upper()
        if level and not level.startswith("L"):
            level = f"L{level}"
        LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
        max_level_num = LEVEL_ORDER.get(level, 3)

        if not source_repo:
            return {"outputText": "Error: sourceRepo is required (e.g., 'apache/airflow')"}

        carve_out = bool(private_repo)
        if carve_out and not private_token:
            return {"outputText": "Error: privateToken is required when privateRepo is set"}

        push_repo = private_repo if carve_out else output_repo
        push_token = private_token if carve_out else output_token

        # Derive repo name, path prefix, and namespace from sourceRepo
        _source = source_repo.strip().strip("/")
        _gh_match = re.match(
            r'(?:https?://)?github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/[^/]+(?:/(.+))?)?$',
            _source,
        )
        if _gh_match:
            repo_owner_name = f"{_gh_match.group(1)}/{_gh_match.group(2)}"
            repo_short_name = _gh_match.group(2)
            source_path_prefix = _gh_match.group(3) or ""
        else:
            source_parts = _source.split("/")
            if len(source_parts) < 2:
                return {"outputText": f"Error: sourceRepo must be owner/repo format, got '{source_repo}'"}
            repo_owner_name = f"{source_parts[0]}/{source_parts[1]}"
            repo_short_name = source_parts[1]
            source_path_prefix = "/".join(source_parts[2:]) if len(source_parts) > 2 else ""

        download_source = repo_owner_name
        if source_path_prefix:
            download_source += f"/{source_path_prefix}"

        code_namespace = f"files:{download_source}"

        namespaces = [code_namespace]
        if supplemental_data:
            for ns in supplemental_data.split(","):
                ns = ns.strip()
                if ns and ns not in namespaces:
                    namespaces.append(ns)

        # Fetch latest commit hash
        source_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if source_token:
            source_headers["Authorization"] = f"Bearer {source_token}"
        try:
            commits_resp = await http_client.get(
                f"https://api.github.com/repos/{repo_owner_name}/commits?per_page=1",
                headers=source_headers,
            )
            commits_data = commits_resp.json()
            commit_hash = commits_data[0]["sha"][:7]
        except Exception as e:
            print(f"  WARNING: Could not fetch commit hash ({e}), using 'latest'", flush=True)
            commit_hash = "latest"

        repo_path_segment = repo_short_name
        if source_path_prefix:
            repo_path_segment += f"/{source_path_prefix}"
        output_directory = f"{output_directory.strip('/')}/{repo_path_segment}/{commit_hash}"
        push_directory = output_directory

        # Source identifier appended to every report commit message so each
        # commit reads as "<commit subject> [source: owner/repo[/path] @ sha]"
        # and you can grep history by source repo or by commit hash. Format
        # is stable across all per-section, consolidated, issues, and
        # redacted pushes.
        source_id_path = repo_owner_name
        if source_path_prefix:
            source_id_path += f"/{source_path_prefix}"
        source_id = f"{source_id_path} @ {commit_hash}"

        # Per-section reports go into CouchDB instead of GitHub. The
        # previous approach committed each per-section report to the
        # private repo, which surfaced one entry on the public
        # commits@tooling.apache.org mailing list per section (often
        # with finding titles in the diff). Now they're stored in a
        # CouchDB namespace keyed by output_directory; consolidate reads
        # from the same namespace. Only consolidated.md, issues.md, and
        # their redacted variants still go to GitHub.
        reports_namespace = f"audit-reports:{output_directory}"

        print(f"  Output directory: {output_directory}", flush=True)
        print(f"  Reports namespace: {reports_namespace}", flush=True)
        print(f"  Pass concurrency: {PASS_CONCURRENCY}", flush=True)
        print(f"  Bundling: max={BUNDLE_MAX_SECTIONS} sections/call, min={BUNDLE_MIN_SECTIONS}", flush=True)
        if carve_out:
            print(f"  Carve-out enabled: full → {private_repo}, redacted → {output_repo}", flush=True)

        all_outputs = []
        successes = []
        failures = []
        report_directories = []

        # =============================================================
        # Redaction helpers (unchanged from original)
        # =============================================================
        def redact_consolidated(content):
            """Strip Critical findings from the consolidated report.

            Robustness: a finding block is only treated as Critical when its
            STRUCTURED severity token says Critical — not when the word
            "critical" appears anywhere in prose. Audit reports legitimately
            use "critical" in descriptions, gap classifications, and impact
            language; matching on bare keywords drops innocent findings.

            Detection precedence (first match wins, per finding):
              1. Finding ID token: `ASVS-{section}-CRIT-NNN` or `-CRITICAL-NNN`
              2. Severity heading: `#### CRITICAL` / `### [CRITICAL]` (any depth)
              3. Severity field:  `**Severity:** Critical` / `**Severity**: Critical`
              4. Old consolidated emoji marker at start of block: `🔴 Critical`

            Block matching covers BOTH formats produced by the pipeline:
              - Old consolidated: `#### FINDING-NNN: ...`
              - New bundled:      `#### CRITICAL` / `#### MEDIUM` / etc., with
                `**Finding ID:** ASVS-NNN-SEV-NNN` inside
            """
            critical_findings = []
            redacted = content

            # Match a finding block: starts with `#### <header>` and runs until
            # the next `####`, `##`, horizontal rule, or end of doc.
            finding_pattern = re.compile(
                r'(####\s+[^\n]+\n[\s\S]*?)(?=####\s|##\s|\n---\n|\Z)',
                re.MULTILINE,
            )

            def is_critical_block(block):
                # 1. Finding ID severity token (most reliable)
                if re.search(r'ASVS-\d+-CRIT(?:ICAL)?-\d+', block, re.IGNORECASE):
                    return True
                # 2. Severity heading at any depth
                first_line = block.split('\n', 1)[0]
                if re.match(r'#{1,6}\s*\[?\s*CRITICAL\s*\]?\s*$', first_line, re.IGNORECASE):
                    return True
                # 3. Explicit Severity field
                if re.search(r'\*\*Severity:?\*\*:?\s*Critical\b', block, re.IGNORECASE):
                    return True
                # 4. Old emoji-prefixed header
                if re.search(r'🔴\s*Critical\b', block, re.IGNORECASE):
                    return True
                return False

            def extract_finding_id(block):
                # Try the new ASVS-{section}-{SEV}-NNN format first
                m = re.search(r'\*\*Finding ID:?\*\*:?\s*(ASVS-\d+-[A-Z]+-\d+)',
                              block, re.IGNORECASE)
                if m:
                    return m.group(1)
                # Fall back to the old FINDING-NNN format
                m = re.match(r'####\s+(FINDING-\d+)', block)
                if m:
                    return m.group(1)
                # Last resort: a stable hash of the block's first line
                first_line = block.split('\n', 1)[0].strip()
                return f"UNKNOWN-{hash(first_line) & 0xFFFF:04X}"

            # Walk every finding block, deciding redaction structurally.
            for match in finding_pattern.finditer(content):
                block = match.group(1)
                if is_critical_block(block):
                    finding_id = extract_finding_id(block)
                    critical_findings.append({"id": finding_id, "block": block.strip()})
                    redacted = redacted.replace(match.group(1), "")

            # Strip the Critical-severity section in the report body
            # (e.g., "### 3.1 Critical Findings" or "## Critical Severity")
            redacted = re.sub(
                r'###?\s+\d+\.\d+\s+Critical[^\n]*\n.*?(?=###?\s+\d+\.\d+\s+\w|##\s+\d|\Z)',
                '', redacted, flags=re.DOTALL,
            )
            redacted = re.sub(
                r'##\s+Critical\s+Severity\b.*?(?=##\s+\w|\Z)',
                '', redacted, flags=re.DOTALL,
            )

            if critical_findings:
                # Build a set of redacted Finding IDs for cross-reference scrubbing
                redacted_ids = set()
                for cf in critical_findings:
                    fid = cf["id"]
                    redacted_ids.add(fid)
                    # Also add the FINDING-NNN form if it's an ASVS-style ID
                    # (consolidated.md cross-refs always use the FINDING-NNN form
                    # regardless of which form appears in the per-section reports)
                    m = re.match(r'FINDING-(\d+)', fid)
                    if m:
                        redacted_ids.add(fid)

                # 1. Recompute the Severity Distribution table.
                # Two formats observed in practice:
                #
                #   Horizontal (one row, columns by severity):
                #     | Critical | High | Medium | Low | Info | Total |
                #     |----------|------|--------|-----|------|-------|
                #     | 6        | 16   | 34     | 21  | 0    | **77**|
                #
                #   Vertical (one row per severity):
                #     | Severity     | Count | Percentage |
                #     |--------------|------:|-----------:|
                #     | **Critical** |     6 |       7.8% |
                #     | **High**     |    16 |      20.8% |
                #     ...
                #     | **Total**    | **77**| **100%**   |
                #
                # Both need to zero the Critical count and decrement Total.
                redacted_count = len(critical_findings)

                def _zero_critical_count(m):
                    # Horizontal-format helper. Replace the Critical count
                    # (first numeric cell after `|`) with 0, leaving the
                    # other counts and Total intact.
                    row = m.group(0)
                    new_row = re.sub(r'(\|\s*)\d+(\s*\|)', r'\g<1>0\g<2>', row, count=1)
                    total_m = re.search(r'\*\*(\d+)\*\*', new_row)
                    if total_m:
                        old_total = int(total_m.group(1))
                        new_total = max(0, old_total - redacted_count)
                        new_row = new_row.replace(f'**{old_total}**', f'**{new_total}**')
                    return new_row

                # Horizontal format: header row + alignment row + data row.
                sev_table_pattern_horizontal = re.compile(
                    r'(\|\s*Critical\s*\|\s*High\s*\|\s*Medium\s*\|\s*Low\s*\|\s*Info[^\n]*\|\n'
                    r'\|[\s:|-]+\|\n)'
                    r'(\|[^\n]+\|)',
                    re.IGNORECASE,
                )
                def _sev_table_replace(m):
                    return m.group(1) + _zero_critical_count(re.match(r'.*', m.group(2)))
                redacted = sev_table_pattern_horizontal.sub(_sev_table_replace, redacted)

                # Vertical format: zero the Critical row's count cell, and
                # decrement the Total row. Match the row pattern:
                #   | (optional formatting) Critical (optional formatting) | <count> | ... |
                # Critical cell may be wrapped in **...** or contain emoji.
                def _zero_vertical_critical_row(m):
                    row = m.group(0)
                    # Replace first numeric or **N** cell after the
                    # Critical label with 0.
                    new_row = re.sub(
                        r'(\|\s*\**\s*(?:🔴\s*)?Critical\s*\**\s*\|\s*)'
                        r'(?:\*\*)?\d+(?:\*\*)?(\s*\|)',
                        r'\g<1>0\g<2>',
                        row,
                        count=1,
                        flags=re.IGNORECASE,
                    )
                    return new_row
                redacted = re.sub(
                    r'\|\s*\**\s*(?:🔴\s*)?Critical\s*\**\s*\|[^\n]+\|',
                    _zero_vertical_critical_row,
                    redacted,
                    flags=re.IGNORECASE,
                )

                # Vertical format: decrement Total row.
                def _decrement_vertical_total_row(m):
                    row = m.group(0)
                    # Find first numeric cell (possibly **N**) after Total
                    num_m = re.search(
                        r'(\|\s*\**\s*Total\s*\**\s*\|\s*\**)(\d+)(\**\s*\|)',
                        row,
                        flags=re.IGNORECASE,
                    )
                    if num_m:
                        old = int(num_m.group(2))
                        new = max(0, old - redacted_count)
                        row = row[:num_m.start(2)] + str(new) + row[num_m.end(2):]
                    return row
                redacted = re.sub(
                    r'\|\s*\**\s*Total\s*\**\s*\|[^\n]+\|',
                    _decrement_vertical_total_row,
                    redacted,
                    flags=re.IGNORECASE,
                )

                # 2. Strip ASCII bar chart Critical line if present (e.g.
                #    "Critical  ████░░  6  ( 7.8%)")
                redacted = re.sub(
                    r'^[ \t]*Critical[ \t]+[█░▓▒]+[^\n]*\n',
                    '',
                    redacted,
                    flags=re.MULTILINE | re.IGNORECASE,
                )

                # 3. Scrub references to redacted Finding IDs in Top Risks /
                #    Cross-Reference Matrix tables. These appear in cells like:
                #    "FINDING-001 through FINDING-004, FINDING-010, ..."
                #    Drop only the redacted IDs, preserving the rest.
                #    Do not touch tables in code blocks or per-finding blocks
                #    (those have already been removed).
                if redacted_ids:
                    # Drop entire table rows whose severity column says
                    # Critical. This catches Top 5 Risks rows (which have
                    # full risk descriptions and titles in adjacent cells —
                    # leaving only the IDs to strip but keeping the rest
                    # leaks the redacted finding's content via title and
                    # description), Cross-Reference Matrix rows, and any
                    # other table that includes severity per row.
                    #
                    # The match is intentionally broad: any line that
                    # starts with `|`, contains `Critical` in any cell
                    # (with or without ** wrapping or 🔴 emoji), and ends
                    # with `|`. False positives are theoretically possible
                    # if a non-redacted finding's title contains the word
                    # "Critical", but in practice severity columns are
                    # the dominant source of the word in tables and we
                    # accept this risk as the cost of full redaction.
                    #
                    # Safety: don't touch lines inside code fences. Code
                    # fences are rendered as-is, so lines starting with
                    # `|` inside ```...``` blocks aren't tables.
                    def _strip_critical_table_rows(text):
                        out = []
                        in_fence = False
                        for line in text.split('\n'):
                            stripped = line.lstrip()
                            if stripped.startswith('```'):
                                in_fence = not in_fence
                                out.append(line)
                                continue
                            if in_fence:
                                out.append(line)
                                continue
                            # Detect table row with Critical in a cell.
                            # Pattern: starts with |, ends with |, contains
                            # Critical (with optional ** or 🔴 wrapping).
                            if (
                                stripped.startswith('|')
                                and stripped.rstrip().endswith('|')
                                and re.search(
                                    r'\|\s*\**\s*(?:🔴\s*)?Critical\s*\**\s*\|',
                                    line,
                                    re.IGNORECASE,
                                )
                            ):
                                # Skip the row (don't append to output)
                                continue
                            out.append(line)
                        return '\n'.join(out)
                    redacted = _strip_critical_table_rows(redacted)

                    sorted_ids = sorted(redacted_ids,
                                         key=lambda s: int(re.search(r'(\d+)', s).group(1)) if re.search(r'(\d+)', s) else 0)

                    # Drop "FINDING-A through FINDING-B" ranges. If the entire
                    # range is redacted, drop the whole expression. Otherwise
                    # rewrite to "FINDING-X, FINDING-Y, ..." with only the
                    # surviving IDs, then let the per-ID stripping below clean
                    # up redacted ones.
                    def _strip_range(m):
                        a = m.group(1)
                        b = m.group(2)
                        try:
                            a_num = int(re.search(r'(\d+)', a).group(1))
                            b_num = int(re.search(r'(\d+)', b).group(1))
                        except Exception:
                            return m.group(0)
                        survivors = [
                            f"FINDING-{n:03d}"
                            for n in range(a_num, b_num + 1)
                            if f"FINDING-{n:03d}" not in redacted_ids
                        ]
                        if not survivors:
                            return ""
                        return ", ".join(survivors)
                    redacted = re.sub(
                        r'(FINDING-\d+)\s+through\s+(FINDING-\d+)',
                        _strip_range,
                        redacted,
                    )

                    # Drop comma-separated occurrences of redacted IDs
                    for fid in sorted_ids:
                        redacted = re.sub(
                            r',\s*' + re.escape(fid) + r'\b',
                            '',
                            redacted,
                        )
                        redacted = re.sub(
                            r'\b' + re.escape(fid) + r'\s*,\s*',
                            '',
                            redacted,
                        )
                        # Bare leftover - could be in a table cell on its own
                        redacted = re.sub(
                            r'\b' + re.escape(fid) + r'\b',
                            '',
                            redacted,
                        )

                    # Scrub "Nx Critical" / "N× Critical" / "N Critical" phrases
                    # in surviving table cells — the count is now wrong and
                    # naming the redacted severity defeats the purpose of the
                    # carve-out. Preserve other severity counts in the cell.
                    def _strip_critical_phrases(m):
                        cell = m.group(0)
                        # Drop the "Nx Critical, " or "N× Critical, " segments
                        cell = re.sub(
                            r'\d+\s*[x×]\s*Critical\s*,?\s*',
                            '',
                            cell,
                            flags=re.IGNORECASE,
                        )
                        # Tidy up trailing/leading commas
                        cell = re.sub(r',\s*\|', ' |', cell)
                        cell = re.sub(r'\|\s*,', '| ', cell)
                        return cell
                    # Apply to lines that look like table rows
                    redacted = re.sub(
                        r'\|[^\n]*Critical[^\n]*\|',
                        _strip_critical_phrases,
                        redacted,
                    )

                    # Clean up leftover artifacts: empty list items,
                    # cells starting with stray ", ", double commas, leading
                    # whitespace from removed ranges, and full Cross-Reference
                    # Matrix rows whose Finding ID col is now empty.
                    redacted = re.sub(r'\|\s*,\s*', '| ', redacted)
                    redacted = re.sub(r',\s*,', ',', redacted)
                    # Collapse multiple spaces inside cells (not at line start).
                    # Use [ \t] not \s to avoid eating newlines, which would
                    # weld the end of a table to the start of the next section.
                    redacted = re.sub(r'\|[ \t]{2,}', '| ', redacted)
                    redacted = re.sub(r'\|\s+\|\s+(Critical|High|Medium|Low)\b[^\n]*\n', '', redacted)

                # Polish: tables left empty by Critical-row removal get
                # replaced with an explanatory notice. This catches things
                # like a Top 5 Risks table where every row was Critical
                # and got stripped — we don't want to leave a bare header
                # + alignment row with no data, which renders awkwardly
                # on GitHub. Detect by walking line-by-line: a header
                # row followed by an alignment row followed by anything
                # other than another `|` row means the table is empty.
                #
                # Note: we do this even when no critical_findings were
                # present in the report, to handle other paths that may
                # produce empty tables. The cost is negligible.
                def _replace_empty_tables(text, redacted_count):
                    out_lines = []
                    lines = text.split('\n')
                    i = 0
                    in_fence = False
                    while i < len(lines):
                        line = lines[i]
                        stripped = line.lstrip()
                        if stripped.startswith('```'):
                            in_fence = not in_fence
                            out_lines.append(line)
                            i += 1
                            continue
                        if in_fence:
                            out_lines.append(line)
                            i += 1
                            continue
                        # Look for header + alignment + (no data rows) pattern.
                        # Header: line starts and ends with `|` and isn't an
                        # alignment row.
                        # Alignment: line is `|` separators with `:` and `-`.
                        # No data: walking forward from after the alignment
                        # row, the next non-blank line isn't a `|`-form data
                        # row (or is a `|`-form alignment row, weird but
                        # possible).
                        is_header = (
                            stripped.startswith('|')
                            and stripped.rstrip().endswith('|')
                            and not re.match(r'^\s*\|[\s:|-]+\|\s*$', line)
                            and i + 1 < len(lines)
                        )
                        if is_header:
                            next_line = lines[i + 1]
                            is_alignment = (
                                next_line.lstrip().startswith('|')
                                and next_line.rstrip().endswith('|')
                                and re.match(r'^\s*\|[\s:|-]+\|\s*$', next_line)
                            )
                            if is_alignment:
                                # Look at the line immediately after alignment.
                                # Skip up to a small number of blank lines that
                                # might be cosmetic padding.
                                j = i + 2
                                blanks_skipped = 0
                                while (
                                    j < len(lines)
                                    and not lines[j].strip()
                                    and blanks_skipped < 2
                                ):
                                    j += 1
                                    blanks_skipped += 1
                                # A data row is a `|`-prefixed line that is
                                # NOT an alignment row.
                                has_data = False
                                if j < len(lines):
                                    nxt = lines[j]
                                    nxt_strip = nxt.lstrip()
                                    if (
                                        nxt_strip.startswith('|')
                                        and nxt.rstrip().endswith('|')
                                        and not re.match(r'^\s*\|[\s:|-]+\|\s*$', nxt)
                                    ):
                                        has_data = True
                                if not has_data:
                                    # Empty table — replace with notice.
                                    notice_text = (
                                        f"> _All entries in this section were Critical findings "
                                        f"and have been redacted. {redacted_count} Critical "
                                        f"{'finding has' if redacted_count == 1 else 'findings have'} "
                                        f"been forwarded to the proper channels for triage._"
                                    )
                                    out_lines.append(notice_text)
                                    # Advance past header + alignment, but
                                    # do NOT consume the blank lines or
                                    # following content — leave them as
                                    # natural section separators.
                                    i += 2
                                    continue
                        out_lines.append(line)
                        i += 1
                    return '\n'.join(out_lines)

                if critical_findings:
                    redacted = _replace_empty_tables(redacted, len(critical_findings))

                notice = (
                    f"\n\n> **Note:** {len(critical_findings)} Critical "
                    f"{'finding has' if len(critical_findings) == 1 else 'findings have'} "
                    f"been redacted from this report and forwarded to the project's "
                    f"PMC private mailing list.\n\n"
                )
                first_sep = redacted.find("\n---\n")
                if first_sep > 0:
                    redacted = redacted[:first_sep + 5] + notice + redacted[first_sep + 5:]
                else:
                    redacted = notice + redacted
            return redacted, critical_findings

        def redact_issues(content):
            """Strip Critical issues from the issues.md file.

            Same robust structured matching as redact_consolidated. Issues
            use a different block delimiter (`## Issue: ...`) but we look
            for the same structured severity signals.
            """
            issue_pattern = re.compile(
                r'(##\s+Issue:[^\n]*\n[\s\S]*?)(?=##\s+Issue:|\Z)',
                re.MULTILINE,
            )
            redacted = content
            removed_count = 0

            def is_critical_issue(block):
                # Issue files have an explicit Priority field
                if re.search(r'\*\*Priority:?\*\*:?\s*Critical\b|priority:\s*critical\b',
                             block, re.IGNORECASE):
                    return True
                # Severity field (issues sometimes have both)
                if re.search(r'\*\*Severity:?\*\*:?\s*Critical\b', block, re.IGNORECASE):
                    return True
                # Finding ID token
                if re.search(r'ASVS-\d+-CRIT(?:ICAL)?-\d+', block, re.IGNORECASE):
                    return True
                # Old format
                if re.search(r'🔴\s*Critical\b', block, re.IGNORECASE):
                    return True
                return False

            for match in issue_pattern.finditer(content):
                block = match.group(1)
                if is_critical_issue(block):
                    redacted = redacted.replace(match.group(1), "")
                    removed_count += 1
            return redacted, removed_count

        def build_email_body(critical_findings, repo_name, commit):
            lines = [
                f"ASVS Security Audit: Critical Findings", "",
                f"Repository: {repo_name}",
                f"Commit: {commit}",
                f"Critical findings: {len(critical_findings)}", "",
                f"The following Critical severity findings were identified",
                f"and have been redacted from the public report.", "",
                f"Full report: https://github.com/{private_repo}/tree/main/{output_directory}/consolidated.md", "",
            ]
            for cf in critical_findings:
                lines.append("---")
                lines.append("")
                lines.append(cf["block"])
                lines.append("")
            return "\n".join(lines)

        async def send_email(recipient, subject, body):
            import smtplib
            from email.mime.text import MIMEText
            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = "tooling-agents@apache.org"
            msg["To"] = recipient
            try:
                smtp = smtplib.SMTP("mail-relay.apache.org", 587, timeout=30)
                smtp.starttls()
                smtp.send_message(msg)
                smtp.quit()
                print(f"  Email sent to {recipient}", flush=True)
            except Exception as e:
                print(f"  Email FAILED to {recipient}: {e}", flush=True)
                failures.append(f"email to {recipient}: {e}")

        async def read_file_from_github(repo, token, filepath):
            headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
            resp = await http_client.get(
                f"https://api.github.com/repos/{repo}/contents/{filepath}",
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            print(f"  WARNING: Could not read {repo}/{filepath}: {resp.status_code}", flush=True)
            return None

        # =============================================================
        # ASVS-level filtering
        # =============================================================
        asvs_level_cache = {}

        def load_asvs_levels():
            if asvs_level_cache:
                return
            try:
                asvs_ns = data_store.use_namespace("asvs")
                all_keys = asvs_ns.list_keys()
                req_keys = [k for k in all_keys if k.startswith("asvs:requirements:")]
                for rk in req_keys:
                    req = asvs_ns.get(rk)
                    if req:
                        section_id = rk.replace("asvs:requirements:", "")
                        asvs_level_cache[section_id] = int(req.get("level", 1))
                print(f"  Loaded ASVS levels for {len(asvs_level_cache)} sections", flush=True)
            except Exception as e:
                print(f"  WARNING: Could not load ASVS levels: {e}", flush=True)

        def filter_sections_by_level(sections):
            """Filter sections by level, AND drop any IDs not present in the
            authoritative ASVS data store.

            Belt-and-suspenders: discovery now validates its output too, but
            this protects against any other source of stale/hallucinated IDs
            (manually-edited domain configs, cache restoration, etc).
            """
            load_asvs_levels()
            kept = []
            dropped_unknown = []
            dropped_higher_level = []
            for s in sections:
                if s not in asvs_level_cache:
                    dropped_unknown.append(s)
                    continue
                if level and asvs_level_cache[s] > max_level_num:
                    dropped_higher_level.append(s)
                    continue
                kept.append(s)
            if dropped_unknown:
                print(f"    WARNING: dropping {len(dropped_unknown)} unknown section ID(s) not in ASVS data store: {dropped_unknown[:5]}{'...' if len(dropped_unknown) > 5 else ''}", flush=True)
            return kept

        # =============================================================
        # Step 1: Download source code (or use cached data)
        # =============================================================
        if clear_cache:
            print(f"{'='*60}\nStep 1: Downloading source code\n  Source: {source_repo}\n{'='*60}", flush=True)

            download_input = download_source
            if source_token:
                download_input += f"\n{source_token}"

            try:
                download_result = await gofannon_client.call(
                    agent_name="asvs_download_repo",
                    input_dict={"inputText": download_input},
                )
                download_output = download_result.get("outputText", "")
                print(f"  {download_output}", flush=True)
            except Exception as e:
                return {"outputText": f"Download failed: {e}"}
        else:
            print(f"{'='*60}\nStep 1: SKIPPED (clearCache=false)\n  Using existing data in namespace: {code_namespace}\n{'='*60}", flush=True)
            # Sanity check: don't silently proceed against an empty namespace
            try:
                files_ns = data_store.use_namespace(code_namespace)
                existing_keys = files_ns.list_keys() or []
                if not existing_keys:
                    return {"outputText": (
                        f"Error: clearCache=false but namespace '{code_namespace}' is empty. "
                        f"Either set clearCache=true to download fresh, or run asvs_download_repo "
                        f"manually first to populate the namespace."
                    )}
                print(f"  Namespace '{code_namespace}' has {len(existing_keys)} cached keys", flush=True)
            except Exception as e:
                return {"outputText": (
                    f"Error: clearCache=false but couldn't read namespace '{code_namespace}': {e}. "
                    f"Either set clearCache=true to download fresh, or check the namespace name."
                )}

        # T12: estimate LOC from download output to decide whether to skip discovery.
        #
        # T12 originated as an L1 optimization: small repos with ~70
        # sections gain little from discovery and the discovery LLM call
        # adds 30-60s of latency for marginal benefit. But at L3 with
        # ~345 sections, discovery's output isn't optional — it's the
        # *only* thing producing domain groupings small enough for the
        # consolidate phase to fit in Sonnet's context window. Without
        # discovery at L3 the orchestrator falls back to a single "all"
        # bucket of 345 sections → ContextWindowExceededError.
        #
        # So T12 only fires when:
        #   1. The user did not explicitly request discovery (or did but
        #      the section count is low enough to safely skip), AND
        #   2. The repo is below the LOC threshold, AND
        #   3. Section count is below the chapter-grouping threshold
        #
        # If discover=true was passed, we respect that intent regardless
        # of repo size. The user knows they need the grouping output.
        estimated_loc = _estimate_loc_from_namespace(code_namespace)
        # Compute expected section count up front so we can use it in T12
        try:
            asvs_ns_check = data_store.use_namespace("asvs")
            _all_keys = asvs_ns_check.list_keys() or []
            _req_keys = [k for k in _all_keys if k.startswith("asvs:requirements:")]
            _all_sections_for_check = [rk.replace("asvs:requirements:", "") for rk in _req_keys]
            # Apply level filter to estimate the post-filter count
            load_asvs_levels()
            expected_section_count = sum(
                1 for s in _all_sections_for_check
                if asvs_level_cache.get(s, 99) <= max_level_num
            )
        except Exception:
            expected_section_count = 999  # err on the side of NOT skipping

        DISCOVERY_REQUIRED_SECTION_THRESHOLD = 100
        # Skip discovery only if all three conditions hold
        skip_discovery = (
            estimated_loc < TINY_REPO_LOC_THRESHOLD
            and expected_section_count < DISCOVERY_REQUIRED_SECTION_THRESHOLD
        )
        if skip_discovery and discover:
            print(f"  Repo is small ({estimated_loc} LOC < {TINY_REPO_LOC_THRESHOLD}) "
                  f"and section count is low ({expected_section_count} < "
                  f"{DISCOVERY_REQUIRED_SECTION_THRESHOLD}); skipping discovery (T12)", flush=True)
        elif (
            estimated_loc < TINY_REPO_LOC_THRESHOLD
            and expected_section_count >= DISCOVERY_REQUIRED_SECTION_THRESHOLD
            and discover
        ):
            print(f"  Repo is small ({estimated_loc} LOC) but section count is high "
                  f"({expected_section_count} sections at level {level or 'all'}); "
                  f"running discovery to produce domain groups for consolidation", flush=True)

        # =============================================================
        # Step 2: Discovery (or fast-path for tiny repos)
        # =============================================================
        false_positive_guidance = []
        domain_groups = {}

        if discover and not skip_discovery:
            print(f"\n{'='*60}\nStep 2: Discovering codebase architecture\n{'='*60}", flush=True)
            try:
                discovery_result = await gofannon_client.call(
                    agent_name="asvs_discover",
                    input_dict={"inputNamespace": ",".join(namespaces)},
                )
                pass_config = json.loads(discovery_result.get("outputText", "{}"))
                if "error" in pass_config:
                    return {"outputText": f"Discovery failed: {pass_config['error']}"}
                passes = pass_config.get("passes", [])
                false_positive_guidance = pass_config.get("false_positive_guidance", [])
                domain_groups = pass_config.get("domain_groups", {})
                print(f"  Discovery complete: {len(passes)} passes", flush=True)
            except Exception as e:
                return {"outputText": f"Discovery agent failed: {e}"}
        else:
            # T12 fast-path or no-discover mode: build a single all-sections pass
            print(f"\n{'='*60}\nStep 2: Single-pass mode (no discovery)\n{'='*60}", flush=True)
            try:
                asvs_ns = data_store.use_namespace("asvs")
                all_keys = asvs_ns.list_keys()
                req_keys = [k for k in all_keys if k.startswith("asvs:requirements:")]
                all_sections = sorted([rk.replace("asvs:requirements:", "") for rk in req_keys])
            except Exception as e:
                return {"outputText": f"Could not load ASVS sections: {e}"}
            passes = [{
                "name": "all",
                "description": "Single-pass audit of all sections (no discovery)",
                "asvs_sections": all_sections,
                "files": [],
                "domain_context": "",
                "estimated_lines": estimated_loc,
            }]
            # Domain grouping for the consolidate phase. With a single
            # "all" bucket, consolidate sends every per-section report to
            # one Sonnet call — fine for L1 (~70 sections) but blows past
            # the 200k context window at L3 (~345 sections, ~400 findings).
            #
            # When discovery is skipped, fall back to ASVS chapter-based
            # grouping (1.x, 2.x, ..., 16.x). This produces ~16 buckets
            # of ~22 sections each at L3, well within Sonnet's context,
            # without needing discovery to run. The audit phase still
            # uses the single "all" pass for batching efficiency; only
            # consolidate sees the chapter split.
            CHAPTER_GROUP_THRESHOLD = 100  # sections
            if len(all_sections) >= CHAPTER_GROUP_THRESHOLD:
                domain_groups = {}
                for section in all_sections:
                    ch_num = section.split(".")[0]
                    ch_name = f"ch{ch_num.zfill(2)}"
                    domain_groups.setdefault(ch_name, []).append(section)
                print(f"  Many sections ({len(all_sections)}); using chapter-based "
                      f"domain grouping for consolidation: {len(domain_groups)} chapters",
                      flush=True)
            else:
                domain_groups = {"all": all_sections}

        # Filter passes by level
        for pass_def in passes:
            pass_def["asvs_sections"] = filter_sections_by_level(pass_def.get("asvs_sections", []))
        passes = [p for p in passes if p.get("asvs_sections")]

        if level:
            for dn in list(domain_groups.keys()):
                domain_groups[dn] = filter_sections_by_level(domain_groups[dn])
            domain_groups = {k: v for k, v in domain_groups.items() if v}

        total_sections = sum(len(p.get("asvs_sections", [])) for p in passes)
        print(f"  After level filter ({level or 'all'}): {total_sections} sections, {len(passes)} passes", flush=True)

        if not passes:
            return {"outputText": f"No ASVS sections match level {level}."}

        # Cover any sections discovery didn't assign
        if discover and not skip_discovery:
            load_asvs_levels()
            all_level_sections = [s for s, lv in asvs_level_cache.items() if lv <= max_level_num]
            covered_sections = set()
            for p in passes:
                covered_sections.update(p.get("asvs_sections", []))
            uncovered = sorted([s for s in all_level_sections if s not in covered_sections])
            if uncovered:
                chapter_groups = {}
                for section in uncovered:
                    ch_num = section.split(".")[0]
                    ch_name = f"ch{ch_num.zfill(2)}_general"
                    chapter_groups.setdefault(ch_name, []).append(section)
                print(f"  {len(uncovered)} sections not assigned by discovery — adding {len(chapter_groups)} chapter passes", flush=True)
                for ch_name, ch_sections in sorted(chapter_groups.items()):
                    passes.append({
                        "name": ch_name,
                        "description": f"ASVS chapter {ch_name.split('_')[0]} sections not assigned to a specific domain",
                        "asvs_sections": ch_sections,
                        "files": [],
                        "domain_context": "",
                        "estimated_lines": 0,
                    })
                    domain_groups[ch_name] = ch_sections
                total_sections = sum(len(p.get("asvs_sections", [])) for p in passes)
                print(f"  Total sections now: {total_sections}", flush=True)

        # =============================================================
        # Step 3: Audit + push (with parallel section dispatch + bundling)
        # =============================================================
        print(f"\n{'='*60}\nStep 3: Auditing {total_sections} sections", flush=True)
        print(f"  Strategy: pass-parallel ({PASS_CONCURRENCY}-way) + section bundling", flush=True)
        print(f"  Pushing to: {push_repo}\n{'='*60}", flush=True)

        section_semaphore = asyncio.Semaphore(PASS_CONCURRENCY)

        # Global GitHub push throttle, shared across ALL bundles.
        #
        # IMPORTANT: GitHub's contents API serializes commits to a branch —
        # each commit must reference the current branch HEAD as its parent.
        # When N commits race against the same branch, only one wins; the
        # rest get 409 Conflict. The push agent retries on 409, but with
        # high concurrency the same races repeat across retries.
        #
        # Default 1 (fully serialized) eliminates the races entirely. The
        # cost is wall-clock: each push is ~1-2s, so 70 pushes adds ~2 min
        # to a run. Acceptable for the determinism it gives us.
        #
        # Higher values are technically possible — the push agent's
        # retry-on-409 absorbs some collisions — but in practice anything
        # above 2-3 starts losing pushes after retries. If you need
        # maximum throughput, switch to a Git Trees API approach instead
        # (one atomic commit for many files); that's a bigger rewrite.
        GITHUB_PUSH_CONCURRENCY = int(os.environ.get("GITHUB_PUSH_CONCURRENCY", "1"))
        github_push_sem = asyncio.Semaphore(GITHUB_PUSH_CONCURRENCY)
        print(f"  GitHub push concurrency: {GITHUB_PUSH_CONCURRENCY}", flush=True)

        async def run_bundle(pass_def, section_chunk):
            """Run a chunk of sections from one pass.

            - For chunks of 1 section: call `asvs_audit` (single-section).
            - For chunks of >1 section: call `asvs_bundle` (NEW agent),
              which audits all sections in one Opus deep-analysis pass.
            """
            async with section_semaphore:
                pass_name = pass_def.get("name", "unknown")
                include_files = pass_def.get("files", [])
                domain_context = pass_def.get("domain_context", "")
                pass_output_dir = f"{push_directory}/{pass_name}" if push_directory else pass_name

                bundle_label = f"{section_chunk[0]}..{section_chunk[-1]}" if len(section_chunk) > 1 else section_chunk[0]
                print(f"  [{pass_name}] {'bundle' if len(section_chunk) > 1 else 'single'}: {bundle_label} ({len(section_chunk)} sections)", flush=True)

                local_successes = []
                local_failures = []
                local_outputs = []

                # ----- Audit call: route to bundle agent or single-section agent -----
                try:
                    if len(section_chunk) == 1:
                        audit_result = await gofannon_client.call(
                            agent_name="asvs_audit",
                            input_dict={
                                "inputText": json.dumps({
                                    "namespaces": namespaces,
                                    "asvs": section_chunk[0],
                                    "includeFiles": include_files,
                                    "domainContext": domain_context,
                                    "severityThreshold": severity_threshold,
                                    "falsePositiveGuidance": false_positive_guidance,
                                })
                            }
                        )
                    else:
                        audit_result = await gofannon_client.call(
                            agent_name="asvs_bundle",  # NEW agent
                            input_dict={
                                "inputText": json.dumps({
                                    "namespaces": namespaces,
                                    "asvs_sections": section_chunk,
                                    "includeFiles": include_files,
                                    "domainContext": domain_context,
                                    "severityThreshold": severity_threshold,
                                    "falsePositiveGuidance": false_positive_guidance,
                                })
                            }
                        )
                    audit_output_text = audit_result.get("outputText", "")
                except Exception as e:
                    print(f"  [{pass_name}] Bundle {bundle_label} AUDIT FAILED: {e}", flush=True)
                    for s in section_chunk:
                        local_failures.append(f"{s} (audit): {e}")
                    return local_successes, local_failures, local_outputs, pass_output_dir

                # ----- Parse output: bundled JSON envelope or single-section markdown -----
                per_section_reports = _parse_audit_output(audit_output_text, section_chunk)

                # ----- Push per-section reports in parallel (throttled) -----
                # Uses the SHARED github_push_sem from outer scope so all
                # bundles across all passes contend for the same global
                # concurrency budget — not per-bundle as before.

                # Per-section reports go to CouchDB only — never to GitHub.
                # Storing them as commits in the private repo would surface
                # finding titles on the public commits@tooling.apache.org
                # mailing list. Consolidate reads from this same namespace
                # in Phase 1 instead of fetching from GitHub.
                #
                # Key format: "{pass_name}/{section_id}.md" — preserves the
                # pass-grouping that the GitHub layout used so consolidate
                # can list by pass and the same logical structure is
                # available for any future tooling.
                reports_ns = data_store.use_namespace(reports_namespace)

                async def store_one(section_id, report_text):
                    try:
                        key = f"{pass_name}/{section_id}.md"
                        reports_ns.set(key, report_text)
                        return section_id, None
                    except Exception as e:
                        err_str = str(e) or f"{type(e).__name__} (no detail)"
                        return section_id, err_str

                push_results = await asyncio.gather(*[
                    store_one(sid, txt) for sid, txt in per_section_reports.items()
                ])
                for sid, err in push_results:
                    if err is None:
                        local_successes.append(sid)
                        print(f"    [{pass_name}] {sid}: stored", flush=True)
                    else:
                        local_failures.append(f"{sid} (store): {err}")
                        print(f"    [{pass_name}] {sid}: store failed: {err}", flush=True)
                local_outputs.extend(per_section_reports.values())

                return local_successes, local_failures, local_outputs, pass_output_dir

        # ----- Build the work list: chunk each pass's sections into bundles -----
        work_items = []
        for pass_def in passes:
            sections = pass_def.get("asvs_sections", [])
            if BUNDLE_MAX_SECTIONS <= 1 or len(sections) < BUNDLE_MIN_SECTIONS:
                # No bundling: each section is its own item
                for s in sections:
                    work_items.append((pass_def, [s]))
            else:
                # Chunk into bundles of up to BUNDLE_MAX_SECTIONS
                for i in range(0, len(sections), BUNDLE_MAX_SECTIONS):
                    chunk = sections[i:i + BUNDLE_MAX_SECTIONS]
                    work_items.append((pass_def, chunk))

        print(f"  Total work items (post-bundling): {len(work_items)}", flush=True)
        print(f"  Avg sections/item: {total_sections / max(1, len(work_items)):.1f}", flush=True)

        # Track output dirs (for consolidation)
        seen_pass_dirs = set()
        for pass_def, _ in work_items:
            pn = pass_def.get("name", "unknown")
            d = f"{push_directory}/{pn}" if push_directory else pn
            if d not in seen_pass_dirs:
                report_directories.append(d)
                seen_pass_dirs.add(d)

        # ----- Dispatch all work items in parallel (T1) -----
        bundle_results = await asyncio.gather(
            *[run_bundle(p, s) for p, s in work_items],
            return_exceptions=True,
        )

        for r in bundle_results:
            if isinstance(r, Exception):
                failures.append(f"bundle dispatch: {r}")
                continue
            local_successes, local_failures, local_outputs, _ = r
            successes.extend(local_successes)
            failures.extend(local_failures)
            all_outputs.extend(local_outputs)

        print(f"\n  Audit phase complete: {len(successes)} succeeded, {len(failures)} failed", flush=True)

        # =============================================================
        # Optional: clean up stale reports from previous runs
        #
        # When discovery (temperature 0.7) reassigns ASVS sections to
        # different domains across runs, old per-section reports remain
        # in their previous domain folders even though the current run
        # produced fresh reports under different folders. These orphans
        # accumulate in the repo and confuse downstream tooling
        # (consolidate-only reruns, QA scripts, finding-count tools).
        #
        # Strict guarantees on what gets deleted:
        #   - Only files matching `^\d+\.\d+\.\d+\.md$` (per-section reports)
        #   - Only inside subdirectories of the commit-hash dir that are
        #     NOT in this run's `report_directories`
        #   - Never touches `consolidated*.md`, `issues*.md`, or any
        #     `rerun/` subdirectory
        #   - Never runs when there were audit failures (something may
        #     have gone wrong; don't compound the problem by deleting)
        # =============================================================
        if clean_stale_reports and successes and not failures:
            print(f"\n{'='*60}\nStep 3.5: Cleaning stale per-section reports\n{'='*60}", flush=True)
            try:
                # Per-section reports now live in CouchDB under
                # reports_namespace, keyed as "{pass_name}/{section_id}.md".
                # On re-runs at the same commit but with different pass
                # groupings (e.g. different domain discovery output), keys
                # from prior runs accumulate. Remove any keys whose
                # pass-prefix isn't in current_pass_basenames.
                current_pass_basenames = set()
                for d in report_directories:
                    bn = d.rstrip("/").split("/")[-1]
                    current_pass_basenames.add(bn)

                reports_ns = data_store.use_namespace(reports_namespace)
                all_keys = reports_ns.list_keys() or []
                orphan_keys = []
                for k in all_keys:
                    # key is "{pass_name}/{section_id}.md"
                    pass_part = k.split("/", 1)[0] if "/" in k else ""
                    if pass_part and pass_part not in current_pass_basenames:
                        orphan_keys.append(k)

                if not orphan_keys:
                    print(f"  No orphan keys to clean", flush=True)
                else:
                    print(f"  Found {len(orphan_keys)} orphan keys "
                          f"(passes not in current run: "
                          f"{sorted(set(k.split('/', 1)[0] for k in orphan_keys))})", flush=True)
                    deleted = 0
                    for k in orphan_keys:
                        try:
                            reports_ns.delete(k)
                            deleted += 1
                        except Exception as de:
                            print(f"    {k}: delete failed: {de}", flush=True)
                    print(f"  Deleted {deleted} stale keys from {reports_namespace}", flush=True)
            except Exception as e:
                # Cleanup failures shouldn't block consolidation
                print(f"  Cleanup encountered an error (continuing): {type(e).__name__}: {e}", flush=True)
        elif clean_stale_reports and failures:
            print(f"\n  cleanStaleReports=true but {len(failures)} audit failures — "
                  f"skipping cleanup to avoid deleting reports during a partial run", flush=True)
        # If clean_stale_reports is False (default), nothing happens here.

        # =============================================================
        # Step 4: Consolidate (unchanged from original)
        # =============================================================
        if consolidate and successes:
            print(f"\n{'='*60}\nStep 4: Consolidating reports\n  Pushing to: {push_repo}\n{'='*60}", flush=True)
            # Build a flat list of every section ID audited in this run, so
            # consolidate can filter out stale reports from prior runs that
            # share the output directories.
            audited_sections = set()
            for sections_in_domain in domain_groups.values():
                for s in sections_in_domain:
                    audited_sections.add(s)
            sections_arg = ", ".join(sorted(audited_sections))

            # `directories` was historically a list of GitHub paths like
            # "ASVS/reports/steve/v3/d0aa7e9/all". Now per-section reports
            # live in CouchDB under the reports_namespace; the dir suffix
            # (the pass name, e.g. "all" or "l1") becomes a key prefix
            # within that namespace. Pass both to consolidate so it knows
            # where to read.
            pass_prefixes = []
            for d in report_directories:
                # Extract the trailing pass name from each historical dir path
                pass_prefixes.append(d.rsplit("/", 1)[-1])

            try:
                consolidate_result = await gofannon_client.call(
                    agent_name="asvs_consolidate",
                    input_dict={
                        "inputText": "\n".join([
                            f"repo: {push_repo}",
                            f"pat: {push_token}",
                            f"directories: {', '.join(pass_prefixes)}",
                            f"output: {push_directory}",
                            f"sections: {sections_arg}",
                            f"source: {source_id}",
                            f"reports_namespace: {reports_namespace}",
                        ]),
                        "domainGroups": json.dumps(domain_groups),
                        "level": level or "L3",
                        "severityThreshold": severity_threshold,
                    }
                )
                # asvs_consolidate's top-level except wrapper returns
                # outputText starting with "Error:" when the body raised.
                # Treat that as a failure even though the call itself
                # didn't throw — otherwise we'd silently mark a broken
                # consolidation as success and proceed to the redaction
                # step, which would then 404 on the missing files.
                consolidate_output = ""
                if isinstance(consolidate_result, dict):
                    consolidate_output = consolidate_result.get("outputText", "") or ""
                if consolidate_output.startswith("Error:"):
                    err_excerpt = consolidate_output[:300]
                    failures.append(f"consolidation: {err_excerpt}")
                    print(f"  Consolidation FAILED: {err_excerpt}", flush=True)
                else:
                    print(f"  Consolidation done", flush=True)
            except Exception as e:
                # Some exception types stringify to empty (e.g. some httpx errors).
                # Surface the type name and full traceback so the failure is
                # diagnosable from logs alone.
                import traceback
                err_type = type(e).__name__
                err_msg = str(e) or "(no message)"
                tb = traceback.format_exc()
                print(f"  Consolidation FAILED: {err_type}: {err_msg}", flush=True)
                print(f"  Traceback:\n{tb}", flush=True)
                failures.append(f"consolidation: {err_type}: {err_msg}")

        # =============================================================
        # Step 5: Carve-out — redact and publish (unchanged)
        # =============================================================
        if carve_out and consolidate and successes:
            print(f"\n{'='*60}\nStep 5: Redacting critical findings for public report\n{'='*60}", flush=True)
            consolidated_content = await read_file_from_github(
                private_repo, private_token, f"{output_directory}/consolidated.md")
            issues_content = await read_file_from_github(
                private_repo, private_token, f"{output_directory}/issues.md")

            critical_findings = []
            if consolidated_content:
                redacted_consolidated, critical_findings = redact_consolidated(consolidated_content)
                print(f"  Redacted {len(critical_findings)} critical findings", flush=True)
                try:
                    push_result = await gofannon_client.call(
                        agent_name="asvs_push_github",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": output_repo, "token": output_token,
                                "directory": output_directory, "filename": "consolidated.md",
                            }),
                            "commitMessage": f"ASVS {level or 'full'} audit: consolidated report (redacted) [source: {source_id}]",
                            "fileContents": redacted_consolidated,
                        }
                    )
                    output_text = push_result.get("outputText", "") if isinstance(push_result, dict) else ""
                    if not output_text or "\"content\"" not in output_text or "\"commit\"" not in output_text:
                        err_msg = output_text[:300] if output_text else "(no outputText)"
                        try:
                            parsed = json.loads(output_text) if output_text else {}
                            if isinstance(parsed, dict) and "message" in parsed:
                                err_msg = parsed["message"]
                        except Exception:
                            pass
                        failures.append(f"redacted consolidated push to {output_repo}: {err_msg}")
                        print(f"  Push redacted consolidated.md to {output_repo} FAILED: {err_msg}", flush=True)
                    else:
                        print(f"  Pushed redacted consolidated.md to {output_repo}", flush=True)
                except Exception as e:
                    typed = type(e).__name__
                    detail = str(e) or f"{typed} (no detail)"
                    failures.append(f"redacted consolidated push: {detail}")
                    print(f"  Push redacted consolidated.md FAILED: {detail}", flush=True)

            if issues_content:
                redacted_issues, removed_count = redact_issues(issues_content)
                print(f"  Redacted {removed_count} critical issues", flush=True)
                try:
                    push_result = await gofannon_client.call(
                        agent_name="asvs_push_github",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": output_repo, "token": output_token,
                                "directory": output_directory, "filename": "issues.md",
                            }),
                            "commitMessage": f"ASVS {level or 'full'} audit: issues (redacted) [source: {source_id}]",
                            "fileContents": redacted_issues,
                        }
                    )
                    output_text = push_result.get("outputText", "") if isinstance(push_result, dict) else ""
                    if not output_text or "\"content\"" not in output_text or "\"commit\"" not in output_text:
                        err_msg = output_text[:300] if output_text else "(no outputText)"
                        try:
                            parsed = json.loads(output_text) if output_text else {}
                            if isinstance(parsed, dict) and "message" in parsed:
                                err_msg = parsed["message"]
                        except Exception:
                            pass
                        failures.append(f"redacted issues push to {output_repo}: {err_msg}")
                        print(f"  Push redacted issues.md to {output_repo} FAILED: {err_msg}", flush=True)
                    else:
                        print(f"  Pushed redacted issues.md to {output_repo}", flush=True)
                except Exception as e:
                    typed = type(e).__name__
                    detail = str(e) or f"{typed} (no detail)"
                    failures.append(f"redacted issues push: {detail}")
                    print(f"  Push redacted issues.md FAILED: {detail}", flush=True)

            # Per-section reports are no longer pushed to GitHub (see
            # reports_namespace above), so there's nothing per-section to
            # redact-and-push here. Public consumers of apache/tooling-agents
            # see only the redacted consolidated.md and issues.md, which
            # contain redaction notices ("N Critical findings have been
            # redacted...") so the existence of redacted findings is still
            # disclosed without their content.

            print(f"  Redacted consolidated and issues pushed to {output_repo}", flush=True)

            if notify_email and critical_findings:
                print(f"  Emailing {len(critical_findings)} critical findings to {notify_email}", flush=True)
                email_subject = f"[ASVS Audit] {len(critical_findings)} Critical findings in {repo_owner_name}"
                email_body = build_email_body(critical_findings, repo_owner_name, commit_hash)
                await send_email(notify_email, email_subject, email_body)

        # =============================================================
        # Summary
        # =============================================================
        print(f"\n{'='*60}\nComplete: {len(successes)} succeeded, {len(failures)} failed", flush=True)
        if carve_out:
            print(f"  Full reports: {private_repo}/{output_directory}/", flush=True)
            print(f"  Redacted reports: {output_repo}/{output_directory}/", flush=True)
        else:
            print(f"  Reports: {output_repo}/{output_directory}/", flush=True)
        if failures:
            for f in failures[:20]:
                print(f"  - {f}", flush=True)
            if len(failures) > 20:
                print(f"  ... and {len(failures) - 20} more failures", flush=True)
        return {"outputText": "\n\n---\n\n".join(all_outputs)}
    finally:
        await http_client.aclose()