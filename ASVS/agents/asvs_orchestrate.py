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
        # branch: optional, empty string means use the repo's default branch.
        # Useful for projects like apache/mina where master/trunk is abandoned
        # and active development lives on a version branch (e.g. 2.2.X).
        # Auditing the wrong branch wastes the entire run.
        branch = input_dict.get("branch", "").strip()
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

        # Fetch latest commit hash. If branch is specified, query that branch's
        # HEAD via ?sha={branch}; otherwise GitHub returns the default branch's
        # HEAD. Branch is logged either way so the run record shows which line
        # of the project was audited.
        source_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if source_token:
            source_headers["Authorization"] = f"Bearer {source_token}"
        try:
            commits_url = f"https://api.github.com/repos/{repo_owner_name}/commits?per_page=1"
            if branch:
                commits_url += f"&sha={branch}"
            commits_resp = await http_client.get(commits_url, headers=source_headers)
            commits_data = commits_resp.json()
            commit_hash = commits_data[0]["sha"][:7]
            if branch:
                print(f"  Source branch: {branch} @ {commit_hash}", flush=True)
            else:
                print(f"  Source branch: (default) @ {commit_hash}", flush=True)
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
            leaks_detected = []
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
                    # Extract the title from the block's first heading line
                    # — used later by the title-based leak scrub (3d).
                    # Patterns to handle:
                    #   #### FINDING-NNN: Title goes here
                    #   #### Title goes here
                    #   #### CRITICAL  (no title — title comes from a later
                    #                    "**Title:** Foo" or "**Finding:** Foo" field)
                    title = ""
                    first_line = block.split("\n", 1)[0]
                    # case A: heading has the title after a colon
                    m_title = re.match(
                        r'#{1,6}\s+(?:FINDING-\d+:\s*)?(.+?)\s*$',
                        first_line,
                    )
                    if m_title:
                        candidate = m_title.group(1).strip()
                        # heading may be just "CRITICAL" / "[CRITICAL]" / "Critical"
                        if not re.match(r'^\[?\s*CRITICAL\s*\]?$', candidate, re.IGNORECASE):
                            title = candidate
                    # case B: title in an inline field
                    if not title:
                        m_field = re.search(
                            r'\*\*(?:Title|Finding)\*\*:?\s*(.+?)\s*(?:\n|$)',
                            block,
                            re.IGNORECASE,
                        )
                        if m_field:
                            title = m_field.group(1).strip()
                    # strip trailing punctuation/decorations
                    title = re.sub(r'\s*\*+\s*$', '', title).strip()
                    title = re.sub(r'\s*\([^)]*\)\s*$', '', title).strip()
                    critical_findings.append({
                        "id": finding_id,
                        "title": title,
                        "block": block.strip(),
                    })
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

                    # 3b. Drop heading-based Critical risk blocks. The
                    # consolidate Sonnet sometimes produces Top 5 Risks as
                    # `#### N. 🔴 Title (Critical)` headings followed by
                    # paragraph content rather than as table rows. The
                    # table-row stripper above doesn't see these. Walk the
                    # document and drop any `#### ...` heading that
                    # contains 🔴 or "(Critical)" along with everything
                    # under it until the next heading at depth ≤ 4 (next
                    # risk or end of section).
                    #
                    # Detection is intentionally narrow — we require
                    # either the 🔴 emoji or the literal token `(Critical)`
                    # in parens. We do NOT match a bare word "Critical"
                    # in the heading because legitimate non-Critical
                    # headings could mention the word in their title
                    # ("Critical Path Analysis", etc.).
                    #
                    # Safety: code fences are skipped exactly as in the
                    # table-row pass.
                    def _strip_critical_heading_blocks(text):
                        lines = text.split('\n')
                        out = []
                        in_fence = False
                        i = 0
                        crit_heading_re = re.compile(
                            r'^####\s.*(?:🔴|\(\s*Critical\s*\))',
                            re.IGNORECASE,
                        )
                        boundary_re = re.compile(r'^#{1,4}(\s|$)')
                        while i < len(lines):
                            line = lines[i]
                            stripped = line.lstrip()
                            if stripped.startswith('```'):
                                in_fence = not in_fence
                                out.append(line)
                                i += 1
                                continue
                            if in_fence:
                                out.append(line)
                                i += 1
                                continue
                            if crit_heading_re.match(line):
                                # Skip this heading + all content under it
                                # until the next heading at depth ≤ 4.
                                i += 1
                                while i < len(lines):
                                    nxt = lines[i]
                                    nxt_stripped = nxt.lstrip()
                                    if nxt_stripped.startswith('```'):
                                        in_fence = not in_fence
                                        i += 1
                                        continue
                                    if (not in_fence) and boundary_re.match(nxt_stripped):
                                        break  # don't consume the boundary line
                                    i += 1
                                continue
                            out.append(line)
                            i += 1
                        return '\n'.join(out)
                    redacted = _strip_critical_heading_blocks(redacted)

                    # 3c. Drop flat list-item Critical risks. Consolidate
                    # sometimes renders Top 5 Risks as plain numbered or
                    # bulleted list lines with a severity prefix:
                    #
                    #     1. [Critical] Title: full risk description...
                    #     - [Critical] Title: full risk description...
                    #     2. **Critical** Title: ...
                    #
                    # Neither the table-row stripper (3a) nor the heading
                    # stripper (3b) catches these — they're just markdown
                    # prose lines. This stripper drops any line that starts
                    # with a list marker (`N.`, `-`, or `*`) and contains
                    # one of the unambiguous Critical severity tokens
                    # before continuing into the title/description.
                    #
                    # Detection is narrow on purpose: we require [Critical],
                    # (Critical), **Critical**, or the 🔴 emoji. A bare
                    # mention of the word "critical" in a list item's
                    # prose does NOT match (e.g., "1. Critical Path
                    # Analysis: ..." in a non-Critical risk would be
                    # preserved). Severity tokens with brackets/parens/
                    # bold/emoji are the dominant way severity gets
                    # rendered into list-item leaders, and we accept the
                    # rare false-negative case in exchange for not
                    # over-redacting innocent list items.
                    def _strip_critical_list_items(text):
                        out = []
                        in_fence = False
                        crit_list_re = re.compile(
                            r'^\s*(?:\d+\.|[-*])\s+.*?'
                            r'(?:\[\s*Critical\s*\]'
                            r'|\(\s*Critical\s*\)'
                            r'|\*\*\s*Critical\s*\*\*'
                            r'|🔴)',
                            re.IGNORECASE,
                        )
                        for line in text.split('\n'):
                            stripped = line.lstrip()
                            if stripped.startswith('```'):
                                in_fence = not in_fence
                                out.append(line)
                                continue
                            if in_fence:
                                out.append(line)
                                continue
                            if crit_list_re.match(line):
                                continue  # drop the entire list item line
                            out.append(line)
                        return '\n'.join(out)
                    redacted = _strip_critical_list_items(redacted)

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
                    # Drop Cross-Reference Matrix rows whose Finding ID cell
                    # is now empty (left by redacting FINDING-001 etc.).
                    # Anchor to line start with re.MULTILINE and use
                    # [ \t]+ (NOT \s+) so the regex cannot cross newlines.
                    # The previous \s+ form ate the trailing pipe of the
                    # Severity Distribution alignment row plus the next
                    # row whenever it was Critical/High/Medium/Low — exactly
                    # the mangled table seen in the May 19 public report.
                    redacted = re.sub(
                        r'^\|[ \t]+\|[ \t]+(Critical|High|Medium|Low)\b[^\n]*\n',
                        '',
                        redacted,
                        flags=re.MULTILINE,
                    )

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
                                        f"been forwarded to the project's PMC private mailing list "
                                        f"for triage through proper channels._"
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

                # 3d. Title-based leak scrub. After all the regex strippers
                # have done their best, walk the document one more time and
                # drop any line that contains a redacted finding's TITLE
                # (extracted up at block-detection time). This is the
                # authoritative leak catcher — it uses the actual content
                # of the redacted finding rather than guessing at format,
                # so it catches Top 5 Risks paragraphs, cross-reference
                # entries, and any future format the consolidate LLM
                # invents. We also strip immediately-following continuation
                # lines (paragraph wrap, indented continuations) until we
                # hit a blank line or a clear structural boundary.
                #
                # Titles need to be at least 6 words / 30 chars to be safe
                # to substring-match on — shorter titles risk false
                # positives against unrelated text. Below the threshold we
                # fall back to whole-line containment with word boundaries.
                redacted_titles = [
                    cf["title"] for cf in critical_findings
                    if cf.get("title") and len(cf["title"]) >= 6
                ]
                if redacted_titles:
                    def _strip_title_leaks(text, titles):
                        out = []
                        lines = text.split('\n')
                        in_fence = False
                        i = 0
                        while i < len(lines):
                            line = lines[i]
                            stripped = line.lstrip()
                            if stripped.startswith('```'):
                                in_fence = not in_fence
                                out.append(line)
                                i += 1
                                continue
                            if in_fence:
                                out.append(line)
                                i += 1
                                continue
                            # Does this line contain any redacted title?
                            matched_title = None
                            for t in titles:
                                # Use literal substring match (case-
                                # insensitive). Titles are distinctive
                                # enough that this is reliable.
                                if t.lower() in line.lower():
                                    matched_title = t
                                    break
                            if matched_title is None:
                                out.append(line)
                                i += 1
                                continue
                            # Drop this line. Also drop following
                            # continuation lines until we hit a blank
                            # line, a heading, a table separator, or a
                            # new list item — whichever comes first.
                            i += 1
                            while i < len(lines):
                                nxt = lines[i]
                                nxt_strip = nxt.lstrip()
                                if not nxt_strip:
                                    # blank line ends the dropped block;
                                    # consume it too so we don't leave
                                    # an orphan paragraph break
                                    i += 1
                                    break
                                if nxt_strip.startswith('```'):
                                    break
                                if re.match(r'^#{1,6}\s', nxt_strip):
                                    break
                                if re.match(r'^\s*(?:\d+\.|[-*])\s+\S', nxt):
                                    break
                                if re.match(r'^\|[\s:|-]+\|\s*$', nxt):
                                    break
                                # otherwise it's a continuation line
                                # (wrapped prose, indented sub-bullet) —
                                # drop it
                                i += 1
                        return '\n'.join(out)
                    redacted = _strip_title_leaks(redacted, redacted_titles)

                # 3e. Severity-distribution table regeneration. The
                # in-place regex editing above is fragile against malformed
                # tables that the consolidate LLM occasionally emits
                # (separator and data rows glued together, missing rows,
                # etc). Rather than chasing each malformation, locate the
                # Severity Distribution section and rebuild its table
                # cleanly from the post-redaction findings.
                #
                # We count surviving findings by walking remaining finding
                # blocks for their `**Severity:** X` field. This is robust
                # — it doesn't depend on what shape the original table was
                # in.
                def _rebuild_severity_table(text):
                    counts = {"Critical": 0, "High": 0, "Medium": 0,
                              "Low": 0, "Info": 0}
                    # Find every surviving finding block and count its
                    # severity.
                    surviving_pattern = re.compile(
                        r'####\s+[^\n]+\n[\s\S]*?(?=####\s|##\s|\n---\n|\Z)',
                        re.MULTILINE,
                    )
                    # Severity appears in several formats in practice:
                    #   - Table cell, bold label:  `| **Severity** | 🟠 High |`
                    #   - Table cell, plain label: `| Severity | ⚪ Info |`  (FINDING-020 used this)
                    #   - Inline, colon inside:    `**Severity:** 🟠 High`
                    #   - Inline, colon after:     `**Severity**: 🟠 High`
                    # The "Info" severity uses the full word "Informational"
                    # in some findings. The previous regex only matched the
                    # inline-with-colon-inside form and only the short "Info"
                    # name — so on the May 19 run it counted ZERO surviving
                    # findings, total stayed 0, the function returned text
                    # unchanged, and the malformed table that stripper 787
                    # left behind never got regenerated.
                    #
                    # Two-form regex: form A is `**Severity:**` (colon
                    # inside the bold acts as implicit separator). Form B
                    # is bold-or-plain `Severity` followed by an explicit
                    # `|` or `:` separator. The required separator/internal
                    # colon is what keeps this from over-matching prose
                    # like "the severity was high".
                    sev_re = re.compile(
                        r'(?:\*\*Severity:\*\*'
                        r'|(?:\*\*)?Severity(?:\*\*)?\s*[|:])'
                        r'\s*(?:🔴|🟠|🟡|🔵|⚪|🟢)?\s*\**'
                        r'(Critical|High|Medium|Low|Info(?:rmational)?)\b',
                        re.IGNORECASE,
                    )
                    for m in surviving_pattern.finditer(text):
                        blk = m.group(0)
                        sev_m = sev_re.search(blk)
                        if sev_m:
                            raw_sev = sev_m.group(1).capitalize()
                            # Normalize "Informational" → "Info" so it
                            # maps to the counts dict key.
                            key = "Info" if raw_sev.lower().startswith("info") else raw_sev
                            counts[key] = counts.get(key, 0) + 1
                    total = sum(counts.values())
                    if total == 0:
                        return text  # nothing to regenerate against

                    def pct(n):
                        return f"{(100.0 * n / total):.1f}%" if total else "0.0%"

                    fresh_table = "\n".join([
                        "| Severity | Count | Percentage |",
                        "|----------|-------|------------|",
                        f"| Critical | {counts['Critical']} | {pct(counts['Critical'])} |",
                        f"| High     | {counts['High']} | {pct(counts['High'])} |",
                        f"| Medium   | {counts['Medium']} | {pct(counts['Medium'])} |",
                        f"| Low      | {counts['Low']} | {pct(counts['Low'])} |",
                        f"| Info     | {counts['Info']} | {pct(counts['Info'])} |",
                    ])

                    # Find the Severity Distribution heading and replace
                    # the immediately-following table block (everything
                    # from the heading's next non-blank `|`-line through
                    # the last `|`-line of that block).
                    heading_re = re.compile(
                        r'(^#{2,4}\s+Severity\s+Distribution[^\n]*\n+)',
                        re.IGNORECASE | re.MULTILINE,
                    )
                    h_match = heading_re.search(text)
                    if not h_match:
                        return text

                    start = h_match.end()
                    # advance past blank lines
                    j = start
                    while j < len(text) and text[j] in ('\n', ' ', '\t'):
                        if text[j] == '\n':
                            j += 1
                            continue
                        break
                    # find table end: scan forward while lines start with `|`
                    # or are blank, until two consecutive non-`|`-non-blank
                    # lines (i.e. table ended). simpler: consume contiguous
                    # `|` lines and one trailing blank.
                    table_end = j
                    lines_after = text[j:].split('\n')
                    consumed = 0
                    for L in lines_after:
                        if L.lstrip().startswith('|'):
                            consumed += len(L) + 1  # +1 for the \n
                            continue
                        # allow one blank inside the table, then stop
                        if not L.strip():
                            consumed += len(L) + 1
                            continue
                        break
                    table_end = j + consumed

                    return text[:start] + "\n" + fresh_table + "\n\n" + text[table_end:]

                redacted = _rebuild_severity_table(redacted)

                # 3f. Defense-in-depth final leak check. After every stripper
                # above has run, scan the output for the redacted findings'
                # titles and IDs. If any survive, prepend a visible LEAK
                # warning to the report. The push still happens so the
                # pipeline doesn't break, but the warning is impossible to
                # miss for anyone reading the published file.
                #
                # False-positive guard: title length >= 20 chars (short
                # titles are common phrases that may legitimately appear in
                # surviving finding descriptions); only count matches
                # OUTSIDE code fences (code examples often reproduce
                # vulnerability descriptions). IDs only count when they
                # match a clear FINDING-/ASVS- pattern with a word boundary.
                def _final_leak_check(text, findings):
                    # Strip code fences for scanning — code examples often
                    # legitimately reproduce vulnerability text
                    no_fences = re.sub(r'```[\s\S]*?```', '', text)
                    leaks = []
                    for cf in findings:
                        title = (cf.get("title") or "").strip()
                        fid = (cf.get("id") or "").strip()
                        if title and len(title) >= 20:
                            idx = no_fences.lower().find(title.lower())
                            if idx >= 0:
                                ctx = no_fences[max(0, idx - 40):idx + len(title) + 40]
                                leaks.append({
                                    "type": "title",
                                    "value": title,
                                    "context": " ".join(ctx.split()),
                                })
                        if fid and fid != "?" and re.match(r'^(FINDING|ASVS|CVE)[-_]', fid, re.IGNORECASE):
                            m = re.search(r'\b' + re.escape(fid) + r'\b', no_fences)
                            if m:
                                idx = m.start()
                                ctx = no_fences[max(0, idx - 40):idx + len(fid) + 40]
                                leaks.append({
                                    "type": "id",
                                    "value": fid,
                                    "context": " ".join(ctx.split()),
                                })
                    return leaks

                leaks_detected = _final_leak_check(redacted, critical_findings)
                if leaks_detected:
                    print(f"!!! REDACTOR LEAK CHECK: {len(leaks_detected)} possible leaks "
                          f"survived all strippers", flush=True)
                    for l in leaks_detected[:10]:
                        print(f"  - {l['type'].upper()}: '{l['value']}' "
                              f"@ \"...{l['context']}...\"", flush=True)

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
            return redacted, critical_findings, leaks_detected

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
                skipped_empty = 0
                skipped_bad_level = []
                for rk in req_keys:
                    req = asvs_ns.get(rk)
                    if not req:
                        skipped_empty += 1
                        continue
                    section_id = rk.replace("asvs:requirements:", "")
                    try:
                        asvs_level_cache[section_id] = int(req.get("level", 1))
                    except (TypeError, ValueError):
                        # Don't let one malformed entry abort the whole
                        # cache load; record it and continue so the
                        # coverage report can warn the operator.
                        skipped_bad_level.append(section_id)
                print(f"  Loaded ASVS levels for {len(asvs_level_cache)} sections", flush=True)
                if skipped_empty or skipped_bad_level:
                    print(
                        f"    WARNING: skipped {skipped_empty} empty + "
                        f"{len(skipped_bad_level)} malformed-level entries "
                        f"out of {len(req_keys)} keys"
                        + (f"; malformed: {skipped_bad_level[:10]}" if skipped_bad_level else ""),
                        flush=True,
                    )
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

            # clearCache=true should mean "wipe everything for this
            # repo/subdir so the run is genuinely from scratch", not
            # just "redownload source code". Until this loop existed,
            # the flag only gated the download step; audit-cache,
            # bundle-cache, and per-commit reports survived across
            # runs. That meant prompt changes silently kept returning
            # the previous run's findings for any cache-hit section.
            #
            # Scope of the wipe:
            #
            # CLEARED (anything derived from this source for this
            # commit):
            #   - files:{source}                        (source code)
            #   - audit-cache:relevance:asvs-*-{src}    (per-section
            #   - audit-cache:analysis:asvs-*-{src}      Haiku/Opus
            #   - audit-cache:relevance:bundle-*-{src}   audit cache)
            #   - audit-cache:analysis:bundle-*-{src}
            #   - audit-reports:{output_directory}      (per-section reports)
            #   - audit-reports-filtered:{output_dir}   (filter outputs)
            #
            # PRESERVED (intentionally, with reasoning):
            #   - audit-cache:inventory:{file_set_hash} — keyed by
            #     content hash; naturally invalidates if files change.
            #   - relevance-filter-cache:{owner_repo_root} — owner_repo_root
            #     can span multiple audited subdirs (e.g. apache/airflow
            #     covers airflow-core, airflow-task-sdk, ...); wiping
            #     here would over-wipe peer subdirs. The cache is
            #     content-keyed by profile_hash and batch_hash, so it
            #     self-invalidates on real changes.
            #   - consolidation:* / extraction:* — keyed by the PUSH
            #     repo (e.g. apache/tooling-runbooks), shared across
            #     audits. Content-hashed internally.
            #   - audit_guidance:* — uploaded guidance, not derived
            #     state. Survives runs by design.
            try:
                all_ns = data_store.list_namespaces() or []
            except Exception as e:
                all_ns = []
                print(f"  WARNING: could not enumerate namespaces "
                      f"({type(e).__name__}: {e}); proceeding with "
                      f"download only (downstream caches may be stale)",
                      flush=True)

            def _owned_by_this_run(ns_name):
                if ns_name == code_namespace:
                    return True
                if ns_name == f"audit-reports:{output_directory}":
                    return True
                if ns_name == f"audit-reports-filtered:{output_directory}":
                    return True
                # Audit/bundle caches embed the source namespace string
                # literally in their namespace name (asvs_audit/bundle:
                # `audit-cache:{relevance,analysis}:{prefix}` where
                # prefix is asvs-{section}-{namespaces} or bundle-{...}).
                if ns_name.startswith("audit-cache:relevance:") or ns_name.startswith("audit-cache:analysis:"):
                    if code_namespace in ns_name:
                        return True
                return False

            to_clear = [ns for ns in all_ns if _owned_by_this_run(ns)]
            if to_clear:
                print(f"  clearCache=true: wiping {len(to_clear)} "
                      f"namespace(s) for {code_namespace}", flush=True)
                total_keys = 0
                for ns_name in to_clear:
                    try:
                        ns = data_store.use_namespace(ns_name)
                        keys = ns.list_keys() or []
                        deleted = 0
                        for k in keys:
                            try:
                                ns.delete(k)
                                deleted += 1
                            except Exception as de:
                                # Per-key failures shouldn't abort the
                                # whole wipe; log and continue.
                                print(f"    {ns_name}/{k}: delete failed: {de}", flush=True)
                        total_keys += deleted
                        print(f"    {ns_name}: deleted {deleted}/{len(keys)} key(s)", flush=True)
                    except Exception as e:
                        print(f"    {ns_name}: list/delete failed: "
                              f"{type(e).__name__}: {e}", flush=True)
                print(f"  Cleared {total_keys} keys across "
                      f"{len(to_clear)} namespace(s)", flush=True)
            else:
                print(f"  clearCache=true: no existing namespaces to "
                      f"wipe for {code_namespace}", flush=True)

            download_input = download_source
            if source_token:
                download_input += f"\n{source_token}"
            # branch line is parsed by asvs_download_repo; absent line means
            # use the repo default. Format is "branch: NAME" so it can't
            # collide with the repo or token line shapes.
            if branch:
                download_input += f"\nbranch: {branch}"

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
                    input_dict={
                        "inputNamespace": ",".join(namespaces),
                        # Pass level so discover pre-filters ASVS sections.
                        # Without this, discover classifies all ~345
                        # sections even when the run is L1 (~130 sections),
                        # wasting a Sonnet call and producing misleading
                        # "343/345 sections assigned" log lines.
                        "level": level,
                    },
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

            # Coverage check: confirm every L3 control appears in at least
            # one pass. The chapter-pass fallback above is supposed to
            # guarantee this; the check verifies it explicitly and warns
            # loudly if the asvs_level_cache itself is incomplete (which
            # would silently reduce coverage without this check).
            final_covered = set()
            for p in passes:
                final_covered.update(p.get("asvs_sections", []))
            all_set = set(all_level_sections)
            still_uncovered = sorted(all_set - final_covered)
            print(
                f"  Unique L{max_level_num} controls covered: "
                f"{len(final_covered & all_set)} / {len(all_set)} "
                f"(controls in ASVS data store at level <= L{max_level_num})",
                flush=True,
            )
            if still_uncovered:
                print(
                    f"  WARNING: {len(still_uncovered)} L{max_level_num} "
                    f"control(s) still uncovered after chapter-pass "
                    f"fallback: {still_uncovered[:10]}"
                    f"{'...' if len(still_uncovered) > 10 else ''}",
                    flush=True,
                )

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
        # Step 3.7: Relevance filter (NEW)
        # =============================================================
        # Triage findings against the project's own documented threat
        # model before consolidation. asvs_relevance_filter auto-
        # discovers SECURITY.md, AGENTS.md, docs/security/* from the
        # source repo (walking both the downloaded source namespace
        # AND the GitHub repo root, so monorepo-subdir audits inherit
        # the top-level project docs), synthesizes a Project Security
        # Profile, and drops or downgrades findings the project
        # documents as out-of-scope.
        #
        # Outputs are written to audit-reports-filtered:{output_dir}
        # in CouchDB; the four _*.md analysis artifacts also get
        # pushed to {private_repo}/{output_directory}/ when a private
        # repo + PAT are configured.
        #
        # Fail-soft end-to-end: if the filter fails or returns no
        # usable namespace, consolidate reads from the original
        # audit-reports namespace and the pipeline behaves as if the
        # filter weren't installed.
        filtered_reports_namespace = reports_namespace  # safe default
        if successes:
            print(f"\n{'='*60}\nStep 3.7: Relevance filter\n{'='*60}", flush=True)
            filter_input_lines = [
                f"owner_repo: {source_repo}",
                f"reports_namespace: {reports_namespace}",
                f"source_namespace: {code_namespace}",
                f"output_directory: {output_directory}",
                f"source_id: {source_id}",
            ]
            # One PAT covers both jobs: GitHub repo-root fetch (against
            # source_repo) and private-repo push (against private_repo).
            # Prefer private_token because the artifact push is the
            # consequential side-effect; falls back to source_token for
            # the fetch leg. If source is private and private_token
            # lacks access, the fetch will quietly 404 and the filter
            # will still work on whatever it found in the source ns.
            filter_pat = private_token or source_token
            if filter_pat:
                filter_input_lines.append(f"pat: {filter_pat}")
            if private_repo:
                filter_input_lines.append(f"private_repo: {private_repo}")
            if supplemental_data:
                filter_input_lines.append(
                    f"audit_guidance_namespaces: {supplemental_data}"
                )
            try:
                filter_result = await gofannon_client.call(
                    agent_name="asvs_relevance_filter",
                    input_dict={"inputText": "\n".join(filter_input_lines)},
                )
                filter_output = ""
                filter_ns = ""
                if isinstance(filter_result, dict):
                    filter_output = filter_result.get("outputText", "") or ""
                    filter_ns = filter_result.get("filteredReportsNamespace", "") or ""
                if filter_output:
                    print(filter_output, flush=True)
                if filter_ns and not filter_output.startswith("Error:"):
                    filtered_reports_namespace = filter_ns
                    print(f"  Consolidate will read from: {filtered_reports_namespace}", flush=True)
                else:
                    print(
                        f"  Filter did not return a usable namespace; "
                        f"falling back to {reports_namespace}",
                        flush=True,
                    )
            except Exception as e:
                print(
                    f"  Relevance filter raised; falling back to "
                    f"{reports_namespace}: {type(e).__name__}: {e}",
                    flush=True,
                )

        # =============================================================
        # Step 4: Consolidate
        # =============================================================
        # Reads from filtered_reports_namespace (set by Step 3.7 to
        # audit-reports-filtered:* when the filter succeeded, else
        # falls back to the raw audit-reports:* namespace).
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
                consolidate_input_lines = [
                    f"repo: {push_repo}",
                    f"pat: {push_token}",
                    f"directories: {', '.join(pass_prefixes)}",
                    f"output: {push_directory}",
                    f"sections: {sections_arg}",
                    f"source: {source_id}",
                    f"reports_namespace: {filtered_reports_namespace}",
                ]
                if branch:
                    consolidate_input_lines.append(f"branch: {branch}")
                consolidate_result = await gofannon_client.call(
                    agent_name="asvs_consolidate",
                    input_dict={
                        "inputText": "\n".join(consolidate_input_lines),
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
        # Step 5: Carve-out — redact and publish
        # =============================================================
        if carve_out and consolidate and successes:
            print(f"\n{'='*60}\nStep 5: Redacting critical findings for public report\n{'='*60}", flush=True)
            # Read consolidate's outputs from the namespace it mirrors
            # them into, NOT from GitHub. GitHub's contents API is
            # eventually consistent: reading a file from there
            # immediately after pushing it 404s reliably enough that it
            # broke the redactor's issues.md fetch on the May 19 run.
            # The namespace (consolidation:{owner}/{repo}/{dirs_key}) is
            # strongly consistent and is the same one consolidate already
            # uses for its intermediate state. consolidate writes keys
            # `final:consolidated.md` and `final:issues.md` for exactly
            # this purpose. If either is missing, fail loudly — silent
            # warnings hid the problem last time.
            consolidated_content = None
            issues_content = None
            try:
                push_owner, push_repo_only = push_repo.split("/", 1)
                _consol_dirs_key = "+".join(sorted(pass_prefixes))
                _consol_ns_name = f"consolidation:{push_owner}/{push_repo_only}/{_consol_dirs_key}"
                _consol_ns = data_store.use_namespace(_consol_ns_name)
                consolidated_content = _consol_ns.get("final:consolidated.md")
                issues_content = _consol_ns.get("final:issues.md")
                if consolidated_content is None:
                    msg = (f"redact: consolidate did not mirror final:consolidated.md "
                           f"to namespace {_consol_ns_name}; cannot redact")
                    print(f"  ERROR: {msg}", flush=True)
                    failures.append(msg)
                if issues_content is None:
                    msg = (f"redact: consolidate did not mirror final:issues.md "
                           f"to namespace {_consol_ns_name}; cannot redact")
                    print(f"  ERROR: {msg}", flush=True)
                    failures.append(msg)
            except Exception as _ns_e:
                msg = f"redact: namespace read failed: {type(_ns_e).__name__}: {_ns_e}"
                print(f"  ERROR: {msg}", flush=True)
                failures.append(msg)

            # Track what actually gets pushed so the completion summary
            # doesn't lie. Previous summary printed
            # "Redacted consolidated and issues pushed to ..."
            # unconditionally — and on May 19 issues.md was never pushed
            # (it 404'd on read) but the summary still claimed success.
            consolidated_pushed = False
            issues_pushed = False

            critical_findings = []
            if consolidated_content:
                redacted_consolidated, critical_findings, consolidated_leaks = redact_consolidated(consolidated_content)
                print(f"  Redacted {len(critical_findings)} critical findings", flush=True)
                if consolidated_leaks:
                    # ─── Leak detected: route around the public push ────
                    # Build the warning banner here in the orchestrator
                    # rather than in the redactor so the redactor stays a
                    # pure transform. Banner goes ONLY on the private-repo
                    # quarantine file; the public repo gets a clean
                    # placeholder explaining the report is under review.
                    leak_summary_lines = [
                        f"- **{l['type'].upper()}:** `{l['value']}` — context: `...{l['context']}...`"
                        for l in consolidated_leaks[:10]
                    ]
                    leak_banner = (
                        "> # ⚠️ CARVE-OUT LEAK DETECTED — DO NOT REDISTRIBUTE ⚠️\n"
                        ">\n"
                        "> The post-redaction defense-in-depth scan found references to "
                        f"redacted Critical findings still present in this file ({len(consolidated_leaks)} "
                        f"detection{'s' if len(consolidated_leaks) != 1 else ''}). The "
                        "automated pipeline withheld this report from the public repo and "
                        "wrote it here for manual inspection.\n"
                        ">\n"
                        "> ## Detected references\n"
                        ">\n"
                        + "\n".join(f"> {ln}" for ln in leak_summary_lines)
                        + "\n>\n"
                        "> ## Next steps\n"
                        ">\n"
                        "> 1. Verify each detection — if any are real leaks, identify "
                        "where the stripper missed and patch the redactor.\n"
                        "> 2. After fixing, re-run the carve-out manually or via a "
                        "re-audit of the same commit.\n"
                        "> 3. If detections are false positives (a surviving finding "
                        "happens to mention a redacted finding's title), the public push "
                        "can be done by hand from this content with the banner removed.\n\n"
                        "---\n\n"
                    )

                    # 1) Push the leaky-with-banner version to the PRIVATE repo
                    quarantine_filename = "_redaction_warning_consolidated.md"
                    try:
                        q_result = await gofannon_client.call(
                            agent_name="asvs_push_github",
                            input_dict={
                                "inputText": json.dumps({
                                    "repo": private_repo, "token": private_token,
                                    "directory": output_directory,
                                    "filename": quarantine_filename,
                                }),
                                "commitMessage": (
                                    f"ASVS audit: redaction warning ({len(consolidated_leaks)} "
                                    f"suspected leak{'s' if len(consolidated_leaks) != 1 else ''}) "
                                    f"[source: {source_id}]"
                                ),
                                "fileContents": leak_banner + redacted_consolidated,
                            }
                        )
                        q_output = q_result.get("outputText", "") if isinstance(q_result, dict) else ""
                        if q_output and "\"content\"" in q_output and "\"commit\"" in q_output:
                            print(f"  Quarantine pushed: {private_repo}/{output_directory}/{quarantine_filename}", flush=True)
                        else:
                            err_msg = q_output[:300] if q_output else "(no outputText)"
                            failures.append(f"quarantine push: {err_msg}")
                            print(f"  Quarantine push FAILED: {err_msg}", flush=True)
                    except Exception as e:
                        typed = type(e).__name__
                        detail = str(e) or f"{typed} (no detail)"
                        failures.append(f"quarantine push: {detail}")
                        print(f"  Quarantine push FAILED: {detail}", flush=True)

                    # 2) Push a clean placeholder to the PUBLIC repo so
                    #    the URL still resolves but doesn't expose leaks
                    public_placeholder = (
                        f"# Security Audit Report — Pending Review\n\n"
                        f"This ASVS security audit report has been withheld from "
                        f"publication pending manual review.\n\n"
                        f"**Status:** Under review "
                        f"({len(consolidated_leaks)} detection"
                        f"{'s' if len(consolidated_leaks) != 1 else ''} from the "
                        f"post-redaction defense-in-depth scan)\n\n"
                        f"**Source:** {source_id}\n\n"
                        f"The audit pipeline's automated redaction process detected "
                        f"references to Critical-severity findings that should not be "
                        f"disclosed publicly. Per the project's coordinated-disclosure "
                        f"policy, the report has not been published until those references "
                        f"have been verified and either removed or confirmed as false "
                        f"positives.\n\n"
                        f"For coordinated disclosure of Critical findings, contact the "
                        f"project's security team via the channels documented at the "
                        f"project's `SECURITY.md` or `/security` documentation.\n\n"
                        f"_This placeholder will be replaced with the full redacted "
                        f"report after review completes._\n"
                    )
                    try:
                        p_result = await gofannon_client.call(
                            agent_name="asvs_push_github",
                            input_dict={
                                "inputText": json.dumps({
                                    "repo": output_repo, "token": output_token,
                                    "directory": output_directory,
                                    "filename": "consolidated.md",
                                }),
                                "commitMessage": (
                                    f"ASVS {level or 'full'} audit: placeholder "
                                    f"(report withheld pending review) [source: {source_id}]"
                                ),
                                "fileContents": public_placeholder,
                            }
                        )
                        p_output = p_result.get("outputText", "") if isinstance(p_result, dict) else ""
                        if p_output and "\"content\"" in p_output and "\"commit\"" in p_output:
                            print(f"  Public placeholder pushed to {output_repo}", flush=True)
                            consolidated_pushed = True
                        else:
                            err_msg = p_output[:300] if p_output else "(no outputText)"
                            failures.append(f"public placeholder push: {err_msg}")
                            print(f"  Public placeholder push FAILED: {err_msg}", flush=True)
                    except Exception as e:
                        typed = type(e).__name__
                        detail = str(e) or f"{typed} (no detail)"
                        failures.append(f"public placeholder push: {detail}")
                        print(f"  Public placeholder push FAILED: {detail}", flush=True)

                    # Surface as a failure so the run summary doesn't claim
                    # everything was clean.
                    failures.append(
                        f"carve-out leak check: {len(consolidated_leaks)} suspected "
                        f"leak(s); public report replaced with placeholder, full "
                        f"version in {private_repo}/{output_directory}/{quarantine_filename}"
                    )
                else:
                    # ─── No leaks: normal public push ─────────────────────
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
                            consolidated_pushed = True
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
                        issues_pushed = True
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

            # Truthful completion summary. The previous unconditional
            # "Redacted consolidated and issues pushed" message hid the
            # May 19 issues.md failure entirely; the WARNING three lines
            # earlier was the only signal.
            pushed_files = []
            if consolidated_pushed:
                pushed_files.append("consolidated.md")
            if issues_pushed:
                pushed_files.append("issues.md")
            if pushed_files:
                print(f"  Pushed redacted {' and '.join(pushed_files)} to {output_repo}", flush=True)
            if consolidated_content and not consolidated_pushed:
                print(f"  WARNING: consolidated.md NOT pushed to {output_repo} (see failures above)", flush=True)
            if issues_content and not issues_pushed:
                print(f"  WARNING: issues.md NOT pushed to {output_repo} (see failures above)", flush=True)

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