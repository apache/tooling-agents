from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json
        import re
        import base64
        from datetime import date

        audit_date = date.today().strftime("%b %d, %Y")

        # =============================================================
        # Markdown HTML sanitizer — escape stray HTML tags that LLMs
        # sometimes emit, which break rendering (e.g. <strong> makes
        # everything bold, <pre> switches to preformatted mode).
        # Applied to every LLM result before assembly into .md files.
        # Preserves fenced code blocks and inline code spans.
        # =============================================================
        def sanitize_md_html(text):
            """Escape HTML tags outside fenced code blocks and inline
            code spans so they render as literal text in markdown."""
            if not text:
                return text

            # Split on fenced code blocks — leave them untouched
            parts = re.split(r'(```[\s\S]*?```)', text)
            out = []
            for part in parts:
                if part.startswith('```'):
                    out.append(part)
                    continue

                # Stash inline code spans
                stash = []
                def _stash(m):
                    stash.append(m.group(0))
                    return f'\x00IC{len(stash)-1}\x00'
                s = re.sub(r'`[^`\n]+`', _stash, part)

                # Escape any HTML tag: <anything> or </anything>
                s = re.sub(r'<(/?\w[^>]*)>', r'&lt;\1&gt;', s)

                # Restore inline code spans
                for j, code in enumerate(stash):
                    s = s.replace(f'\x00IC{j}\x00', code)
                out.append(s)
            return ''.join(out)

        # Parse inputs — tolerant of "label: value" or raw values
        input_text = input_dict.get("inputText", "")
        print(f"DEBUG raw input: {repr(input_text[:500])}", flush=True)
        lines = input_text.strip().split("\n")
        owner_repo = ""
        pat = ""
        directories_raw = ""
        output_directory = ""
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip().lower()
                value = value.strip()
                if key in ("owner/repo", "repo", "repository", "owner_repo"):
                    owner_repo = value
                elif key in ("pat", "token", "github_token", "personal_access_token"):
                    pat = value
                elif key in ("directories", "dirs", "paths"):
                    directories_raw = value
                elif key in ("directory", "dir", "path"):
                    directories_raw = value
                elif key in ("output", "output_directory", "output_dir"):
                    output_directory = value

        # Parse directories — comma-separated
        directories = [d.strip().strip("/") for d in directories_raw.split(",") if d.strip()]

        # Fallback: positional parsing
        if not owner_repo or not pat or not directories:
            parts = input_text.strip().split()
            tokens = [p.strip() for p in parts if p.strip()]
            if not owner_repo:
                for t in tokens:
                    if "/" in t and not t.startswith("/") and not t.startswith("ghp_") and "." not in t.split("/")[0]:
                        owner_repo = t
                        break
            if not pat:
                for t in tokens:
                    if t.startswith("ghp_") or t.startswith("github_pat_"):
                        pat = t
                        break

        assert owner_repo, "Could not parse owner/repo from input"
        assert pat, "Could not parse PAT from input"
        assert directories, "Could not parse directories from input. Use 'directories: path/to/L1, path/to/L2'"

        owner, repo = owner_repo.split("/", 1)

        # Extract level labels from directory names (e.g., "security/ASVS/reports/6de01e2/L1" → "L1")
        dir_levels = {}
        for d in directories:
            level = d.split("/")[-1]  # last path component: L1, L2, L3
            dir_levels[d] = level

        # Derive output directory — one level up from the input directories
        if not output_directory:
            output_directory = "/".join(directories[0].split("/")[:-1])
        output_directory = output_directory.strip("/")

        # Build level-tagged filenames (e.g., consolidated-L1-L2.md, issues-L1-L2.md)
        sorted_levels = sorted(set(dir_levels.values()))
        levels_suffix = "-".join(sorted_levels)  # "L1-L2" or "L1-L2-L3"
        consolidated_filename = f"consolidated-{levels_suffix}.md"
        issues_filename = f"issues-{levels_suffix}.md"

        print(f"Repository: {owner}/{repo}")
        print(f"Directories: {directories}")
        print(f"Levels: {dir_levels}")
        print(f"Output: {output_directory}")
        print(f"PAT: {pat[:10]}...")

        # =============================================================
        # Model configuration
        # =============================================================
        FAST_PROVIDER = "bedrock"
        FAST_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        FAST_PARAMS = {"temperature": 0.7, "max_tokens": 16384}

        HEAVY_PROVIDER = "bedrock"
        HEAVY_MODEL = "us.anthropic.claude-opus-4-6-v1"
        HEAVY_PARAMS = {"temperature": 1, "reasoning_effort": "high", "max_tokens": 128000}

        FAST_CONTEXT_WINDOW = get_context_window(FAST_PROVIDER, FAST_MODEL)
        HEAVY_CONTEXT_WINDOW = get_context_window(HEAVY_PROVIDER, HEAVY_MODEL)

        # Checkpointing — keyed on all directories combined
        dirs_key = "+".join(sorted(directories))
        extraction_ns = data_store.use_namespace(f"extraction:{owner}/{repo}/{dirs_key}")
        consolidation_ns = data_store.use_namespace(f"consolidation:{owner}/{repo}/{dirs_key}")

        # GitHub API setup
        GITHUB_API = "https://api.github.com"
        headers = {
            "Authorization": f"token {pat}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        repo_resp = await http_client.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers)
        repo_data = repo_resp.json()
        default_branch = repo_data.get("default_branch", "main")
        print(f"Default branch: {default_branch}")

        # ============================================================
        # PHASE 1: Read All Reports from All Directories
        # ============================================================
        print("\n=== PHASE 1: Reading all reports ===")

        reports = {}  # key: "L1:filename.md" or "L2:filename.md"
        report_levels = {}  # key: "L1:filename.md" → "L1"
        report_dirs = {}  # key: "L1:filename.md" → full directory path

        for directory in directories:
            level = dir_levels[directory]
            print(f"\n  Reading {level} reports from {directory}...")

            contents_resp = await http_client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{directory}",
                headers=headers,
                params={"ref": default_branch},
            )
            if contents_resp.status_code != 200:
                print(f"  WARNING: Failed to list {directory}: {contents_resp.status_code}")
                continue

            dir_contents = contents_resp.json()
            report_files = []
            for item in dir_contents:
                if item["type"] == "file" and item["name"].endswith(".md"):
                    if not item["name"].startswith("consolidated") and \
                       not item["name"].startswith("issues"):
                        report_files.append(item)

            print(f"  Found {len(report_files)} report files in {level}")

            for item in report_files:
                file_resp = await http_client.get(
                    f"{GITHUB_API}/repos/{owner}/{repo}/contents/{directory}/{item['name']}",
                    headers=headers,
                    params={"ref": default_branch},
                )
                if file_resp.status_code == 200:
                    file_data = file_resp.json()
                    content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                    report_key = f"{level}:{item['name']}"
                    reports[report_key] = content
                    report_levels[report_key] = level
                    report_dirs[report_key] = directory
                    print(f"    Read {report_key} ({len(content)} chars)")
                else:
                    print(f"    WARNING: Failed to read {item['name']}: {file_resp.status_code}")

        total_reports = len(reports)
        level_counts = {}
        for rk, lv in report_levels.items():
            level_counts[lv] = level_counts.get(lv, 0) + 1
        print(f"\nSuccessfully read {total_reports} reports: {level_counts}")

        # ============================================================
        # PHASE 2: Extract Findings (Sonnet, parallel, checkpointed)
        # ============================================================
        print("\n=== PHASE 2: Extracting findings (Sonnet, up to 5 concurrent) ===")

        EXTRACTION_PROMPT_TEMPLATE = """You are a security finding extractor. Given an ASVS audit report, extract ALL findings into structured JSON.

For each finding, capture:
- source_report: the report key provided (includes level prefix like "L1:filename.md")
- finding_id: the ID used in the source report
- severity: Critical/High/Medium/Low/Informational
- title: short descriptive title
- description: full description of the vulnerability
- cwe: CWE identifier if mentioned (e.g., "CWE-22")
- asvs_section: the ASVS section being audited (e.g., "8.2.2")
- asvs_level: the ASVS level this report covers (provided below)
- affected_files: list of objects with "file" and "line" keys
- recommended_remediation: the recommended fix
- positive_controls: list of any positive security controls or good practices noted

Also extract:
- asvs_status: overall status of this ASVS section (Pass/Fail/Partial/N/A)
- asvs_section_title: the title/topic of this ASVS section if mentioned

If the report has NO security findings (section passed or is N/A), return an empty findings list but still set asvs_status and asvs_section_title.

Return ONLY valid JSON in this format:
{
  "source_report": "LEVEL:filename.md",
  "asvs_section": "X.Y.Z",
  "asvs_level": "L1|L2|L3",
  "asvs_section_title": "Title of the section",
  "asvs_status": "Pass|Fail|Partial|N/A",
  "findings": [...],
  "positive_controls": [{"control": "description", "evidence": "where it was observed", "files": ["file:line"]}]
}"""

        extraction_semaphore = asyncio.Semaphore(5)
        all_extracted = {}
        extraction_errors = []

        async def extract_report(report_key, content):
            cached = extraction_ns.get(report_key)
            if cached:
                print(f"  {report_key}: cached ({len(cached.get('findings', []))} findings)")
                return report_key, cached, None

            level = report_levels[report_key]

            async with extraction_semaphore:
                print(f"  {report_key}: extracting...", end=" ", flush=True)
                messages = [
                    {"role": "user", "content": f"{EXTRACTION_PROMPT_TEMPLATE}\n\nSource report key: {report_key}\nASVS Level: {level}\n\nReport content:\n{content}"}
                ]
                try:
                    result, _ = await call_llm(
                        provider=FAST_PROVIDER,
                        model=FAST_MODEL,
                        messages=messages,
                        parameters=FAST_PARAMS,
                        timeout=600,
                    )
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        extracted = json.loads(json_match.group())
                        # Ensure level is set
                        extracted["asvs_level"] = level
                        extracted["source_report"] = report_key
                        extraction_ns.set(report_key, extracted)
                        finding_count = len(extracted.get("findings", []))
                        status = extracted.get("asvs_status", "Unknown")
                        print(f"{finding_count} findings, status: {status}")
                        return report_key, extracted, None
                    else:
                        print(f"WARNING: no JSON in result")
                        return report_key, None, "No JSON in result"
                except Exception as e:
                    print(f"ERROR: {e}")
                    return report_key, None, str(e)

        extraction_tasks = [
            extract_report(report_key, content)
            for report_key, content in reports.items()
        ]
        extraction_results = await asyncio.gather(*extraction_tasks)

        for report_key, extracted, error in extraction_results:
            if extracted:
                all_extracted[report_key] = extracted
            elif error:
                extraction_errors.append(report_key)

        if extraction_errors:
            print(f"\nRetrying {len(extraction_errors)} failed extractions...")
            retry_tasks = [
                extract_report(report_key, reports[report_key])
                for report_key in extraction_errors
            ]
            retry_results = await asyncio.gather(*retry_tasks)
            for report_key, extracted, error in retry_results:
                if extracted:
                    all_extracted[report_key] = extracted
                    extraction_errors.remove(report_key)

        total_extracted = sum(len(v.get("findings", [])) for v in all_extracted.values())
        print(f"\nTotal extracted findings: {total_extracted}")
        print(f"Reports with errors: {len(extraction_errors)}")

        # Per-level stats
        for lv in sorted(set(dir_levels.values())):
            lv_findings = sum(len(v.get("findings", [])) for k, v in all_extracted.items() if report_levels.get(k) == lv)
            lv_reports = sum(1 for k in all_extracted if report_levels.get(k) == lv)
            print(f"  {lv}: {lv_findings} findings from {lv_reports} reports")

        # ============================================================
        # PHASE 2.5: Enrich with ASVS requirement context
        # ============================================================
        print("\n=== Loading ASVS requirement context ===")

        asvs_ns = data_store.use_namespace("asvs")
        ASVS_PREFIX = "asvs:"

        all_asvs_ids = set()
        for extracted in all_extracted.values():
            section = extracted.get("asvs_section", "")
            if section:
                all_asvs_ids.add(section)
            for finding in extracted.get("findings", []):
                s = finding.get("asvs_section", "")
                if s:
                    all_asvs_ids.add(s)

        asvs_context = {}
        chapters_cache = {}
        sections_cache = {}

        for req_id in sorted(all_asvs_ids):
            req = asvs_ns.get(f"{ASVS_PREFIX}requirements:{req_id}")
            if not req:
                continue

            section_id = req.get("section_id", "")
            chapter_id = req.get("chapter_id", "")

            if section_id and section_id not in sections_cache:
                sections_cache[section_id] = asvs_ns.get(f"{ASVS_PREFIX}sections:{section_id}")
            if chapter_id and chapter_id not in chapters_cache:
                chapters_cache[chapter_id] = asvs_ns.get(f"{ASVS_PREFIX}chapters:{chapter_id}")

            sec = sections_cache.get(section_id) or {}
            ch = chapters_cache.get(chapter_id) or {}

            asvs_context[req_id] = {
                "req_description": req.get("req_description", ""),
                "level": req.get("level"),
                "section_name": sec.get("section_name", ""),
                "section_description": sec.get("description", ""),
                "chapter_name": ch.get("chapter_name", ""),
                "control_objective": ch.get("control_objective", ""),
            }

        print(f"  Loaded ASVS context for {len(asvs_context)} requirements")

        # ============================================================
        # PHASE 3: Domain-Grouped Consolidation (Sonnet, parallel, checkpointed)
        # ============================================================
        print("\n=== PHASE 3: Domain-grouped consolidation (Sonnet, up to 3 concurrent) ===")

        DOMAIN_GROUPS = {
            "input_encoding": [
                "1.1.1", "1.1.2",
                "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5",
                "1.3.1", "1.3.2",
                "1.4.1", "1.4.2", "1.4.3",
                "1.5.1",
            ],
            "business_logic": [
                "2.1.1", "2.2.1", "2.2.2", "2.3.1",
                "2.4.1",
            ],
            "session_csrf": [
                "3.2.1", "3.2.2", "3.3.1", "3.4.1", "3.4.2",
                "3.5.1", "3.5.2", "3.5.3",
                "3.7.1", "3.7.2",
            ],
            "content_type": [
                "4.1.1", "4.2.1", "4.3.1", "4.3.2", "4.4.1",
            ],
            "file_path": [
                "5.1.1", "5.2.1", "5.2.2", "5.3.1", "5.3.2",
                "5.4.1", "5.4.2", "5.4.3",
            ],
            "auth_rate_limit": [
                "6.1.1", "6.2.1", "6.2.2", "6.2.3", "6.2.4",
                "6.2.5", "6.2.6", "6.2.7", "6.2.8",
                "6.3.1", "6.3.2", "6.4.1", "6.4.2",
                "6.5.1", "6.5.2", "6.5.3", "6.5.4", "6.5.5",
                "6.6.1", "6.6.2", "6.6.3",
                "6.8.1", "6.8.2", "6.8.3", "6.8.4",
            ],
            "session_token": [
                "7.1.1", "7.1.2", "7.1.3",
                "7.2.1", "7.2.2", "7.2.3", "7.2.4",
                "7.3.1", "7.3.2",
                "7.4.1", "7.4.2",
                "7.5.1", "7.5.2",
                "7.6.1", "7.6.2",
            ],
            "authorization": [
                "8.1.1", "8.2.1", "8.2.2", "8.3.1",
                "8.4.1",
            ],
            "jwt_token": [
                "9.1.1", "9.1.2", "9.1.3", "9.2.1",
            ],
            "oauth": [
                "10.1.1", "10.1.2", "10.2.1", "10.2.2",
                "10.3.1", "10.3.2", "10.3.3", "10.3.4",
                "10.4.1", "10.4.2", "10.4.3", "10.4.4", "10.4.5",
                "10.5.1", "10.5.2", "10.5.3", "10.5.4", "10.5.5",
                "10.6.1", "10.6.2",
                "10.7.1", "10.7.2", "10.7.3",
            ],
            "crypto_tls": [
                "11.1.1", "11.1.2", "11.2.1", "11.2.2", "11.2.3",
                "11.3.1", "11.3.2", "11.4.1",
                "11.5.1", "11.6.1",
                "12.1.1", "12.2.1", "12.2.2",
                "12.3.1", "12.3.2", "12.3.3", "12.3.4",
            ],
            "api_scm_client": [
                "13.1.1", "13.2.1", "13.2.2", "13.2.3", "13.2.4", "13.2.5",
                "13.3.1", "13.3.2",
                "13.4.1",
                "14.1.1", "14.1.2",
                "14.2.1", "14.3.1",
            ],
            "dependencies": [
                "15.1.1", "15.2.1", "15.3.1",
            ],
            "audit_logging": [
                "16.1.1",
                "16.2.1", "16.2.2", "16.2.3", "16.2.4", "16.2.5",
                "16.3.1", "16.3.2", "16.3.3", "16.3.4",
                "16.4.1", "16.4.2", "16.4.3",
                "16.5.1", "16.5.2", "16.5.3",
            ],
            "webrtc": [
                "17.1.1", "17.2.1", "17.2.2", "17.2.3", "17.2.4",
                "17.3.1", "17.3.2",
            ],
        }

        # Extend domain groups for L2/L3 sections not in L1 map
        section_to_domain = {}
        for domain, sections in DOMAIN_GROUPS.items():
            for section in sections:
                section_to_domain[section] = domain

        # Build chapter-to-domain mapping for L2/L3 sections not explicitly listed
        chapter_domain_map = {}
        for domain, sections in DOMAIN_GROUPS.items():
            for section in sections:
                chapter = ".".join(section.split(".")[:2])  # e.g., "1.2"
                chapter_domain_map[chapter] = domain

        domain_reports = {domain: {} for domain in DOMAIN_GROUPS}
        domain_reports["misc"] = {}

        for report_key, extracted in all_extracted.items():
            asvs_section = extracted.get("asvs_section", "")
            if not asvs_section:
                # Try to extract from filename part of report key (e.g., "L2:1.3.7.md")
                filename_part = report_key.split(":", 1)[-1] if ":" in report_key else report_key
                match = re.match(r'(\d+\.\d+\.\d+)', filename_part)
                if match:
                    asvs_section = match.group(1)

            # Try exact match first, then chapter-level match, then misc
            domain = section_to_domain.get(asvs_section)
            if not domain and asvs_section:
                chapter = ".".join(asvs_section.split(".")[:2])
                domain = chapter_domain_map.get(chapter, "misc")
            if not domain:
                domain = "misc"

            if domain not in domain_reports:
                domain_reports[domain] = {}
            domain_reports[domain][report_key] = extracted

        domain_reports = {d: r for d, r in domain_reports.items() if r}

        for domain, rpts in domain_reports.items():
            finding_count = sum(len(r.get("findings", [])) for r in rpts.values())
            levels_in_domain = set(report_levels.get(rk, "?") for rk in rpts.keys())
            print(f"  {domain}: {len(rpts)} reports, {finding_count} findings ({', '.join(sorted(levels_in_domain))})")

        CONSOLIDATION_PROMPT = """You are a security audit consolidator. You are given extracted findings from multiple ASVS audit reports within the SAME security domain, potentially from DIFFERENT ASVS levels (L1, L2, L3).

Your job is to:
1. **Identify TRUE duplicates**: The EXACT same vulnerability in the EXACT same code location, reported by multiple ASVS sections OR across levels. Merge these into ONE finding and note ALL source reports and levels.
2. **Preserve EVERY unique finding**. If in doubt, keep findings SEPARATE.
3. **Track ASVS levels**: Each finding must list which ASVS level(s) flagged it. A finding from L2 that is NOT in L1 should be tagged as L2-only.
4. **Use the ASVS requirement descriptions** provided to understand what each section tests for.
5. **Do NOT add cross-references between findings.** Cross-references will be computed deterministically after consolidation.

**Deduplication test**: If a developer could fix one WITHOUT fixing the other, they are SEPARATE findings.

Return valid JSON with this structure:
{
  "domain": "domain_name",
  "consolidated_findings": [
    {
      "temp_id": "DOMAIN-N",
      "severity": "Critical|High|Medium|Low|Informational",
      "title": "descriptive title",
      "description": "full description",
      "cwe": "CWE-NNN or null",
      "asvs_sections": ["X.Y.Z", ...],
      "asvs_levels": ["L1", "L2"],
      "affected_files": [{"file": "path", "line": "N"}],
      "source_reports": ["L1:filename.md", "L2:filename.md", ...],
      "recommended_remediation": "specific fix with code examples where possible",
      "merged_from": ["original finding IDs that were deduplicated into this one"]
    }
  ],
  "positive_controls": [
    {"control": "description", "evidence": "where observed", "files": ["file:line"]}
  ],
  "asvs_statuses": {
    "X.Y.Z": {"status": "Pass|Fail|Partial|N/A", "title": "section title", "level": "L1|L2|L3"}
  },
  "dedup_log": [
    "Merged FINDING-X from L1:report_A with FINDING-Y from L2:report_B because: reason"
  ]
}"""

        consolidation_semaphore = asyncio.Semaphore(3)
        domain_consolidated = {}

        def build_asvs_context_block(rpts):
            domain_asvs_sections = set()
            for rpt_data in rpts.values():
                s = rpt_data.get("asvs_section", "")
                if s:
                    domain_asvs_sections.add(s)
            if not domain_asvs_sections:
                return ""
            ctx_lines = []
            for sid in sorted(domain_asvs_sections):
                ctx = asvs_context.get(sid)
                if ctx:
                    ctx_lines.append(
                        f"- **{sid}** (Level {ctx.get('level', '?')}, {ctx['section_name']}): "
                        f"{ctx['req_description'][:300]}"
                    )
            if not ctx_lines:
                return ""
            return (
                "\n\n## ASVS Requirement Descriptions\n"
                "Use these to understand what each section tests for "
                "when deciding if findings are duplicates or distinct:\n"
                + "\n".join(ctx_lines)
            )

        async def consolidate_domain(domain, rpts):
            cached = consolidation_ns.get(domain)
            if cached:
                finding_count = len(cached.get("consolidated_findings", []))
                print(f"  {domain}: cached ({finding_count} findings)")
                return domain, cached

            async with consolidation_semaphore:
                print(f"  {domain}: consolidating {len(rpts)} reports...", flush=True)
                domain_data = json.dumps(rpts, indent=2, default=str)
                asvs_block = build_asvs_context_block(rpts)
                user_msg = f"Domain: {domain}{asvs_block}\n\nExtracted findings from {len(rpts)} reports:\n\n{domain_data}"
                messages = [{"role": "user", "content": f"{CONSOLIDATION_PROMPT}\n\n{user_msg}"}]

                msg_tokens = count_message_tokens(messages, FAST_PROVIDER, FAST_MODEL)
                limit = int(FAST_CONTEXT_WINDOW * 0.80)
                print(f"    Tokens: {msg_tokens} (limit: {limit})")

                if msg_tokens > limit:
                    print(f"    Too large, splitting...")
                    items = list(rpts.items())
                    mid = len(items) // 2
                    sub_groups = [dict(items[:mid]), dict(items[mid:])]
                    sub_results = []
                    for si, sub in enumerate(sub_groups):
                        sub_data = json.dumps(sub, indent=2, default=str)
                        sub_asvs_block = build_asvs_context_block(sub)
                        sub_msg = f"Domain: {domain} (sub-group {si+1}/{len(sub_groups)}){sub_asvs_block}\n\nExtracted findings from {len(sub)} reports:\n\n{sub_data}"
                        sub_messages = [{"role": "user", "content": f"{CONSOLIDATION_PROMPT}\n\n{sub_msg}"}]
                        try:
                            result, _ = await call_llm(
                                provider=FAST_PROVIDER,
                                model=FAST_MODEL,
                                messages=sub_messages,
                                parameters={**FAST_PARAMS, "max_tokens": 64000},
                                timeout=600,
                            )
                            json_match = re.search(r'\{[\s\S]*\}', result)
                            if json_match:
                                sub_results.append(json.loads(json_match.group()))
                                print(f"    Sub-group {si+1}: {len(sub_results[-1].get('consolidated_findings', []))} findings")
                        except Exception as e:
                            print(f"    ERROR in sub-group {si+1}: {e}")

                    if sub_results:
                        merged = {
                            "domain": domain,
                            "consolidated_findings": [],
                            "positive_controls": [],
                            "asvs_statuses": {},
                            "dedup_log": [],
                        }
                        for sr in sub_results:
                            merged["consolidated_findings"].extend(sr.get("consolidated_findings", []))
                            merged["positive_controls"].extend(sr.get("positive_controls", []))
                            merged["asvs_statuses"].update(sr.get("asvs_statuses", {}))
                            merged["dedup_log"].extend(sr.get("dedup_log", []))
                        consolidation_ns.set(domain, merged)
                        return domain, merged
                    return domain, None

                try:
                    result, _ = await call_llm(
                        provider=FAST_PROVIDER,
                        model=FAST_MODEL,
                        messages=messages,
                        parameters={**FAST_PARAMS, "max_tokens": 64000},
                        timeout=600,
                    )
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        consolidated = json.loads(json_match.group())
                        consolidation_ns.set(domain, consolidated)
                        finding_count = len(consolidated.get("consolidated_findings", []))
                        dedup_count = len(consolidated.get("dedup_log", []))
                        print(f"    Result: {finding_count} findings, {dedup_count} dedup merges")
                        return domain, consolidated
                    else:
                        print(f"    WARNING: No JSON in result")
                        return domain, None
                except Exception as e:
                    print(f"    ERROR: {e}")
                    print(f"    Falling back to individual findings for {domain}")
                    return domain, None

        consolidation_tasks = [
            consolidate_domain(domain, rpts)
            for domain, rpts in domain_reports.items()
        ]
        consolidation_results = await asyncio.gather(*consolidation_tasks)

        for domain, consolidated in consolidation_results:
            if consolidated:
                domain_consolidated[domain] = consolidated
            else:
                rpts = domain_reports[domain]
                fallback = {
                    "domain": domain,
                    "consolidated_findings": [],
                    "positive_controls": [],
                    "asvs_statuses": {},
                    "dedup_log": [],
                }
                for report_key, extracted in rpts.items():
                    level = report_levels.get(report_key, "?")
                    for fi, finding in enumerate(extracted.get("findings", [])):
                        fallback["consolidated_findings"].append({
                            "temp_id": f"{domain.upper()}-{fi+1}",
                            "severity": finding.get("severity", "Medium"),
                            "title": finding.get("title", "Unknown"),
                            "description": finding.get("description", ""),
                            "cwe": finding.get("cwe"),
                            "asvs_sections": [finding.get("asvs_section", "")],
                            "asvs_levels": [level],
                            "affected_files": finding.get("affected_files", []),
                            "source_reports": [report_key],
                            "recommended_remediation": finding.get("recommended_remediation", ""),
                            "merged_from": [],
                        })
                    section = extracted.get("asvs_section", "")
                    if section:
                        fallback["asvs_statuses"][section] = {
                            "status": extracted.get("asvs_status", "Unknown"),
                            "title": extracted.get("asvs_section_title", ""),
                            "level": level,
                        }
                    fallback["positive_controls"].extend(extracted.get("positive_controls", []))
                domain_consolidated[domain] = fallback

        total_consolidated = sum(
            len(d.get("consolidated_findings", []))
            for d in domain_consolidated.values()
        )
        print(f"\nTotal consolidated findings (pre-cross-domain): {total_consolidated} (from {total_extracted} extracted)")

        # ============================================================
        # PHASE 3.5: Cross-Domain Deduplication
        # ============================================================
        print("\n=== PHASE 3.5: Cross-domain deduplication ===")

        # Collect all findings into a flat list with domain tracking
        xd_all = []
        for domain, data in domain_consolidated.items():
            for fi, finding in enumerate(data.get("consolidated_findings", [])):
                finding["_xd_domain"] = domain
                finding["_xd_idx"] = fi
                xd_all.append(finding)

        # Extract primary affected file for each finding
        def primary_file(finding):
            af = finding.get("affected_files", [])
            if not af:
                return ""
            first = af[0]
            if isinstance(first, dict):
                return first.get("file", "").split(":")[0].split(" (")[0].strip().strip("`")
            return str(first).split(":")[0].split(" (")[0].strip().strip("`")

        # Normalize title for comparison
        def norm_title(t):
            t = t.lower().strip()
            # Remove common prefix/suffix variations
            for noise in ["completely ", "critical: ", "high: ", "medium: ", "low: "]:
                t = t.replace(noise, "")
            # Remove punctuation
            t = re.sub(r'[^a-z0-9 ]', '', t)
            # Collapse whitespace
            t = re.sub(r'\s+', ' ', t).strip()
            return t

        # Group by primary file
        file_groups = {}
        for finding in xd_all:
            pf = primary_file(finding)
            if pf:
                file_groups.setdefault(pf, []).append(finding)

        # Pass 1: Deterministic dedup — same file + similar title = merge
        xd_merge_count = 0
        xd_removed = set()  # (domain, idx) tuples of findings absorbed into another

        def merge_into(primary, duplicate):
            """Merge duplicate's metadata into primary finding."""
            # Combine source reports
            existing_sources = set(primary.get("source_reports", []))
            for sr in duplicate.get("source_reports", []):
                if sr not in existing_sources:
                    primary.setdefault("source_reports", []).append(sr)
                    existing_sources.add(sr)
            # Combine ASVS sections
            existing_sections = set(primary.get("asvs_sections", []))
            for sec in duplicate.get("asvs_sections", []):
                if sec not in existing_sections:
                    primary.setdefault("asvs_sections", []).append(sec)
                    existing_sections.add(sec)
            # Combine ASVS levels
            existing_levels = set(primary.get("asvs_levels", []))
            for lv in duplicate.get("asvs_levels", []):
                if lv not in existing_levels:
                    primary.setdefault("asvs_levels", []).append(lv)
                    existing_levels.add(lv)
            # Track what was merged
            dup_id = duplicate.get("temp_id", "unknown")
            primary.setdefault("merged_from", []).append(dup_id)
            # Keep longer description
            if len(duplicate.get("description", "")) > len(primary.get("description", "")):
                primary["description"] = duplicate["description"]
            # Keep more detailed remediation
            if len(duplicate.get("recommended_remediation", "")) > len(primary.get("recommended_remediation", "")):
                primary["recommended_remediation"] = duplicate["recommended_remediation"]

        for pf, group in file_groups.items():
            if len(group) < 2:
                continue
            # Within each file group, cluster by normalized title
            title_clusters = {}
            for finding in group:
                nt = norm_title(finding.get("title", ""))
                title_clusters.setdefault(nt, []).append(finding)

            for nt, cluster in title_clusters.items():
                if len(cluster) < 2:
                    continue
                # Pick the finding with the most source reports as primary
                cluster.sort(key=lambda f: len(f.get("source_reports", [])), reverse=True)
                primary = cluster[0]
                for duplicate in cluster[1:]:
                    dup_key = (duplicate["_xd_domain"], duplicate["_xd_idx"])
                    if dup_key in xd_removed:
                        continue
                    merge_into(primary, duplicate)
                    xd_removed.add(dup_key)
                    xd_merge_count += 1
                    print(f"  Merged: '{duplicate.get('title', '')[:60]}' from {duplicate['_xd_domain']} into {primary['_xd_domain']}")

        # Pass 2: LLM-assisted dedup for same-file groups with remaining duplicates
        # Only run on groups where 3+ findings share a file after Pass 1
        xd_llm_groups = {}
        for pf, group in file_groups.items():
            remaining = [f for f in group if (f["_xd_domain"], f["_xd_idx"]) not in xd_removed]
            if len(remaining) >= 3:
                xd_llm_groups[pf] = remaining

        if xd_llm_groups:
            print(f"\n  LLM-assisted dedup: {len(xd_llm_groups)} file groups with 3+ remaining findings")

            XD_DEDUP_PROMPT = """You are deduplicating security findings that affect the SAME file but came from DIFFERENT ASVS domain groups.

Two findings are TRUE DUPLICATES if:
- They describe the EXACT SAME bug in the EXACT SAME code location
- A developer fixing one would automatically fix the other
- The only difference is which ASVS section flagged them

Two findings are NOT duplicates if:
- They describe different bugs even in the same file
- They require different fixes
- They affect different functions/lines

For each group of findings below, return a JSON object:
{
  "merges": [
    {"keep": "TEMP-ID-to-keep", "absorb": ["TEMP-ID-1", "TEMP-ID-2"], "reason": "same bug: description"}
  ]
}

If no duplicates exist in a group, return: {"merges": []}
Return ONLY valid JSON."""

            for pf, group in xd_llm_groups.items():
                group_data = []
                for f in group:
                    group_data.append({
                        "temp_id": f"{f['_xd_domain']}:{f.get('temp_id', '?')}",
                        "domain": f["_xd_domain"],
                        "title": f.get("title", ""),
                        "severity": f.get("severity", ""),
                        "description": f.get("description", "")[:500],
                        "asvs_sections": f.get("asvs_sections", []),
                        "affected_files": f.get("affected_files", [])[:3],
                        "source_reports_count": len(f.get("source_reports", [])),
                    })

                user_msg = f"File: {pf}\n\nFindings ({len(group_data)}):\n{json.dumps(group_data, indent=2, default=str)}"
                messages = [{"role": "user", "content": f"{XD_DEDUP_PROMPT}\n\n{user_msg}"}]

                msg_tokens = count_message_tokens(messages, FAST_PROVIDER, FAST_MODEL)
                if msg_tokens > int(FAST_CONTEXT_WINDOW * 0.60):
                    print(f"    {pf}: {len(group)} findings, too large for LLM dedup — skipping")
                    continue

                try:
                    result, _ = await call_llm(
                        provider=FAST_PROVIDER,
                        model=FAST_MODEL,
                        messages=messages,
                        parameters=FAST_PARAMS,
                        timeout=120,
                    )
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        dedup_result = json.loads(json_match.group())
                        merges = dedup_result.get("merges", [])
                        if merges:
                            # Build lookup: "domain:temp_id" -> finding
                            lookup = {}
                            for f in group:
                                key = f"{f['_xd_domain']}:{f.get('temp_id', '?')}"
                                lookup[key] = f

                            for merge in merges:
                                keep_key = merge.get("keep", "")
                                absorb_keys = merge.get("absorb", [])
                                reason = merge.get("reason", "")
                                keep_finding = lookup.get(keep_key)
                                if not keep_finding:
                                    continue
                                for abs_key in absorb_keys:
                                    abs_finding = lookup.get(abs_key)
                                    if not abs_finding:
                                        continue
                                    abs_dup_key = (abs_finding["_xd_domain"], abs_finding["_xd_idx"])
                                    if abs_dup_key in xd_removed:
                                        continue
                                    merge_into(keep_finding, abs_finding)
                                    xd_removed.add(abs_dup_key)
                                    xd_merge_count += 1
                                    print(f"    LLM merged: {abs_key} into {keep_key} ({reason[:60]})")
                except Exception as e:
                    print(f"    {pf}: LLM dedup failed ({type(e).__name__}), skipping")

        # Remove absorbed findings from domain_consolidated
        if xd_removed:
            for domain, data in domain_consolidated.items():
                original = data.get("consolidated_findings", [])
                filtered = [f for fi, f in enumerate(original) if (domain, fi) not in xd_removed]
                data["consolidated_findings"] = filtered

            # Clean up tracking fields
            for domain, data in domain_consolidated.items():
                for f in data.get("consolidated_findings", []):
                    f.pop("_xd_domain", None)
                    f.pop("_xd_idx", None)

        total_after_xd = sum(
            len(d.get("consolidated_findings", []))
            for d in domain_consolidated.values()
        )
        print(f"\nCross-domain dedup: {xd_merge_count} merges, {total_consolidated} → {total_after_xd} findings")

        # ============================================================
        # PHASE 4: Final Merge and Report Generation (Batched by severity)
        # ============================================================
        print("\n=== PHASE 4: Final merge and report generation (batched by severity) ===")

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        all_findings = []

        for domain, data in domain_consolidated.items():
            for finding in data.get("consolidated_findings", []):
                finding["_domain"] = domain
                # Ensure asvs_levels is always present
                if "asvs_levels" not in finding:
                    # Derive from source_reports
                    levels = set()
                    for sr in finding.get("source_reports", []):
                        if ":" in sr:
                            levels.add(sr.split(":")[0])
                    finding["asvs_levels"] = sorted(levels) if levels else ["Unknown"]
                all_findings.append(finding)

        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Informational"), 4))

        for i, finding in enumerate(all_findings, 1):
            global_id = f"FINDING-{i:03d}"
            finding["global_id"] = global_id

        # Build cross-references deterministically — no LLM judgment
        print("Building deterministic cross-references...")

        def extract_primary_file(finding):
            af = finding.get("affected_files", [])
            if not af:
                return ""
            first = af[0]
            if isinstance(first, dict):
                raw = first.get("file", "")
            else:
                raw = str(first)
            return re.sub(r'[:\s(].*', '', raw).strip().strip("`")

        def extract_function_names(finding):
            """Extract function/method names from affected_files entries."""
            names = set()
            for af in finding.get("affected_files", []):
                raw = af.get("file", "") if isinstance(af, dict) else str(af)
                # Match function references like "func()" or "Class.method()"
                for m in re.finditer(r'(?:^|[:\s])([a-zA-Z_]\w*(?:\.\w+)*)\s*\(', raw):
                    names.add(m.group(1))
            return names

        # Index findings by primary file, CWE, and function names
        by_file = {}
        by_cwe = {}
        by_func = {}
        for finding in all_findings:
            gid = finding["global_id"]
            pf = extract_primary_file(finding)
            if pf:
                by_file.setdefault(pf, set()).add(gid)
            cwe = finding.get("cwe", "")
            if cwe and cwe != "null":
                by_cwe.setdefault(cwe, set()).add(gid)
            for fn in extract_function_names(finding):
                by_func.setdefault(fn, set()).add(gid)

        # Assign cross-references using hard rules
        xref_count = 0
        for finding in all_findings:
            gid = finding["global_id"]
            related = set()

            pf = extract_primary_file(finding)
            cwe = finding.get("cwe", "")
            if cwe == "null":
                cwe = ""
            funcs = extract_function_names(finding)

            # Rule 1: same CWE (regardless of file)
            if cwe and cwe in by_cwe:
                related |= by_cwe[cwe]

            # Rule 2: same function name (regardless of file)
            for fn in funcs:
                if fn in by_func:
                    related |= by_func[fn]

            # Rule 3: same primary file AND (same CWE or same function)
            if pf and pf in by_file:
                same_file_ids = by_file[pf]
                for other_id in same_file_ids:
                    if other_id == gid:
                        continue
                    other = next((f for f in all_findings if f["global_id"] == other_id), None)
                    if not other:
                        continue
                    other_cwe = other.get("cwe", "")
                    if other_cwe == "null":
                        other_cwe = ""
                    other_funcs = extract_function_names(other)
                    # Must share CWE or function, not just file
                    if (cwe and other_cwe and cwe == other_cwe) or (funcs & other_funcs):
                        related.add(other_id)

            # Remove self-reference
            related.discard(gid)

            # Cap at 10
            if len(related) > 10:
                related = set(sorted(related)[:10])

            finding["related_findings"] = sorted(related) if related else []
            if related:
                xref_count += 1

        print(f"  {xref_count} findings have cross-references")

        # Collect ASVS statuses
        all_asvs_statuses = {}
        for domain, data in domain_consolidated.items():
            for section, info in data.get("asvs_statuses", {}).items():
                all_asvs_statuses[section] = info
        for report_key, extracted in all_extracted.items():
            section = extracted.get("asvs_section", "")
            level = report_levels.get(report_key, "?")
            if section and section not in all_asvs_statuses:
                all_asvs_statuses[section] = {
                    "status": extracted.get("asvs_status", "Unknown"),
                    "title": extracted.get("asvs_section_title", ""),
                    "level": level,
                }

        # Collect positive controls
        all_positive_controls = []
        for domain, data in domain_consolidated.items():
            for ctrl in data.get("positive_controls", []):
                ctrl["_domain"] = domain
                all_positive_controls.append(ctrl)
        for report_key, extracted in all_extracted.items():
            for ctrl in extracted.get("positive_controls", []):
                ctrl["_source"] = report_key
                all_positive_controls.append(ctrl)

        # Severity counts
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in all_findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Extract commit from directory path
        commit_info = "N/A"
        for part in directories[0].split("/"):
            if len(part) >= 7 and re.match(r'^[0-9a-f]+$', part):
                commit_info = part
                break

        levels_str = ", ".join(sorted(set(dir_levels.values())))

        # Group findings by severity tier
        findings_by_severity = {}
        for f in all_findings:
            sev = f.get("severity", "Informational")
            findings_by_severity.setdefault(sev, []).append(f)

        # ----------------------------------------------------------
        # Part 1: Executive Summary (Opus)
        # ----------------------------------------------------------
        print(f"Generating executive summary with Opus...")

        exec_summary_prompt = f"""Generate the opening sections of a comprehensive security audit consolidated report in Markdown.

This report consolidates findings from MULTIPLE ASVS levels: {levels_str}

## Report Data

Repository: {owner}/{repo}
Directories: {', '.join(directories)}
ASVS Levels: {levels_str}
Commit: {commit_info}
Date: {audit_date}
Auditor: Tooling Agents
Source report count: {total_reports} ({', '.join(f'{lv}: {ct}' for lv, ct in sorted(level_counts.items()))})
Total findings: {len(all_findings)}

### Severity Distribution
- Critical: {severity_counts.get('Critical', 0)}
- High: {severity_counts.get('High', 0)}
- Medium: {severity_counts.get('Medium', 0)}
- Low: {severity_counts.get('Low', 0)}
- Informational: {severity_counts.get('Informational', 0)}

### All Finding Titles (with level coverage)
"""
        for f in all_findings:
            levels = ", ".join(f.get("asvs_levels", []))
            exec_summary_prompt += f"- [{f.get('severity')}] [{levels}] {f.get('global_id')}: {f.get('title')} (ASVS: {', '.join(f.get('asvs_sections', []))})\n"

        exec_summary_prompt += f"""
### Positive Security Controls
{json.dumps(all_positive_controls[:50], indent=2, default=str)}

## Generate ONLY these sections:

1. **Report Metadata** (as a table: Repository, Audit Directories, ASVS Levels, Commit, Date, Auditor, Source Report Count, Total Findings, Audit Standard)
2. **Executive Summary**:
   - 2.1 Severity Distribution table with emoji indicators
   - 2.2 Level Coverage Summary (which levels found which findings — highlight L2/L3-only findings)
   - 2.3 Top 5 Systemic Risks (identify patterns across findings, with key finding IDs)
   - 2.4 Key Positive Controls Observed (comprehensive list with evidence)

Output ONLY Markdown. End with a `---` separator."""

        exec_messages = [{"role": "user", "content": exec_summary_prompt}]
        exec_tokens = count_message_tokens(exec_messages, HEAVY_PROVIDER, HEAVY_MODEL)
        print(f"  Executive summary prompt: {exec_tokens} tokens")

        exec_result, _ = await call_llm(
            provider=HEAVY_PROVIDER,
            model=HEAVY_MODEL,
            messages=exec_messages,
            parameters={**HEAVY_PARAMS, "max_tokens": 32000},
            timeout=900,
        )
        exec_result = sanitize_md_html(exec_result)  # ← SANITIZE
        print(f"  Executive summary: {len(exec_result)} chars")

        # ----------------------------------------------------------
        # Part 2: Findings sections (Sonnet, batched by count with retry)
        # ----------------------------------------------------------
        FINDING_FORMAT_INSTRUCTIONS = """For each finding, generate a section with:
- `#### FINDING-NNN: Title` as heading
- A table with: Severity (with emoji), ASVS Level(s), CWE, ASVS section(s), Affected Files (with line numbers), Source Reports (with level prefix), Related Findings
- **Description:** paragraph explaining what is wrong and how it could be exploited
- **Recommended Remediation:** specific fix with code examples where helpful

Use these severity emojis: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ⚪ Informational
Include the ASVS level(s) in the table (e.g., "L1, L2" or "L2-only")
Separate each finding with `---`."""

        findings_md_parts = []
        severity_tier_order = ["Critical", "High", "Medium", "Low", "Informational"]
        severity_section_names = {
            "Critical": "3.1 Critical Findings",
            "High": "3.2 High Findings",
            "Medium": "3.3 Medium Findings",
            "Low": "3.4 Low Findings",
            "Informational": "3.5 Informational Findings",
        }

        MAX_FINDINGS_PER_BATCH = 30

        for sev in severity_tier_order:
            sev_findings = findings_by_severity.get(sev, [])
            if not sev_findings:
                continue

            sub_batches = []
            for i in range(0, len(sev_findings), MAX_FINDINGS_PER_BATCH):
                sub_batches.append(sev_findings[i:i + MAX_FINDINGS_PER_BATCH])

            print(f"  {sev} ({len(sev_findings)} findings, {len(sub_batches)} batches):", flush=True)

            for sb_idx, sub_batch in enumerate(sub_batches):
                sub_json = json.dumps(sub_batch, indent=2, default=str)
                is_first = (sb_idx == 0)
                sub_prompt = f"""Format these {len(sub_batch)} {sev} severity security findings into Markdown.

{FINDING_FORMAT_INSTRUCTIONS}

Generate a COMPLETE individual section for EVERY finding below. Do NOT summarize, compress, or create table-only entries.
Each finding MUST have its own `#### FINDING-NNN:` heading, attribute table, description, and remediation.

{"Start with: ### " + severity_section_names[sev] if is_first else "Continue formatting findings. Do NOT include a section header."}

Findings data:
{sub_json}

Output ONLY Markdown. Include ALL {len(sub_batch)} findings with full detail."""

                for attempt in range(3):
                    try:
                        sub_result, _ = await call_llm(
                            provider=FAST_PROVIDER,
                            model=FAST_MODEL,
                            messages=[{"role": "user", "content": sub_prompt}],
                            parameters={**FAST_PARAMS, "max_tokens": 64000},
                            timeout=900,
                        )
                        sub_result = sanitize_md_html(sub_result)  # ← SANITIZE
                        sub_count = len(re.findall(r'#### FINDING-\d{3}', sub_result))
                        print(f"    Batch {sb_idx+1}: {sub_count}/{len(sub_batch)} sections generated")
                        if sub_count >= len(sub_batch):
                            findings_md_parts.append(sub_result)
                            break
                        elif attempt < 2:
                            print(f"    Missing {len(sub_batch) - sub_count} sections, retrying...", flush=True)
                            await asyncio.sleep(5)
                        else:
                            print(f"    Accepting {sub_count}/{len(sub_batch)} after 3 attempts")
                            findings_md_parts.append(sub_result)
                    except Exception as e:
                        if attempt < 2:
                            print(f"    Batch {sb_idx+1} attempt {attempt+1} failed ({type(e).__name__}), retrying...", flush=True)
                            await asyncio.sleep(5)
                        else:
                            print(f"    Batch {sb_idx+1} FAILED after 3 attempts: {e}")

        # ----------------------------------------------------------
        # Part 3: Tail sections (Sonnet)
        # ----------------------------------------------------------
        print(f"Generating tail sections (positive controls, ASVS table, cross-ref matrix)...")

        tail_prompt = f"""Generate the final sections of a security audit consolidated report in Markdown.
This report covers ASVS levels: {levels_str}

### Positive Security Controls Data:
{json.dumps(all_positive_controls[:100], indent=2, default=str)}

### ASVS Section Statuses:
{json.dumps(all_asvs_statuses, indent=2, default=str)}

### Finding references for cross-reference matrix:
"""
        for f in all_findings:
            levels = ", ".join(f.get("asvs_levels", []))
            tail_prompt += f"- {f.get('global_id')} [{f.get('severity')}] [{levels}]: {f.get('title')} (ASVS: {', '.join(f.get('asvs_sections', []))})\n"

        tail_prompt += f"""
Generate ONLY these sections:

## 4. Positive Security Controls
Table with columns: Control | Evidence | Files

## 5. ASVS Compliance Summary
Table with columns: ASVS Section | Section Title | Level | Status (✅ Pass / ⚠️ Partial / ❌ Fail / N/A) | Key Findings

## 6. Cross-Reference Matrix
Table grouping findings by attack surface with finding IDs organized by severity.
Columns: Attack Surface | ASVS Levels | Critical | High | Medium | Low | Info

Do NOT generate a Level Coverage section — it will be added separately.

End with nothing — more content will be appended after this.

Output ONLY Markdown."""

        for attempt in range(2):
            try:
                tail_result, _ = await call_llm(
                    provider=FAST_PROVIDER,
                    model=FAST_MODEL,
                    messages=[{"role": "user", "content": tail_prompt}],
                    parameters={**FAST_PARAMS, "max_tokens": 64000},
                    timeout=900,
                )
                tail_result = sanitize_md_html(tail_result)  # ← SANITIZE
                print(f"  Tail sections: {len(tail_result)} chars")
                break
            except Exception as e:
                if attempt == 0:
                    print(f"  Tail sections attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                    await asyncio.sleep(5)
                else:
                    print(f"  Tail sections FAILED: {e}")
                    tail_result = "\n\n*Tail sections generation failed. See individual findings above.*\n"

        # Assemble final report
        consolidated_md = exec_result.rstrip()
        consolidated_md += "\n\n## 3. Findings\n\n"
        consolidated_md += "\n\n".join(findings_md_parts)
        consolidated_md += "\n\n---\n\n"
        consolidated_md += tail_result

        # Generate Section 7 deterministically (not via LLM — avoids hallucinated numbers)
        print("Generating Section 7 (Level Coverage) deterministically...")
        section7_lines = ["\n\n## 7. Level Coverage Analysis\n"]
        section7_lines.append("| Level | Sections Audited | Findings Found | Unique to Level |")
        section7_lines.append("|-------|-----------------|----------------|-----------------|")
        for lv in sorted(set(dir_levels.values())):
            lv_sections = sum(1 for rk in all_extracted if report_levels.get(rk) == lv)
            lv_findings = [f for f in all_findings if lv in f.get("asvs_levels", [])]
            lv_only = [f for f in lv_findings if f.get("asvs_levels") == [lv]]
            section7_lines.append(f"| {lv} | {lv_sections} | {len(lv_findings)} | {len(lv_only)} |")

        # Both levels
        both = [f for f in all_findings if len(f.get("asvs_levels", [])) > 1]
        section7_lines.append(f"| Both | — | {len(both)} | — |")
        section7_lines.append(f"\n**Total consolidated findings: {len(all_findings)}**")
        section7_lines.append(f"\n*End of Consolidated Security Audit Report*")

        consolidated_md += "\n".join(section7_lines)

        print(f"Consolidated report generated: {len(consolidated_md)} chars")

        # ============================================================
        # Generate issues.md (Sonnet — batched with retry)
        # ============================================================
        ISSUES_BATCH_SIZE = 75

        # Filter out Informational findings for issues generation
        # Robust check: severity field may contain emoji prefix from earlier formatting
        informational_ids = set()
        actionable_findings = []
        for f in all_findings:
            sev = f.get("severity", "").strip()
            if "informational" in sev.lower():
                informational_ids.add(f.get("global_id", ""))
            else:
                actionable_findings.append(f)

        # Strip Informational finding IDs from related_findings in issues data
        # so Sonnet doesn't reference or generate issues for them
        issues_findings_data = []
        for f in actionable_findings:
            f_copy = dict(f)
            if f_copy.get("related_findings"):
                f_copy["related_findings"] = [
                    r for r in f_copy["related_findings"]
                    if r not in informational_ids
                ]
            issues_findings_data.append(f_copy)

        total_batches = (len(issues_findings_data) + ISSUES_BATCH_SIZE - 1) // ISSUES_BATCH_SIZE

        print(f"\nGenerating {issues_filename} (Sonnet, {total_batches} batches)...")
        print(f"Actionable findings for issues: {len(actionable_findings)}")

        ISSUE_FORMAT_INSTRUCTIONS = """Use this format per issue:

---

## Issue: FINDING-NNN - [Descriptive Title]

**Labels:** bug, security, priority:[critical|high|medium|low], asvs-level:[L1|L2|L3]

**ASVS Level(s):** [L1, L2] or [L2-only]

**Description:**

### Summary
[One paragraph: what is wrong, where, and what an attacker could do]

### Details
[Technical details including affected files and line numbers.]

### Recommended Remediation
[Specific fix with code examples where possible]

### Acceptance Criteria
- [ ] [Specific testable condition]
- [ ] Unit test verifying the fix

### References
- Source reports: [list with level prefixes, e.g., L1:7.2.1.md, L2:7.2.1.md]
- Related findings: [list]
- ASVS sections: [list]

### Priority
[Critical|High|Medium|Low]"""

        issues_parts = []
        issues_params = {**FAST_PARAMS}
        issues_params["max_tokens"] = 64000

        for batch_idx in range(0, len(issues_findings_data), ISSUES_BATCH_SIZE):
            batch = issues_findings_data[batch_idx:batch_idx + ISSUES_BATCH_SIZE]
            batch_num = (batch_idx // ISSUES_BATCH_SIZE) + 1
            is_first_batch = batch_idx == 0

            batch_json = json.dumps(batch, indent=2, default=str)

            issues_prompt = f"""Generate GitHub issues in Markdown for these security findings (batch {batch_num}/{total_batches}).
These findings come from ASVS levels: {levels_str}

## Rules
1. Generate ONE issue per finding
2. Include ASVS level(s) in labels: asvs-level:L1, asvs-level:L2, etc.
3. If a finding is L2-only or L3-only, highlight this in the description
4. Include level-prefixed source reports in References (e.g., L1:7.2.1.md)
5. Do NOT merge findings across different files into mega-issues
6. Do NOT generate issues for Informational findings

{ISSUE_FORMAT_INSTRUCTIONS}

{"Output the document header before the first issue: # Security Issues" if is_first_batch else "Continue generating issues. Do NOT include a document header — start directly with the first issue separator (---)."}

## Findings Data
{batch_json}

Generate issues for ALL {len(batch)} findings above. Output ONLY Markdown."""

            issues_messages = [{"role": "user", "content": issues_prompt}]
            prompt_tokens = count_message_tokens(issues_messages, FAST_PROVIDER, FAST_MODEL)
            print(f"  Batch {batch_num}/{total_batches}: {len(batch)} findings, {prompt_tokens} prompt tokens")

            batch_succeeded = False
            for attempt in range(3):
                try:
                    issues_content, _ = await call_llm(
                        provider=FAST_PROVIDER,
                        model=FAST_MODEL,
                        messages=issues_messages,
                        parameters=issues_params,
                        timeout=900,
                    )
                    issues_parts.append(sanitize_md_html(issues_content))  # ← SANITIZE
                    batch_issue_count = len(re.findall(r'## Issue: FINDING-\d{3}', issues_content))
                    print(f"    Batch {batch_num} complete: {len(issues_content)} chars, {batch_issue_count} issues")
                    batch_succeeded = True
                    break
                except Exception as e:
                    if attempt < 2:
                        wait = 10 * (attempt + 1)
                        print(f"    Batch {batch_num} attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                        await asyncio.sleep(wait)
                    else:
                        print(f"    Batch {batch_num} FAILED after 3 attempts: {type(e).__name__}: {e}")

            if not batch_succeeded:
                fallback_parts = []
                for f in batch:
                    fid = f.get("global_id", "UNKNOWN")
                    # ← SANITIZE fields from earlier LLM extraction
                    title = sanitize_md_html(f.get("title", "Unknown finding"))
                    severity = f.get("severity", "Medium")
                    desc = sanitize_md_html(f.get("description", "See consolidated report for details."))
                    levels = ", ".join(f.get("asvs_levels", ["Unknown"]))
                    level_labels = " ".join(f"asvs-level:{lv}" for lv in f.get("asvs_levels", []))
                    files = ", ".join(
                        af.get("file", "unknown") for af in f.get("affected_files", [])
                    ) or "See consolidated report"
                    remediation = sanitize_md_html(f.get("recommended_remediation", "See consolidated report."))
                    sources = ", ".join(f.get("source_reports", []))
                    related = ", ".join(f.get("related_findings", []))
                    asvs_secs = ", ".join(f.get("asvs_sections", []))
                    fallback_parts.append(f"""---

## Issue: {fid} - {title}

**Labels:** bug, security, priority:{severity.lower()}, {level_labels}

**ASVS Level(s):** {levels}

**Description:**

### Summary
{desc}

### Details
Affected files: {files}

### Recommended Remediation
{remediation}

### Acceptance Criteria
- [ ] Vulnerability is remediated
- [ ] Unit test verifying the fix

### References
- Source reports: {sources}
- Related findings: {related}
- ASVS sections: {asvs_secs}

### Priority
{severity}""")
                issues_parts.append("\n\n".join(fallback_parts))
                print(f"    Generated {len(batch)} fallback issues")

        issues_md = "\n\n".join(issues_parts)
        print(f"Issues file generated: {len(issues_md)} chars")

        # ============================================================
        # Quality Checks
        # ============================================================
        print("\n=== Quality Checks ===")

        # Check for duplicate FINDING IDs in the report
        all_finding_ids = re.findall(r'#### (FINDING-\d{3}):', consolidated_md)
        id_counts = {}
        for fid in all_finding_ids:
            id_counts[fid] = id_counts.get(fid, 0) + 1
        duplicate_ids = {fid: cnt for fid, cnt in id_counts.items() if cnt > 1}
        if duplicate_ids:
            print(f"WARNING: Duplicate FINDING IDs detected: {duplicate_ids}")
        else:
            print(f"FINDING ID uniqueness: OK ({len(all_finding_ids)} unique IDs)")

        finding_ids_in_report = set(re.findall(r'FINDING-\d{3}', consolidated_md))
        print(f"FINDING IDs mentioned in consolidated report: {len(finding_ids_in_report)}")

        finding_sections_in_report = set(re.findall(r'#### FINDING-(\d{3})', consolidated_md))
        print(f"FINDING sections with full detail: {len(finding_sections_in_report)} (expected: {len(all_findings)})")
        if len(finding_sections_in_report) < len(all_findings):
            missing_sections = set(f"{i:03d}" for i in range(1, len(all_findings) + 1)) - finding_sections_in_report
            print(f"  Missing sections for: {', '.join(f'FINDING-{m}' for m in sorted(missing_sections)[:10])}{'...' if len(missing_sections) > 10 else ''}")

        # Count actual issue entries (headers), not just FINDING ID mentions
        issue_headers_in_issues = set(re.findall(r'## Issue: (FINDING-\d{3})', issues_md))
        issue_ids_mentioned = set(re.findall(r'FINDING-\d{3}', issues_md))
        print(f"Issue entries in issues file: {len(issue_headers_in_issues)} (expected: {len(actionable_findings)})")
        if len(issue_headers_in_issues) != len(actionable_findings):
            extra = issue_headers_in_issues - set(f.get("global_id", "") for f in actionable_findings)
            missing = set(f.get("global_id", "") for f in actionable_findings) - issue_headers_in_issues
            if extra:
                print(f"  Extra issues (should not exist): {sorted(extra)[:10]}")
            if missing:
                print(f"  Missing issues: {sorted(missing)[:10]}")

        # Per-level finding counts
        print(f"\n--- Level Analysis ---")
        for lv in sorted(set(dir_levels.values())):
            lv_findings = [f for f in all_findings if lv in f.get("asvs_levels", [])]
            lv_only = [f for f in lv_findings if f.get("asvs_levels") == [lv]]
            print(f"  {lv}: {len(lv_findings)} findings total, {len(lv_only)} unique to {lv}")

        reports_mentioned = set()
        for f in all_findings:
            for sr in f.get("source_reports", []):
                reports_mentioned.add(sr)
        unrepresented = set(reports.keys()) - reports_mentioned

        if unrepresented:
            print(f"\n--- Report Representation Analysis ---")
            print(f"  {len(unrepresented)} of {total_reports} reports not represented in consolidated findings:")

            zero_finding_reports = []
            deduped_reports = []
            error_reports = []

            for rpt in sorted(unrepresented):
                extracted = all_extracted.get(rpt)
                if not extracted:
                    error_reports.append(rpt)
                elif len(extracted.get("findings", [])) == 0:
                    status = extracted.get("asvs_status", "Unknown")
                    title = extracted.get("asvs_section_title", "")
                    zero_finding_reports.append((rpt, status, title))
                else:
                    finding_count = len(extracted.get("findings", []))
                    deduped_reports.append((rpt, finding_count))

            if zero_finding_reports:
                print(f"\n  {len(zero_finding_reports)} reports had 0 extracted findings (Pass/N/A — expected):")
                for rpt, status, title in zero_finding_reports[:20]:
                    print(f"    {rpt}: '{title}' — status: {status}")
                if len(zero_finding_reports) > 20:
                    print(f"    ... and {len(zero_finding_reports) - 20} more")

            if deduped_reports:
                print(f"\n  {len(deduped_reports)} reports had findings that were fully deduped into other reports:")
                for rpt, count in deduped_reports[:10]:
                    print(f"    {rpt}: {count} findings extracted, all merged during consolidation")
                if len(deduped_reports) > 10:
                    print(f"    ... and {len(deduped_reports) - 10} more")

            if error_reports:
                print(f"\n  {len(error_reports)} reports failed extraction entirely:")
                for rpt in error_reports:
                    print(f"    {rpt}: extraction failed — no data available")

            print(f"  ---")
        else:
            print("All source reports represented in consolidated findings")

        if total_extracted > 0:
            loss_pct = (1 - len(all_findings) / total_extracted) * 100
            print(f"Finding reduction: {total_extracted} → {len(all_findings)} ({loss_pct:.1f}%)")
            if loss_pct > 20:
                print("WARNING: >20% reduction — deduplication may be too aggressive")

        # ============================================================
        # Push files to GitHub
        # ============================================================
        print("\n=== Pushing files to GitHub ===")

        async def push_file(path, content_str, message):
            existing_sha = None
            check_resp = await http_client.get(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
                headers=headers,
                params={"ref": default_branch},
            )
            if check_resp.status_code == 200:
                existing_sha = check_resp.json().get("sha")
                print(f"  Updating: {path}")
            else:
                print(f"  Creating: {path}")

            payload = {
                "message": message,
                "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"),
                "branch": default_branch,
            }
            if existing_sha:
                payload["sha"] = existing_sha

            put_resp = await http_client.put(
                f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}",
                headers=headers,
                json=payload,
            )
            if put_resp.status_code in (200, 201):
                print(f"  OK: {path}")
                return True
            else:
                print(f"  ERROR: {path}: {put_resp.status_code} {put_resp.text[:200]}")
                return False

        await push_file(
            f"{output_directory}/{consolidated_filename}",
            consolidated_md,
            f"Add consolidated security audit report ({levels_str}) for {output_directory}",
        )
        await push_file(
            f"{output_directory}/{issues_filename}",
            issues_md,
            f"Add security issues file ({levels_str}) for {output_directory}",
        )

        print("\n=== Done ===")
        print(f"Total findings: {len(all_findings)}")
        print(f"Actionable issues: {len(actionable_findings)}")
        print(f"Severity: {severity_counts}")

        return {
            "outputText": f"Successfully generated and pushed consolidated security audit report and issues file.\n\n"
                          f"**Repository:** {owner}/{repo}\n"
                          f"**Directories:** {', '.join(directories)}\n"
                          f"**ASVS Levels:** {levels_str}\n"
                          f"**Output:** {output_directory}\n"
                          f"**Source reports analyzed:** {total_reports} ({', '.join(f'{lv}: {ct}' for lv, ct in sorted(level_counts.items()))})\n"
                          f"**Total findings:** {len(all_findings)}\n"
                          f"**Severity breakdown:**\n"
                          f"  - Critical: {severity_counts.get('Critical', 0)}\n"
                          f"  - High: {severity_counts.get('High', 0)}\n"
                          f"  - Medium: {severity_counts.get('Medium', 0)}\n"
                          f"  - Low: {severity_counts.get('Low', 0)}\n"
                          f"  - Informational: {severity_counts.get('Informational', 0)}\n"
                          f"**Actionable issues generated:** {len(actionable_findings)}\n\n"
                          f"**Files pushed:**\n"
                          f"  - `{output_directory}/{consolidated_filename}`\n"
                          f"  - `{output_directory}/{issues_filename}`"
        }
    finally:
        await http_client.aclose()