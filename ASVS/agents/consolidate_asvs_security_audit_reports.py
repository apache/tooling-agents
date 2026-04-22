# consolidate_asvs_security_audit_reports

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
        # Markdown HTML sanitizer
        # =============================================================
        def sanitize_md_html(text):
            if not text:
                return text
            parts = re.split(r'(```[\s\S]*?```)', text)
            out = []
            for part in parts:
                if part.startswith('```'):
                    out.append(part)
                    continue
                stash = []
                def _stash(m):
                    stash.append(m.group(0))
                    return f'\x00IC{len(stash)-1}\x00'
                s = re.sub(r'`[^`\n]+`', _stash, part)
                s = re.sub(r'<(/?\w[^>]*)>', r'&lt;\1&gt;', s)
                for j, code in enumerate(stash):
                    s = s.replace(f'\x00IC{j}\x00', code)
                out.append(s)
            return ''.join(out)

        # =============================================================
        # Parse inputs
        # =============================================================
        input_text = input_dict.get("inputText", "")
        domain_groups_raw = input_dict.get("domainGroups", "")
        level = input_dict.get("level", "L3")
        severity_threshold = input_dict.get("severityThreshold", "")

        # Normalize level
        level = level.strip().upper()
        if level and not level.startswith("L"):
            level = f"L{level}"
        LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
        max_level_num = LEVEL_ORDER.get(level, 3)

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
                elif key in ("directories", "dirs", "paths", "directory", "dir", "path"):
                    directories_raw = value
                elif key in ("output", "output_directory", "output_dir"):
                    output_directory = value

        directories = [d.strip().strip("/") for d in directories_raw.split(",") if d.strip()]

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
        assert directories, "Could not parse directories from input"

        owner, repo = owner_repo.split("/", 1)

        if not output_directory:
            output_directory = "/".join(directories[0].split("/")[:-1])
        output_directory = output_directory.strip("/")

        # Output filenames — no level suffix
        consolidated_filename = "consolidated.md"
        issues_filename = "issues.md"

        print(f"Repository: {owner}/{repo}")
        print(f"Directories: {directories}")
        print(f"Level: {level}")
        print(f"Output: {output_directory}")

        # =============================================================
        # Model configuration
        # =============================================================
        FAST_PROVIDER = "bedrock"
        FAST_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        FAST_PARAMS = {"temperature": 0.7, "max_tokens": 16384}

        HEAVY_PROVIDER = "bedrock"
        HEAVY_MODEL = "us.anthropic.claude-opus-4-6-v1"
        HEAVY_PARAMS = {"temperature": 1, "reasoning_effort": "medium", "max_tokens": 128000}

        FAST_CONTEXT_WINDOW = get_context_window(FAST_PROVIDER, FAST_MODEL)
        HEAVY_CONTEXT_WINDOW = get_context_window(HEAVY_PROVIDER, HEAVY_MODEL)

        dirs_key = "+".join(sorted(directories))
        extraction_ns = data_store.use_namespace(f"extraction:{owner}/{repo}/{dirs_key}")
        consolidation_ns = data_store.use_namespace(f"consolidation:{owner}/{repo}/{dirs_key}")

        GITHUB_API = "https://api.github.com"
        headers = {
            "Authorization": f"token {pat}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        repo_resp = await http_client.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=headers)
        repo_data = repo_resp.json()
        default_branch = repo_data.get("default_branch", "main")

        # ============================================================
        # PHASE 1: Read All Reports from All Directories
        # ============================================================
        print("\n=== PHASE 1: Reading all reports ===")

        reports = {}

        for directory in directories:
            print(f"\n  Reading reports from {directory}...")
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

            print(f"  Found {len(report_files)} report files")

            for item in report_files:
                file_resp = await http_client.get(
                    f"{GITHUB_API}/repos/{owner}/{repo}/contents/{directory}/{item['name']}",
                    headers=headers,
                    params={"ref": default_branch},
                )
                if file_resp.status_code == 200:
                    file_data = file_resp.json()
                    content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                    report_key = item['name']
                    reports[report_key] = content
                    print(f"    Read {report_key} ({len(content)} chars)")

        total_reports = len(reports)
        print(f"\nSuccessfully read {total_reports} reports")

        # ============================================================
        # PHASE 2: Extract Findings (Sonnet, parallel, checkpointed)
        # ============================================================
        print("\n=== PHASE 2: Extracting findings ===")

        EXTRACTION_PROMPT_TEMPLATE = """You are a security finding extractor. Given an ASVS audit report, extract ALL findings into structured JSON.

For each finding, capture:
- source_report: the report filename
- finding_id: the ID used in the source report
- severity: Critical/High/Medium/Low/Informational
- title: short descriptive title
- description: full description of the vulnerability
- cwe: CWE identifier if mentioned
- asvs_section: the ASVS section being audited (e.g., "8.2.2")
- affected_files: list of objects with "file" and "line" keys
- recommended_remediation: the recommended fix
- positive_controls: list of any positive security controls noted

Also extract:
- asvs_status: overall status of this ASVS section (Pass/Fail/Partial/N/A)
- asvs_section_title: the title/topic of this ASVS section if mentioned

If the report has NO findings, return an empty findings list but still set asvs_status.

Return ONLY valid JSON:
{
  "source_report": "filename.md",
  "asvs_section": "X.Y.Z",
  "asvs_section_title": "Title",
  "asvs_status": "Pass|Fail|Partial|N/A",
  "findings": [...],
  "positive_controls": [{"control": "description", "evidence": "where observed", "files": ["file:line"]}]
}"""

        extraction_semaphore = asyncio.Semaphore(5)
        all_extracted = {}
        extraction_errors = []

        async def extract_report(report_key, content):
            cached = extraction_ns.get(report_key)
            if cached:
                print(f"  {report_key}: cached ({len(cached.get('findings', []))} findings)")
                return report_key, cached, None

            async with extraction_semaphore:
                print(f"  {report_key}: extracting...", end=" ", flush=True)
                messages = [
                    {"role": "user", "content": f"{EXTRACTION_PROMPT_TEMPLATE}\n\nSource report: {report_key}\n\nReport content:\n{content}"}
                ]
                try:
                    result, _ = await call_llm(
                        provider=FAST_PROVIDER, model=FAST_MODEL,
                        messages=messages, parameters=FAST_PARAMS, timeout=600,
                    )
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        extracted = json.loads(json_match.group())
                        extracted["source_report"] = report_key
                        extraction_ns.set(report_key, extracted)
                        print(f"{len(extracted.get('findings', []))} findings, status: {extracted.get('asvs_status', '?')}")
                        return report_key, extracted, None
                    else:
                        print(f"WARNING: no JSON")
                        return report_key, None, "No JSON in result"
                except Exception as e:
                    print(f"ERROR: {e}")
                    return report_key, None, str(e)

        extraction_results = await asyncio.gather(*[
            extract_report(rk, content) for rk, content in reports.items()
        ])
        for rk, extracted, error in extraction_results:
            if extracted:
                all_extracted[rk] = extracted
            elif error:
                extraction_errors.append(rk)

        if extraction_errors:
            print(f"\nRetrying {len(extraction_errors)} failed extractions...")
            retry_results = await asyncio.gather(*[
                extract_report(rk, reports[rk]) for rk in extraction_errors
            ])
            for rk, extracted, error in retry_results:
                if extracted:
                    all_extracted[rk] = extracted
                    extraction_errors.remove(rk)

        total_extracted = sum(len(v.get("findings", [])) for v in all_extracted.values())
        print(f"\nTotal extracted findings: {total_extracted}")

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

        def get_asvs_level(section_id):
            ctx = asvs_context.get(section_id)
            if ctx and ctx.get("level"):
                return f"L{ctx['level']}"
            return "L?"

        # ============================================================
        # PHASE 3: Domain-Grouped Consolidation
        # ============================================================
        print("\n=== PHASE 3: Domain-grouped consolidation ===")

        # Domain groups from input or ATR defaults
        if domain_groups_raw:
            DOMAIN_GROUPS = json.loads(domain_groups_raw) if isinstance(domain_groups_raw, str) else domain_groups_raw
            print(f"  Using provided domain groups: {len(DOMAIN_GROUPS)} domains", flush=True)
        else:
            DOMAIN_GROUPS = {
                "input_encoding": ["1.1.1","1.1.2","1.2.1","1.2.2","1.2.3","1.2.4","1.2.5","1.3.1","1.3.2","1.4.1","1.4.2","1.4.3","1.5.1"],
                "business_logic": ["2.1.1","2.2.1","2.2.2","2.3.1","2.4.1"],
                "session_csrf": ["3.2.1","3.2.2","3.3.1","3.4.1","3.4.2","3.5.1","3.5.2","3.5.3","3.7.1","3.7.2"],
                "content_type": ["4.1.1","4.2.1","4.3.1","4.3.2","4.4.1"],
                "file_path": ["5.1.1","5.2.1","5.2.2","5.3.1","5.3.2","5.4.1","5.4.2","5.4.3"],
                "auth_rate_limit": ["6.1.1","6.2.1","6.2.2","6.2.3","6.2.4","6.2.5","6.2.6","6.2.7","6.2.8","6.3.1","6.3.2","6.4.1","6.4.2","6.5.1","6.5.2","6.5.3","6.5.4","6.5.5","6.6.1","6.6.2","6.6.3","6.8.1","6.8.2","6.8.3","6.8.4"],
                "session_token": ["7.1.1","7.1.2","7.1.3","7.2.1","7.2.2","7.2.3","7.2.4","7.3.1","7.3.2","7.4.1","7.4.2","7.5.1","7.5.2","7.6.1","7.6.2"],
                "authorization": ["8.1.1","8.2.1","8.2.2","8.3.1","8.4.1"],
                "jwt_token": ["9.1.1","9.1.2","9.1.3","9.2.1"],
                "oauth": ["10.1.1","10.1.2","10.2.1","10.2.2","10.3.1","10.3.2","10.3.3","10.3.4","10.4.1","10.4.2","10.4.3","10.4.4","10.4.5","10.5.1","10.5.2","10.5.3","10.5.4","10.5.5","10.6.1","10.6.2","10.7.1","10.7.2","10.7.3"],
                "crypto_tls": ["11.1.1","11.1.2","11.2.1","11.2.2","11.2.3","11.3.1","11.3.2","11.4.1","11.5.1","11.6.1","12.1.1","12.2.1","12.2.2","12.3.1","12.3.2","12.3.3","12.3.4"],
                "api_scm_client": ["13.1.1","13.2.1","13.2.2","13.2.3","13.2.4","13.2.5","13.3.1","13.3.2","13.4.1","14.1.1","14.1.2","14.2.1","14.3.1"],
                "dependencies": ["15.1.1","15.2.1","15.3.1"],
                "audit_logging": ["16.1.1","16.2.1","16.2.2","16.2.3","16.2.4","16.2.5","16.3.1","16.3.2","16.3.3","16.3.4","16.4.1","16.4.2","16.4.3","16.5.1","16.5.2","16.5.3"],
                "webrtc": ["17.1.1","17.2.1","17.2.2","17.2.3","17.2.4","17.3.1","17.3.2"],
            }
            print(f"  Using default ATR domain groups: {len(DOMAIN_GROUPS)} domains", flush=True)

        section_to_domain = {}
        for domain, sections in DOMAIN_GROUPS.items():
            for section in sections:
                section_to_domain[section] = domain

        chapter_domain_map = {}
        for domain, sections in DOMAIN_GROUPS.items():
            for section in sections:
                chapter = ".".join(section.split(".")[:2])
                chapter_domain_map[chapter] = domain

        domain_reports = {domain: {} for domain in DOMAIN_GROUPS}
        domain_reports["misc"] = {}

        for report_key, extracted in all_extracted.items():
            asvs_section = extracted.get("asvs_section", "")
            if not asvs_section:
                filename_part = report_key.split(":")[-1] if ":" in report_key else report_key
                match = re.match(r'(\d+\.\d+\.\d+)', filename_part)
                if match:
                    asvs_section = match.group(1)

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
            print(f"  {domain}: {len(rpts)} reports, {finding_count} findings")

        CONSOLIDATION_PROMPT = f"""You are a security audit consolidator. You are given extracted findings from multiple ASVS audit reports within the SAME security domain.

Audit scope: up to {level}

Your job is to:
1. **Identify TRUE duplicates**: The EXACT same vulnerability in the EXACT same code location. Merge these into ONE finding.
2. **Preserve EVERY unique finding**. If in doubt, keep findings SEPARATE.
3. **Track ASVS levels**: Each finding must list which ASVS level(s) apply based on its ASVS sections.
4. **Use the ASVS requirement descriptions** provided to understand what each section tests for.
5. **Do NOT add cross-references between findings.**

**Deduplication test**: If a developer could fix one WITHOUT fixing the other, they are SEPARATE findings.

Return valid JSON:
{{
  "domain": "domain_name",
  "consolidated_findings": [
    {{
      "temp_id": "DOMAIN-N",
      "severity": "Critical|High|Medium|Low|Informational",
      "title": "descriptive title",
      "description": "full description",
      "cwe": "CWE-NNN or null",
      "asvs_sections": ["X.Y.Z", ...],
      "asvs_levels": ["L1", "L2"],
      "affected_files": [{{"file": "path", "line": "N"}}],
      "source_reports": ["filename.md", ...],
      "recommended_remediation": "specific fix",
      "merged_from": ["original finding IDs"]
    }}
  ],
  "positive_controls": [
    {{"control": "description", "evidence": "where observed", "files": ["file:line"]}}
  ],
  "asvs_statuses": {{
    "X.Y.Z": {{"status": "Pass|Fail|Partial|N/A", "title": "section title"}}
  }},
  "dedup_log": [
    "Merged FINDING-X with FINDING-Y because: reason"
  ]
}}"""

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
                        f"- **{sid}** ({get_asvs_level(sid)}, {ctx['section_name']}): "
                        f"{ctx['req_description'][:300]}"
                    )
            if not ctx_lines:
                return ""
            return "\n\n## ASVS Requirement Descriptions\n" + "\n".join(ctx_lines)

        async def consolidate_domain(domain, rpts):
            cached = consolidation_ns.get(domain)
            if cached:
                print(f"  {domain}: cached ({len(cached.get('consolidated_findings', []))} findings)")
                return domain, cached

            async with consolidation_semaphore:
                print(f"  {domain}: consolidating {len(rpts)} reports...", flush=True)
                domain_data = json.dumps(rpts, indent=2, default=str)
                asvs_block = build_asvs_context_block(rpts)
                user_msg = f"Domain: {domain}{asvs_block}\n\nExtracted findings:\n\n{domain_data}"
                messages = [{"role": "user", "content": f"{CONSOLIDATION_PROMPT}\n\n{user_msg}"}]

                msg_tokens = count_message_tokens(messages, FAST_PROVIDER, FAST_MODEL)
                limit = int(FAST_CONTEXT_WINDOW * 0.80)

                if msg_tokens > limit:
                    items = list(rpts.items())
                    mid = len(items) // 2
                    sub_results = []
                    for si, sub in enumerate([dict(items[:mid]), dict(items[mid:])]):
                        sub_data = json.dumps(sub, indent=2, default=str)
                        sub_asvs = build_asvs_context_block(sub)
                        sub_msg = f"Domain: {domain} (sub-group {si+1}/2){sub_asvs}\n\nFindings:\n\n{sub_data}"
                        sub_messages = [{"role": "user", "content": f"{CONSOLIDATION_PROMPT}\n\n{sub_msg}"}]
                        try:
                            result, _ = await call_llm(
                                provider=FAST_PROVIDER, model=FAST_MODEL,
                                messages=sub_messages,
                                parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=600,
                            )
                            json_match = re.search(r'\{[\s\S]*\}', result)
                            if json_match:
                                sub_results.append(json.loads(json_match.group()))
                        except Exception as e:
                            print(f"    ERROR in sub-group {si+1}: {e}")
                    if sub_results:
                        merged = {"domain": domain, "consolidated_findings": [], "positive_controls": [], "asvs_statuses": {}, "dedup_log": []}
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
                        provider=FAST_PROVIDER, model=FAST_MODEL,
                        messages=messages,
                        parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=600,
                    )
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        consolidated = json.loads(json_match.group())
                        consolidation_ns.set(domain, consolidated)
                        print(f"    Result: {len(consolidated.get('consolidated_findings', []))} findings")
                        return domain, consolidated
                    return domain, None
                except Exception as e:
                    print(f"    ERROR: {e}")
                    return domain, None

        consolidation_results = await asyncio.gather(*[
            consolidate_domain(domain, rpts) for domain, rpts in domain_reports.items()
        ])

        for domain, consolidated in consolidation_results:
            if consolidated:
                domain_consolidated[domain] = consolidated
            else:
                rpts = domain_reports[domain]
                fallback = {"domain": domain, "consolidated_findings": [], "positive_controls": [], "asvs_statuses": {}, "dedup_log": []}
                for report_key, extracted in rpts.items():
                    for fi, finding in enumerate(extracted.get("findings", [])):
                        asvs_sec = finding.get("asvs_section", "")
                        fallback["consolidated_findings"].append({
                            "temp_id": f"{domain.upper()}-{fi+1}",
                            "severity": finding.get("severity", "Medium"),
                            "title": finding.get("title", "Unknown"),
                            "description": finding.get("description", ""),
                            "cwe": finding.get("cwe"),
                            "asvs_sections": [asvs_sec],
                            "asvs_levels": [get_asvs_level(asvs_sec)],
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
                        }
                    fallback["positive_controls"].extend(extracted.get("positive_controls", []))
                domain_consolidated[domain] = fallback

        total_consolidated = sum(len(d.get("consolidated_findings", [])) for d in domain_consolidated.values())
        print(f"\nTotal consolidated findings (pre-cross-domain): {total_consolidated}")

        # ============================================================
        # PHASE 3.5: Cross-Domain Deduplication
        # ============================================================
        print("\n=== PHASE 3.5: Cross-domain deduplication ===")

        xd_all = []
        for domain, data in domain_consolidated.items():
            for fi, finding in enumerate(data.get("consolidated_findings", [])):
                finding["_xd_domain"] = domain
                finding["_xd_idx"] = fi
                xd_all.append(finding)

        def primary_file(finding):
            af = finding.get("affected_files", [])
            if not af:
                return ""
            first = af[0]
            if isinstance(first, dict):
                return first.get("file", "").split(":")[0].split(" (")[0].strip().strip("`")
            return str(first).split(":")[0].split(" (")[0].strip().strip("`")

        def norm_title(t):
            t = t.lower().strip()
            for noise in ["completely ", "critical: ", "high: ", "medium: ", "low: "]:
                t = t.replace(noise, "")
            t = re.sub(r'[^a-z0-9 ]', '', t)
            t = re.sub(r'\s+', ' ', t).strip()
            return t

        file_groups = {}
        for finding in xd_all:
            pf = primary_file(finding)
            if pf:
                file_groups.setdefault(pf, []).append(finding)

        xd_merge_count = 0
        xd_removed = set()

        def merge_into(primary, duplicate):
            for sr in duplicate.get("source_reports", []):
                if sr not in primary.get("source_reports", []):
                    primary.setdefault("source_reports", []).append(sr)
            for sec in duplicate.get("asvs_sections", []):
                if sec not in primary.get("asvs_sections", []):
                    primary.setdefault("asvs_sections", []).append(sec)
            for lv in duplicate.get("asvs_levels", []):
                if lv not in primary.get("asvs_levels", []):
                    primary.setdefault("asvs_levels", []).append(lv)
            primary.setdefault("merged_from", []).append(duplicate.get("temp_id", "unknown"))
            if len(duplicate.get("description", "")) > len(primary.get("description", "")):
                primary["description"] = duplicate["description"]
            if len(duplicate.get("recommended_remediation", "")) > len(primary.get("recommended_remediation", "")):
                primary["recommended_remediation"] = duplicate["recommended_remediation"]

        for pf, group in file_groups.items():
            if len(group) < 2:
                continue
            title_clusters = {}
            for finding in group:
                nt = norm_title(finding.get("title", ""))
                title_clusters.setdefault(nt, []).append(finding)
            for nt, cluster in title_clusters.items():
                if len(cluster) < 2:
                    continue
                cluster.sort(key=lambda f: len(f.get("source_reports", [])), reverse=True)
                primary = cluster[0]
                for duplicate in cluster[1:]:
                    dup_key = (duplicate["_xd_domain"], duplicate["_xd_idx"])
                    if dup_key in xd_removed:
                        continue
                    merge_into(primary, duplicate)
                    xd_removed.add(dup_key)
                    xd_merge_count += 1

        # LLM-assisted dedup for large file groups
        xd_llm_groups = {pf: [f for f in group if (f["_xd_domain"], f["_xd_idx"]) not in xd_removed]
                         for pf, group in file_groups.items()}
        xd_llm_groups = {pf: g for pf, g in xd_llm_groups.items() if len(g) >= 3}

        if xd_llm_groups:
            XD_DEDUP_PROMPT = """You are deduplicating security findings that affect the SAME file but came from DIFFERENT ASVS domain groups.

Two findings are TRUE DUPLICATES if they describe the EXACT SAME bug and a developer fixing one would fix the other.

Return JSON: {"merges": [{"keep": "TEMP-ID", "absorb": ["TEMP-ID-1"], "reason": "same bug"}]}
If no duplicates: {"merges": []}"""

            for pf, group in xd_llm_groups.items():
                group_data = [{"temp_id": f"{f['_xd_domain']}:{f.get('temp_id','?')}", "title": f.get("title",""), "description": f.get("description","")[:500], "asvs_sections": f.get("asvs_sections",[]), "affected_files": f.get("affected_files",[])[:3]} for f in group]
                messages = [{"role": "user", "content": f"{XD_DEDUP_PROMPT}\n\nFile: {pf}\n\n{json.dumps(group_data, indent=2, default=str)}"}]
                if count_message_tokens(messages, FAST_PROVIDER, FAST_MODEL) > int(FAST_CONTEXT_WINDOW * 0.60):
                    continue
                try:
                    result, _ = await call_llm(provider=FAST_PROVIDER, model=FAST_MODEL, messages=messages, parameters=FAST_PARAMS, timeout=120)
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        dedup_result = json.loads(json_match.group())
                        lookup = {f"{f['_xd_domain']}:{f.get('temp_id','?')}": f for f in group}
                        for merge in dedup_result.get("merges", []):
                            keep = lookup.get(merge.get("keep",""))
                            if not keep:
                                continue
                            for abs_key in merge.get("absorb", []):
                                abs_f = lookup.get(abs_key)
                                if abs_f and (abs_f["_xd_domain"], abs_f["_xd_idx"]) not in xd_removed:
                                    merge_into(keep, abs_f)
                                    xd_removed.add((abs_f["_xd_domain"], abs_f["_xd_idx"]))
                                    xd_merge_count += 1
                except Exception:
                    pass

        if xd_removed:
            for domain, data in domain_consolidated.items():
                data["consolidated_findings"] = [f for fi, f in enumerate(data.get("consolidated_findings", [])) if (domain, fi) not in xd_removed]
            for domain, data in domain_consolidated.items():
                for f in data.get("consolidated_findings", []):
                    f.pop("_xd_domain", None)
                    f.pop("_xd_idx", None)

        total_after_xd = sum(len(d.get("consolidated_findings", [])) for d in domain_consolidated.values())
        print(f"Cross-domain dedup: {xd_merge_count} merges, {total_consolidated} → {total_after_xd} findings")

        # ============================================================
        # PHASE 4: Final Merge and Report Generation
        # ============================================================
        print("\n=== PHASE 4: Final merge and report generation ===")

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
        all_findings = []

        for domain, data in domain_consolidated.items():
            for finding in data.get("consolidated_findings", []):
                finding["_domain"] = domain
                if "asvs_levels" not in finding or not finding["asvs_levels"]:
                    levels = set()
                    for sec in finding.get("asvs_sections", []):
                        levels.add(get_asvs_level(sec))
                    finding["asvs_levels"] = sorted(levels) if levels else [level]
                all_findings.append(finding)

        all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "Informational"), 4))

        for i, finding in enumerate(all_findings, 1):
            finding["global_id"] = f"FINDING-{i:03d}"

        # Cross-references
        print("Building cross-references...")

        def extract_primary_file(finding):
            af = finding.get("affected_files", [])
            if not af:
                return ""
            first = af[0]
            raw = first.get("file", "") if isinstance(first, dict) else str(first)
            return re.sub(r'[:\s(].*', '', raw).strip().strip("`")

        def extract_function_names(finding):
            names = set()
            for af in finding.get("affected_files", []):
                raw = af.get("file", "") if isinstance(af, dict) else str(af)
                for m in re.finditer(r'(?:^|[:\s])([a-zA-Z_]\w*(?:\.\w+)*)\s*\(', raw):
                    names.add(m.group(1))
            return names

        by_file, by_cwe, by_func = {}, {}, {}
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

        for finding in all_findings:
            gid = finding["global_id"]
            related = set()
            cwe = finding.get("cwe", "")
            if cwe == "null":
                cwe = ""
            if cwe and cwe in by_cwe:
                related |= by_cwe[cwe]
            for fn in extract_function_names(finding):
                if fn in by_func:
                    related |= by_func[fn]
            pf = extract_primary_file(finding)
            if pf and pf in by_file:
                for oid in by_file[pf]:
                    if oid == gid:
                        continue
                    other = next((f for f in all_findings if f["global_id"] == oid), None)
                    if not other:
                        continue
                    ocwe = other.get("cwe", "")
                    if ocwe == "null":
                        ocwe = ""
                    if (cwe and ocwe and cwe == ocwe) or (extract_function_names(finding) & extract_function_names(other)):
                        related.add(oid)
            related.discard(gid)
            finding["related_findings"] = sorted(related)[:10] if related else []

        all_asvs_statuses = {}
        for domain, data in domain_consolidated.items():
            for section, info in data.get("asvs_statuses", {}).items():
                all_asvs_statuses[section] = info
        for rk, extracted in all_extracted.items():
            section = extracted.get("asvs_section", "")
            if section and section not in all_asvs_statuses:
                all_asvs_statuses[section] = {
                    "status": extracted.get("asvs_status", "Unknown"),
                    "title": extracted.get("asvs_section_title", ""),
                }

        all_positive_controls = []
        for domain, data in domain_consolidated.items():
            for ctrl in data.get("positive_controls", []):
                ctrl["_domain"] = domain
                all_positive_controls.append(ctrl)

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in all_findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        commit_info = "N/A"
        for part in directories[0].split("/"):
            if len(part) >= 7 and re.match(r'^[0-9a-f]+$', part):
                commit_info = part
                break

        findings_by_severity = {}
        for f in all_findings:
            findings_by_severity.setdefault(f.get("severity", "Informational"), []).append(f)

        # Executive summary (Opus)
        print(f"Generating executive summary...")
        severity_scope = f"Severity threshold: {severity_threshold} and above" if severity_threshold else "Severity threshold: none (all findings included)"

        exec_summary_prompt = f"""Generate the opening sections of a security audit consolidated report in Markdown.

Audit scope: up to {level}
{severity_scope}

Repository: {owner}/{repo}
Directories: {', '.join(directories)}
ASVS Level: {level}
{severity_scope}
Commit: {commit_info}
Date: {audit_date}
Auditor: Tooling Agents
Source reports: {total_reports}
Total findings: {len(all_findings)}

Severity: Critical={severity_counts.get('Critical',0)}, High={severity_counts.get('High',0)}, Medium={severity_counts.get('Medium',0)}, Low={severity_counts.get('Low',0)}, Info={severity_counts.get('Informational',0)}

Finding titles:
"""
        for f in all_findings:
            lvs = ", ".join(f.get("asvs_levels", []))
            exec_summary_prompt += f"- [{f.get('severity')}] [{lvs}] {f.get('global_id')}: {f.get('title')} (ASVS: {', '.join(f.get('asvs_sections', []))})\n"

        exec_summary_prompt += f"""
Positive controls: {json.dumps(all_positive_controls[:50], indent=2, default=str)}

Generate ONLY:
1. Report Metadata table (Repository, ASVS Level, Severity Threshold, Commit, Date, Auditor, Source Reports, Total Findings)
2. Executive Summary with severity distribution, level coverage, top 5 risks, positive controls

End with ---."""

        exec_result, _ = await call_llm(provider=HEAVY_PROVIDER, model=HEAVY_MODEL,
            messages=[{"role": "user", "content": exec_summary_prompt}],
            parameters={**HEAVY_PARAMS, "max_tokens": 32000}, timeout=900)
        exec_result = sanitize_md_html(exec_result)

        # Findings (Sonnet, batched)
        FINDING_FORMAT = """For each finding: #### FINDING-NNN: Title, attribute table (Severity, ASVS Level(s), CWE, ASVS sections, Files, Source Reports, Related), Description, Remediation. Use emojis: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ⚪ Info. Separate with ---."""

        findings_md_parts = []
        MAX_PER_BATCH = 30
        sev_section_names = {"Critical": "3.1 Critical", "High": "3.2 High", "Medium": "3.3 Medium", "Low": "3.4 Low", "Informational": "3.5 Informational"}

        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            sev_findings = findings_by_severity.get(sev, [])
            if not sev_findings:
                continue
            for sb_idx in range(0, len(sev_findings), MAX_PER_BATCH):
                batch = sev_findings[sb_idx:sb_idx + MAX_PER_BATCH]
                is_first = (sb_idx == 0)
                prompt = f"""Format these {len(batch)} {sev} findings into Markdown.\n{FINDING_FORMAT}\n{"Start with: ### " + sev_section_names[sev] if is_first else "Continue. No header."}\n\n{json.dumps(batch, indent=2, default=str)}\n\nGenerate ALL {len(batch)} findings with full detail."""
                for attempt in range(3):
                    try:
                        result, _ = await call_llm(provider=FAST_PROVIDER, model=FAST_MODEL,
                            messages=[{"role": "user", "content": prompt}],
                            parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900)
                        findings_md_parts.append(sanitize_md_html(result))
                        break
                    except Exception as e:
                        if attempt < 2:
                            await asyncio.sleep(5)

        # Tail sections (Sonnet)
        tail_prompt = f"""Generate final sections:\n## 4. Positive Security Controls (table)\n## 5. ASVS Compliance Summary (table with status)\n## 6. Cross-Reference Matrix\n\nPositive controls: {json.dumps(all_positive_controls[:100], indent=2, default=str)}\nASVS statuses: {json.dumps(all_asvs_statuses, indent=2, default=str)}\nFindings: {json.dumps([{"id": f["global_id"], "sev": f["severity"], "title": f["title"], "asvs": f.get("asvs_sections",[])} for f in all_findings], indent=2, default=str)}"""

        try:
            tail_result, _ = await call_llm(provider=FAST_PROVIDER, model=FAST_MODEL,
                messages=[{"role": "user", "content": tail_prompt}],
                parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900)
            tail_result = sanitize_md_html(tail_result)
        except:
            tail_result = "\n*Tail sections generation failed.*\n"

        # Assemble
        consolidated_md = exec_result.rstrip() + "\n\n## 3. Findings\n\n" + "\n\n".join(findings_md_parts) + "\n\n---\n\n" + tail_result

        # Section 7: Level Coverage (deterministic)
        s7 = ["\n\n## 7. Level Coverage Analysis\n", f"\n**Audit scope:** up to {level}\n"]
        if severity_threshold:
            s7.append(f"**Severity threshold:** {severity_threshold} and above\n")
        s7.append("| Level | Sections Audited | Findings Found |")
        s7.append("|-------|-----------------|----------------|")
        for lv_name, lv_num in [("L1", 1), ("L2", 2), ("L3", 3)]:
            if lv_num > max_level_num:
                continue
            lv_sections = sum(1 for rk, ext in all_extracted.items() if get_asvs_level(ext.get("asvs_section", "")) == lv_name)
            lv_findings = [f for f in all_findings if lv_name in f.get("asvs_levels", [])]
            s7.append(f"| {lv_name} | {lv_sections} | {len(lv_findings)} |")
        s7.append(f"\n**Total consolidated findings: {len(all_findings)}**")
        s7.append("\n*End of Consolidated Security Audit Report*")
        consolidated_md += "\n".join(s7)

        # Issues file
        informational_ids = set(f["global_id"] for f in all_findings if "informational" in f.get("severity","").lower())
        actionable = [f for f in all_findings if f["global_id"] not in informational_ids]

        ISSUE_FMT = """---\n## Issue: FINDING-NNN - Title\n**Labels:** bug, security, priority:sev\n**Description:**\n### Summary\n### Details\n### Remediation\n### Acceptance Criteria\n- [ ] Fixed\n- [ ] Test added\n### References\n### Priority"""

        issues_parts = []
        for bi in range(0, len(actionable), 75):
            batch = actionable[bi:bi+75]
            is_first = (bi == 0)
            prompt = f"""Generate GitHub issues for {len(batch)} findings.\n{ISSUE_FMT}\n{"Start with: # Security Issues" if is_first else "Continue. No header."}\n\n{json.dumps(batch, indent=2, default=str)}"""
            for attempt in range(3):
                try:
                    result, _ = await call_llm(provider=FAST_PROVIDER, model=FAST_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                        parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900)
                    issues_parts.append(sanitize_md_html(result))
                    break
                except:
                    if attempt < 2:
                        await asyncio.sleep(5)
                    else:
                        # Fallback
                        fb = []
                        for f in batch:
                            fb.append(f"---\n\n## Issue: {f['global_id']} - {sanitize_md_html(f.get('title',''))}\n\n**Labels:** bug, security, priority:{f.get('severity','Medium').lower()}\n\n**Description:**\n\n{sanitize_md_html(f.get('description',''))}\n\n**Remediation:** {sanitize_md_html(f.get('recommended_remediation',''))}\n\n**Priority:** {f.get('severity','Medium')}")
                        issues_parts.append("\n\n".join(fb))

        issues_md = "\n\n".join(issues_parts)

        # Quality checks
        print(f"\n=== Quality Checks ===")
        finding_sections = set(re.findall(r'#### FINDING-(\d{3})', consolidated_md))
        print(f"Finding sections: {len(finding_sections)} (expected: {len(all_findings)})")
        issue_headers = set(re.findall(r'## Issue: (FINDING-\d{3})', issues_md))
        print(f"Issues: {len(issue_headers)} (expected: {len(actionable)})")

        # Push to GitHub
        print("\n=== Pushing files ===")

        async def push_file(path, content_str, message):
            existing_sha = None
            check = await http_client.get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", headers=headers, params={"ref": default_branch})
            if check.status_code == 200:
                existing_sha = check.json().get("sha")
            payload = {"message": message, "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"), "branch": default_branch}
            if existing_sha:
                payload["sha"] = existing_sha
            resp = await http_client.put(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", headers=headers, json=payload)
            print(f"  {'OK' if resp.status_code in (200,201) else 'ERROR'}: {path}")

        await push_file(f"{output_directory}/{consolidated_filename}", consolidated_md, f"Add consolidated audit report ({level})")
        await push_file(f"{output_directory}/{issues_filename}", issues_md, f"Add security issues ({level})")

        print(f"\n=== Done ===")
        print(f"Total findings: {len(all_findings)}, Actionable issues: {len(actionable)}")

        return {
            "outputText": f"Consolidated report and issues pushed.\n"
                          f"Repository: {owner}/{repo}\n"
                          f"Level: {level}\n"
                          f"Findings: {len(all_findings)}\n"
                          f"Files: {output_directory}/{consolidated_filename}, {output_directory}/{issues_filename}"
        }
    finally:
        await http_client.aclose()