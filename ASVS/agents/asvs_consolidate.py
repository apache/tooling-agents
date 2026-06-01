# asvs_consolidate
#
# Reads per-section reports from GitHub, deduplicates findings within and
# across domains, and produces the final consolidated.md report and
# issues.md (one issue per actionable finding).
#
# Improvements over original:
#   - Phase 1 file reads now run in parallel (was sequential per file).
#     Saves ~30-90 sec per repo on Phase 1.
#   - Final consolidated.md and issues.md pushes run in parallel.
#   - extraction_semaphore raised 5 → 8; consolidation_semaphore 3 → 5
#     (Sonnet has plenty of headroom on Bedrock).
#
# Same I/O contract — drop-in replacement.

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    # Configure httpx with explicit timeouts, connection limits, and transport
    # retries. With 345 reports being fetched in Phase 1, the default httpx
    # client (5s read timeout, no connection pool limit, no retries) can
    # produce mid-request errors that stringify to empty and obscure the
    # actual failure cause. Match the asvs_push_github agent's posture.
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=15.0, read=60.0, write=60.0, pool=60.0),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        transport=httpx.AsyncHTTPTransport(retries=3),
    )
    try:
        import json
        import re
        import ast

        def parse_llm_json(raw):
            """Parse JSON from LLM output with multiple fallbacks for common issues."""
            # 1. Standard JSON
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                pass

            # 2. Fix single-quoted keys/values (most common Sonnet issue)
            try:
                # Replace single quotes used as JSON delimiters with double quotes
                # This is naive but catches {'key': 'value'} patterns
                fixed = re.sub(r"(?<=[{,\[])\s*'([^']+)'\s*:", r' "\1":', raw)
                fixed = re.sub(r":\s*'([^']*)'", r': "\1"', fixed)
                # Fix trailing commas
                fixed = re.sub(r",\s*([}\]])", r"\1", fixed)
                return json.loads(fixed)
            except (json.JSONDecodeError, Exception):
                pass

            # 3. Python literal (handles True/False/None + single quotes)
            try:
                return ast.literal_eval(raw)
            except Exception:
                pass

            # 4. Last resort: strip non-JSON wrapper and retry
            try:
                # Sometimes Sonnet wraps JSON in markdown or extra text
                inner = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', raw)
                if inner:
                    return json.loads(inner.group())
            except Exception:
                pass

            raise json.JSONDecodeError("All parsing strategies failed", raw, 0)

        def _extract_finding_json(model_output):
            """Find a JSON object in the model's response that matches the extraction schema.

            The original extraction regex required the JSON to begin with one of
            {asvs_section, findings, asvs_status} as its FIRST key. Sonnet 4.5
            follows the prompt template literally, which lists "source_report"
            first — so the regex never matched and consolidation got 0 findings
            even when per-section reports clearly contained findings.

            This walks every balanced top-level {...} block in the response and
            returns the first one that parses as JSON AND contains any of the
            expected extraction-schema keys. Robust to:
              - any key ordering
              - markdown code fences (opening AND closing)
              - prose preamble or trailing text
              - nested braces inside string values (tracks string state)
              - multiple JSON blocks where only one matches the schema
              - trailing commas (lenient parse fallback)
            """
            if not model_output:
                return None

            # Strip code fences (both opening AND closing)
            cleaned = re.sub(r'```(?:json|JSON)?\s*\n?', '', model_output)
            cleaned = cleaned.replace('```', '')

            SCHEMA_KEYS = {
                'source_report', 'asvs_section', 'findings', 'asvs_status',
                'asvs_section_title', 'positive_controls',
            }

            n = len(cleaned)
            i = 0
            while i < n:
                if cleaned[i] != '{':
                    i += 1
                    continue
                depth = 0
                in_string = False
                escape = False
                end = -1
                for j in range(i, n):
                    ch = cleaned[j]
                    if escape:
                        escape = False
                        continue
                    if ch == '\\' and in_string:
                        escape = True
                        continue
                    if ch == '"':
                        in_string = not in_string
                        continue
                    if in_string:
                        continue
                    if ch == '{':
                        depth += 1
                    elif ch == '}':
                        depth -= 1
                        if depth == 0:
                            end = j + 1
                            break
                if end < 0:
                    return None  # Unbalanced braces from here on
                candidate = cleaned[i:end]
                try:
                    obj = json.loads(candidate)
                except json.JSONDecodeError:
                    # Lenient: strip trailing commas and retry
                    try:
                        lenient = re.sub(r',(\s*[}\]])', r'\1', candidate)
                        obj = json.loads(lenient)
                    except json.JSONDecodeError:
                        i = end
                        continue
                if isinstance(obj, dict) and (set(obj.keys()) & SCHEMA_KEYS):
                    return obj
                i = end

            return None

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
                # Convert <br> tags to comma-space before generic HTML escape.
                # Sonnet sometimes emits <br> inside table cells to vertically
                # stack multiple values (file lists, etc.). The generic escape
                # below would render them as literal "<br>" text in the output,
                # which is ugly; replacing with ", " produces a readable
                # single-line list. Both <br> and <br /> variants are handled.
                s = re.sub(r'<\s*br\s*/?\s*>', ', ', s, flags=re.IGNORECASE)
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

        # Redact tokens before any logging. GitHub PATs come in several
        # prefixes (github_pat_*, ghp_*, ghs_*, ghu_*, gho_*, ghr_*) and
        # may be tens of chars long. Replace with a fixed marker that
        # preserves visibility of the surrounding structure but never the
        # secret itself.
        def _redact_secrets(s):
            if not s:
                return s
            # GitHub tokens — redact value while keeping the prefix visible
            # so debug output is still useful.
            s = re.sub(r'\bgithub_pat_[A-Za-z0-9_]+', 'github_pat_<REDACTED>', s)
            s = re.sub(r'\bgh[psour]_[A-Za-z0-9_]+', lambda m: m.group(0)[:4] + '<REDACTED>', s)
            # Also handle our agents' "pat: <value>" / "token: <value>" /
            # "Authorization: Bearer <value>" line forms in case future
            # callers use a token format we don't recognize.
            s = re.sub(
                r'(?im)^(\s*(?:pat|token|authorization)\s*:\s*)\S+',
                r'\1<REDACTED>',
                s,
            )
            s = re.sub(
                r'(?i)(Bearer\s+)[A-Za-z0-9_\-\.]+',
                r'\1<REDACTED>',
                s,
            )
            return s

        # Useful for verifying input structure without leaking secrets.
        # Preview is bounded AND redacted; never log raw input.
        _preview = _redact_secrets(input_text[:500])
        print(f"DEBUG raw input (redacted): {repr(_preview)}", flush=True)
        lines = input_text.strip().split("\n")
        owner_repo = ""
        pat = ""
        directories_raw = ""
        output_directory = ""
        sections_raw = ""
        source_id = ""
        reports_namespace_arg = ""
        branch = ""
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
                elif key in ("sections", "section_ids", "asvs_sections"):
                    sections_raw = value
                elif key in ("source", "source_id", "source_repo"):
                    source_id = value
                elif key in ("reports_namespace", "reportsnamespace", "report_namespace"):
                    reports_namespace_arg = value
                elif key == "branch":
                    branch = value

        directories = [d.strip().strip("/") for d in directories_raw.split(",") if d.strip()]
        # Optional: list of section IDs (e.g. "1.2.1, 1.2.2, 2.1.1") that
        # constrain which per-section reports we'll read. When provided,
        # any file whose name doesn't match one of these section IDs is
        # skipped. This prevents stale reports from prior runs (left in
        # the same directory) from polluting consolidation.
        section_filter = set()
        if sections_raw:
            for s in sections_raw.split(","):
                s = s.strip()
                if s:
                    section_filter.add(s)

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
        HEAVY_MODEL = "us.anthropic.claude-opus-4-8"
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
        # PHASE 1: Read All Reports from CouchDB
        # ============================================================
        # Per-section reports were previously fetched from GitHub via
        # repos/{owner}/{repo}/contents/{dir}/{name}.md, requiring 345+
        # parallel HTTP calls under L3 load. Now they live in CouchDB
        # under reports_namespace_arg, keyed as "{pass_name}/{N.N.N.md}".
        # CouchDB reads are local, fast, and rate-limit-free.
        print("\n=== PHASE 1: Reading all reports ===")

        if not reports_namespace_arg:
            return {
                "outputText": "Error: reports_namespace not provided in input. "
                              "Caller (orchestrator) must pass `reports_namespace: ...` "
                              "so consolidate knows where to read per-section reports.",
            }

        reports = {}
        report_dirs = {}  # report_key -> pass-name it came from

        try:
            ns = data_store.use_namespace(reports_namespace_arg)
            all_keys = ns.list_keys() or []
            print(f"  Namespace {reports_namespace_arg}: {len(all_keys)} keys total", flush=True)
        except Exception as e:
            return {
                "outputText": f"Error: failed to read reports namespace "
                              f"{reports_namespace_arg}: {type(e).__name__}: {e}"
            }

        for directory in directories:
            # Each `directory` is now a pass-name prefix within the
            # reports namespace (e.g. "all" or "l1"), not a GitHub path.
            print(f"\n  Reading reports for pass '{directory}'...")
            pass_keys = [k for k in all_keys if k.startswith(directory + "/")]
            # Filter to per-section reports only (matches NN.NN.NN.md form).
            # Excludes any non-conforming filename that may have been written
            # under the same prefix.
            report_keys = []
            for k in pass_keys:
                fname = k.rsplit("/", 1)[-1]
                if not re.match(r'^\d+(?:\.\d+){2,}\.md$', fname):
                    continue
                # If a section filter was provided, only keep files whose
                # section ID is in the audited set.
                if section_filter:
                    sec_id = fname[:-3]  # strip ".md"
                    if sec_id not in section_filter:
                        continue
                report_keys.append(k)

            print(f"  Found {len(report_keys)} report keys")

            for k in report_keys:
                try:
                    content = ns.get(k)
                    if content is None:
                        print(f"    WARNING: {k} returned None", flush=True)
                        continue
                    # Stored value is a markdown string. Tolerate dict-wrapped
                    # values for forward compatibility.
                    if isinstance(content, dict):
                        content = content.get("report") or content.get("content") or json.dumps(content)
                    fname = k.rsplit("/", 1)[-1]
                    reports[fname] = content
                    report_dirs[fname] = directory
                except Exception as e:
                    print(f"    WARNING: {k} read failed: {type(e).__name__}: {e}", flush=True)

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

CRITICAL OUTPUT REQUIREMENTS — read carefully:
1. Output ONLY a single raw JSON object. No prose before or after. No markdown code fences. No "Here is the JSON" preamble.
2. Your entire response must start with `{` and end with `}`.
3. The JSON object MUST include all of these top-level keys: source_report, asvs_section, asvs_section_title, asvs_status, findings, positive_controls.
4. Use double quotes for all keys and string values. No trailing commas.

JSON schema:
{
  "source_report": "filename.md",
  "asvs_section": "X.Y.Z",
  "asvs_section_title": "Title",
  "asvs_status": "Pass|Fail|Partial|N/A",
  "findings": [...],
  "positive_controls": [{"control": "description", "evidence": "where observed", "files": ["file:line"]}]
}"""

        # GUARDRAIL: failure-shape patterns that may appear in stored
        # per-section reports. These indicate the audit pipeline failed
        # for the section rather than producing a real audit. The LLM
        # extraction step, given such content, tends to silently return
        # `{"findings": [], "asvs_status": "N/A"}` because the failure
        # text doesn't look like findings. Detecting these patterns up
        # front lets us tag the section as ERROR and surface in the
        # quality check rather than burying the failure as fake-N/A.
        #
        # The patterns must match content produced by:
        #   asvs_bundle.py     all-batches-failed envelope, no-files envelope
        #   asvs_orchestrate.py  _parse_audit_output ERROR stubs
        _FAILURE_PATTERNS = (
            "**Status:** ERROR",                            # orchestrator stubs
            '"error": "All analysis batches failed"',       # raw bundle envelope
            '"error": "No files found in namespaces',       # raw bundle envelope
            "did not return per-section output",            # legacy stub (pre-guardrails)
            "Bundled audit produced no output",             # legacy stub
        )

        def _detect_pipeline_failure(content):
            """Return (is_failure, marker_text) if the content looks like a
            pipeline-failure stub rather than a real audit report."""
            if not content:
                return False, None
            head = content[:1500]
            for pat in _FAILURE_PATTERNS:
                if pat in head:
                    return True, pat
            return False, None

        extraction_semaphore = asyncio.Semaphore(8)  # raised from 5
        all_extracted = {}
        extraction_errors = []
        pipeline_failure_sections = []  # surfaced in Quality Checks

        async def extract_report(report_key, content):
            # GUARDRAIL: short-circuit pipeline-failure content before
            # the LLM extraction call. This both saves a Sonnet call per
            # failed section and ensures the failure is recorded as ERROR
            # rather than the LLM's default-N/A interpretation.
            is_failure, marker = _detect_pipeline_failure(content)
            if is_failure:
                # Derive a best-effort ASVS section ID from the report key
                # (e.g., "oauth_openid_integration/10.1.1.md" -> "10.1.1").
                import re as _re
                m = _re.search(r'(\d+\.\d+(?:\.\d+)?)\.md$', report_key)
                section_id = m.group(1) if m else report_key
                print(
                    f"  {report_key}: PIPELINE FAILURE detected "
                    f"(marker={marker!r}); short-circuit extraction",
                    flush=True,
                )
                synthetic = {
                    "source_report": report_key,
                    "asvs_section": section_id,
                    "asvs_section_title": "",
                    "asvs_status": "ERROR",
                    "findings": [],
                    "positive_controls": [],
                    "_pipeline_failure": True,
                    "_pipeline_failure_marker": marker,
                }
                pipeline_failure_sections.append((report_key, section_id, marker))
                return report_key, synthetic, None

            # Cache key includes content hash so re-running against an updated
            # report file produces fresh extraction. Without this, the same
            # filename in the same directory always hits the cache regardless
            # of whether the content changed (e.g., after a rerun-sections.sh
            # cycle or a bundle-mode re-audit producing new findings).
            import hashlib
            content_hash = hashlib.sha256((content or "").encode()).hexdigest()[:16]
            cache_key = f"{report_key}:{content_hash}"

            cached = extraction_ns.get(cache_key)
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
                    extracted = _extract_finding_json(result)
                    if extracted is None:
                        # Diagnostic: log a snippet so debugging is possible without enabling DEBUG mode
                        snippet = (result or "").strip().replace("\n", " ")[:200]
                        print(f"WARNING: no JSON found (response begins: {snippet!r})")
                        return report_key, None, "No JSON in result"
                    extracted["source_report"] = report_key
                    extraction_ns.set(cache_key, extracted)
                    print(f"{len(extracted.get('findings', []))} findings, status: {extracted.get('asvs_status', '?')}")
                    return report_key, extracted, None
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

        consolidation_semaphore = asyncio.Semaphore(5)  # raised from 3
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
            # Cache key must change when the input findings change. Previously
            # the cache was keyed on just the domain name, which meant any
            # earlier consolidation result was reused regardless of how the
            # input had changed. After re-running audit with new findings,
            # the cache returned the old (stale) consolidation, silently
            # dropping all the new findings.
            #
            # Now the key incorporates a content hash of the input reports
            # so any change in the inputs produces a fresh consolidation.
            import hashlib
            rpts_repr = json.dumps(rpts, sort_keys=True, default=str)
            input_hash = hashlib.sha256(rpts_repr.encode()).hexdigest()[:16]
            cache_key = f"{domain}:{input_hash}"

            cached = consolidation_ns.get(cache_key)
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

                if msg_tokens > limit or len(rpts) > 25:
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
                                parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900,
                            )
                            json_match = re.search(r'\{[\s\S]*\}', result)
                            if json_match:
                                sub_results.append(parse_llm_json(json_match.group()))
                        except Exception as e:
                            print(f"    ERROR in sub-group {si+1}: {e}")
                    if sub_results:
                        merged = {"domain": domain, "consolidated_findings": [], "positive_controls": [], "asvs_statuses": {}, "dedup_log": []}
                        for sr in sub_results:
                            merged["consolidated_findings"].extend(sr.get("consolidated_findings", []))
                            merged["positive_controls"].extend(sr.get("positive_controls", []))
                            merged["asvs_statuses"].update(sr.get("asvs_statuses", {}))
                            merged["dedup_log"].extend(sr.get("dedup_log", []))
                        consolidation_ns.set(cache_key, merged)
                        return domain, merged
                    return domain, None

                try:
                    result, _ = await call_llm(
                        provider=FAST_PROVIDER, model=FAST_MODEL,
                        messages=messages,
                        parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900,
                    )
                    json_match = re.search(r'\{[\s\S]*\}', result)
                    if json_match:
                        consolidated = parse_llm_json(json_match.group())
                        consolidation_ns.set(cache_key, consolidated)
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
                        dedup_result = parse_llm_json(json_match.group())
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

        # n_actionable excludes Informational findings — those are recorded in
        # the consolidated report but deliberately not turned into issues.md
        # entries (they don't warrant GitHub tickets). Defined here so the
        # executive-summary metadata table, the deterministic cross-ref
        # footer, and the issues.md preamble can all reference the same
        # value without recomputing.
        n_actionable = len(all_findings) - severity_counts.get("Informational", 0)

        # The commit hash lives in `output_directory`, by convention as the
        # trailing path segment (e.g. "ASVS/reports/airflow/task-sdk/6431cd1").
        # The previous code searched `directories[0]`, but that's a discovered
        # domain name like "sentry_integration", not a path — so commit_info
        # always fell through to "N/A". We scan output_directory in reverse so
        # the trailing hash-shaped segment wins; a path component would have
        # to be entirely hex and 7+ chars to false-positive, which the usual
        # repo/component names (airflow-core, task-sdk, etc.) can't satisfy
        # because they contain hyphens or non-hex letters.
        commit_info = "N/A"
        for part in reversed(output_directory.split("/")):
            if len(part) >= 7 and re.match(r'^[0-9a-f]+$', part):
                commit_info = part
                break

        findings_by_severity = {}
        for f in all_findings:
            findings_by_severity.setdefault(f.get("severity", "Informational"), []).append(f)

        # Executive summary (Opus)
        print(f"Generating executive summary...")
        severity_scope = f"Severity threshold: {severity_threshold} and above" if severity_threshold else "Severity threshold: none (all findings included)"

        # Build the display identifier for the audited source. `source_id`
        # from the orchestrator looks like "owner/repo[/path] @ commit_hash";
        # for the Repository field we want just the path (the commit hash
        # is rendered as its own Commit field). Fall back to owner/repo —
        # the PUBLISHING target — only when source_id wasn't passed, which
        # is the legacy / direct-invoke case. The previous behaviour
        # unconditionally used owner/repo, which produced report titles
        # naming the wrong project (the output runbooks repo instead of
        # the audited code).
        source_display = source_id.split(" @ ", 1)[0] if source_id else f"{owner}/{repo}"

        exec_summary_prompt = f"""Generate the opening sections of a security audit consolidated report in Markdown.

Audit scope: up to {level}
{severity_scope}

Repository: {source_display}
Directories: {', '.join(directories)}
ASVS Level: {level}
{severity_scope}
Commit: {commit_info}
Date: {audit_date}
Auditor: Tooling Agents
Source reports: {total_reports}
Total findings: {len(all_findings)}
Actionable issues: {n_actionable}

Severity: Critical={severity_counts.get('Critical',0)}, High={severity_counts.get('High',0)}, Medium={severity_counts.get('Medium',0)}, Low={severity_counts.get('Low',0)}, Info={severity_counts.get('Informational',0)}

Finding titles:
"""
        for f in all_findings:
            lvs = ", ".join(f.get("asvs_levels", []))
            exec_summary_prompt += f"- [{f.get('severity')}] [{lvs}] {f.get('global_id')}: {f.get('title')} (ASVS: {', '.join(f.get('asvs_sections', []))})\n"

        exec_summary_prompt += f"""
Positive controls: {json.dumps(all_positive_controls[:50], indent=2, default=str)}

Generate ONLY:
1. The report title as a single H1 line in this EXACT form (do not paraphrase,
   add subtitles, alternative phrasings, or any taglines):
   `# Security Audit Consolidated Report — {source_display}`
2. Report Metadata table with these rows in this exact order:
   Repository, {"Branch, " if branch else ""}ASVS Level, Severity Threshold, Commit, Date, Auditor,
   Source Reports, Total Findings{", Actionable Issues" if n_actionable != len(all_findings) else ""}.
   Use `{source_display}` for the Repository cell.
   {"Use exactly `" + branch + "` for the Branch cell." if branch else ""}
   Use exactly `{len(all_findings)}` for the Total Findings cell.
   {"Use exactly `" + str(n_actionable) + "` for the Actionable Issues cell." if n_actionable != len(all_findings) else ""}
   {"Below the metadata table, add one italicised line: *Informational findings are recorded in this report but not opened as GitHub issues — see issues.md for the " + str(n_actionable) + " actionable items.*" if n_actionable != len(all_findings) else ""}
3. Executive Summary, in this exact structure:
   - "### Severity Distribution" heading, followed by a count-only
     table with EXACTLY these columns:
         | Severity | Count |
         |----------|-------|
         | Critical | <n>   |
         | High     | <n>   |
         | Medium   | <n>   |
         | Low      | <n>   |
         | Info     | <n>   |
     DO NOT include a Percentage column. DO NOT include a Total row.
     DO NOT add percentages anywhere else in the executive summary.
     Percentages of finding severities are not useful information
     for the reader and create confusion when the public variant of
     this report zeroes selected counts. Count-only is the only
     supported shape.
   - "### ASVS Level Coverage" heading with 1-2 sentences of prose.
   - "### Top 5 Risks" heading, followed by a numbered list (1.
     through 5.) of the highest-impact findings. For each item, use
     EXACTLY this shape:
         N. **<short title>** [<Severity>] — <one-sentence summary>
     Severity goes in square brackets at the END of the bold title,
     OUTSIDE any inline parentheticals. Do NOT embed severity inside
     the title in parens (e.g., do not write "Title (Critical)") —
     downstream redaction relies on the bracketed-suffix shape.
   - "### Positive Controls Observed" heading with the bulleted list
     or table of positive controls.

End with ---."""

        exec_result, _ = await call_llm(provider=HEAVY_PROVIDER, model=HEAVY_MODEL,
            messages=[{"role": "user", "content": exec_summary_prompt}],
            parameters={**HEAVY_PARAMS, "max_tokens": 32000}, timeout=900)
        exec_result = sanitize_md_html(exec_result)

        # Findings (Sonnet, batched)
        FINDING_FORMAT = """For each finding: #### FINDING-NNN: Title, attribute table (Severity, ASVS Level(s), CWE, ASVS sections, Files, Source Reports, Related), Description, Remediation. Use emojis: 🔴 Critical, 🟠 High, 🟡 Medium, 🔵 Low, ⚪ Info. Separate with ---.

For multi-value table cells (Files, Source Reports, etc.): use ", " (comma-space) to separate values within a single cell. NEVER use HTML <br> tags inside table cells. NEVER use newlines inside table cells. If the list is long, separate with ", " on a single line — markdown tables don't render multi-line cells reliably across viewers (especially GitHub)."""

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
                # Retries handled centrally in call_llm. On exhaustion the
                # batch's findings_md_parts entry is skipped — the rest of
                # the severity grouping still renders.
                try:
                    result, _ = await call_llm(provider=FAST_PROVIDER, model=FAST_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                        parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900)
                    findings_md_parts.append(sanitize_md_html(result))
                except Exception:
                    pass

        # ============================================================
        # Tail sections (deterministic — no LLM)
        # ============================================================
        # Sections 4, 5, 6 used to be LLM-generated from a minimal data
        # summary, which produced four distinct hallucination classes:
        #
        # 1. Cross-Reference Matrix "Affected Components" column was
        #    invented. The data summary fed to the LLM didn't include
        #    finding.affected_files, so the model filled the cell with
        #    plausible-sounding paths (e.g. FAB provider files cited
        #    for SimpleAuthManager findings, www/ paths cited for
        #    api_fastapi findings). Reader trusted them and they were
        #    wrong.
        # 2. ASVS Compliance Summary chapter headers used ASVS v4 names
        #    paired with v5 section numbers ("V7: Error Handling and
        #    Logging" labelling rows for 7.2.x Session Management).
        #    The model defaulted to training-data chapter titles
        #    rather than the actual chapter_name values loaded into
        #    chapters_cache during PHASE-load.
        # 3. Total Unique Findings footer was off by one ("7 Low, 2
        #    Medium" when the actual count was 8 Low + 2 Medium = 10).
        #    The LLM was re-counting from a partial JSON instead of
        #    reading severity_counts which is exact.
        # 4. Per-requirement "Notes" cells contained prose like "Jinja2
        #    auto-escaping enabled" with no evidence anywhere in the
        #    extracted audit data — the extraction schema doesn't
        #    capture per-section reasoning, so any prose there was
        #    fabricated.
        #
        # Everything below now reads from data we already have:
        #   - asvs_context[req_id]: req_description, section_name,
        #     chapter_name, level — loaded from the 'asvs' namespace
        #     at the start of this phase.
        #   - all_findings: full finding objects including
        #     affected_files, related_findings, asvs_sections.
        #   - all_asvs_statuses: per-requirement Pass/Partial/N/A/Fail
        #     status from the per-section extracted reports.
        #   - all_positive_controls: per-domain control list from the
        #     per-section extracted reports.
        #   - severity_counts: exact counts already computed above.
        #
        # The Notes column shows ONLY "See FINDING-XXX" cross-references
        # when a finding maps to the requirement. We don't synthesize
        # any other prose: the per-section reports in
        # audit-reports-filtered:* are the source of audit reasoning
        # and the reader can consult them directly.

        tail_lines = []

        # --- Section 4: Positive Security Controls ---
        tail_lines.append("# 4. Positive Security Controls")
        tail_lines.append("")
        if all_positive_controls:
            tail_lines.append("| Domain | Control | Evidence Source | Supporting Files |")
            tail_lines.append("|--------|---------|-----------------|------------------|")
            for ctrl in all_positive_controls:
                d_raw = ctrl.get("_domain", "") or ""
                d_disp = d_raw.replace("_", " ").title() if d_raw else "—"
                control = (ctrl.get("control") or "").replace("|", "\\|").replace("\n", " ").strip()
                evidence = (ctrl.get("evidence") or "").replace("|", "\\|").replace("\n", " ").strip()
                files_raw = ctrl.get("files", []) or []
                files_str = ", ".join(str(f).replace("|", "\\|") for f in files_raw if str(f).strip()) or "—"
                tail_lines.append(f"| {d_disp} | {control or '—'} | {evidence or '—'} | {files_str} |")
        else:
            tail_lines.append("*No positive controls recorded for this audit.*")
        tail_lines.append("")
        tail_lines.append("---")
        tail_lines.append("")

        # --- Section 5: ASVS Compliance Summary ---
        # Iterate audited requirement IDs in numeric order; group rows
        # under chapter headers pulled from asvs_context['chapter_name'].
        tail_lines.append("# 5. ASVS Compliance Summary")
        tail_lines.append("")
        tail_lines.append("| ASVS ID | Requirement Title | Status | Notes |")
        tail_lines.append("|---------|-------------------|--------|-------|")

        def _req_sort_key(rid):
            try:
                return tuple(int(p) for p in rid.split("."))
            except ValueError:
                # Malformed ids sort to the end rather than crashing.
                return (10**6,)

        # Reverse index: requirement id -> list of finding IDs that
        # reference it. Used only to fill the "Notes" column with
        # "See FINDING-..." references; never as a basis for prose.
        req_to_findings = {}
        for f in all_findings:
            for s in f.get("asvs_sections", []) or []:
                req_to_findings.setdefault(s, []).append(f["global_id"])

        audited_reqs = sorted(all_asvs_statuses.keys(), key=_req_sort_key)
        current_chapter = None
        for rid in audited_reqs:
            ctx = asvs_context.get(rid, {}) or {}
            chapter_id = rid.split(".", 1)[0] if "." in rid else rid
            if chapter_id != current_chapter:
                ch_name = ctx.get("chapter_name", "")
                header = f"**V{chapter_id}: {ch_name}**" if ch_name else f"**V{chapter_id}**"
                tail_lines.append(f"| {header} | | | |")
                current_chapter = chapter_id

            entry = all_asvs_statuses[rid] or {}
            status_raw = entry.get("status", "Unknown")
            status_display = f"**{status_raw}**"
            title = (ctx.get("req_description") or entry.get("title") or "").replace("|", "\\|").replace("\n", " ").strip()
            finding_refs = req_to_findings.get(rid, [])
            notes = ("See " + ", ".join(finding_refs)) if finding_refs else ""
            tail_lines.append(f"| {rid} | {title} | {status_display} | {notes} |")

        # Status counts — deterministic.
        n_pass = sum(1 for v in all_asvs_statuses.values() if (v or {}).get("status") == "Pass")
        n_partial = sum(1 for v in all_asvs_statuses.values() if (v or {}).get("status") == "Partial")
        n_na = sum(1 for v in all_asvs_statuses.values() if (v or {}).get("status") in ("N/A", "Not Applicable"))
        n_fail = sum(1 for v in all_asvs_statuses.values() if (v or {}).get("status") in ("Fail", "Failed", "Open"))
        n_total = len(all_asvs_statuses)
        n_other = n_total - n_pass - n_partial - n_na - n_fail

        tail_lines.append("")
        tail_lines.append("**Summary Statistics:**")
        if n_total > 0:
            tail_lines.append(f"- **Pass**: {n_pass} requirements ({n_pass * 100 / n_total:.1f}%)")
            tail_lines.append(f"- **Partial**: {n_partial} requirements ({n_partial * 100 / n_total:.1f}%)")
            tail_lines.append(f"- **N/A**: {n_na} requirements ({n_na * 100 / n_total:.1f}%)")
            tail_lines.append(f"- **Fail**: {n_fail} requirements ({n_fail * 100 / n_total:.1f}%)")
            if n_other > 0:
                tail_lines.append(f"- **Other / Unknown**: {n_other} requirements ({n_other * 100 / n_total:.1f}%)")
        else:
            tail_lines.append("- *No audited requirements.*")
        tail_lines.append("")
        tail_lines.append("---")
        tail_lines.append("")

        # --- Section 6: Cross-Reference Matrix ---
        # One row per finding. "Affected Components" is rendered
        # VERBATIM from finding.affected_files — no model in the loop.
        tail_lines.append("# 6. Cross-Reference Matrix")
        tail_lines.append("")
        if all_findings:
            tail_lines.append("| Finding ID | Severity | ASVS Requirements | Related Findings | Affected Components |")
            tail_lines.append("|------------|----------|-------------------|------------------|---------------------|")
            for f in all_findings:
                gid = f["global_id"]
                sev = f.get("severity", "Unknown")
                asvs_reqs = ", ".join(f.get("asvs_sections", []) or []) or "—"
                related = ", ".join(f.get("related_findings", []) or []) or "—"
                # affected_files entries are dicts {"file": "path:line"}
                # in the normal path and bare strings in older / fallback
                # paths — handle both.
                affected = []
                for af in (f.get("affected_files") or []):
                    val = af.get("file", "") if isinstance(af, dict) else str(af)
                    val = (val or "").strip()
                    if val:
                        affected.append(val.replace("|", "\\|"))
                affected_str = ", ".join(affected) or "—"
                tail_lines.append(f"| {gid} | {sev} | {asvs_reqs} | {related} | {affected_str} |")
        else:
            tail_lines.append("*No findings to cross-reference.*")

        # Severity totals footer — sourced from severity_counts which
        # was computed by iterating all_findings, so it's tautologically
        # consistent with the rows above. Previously the LLM re-counted
        # from its own partial summary and got it wrong by one.
        crit = severity_counts.get("Critical", 0)
        high = severity_counts.get("High", 0)
        med = severity_counts.get("Medium", 0)
        low = severity_counts.get("Low", 0)
        info = severity_counts.get("Informational", 0)
        n_findings_total = crit + high + med + low + info
        tail_lines.append("")
        tail_lines.append(
            f"**Total Unique Findings**: {n_findings_total} "
            f"({crit} Critical, {high} High, {med} Medium, {low} Low, {info} Info)"
        )
        # When there are Informational findings, surface the actionable
        # count here so a reader who notices the consolidated.md total
        # doesn't match issues.md isn't left wondering. Suppressed when
        # info == 0 to keep the output clean for the common case.
        if info > 0:
            n_act = n_findings_total - info
            tail_lines.append("")
            tail_lines.append(
                f"*{n_act} of {n_findings_total} are actionable. "
                f"Informational findings are recorded here but not opened "
                f"as GitHub issues; see issues.md for the {n_act} actionable items.*"
            )

        tail_result = "\n".join(tail_lines)

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

        if extraction_errors:
            s7.append(f"\n\n### Reports Not Included in Consolidation")
            s7.append(f"\n{len(extraction_errors)} per-section report(s) could not be automatically extracted into this consolidated report. ")
            s7.append(f"Findings from these sections are available in the original per-section reports:\n")
            s7.append("| Section | Per-Section Report |")
            s7.append("|---------|-------------------|")
            for rk in sorted(extraction_errors):
                section_id = rk.replace(".md", "")
                directory = report_dirs.get(rk, directories[0] if directories else "")
                link = f"https://github.com/{owner}/{repo}/blob/main/{directory}/{rk}"
                s7.append(f"| {section_id} | [{directory}/{rk}]({link}) |")

        s7.append("\n*End of Consolidated Security Audit Report*")
        consolidated_md += "\n".join(s7)

        # Issues file
        informational_ids = set(f["global_id"] for f in all_findings if "informational" in f.get("severity","").lower())
        actionable = [f for f in all_findings if f["global_id"] not in informational_ids]

        ISSUE_FMT = """---\n## Issue: FINDING-NNN - Title\n**Labels:** bug, security, priority:sev\n**Description:**\n### Summary\n### Details\n### Remediation\n### Acceptance Criteria\n- [ ] Fixed\n- [ ] Test added\n### References\n### Priority"""

        # Deterministic preamble. The LLM used to emit "# Security Issues"
        # for the first batch and "Continue. No header." for the rest, which
        # meant the file had no way to surface the actionable-vs-total
        # split. Writing the header here, including the explanatory line
        # when there are Informational findings, lets a reader who sees
        # "Total Findings: N" in consolidated.md but only K issues here
        # understand why without having to find the run log.
        issues_parts = []
        n_info = len(all_findings) - len(actionable)
        if n_info > 0:
            issues_parts.append(
                "# Security Issues\n\n"
                f"*{len(actionable)} actionable finding(s). {n_info} informational "
                f"finding(s) from the consolidated report are not opened as issues — "
                f"see consolidated.md for those.*"
            )
        else:
            issues_parts.append("# Security Issues")

        for bi in range(0, len(actionable), 40):
            batch = actionable[bi:bi+40]
            # Header is now written above deterministically — tell the LLM
            # to start straight from the first finding's separator.
            prompt = f"""Generate GitHub issues for {len(batch)} findings.\n{ISSUE_FMT}\nDo not include a top-level heading. Start directly with the first finding's `---` separator.\n\n{json.dumps(batch, indent=2, default=str)}"""
            # Retries handled centrally. On exhaustion, fall back to the
            # deterministic per-finding format below so every issue still
            # gets rendered, just without LLM polish.
            try:
                result, _ = await call_llm(provider=FAST_PROVIDER, model=FAST_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    parameters={**FAST_PARAMS, "max_tokens": 64000}, timeout=900)
                result = sanitize_md_html(result)
                # Count how many issues were generated
                generated_ids = set(re.findall(r'FINDING-(\d{3})', result))
                expected_ids = set(f["global_id"].replace("FINDING-", "") for f in batch if "global_id" in f)
                missing_ids = expected_ids - generated_ids
                issues_parts.append(result)
                if missing_ids:
                    # Fill in missing issues with deterministic fallback
                    missing_findings = [f for f in batch if f.get("global_id", "").replace("FINDING-", "") in missing_ids]
                    fb = []
                    for f in missing_findings:
                        fb.append(f"---\n\n## Issue: {f['global_id']} - {sanitize_md_html(f.get('title',''))}\n\n**Labels:** bug, security, priority:{f.get('severity','Medium').lower()}\n\n**Description:**\n\n{sanitize_md_html(f.get('description',''))}\n\n**Remediation:** {sanitize_md_html(f.get('recommended_remediation',''))}\n\n**Priority:** {f.get('severity','Medium')}")
                    issues_parts.append("\n\n".join(fb))
                    print(f"    Filled {len(missing_findings)} missing issues from batch")
            except Exception:
                # Full fallback: render every finding in the batch
                # deterministically rather than losing it.
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

        # GUARDRAIL: pipeline-failure surfacing. Sections whose stored
        # report content matched a known failure pattern were extracted
        # as ERROR (not silently as N/A). If any are present, the run is
        # not safe to publish without manual review — the consolidated
        # report will be missing real audit content for those sections,
        # and the silent failure mode this guardrail is closing has in
        # the past produced reports where V10 (OAuth) was entirely empty
        # because every section came through as a stub.
        print(f"Pipeline-failure sections: {len(pipeline_failure_sections)}")
        if pipeline_failure_sections:
            print("  *** RUN SHOULD NOT BE PUBLISHED WITHOUT REVIEW ***")
            # Group by marker so the operator sees the failure shape at
            # a glance rather than scrolling through N individual lines.
            by_marker = {}
            for rk, sid, marker in pipeline_failure_sections:
                by_marker.setdefault(marker, []).append((rk, sid))
            for marker, items in sorted(by_marker.items()):
                print(f"  marker={marker!r}: {len(items)} section(s)")
                # Cap displayed list at 20 to avoid log spam on a fully
                # broken run; the count above gives the full picture.
                for rk, sid in items[:20]:
                    print(f"    - {sid}  (from {rk})")
                if len(items) > 20:
                    print(f"    ... and {len(items) - 20} more")

        # Push to GitHub
        print("\n=== Pushing files ===")

        async def push_file(path, content_str, message):
            """Push a single file with retry-on-409 for branch HEAD races.

            GitHub's contents API serializes commits to a branch. When two
            commits race against the same HEAD, the loser gets 409 Conflict
            with "is at X but expected Y". Refetching the SHA and retrying
            handles this. We use exponential backoff with jitter to spread
            out retry attempts.
            """
            import random
            max_attempts = 5
            last_resp = None
            for attempt in range(max_attempts):
                existing_sha = None
                check = await http_client.get(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", headers=headers, params={"ref": default_branch})
                if check.status_code == 200:
                    existing_sha = check.json().get("sha")
                payload = {"message": message, "content": base64.b64encode(content_str.encode("utf-8")).decode("ascii"), "branch": default_branch}
                if existing_sha:
                    payload["sha"] = existing_sha
                resp = await http_client.put(f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}", headers=headers, json=payload)
                last_resp = resp
                if resp.status_code in (200, 201):
                    print(f"  OK: {path}")
                    return True
                is_conflict = resp.status_code == 409 or (
                    resp.status_code == 422 and "does not match" in (resp.text or "")
                )
                if not is_conflict:
                    break
                if attempt < max_attempts - 1:
                    await asyncio.sleep(0.2 * (2 ** attempt) + random.uniform(0, 0.2))

            # Fell through retries OR hit a non-retryable error.
            resp = last_resp
            try:
                body = resp.json()
                err = body.get("message", "no message")
                if "errors" in body:
                    err += f" — {body['errors']}"
            except Exception:
                err = resp.text[:200]
            print(f"  ERROR: {path}  ({resp.status_code}): {err}")
            return False

        # Serialize the two pushes — pushing them in parallel via asyncio.gather
        # was causing one to lose to the other on the branch HEAD race. The
        # inner retry handles this in most cases, but serializing them here
        # eliminates the race for these two specifically (and barely costs
        # anything since it's only two files).
        # Append source identifier to commit messages so each commit is
        # traceable back to the audited repo + path + commit hash.
        _src_suffix = f" [source: {source_id}]" if source_id else ""
        await push_file(f"{output_directory}/{consolidated_filename}", consolidated_md, f"Add consolidated audit report ({level}){_src_suffix}")
        await push_file(f"{output_directory}/{issues_filename}", issues_md, f"Add security issues ({level}){_src_suffix}")

        # Mirror final outputs into the consolidation namespace so
        # downstream steps (the orchestrator's redactor) can read them
        # without round-tripping through GitHub. The GitHub contents API
        # is eventually consistent: reading consolidated.md or issues.md
        # back immediately after pushing them 404s reliably enough that
        # it broke the redactor's issues.md fetch on the May 19 run.
        # The namespace is strongly consistent. Keys are prefixed with
        # "final:" so they're trivial to distinguish from the intermediate
        # consolidation state that already lives in this namespace.
        try:
            consolidation_ns.set("final:consolidated.md", consolidated_md)
            consolidation_ns.set("final:issues.md", issues_md)
            print(f"  Mirrored final outputs to namespace consolidation:{owner}/{repo}/{dirs_key}", flush=True)
        except Exception as _mirror_e:
            # Don't fail consolidation if the namespace write fails — the
            # GitHub copy is still the source of truth. Just warn loudly
            # so the redactor's eventual failure has a breadcrumb.
            print(f"  WARNING: namespace mirror of final outputs FAILED: "
                  f"{type(_mirror_e).__name__}: {_mirror_e}", flush=True)

        print(f"\n=== Done ===")
        print(f"Total findings: {len(all_findings)}, Actionable issues: {len(actionable)}")

        return {
            "outputText": f"Consolidated report and issues pushed.\n"
                          f"Repository: {owner}/{repo}\n"
                          f"Level: {level}\n"
                          f"Findings: {len(all_findings)}\n"
                          f"Files: {output_directory}/{consolidated_filename}, {output_directory}/{issues_filename}"
        }
    except Exception as e:
        # Top-level catch: any unhandled exception in run() body. Without
        # this, errors bubble up to gofannon which often stringifies httpx
        # errors to empty strings, making diagnosis impossible. Log the
        # type and full traceback so the orchestrator's log shows what
        # happened, and return a structured Error: outputText so the
        # orchestrator can distinguish failure from success. Defined
        # INSIDE run() rather than as a module-level wrapper because
        # gofannon's exec namespace doesn't reliably preserve module-
        # level bindings at call time.
        import traceback as _tb
        err_type = type(e).__name__
        err_msg = str(e) or "(no message)"
        tb_str = _tb.format_exc()
        print(f"\n!!! asvs_consolidate FATAL: {err_type}: {err_msg}", flush=True)
        print(f"Traceback:\n{tb_str}", flush=True)
        return {
            "outputText": f"Error: asvs_consolidate raised {err_type}: {err_msg}\n\n{tb_str}"
        }
    finally:
        try:
            await http_client.aclose()
        except Exception:
            pass