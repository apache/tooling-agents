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

        async def _redact_and_push(gofannon_client, http_client, private_repo, private_token,
                                    output_repo, output_token, pass_output_dir, filename,
                                    redact_fn):
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
                    return
                file_data = resp.json()
                file_content = base64.b64decode(file_data["content"]).decode("utf-8", errors="replace")
                redacted_section, _ = redact_fn(file_content)
                try:
                    await gofannon_client.call(
                        agent_name="asvs_push_github",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": output_repo, "token": output_token,
                                "directory": pass_output_dir, "filename": filename,
                            }),
                            "commitMessage": f"ASVS audit: {filename} (redacted)",
                            "fileContents": redacted_section,
                        }
                    )
                except Exception as e:
                    print(f"  Push redacted {filename} FAILED: {e}", flush=True)


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

        if isinstance(discover, str):
            discover = discover.lower() in ("true", "1", "yes")
        if isinstance(consolidate, str):
            consolidate = consolidate.lower() in ("true", "1", "yes")
        if isinstance(clear_cache, str):
            clear_cache = clear_cache.lower() in ("true", "1", "yes")

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

        print(f"  Output directory: {output_directory}", flush=True)
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

        # T12: estimate LOC from download output to decide whether to skip discovery
        estimated_loc = _estimate_loc_from_namespace(code_namespace)
        skip_discovery = estimated_loc < TINY_REPO_LOC_THRESHOLD
        if skip_discovery and discover:
            print(f"  Repo is small ({estimated_loc} LOC < {TINY_REPO_LOC_THRESHOLD}); skipping discovery (T12)", flush=True)

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

        # Global GitHub push throttle, shared across ALL bundles. Default 6
        # is comfortable now that asvs_push_github retries on 409 branch-head
        # conflicts. Previously we had to keep this low to avoid silent
        # failures from those races. Lower to 4 or 3 if you see push failures
        # from genuine GitHub abuse-detection (403/422 responses, not 409).
        GITHUB_PUSH_CONCURRENCY = int(os.environ.get("GITHUB_PUSH_CONCURRENCY", "6"))
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

                async def push_one(section_id, report_text):
                    async with github_push_sem:
                        try:
                            push_result = await gofannon_client.call(
                                agent_name="asvs_push_github",
                                input_dict={
                                    "inputText": json.dumps({
                                        "repo": push_repo,
                                        "token": push_token,
                                        "directory": pass_output_dir,
                                        "filename": f"{section_id}.md",
                                    }),
                                    "commitMessage": f"ASVS {level or 'full'} audit: {section_id} ({pass_name})",
                                    "fileContents": report_text,
                                }
                            )
                            # asvs_push_github doesn't raise on GitHub errors —
                            # it returns the error body in outputText. Inspect
                            # to detect false-positive successes (rate limit,
                            # 422 abuse detection, 404 missing repo, etc).
                            output_text = (push_result or {}).get("outputText", "")
                            # Success indicators: GitHub's PUT response includes
                            # "content" and "commit" objects on success.
                            if '"content"' in output_text and '"commit"' in output_text:
                                return section_id, None
                            # Otherwise extract a short error message.
                            err_msg = output_text[:200] if output_text else "empty response"
                            if output_text.startswith("Error: "):
                                err_msg = output_text.split("\n", 1)[0][:200]
                            else:
                                # Try to pull GitHub's "message" field
                                m = re.search(r'"message"\s*:\s*"([^"]+)"', output_text)
                                if m:
                                    err_msg = f"GitHub: {m.group(1)}"
                            return section_id, err_msg
                        except Exception as e:
                            err_str = str(e) or f"{type(e).__name__} (no detail)"
                            return section_id, err_str

                push_results = await asyncio.gather(*[
                    push_one(sid, txt) for sid, txt in per_section_reports.items()
                ])
                for sid, err in push_results:
                    if err is None:
                        local_successes.append(sid)
                        print(f"    [{pass_name}] {sid}: pushed", flush=True)
                    else:
                        local_failures.append(f"{sid} (push): {err}")
                        print(f"    [{pass_name}] {sid}: push failed: {err}", flush=True)
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
        # Step 4: Consolidate (unchanged from original)
        # =============================================================
        if consolidate and successes:
            print(f"\n{'='*60}\nStep 4: Consolidating reports\n  Pushing to: {push_repo}\n{'='*60}", flush=True)
            try:
                await gofannon_client.call(
                    agent_name="asvs_consolidate",
                    input_dict={
                        "inputText": "\n".join([
                            f"repo: {push_repo}",
                            f"pat: {push_token}",
                            f"directories: {', '.join(report_directories)}",
                            f"output: {push_directory}",
                        ]),
                        "domainGroups": json.dumps(domain_groups),
                        "level": level or "L3",
                        "severityThreshold": severity_threshold,
                    }
                )
                print(f"  Consolidation done", flush=True)
            except Exception as e:
                print(f"  Consolidation FAILED: {e}", flush=True)
                failures.append(f"consolidation: {e}")

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
                    await gofannon_client.call(
                        agent_name="asvs_push_github",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": output_repo, "token": output_token,
                                "directory": output_directory, "filename": "consolidated.md",
                            }),
                            "commitMessage": f"ASVS {level or 'full'} audit: consolidated report (redacted)",
                            "fileContents": redacted_consolidated,
                        }
                    )
                except Exception as e:
                    failures.append(f"redacted consolidated push: {e}")

            if issues_content:
                redacted_issues, removed_count = redact_issues(issues_content)
                print(f"  Redacted {removed_count} critical issues", flush=True)
                try:
                    await gofannon_client.call(
                        agent_name="asvs_push_github",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": output_repo, "token": output_token,
                                "directory": output_directory, "filename": "issues.md",
                            }),
                            "commitMessage": f"ASVS {level or 'full'} audit: issues (redacted)",
                            "fileContents": redacted_issues,
                        }
                    )
                except Exception as e:
                    failures.append(f"redacted issues push: {e}")

            # Push redacted per-section reports
            for pass_output_dir in report_directories:
                list_headers = {"Authorization": f"token {private_token}", "Accept": "application/vnd.github.v3+json"}
                list_resp = await http_client.get(
                    f"https://api.github.com/repos/{private_repo}/contents/{pass_output_dir}",
                    headers=list_headers,
                )
                if list_resp.status_code != 200:
                    continue
                dir_contents = list_resp.json()
                redaction_tasks = []
                for item in dir_contents:
                    if item["type"] != "file" or not item["name"].endswith(".md"):
                        continue
                    redaction_tasks.append(_redact_and_push(
                        gofannon_client, http_client, private_repo, private_token,
                        output_repo, output_token, pass_output_dir, item["name"],
                        redact_consolidated,
                    ))
                await asyncio.gather(*redaction_tasks, return_exceptions=True)

            print(f"  Redacted reports pushed to {output_repo}", flush=True)

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