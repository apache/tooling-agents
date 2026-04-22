# orchestrate_asvs_audit_to_github

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

        # Carve-out inputs
        private_repo = input_dict.get("privateRepo", "")
        private_token = input_dict.get("privateToken", "")
        notify_email = input_dict.get("notifyEmail", "")

        if isinstance(discover, str):
            discover = discover.lower() in ("true", "1", "yes")
        if isinstance(consolidate, str):
            consolidate = consolidate.lower() in ("true", "1", "yes")

        level = level.strip().upper()
        if level and not level.startswith("L"):
            level = f"L{level}"
        LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
        max_level_num = LEVEL_ORDER.get(level, 3)

        if not source_repo:
            return {"outputText": "Error: sourceRepo is required (e.g., 'apache/airflow', 'apache/airflow/src', or 'https://github.com/apache/airflow/tree/main/src')"}

        # Validate carve-out inputs
        carve_out = bool(private_repo)
        if carve_out and not private_token:
            return {"outputText": "Error: privateToken is required when privateRepo is set"}

        # Determine where audit + consolidation pushes go
        push_repo = private_repo if carve_out else output_repo
        push_token = private_token if carve_out else output_token

        # Derive repo name, path prefix, and namespace from sourceRepo
        import re as _re
        _source = source_repo.strip().strip("/")

        _gh_match = _re.match(
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

        # When carve-out is on, audit+consolidate push to private repo at same path
        push_directory = output_directory

        print(f"  Output directory: {output_directory}", flush=True)
        if carve_out:
            print(f"  Carve-out enabled: full → {private_repo}, redacted → {output_repo}", flush=True)

        all_outputs = []
        successes = []
        failures = []
        report_directories = []

        # =============================================================
        # Redaction helpers
        # =============================================================
        def redact_consolidated(content):
            """Strip CRITICAL findings from consolidated.md.
            Returns (redacted_content, list_of_critical_findings)."""
            critical_findings = []
            redacted = content

            # Extract CRITICAL finding blocks: #### FINDING-NNN: ... until next #### or ## or ---
            finding_pattern = re.compile(
                r'(#### (FINDING-\d{3}):.*?)(?=####\s|##\s|---|\Z)',
                re.DOTALL,
            )
            for match in finding_pattern.finditer(content):
                block = match.group(1)
                finding_id = match.group(2)
                # Check if this block contains a Critical severity indicator
                if re.search(r'🔴\s*Critical|severity[:\s]*Critical|\bCRITICAL\b', block, re.IGNORECASE):
                    critical_findings.append({"id": finding_id, "block": block.strip()})
                    redacted = redacted.replace(match.group(1), "")

            # Clean up empty severity sections (### 3.1 Critical Findings with no content)
            redacted = re.sub(
                r'### 3\.1 Critical.*?(?=### 3\.\d|## \d|\Z)',
                '',
                redacted,
                flags=re.DOTALL,
            )

            # Add redaction notice after executive summary
            if critical_findings:
                notice = (
                    f"\n\n> **Note:** {len(critical_findings)} Critical "
                    f"{'finding has' if len(critical_findings) == 1 else 'findings have'} "
                    f"been redacted from this report and forwarded to the project's "
                    f"PMC private mailing list.\n\n"
                )
                # Insert after the first --- separator (end of executive summary)
                first_sep = redacted.find("\n---\n")
                if first_sep > 0:
                    redacted = redacted[:first_sep + 5] + notice + redacted[first_sep + 5:]
                else:
                    redacted = notice + redacted

            return redacted, critical_findings

        def redact_issues(content):
            """Strip CRITICAL issues from issues.md."""
            # Issue blocks: ## Issue: FINDING-NNN ... until next ## Issue: or end
            issue_pattern = re.compile(
                r'(## Issue: (FINDING-\d{3}).*?)(?=## Issue:|\Z)',
                re.DOTALL,
            )
            redacted = content
            removed_count = 0
            for match in issue_pattern.finditer(content):
                block = match.group(1)
                if re.search(r'priority:\s*critical|Priority\s*\n\s*Critical|\bCRITICAL\b', block, re.IGNORECASE):
                    redacted = redacted.replace(match.group(1), "")
                    removed_count += 1
            return redacted, removed_count

        def build_email_body(critical_findings, repo_name, commit):
            """Build email body summarizing critical findings."""
            lines = [
                f"ASVS Security Audit: Critical Findings",
                f"",
                f"Repository: {repo_name}",
                f"Commit: {commit}",
                f"Critical findings: {len(critical_findings)}",
                f"",
                f"The following Critical severity findings were identified",
                f"and have been redacted from the public report.",
                f"",
                f"Full report: https://github.com/{private_repo}/tree/main/{output_directory}/consolidated.md",
                f"",
            ]
            for cf in critical_findings:
                lines.append(f"---")
                lines.append(f"")
                lines.append(cf["block"])
                lines.append(f"")
            return "\n".join(lines)

        async def send_email(recipient, subject, body):
            """Send email via SMTP."""
            import smtplib
            from email.mime.text import MIMEText

            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = "tooling-agents@apache.org"
            msg["To"] = recipient

            try:
                # Try ASF mail relay first (no auth needed from ASF infra)
                smtp = smtplib.SMTP("mail-relay.apache.org", 587, timeout=30)
                smtp.starttls()
                smtp.send_message(msg)
                smtp.quit()
                print(f"  Email sent to {recipient}", flush=True)
            except Exception as e:
                print(f"  Email FAILED to {recipient}: {e}", flush=True)
                failures.append(f"email to {recipient}: {e}")

        async def read_file_from_github(repo, token, filepath):
            """Read a file from GitHub."""
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            }
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
        # Helper: filter ASVS sections by level
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
            if not level:
                return sections
            load_asvs_levels()
            return [s for s in sections if asvs_level_cache.get(s, 1) <= max_level_num]

        # =============================================================
        # Step 1: Download source code
        # =============================================================
        print(f"{'='*60}", flush=True)
        print(f"Step 1: Downloading source code", flush=True)
        print(f"  Source: {source_repo}", flush=True)
        print(f"  Repo: {repo_owner_name}", flush=True)
        if source_path_prefix:
            print(f"  Path: {source_path_prefix}", flush=True)
        print(f"  Namespace: {code_namespace}", flush=True)
        print(f"{'='*60}", flush=True)

        download_input = download_source
        if source_token:
            download_input += f"\n{source_token}"

        try:
            download_result = await gofannon_client.call(
                agent_name="download_github_repo_to_datastore",
                input_dict={
                    "inputText": download_input,
                }
            )
            download_output = download_result.get("outputText", "")
            print(f"  {download_output}", flush=True)
        except Exception as e:
            return {"outputText": f"Download failed: {e}"}

        if discover:
            # =============================================================
            # DISCOVERY MODE
            # =============================================================
            print(f"\n{'='*60}", flush=True)
            print(f"Step 2: Discovering codebase architecture", flush=True)
            print(f"  Namespaces: {namespaces}", flush=True)
            print(f"{'='*60}", flush=True)

            try:
                discovery_result = await gofannon_client.call(
                    agent_name="discover_codebase_architecture",
                    input_dict={
                        "inputNamespace": ",".join(namespaces),
                    }
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

            # Filter by level
            for pass_def in passes:
                pass_def["asvs_sections"] = filter_sections_by_level(pass_def.get("asvs_sections", []))
            passes = [p for p in passes if p.get("asvs_sections")]

            if level:
                for dn in list(domain_groups.keys()):
                    domain_groups[dn] = filter_sections_by_level(domain_groups[dn])
                domain_groups = {k: v for k, v in domain_groups.items() if v}

            total_sections = sum(len(p.get("asvs_sections", [])) for p in passes)
            print(f"  After level filter ({level or 'all'}): {total_sections} sections, {len(passes)} passes", flush=True)

            # Check for uncovered sections
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

                print(f"  {len(uncovered)} sections not assigned by discovery — adding {len(chapter_groups)} chapter-based passes", flush=True)
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
                    print(f"    {ch_name}: {len(ch_sections)} sections", flush=True)

                total_sections = sum(len(p.get("asvs_sections", [])) for p in passes)
                print(f"  Total sections now: {total_sections} (of {len(all_level_sections)} at {level or 'L3'})", flush=True)

            if total_sections == 0:
                return {"outputText": f"No ASVS sections match level {level}."}

            # =============================================================
            # Step 3: Audit + push (to private repo if carve-out, else public)
            # =============================================================
            print(f"\n{'='*60}", flush=True)
            print(f"Step 3: Auditing {total_sections} sections", flush=True)
            print(f"  Pushing to: {push_repo}", flush=True)
            print(f"{'='*60}", flush=True)

            section_idx = 0
            for pass_def in passes:
                pass_name = pass_def.get("name", "unknown")
                sections = pass_def.get("asvs_sections", [])
                include_files = pass_def.get("files", [])
                domain_context = pass_def.get("domain_context", "")
                pass_output_dir = f"{push_directory}/{pass_name}" if push_directory else pass_name
                report_directories.append(pass_output_dir)

                print(f"\n{'='*60}", flush=True)
                print(f"Pass: {pass_name} ({len(sections)} sections)", flush=True)
                print(f"{'='*60}", flush=True)

                for section in sections:
                    section_idx += 1
                    print(f"\n[{section_idx}/{total_sections}] {section} ({pass_name})", flush=True)

                    audit_output_text = None
                    try:
                        audit_result = await gofannon_client.call(
                            agent_name="run_asvs_security_audit",
                            input_dict={
                                "inputText": json.dumps({
                                    "namespaces": namespaces,
                                    "asvs": section,
                                    "includeFiles": include_files,
                                    "domainContext": domain_context,
                                    "severityThreshold": severity_threshold,
                                    "falsePositiveGuidance": false_positive_guidance,
                                })
                            }
                        )
                        audit_output_text = audit_result.get("outputText", "")
                        print(f"  Audit done: {len(audit_output_text)} chars", flush=True)
                    except Exception as e:
                        print(f"  Audit FAILED: {e}", flush=True)
                        failures.append(f"{section} (audit): {e}")
                        continue

                    try:
                        await gofannon_client.call(
                            agent_name="add_markdown_file_to_github_directory",
                            input_dict={
                                "inputText": json.dumps({
                                    "repo": push_repo,
                                    "token": push_token,
                                    "directory": pass_output_dir,
                                    "filename": f"{section}.md",
                                }),
                                "commitMessage": f"ASVS {level or 'full'} audit: {section} ({pass_name})",
                                "fileContents": audit_output_text,
                            }
                        )
                        print(f"  Push OK", flush=True)
                        successes.append(section)
                    except Exception as e:
                        print(f"  Push FAILED: {e}", flush=True)
                        failures.append(f"{section} (push): {e}")
                    all_outputs.append(audit_output_text)

            # =============================================================
            # Step 4: Consolidate (pushed to private repo if carve-out)
            # =============================================================
            if consolidate and successes:
                print(f"\n{'='*60}", flush=True)
                print(f"Step 4: Consolidating reports", flush=True)
                print(f"  Pushing to: {push_repo}", flush=True)
                print(f"{'='*60}", flush=True)
                try:
                    await gofannon_client.call(
                        agent_name="consolidate_asvs_security_audit_reports",
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
            # Step 5: Carve-out — redact and publish to public repo
            # =============================================================
            if carve_out and consolidate and successes:
                print(f"\n{'='*60}", flush=True)
                print(f"Step 5: Redacting critical findings for public report", flush=True)
                print(f"  Reading from: {private_repo}", flush=True)
                print(f"  Publishing to: {output_repo}", flush=True)
                print(f"{'='*60}", flush=True)

                # Read consolidated.md from private repo
                consolidated_content = await read_file_from_github(
                    private_repo, private_token,
                    f"{output_directory}/consolidated.md",
                )
                issues_content = await read_file_from_github(
                    private_repo, private_token,
                    f"{output_directory}/issues.md",
                )

                critical_findings = []

                if consolidated_content:
                    redacted_consolidated, critical_findings = redact_consolidated(consolidated_content)
                    print(f"  Redacted {len(critical_findings)} critical findings from consolidated report", flush=True)

                    # Push redacted consolidated.md to public repo
                    try:
                        await gofannon_client.call(
                            agent_name="add_markdown_file_to_github_directory",
                            input_dict={
                                "inputText": json.dumps({
                                    "repo": output_repo,
                                    "token": output_token,
                                    "directory": output_directory,
                                    "filename": "consolidated.md",
                                }),
                                "commitMessage": f"ASVS {level or 'full'} audit: consolidated report (redacted)",
                                "fileContents": redacted_consolidated,
                            }
                        )
                        print(f"  Pushed redacted consolidated.md to {output_repo}", flush=True)
                    except Exception as e:
                        print(f"  Push redacted consolidated.md FAILED: {e}", flush=True)
                        failures.append(f"redacted consolidated push: {e}")
                else:
                    print(f"  WARNING: Could not read consolidated.md from private repo", flush=True)

                if issues_content:
                    redacted_issues, removed_count = redact_issues(issues_content)
                    print(f"  Redacted {removed_count} critical issues", flush=True)

                    # Push redacted issues.md to public repo
                    try:
                        await gofannon_client.call(
                            agent_name="add_markdown_file_to_github_directory",
                            input_dict={
                                "inputText": json.dumps({
                                    "repo": output_repo,
                                    "token": output_token,
                                    "directory": output_directory,
                                    "filename": "issues.md",
                                }),
                                "commitMessage": f"ASVS {level or 'full'} audit: issues (redacted)",
                                "fileContents": redacted_issues,
                            }
                        )
                        print(f"  Pushed redacted issues.md to {output_repo}", flush=True)
                    except Exception as e:
                        print(f"  Push redacted issues.md FAILED: {e}", flush=True)
                        failures.append(f"redacted issues push: {e}")

                # Push redacted per-section reports to public repo
                # Read each from private, strip critical blocks, push to public
                for pass_output_dir in report_directories:
                    # List files in this directory from private repo
                    list_headers = {
                        "Authorization": f"token {private_token}",
                        "Accept": "application/vnd.github.v3+json",
                    }
                    list_resp = await http_client.get(
                        f"https://api.github.com/repos/{private_repo}/contents/{pass_output_dir}",
                        headers=list_headers,
                    )
                    if list_resp.status_code != 200:
                        continue
                    dir_contents = list_resp.json()
                    for item in dir_contents:
                        if item["type"] != "file" or not item["name"].endswith(".md"):
                            continue
                        file_content = await read_file_from_github(
                            private_repo, private_token,
                            f"{pass_output_dir}/{item['name']}",
                        )
                        if not file_content:
                            continue
                        # Redact critical findings from individual reports
                        redacted_section, _ = redact_consolidated(file_content)
                        try:
                            await gofannon_client.call(
                                agent_name="add_markdown_file_to_github_directory",
                                input_dict={
                                    "inputText": json.dumps({
                                        "repo": output_repo,
                                        "token": output_token,
                                        "directory": pass_output_dir,
                                        "filename": item["name"],
                                    }),
                                    "commitMessage": f"ASVS audit: {item['name']} (redacted)",
                                    "fileContents": redacted_section,
                                }
                            )
                        except Exception as e:
                            print(f"  Push redacted {item['name']} FAILED: {e}", flush=True)

                print(f"  Redacted reports pushed to {output_repo}", flush=True)

                # Email critical findings to PMC
                if notify_email and critical_findings:
                    print(f"  Emailing {len(critical_findings)} critical findings to {notify_email}", flush=True)
                    email_subject = f"[ASVS Audit] {len(critical_findings)} Critical findings in {repo_owner_name}"
                    email_body = build_email_body(critical_findings, repo_owner_name, commit_hash)
                    await send_email(notify_email, email_subject, email_body)
                elif notify_email:
                    print(f"  No critical findings to email", flush=True)

            elif not successes:
                print(f"\n  Skipping consolidation — no successful audits", flush=True)

        else:
            # =============================================================
            # NO-DISCOVER MODE
            # =============================================================
            print(f"\n{'='*60}", flush=True)
            print(f"Step 2: Loading ASVS sections (no discovery)", flush=True)
            print(f"{'='*60}", flush=True)

            all_sections = []
            try:
                asvs_ns = data_store.use_namespace("asvs")
                all_keys = asvs_ns.list_keys()
                req_keys = [k for k in all_keys if k.startswith("asvs:requirements:")]
                for rk in sorted(req_keys):
                    section_id = rk.replace("asvs:requirements:", "")
                    all_sections.append(section_id)
            except Exception as e:
                return {"outputText": f"Could not load ASVS sections: {e}"}

            sections = filter_sections_by_level(all_sections)
            print(f"  {len(sections)} sections to audit (level: {level or 'all'})", flush=True)

            for i, section in enumerate(sections):
                print(f"\n[{i+1}/{len(sections)}] Section {section}", flush=True)
                audit_output_text = None
                try:
                    audit_result = await gofannon_client.call(
                        agent_name="run_asvs_security_audit",
                        input_dict={
                            "inputText": json.dumps({
                                "namespaces": namespaces,
                                "asvs": section,
                            })
                        }
                    )
                    audit_output_text = audit_result.get("outputText", "")
                except Exception as e:
                    failures.append(f"{section} (audit): {e}")
                    continue
                try:
                    await gofannon_client.call(
                        agent_name="add_markdown_file_to_github_directory",
                        input_dict={
                            "inputText": json.dumps({
                                "repo": push_repo,
                                "token": push_token,
                                "directory": push_directory,
                                "filename": f"{section}.md",
                            }),
                            "commitMessage": f"ASVS audit: {section}",
                            "fileContents": audit_output_text,
                        }
                    )
                    successes.append(section)
                except Exception as e:
                    failures.append(f"{section} (push): {e}")
                all_outputs.append(audit_output_text)

        # =============================================================
        # Summary
        # =============================================================
        print(f"\n{'='*60}", flush=True)
        print(f"Complete: {len(successes)} succeeded, {len(failures)} failed", flush=True)
        if carve_out:
            print(f"  Full reports: {private_repo}/{output_directory}/", flush=True)
            print(f"  Redacted reports: {output_repo}/{output_directory}/", flush=True)
        else:
            print(f"  Reports: {output_repo}/{output_directory}/", flush=True)
        if failures:
            for f in failures:
                print(f"  - {f}", flush=True)
        return {"outputText": "\n\n---\n\n".join(all_outputs)}
    finally:
        await http_client.aclose()