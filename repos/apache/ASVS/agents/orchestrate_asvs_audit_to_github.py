# orchestrate_asvs_audit_to_github

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json

        # =============================================================
        # Parse inputs
        # =============================================================
        source_repo = input_dict.get("sourceRepo", "")       # e.g., "apache/airflow" or "apache/airflow/airflow-core/src"
        source_token = input_dict.get("sourceToken", "")      # PAT for private source repos
        supplemental_data = input_dict.get("supplementalData", "")  # extra namespaces, comma-separated
        output_repo = input_dict.get("outputRepo", "")
        output_token = input_dict.get("outputToken", "")
        output_directory = input_dict.get("outputDirectory", "")
        discover = input_dict.get("discover", "true")
        severity_threshold = input_dict.get("severityThreshold", "")
        consolidate = input_dict.get("consolidate", "true")
        level = input_dict.get("level", "")

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

        # Derive repo name, path prefix, and namespace from sourceRepo
        # Accepts:
        #   "apache/steve"                                    → repo=apache/steve, path=""
        #   "apache/steve/v3"                                 → repo=apache/steve, path="v3"
        #   "apache/airflow/airflow-core/src"                 → repo=apache/airflow, path="airflow-core/src"
        #   "https://github.com/apache/steve/tree/trunk/v3"   → repo=apache/steve, path="v3"
        import re as _re
        _source = source_repo.strip().strip("/")

        # Strip GitHub URL prefix and tree/branch segment if present
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

        code_namespace = f"files:{repo_owner_name}"

        # Reconstruct the download input: owner/repo/path (short form for the download agent)
        download_source = repo_owner_name
        if source_path_prefix:
            download_source += f"/{source_path_prefix}"

        # Build namespace list: code namespace + any supplemental
        namespaces = [code_namespace]
        if supplemental_data:
            for ns in supplemental_data.split(","):
                ns = ns.strip()
                if ns and ns not in namespaces:
                    namespaces.append(ns)

        # Fetch latest commit hash and append repo/hash to output directory
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

        output_directory = f"{output_directory.strip('/')}/{repo_short_name}/{commit_hash}"
        print(f"  Output directory: {output_directory}", flush=True)

        all_outputs = []
        successes = []
        failures = []
        report_directories = []

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

        # =============================================================
        # Step 2: Discover architecture
        # =============================================================
        if discover:
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

            if total_sections == 0:
                return {"outputText": f"No ASVS sections match level {level}."}

            # =============================================================
            # Step 3: Audit + push
            # =============================================================
            print(f"\n{'='*60}", flush=True)
            print(f"Step 3: Auditing {total_sections} sections", flush=True)
            print(f"{'='*60}", flush=True)

            section_idx = 0
            for pass_def in passes:
                pass_name = pass_def.get("name", "unknown")
                sections = pass_def.get("asvs_sections", [])
                include_files = pass_def.get("files", [])
                domain_context = pass_def.get("domain_context", "")
                pass_output_dir = f"{output_directory}/{pass_name}" if output_directory else pass_name
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
                                    "repo": output_repo,
                                    "token": output_token,
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
            # Step 4: Consolidate
            # =============================================================
            if consolidate and successes:
                print(f"\n{'='*60}", flush=True)
                print(f"Step 4: Consolidating reports", flush=True)
                print(f"{'='*60}", flush=True)
                try:
                    await gofannon_client.call(
                        agent_name="consolidate_asvs_security_audit_reports",
                        input_dict={
                            "inputText": "\n".join([
                                f"repo: {output_repo}",
                                f"pat: {output_token}",
                                f"directories: {', '.join(report_directories)}",
                                f"output: {output_directory}",
                            ]),
                            "domainGroups": json.dumps(domain_groups),
                            "level": level or "L3",
                        }
                    )
                    print(f"  Consolidation done", flush=True)
                except Exception as e:
                    print(f"  Consolidation FAILED: {e}", flush=True)
                    failures.append(f"consolidation: {e}")
            elif not successes:
                print(f"\n  Skipping consolidation — no successful audits", flush=True)

        else:
            # =============================================================
            # NO-DISCOVER MODE: just audit all ASVS sections in the data
            # store without domain scoping. Useful for small codebases.
            # =============================================================
            print(f"\n{'='*60}", flush=True)
            print(f"Step 2: Loading ASVS sections (no discovery)", flush=True)
            print(f"{'='*60}", flush=True)

            # Get all ASVS sections from the data store, filtered by level
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
                                "repo": output_repo,
                                "token": output_token,
                                "directory": output_directory,
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
        if failures:
            for f in failures:
                print(f"  - {f}", flush=True)
        return {"outputText": "\n\n---\n\n".join(all_outputs)}
    finally:
        await http_client.aclose()