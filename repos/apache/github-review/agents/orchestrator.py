from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json

        # --- All inputs are required ---
        github_owner = input_dict.get("github_owner", "").strip()
        read_pat = input_dict.get("read_pat", "").strip()
        write_private_repo = input_dict.get("write_private_repo", "").strip()
        write_private_directory = input_dict.get("write_private_directory", "").strip()
        write_private_pat = input_dict.get("write_private_pat", "").strip()
        write_public_repo = input_dict.get("write_public_repo", "").strip()
        write_public_directory = input_dict.get("write_public_directory", "").strip()
        write_public_pat = input_dict.get("write_public_pat", "").strip()
        redacted_severity = input_dict.get("redacted_severity", "CRITICAL").strip().upper()
        skip_prefetch_raw = input_dict.get("skip_prefetch", "false")
        skip_prefetch = str(skip_prefetch_raw).lower().strip() in ("true", "1", "yes")

        for name, val in [("github_owner", github_owner), ("read_pat", read_pat),
                          ("write_private_repo", write_private_repo),
                          ("write_private_directory", write_private_directory),
                          ("write_private_pat", write_private_pat),
                          ("write_public_repo", write_public_repo),
                          ("write_public_directory", write_public_directory),
                          ("write_public_pat", write_public_pat)]:
            if not val:
                return {"outputText": f"Error: `{name}` is required."}

        pushed_files = []
        errors = []

        async def push_file(repo, pat, directory, filename, content, commit_msg):
            try:
                result = await gofannon_client.call(
                    agent_name="add_markdown_file_to_github_directory",
                    input_dict={
                        "inputText": json.dumps({
                            "repo": repo,
                            "token": pat,
                            "directory": directory,
                            "filename": filename,
                        }),
                        "commitMessage": commit_msg,
                        "fileContents": content,
                    }
                )
                output = result.get("outputText", "")
                if "error" in output.lower() and "message" in output.lower():
                    pushed_files.append((repo, f"{directory}/{filename}", "ERROR"))
                    errors.append(f"Push {repo}/{directory}/{filename}: {output[:200]}")
                    print(f"  ERROR pushing {filename} to {repo}", flush=True)
                else:
                    pushed_files.append((repo, f"{directory}/{filename}", "OK"))
                    print(f"  Pushed {filename} to {repo}", flush=True)
            except Exception as e:
                pushed_files.append((repo, f"{directory}/{filename}", "ERROR"))
                errors.append(f"Push {repo}/{directory}/{filename}: {e}")
                print(f"  ERROR pushing {filename} to {repo}: {e}", flush=True)

        async def run_agent(name, **kwargs):
            try:
                result = await gofannon_client.call(
                    agent_name=name,
                    input_dict={k: str(v) for k, v in kwargs.items() if v},
                )
                return result.get("outputText", "")
            except Exception as e:
                errors.append(f"Agent {name}: {e}")
                print(f"  AGENT ERROR {name}: {e}", flush=True)
                return None

        # ==============================================================
        # Phase 1: Prefetch (only step that hits GitHub API)
        # ==============================================================

        prefetch_stats = {}

        if skip_prefetch:
            print(f"\n{'='*60}", flush=True)
            print(f"Phase 1: Prefetch SKIPPED (skip_prefetch=true)", flush=True)
            print(f"{'='*60}\n", flush=True)
        else:
            print(f"\n{'='*60}", flush=True)
            print(f"Phase 1: Prefetch for {github_owner}", flush=True)
            print(f"{'='*60}\n", flush=True)

            prefetch_output = await run_agent("asf_gha_prefetch",
                github_owner=github_owner,
                read_pat=read_pat,
            )

            if prefetch_output is None:
                return {"outputText": "Error: Prefetch failed. Cannot continue.\n\n" +
                        "\n".join(errors)}

            try:
                prefetch_stats = json.loads(prefetch_output)
            except Exception:
                pass

        # ==============================================================
        # Phase 2: Private reports (full, no redaction)
        # All agents read from CouchDB. No GitHub API calls.
        # Push each file immediately after generation.
        # ==============================================================

        print(f"\n{'='*60}", flush=True)
        print(f"Phase 2: Private reports (full)", flush=True)
        print(f"{'='*60}\n", flush=True)

        print("Running publishing agent...", flush=True)
        publishing_report = await run_agent("asf_gha_publishing",
            github_owner=github_owner)
        if publishing_report:
            await push_file(write_private_repo, write_private_pat,
                write_private_directory, "publishing.md", publishing_report,
                f"CI scan: publishing analysis ({github_owner})")

        print("Running security agent...", flush=True)
        security_report = await run_agent("asf_gha_security",
            github_owner=github_owner)
        if security_report:
            await push_file(write_private_repo, write_private_pat,
                write_private_directory, "security.md", security_report,
                f"CI scan: security analysis ({github_owner})")

        print("Running review agent...", flush=True)
        review_report = await run_agent("asf_gha_review",
            github_owner=github_owner)
        if review_report:
            await push_file(write_private_repo, write_private_pat,
                write_private_directory, "review.md", review_report,
                f"CI scan: combined review ({github_owner})")

        print("Running brief agent...", flush=True)
        brief_report = await run_agent("asf_gha_brief",
            github_owner=github_owner)
        if brief_report:
            await push_file(write_private_repo, write_private_pat,
                write_private_directory, "brief.md", brief_report,
                f"CI scan: executive brief ({github_owner})")

        print("Running json-export agent...", flush=True)
        json_report = await run_agent("asf_gha_json_export",
            github_owner=github_owner)
        if json_report:
            await push_file(write_private_repo, write_private_pat,
                write_private_directory, "json-export.json", json_report,
                f"CI scan: JSON export ({github_owner})")

        # ==============================================================
        # Phase 3: Public reports (redacted)
        # Same five agents, same order, with redacted_severity.
        # ==============================================================

        print(f"\n{'='*60}", flush=True)
        print(f"Phase 3: Public reports (redacting {redacted_severity})", flush=True)
        print(f"{'='*60}\n", flush=True)

        print("Running publishing agent (redacted)...", flush=True)
        pub_redacted = await run_agent("asf_gha_publishing",
            github_owner=github_owner,
            redacted_severity=redacted_severity)
        if pub_redacted:
            await push_file(write_public_repo, write_public_pat,
                write_public_directory, "publishing.md", pub_redacted,
                f"CI scan: publishing analysis ({github_owner})")

        print("Running security agent (redacted)...", flush=True)
        sec_redacted = await run_agent("asf_gha_security",
            github_owner=github_owner,
            redacted_severity=redacted_severity)
        if sec_redacted:
            await push_file(write_public_repo, write_public_pat,
                write_public_directory, "security.md", sec_redacted,
                f"CI scan: security analysis ({github_owner})")

        print("Running review agent (redacted)...", flush=True)
        rev_redacted = await run_agent("asf_gha_review",
            github_owner=github_owner,
            redacted_severity=redacted_severity)
        if rev_redacted:
            await push_file(write_public_repo, write_public_pat,
                write_public_directory, "review.md", rev_redacted,
                f"CI scan: combined review ({github_owner})")

        print("Running brief agent (redacted)...", flush=True)
        brief_redacted = await run_agent("asf_gha_brief",
            github_owner=github_owner,
            redacted_severity=redacted_severity)
        if brief_redacted:
            await push_file(write_public_repo, write_public_pat,
                write_public_directory, "brief.md", brief_redacted,
                f"CI scan: executive brief ({github_owner})")

        print("Running json-export agent (redacted)...", flush=True)
        json_redacted = await run_agent("asf_gha_json_export",
            github_owner=github_owner,
            redacted_severity=redacted_severity)
        if json_redacted:
            await push_file(write_public_repo, write_public_pat,
                write_public_directory, "json-export.json", json_redacted,
                f"CI scan: JSON export ({github_owner})")

        # ==============================================================
        # Summary
        # ==============================================================

        summary = []
        summary.append(f"# CI Security Scan: {github_owner}\n")

        if prefetch_stats:
            summary.append("## Scan Statistics\n")
            summary.append(f"- Repos processed: {prefetch_stats.get('repos', '?')}")
            summary.append(f"- Workflows fetched: {prefetch_stats.get('wf_fetched', '?')}")
            summary.append(f"- Workflows skipped (cached): {prefetch_stats.get('wf_skipped', '?')}")
            summary.append(f"- YAML files cached: {prefetch_stats.get('wf_yaml_cached', '?')}")
            summary.append(f"- Composite actions cached: {prefetch_stats.get('ca_total', '?')}")
            summary.append(f"- Errors: {prefetch_stats.get('errors', '?')}")
            summary.append("")

        if brief_report:
            for line in brief_report.split("\n"):
                if line.startswith("*") and "repos scanned" in line:
                    summary.append("## Key Numbers\n")
                    summary.append(line)
                    summary.append("")
                    break

        summary.append("## Files Pushed\n")
        summary.append("### Private Reports (full)\n")
        for repo, path, status in pushed_files:
            if repo == write_private_repo:
                icon = "+" if status == "OK" else "x"
                summary.append(f"- [{icon}] `{path}`")
        summary.append("")

        summary.append(f"### Public Reports (redacted {redacted_severity})\n")
        for repo, path, status in pushed_files:
            if repo == write_public_repo:
                icon = "+" if status == "OK" else "x"
                summary.append(f"- [{icon}] `{path}`")
        summary.append("")

        if errors:
            summary.append(f"## Errors ({len(errors)})\n")
            for e in errors:
                summary.append(f"- {e}")
            summary.append("")

        n_ok = sum(1 for _, _, s in pushed_files if s == "OK")
        n_err = sum(1 for _, _, s in pushed_files if s != "OK")
        summary.append("---\n")
        summary.append(f"*{n_ok} files pushed successfully, {n_err} errors.*")

        return {"outputText": "\n".join(summary)}

    finally:
        await http_client.aclose()