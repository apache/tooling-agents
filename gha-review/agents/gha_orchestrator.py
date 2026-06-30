"""
gha_orchestrator

Runs the full CI/CD security + publishing analysis pipeline for a GitHub org.
Single pass, full reports, pushes to one private repo.

Inputs:
  github_owner      — GitHub org to scan (e.g. "apache")
  read_pat          — PAT with read access to org repos (for prefetch + run history)
  write_repo        — repo to push reports to (e.g. "apache/tooling-agents-private")
  write_directory   — directory within repo (e.g. "gha-review")
  write_pat         — PAT with write access to write_repo
  skip_prefetch     — "true" to skip Phase 1 and use cached data (default "false")

Outputs (pushed to write_repo/write_directory/):
  gha_brief.md                — executive action plan
  gha_review.md               — combined risk assessment
  gha_publishing.md           — workflow classification results
  gha_security.md             — all security findings
  gha_publishing_detail.md    — enriched: secrets, action SHAs, triggers, run history
  gha_publishing_risks.md     — dangerous patterns analysis
  gha_artifact_verification.md — registry cross-reference
  gha_atr_catalog.json        — Apache Trusted Releases feed
  gha_channel_pypi.md         — per-channel detail (one per active channel)
  gha_channel_npm.md
  gha_channel_maven_central.md
  gha_channel_docker_hub.md
  ...
  gha_json_export.json        — machine-readable structured export

Pipeline:
  Phase 1: Prefetch           (caches workflow YAML from GitHub API)
  Phase 2: Analysis + Reports
    ├─ Publishing              (LLM classification)
    ├─ Security                (pattern-matching)
    ├─ Publishing Detail       (YAML parsing + GitHub API run history)
    ├─ Artifact Verify         (registry API queries)
    ├─ Review                  (combined risk assessment)
    ├─ Brief                   (executive summary)
    └─ JSON Export             (machine-readable)
"""

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = {url: RemoteMCPClient(remote_url=url) for url in tools.keys()}
    http_client = httpx.AsyncClient()
    try:
        import json

        # ── Inputs ──
        github_owner = input_dict.get("github_owner", "").strip()
        read_pat = input_dict.get("read_pat", "").strip()
        write_repo = input_dict.get("write_repo", "").strip()
        write_directory = input_dict.get("write_directory", "").strip()
        write_pat = input_dict.get("write_pat", "").strip()
        skip_prefetch = str(input_dict.get("skip_prefetch", "false")).lower().strip() in ("true", "1", "yes")

        for name, val in [("github_owner", github_owner), ("read_pat", read_pat),
                          ("write_repo", write_repo), ("write_directory", write_directory),
                          ("write_pat", write_pat)]:
            if not val:
                return {"outputText": f"Error: `{name}` is required."}

        pushed = []   # (filename, status)
        errors = []

        # ── Helpers ──

        async def push_file(filename, content, commit_msg):
            try:
                filepath = f"{write_directory}/{filename}" if write_directory else filename
                result = await gofannon_client.call(
                    agent_name="add_markdown_file_to_github_directory",
                    input_dict={
                        "inputText": json.dumps({
                            "repo": write_repo,
                            "token": write_pat,
                            "filePath": filepath,
                        }),
                        "commitMessage": commit_msg,
                        "fileContents": content,
                    }
                )
                output = result.get("outputText", "")
                if "error" in output.lower() and "message" in output.lower():
                    pushed.append((filename, "ERROR"))
                    errors.append(f"Push {filename}: {output[:200]}")
                    print(f"  ✗ {filename}", flush=True)
                else:
                    pushed.append((filename, "OK"))
                    print(f"  ✓ {filename}", flush=True)
            except Exception as e:
                pushed.append((filename, "ERROR"))
                errors.append(f"Push {filename}: {e}")
                print(f"  ✗ {filename}: {e}", flush=True)

        async def run_agent(name, **kwargs):
            try:
                result = await gofannon_client.call(
                    agent_name=name,
                    input_dict={k: str(v) for k, v in kwargs.items() if v},
                )
                return result.get("outputText", "")
            except Exception as e:
                errors.append(f"Agent {name}: {e}")
                print(f"  ✗ AGENT {name}: {e}", flush=True)
                return None

        async def push_multi_file_output(output, fallback_name):
            """Parse JSON {files: {name: content}} and push each with gha_ prefix."""
            if not output:
                return
            try:
                data = json.loads(output)
                files = data.get("files", {})
                for fname, content in sorted(files.items()):
                    gha_name = "gha_" + fname.replace("-", "_")
                    await push_file(gha_name, content,
                        f"CI scan: {fname} ({github_owner})")
                return
            except (json.JSONDecodeError, AttributeError):
                pass
            await push_file(fallback_name, output,
                f"CI scan: {fallback_name} ({github_owner})")

        # ══════════════════════════════════════════════════
        # Phase 1: Prefetch
        # ══════════════════════════════════════════════════

        prefetch_stats = {}

        if skip_prefetch:
            print(f"\n{'='*60}", flush=True)
            print(f"Phase 1: SKIPPED (using cache)", flush=True)
            print(f"{'='*60}\n", flush=True)
        else:
            print(f"\n{'='*60}", flush=True)
            print(f"Phase 1: Prefetch — {github_owner}", flush=True)
            print(f"{'='*60}\n", flush=True)

            prefetch_output = await run_agent("gha_prefetch",
                github_owner=github_owner,
                read_pat=read_pat)

            if prefetch_output is None:
                return {"outputText": "Error: Prefetch failed.\n\n" + "\n".join(errors)}
            try:
                prefetch_stats = json.loads(prefetch_output)
            except Exception:
                pass

        # ══════════════════════════════════════════════════
        # Phase 2: Analysis + Reports
        # ══════════════════════════════════════════════════

        print(f"\n{'='*60}", flush=True)
        print(f"Phase 2: Analysis + Reports", flush=True)
        print(f"{'='*60}\n", flush=True)

        print("▸ Publishing classification...", flush=True)
        publishing_report = await run_agent("gha_publishing",
            github_owner=github_owner)
        if publishing_report:
            await push_file("gha_publishing.md", publishing_report,
                f"CI scan: publishing ({github_owner})")

        print("▸ Security analysis...", flush=True)
        security_report = await run_agent("gha_security",
            github_owner=github_owner)
        if security_report:
            await push_file("gha_security.md", security_report,
                f"CI scan: security ({github_owner})")

        print("▸ Publishing detail...", flush=True)
        detail_output = await run_agent("gha_publishing_detail",
            github_owner=github_owner,
            read_pat=read_pat)
        await push_multi_file_output(detail_output, "gha_publishing_detail.md")

        print("▸ Artifact verification...", flush=True)
        verify_output = await run_agent("gha_artifact_verify",
            github_owner=github_owner)
        await push_multi_file_output(verify_output, "gha_artifact_verification.md")

        print("▸ Combined review...", flush=True)
        review_report = await run_agent("gha_review",
            github_owner=github_owner)
        if review_report:
            await push_file("gha_review.md", review_report,
                f"CI scan: review ({github_owner})")

        print("▸ Executive brief...", flush=True)
        brief_report = await run_agent("gha_brief",
            github_owner=github_owner)
        if brief_report:
            await push_file("gha_brief.md", brief_report,
                f"CI scan: brief ({github_owner})")

        print("▸ JSON export...", flush=True)
        json_report = await run_agent("gha_json_export",
            github_owner=github_owner)
        if json_report:
            await push_file("gha_json_export.json", json_report,
                f"CI scan: JSON export ({github_owner})")

        # ══════════════════════════════════════════════════
        # Summary
        # ══════════════════════════════════════════════════

        summary = []
        summary.append(f"# CI Security Scan: {github_owner}\n")

        if prefetch_stats:
            summary.append("## Prefetch\n")
            for k in ('repos', 'wf_fetched', 'wf_skipped', 'wf_yaml_cached', 'ca_total', 'errors'):
                summary.append(f"- {k}: {prefetch_stats.get(k, '?')}")
            summary.append("")

        if brief_report:
            for line in brief_report.split("\n"):
                if line.startswith("*") and "repos scanned" in line:
                    summary.append("## Scan\n")
                    summary.append(line)
                    summary.append("")
                    break

        n_ok = sum(1 for _, s in pushed if s == "OK")
        n_err = sum(1 for _, s in pushed if s != "OK")

        summary.append("## Files\n")
        summary.append(f"Target: `{write_repo}/{write_directory}/`\n")
        for fname, status in pushed:
            icon = "✓" if status == "OK" else "✗"
            summary.append(f"- [{icon}] `{fname}`")
        summary.append("")

        if errors:
            summary.append(f"## Errors ({len(errors)})\n")
            for e in errors:
                summary.append(f"- {e}")
            summary.append("")

        summary.append("---\n")
        summary.append(f"*{n_ok} files pushed, {n_err} errors.*")

        return {"outputText": "\n".join(summary)}

    finally:
        await http_client.aclose()
