from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
import re

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        owner = input_dict.get("owner", "apache")
        repos_str = input_dict.get("repos", "").strip()
        repo_filter = set(r.strip() for r in repos_str.split(",") if r.strip()) if repos_str else None
        print(f"Executive brief starting for owner={owner}" +
              (f" (filtered to {len(repo_filter)} repos)" if repo_filter else ""), flush=True)

        report_ns = data_store.use_namespace(f"ci-report:{owner}")
        security_ns = data_store.use_namespace(f"ci-security:{owner}")

        pub_stats = report_ns.get("latest_stats")
        sec_stats = security_ns.get("latest_stats")

        if not pub_stats or not sec_stats:
            return {"outputText": "Error: Run Publishing and Security agents first."}

        publishing_repos = set(pub_stats.get("publishing_repos", []))
        if repo_filter:
            publishing_repos = publishing_repos & repo_filter
        repos_scanned = len(repo_filter) if repo_filter else pub_stats.get("repos_scanned", 0)
        total_workflows = pub_stats.get("total_workflows", 0)
        tp_workflow_count = pub_stats.get("trusted_publishing_opportunities", 0)
        pub_report = report_ns.get("latest_report")

        # Count unique repos needing TP migration (not workflows — one repo can have multiple)
        tp_repo_set = set()
        if pub_report:
            in_tp_section = False
            for line in pub_report.split("\n"):
                stripped = line.strip()
                if "Trusted Publishing Migration" in stripped and stripped.startswith("#"):
                    in_tp_section = True
                    continue
                if in_tp_section:
                    # Stop at the next ## heading (but not ### subheadings within TP section)
                    if stripped.startswith("## ") and "Trusted Publishing" not in stripped:
                        break
                    # Parse table rows
                    if stripped.startswith("|") and "|" in stripped[1:]:
                        parts = [p.strip() for p in stripped.split("|")]
                        if len(parts) >= 3 and parts[1] and parts[1] not in ("Repository", ""):
                            repo_name = parts[1].strip().strip("`").strip()
                            if repo_name and not repo_name.startswith("-"):
                                if repo_filter is None or repo_name in repo_filter:
                                    tp_repo_set.add(repo_name)
        tp_count = len(tp_repo_set) if tp_repo_set else tp_workflow_count
        eco_counts = pub_stats.get("ecosystem_counts", {})

        sev_counts = sec_stats.get("severity_counts", {})
        check_counts = sec_stats.get("check_counts", {})
        total_findings = sec_stats.get("total_findings", 0)

        # --- Read per-repo findings to build specifics ---
        all_sec_keys = security_ns.list_keys()
        finding_keys = [k for k in all_sec_keys if k.startswith("findings:")]
        if repo_filter:
            finding_keys = [k for k in finding_keys if k.replace("findings:", "") in repo_filter]

        # Collect CRITICAL, HIGH, and composite injection findings with repo context
        critical_findings = []  # (repo, file, check, detail)
        high_publishing = []    # (repo, file, check, detail)
        high_nonpublishing = [] # (repo, file, check, detail)
        composite_injection_repos = set()  # repos with composite_action_input_injection

        repos_with_critical = set()
        repos_with_high = set()
        repos_unpinned = 0

        for k in finding_keys:
            repo = k.replace("findings:", "")
            findings = security_ns.get(k)
            if not findings or not isinstance(findings, list):
                continue

            has_unpinned = False
            for f in findings:
                sev = f.get("severity", "INFO")
                check = f.get("check", "unknown")
                detail = f.get("detail", "")
                file = f.get("file", "")

                if sev == "CRITICAL":
                    critical_findings.append((repo, file, check, detail))
                    repos_with_critical.add(repo)
                elif sev == "HIGH":
                    repos_with_high.add(repo)
                    if repo in publishing_repos:
                        high_publishing.append((repo, file, check, detail))
                    else:
                        high_nonpublishing.append((repo, file, check, detail))

                if check == "composite_action_input_injection" and repo in publishing_repos:
                    composite_injection_repos.add(repo)

                if check == "unpinned_actions":
                    has_unpinned = True

            if has_unpinned:
                repos_unpinned += 1

        # Deduplicate HIGH to repo level for the brief
        high_pub_repos = sorted(set(r for r, _, _, _ in high_publishing))
        high_nonpub_repos = sorted(set(r for r, _, _, _ in high_nonpublishing))

        # --- Parse per-repo ecosystems from pub_report for context ---
        repo_ecosystems = {}
        if pub_report:
            header_pattern = re.compile(
                r'### ' + re.escape(f'{owner}/') + r'(\S+)\s*\n+'
                r'\*\*(\d+)\*\* release/snapshot workflows \| Ecosystems: \*\*([^*]+)\*\*')
            for m in header_pattern.finditer(pub_report):
                repo_ecosystems[m.group(1)] = [e.strip() for e in m.group(3).split(",")]

        print(f"CRITICAL: {len(critical_findings)} findings in {len(repos_with_critical)} repos", flush=True)
        print(f"HIGH (publishing): {len(high_publishing)} findings in {len(high_pub_repos)} repos", flush=True)
        print(f"HIGH (non-publishing): {len(high_nonpublishing)} findings in {len(high_nonpub_repos)} repos", flush=True)

        # --- Build brief ---
        PUB = "publishing.md"
        SEC = "security.md"
        REVIEW = "review.md"
        JSON = "json-export.json"

        def plural(n, singular, plural_form=None):
            if plural_form is None:
                plural_form = singular + "s"
            return singular if n == 1 else plural_form

        lines = []
        lines.append(f"# Apache CI Security: Action Required\n")

        lines.append("## Goal\n")
        lines.append(f"Identify CI pipelines across {repos_scanned} Apache GitHub repositories that could be "
                     f"exploited to compromise published packages or leak secrets. "
                     f"**{len(publishing_repos)}** repos publish to registries including "
                     f"npm, PyPI, Maven Central, Docker Hub, and crates.io.\n")

        # --- Section 1: Exploitable now ---
        n_crit = len(repos_with_critical)
        if critical_findings:
            lines.append("## Exploitable Now\n")
            lines.append(f"**{n_crit}** {plural(n_crit, 'repo')} have workflows where an external contributor "
                         f"can execute arbitrary code with access to repository secrets and write permissions.\n")

            # Group by check type
            crit_by_check = {}
            for repo, file, check, detail in critical_findings:
                crit_by_check.setdefault(check, []).append((repo, file, detail))

            for check, items in sorted(crit_by_check.items(), key=lambda x: -len(x[1])):
                check_labels = {
                    "prt_checkout": "pull_request_target with PR code checkout",
                    "run_block_injection": "untrusted input injection in run blocks",
                }
                label = check_labels.get(check, check)

                # Show which ones are publishing repos
                for repo, file, detail in sorted(items):
                    eco = repo_ecosystems.get(repo)
                    eco_str = f" — publishes to **{', '.join(eco)}**" if eco else ""
                    lines.append(f"- **{owner}/{repo}** `{file}`: {label}{eco_str}")

            lines.append("")

        # --- Section 2: High-risk publishing repos ---
        if high_pub_repos:
            n_high = len(high_pub_repos)
            lines.append("## High Risk: Publishing Repos\n")
            lines.append(f"**{n_high}** {plural(n_high, 'repo')} that publish packages have HIGH-severity findings.\n")

            for repo in high_pub_repos:
                eco = repo_ecosystems.get(repo)
                eco_str = f" ({', '.join(eco)})" if eco else ""
                lines.append(f"- **{owner}/{repo}**{eco_str}")

            lines.append("")

        # --- Section 2b: Composite injection in publishing repos ---
        # These are now MEDIUM but still worth calling out for publishing repos
        ca_pub_only = sorted(composite_injection_repos - repos_with_high - repos_with_critical)
        if ca_pub_only:
            n_ca = len(ca_pub_only)
            lines.append("## Latent Risk: Composite Action Injection in Publishing Repos\n")
            lines.append(f"**{n_ca}** {plural(n_ca, 'repo')} that publish packages have composite actions that "
                         f"interpolate `inputs.*` in shell blocks. Not exploitable today — callers pass "
                         f"trusted values — but one unsafe caller away from shell injection.\n")

            for repo in ca_pub_only:
                eco = repo_ecosystems.get(repo)
                eco_str = f" ({', '.join(eco)})" if eco else ""
                lines.append(f"- **{owner}/{repo}**{eco_str}")

            lines.append("")

        # --- Section 3: Systemic issues ---
        lines.append("## Systemic Issues\n")

        if tp_count:
            lines.append(f"**Trusted publishing migration.** {tp_count} {plural(tp_count, 'repo')} "
                         f"use long-lived secrets (NPM_TOKEN, PYPI_API_TOKEN, etc.) to publish to "
                         f"registries that support OIDC. Migrating to trusted publishing eliminates "
                         f"stored secrets entirely. "
                         f"([migration details]({PUB}#trusted-publishing-migration-opportunities))\n")

        if repos_unpinned:
            lines.append(f"**Unpinned actions.** {repos_unpinned} {plural(repos_unpinned, 'repo')} "
                         f"reference GitHub Actions by mutable tag instead of SHA pin. "
                         f"A compromised action tag (like the [tj-actions/changed-files incident](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-attack)) "
                         f"would execute in every affected workflow. "
                         f"([finding details]({SEC}#medium-findings))\n")

        codeowners_missing = check_counts.get("missing_codeowners", 0)
        if codeowners_missing:
            lines.append(f"**No workflow review gates.** {codeowners_missing} {plural(codeowners_missing, 'repo')} "
                         f"have no CODEOWNERS file. Any committer can modify workflow files — adding "
                         f"triggers, weakening permissions, or introducing injection patterns — "
                         f"without mandatory security review.\n")

        # --- Section 4: What to do ---
        lines.append("## Recommended Actions\n")

        rec_num = 1
        if critical_findings:
            lines.append(f"{rec_num}. **Fix CRITICAL workflows this week.** "
                         f"The {n_crit} repos above have workflows that grant external PRs access to "
                         f"publishing secrets. Remediation: change `pull_request_target` checkout to use "
                         f"`github.event.pull_request.base.sha` or split into two workflows.\n")
            rec_num += 1

        if tp_count:
            lines.append(f"{rec_num}. **Migrate to trusted publishing this quarter.** "
                         f"Start with PyPI (easiest — `pypa/gh-action-pypi-publish` supports OIDC natively) "
                         f"then npm (`--provenance` flag). Eliminates the highest-value secrets from CI.\n")
            rec_num += 1

        if high_pub_repos:
            n_hp = len(high_pub_repos)
            lines.append(f"{rec_num}. **Investigate HIGH findings in publishing repos.** "
                         f"The {n_hp} {plural(n_hp, 'repo')} above {plural(n_hp, 'has', 'have')} "
                         f"HIGH-severity issues that need review.\n")
            rec_num += 1

        if ca_pub_only:
            n_ca = len(ca_pub_only)
            lines.append(f"{rec_num}. **Audit composite action callers.** "
                         f"{n_ca} publishing {plural(n_ca, 'repo')} {plural(n_ca, 'has', 'have')} composite "
                         f"actions that interpolate `inputs.*` in shell blocks. Verify no workflow passes "
                         f"untrusted values (PR title, branch name, comment body) to these actions.\n")
            rec_num += 1

        if repos_unpinned > 20:
            lines.append(f"{rec_num}. **Pin actions to SHA in publishing repos first.** "
                         f"Use [StepSecurity/secure-repo](https://github.com/step-security/secure-repo) "
                         f"to bulk-pin actions. Prioritize the {len(publishing_repos)} repos that publish packages.\n")
            rec_num += 1

        # --- Section 5: Full analysis links ---
        lines.append("## Full Analysis\n")
        lines.append(f"- [{REVIEW}]({REVIEW}) — combined risk assessment with attack scenarios")
        lines.append(f"- [{PUB}]({PUB}) — which repos publish what, where, and how")
        lines.append(f"- [{SEC}]({SEC}) — all {total_findings} security findings by repo")
        lines.append(f"- [{JSON}]({JSON}) — machine-readable data ([query examples](README.md#jq-examples))")
        lines.append(f"- [README.md](README.md) — report guide, JSON schema, jq commands")
        lines.append("")

        # --- Stats footer ---
        lines.append("---\n")
        lines.append(f"*{repos_scanned} repos scanned, {total_workflows} workflows analyzed, "
                     f"{len(publishing_repos)} publish to registries, "
                     f"{total_findings} security findings.*")

        full_brief = "\n".join(lines)
        print(f"Brief: {len(full_brief)} chars", flush=True)

        combined_ns = data_store.use_namespace(f"ci-combined:{owner}")
        combined_ns.set("latest_brief", full_brief)

        return {"outputText": full_brief}

    finally:
        await http_client.aclose()