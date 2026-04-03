from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
import re

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        owner = input_dict.get("owner", "apache")
        print(f"Agent 3 starting for owner={owner}", flush=True)

        report_ns = data_store.use_namespace(f"ci-report:{owner}")
        security_ns = data_store.use_namespace(f"ci-security:{owner}")

        pub_stats = report_ns.get("latest_stats")
        sec_stats = security_ns.get("latest_stats")
        pub_report = report_ns.get("latest_report")
        sec_report = security_ns.get("latest_report")

        if not pub_stats or not sec_stats:
            return {"outputText": "Error: Run Agent 1 and Agent 2 first."}

        print(f"Publishing report: {len(pub_report or '')} chars", flush=True)
        print(f"Security report: {len(sec_report or '')} chars", flush=True)

        # --- Parse per-repo ecosystems from publishing report text ---
        repo_ecosystems = {}
        repo_categories = {}
        if pub_report:
            header_pattern = re.compile(
                r'### ' + re.escape(f'{owner}/') + r'(\S+)\s*\n+'
                r'\*\*(\d+)\*\* release/snapshot workflows \| Ecosystems: \*\*([^*]+)\*\*'
                r' \|(.+)')
            for m in header_pattern.finditer(pub_report):
                repo = m.group(1)
                ecosystems = [e.strip() for e in m.group(3).split(",")]
                repo_ecosystems[repo] = ecosystems
                cats_str = m.group(4)
                cats = {}
                for cat_m in re.finditer(r'(Release Artifacts|Snapshot[^:]*): (\d+)', cats_str):
                    if "Release" in cat_m.group(1):
                        cats["release"] = int(cat_m.group(2))
                    else:
                        cats["snapshot"] = int(cat_m.group(2))
                repo_categories[repo] = cats

        print(f"Parsed ecosystems for {len(repo_ecosystems)} repos", flush=True)

        # --- Read per-repo security findings ---
        all_sec_keys = security_ns.list_keys()
        finding_keys = [k for k in all_sec_keys if k.startswith("findings:")]

        repo_security = {}

        for k in finding_keys:
            repo = k.replace("findings:", "")
            findings = security_ns.get(k)
            if not findings or not isinstance(findings, list):
                continue

            sev_counts = {}
            check_counts = {}
            for f in findings:
                sev = f.get("severity", "INFO")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                chk = f.get("check", "unknown")
                if sev != "INFO":
                    check_counts[chk] = check_counts.get(chk, 0) + 1

            worst = "INFO"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if sev_counts.get(s, 0) > 0:
                    worst = s
                    break

            top_checks = sorted(check_counts.items(), key=lambda x: -x[1])[:3]

            repo_security[repo] = {
                "severities": sev_counts,
                "total": len(findings),
                "worst": worst,
                "top_checks": top_checks,
            }

        print(f"Security data for {len(repo_security)} repos", flush=True)

        # --- Parse trusted publishing opportunities ---
        tp_repos = set()
        tp_opportunities = pub_stats.get("trusted_publishing_opportunities", [])
        if isinstance(tp_opportunities, list):
            for opp in tp_opportunities:
                if isinstance(opp, dict):
                    tp_repos.add(opp.get("repo", ""))
                elif isinstance(opp, str):
                    tp_repos.add(opp)
        if pub_report:
            tp_section = False
            for line in pub_report.split("\n"):
                if "Trusted Publishing Migration" in line:
                    tp_section = True
                    continue
                if tp_section and line.startswith("## ") and "Trusted" not in line:
                    break
                if tp_section and "| " in line and "`" in line:
                    parts = line.split("|")
                    if len(parts) > 1:
                        repo_name = parts[1].strip()
                        if repo_name and repo_name != "Repository":
                            tp_repos.add(repo_name)

        print(f"Trusted publishing opportunity repos: {len(tp_repos)}", flush=True)

        # --- Build combined risk table ---
        publishing_repos = set(pub_stats.get("publishing_repos", []))
        all_repos = publishing_repos | set(repo_security.keys())

        repo_rows = []
        for repo in sorted(all_repos):
            ecosystems = repo_ecosystems.get(repo, [])
            sec = repo_security.get(repo, {})
            worst = sec.get("worst", "—")
            total = sec.get("total", 0)
            sev_counts = sec.get("severities", {})
            top_checks = sec.get("top_checks", [])
            cats = repo_categories.get(repo, {})
            publishes = repo in publishing_repos
            has_tp_opportunity = repo in tp_repos

            eco_score = len(ecosystems) if ecosystems else (1 if publishes else 0)
            sev_score = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 10, "LOW": 3, "INFO": 1, "—": 0}.get(worst, 0)
            risk_score = eco_score * sev_score + total

            repo_rows.append({
                "repo": repo,
                "ecosystems": ecosystems,
                "publishes": publishes,
                "worst": worst,
                "total": total,
                "sev_counts": sev_counts,
                "top_checks": top_checks,
                "cats": cats,
                "has_tp": has_tp_opportunity,
                "risk_score": risk_score,
            })

        repo_rows.sort(key=lambda r: -r["risk_score"])

        # --- Classify into tiers ---
        critical_repos = [r for r in repo_rows if r["worst"] == "CRITICAL"]
        high_repos = [r for r in repo_rows if r["worst"] == "HIGH"]
        high_publishing = [r for r in high_repos if r["publishes"]]
        high_nonpublishing = [r for r in high_repos if not r["publishes"]]
        medium_repos = [r for r in repo_rows if r["worst"] == "MEDIUM" and r["publishes"]]
        low_repos = [r for r in repo_rows if r["worst"] in ("LOW", "INFO", "—") and r["publishes"]]

        # --- Generate report ---
        PUB = "apache-github-publishing.md"
        SEC = "apache-github-security.md"

        def anchor(text):
            a = text.lower().strip()
            a = re.sub(r'[^\w\s-]', '', a)
            a = re.sub(r'\s+', '-', a)
            a = re.sub(r'-+', '-', a)
            return a.strip('-')

        def repo_pub_link(repo):
            return f"[publishing]({PUB}#{anchor(f'{owner}/{repo}')})"

        def repo_sec_link(repo):
            return f"[security]({SEC}#{anchor(f'{owner}/{repo}')})"

        def eco_str(ecosystems):
            if not ecosystems:
                return "—"
            return ", ".join(ecosystems)

        def sev_summary(sev_counts):
            parts = []
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                c = sev_counts.get(s, 0)
                if c > 0:
                    parts.append(f"{c} {s}")
            return ", ".join(parts) if parts else "INFO only"

        def check_summary(top_checks):
            if not top_checks:
                return ""
            return ", ".join(f"{chk} ({n})" for chk, n in top_checks)

        def plural(n, singular, plural_form=None):
            if plural_form is None:
                plural_form = singular + "s"
            return singular if n == 1 else plural_form

        lines = []
        lines.append(f"# Apache GitHub Review: Combined Risk Assessment\n")
        lines.append(f"Cross-referencing CI publishing analysis with security scan results "
                     f"across **{len(all_repos)}** repositories.\n")

        lines.append("## Companion Reports\n")
        lines.append(f"| Report | Description |")
        lines.append(f"|--------|-------------|")
        lines.append(f"| [{PUB}]({PUB}) | Which repos publish packages to registries, "
                     f"what ecosystems, auth methods, trusted publishing opportunities. "
                     f"{pub_stats.get('total_workflows', '?')} workflows across "
                     f"{pub_stats.get('repos_scanned', '?')} repos. |")
        lines.append(f"| [{SEC}]({SEC}) | Pattern-matching security checks on cached workflow YAML: "
                     f"injection patterns, unpinned actions, permissions, composite action analysis. "
                     f"{sec_stats.get('total_findings', '?')} findings across "
                     f"{sec_stats.get('repos_with_findings', '?')} repos. |")
        lines.append("")

        # --- At a glance ---
        lines.append("## At a Glance\n")
        lines.append(f"| Metric | Value |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Repos scanned | {pub_stats.get('repos_scanned', '?')} |")
        lines.append(f"| Repos publishing to registries | {len(publishing_repos)} |")
        lines.append(f"| Total security findings | {sec_stats.get('total_findings', '?')} |")
        sev = sec_stats.get("severity_counts", {})
        if sev.get("CRITICAL", 0):
            lines.append(f"| CRITICAL findings | {sev.get('CRITICAL', 0)} |")
        if sev.get("HIGH", 0):
            lines.append(f"| HIGH findings | {sev.get('HIGH', 0)} |")
        if tp_repos:
            lines.append(f"| Repos needing trusted publishing migration | {len(tp_repos)} |")
        eco = pub_stats.get("ecosystem_counts", {})
        doc_targets = {"codecov", "github_pages", "surge_sh", "s3", "gcr", "ghcr"}
        release_eco = {k: v for k, v in eco.items() if k not in doc_targets}
        top_eco = sorted(release_eco.items(), key=lambda x: -x[1])[:5]
        eco_summary = ", ".join(f"{e} ({c})" for e, c in top_eco) if top_eco else "none"
        lines.append(f"| Top ecosystems | {eco_summary} |")
        lines.append("")

        # --- CRITICAL + HIGH publishing tier ---
        immediate = critical_repos + high_publishing
        if immediate:
            lines.append("## Immediate Attention Required\n")
            lines.append("Repos with CRITICAL or HIGH security findings that also publish packages.\n")

            for r in immediate:
                repo = r["repo"]
                lines.append(f"### {owner}/{repo}\n")

                eco_display = eco_str(r["ecosystems"])
                cat_parts = []
                if r["cats"].get("release"):
                    cat_parts.append(f"{r['cats']['release']} release")
                if r["cats"].get("snapshot"):
                    cat_parts.append(f"{r['cats']['snapshot']} snapshot")
                cat_display = ", ".join(cat_parts) if cat_parts else ""

                details = []
                if r["publishes"] and r["ecosystems"]:
                    pub_line = f"**Publishes to:** {eco_display}"
                    if cat_display:
                        pub_line += f" ({cat_display})"
                    details.append(pub_line)
                elif r["publishes"]:
                    details.append(f"**Publishes:** yes (see {repo_pub_link(repo)})")

                details.append(f"**Security:** {r['total']} findings — {sev_summary(r['sev_counts'])}")

                if r["top_checks"]:
                    details.append(f"**Top issues:** {check_summary(r['top_checks'])}")

                if r["has_tp"]:
                    details.append(f"**Trusted publishing:** migration opportunity — currently using long-lived tokens "
                                   f"([details]({PUB}#trusted-publishing-migration-opportunities))")

                details.append(f"**Details:** {repo_pub_link(repo)} · {repo_sec_link(repo)}")

                lines.append("  \n".join(details))
                lines.append("")

        # --- HIGH non-publishing repos ---
        if high_nonpublishing:
            lines.append("## Non-Publishing Repos with HIGH Findings\n")
            lines.append("These repos do not publish packages but have HIGH-severity security findings "
                         "in their CI workflows.\n")

            for r in high_nonpublishing:
                repo = r["repo"]
                lines.append(f"### {owner}/{repo}\n")

                details = []
                details.append(f"**Security:** {r['total']} findings — {sev_summary(r['sev_counts'])}")

                if r["top_checks"]:
                    details.append(f"**Top issues:** {check_summary(r['top_checks'])}")

                details.append(f"**Details:** {repo_sec_link(repo)}")

                lines.append("  \n".join(details))
                lines.append("")

        # --- MEDIUM tier: publishing repos ---
        if medium_repos:
            lines.append("## Moderate Risk: Publishing Repos with MEDIUM Findings\n")
            lines.append("These repos publish packages and have MEDIUM-severity findings (typically unpinned actions).\n")
            lines.append(f"| Repo | Ecosystems | Findings | Top Issue | Trusted Pub | Details |")
            lines.append(f"|------|-----------|----------|-----------|------------|---------|")

            for r in medium_repos:
                repo = r["repo"]
                eco = eco_str(r["ecosystems"]) if r["ecosystems"] else "—"
                top = r["top_checks"][0][0] if r["top_checks"] else "unpinned_actions"
                tp = "migrate" if r["has_tp"] else "—"
                links = f"{repo_pub_link(repo)} · {repo_sec_link(repo)}"
                lines.append(f"| {owner}/{repo} | {eco} | {r['total']} | {top} | {tp} | {links} |")

            lines.append("")

        # --- LOW tier summary ---
        if low_repos:
            n_low = len(low_repos)
            lines.append("## Low Risk: Publishing Repos\n")
            lines.append(f"{n_low} {plural(n_low, 'repo')} {plural(n_low, 'publishes', 'publish')} packages with only LOW/INFO-level "
                         f"security findings (missing CODEOWNERS, no dependabot config).\n")
            lines.append(f"<details>\n<summary>Show {n_low} {plural(n_low, 'repo')}</summary>\n")
            for r in low_repos:
                repo = r["repo"]
                eco = eco_str(r["ecosystems"]) if r["ecosystems"] else "—"
                lines.append(f"- **{owner}/{repo}** — {eco} — {r['total']} findings "
                             f"({repo_pub_link(repo)} · {repo_sec_link(repo)})")
            lines.append(f"\n</details>\n")

        # --- Trusted Publishing summary (skip if none) ---
        if tp_repos:
            n_tp = len(tp_repos)
            lines.append("## Trusted Publishing Opportunities\n")
            lines.append(f"**{n_tp}** {plural(n_tp, 'repo')} {plural(n_tp, 'uses', 'use')} long-lived tokens to publish to ecosystems "
                         f"that support OIDC trusted publishing. Migrating eliminates stored secrets.\n")
            lines.append(f"Full details: [{PUB} → Trusted Publishing]"
                         f"({PUB}#trusted-publishing-migration-opportunities)\n")

            tp_ecosystems = {}
            if pub_report:
                current_eco = None
                for line in pub_report.split("\n"):
                    if line.startswith("### ") and "Trusted Publishing" not in line:
                        eco_name = line[4:].strip()
                        if eco_name in ("crates.io", "npm", "NuGet", "PyPI", "RubyGems"):
                            current_eco = eco_name
                            continue
                    if current_eco and line.startswith("## "):
                        current_eco = None
                        continue
                    if current_eco and "| " in line and "`" in line:
                        parts = [p.strip() for p in line.split("|")]
                        if len(parts) > 2 and parts[1] and parts[1] != "Repository":
                            tp_ecosystems.setdefault(current_eco, []).append(parts[1])

            for eco, repos in sorted(tp_ecosystems.items()):
                unique = sorted(set(repos))
                lines.append(f"- **{eco}**: {', '.join(unique)}")
            lines.append("")

        # --- Summary when nothing in the intersection ---
        if not publishing_repos:
            lines.append("## Summary\n")
            lines.append(f"None of the {pub_stats.get('repos_scanned', '?')} scanned repos publish packages to "
                         f"registries. Security findings are limited to general CI hygiene "
                         f"(unpinned actions, missing CODEOWNERS). See the "
                         f"[security report]({SEC}) for details.\n")

        # --- Key recommendations (only include items with nonzero counts) ---
        lines.append("## Key Recommendations\n")

        rec_num = 1

        if critical_repos:
            crit_names = ", ".join("`" + r["repo"] + "`" for r in critical_repos)
            verb = "has" if len(critical_repos) == 1 else "have"
            lines.append(f"{rec_num}. **Fix CRITICAL findings immediately.** "
                         f"{crit_names} {verb} exploitable CI vulnerabilities "
                         f"([details]({SEC})).")
            rec_num += 1

        if tp_repos:
            n_tp = len(tp_repos)
            lines.append(f"{rec_num}. **Migrate to trusted publishing.** "
                         f"{n_tp} {plural(n_tp, 'repo')} can eliminate long-lived secrets by adopting OIDC. "
                         f"Start with repos publishing to PyPI and npm — "
                         f"[migration guide]({PUB}#trusted-publishing-migration-opportunities).")
            rec_num += 1

        if high_repos:
            repos_with_high = [r for r in repo_rows
                               if r["sev_counts"].get("HIGH", 0) > 0]
            n_high = len(repos_with_high)
            lines.append(f"{rec_num}. **Review composite action injection patterns.** "
                         f"{n_high} {plural(n_high, 'repo')} {plural(n_high, 'has', 'have')} "
                         f"HIGH findings from `inputs.*` directly interpolated "
                         f"in composite action run blocks. While these are called from trusted contexts today, "
                         f"they create hidden injection surfaces.")
            rec_num += 1

        repos_with_findings = sec_stats.get("repos_with_findings", 0)
        if repos_with_findings:
            n_repos = repos_with_findings
            lines.append(f"{rec_num}. **Pin actions to SHA hashes.** "
                         f"{'The scanned repo uses' if n_repos == 1 else f'All {n_repos} repos use'} "
                         f"mutable tag refs. "
                         f"See the [unpinned actions findings]({SEC}#medium-findings) for per-repo counts.")
            rec_num += 1

        codeowners_missing = sec_stats.get("check_counts", {}).get("missing_codeowners", 0)
        codeowners_gap = sec_stats.get("check_counts", {}).get("codeowners_gap", 0)
        if codeowners_missing or codeowners_gap:
            parts = []
            if codeowners_missing:
                parts.append(f"{codeowners_missing} {plural(codeowners_missing, 'repo')} "
                             f"{plural(codeowners_missing, 'has', 'have')} no CODEOWNERS file")
            if codeowners_gap:
                parts.append(f"{codeowners_gap} {plural(codeowners_gap, 'has', 'have')} CODEOWNERS "
                             f"without `.github/` rules")
            lines.append(f"{rec_num}. **Add CODEOWNERS with `.github/` coverage.** "
                         f"{' and '.join(parts)}. Workflow changes can bypass security review.")
        lines.append("")

        lines.append("---\n")
        lines.append(f"*Generated from [{PUB}]({PUB}) and [{SEC}]({SEC}).*")

        full_report = "\n".join(lines)
        print(f"Report length: {len(full_report)} chars", flush=True)

        combined_ns = data_store.use_namespace(f"ci-combined:{owner}")
        combined_ns.set("latest_report", full_report)

        return {"outputText": full_report}

    finally:
        await http_client.aclose()