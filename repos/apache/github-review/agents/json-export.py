from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
import re

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        owner = input_dict.get("owner", "apache")
        print(f"Agent 4 (JSON export) starting for owner={owner}", flush=True)

        report_ns = data_store.use_namespace(f"ci-report:{owner}")
        security_ns = data_store.use_namespace(f"ci-security:{owner}")
        classification_ns = data_store.use_namespace(f"ci-classification:{owner}")

        pub_stats = report_ns.get("latest_stats")
        sec_stats = security_ns.get("latest_stats")

        if not pub_stats or not sec_stats:
            return {"outputText": "Error: Run Agent 1 and Agent 2 first."}

        # --- Collect all repos ---
        publishing_repos = set(pub_stats.get("publishing_repos", []))

        # --- Read per-repo classifications from Agent 1 cache ---
        all_cls_keys = classification_ns.list_keys()
        meta_keys = [k for k in all_cls_keys if k.startswith("__meta__:")]

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

        # --- Read per-repo security findings from Agent 2 cache ---
        all_sec_keys = security_ns.list_keys()
        finding_keys = [k for k in all_sec_keys if k.startswith("findings:")]

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
            return {
                "severity": f.get("severity", "INFO"),
                "check": f.get("check", "unknown"),
                "file": f.get("file", "unknown"),
                "description": f.get("description", ""),
            }

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

        # --- Build top-level summary ---
        output = {
            "schema_version": "1.0",
            "owner": owner,
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
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