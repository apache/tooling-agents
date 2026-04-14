from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        owner = input_dict.get("owner", "apache")
        github_pat = input_dict.get("github_pat", "").strip()
        clear_cache_raw = input_dict.get("clear_cache", "false")
        clear_cache = str(clear_cache_raw).lower().strip() in ("true", "1", "yes")
        repos_filter_str = input_dict.get("repos", "").strip()

        if not github_pat:
            return {"outputText": "Error: `github_pat` is required."}

        GITHUB_API = "https://api.github.com"
        gh_headers = {"Accept": "application/vnd.github.v3+json", "Authorization": f"token {github_pat}"}

        workflow_ns = data_store.use_namespace(f"ci-workflows:{owner}")
        security_ns = data_store.use_namespace(f"ci-security:{owner}")

        if clear_cache:
            print("Clear cache requested — will re-scan all repos (no deletions needed).", flush=True)

        all_wf_keys = workflow_ns.list_keys()
        if not all_wf_keys:
            return {"outputText": "Error: no cached workflows found in `ci-workflows:" + owner + "`. "
                    "Run the Publishing Analyzer agent first."}

        repos = {}
        for key in all_wf_keys:
            if "/" in key:
                repo, wf_name = key.split("/", 1)
                repos.setdefault(repo, []).append(wf_name)

        # Filter to specific repos if provided
        if repos_filter_str:
            repo_filter = set(r.strip() for r in repos_filter_str.split(",") if r.strip())
            repos = {r: wfs for r, wfs in repos.items() if r in repo_filter}
            print(f"Filtered to {len(repos)} repos: {', '.join(sorted(repos.keys()))}\n", flush=True)
        else:
            print(f"Found {len(all_wf_keys)} cached workflows across {len(repos)} repos\n", flush=True)

        async def github_get(url, max_retries=3):
            for attempt in range(max_retries):
                try:
                    resp = await http_client.get(url, headers=gh_headers, timeout=15.0)
                    if resp.status_code == 429 or (resp.status_code == 403 and
                            resp.headers.get("X-RateLimit-Remaining", "1") == "0"):
                        await asyncio.sleep(30)
                        continue
                    return resp
                except Exception:
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2)
            return None

        TRUSTED_ORGS = {
            "actions", "github", "docker", "google-github-actions", "aws-actions",
            "azure", "hashicorp", "gradle", "ruby", "codecov", "peaceiris",
            "pypa", "peter-evans", "softprops", "JamesIves", "crazy-max",
            "dorny", "EnricoMi", "pnpm", "apache",
        }

        # ASF policy: actions in apache/*, github/*, actions/* MAY be used
        # without restrictions. Only actions outside these orgs MUST be
        # SHA-pinned. See https://infra.apache.org/github-actions-policy.html
        ASF_EXEMPT_ORGS = {"actions", "github", "apache"}

        PR_TRIGGERS = {"pull_request", "pull_request_target", "issue_comment"}

        # --- Pattern matching helpers ---

        def is_sha_pinned(ref):
            if not ref:
                return False
            return len(ref) == 40 and all(c in "0123456789abcdef" for c in ref.lower())

        def extract_action_refs(content):
            refs = []
            for line in content.split("\n"):
                stripped = line.strip()
                if "uses:" in stripped:
                    idx = stripped.index("uses:")
                    action_ref = stripped[idx + 5:].strip().strip("'\"")
                    if "#" in action_ref:
                        action_ref = action_ref[:action_ref.index("#")].strip()
                    if action_ref and not action_ref.startswith("$"):
                        refs.append(action_ref)
            return refs

        def parse_action_ref(ref):
            if ref.startswith("./"):
                return {"type": "local", "path": ref, "raw": ref}
            if "@" in ref:
                action_path, version = ref.rsplit("@", 1)
                parts = action_path.split("/")
                org = parts[0] if parts else ""
                name = "/".join(parts[:2]) if len(parts) >= 2 else action_path
                return {"type": "remote", "org": org, "name": name, "full": action_path,
                        "version": version, "pinned": is_sha_pinned(version), "raw": ref}
            return {"type": "unknown", "raw": ref}

        def extract_triggers(content):
            triggers = set()
            in_on = False
            for line in content.split("\n"):
                stripped = line.strip()
                if stripped.startswith("on:"):
                    in_on = True
                    rest = stripped[3:].strip()
                    if rest.startswith("["):
                        for t in rest.strip("[]").split(","):
                            triggers.add(t.strip())
                        in_on = False
                    elif rest and not rest.startswith("#"):
                        triggers.add(rest.rstrip(":"))
                    continue
                if in_on:
                    if stripped and not stripped.startswith("#"):
                        if not line.startswith(" ") and not line.startswith("\t"):
                            in_on = False
                            continue
                        if ":" in stripped:
                            trigger_name = stripped.split(":")[0].strip()
                            if trigger_name and not trigger_name.startswith("-"):
                                triggers.add(trigger_name)
            return triggers

        def extract_permissions(content):
            perms = {}
            in_perms = False
            indent = 0
            for line in content.split("\n"):
                stripped = line.strip()
                if stripped.startswith("permissions:"):
                    rest = stripped[12:].strip()
                    if rest and rest != "{}" and not rest.startswith("#"):
                        perms["_level"] = rest
                        return perms
                    in_perms = True
                    indent = len(line) - len(line.lstrip())
                    continue
                if in_perms:
                    if not stripped or stripped.startswith("#"):
                        continue
                    cur_indent = len(line) - len(line.lstrip())
                    if cur_indent <= indent and stripped:
                        break
                    if ":" in stripped:
                        key, val = stripped.split(":", 1)
                        perms[key.strip()] = val.strip()
            return perms

        def find_injection_in_run_blocks(content, context_label="", triggers=None):
            """Find ${{ }} interpolation in run: blocks. Returns list of (severity, detail, line_num)."""
            findings = []
            in_run = False
            run_indent = 0
            current_step = ""

            for line_num, line in enumerate(content.split("\n"), 1):
                stripped = line.strip()

                if stripped.startswith("- name:"):
                    current_step = stripped[7:].strip().strip("'\"")

                if stripped.startswith("run:"):
                    in_run = True
                    run_indent = len(line) - len(line.lstrip())
                    run_content = stripped[4:].strip()
                    if run_content.startswith("|") or run_content.startswith(">"):
                        continue
                    if "${{" in run_content:
                        findings.extend(_classify_interpolation(run_content, current_step, context_label, triggers, line_num))
                    in_run = False
                    continue

                if in_run:
                    cur_indent = len(line) - len(line.lstrip())
                    if stripped and cur_indent <= run_indent:
                        in_run = False
                    elif "${{" in line:
                        findings.extend(_classify_interpolation(line, current_step, context_label, triggers, line_num))

            return findings

        def _classify_interpolation(line, step_name, context_label="", triggers=None, line_num=None):
            findings = []
            prefix = f" in {context_label}" if context_label else ""
            step_info = f" at step '{step_name}'" if step_name else ""
            triggers = triggers or set()

            import re as _re
            exprs = _re.findall(r'\$\{\{([^}]+)\}\}', line)

            # Determine if PR-related expressions are actually dangerous based on trigger
            # pull_request: fork PRs don't get secrets, so interpolation is low risk
            # pull_request_target: fork PRs DO get base repo secrets — dangerous
            has_prt = "pull_request_target" in triggers
            has_pr_only = "pull_request" in triggers and not has_prt

            for expr in exprs:
                expr = expr.strip()
                expr_lower = expr.lower()

                untrusted_patterns = [
                    "event.pull_request.title", "event.pull_request.body",
                    "event.pull_request.head.ref", "event.pull_request.head.label",
                    "event.issue.title", "event.issue.body",
                    "event.comment.body", "event.review.body",
                    "event.discussion.title", "event.discussion.body",
                ]
                if any(p in expr_lower for p in untrusted_patterns):
                    if has_pr_only:
                        # pull_request trigger: fork PRs don't get secrets
                        findings.append(("LOW",
                            f"Untrusted input `${{{{ {expr} }}}}` interpolated in run block"
                            f"{step_info}{prefix}. Trigger is `pull_request` (not `pull_request_target`), "
                            f"so fork PRs do not have access to secrets. "
                            f"Same-repo PRs are from committers. Shell injection possible but low impact.",
                            line_num))
                    else:
                        findings.append(("CRITICAL",
                            f"Direct interpolation of untrusted input `${{{{ {expr} }}}}` in run block"
                            f"{step_info}{prefix}. Exploitable by external contributors.",
                            line_num))
                    continue

                if "secrets." in expr_lower:
                    findings.append(("LOW",
                        f"Secret `${{{{ {expr} }}}}` directly interpolated in run block"
                        f"{step_info}{prefix}. Trusted value but risks log leakage.",
                        line_num))
                    continue

                if "event.inputs." in expr_lower or "inputs." in expr_lower:
                    findings.append(("LOW",
                        f"Workflow input `${{{{ {expr} }}}}` directly interpolated in run block"
                        f"{step_info}{prefix}. Trusted committer input but should use env: block.",
                        line_num))
                    continue

                github_controlled = [
                    "github.actor", "github.sha", "github.ref", "github.repository",
                    "github.run_id", "github.run_number", "github.workspace",
                    "github.ref_name", "github.head_ref", "github.base_ref",
                    "runner.", "matrix.", "steps.", "needs.", "env.",
                ]
                if any(p in expr_lower for p in github_controlled):
                    continue

            return findings

        def extract_trigger_event_types(content, trigger_name):
            """Extract event types for any trigger (e.g., pull_request_target, pull_request).
            Returns set of types like {'labeled', 'opened', 'synchronize'}."""
            types = set()
            in_trigger = False
            trigger_indent = 0
            for line in content.split("\n"):
                stripped = line.strip()
                indent = len(line) - len(line.lstrip())
                if stripped.startswith(trigger_name):
                    in_trigger = True
                    trigger_indent = indent
                    continue
                if in_trigger:
                    if stripped and indent <= trigger_indent and not stripped.startswith("types"):
                        break
                    if stripped.startswith("types:"):
                        rest = stripped[6:].strip()
                        if rest.startswith("["):
                            for t in rest.strip("[]").split(","):
                                types.add(t.strip())
                        continue
                    if stripped.startswith("-"):
                        types.add(stripped.lstrip("- ").strip())
            return types

        def extract_prt_event_types(content):
            """Extract event types for pull_request_target (e.g., labeled, opened, synchronize)."""
            return extract_trigger_event_types(content, "pull_request_target")

        def check_prt_checkout(content):
            triggers = extract_triggers(content)
            if "pull_request_target" not in triggers:
                return None

            # Parse checkout steps and their ref: parameters
            lines = content.split("\n")
            in_checkout = False
            checkout_indent = 0
            checkouts = []  # list of (has_ref, ref_value, checkout_line, ref_line)
            current_ref = None
            current_checkout_line = None
            current_ref_line = None

            for i, line in enumerate(lines):
                stripped = line.strip()
                indent = len(line) - len(line.lstrip())

                if "actions/checkout" in stripped and ("uses:" in stripped or "uses :" in stripped):
                    if in_checkout:
                        checkouts.append((current_ref is not None, current_ref or "",
                                          current_checkout_line, current_ref_line))
                    in_checkout = True
                    checkout_indent = indent
                    current_ref = None
                    current_checkout_line = i + 1  # 1-indexed
                    current_ref_line = None
                    continue

                if in_checkout:
                    if stripped and indent <= checkout_indent and not stripped.startswith("with:"):
                        checkouts.append((current_ref is not None, current_ref or "",
                                          current_checkout_line, current_ref_line))
                        in_checkout = False
                        current_ref = None
                        current_checkout_line = None
                        current_ref_line = None
                    elif "ref:" in stripped:
                        current_ref = stripped.split("ref:", 1)[1].strip()
                        current_ref_line = i + 1

            if in_checkout:
                checkouts.append((current_ref is not None, current_ref or "",
                                  current_checkout_line, current_ref_line))

            if not checkouts:
                return None

            # Classify each checkout
            pr_head_patterns = [
                "pull_request.head.sha",
                "pull_request.head.ref",
                "github.event.pull_request.head",
                "github.head_ref",
            ]

            checks_pr_head = False
            has_explicit_base = False
            has_no_ref = False
            finding_line = None

            for has_ref, ref_value, checkout_line, ref_line in checkouts:
                if not has_ref:
                    has_no_ref = True
                    finding_line = checkout_line
                    continue
                ref_lower = ref_value.lower()
                if any(pat in ref_lower for pat in pr_head_patterns):
                    checks_pr_head = True
                    finding_line = ref_line or checkout_line
                    break
                if "base.sha" in ref_lower or "base.ref" in ref_lower:
                    has_explicit_base = True
                    finding_line = checkout_line

            if not checks_pr_head:
                if has_no_ref and not has_explicit_base:
                    return ("INFO", "pull_request_target trigger with checkout action (default ref). "
                            "Default behavior checks out base branch — safe unless ref: is added later.",
                            finding_line)
                elif has_explicit_base:
                    return ("INFO", "pull_request_target trigger with explicit base ref checkout. Safe.",
                            finding_line)
                else:
                    return ("LOW", "pull_request_target trigger with checkout action using custom ref. "
                            "Verify the ref does not resolve to untrusted PR code.",
                            finding_line)

            # --- PR head IS checked out — assess mitigating factors ---

            # Factor 1: Event types — is this maintainer-gated?
            prt_types = extract_prt_event_types(content)
            maintainer_gated_types = {"labeled", "unlabeled", "assigned", "unassigned",
                                       "review_requested", "review_request_removed"}

            is_maintainer_gated = False
            if prt_types and prt_types.issubset(maintainer_gated_types):
                is_maintainer_gated = True

            # Factor 2: Permissions — what can the workflow actually do?
            perms = extract_permissions(content)
            dangerous_perms = {"contents", "packages", "id-token", "actions"}
            has_dangerous_perms = False
            perm_level = perms.get("_level", "")

            if perm_level in ("write-all",):
                has_dangerous_perms = True
            elif not perms:
                # No permissions block at all — inherits repo defaults (often broad)
                has_dangerous_perms = True
            else:
                for perm_name in dangerous_perms:
                    if perms.get(perm_name) == "write":
                        has_dangerous_perms = True
                        break

            # Build detail with mitigating factors
            mitigations = []
            if is_maintainer_gated:
                mitigations.append(f"trigger restricted to maintainer-gated events ({', '.join(sorted(prt_types))})")
            if not has_dangerous_perms:
                write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
                mitigations.append(f"limited permissions ({', '.join(write_perms) if write_perms else 'read-only'})")

            # Determine severity
            if is_maintainer_gated and not has_dangerous_perms:
                return ("LOW",
                        "pull_request_target checks out PR head code, but risk is mitigated: "
                        + "; ".join(mitigations) + ". "
                        "Maintainer must trigger the workflow and permissions limit blast radius.",
                        finding_line)
            elif is_maintainer_gated:
                return ("MEDIUM",
                        "pull_request_target checks out PR head code with dangerous permissions, "
                        "but trigger requires maintainer action ("
                        + ", ".join(sorted(prt_types)) + "). "
                        "A maintainer labeling a malicious PR would grant it access to secrets.",
                        finding_line)
            elif not has_dangerous_perms:
                write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
                return ("MEDIUM",
                        "pull_request_target checks out PR head code, but permissions are limited to: "
                        + (", ".join(write_perms) if write_perms else "read-only") + ". "
                        "Blast radius is reduced — no access to publishing secrets or contents:write.",
                        finding_line)
            else:
                return ("CRITICAL",
                        "pull_request_target trigger with explicit checkout of PR head code "
                        "(ref: github.event.pull_request.head). Untrusted PR code executes with "
                        "base repo secrets and write permissions.",
                        finding_line)

        def check_self_hosted(content, triggers):
            # Find first line with self-hosted
            sh_line = None
            for line_num, line in enumerate(content.split("\n"), 1):
                if "self-hosted" in line:
                    sh_line = line_num
                    break
            if sh_line is None:
                return None

            has_pr_trigger = bool(triggers & PR_TRIGGERS)
            if not has_pr_trigger:
                return ("INFO", "Uses self-hosted runners. Ensure runners are ephemeral.", sh_line)

            # --- PR trigger present — assess mitigating factors (same 2x2 as prt_checkout) ---

            # Factor 1: Event types — is this maintainer-gated?
            maintainer_gated_types = {"labeled", "unlabeled", "assigned", "unassigned",
                                       "review_requested", "review_request_removed"}
            pr_event_types = set()
            for t in ("pull_request_target", "pull_request"):
                if t in triggers:
                    pr_event_types |= extract_trigger_event_types(content, t)

            is_maintainer_gated = bool(pr_event_types) and pr_event_types.issubset(maintainer_gated_types)

            # Factor 2: Permissions — what can the workflow actually do?
            perms = extract_permissions(content)
            dangerous_perms = {"contents", "packages", "id-token", "actions"}
            has_dangerous_perms = False
            perm_level = perms.get("_level", "")

            if perm_level in ("write-all",):
                has_dangerous_perms = True
            elif not perms:
                has_dangerous_perms = True
            else:
                for perm_name in dangerous_perms:
                    if perms.get(perm_name) == "write":
                        has_dangerous_perms = True
                        break

            # Build detail with mitigating factors
            mitigations = []
            if is_maintainer_gated:
                mitigations.append(f"trigger restricted to maintainer-gated events ({', '.join(sorted(pr_event_types))})")
            if not has_dangerous_perms:
                write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
                mitigations.append(f"limited permissions ({', '.join(write_perms) if write_perms else 'read-only'})")

            # Determine severity (same 2x2 as prt_checkout but HIGH ceiling instead of CRITICAL)
            if is_maintainer_gated and not has_dangerous_perms:
                return ("LOW",
                        "Self-hosted runner with PR trigger, but risk is mitigated: "
                        + "; ".join(mitigations) + ". "
                        "Maintainer must trigger the workflow and permissions limit blast radius.",
                        sh_line)
            elif is_maintainer_gated:
                return ("MEDIUM",
                        "Self-hosted runner with PR trigger and dangerous permissions, "
                        "but trigger requires maintainer action ("
                        + ", ".join(sorted(pr_event_types)) + "). "
                        "A maintainer labeling a malicious PR would grant runner access to secrets.",
                        sh_line)
            elif not has_dangerous_perms:
                write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
                return ("MEDIUM",
                        "Self-hosted runner with PR trigger, but permissions are limited to: "
                        + (", ".join(write_perms) if write_perms else "read-only") + ". "
                        "Blast radius is reduced — no access to publishing secrets or contents:write.",
                        sh_line)
            else:
                return ("HIGH",
                        "Self-hosted runner with PR trigger. External contributors can "
                        "execute arbitrary code on self-hosted infrastructure with broad permissions.",
                        sh_line)

        def check_permissions(content):
            perms = extract_permissions(content)
            findings = []
            # Find the permissions: line
            perm_line = None
            for line_num, line in enumerate(content.split("\n"), 1):
                if line.strip().startswith("permissions:"):
                    perm_line = line_num
                    break
            level = perms.get("_level", "")
            if level in ("write-all", "read-all|write-all"):
                findings.append(("HIGH", "Workflow uses `permissions: write-all`. "
                                 "Follow least-privilege principle.", perm_line))
            write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
            if len(write_perms) > 3:
                findings.append(("LOW", f"Requests write access to {len(write_perms)} scopes: "
                                 f"{', '.join(write_perms)}.", perm_line))
            return findings

        def check_cache_poisoning(content, triggers):
            has_pr = bool(triggers & {"pull_request", "pull_request_target"})
            has_cache = "actions/cache" in content
            if has_cache and has_pr:
                # Find the actions/cache line
                cache_line = None
                for line_num, line in enumerate(content.split("\n"), 1):
                    if "actions/cache" in line:
                        cache_line = line_num
                        break
                for line_num, line in enumerate(content.split("\n"), 1):
                    if "key:" in line and ("pull_request" in line or "head_ref" in line):
                        return ("HIGH", "Cache key derived from PR-controlled value. "
                                "A malicious PR could poison the cache.", line_num)
                return ("INFO", "Uses actions/cache with PR trigger. Verify cache keys "
                        "are not PR-controlled.", cache_line)
            return None

        def deduplicate_findings(findings):
            """Collapse repeated same-check same-file findings into summaries."""
            deduped = []
            # Group by (check, file, severity)
            groups = {}
            for f in findings:
                key = (f["check"], f["file"], f["severity"])
                groups.setdefault(key, []).append(f)

            def _collect_lines(items):
                """Collect non-null line numbers from a list of findings."""
                return sorted(set(item["line"] for item in items if item.get("line")))

            for (check, file, severity), items in groups.items():
                if len(items) == 1:
                    deduped.append(items[0])
                elif check in ("run_block_injection", "composite_action_injection"):
                    # Summarize: extract unique expressions
                    import re as _re
                    exprs = set()
                    for item in items:
                        found = _re.findall(r'`\$\{\{ ([^}]+) \}\}`', item["detail"])
                        exprs.update(found)
                    expr_list = sorted(exprs)[:5]
                    expr_str = ", ".join(f"`{e}`" for e in expr_list)
                    more = f" +{len(exprs) - 5} more" if len(exprs) > 5 else ""
                    collected = _collect_lines(items)
                    entry = {
                        "check": check,
                        "file": file,
                        "severity": severity,
                        "detail": (f"{len(items)} instances of direct interpolation in run blocks. "
                                   f"Expressions: {expr_str}{more}."),
                        "count": len(items),
                    }
                    if collected:
                        entry["lines"] = collected
                    deduped.append(entry)
                elif check == "composite_action_unpinned":
                    # Summarize unpinned refs inside one composite action
                    refs = [item["detail"].split("`")[1] if "`" in item["detail"] else "?" for item in items]
                    unique_refs = sorted(set(refs))
                    collected = _collect_lines(items)
                    entry = {
                        "check": check,
                        "file": file,
                        "severity": severity,
                        "detail": (f"{len(items)} unpinned action refs in composite action: "
                                   f"{', '.join(f'`{r}`' for r in unique_refs[:5])}"
                                   + (f" +{len(unique_refs)-5} more" if len(unique_refs) > 5 else "")),
                        "count": len(items),
                    }
                    if collected:
                        entry["lines"] = collected
                    deduped.append(entry)
                else:
                    # For other checks, keep first and note count
                    entry = dict(items[0])
                    if len(items) > 1:
                        entry["detail"] = f"({len(items)}x) {entry['detail']}"
                        entry["count"] = len(items)
                        collected = _collect_lines(items)
                        if collected:
                            entry["lines"] = collected
                    deduped.append(entry)

            return deduped


        # ===== Main scan loop =====
        all_findings = {}
        repos_scanned = 0

        for repo_name, wf_names in sorted(repos.items()):
            repos_scanned += 1

            if repos_scanned % 10 == 1:
                print(f"[{repos_scanned}/{len(repos)}] Scanning {repo_name}...", flush=True)

            cached = security_ns.get(f"findings:{repo_name}")
            if cached is not None and not clear_cache:
                if cached:
                    all_findings[repo_name] = cached
                continue

            repo_findings = []
            all_action_refs = []
            repo_triggers = set()

            # --- Analyze each cached workflow ---
            for wf_name in wf_names:
                # Skip composite action files — analyzed separately in Check 9
                if ".github/actions/" in wf_name:
                    continue

                content = workflow_ns.get(f"{repo_name}/{wf_name}")
                if not content or not isinstance(content, str):
                    continue

                triggers = extract_triggers(content)
                repo_triggers.update(triggers)
                action_refs = extract_action_refs(content)
                all_action_refs.extend([(wf_name, ref) for ref in action_refs])

                # Check 1: pull_request_target + checkout
                prt = check_prt_checkout(content)
                if prt:
                    repo_findings.append({"check": "prt_checkout", "severity": prt[0],
                                          "file": wf_name, "detail": prt[1],
                                          "line": prt[2] if len(prt) > 2 else None})

                # Check 2: Self-hosted runners
                sh = check_self_hosted(content, triggers)
                if sh:
                    repo_findings.append({"check": "self_hosted_runner", "severity": sh[0],
                                          "file": wf_name, "detail": sh[1],
                                          "line": sh[2] if len(sh) > 2 else None})

                # Check 3: Permissions
                for item in check_permissions(content):
                    repo_findings.append({"check": "broad_permissions", "severity": item[0],
                                          "file": wf_name, "detail": item[1],
                                          "line": item[2] if len(item) > 2 else None})

                # Check 4: Cache poisoning
                cp = check_cache_poisoning(content, triggers)
                if cp:
                    repo_findings.append({"check": "cache_poisoning", "severity": cp[0],
                                          "file": wf_name, "detail": cp[1],
                                          "line": cp[2] if len(cp) > 2 else None})

                # Check 5: Injection in workflow run blocks
                injections = find_injection_in_run_blocks(content, context_label=f"workflow {wf_name}", triggers=triggers)
                for item in injections:
                    repo_findings.append({"check": "run_block_injection", "severity": item[0],
                                          "file": wf_name, "detail": item[1],
                                          "line": item[2] if len(item) > 2 else None})

            # Check 6: Unpinned actions (repo-wide summary)
            unpinned = []
            third_party = []
            for wf_name, ref in all_action_refs:
                parsed = parse_action_ref(ref)
                if parsed["type"] == "local":
                    continue
                if parsed["type"] == "remote":
                    # ASF policy: actions in apache/*, github/*, actions/* are
                    # exempt from pinning requirements. Only flag unpinned refs
                    # for actions outside these namespaces.
                    if not parsed["pinned"] and parsed["org"] not in ASF_EXEMPT_ORGS:
                        unpinned.append({"file": wf_name, "action": parsed["raw"],
                                         "org": parsed["org"], "name": parsed["name"]})
                    if parsed["org"] not in TRUSTED_ORGS:
                        third_party.append({"file": wf_name, "action": parsed["raw"],
                                            "org": parsed["org"], "name": parsed["name"]})

            if unpinned:
                by_action = {}
                for u in unpinned:
                    by_action.setdefault(u["name"], []).append(u["file"])
                top = sorted(by_action.items(), key=lambda x: -len(x[1]))[:5]
                detail_parts = [f"`{name}` ({len(files)})" for name, files in top]
                repo_findings.append({
                    "check": "unpinned_actions", "severity": "MEDIUM",
                    "file": "(repo-wide)",
                    "detail": (f"{len(unpinned)} unpinned third-party action refs (mutable tags, "
                               f"outside actions/*/github/*/apache/*). "
                               f"Top: {', '.join(detail_parts)}."),
                    "count": len(unpinned), "total_refs": len(all_action_refs),
                })

            if third_party:
                unique = sorted(set(t["name"] for t in third_party))
                repo_findings.append({
                    "check": "third_party_actions", "severity": "INFO",
                    "file": "(repo-wide)",
                    "detail": (f"{len(unique)} third-party actions: "
                               f"{', '.join(unique[:10])}"
                               + (f" +{len(unique)-10} more" if len(unique) > 10 else "")),
                    "count": len(unique),
                })

            # --- Fetch extra files from GitHub ---

            # Check 7: CODEOWNERS
            resp = await github_get(f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/.github/CODEOWNERS")
            if resp and resp.status_code == 200:
                try:
                    co_url = resp.json().get("download_url")
                    if co_url:
                        co_resp = await http_client.get(co_url, follow_redirects=True, timeout=10.0)
                        if co_resp.status_code == 200:
                            co_content = co_resp.text
                            has_github_rule = any(".github" in line and not line.strip().startswith("#")
                                                  for line in co_content.split("\n"))
                            if not has_github_rule:
                                repo_findings.append({
                                    "check": "codeowners_gap", "severity": "LOW",
                                    "file": "CODEOWNERS",
                                    "detail": "CODEOWNERS exists but has no rule covering `.github/`. "
                                              "Workflow changes can bypass security-focused review.",
                                })
                except Exception:
                    pass
            elif resp and resp.status_code == 404:
                repo_findings.append({
                    "check": "missing_codeowners", "severity": "LOW",
                    "file": "(missing)",
                    "detail": "No CODEOWNERS file. Workflow changes have no mandatory review.",
                })

            # Check 8: Dependabot / Renovate
            has_deps = False
            for path in [".github/dependabot.yml", ".github/dependabot.yaml",
                         "renovate.json", ".github/renovate.json", ".renovaterc.json"]:
                resp = await github_get(f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{path}")
                if resp and resp.status_code == 200:
                    has_deps = True
                    break

            if not has_deps:
                repo_findings.append({
                    "check": "missing_dependency_updates", "severity": "LOW",
                    "file": "(missing)",
                    "detail": "No dependabot.yml or renovate.json found. ASF policy requires automated dependency management.",
                })

            # Check 9: Composite actions — read from prefetch cache or fall back to GitHub
            composite_findings = []
            composite_analyzed = 0
            composite_total = 0

            # Collect (action_name, short_path, action_content) tuples
            composite_items = []

            composites_meta = workflow_ns.get(f"__composites__:{repo_name}")
            if composites_meta and composites_meta.get("complete"):
                # Read from prefetch cache
                cached_actions = composites_meta.get("actions", [])
                for short_path in cached_actions:
                    action_content = workflow_ns.get(f"{repo_name}/{short_path}")
                    if action_content:
                        action_name = short_path.replace(".github/actions/", "").rsplit("/", 1)[0]
                        composite_items.append((action_name, short_path, action_content))
            else:
                # Fall back to GitHub API
                resp = await github_get(
                    f"{GITHUB_API}/repos/{owner}/{repo_name}/git/trees/HEAD?recursive=1")
                if resp and resp.status_code == 200:
                    try:
                        tree = resp.json().get("tree", [])
                        action_files = [
                            item["path"] for item in tree
                            if item.get("path", "").startswith(".github/actions/")
                            and item.get("path", "").endswith(("/action.yml", "/action.yaml"))
                            and item.get("type") == "blob"
                        ]
                        for action_path in action_files:
                            action_name = action_path.replace(".github/actions/", "").rsplit("/", 1)[0]
                            aresp = await github_get(
                                f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{action_path}")
                            if not aresp or aresp.status_code != 200:
                                continue
                            try:
                                dl_url = aresp.json().get("download_url")
                                if not dl_url:
                                    continue
                                dl_resp = await http_client.get(dl_url, follow_redirects=True, timeout=10.0)
                                if dl_resp.status_code != 200:
                                    continue
                                action_content = dl_resp.text
                                short_path = f".github/actions/{action_name}/action.yml"
                                workflow_ns.set(f"{repo_name}/{short_path}", action_content)
                                composite_items.append((action_name, short_path, action_content))
                            except Exception:
                                continue
                    except Exception as e:
                        print(f"  Error scanning composite actions for {repo_name}: {str(e)[:100]}", flush=True)

            composite_total = len(composite_items)

            # Analyze each composite action
            for action_name, short_path, action_content in composite_items:
                composite_analyzed += 1

                # Run injection checks
                context = f"composite action .github/actions/{action_name}"
                injections = find_injection_in_run_blocks(action_content, context_label=context)
                for item in injections:
                    composite_findings.append({
                        "check": "composite_action_injection",
                        "severity": item[0],
                        "file": short_path,
                        "detail": item[1],
                        "line": item[2] if len(item) > 2 else None,
                    })

                # Check unpinned actions inside composite (only third-party per ASF policy)
                ca_refs = extract_action_refs(action_content)
                for ref in ca_refs:
                    parsed = parse_action_ref(ref)
                    if (parsed["type"] == "remote" and not parsed["pinned"]
                            and parsed["org"] not in ASF_EXEMPT_ORGS):
                        # Find the line with this uses: ref
                        ref_line = None
                        for ln, cl in enumerate(action_content.split("\n"), 1):
                            if ref in cl:
                                ref_line = ln
                                break
                        composite_findings.append({
                            "check": "composite_action_unpinned",
                            "severity": "MEDIUM",
                            "file": short_path,
                            "detail": (f"Composite action uses unpinned action `{parsed['raw']}`. "
                                       "Supply chain risk."),
                            "line": ref_line,
                        })

                # Check inputs.* directly in run blocks (hidden injection)
                has_input_injection = False
                input_inj_line = None
                in_run = False
                run_indent = 0
                for ln, cline in enumerate(action_content.split("\n"), 1):
                    cs = cline.strip()
                    if cs.startswith("run:"):
                        in_run = True
                        run_indent = len(cline) - len(cline.lstrip())
                        rest = cs[4:].strip()
                        if rest.startswith("|") or rest.startswith(">"):
                            continue
                        if "inputs." in rest and "${{" in rest:
                            has_input_injection = True
                            input_inj_line = ln
                            break
                    elif in_run:
                        ci = len(cline) - len(cline.lstrip())
                        if cs and ci <= run_indent:
                            in_run = False
                        elif "inputs." in cline and "${{" in cline:
                            has_input_injection = True
                            input_inj_line = ln
                            break

                if has_input_injection:
                    composite_findings.append({
                        "check": "composite_action_input_injection",
                        "severity": "MEDIUM",
                        "file": short_path,
                        "detail": (f"Composite action `{action_name}` directly interpolates "
                                   "`inputs.*` in run block. Not exploitable unless a calling workflow "
                                   "passes attacker-controlled values (PR title, branch name, comment body). "
                                   "Currently a latent injection surface — verify callers only pass trusted input."),
                        "line": input_inj_line,
                    })

            # Deduplicate composite findings per file before adding
            composite_findings = deduplicate_findings(composite_findings)
            repo_findings.extend(composite_findings)

            if composite_total > 0:
                print(f"  Composite actions: {composite_analyzed}/{composite_total} analyzed, "
                      f"{len(composite_findings)} finding(s)", flush=True)

            # Deduplicate all findings for this repo
            repo_findings = deduplicate_findings(repo_findings)

            # Store
            security_ns.set(f"findings:{repo_name}", repo_findings)
            if repo_findings:
                all_findings[repo_name] = repo_findings

            await asyncio.sleep(0.1)

        print(f"\n{'=' * 60}", flush=True)
        print(f"Security scan complete! {repos_scanned} repos", flush=True)
        total_findings = sum(len(f) for f in all_findings.values())
        print(f"Total findings: {total_findings} across {len(all_findings)} repos", flush=True)
        print(f"{'=' * 60}\n", flush=True)

        # ===== Build report =====
        report_title = f"CI Security Scan: {owner}"

        severity_counts = {}
        check_counts = {}
        for repo, findings in all_findings.items():
            for f in findings:
                sev = f.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                chk = f.get("check", "unknown")
                check_counts[chk] = check_counts.get(chk, 0) + 1

        lines = []
        lines.append(f"Analyzed **{repos_scanned}** repositories using cached workflow YAML "
                     f"from the Publishing Analyzer.\n")

        lines.append("## Executive Summary\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                lines.append(f"| **{sev}** | **{count}** |")
        lines.append("")

        check_descriptions = {
            "prt_checkout": "pull_request_target + checkout (CRITICAL only when ref: points to PR head)",
            "self_hosted_runner": "Self-hosted runners exposed to PR triggers",
            "broad_permissions": "Overly broad GITHUB_TOKEN permissions",
            "cache_poisoning": "Potential cache poisoning via PR-controlled keys",
            "run_block_injection": "Direct ${{ }} interpolation in workflow run blocks",
            "unpinned_actions": "Third-party actions not SHA-pinned (ASF policy violation)",
            "third_party_actions": "Actions from outside actions/*/github/*/apache/* namespaces",
            "codeowners_gap": "CODEOWNERS missing .github/ coverage",
            "missing_codeowners": "No CODEOWNERS file",
            "missing_dependency_updates": "No dependabot/renovate configuration (ASF policy violation)",
            "composite_action_injection": "Injection in composite action run block",
            "composite_action_unpinned": "Third-party unpinned action ref inside composite action",
            "composite_action_input_injection": "Latent injection surface — composite action interpolates inputs.* in run block",
        }

        lines.append("## Findings by Check Type\n")
        lines.append("| Check | Count | Description |")
        lines.append("|-------|-------|-------------|")
        for chk, count in sorted(check_counts.items(), key=lambda x: -x[1]):
            desc = check_descriptions.get(chk, chk)
            lines.append(f"| {chk} | {count} | {desc} |")
        lines.append("")

        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for repo, findings in all_findings.items():
            for f in findings:
                sev = f.get("severity", "INFO")
                if sev in by_severity:
                    by_severity[sev].append((repo, f))

        def file_ref(f):
            """Format file reference with line number(s) if available."""
            name = f.get("file", "")
            if f.get("lines"):
                return f"{name}:{','.join(str(l) for l in f['lines'])}"
            elif f.get("line"):
                return f"{name}:{f['line']}"
            return name

        if by_severity["CRITICAL"]:
            lines.append("## CRITICAL Findings\n")
            lines.append("Untrusted external input directly interpolated in shell execution contexts.\n")
            for repo, f in sorted(by_severity["CRITICAL"], key=lambda x: (x[0], x[1].get("file", ""))):
                lines.append(f"- **{owner}/{repo}** (`{file_ref(f)}`): [{f['check']}] {f['detail']}")
            lines.append("")

        if by_severity["HIGH"]:
            lines.append("## HIGH Findings\n")
            for repo, f in sorted(by_severity["HIGH"], key=lambda x: (x[0], x[1].get("file", ""))):
                lines.append(f"- **{owner}/{repo}** (`{file_ref(f)}`): [{f['check']}] {f['detail']}")
            lines.append("")

        if by_severity["MEDIUM"]:
            lines.append("## MEDIUM Findings\n")
            lines.append(f"<details>\n<summary>Show {len(by_severity['MEDIUM'])} medium findings</summary>\n")
            for repo, f in sorted(by_severity["MEDIUM"], key=lambda x: (x[0], x[1].get("file", ""))):
                lines.append(f"- **{owner}/{repo}** (`{file_ref(f)}`): [{f['check']}] {f['detail']}")
            lines.append(f"\n</details>\n")

        if by_severity["LOW"]:
            lines.append("## LOW Findings\n")
            lines.append(f"<details>\n<summary>Show {len(by_severity['LOW'])} low findings</summary>\n")
            for repo, f in sorted(by_severity["LOW"], key=lambda x: (x[0], x[1].get("file", ""))):
                lines.append(f"- **{owner}/{repo}** (`{file_ref(f)}`): [{f['check']}] {f['detail']}")
            lines.append(f"\n</details>\n")

        if by_severity["INFO"]:
            lines.append("## INFO Findings\n")
            lines.append(f"<details>\n<summary>Show {len(by_severity['INFO'])} info findings</summary>\n")
            for repo, f in sorted(by_severity["INFO"], key=lambda x: (x[0], x[1].get("file", ""))):
                lines.append(f"- **{owner}/{repo}** (`{file_ref(f)}`): [{f['check']}] {f['detail']}")
            lines.append(f"\n</details>\n")

        lines.append("## Detailed Results by Repository\n")
        for repo in sorted(all_findings.keys()):
            findings = all_findings[repo]
            if not findings:
                continue
            sev_summary = {}
            for f in findings:
                sev_summary[f["severity"]] = sev_summary.get(f["severity"], 0) + 1
            sev_str = ", ".join(f"{s}: {c}" for s, c in sorted(sev_summary.items()))

            lines.append(f"### {owner}/{repo}\n")
            lines.append(f"**{len(findings)}** findings | {sev_str}\n")

            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            for f in sorted(findings, key=lambda x: sev_order.get(x["severity"], 99)):
                lines.append(f"- **[{f['severity']}]** `{file_ref(f)}` — [{f['check']}] {f['detail']}")
            lines.append("")

        lines.append("---\n")
        lines.append(f"*Findings cached in `ci-security:{owner}`. "
                     f"Set `clear_cache` to `true` to re-scan.*")

        report_body = "\n".join(lines)

        def to_anchor(text):
            anchor = text.lower().strip()
            anchor = re.sub(r'[^\w\s-]', '', anchor)
            anchor = re.sub(r'\s+', '-', anchor)
            anchor = re.sub(r'-+', '-', anchor)
            return anchor.strip('-')

        toc_lines = [f"# {report_title}\n", "## Contents\n"]
        toc_lines.append(f"- [Executive Summary](#{to_anchor('Executive Summary')})")
        toc_lines.append(f"- [Findings by Check Type](#{to_anchor('Findings by Check Type')})")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if by_severity.get(sev):
                toc_lines.append(f"- [{sev} Findings](#{to_anchor(f'{sev} Findings')}) ({len(by_severity[sev])})")
        toc_lines.append(f"- [Detailed Results](#{to_anchor('Detailed Results by Repository')})")
        for repo in sorted(all_findings.keys()):
            toc_lines.append(f"  - [{owner}/{repo}](#{to_anchor(f'{owner}/{repo}')})")

        toc = "\n".join(toc_lines)
        full_report = toc + "\n\n---\n\n" + report_body

        security_ns.set("latest_report", full_report)
        security_ns.set("latest_stats", {
            "repos_scanned": repos_scanned,
            "repos_with_findings": len(all_findings),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "check_counts": check_counts,
        })

        return {"outputText": full_report}

    finally:
        await http_client.aclose()