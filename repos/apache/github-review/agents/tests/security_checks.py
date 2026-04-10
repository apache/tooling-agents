"""
Security check functions extracted from agent-security-scanner-v3.py.

Keep in sync with Agent 2. When modifying checks in the agent,
update this module and run the tests before deploying.
"""
import re

PR_TRIGGERS = {"pull_request", "pull_request_target", "issue_comment"}

TRUSTED_ORGS = {
    "actions", "github", "docker", "google-github-actions", "aws-actions",
    "azure", "hashicorp", "gradle", "ruby", "codecov", "peaceiris",
    "pypa", "peter-evans", "softprops", "JamesIves", "crazy-max",
    "dorny", "EnricoMi", "pnpm", "apache",
}


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


def extract_prt_event_types(content):
    """Extract event types for pull_request_target (e.g., labeled, opened, synchronize)."""
    types = set()
    in_prt = False
    prt_indent = 0
    for line in content.split("\n"):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped.startswith("pull_request_target"):
            in_prt = True
            prt_indent = indent
            continue
        if in_prt:
            if stripped and indent <= prt_indent and not stripped.startswith("types"):
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


def _classify_interpolation(line, step_name, context_label="", triggers=None):
    findings = []
    prefix = f" in {context_label}" if context_label else ""
    step_info = f" at step '{step_name}'" if step_name else ""
    triggers = triggers or set()

    exprs = re.findall(r'\$\{\{([^}]+)\}\}', line)

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
                findings.append(("LOW",
                    f"Untrusted input `${{{{ {expr} }}}}` interpolated in run block"
                    f"{step_info}{prefix}. Trigger is `pull_request` (not `pull_request_target`), "
                    f"so fork PRs do not have access to secrets. "
                    f"Same-repo PRs are from committers. Shell injection possible but low impact."))
            else:
                findings.append(("CRITICAL",
                    f"Direct interpolation of untrusted input `${{{{ {expr} }}}}` in run block"
                    f"{step_info}{prefix}. Exploitable by external contributors."))
            continue

        if "secrets." in expr_lower:
            findings.append(("LOW",
                f"Secret `${{{{ {expr} }}}}` directly interpolated in run block"
                f"{step_info}{prefix}. Trusted value but risks log leakage."))
            continue

        if "event.inputs." in expr_lower or "inputs." in expr_lower:
            findings.append(("LOW",
                f"Workflow input `${{{{ {expr} }}}}` directly interpolated in run block"
                f"{step_info}{prefix}. Trusted committer input but should use env: block."))
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


def find_injection_in_run_blocks(content, context_label="", triggers=None):
    """Find ${{ }} interpolation in run: blocks. Returns list of (severity, detail)."""
    findings = []
    in_run = False
    run_indent = 0
    current_step = ""

    for line in content.split("\n"):
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
                findings.extend(_classify_interpolation(run_content, current_step, context_label, triggers))
            in_run = False
            continue

        if in_run:
            cur_indent = len(line) - len(line.lstrip())
            if stripped and cur_indent <= run_indent:
                in_run = False
            elif "${{" in line:
                findings.extend(_classify_interpolation(line, current_step, context_label, triggers))

    return findings


def check_prt_checkout(content):
    triggers = extract_triggers(content)
    if "pull_request_target" not in triggers:
        return None

    lines = content.split("\n")
    in_checkout = False
    checkout_indent = 0
    checkouts = []
    current_ref = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())

        if "actions/checkout" in stripped and ("uses:" in stripped or "uses :" in stripped):
            if in_checkout:
                checkouts.append((current_ref is not None, current_ref or ""))
            in_checkout = True
            checkout_indent = indent
            current_ref = None
            continue

        if in_checkout:
            if stripped and indent <= checkout_indent and not stripped.startswith("with:"):
                checkouts.append((current_ref is not None, current_ref or ""))
                in_checkout = False
                current_ref = None
            elif "ref:" in stripped:
                current_ref = stripped.split("ref:", 1)[1].strip()

    if in_checkout:
        checkouts.append((current_ref is not None, current_ref or ""))

    if not checkouts:
        return None

    pr_head_patterns = [
        "pull_request.head.sha",
        "pull_request.head.ref",
        "github.event.pull_request.head",
        "github.head_ref",
    ]

    checks_pr_head = False
    has_explicit_base = False
    has_no_ref = False

    for has_ref, ref_value in checkouts:
        if not has_ref:
            has_no_ref = True
            continue
        ref_lower = ref_value.lower()
        if any(pat in ref_lower for pat in pr_head_patterns):
            checks_pr_head = True
            break
        if "base.sha" in ref_lower or "base.ref" in ref_lower:
            has_explicit_base = True

    if not checks_pr_head:
        if has_no_ref and not has_explicit_base:
            return ("INFO", "pull_request_target trigger with checkout action (default ref). "
                    "Default behavior checks out base branch — safe unless ref: is added later.")
        elif has_explicit_base:
            return ("INFO", "pull_request_target trigger with explicit base ref checkout. Safe.")
        else:
            return ("LOW", "pull_request_target trigger with checkout action using custom ref. "
                    "Verify the ref does not resolve to untrusted PR code.")

    # --- PR head IS checked out — assess mitigating factors ---

    prt_types = extract_prt_event_types(content)
    maintainer_gated_types = {"labeled", "unlabeled", "assigned", "unassigned",
                               "review_requested", "review_request_removed"}

    is_maintainer_gated = False
    if prt_types and prt_types.issubset(maintainer_gated_types):
        is_maintainer_gated = True

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

    mitigations = []
    if is_maintainer_gated:
        mitigations.append(f"trigger restricted to maintainer-gated events ({', '.join(sorted(prt_types))})")
    if not has_dangerous_perms:
        write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
        mitigations.append(f"limited permissions ({', '.join(write_perms) if write_perms else 'read-only'})")

    if is_maintainer_gated and not has_dangerous_perms:
        return ("LOW",
                "pull_request_target checks out PR head code, but risk is mitigated: "
                + "; ".join(mitigations) + ". "
                "Maintainer must trigger the workflow and permissions limit blast radius.")
    elif is_maintainer_gated:
        return ("MEDIUM",
                "pull_request_target checks out PR head code with dangerous permissions, "
                "but trigger requires maintainer action ("
                + ", ".join(sorted(prt_types)) + "). "
                "A maintainer labeling a malicious PR would grant it access to secrets.")
    elif not has_dangerous_perms:
        write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
        return ("MEDIUM",
                "pull_request_target checks out PR head code, but permissions are limited to: "
                + (", ".join(write_perms) if write_perms else "read-only") + ". "
                "Blast radius is reduced — no access to publishing secrets or contents:write.")
    else:
        return ("CRITICAL",
                "pull_request_target trigger with explicit checkout of PR head code "
                "(ref: github.event.pull_request.head). Untrusted PR code executes with "
                "base repo secrets and write permissions.")


def check_self_hosted(content, triggers=None):
    if triggers is None:
        triggers = extract_triggers(content)
    has_self_hosted = "self-hosted" in content
    has_pr_trigger = bool(triggers & PR_TRIGGERS)
    if has_self_hosted and has_pr_trigger:
        return ("HIGH", "Self-hosted runner with PR trigger. External contributors can "
                "execute arbitrary code on self-hosted infrastructure.")
    elif has_self_hosted:
        return ("INFO", "Uses self-hosted runners. Ensure runners are ephemeral.")
    return None


def check_permissions(content):
    perms = extract_permissions(content)
    findings = []
    level = perms.get("_level", "")
    if level in ("write-all", "read-all|write-all"):
        findings.append(("HIGH", "Workflow uses `permissions: write-all`. "
                         "Follow least-privilege principle."))
    write_perms = [k for k, v in perms.items() if v == "write" and k != "_level"]
    if len(write_perms) > 3:
        findings.append(("LOW", f"Requests write access to {len(write_perms)} scopes: "
                         f"{', '.join(write_perms)}."))
    return findings


def check_cache_poisoning(content, triggers=None):
    if triggers is None:
        triggers = extract_triggers(content)
    has_pr = bool(triggers & {"pull_request", "pull_request_target"})
    has_cache = "actions/cache" in content
    if has_cache and has_pr:
        for line in content.split("\n"):
            if "key:" in line and ("pull_request" in line or "head_ref" in line):
                return ("HIGH", "Cache key derived from PR-controlled value. "
                        "A malicious PR could poison the cache.")
        return ("INFO", "Uses actions/cache with PR trigger. Verify cache keys "
                "are not PR-controlled.")
    return None
