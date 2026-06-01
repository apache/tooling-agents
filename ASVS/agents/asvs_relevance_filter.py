# asvs_relevance_filter
#
# Runs between asvs_audit/asvs_bundle and asvs_consolidate. Three phases:
#
#   Phase 1 — Project Security Profile (auto-discover, multi-repo aware)
#     Discovers security-policy documents from THREE sources:
#       (a) the source CouchDB namespace — catches anything that was
#           downloaded into the audit's working set (e.g. airflow-core/
#           AGENTS.md, docs/security/*.rst), at any depth.
#       (b) the repo root via the GitHub Contents API — fetches well-known
#           top-level files (SECURITY.md, AGENTS.md, THREATMODEL.md and
#           variants). This is the "multi-repo inheritance" path: when
#           auditing a monorepo subdirectory like apache/airflow/airflow-
#           core, the source namespace only contains files under airflow-
#           core/, so the repo-root SECURITY.md and AGENTS.md would be
#           invisible without this fetch. With a PAT supplied, private
#           repos work too.
#       (c) any explicit audit_guidance:* namespaces passed in.
#     Synthesizes a structured profile via one Opus call, cached by the
#     SHA-256 hash of the input doc set and keyed on owner_repo so the
#     same profile is reused across module audits of the same project.
#
#   Phase 2 — Per-chapter triage with confidence scoring
#     Groups per-section reports by ASVS chapter and batches each chapter
#     into one Opus call. The model returns KEEP / DOWNGRADE / DROP per
#     finding, AND a confidence in {high, medium, low} on each drop.
#     High-confidence drops are silently filtered. Medium/low-confidence
#     drops go to a human review queue artifact.
#
#   Phase 3 — Write artifacts
#     Writes filtered per-section reports to audit-reports-filtered:{...}.
#     Produces four inspectable artifacts:
#       _security_profile.md          — the synthesized profile
#       _filter_drop_log.md           — every drop with reason
#       _suggested_audit_guidance.md  — recurring drop patterns formatted
#                                       as AGENTS.md additions
#       _review_queue.md              — low-confidence drops for human review
#
#   Phase 4 — Push artifacts to private repo (optional)
#     If private_repo + pat are supplied, the four _*.md artifacts are also
#     written to {private_repo}/{output_directory}/ via the GitHub Contents
#     API, matching asvs_push_github's convention. Filtered per-section
#     reports stay in CouchDB only.

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx


async def run(input_dict, tools):
    mcpc = {url: RemoteMCPClient(remote_url=url) for url in tools.keys()}
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=15.0, read=60.0, write=60.0, pool=60.0),
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        transport=httpx.AsyncHTTPTransport(retries=3),
    )
    try:
        import json
        import re
        import base64
        import hashlib
        import fnmatch
        import asyncio as _asyncio

        # ─── parse inputText (multiline key:value) ───────────────────
        input_text = input_dict.get("inputText", "") or ""
        fields = {}
        for line in input_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            fields[k.strip().lower()] = v.strip()

        owner_repo = fields.get("owner_repo") or fields.get("repository") or ""
        pat = fields.get("pat") or fields.get("token") or fields.get("github_token") or ""
        private_repo = fields.get("private_repo") or ""
        reports_namespace = fields.get("reports_namespace") or ""
        source_namespace = fields.get("source_namespace") or ""
        output_directory = fields.get("output_directory") or ""
        # source_id is used in commit subjects so apache commits@ mailing
        # list digests can be grepped by audited target. Format matches
        # what the orchestrator uses for its own pushes:
        # "owner/repo[/path] @ commit_hash". Fall back to owner_repo if
        # not passed (older orchestrators) so the filter still works.
        source_id = fields.get("source_id") or owner_repo or "unknown"
        guidance_raw = fields.get("audit_guidance_namespaces") or ""
        try:
            batch_max_chars = int(fields.get("batch_max_chars") or "120000")
        except ValueError:
            batch_max_chars = 120000

        guidance_namespaces = [s.strip() for s in guidance_raw.split(",") if s.strip()]

        if not reports_namespace:
            return {"outputText": "Error: reports_namespace is required"}
        if not source_namespace:
            return {"outputText": "Error: source_namespace is required"}
        if not output_directory:
            output_directory = reports_namespace.split(":", 1)[-1]

        owner_repo_root = "/".join(owner_repo.split("/", 2)[:2]) if owner_repo else ""

        # Validate guidance namespaces against the repo being audited.
        # Bug observed in production: a stale supplementalData value
        # carried airflow's audit_guidance namespace into a log4net
        # audit, so airflow's "DAG authors are trusted" policy was
        # applied to a .NET logging library and dropped legitimate
        # findings. Reject any audit_guidance:{project} namespace
        # whose project component doesn't match either the repo org
        # or its basename. Org-level guidance (audit_guidance:apache)
        # is allowed for any apache/* repo; project-level guidance
        # (audit_guidance:airflow) is allowed only for the airflow
        # repo and its subdirectories. Non-audit_guidance namespaces
        # (e.g. project-specific data namespaces) pass through
        # unchecked since they aren't subject to this convention.
        rejected_guidance_namespaces = []
        if owner_repo_root:
            org_part, _, base_part = owner_repo_root.partition("/")
            allowed_projects = {p for p in (org_part, base_part) if p}
            kept = []
            for gns in guidance_namespaces:
                if not gns.startswith("audit_guidance:"):
                    kept.append(gns)
                    continue
                project = gns.split(":", 1)[1]
                if project in allowed_projects:
                    kept.append(gns)
                else:
                    rejected_guidance_namespaces.append((gns, project))
            if rejected_guidance_namespaces:
                print(
                    f"[filter] WARN: rejected "
                    f"{len(rejected_guidance_namespaces)} guidance "
                    f"namespace(s) whose project does not match "
                    f"repo {owner_repo_root} "
                    f"(allowed projects: {sorted(allowed_projects)}):"
                )
                for gns, project in rejected_guidance_namespaces:
                    print(
                        f"[filter]   - {gns} (project={project}) — "
                        f"likely guidance from a different project. "
                        f"If intentional, rename the namespace to "
                        f"match this repo, or set "
                        f"supplementalData=audit_guidance:{base_part} "
                        f"in the orchestrator input."
                    )
            guidance_namespaces = kept

        print(f"[filter] owner_repo={owner_repo} (root={owner_repo_root})")
        print(f"[filter] reports_namespace={reports_namespace}")
        print(f"[filter] source_namespace={source_namespace}")
        print(f"[filter] guidance_namespaces={guidance_namespaces}")
        print(f"[filter] output_directory={output_directory}")
        print(f"[filter] private_repo={private_repo or '(none)'}")
        print(f"[filter] pat={'set' if pat else 'not set'}")

        REASON_PROVIDER = "bedrock"
        REASON_MODEL = "us.anthropic.claude-opus-4-8"

        source_ns = data_store.use_namespace(source_namespace)
        reports_ns = data_store.use_namespace(reports_namespace)
        filtered_ns_name = f"audit-reports-filtered:{output_directory}"
        filtered_ns = data_store.use_namespace(filtered_ns_name)
        cache_key_scope = owner_repo_root or output_directory
        cache_ns = data_store.use_namespace(f"relevance-filter-cache:{cache_key_scope}")

        # ═══ helpers ═══════════════════════════════════════════════════

        def _read_ns_value(ns, key):
            try:
                v = ns.get(key)
            except Exception:
                return None
            if v is None:
                return None
            if isinstance(v, dict):
                return v.get("report") or v.get("content") or v.get("body") or json.dumps(v)
            return v if isinstance(v, str) else str(v)

        def _extract_json_object(text):
            if not text:
                return None
            depth = 0
            start = -1
            in_str = False
            esc = False
            for i, ch in enumerate(text):
                if esc:
                    esc = False
                    continue
                if ch == "\\":
                    esc = True
                    continue
                if ch == '"' and not esc:
                    in_str = not in_str
                    continue
                if in_str:
                    continue
                if ch == "{":
                    if depth == 0:
                        start = i
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0 and start != -1:
                        return text[start:i + 1]
            return None

        async def _fetch_github_file(owner_repo_norm, path):
            """Fetch a file from the GitHub Contents API. Returns content or None.

            Works for private repos when pat is set. Accept:
            application/vnd.github.raw returns raw file body directly.
            """
            if not owner_repo_norm:
                return None
            url = f"https://api.github.com/repos/{owner_repo_norm}/contents/{path}"
            headers = {"Accept": "application/vnd.github.raw"}
            if pat:
                headers["Authorization"] = f"Bearer {pat}"
                headers["X-GitHub-Api-Version"] = "2022-11-28"
            try:
                resp = await http_client.get(url, headers=headers)
                if resp.status_code == 200:
                    return resp.text
                if resp.status_code == 404:
                    return None
                print(f"[filter]   GitHub fetch {path}: HTTP {resp.status_code}")
                return None
            except Exception as e:
                print(f"[filter]   GitHub fetch {path} failed: {e}")
                return None

        async def _push_to_private_repo(path, content, commit_message):
            """Create or update a file in the private repo via Contents API."""
            if not private_repo or not pat:
                return False
            url = f"https://api.github.com/repos/{private_repo}/contents/{path}"
            headers = {
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {pat}",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            existing_sha = None
            try:
                resp = await http_client.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        existing_sha = resp.json().get("sha")
                    except Exception:
                        pass
            except Exception:
                pass

            payload = {
                "message": commit_message,
                "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            }
            if existing_sha:
                payload["sha"] = existing_sha

            try:
                resp = await http_client.put(url, headers=headers, json=payload)
                if resp.status_code in (200, 201):
                    return True
                print(f"[filter]   private-repo push {path}: HTTP {resp.status_code} {(resp.text or '')[:200]}")
            except Exception as e:
                print(f"[filter]   private-repo push {path} failed: {e}")
            return False

        def _format_finding_md(f):
            fid = f.get("finding_id") or f.get("id") or f.get("original_id") or ""
            title = f.get("title", "(untitled)")
            severity = f.get("severity", "Medium")
            cwe = f.get("cwe") or ""
            asvs = f.get("asvs_section") or f.get("asvs") or ""
            files = f.get("affected_files") or f.get("files") or []
            desc = f.get("description") or ""
            remed = f.get("recommended_remediation") or f.get("remediation") or ""

            lines = [f"### {fid + ': ' if fid else ''}{title}", ""]
            lines.append(f"**Severity:** {severity}  ")
            if cwe:
                lines.append(f"**CWE:** {cwe}  ")
            if asvs:
                lines.append(f"**ASVS:** {asvs}  ")
            if files:
                parts = []
                for x in files:
                    if isinstance(x, dict):
                        path_ = x.get("file") or x.get("path") or ""
                        line_ = x.get("line")
                        parts.append(f"{path_}:{line_}" if line_ else path_)
                    else:
                        parts.append(str(x))
                lines.append(f"**Files:** {', '.join(parts)}  ")
            lines.append("")
            lines.append(f"**Description:** {desc}")
            lines.append("")
            lines.append(f"**Recommended Remediation:** {remed}")
            lines.append("")
            lines.append("---")
            lines.append("")
            return "\n".join(lines)

        def _rebuild_report_md(section_id, new_status, kept, dropped, promoted):
            parts = [
                f"# ASVS {section_id} Audit Report",
                "",
                "*This report has been processed by asvs_relevance_filter against the project security profile.*",
                "",
                f"**ASVS Status:** {new_status or 'Unknown'}",
                "",
                "## Findings",
                "",
            ]
            if kept:
                for f in kept:
                    parts.append(_format_finding_md(f))
            else:
                parts.append("*No findings remain after relevance filtering.*")
                parts.append("")

            if promoted:
                parts.append("## Positive Controls (promoted from dropped findings)")
                parts.append("")
                for p in promoted:
                    ctrl = p.get("control") or p.get("description") or ""
                    src = p.get("source") or ""
                    parts.append(f"- **{ctrl}**" + (f" *(source: {src})*" if src else ""))
                parts.append("")

            if dropped:
                parts.append("## Dropped Findings (filtered out)")
                parts.append("")
                parts.append("These findings were dropped because they fall outside the project's documented threat model. See `_filter_drop_log.md` for the full reason set.")
                parts.append("")
                for d in dropped:
                    fid = d.get("original_id") or d.get("id") or "?"
                    title = d.get("title", "?")
                    sev = d.get("severity", "?")
                    reason = d.get("reason", "?")
                    conf = d.get("confidence", "?")
                    parts.append(f"- ~~{fid}: {title}~~ *(was {sev}, confidence {conf})* — {reason}")
                parts.append("")

            return "\n".join(parts)

        def _build_drop_log_md(entries, profile_hash):
            lines = [
                "# Relevance Filter Drop Log",
                "",
                f"**Total dropped:** {len(entries)}",
                f"**Profile hash:** `{profile_hash}`",
                "",
            ]
            if not entries:
                lines.append("*No findings dropped.*")
                return "\n".join(lines)

            by_reason = {}
            for e in entries:
                by_reason.setdefault(e["reason"], []).append(e)

            lines.append("## Drops grouped by reason")
            lines.append("")
            for reason, group in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
                lines.append(f"### {reason}")
                lines.append(f"*{len(group)} finding(s)*")
                lines.append("")
                for e in group:
                    lines.append(
                        f"- **{e['section']}** {e['finding_id']} "
                        f"({e['severity']}, confidence {e['confidence']}): {e['title']}"
                    )
                lines.append("")
            return "\n".join(lines)

        async def _build_suggested_guidance_md(entries, min_cluster=3, known_guidance_filenames=None):
            """Cluster drop reasons by underlying policy via LLM, then
            format the recurring patterns into actionable AGENTS.md /
            SECURITY.md suggestions.

            Replaces the previous exact-string grouping which missed
            semantically-identical reasons that were lexically different.
            On the May 19 airflow run, the SimpleAuthManager "dev-only,
            production auth delegated to Deployment Manager" pattern
            recurred 10+ times across 6.2.x, 6.3.x, 6.4.1, and 7.2.1 —
            but each call paraphrased it slightly differently
            ("self-documented dev-only", "not intended for production",
            "production auth delegated"...), so exact-string grouping saw
            10+ singleton reasons and the suggestion file came out empty.
            One LLM clustering call recovers the underlying pattern.
            """
            header = [
                "# Suggested Audit Guidance Additions",
                "",
                "*Drop patterns that recurred at least "
                f"{min_cluster} time(s) in this run, clustered by underlying policy "
                "basis. Consider codifying these into your project's "
                "AGENTS.md / SECURITY.md / threat-model docs so future runs "
                "catch them at audit-time, not just at filter-time.*",
                "",
            ]

            # CITATION-AWARE SPLIT: drops that already cite an existing
            # audit_guidance file by name are NOT inferred gaps — they
            # are guidance working as intended. On the May 19 airflow-
            # core run the filter dropped 8 findings explicitly citing
            # delegated_infrastructure_controls.md, then this function
            # suggested uploading that exact file as "new" guidance.
            # Split entries into cited vs inferred; cluster only the
            # inferred ones; surface the cited ones in a separate
            # diagnostic section so the operator can confirm existing
            # guidance is doing work.
            #
            # The triage LLM writes citations in two forms:
            #   (a) full namespace: audit_guidance:airflow::foo.md
            #   (b) bare filename:  foo.md
            # The explicit form is unambiguous. The bare form is
            # ambiguous (could mention any .md file), so we only treat
            # it as a citation when the basename is in
            # known_guidance_filenames — i.e. it's actually one of the
            # uploaded guidance docs in Phase 1's policy doc set.
            citation_re = re.compile(r"audit_guidance:[^:]+::([\w_.\-]+\.md)")
            known_filenames = set(known_guidance_filenames or ())
            bare_filename_re = None
            if known_filenames:
                # word-bounded match on any known filename
                escaped = "|".join(re.escape(n) for n in known_filenames)
                bare_filename_re = re.compile(
                    r"(?<![\w./:])(" + escaped + r")(?![\w])"
                )
            cited_entries = []
            inferred_entries = []
            cited_by_file = {}
            for e in entries:
                reason = e.get("reason") or ""
                matched_files = set(citation_re.findall(reason))
                if bare_filename_re is not None:
                    matched_files.update(bare_filename_re.findall(reason))
                if matched_files:
                    cited_entries.append(e)
                    for fname in matched_files:
                        cited_by_file.setdefault(fname, []).append(e)
                else:
                    inferred_entries.append(e)

            def _codified_section_lines():
                if not cited_by_file:
                    return []
                out = [
                    "",
                    "## Already-codified patterns confirmed working",
                    "",
                    "*These drops cited an existing audit_guidance file by "
                    "name. The filter is working as intended for these "
                    "patterns — no new guidance needed. Listed here as a "
                    "sanity check that uploaded policy docs are being "
                    "applied.*",
                    "",
                ]
                for fname, drops in sorted(
                    cited_by_file.items(), key=lambda x: -len(x[1])
                ):
                    out.append(f"### {len(drops)}×: cited `{fname}`")
                    out.append("")
                    secs = sorted({d.get("section", "?") for d in drops})
                    if secs:
                        out.append(f"**ASVS sections:** {', '.join(secs)}")
                        out.append("")
                return out

            if not entries:
                return "\n".join(header + ["*No drops in this run.*"])
            if len(inferred_entries) < min_cluster:
                msg = (
                    f"*Only {len(inferred_entries)} inferred drops (drops "
                    f"not citing existing guidance files) — too few to "
                    f"cluster. {len(cited_entries)} drops cited existing "
                    f"audit_guidance files and were excluded from "
                    f"suggestion clustering.*"
                )
                return "\n".join(
                    header + [msg] + _codified_section_lines()
                )

            drops_for_prompt = [
                {
                    "section": e.get("section", ""),
                    "finding_id": e.get("finding_id", ""),
                    "title": (e.get("title") or "")[:200],
                    "reason": (e.get("reason") or "")[:600],
                }
                for e in inferred_entries
            ]

            prompt = (
                "You are clustering security audit drop reasons — short LLM-written "
                "justifications for why particular findings were dropped as out-of-"
                "scope or already-mitigated. The same underlying project policy gets "
                "paraphrased differently each time it is written, so naive text "
                "grouping misses real clusters. Your job is to recover the underlying "
                "policies and count how many drops cite each.\n\n"
                f"Cluster size threshold: {min_cluster} (omit smaller clusters).\n\n"
                "Drops:\n"
                f"{json.dumps(drops_for_prompt, indent=2)}\n\n"
                f"For each cluster with at least {min_cluster} drops, return:\n"
                "  - label: 1-line summary of the underlying policy\n"
                "  - count: number of drops in this cluster\n"
                "  - sections: list of ASVS section IDs in this cluster (e.g. "
                "[\"6.2.1\", \"6.3.2\"])\n"
                "  - example_titles: 3-5 distinctive finding titles from the cluster\n"
                "  - suggested_guidance: a 1-2 sentence policy statement that, if "
                "added to AGENTS.md / SECURITY.md, would let future audit runs "
                "treat this class of issue as out-of-scope at audit-time. Write in "
                "the project's voice (e.g. \"This project delegates X to Y because "
                "Z\" or \"This project considers X out of scope because Y\"). Do "
                "NOT reference the audit pipeline — the guidance is for the "
                "project's own docs.\n\n"
                "Return ONLY a valid JSON object with the shape:\n"
                "{ \"clusters\": [ { \"label\": str, \"count\": int, "
                "\"sections\": [str], \"example_titles\": [str], "
                "\"suggested_guidance\": str } ] }\n"
                "Order clusters by count descending. Omit clusters smaller than the "
                "threshold. If no cluster meets the threshold, return "
                "{ \"clusters\": [] }."
            )

            try:
                raw, _ = await call_llm(
                    provider=REASON_PROVIDER,
                    model=REASON_MODEL,
                    messages=[{"role": "user", "content": prompt}],
                    parameters={
                        # Same temperature/reasoning constraint as elsewhere
                        # in this file: thinking requires temp=1.0.
                        "temperature": 1.0,
                        "reasoning_effort": "low",
                        "max_tokens": 8000,
                    },
                    timeout=300,
                )
            except Exception as e:
                return "\n".join(header + [
                    f"*Clustering pass failed: {type(e).__name__}: {e}.*",
                    "*See `_filter_drop_log.md` for full distribution; manual review needed.*",
                ])

            obj_text = _extract_json_object(raw)
            if not obj_text:
                return "\n".join(header + [
                    "*Clustering pass returned no parseable JSON. See "
                    "`_filter_drop_log.md` for full distribution.*",
                    "",
                    "Raw LLM output (first 1000 chars):",
                    "",
                    "```",
                    (raw[:1000] if isinstance(raw, str) else str(raw)[:1000]),
                    "```",
                ])

            try:
                parsed = json.loads(obj_text)
            except json.JSONDecodeError as e:
                return "\n".join(header + [
                    f"*Clustering pass JSON parse failed: {e}.*",
                    "*See `_filter_drop_log.md` for full distribution.*",
                ])

            clusters = parsed.get("clusters", []) if isinstance(parsed, dict) else []
            if not clusters:
                msg = (
                    f"*No clusters of size >= {min_cluster} found among "
                    f"{len(inferred_entries)} inferred drops. "
                    f"{len(cited_entries)} additional drops cited existing "
                    f"audit_guidance files. See `_filter_drop_log.md` for "
                    f"the long tail.*"
                )
                return "\n".join(
                    header + [msg] + _codified_section_lines()
                )

            lines = list(header) + ["## Recurring drop clusters", ""]
            for c in clusters:
                label = c.get("label", "(no label)")
                count = c.get("count", 0)
                # The LLM returns sections per-drop in cluster order, so
                # the same section id can appear multiple times when
                # multiple findings under that section cluster together
                # (observed: "2.4.1, 2.4.1, 1.4.2"). Dedupe and sort for
                # readable output while keeping the underlying ordering
                # information available via the example_titles list.
                raw_sections = c.get("sections", []) or []
                sections = sorted({s for s in raw_sections if s})
                examples = c.get("example_titles", []) or []
                guidance = c.get("suggested_guidance", "(no guidance text generated)")

                lines.append(f"### {count}×: {label}")
                lines.append("")
                if sections:
                    lines.append(f"**ASVS sections:** {', '.join(sections)}")
                    lines.append("")
                if examples:
                    lines.append("**Example finding titles:**")
                    for ex in examples[:5]:
                        lines.append(f"- {ex}")
                    lines.append("")
                lines.append("**Suggested AGENTS.md / SECURITY.md addition:**")
                lines.append("")
                lines.append("```markdown")
                lines.append(guidance)
                lines.append("```")
                lines.append("")
                lines.append(
                    "Upload with `asvs_guidance_upload` (repo, filename, "
                    "fileContents), then pass "
                    "`supplementalData: audit_guidance:<repo>` to the orchestrator "
                    "on the next run so the audit phase reads this guidance "
                    "alongside source code."
                )
                lines.append("")
            lines.extend(_codified_section_lines())
            return "\n".join(lines)

        def _build_review_queue_md(entries, profile_hash):
            review = [e for e in entries if e.get("confidence", "").lower() in ("medium", "low")]
            lines = [
                "# Relevance Filter — Human Review Queue",
                "",
                f"**Profile hash:** `{profile_hash}`",
                f"**Items needing review:** {len(review)}",
                "",
                "*These drops had medium or low confidence. The filter dropped them, but "
                "the project profile did not explicitly authorize the drop — it was an "
                "inference. Review to confirm the drop is correct; if not, add explicit "
                "guidance so the next run is high-confidence.*",
                "",
            ]
            if not review:
                lines.append("*All drops were high-confidence; nothing to review.*")
                return "\n".join(lines)

            for conf_level in ("low", "medium"):
                items = [e for e in review if e.get("confidence", "").lower() == conf_level]
                if not items:
                    continue
                lines.append(f"## {conf_level.title()}-confidence drops ({len(items)})")
                lines.append("")
                for e in items:
                    lines.append(
                        f"- **{e['section']}** {e['finding_id']} "
                        f"({e['severity']}): {e['title']}"
                    )
                    lines.append(f"  - **Drop reason:** {e['reason']}")
                    lines.append("")
            return "\n".join(lines)

        # ═══════════════════════════════════════════════════════════════
        # PHASE 1 — Project Security Profile
        # ═══════════════════════════════════════════════════════════════
        print("\n[filter] === Phase 1: Project Security Profile ===")

        SOURCE_DOC_PATTERNS = [
            # canonical project policy docs at root or any depth — extensions
            # required so `*/security/permissions.py` doesn't match
            "security.md", "security.rst", "security.txt", "security",
            "*/security.md", "*/security.rst", "*/security.txt", "*/security",
            "agents.md", "agents.rst",
            "*/agents.md", "*/agents.rst",
            "threatmodel.md", "threatmodel.rst", "threat_model.md", "threat_model.rst",
            "*/threatmodel.md", "*/threatmodel.rst",
            "*/threat_model.md", "*/threat_model.rst",
            # docs/security tree — extensions required to skip
            # __init__.py, helpers, etc. that happen to live alongside
            "docs/security/*.md", "docs/security/*.rst",
            "docs/security/**/*.md", "docs/security/**/*.rst",
            "*/docs/security/*.md", "*/docs/security/*.rst",
            "*/docs/security/**/*.md", "*/docs/security/**/*.rst",
            # project-convention "X.security.md" sidecars
            "*.security.md", "*/*.security.md",
            # other security-themed prose docs (extension-bound)
            "docs/*security*.rst", "docs/*security*.md",
            "*/docs/*security*.rst", "*/docs/*security*.md",
        ]

        # Hard exclude: even if a pattern matches, drop files with these
        # extensions. Belt-and-suspenders against any future pattern that
        # could pick up code/test files.
        EXCLUDED_DOC_EXTENSIONS = (
            ".py", ".pyc", ".pyi",
            ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
            ".go", ".rs", ".java", ".kt", ".scala",
            ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
            ".rb", ".php", ".swift", ".cs",
            ".yaml", ".yml", ".toml", ".ini", ".cfg",
            ".lock", ".json",
        )

        # repo-root paths to attempt via GitHub Contents API
        REPO_ROOT_PATHS = [
            "SECURITY.md", "SECURITY.rst", "SECURITY",
            "AGENTS.md", "AGENTS.rst",
            "THREATMODEL.md", "THREAT_MODEL.md",
            ".github/SECURITY.md",
            "docs/SECURITY.md",
        ]

        try:
            source_keys = source_ns.list_keys() or []
        except Exception as e:
            print(f"[filter] WARN: could not list source namespace: {e}")
            source_keys = []

        candidate_keys = []
        for key in source_keys:
            kl = key.lower()
            # Hard exclude code/test files even if a glob matches their path
            if kl.endswith(EXCLUDED_DOC_EXTENSIONS):
                continue
            for pattern in SOURCE_DOC_PATTERNS:
                if fnmatch.fnmatch(kl, pattern.lower()):
                    candidate_keys.append(key)
                    break
        candidate_keys = sorted(set(candidate_keys))
        print(f"[filter] discovered {len(candidate_keys)} candidate docs in source namespace")

        # ─── priority + budget for the doc set ─────────────────────────
        # Collect candidates from ALL three sources (source namespace,
        # repo-root GitHub fetch, explicit guidance namespaces) before
        # applying the budget. Earlier version sorted within each source
        # in order, which caused tier-2/3 source-namespace docs to fill
        # the budget before tier-1 repo-root docs like AGENTS.md and
        # SECURITY.md were even considered. Now: global sort, top tiers
        # win regardless of where they came from.

        PER_DOC_CHAR_CAP = 30000
        TOTAL_CHAR_BUDGET = 120000

        def _doc_priority(key):
            """Lower number = higher priority. Drives global ordering when
            the total budget can't fit all candidates."""
            basename = key.rsplit("/", 1)[-1].lower()
            full = key.lower()
            # Tier 1 — canonical top-level project policy docs
            if basename in (
                "agents.md", "agents.rst",
                "security.md", "security.rst", "security",
                "threatmodel.md", "threat_model.md",
            ):
                return 1
            # Tier 2 — documented security/threat models
            if "security_model" in full or "threatmodel" in full or "threat_model" in full:
                return 2
            # Tier 3 — sensitive-data / authn / authz / policies
            if any(t in full for t in (
                "secret", "auth", "permission", "audit_log", "fernet",
                "vulnerabilit", "releasing_security", "sbom",
            )):
                return 3
            # Tier 4 — everything else under docs/security
            return 4

        # Collect from all sources into one ranked list before applying budget
        all_candidates = []  # list of (priority, label, key, content)

        # Source namespace
        for key in candidate_keys:
            content = _read_ns_value(source_ns, key)
            if not content or len(content) < 200:
                continue
            all_candidates.append(
                (_doc_priority(key), f"source::{key}", key, content)
            )

        # repo-root inheritance: pull top-level project docs via GitHub.
        # Skip a remote fetch if the same basename already exists locally
        # in the source namespace (the local copy is in-scope for this audit).
        github_root_hits = 0
        if owner_repo_root:
            already_have_basenames = {
                k.rsplit("/", 1)[-1].lower()
                for k in candidate_keys
            }
            for rp in REPO_ROOT_PATHS:
                rp_basename = rp.rsplit("/", 1)[-1].lower()
                if rp_basename in already_have_basenames:
                    continue
                content = await _fetch_github_file(owner_repo_root, rp)
                if not content or len(content) < 200:
                    continue
                all_candidates.append(
                    (_doc_priority(rp), f"github://{owner_repo_root}/{rp}", rp, content)
                )
                github_root_hits += 1
        print(f"[filter] fetched {github_root_hits} repo-root docs from GitHub")

        # Explicit guidance namespaces — tier-1 (user-curated authority)
        for gns_name in guidance_namespaces:
            try:
                gns = data_store.use_namespace(gns_name)
                gkeys = gns.list_keys() or []
                for gkey in gkeys:
                    content = _read_ns_value(gns, gkey)
                    if not content:
                        continue
                    all_candidates.append((1, f"{gns_name}::{gkey}", gkey, content))
            except Exception as e:
                print(f"[filter] WARN: guidance namespace {gns_name}: {e}")

        # Sort by priority globally; within a tier, prefer shorter docs
        # (more likely to be canonical/concise) and stable filename order
        all_candidates.sort(key=lambda c: (c[0], len(c[3]), c[2].lower()))

        policy_docs = {}
        included_summary = []  # (priority, key, chars)
        skipped_for_budget = []
        total_chars = 0

        for priority, label, key, content in all_candidates:
            capped = content[:PER_DOC_CHAR_CAP]
            if total_chars + len(capped) > TOTAL_CHAR_BUDGET:
                skipped_for_budget.append((priority, label, key, len(capped)))
                continue
            policy_docs[label] = capped
            included_summary.append((priority, key, len(capped)))
            total_chars += len(capped)

        print(f"[filter] policy docs assembled: {len(policy_docs)} files, "
              f"{total_chars} chars ({total_chars * 100 // TOTAL_CHAR_BUDGET}% of budget)")
        if included_summary:
            print(f"[filter] included docs by tier:")
            for p, k, sz in sorted(included_summary)[:30]:
                print(f"  + tier {p}, {sz} chars: {k}")
        if skipped_for_budget:
            print(f"[filter] skipped {len(skipped_for_budget)} over-budget docs:")
            for p, _lbl, k, sz in skipped_for_budget[:10]:
                print(f"  - tier {p}, {sz} chars: {k}")

        if not policy_docs:
            print("[filter] no policy docs found — profile empty, filter pass-through")
            profile = (
                "# Project Security Profile\n\n"
                "*No security-policy documents discovered. Relevance filter has no "
                "project-specific authority and treats all findings as in-scope.*\n"
            )
            profile_hash = "empty"
        else:
            docs_blob = json.dumps(policy_docs, sort_keys=True)
            profile_hash = hashlib.sha256(docs_blob.encode("utf-8")).hexdigest()[:16]
            profile_cache_key = f"profile:{profile_hash}"

            cached_profile = None
            try:
                cached_profile = cache_ns.get(profile_cache_key)
            except Exception:
                cached_profile = None

            if cached_profile and isinstance(cached_profile, str) and len(cached_profile) > 100:
                print(f"[filter] profile cache hit ({profile_hash})")
                profile = cached_profile
            else:
                PROFILE_PROMPT = (
                    "You are reading a project's own security-policy documents, threat model "
                    "writeups, contributor guides, and architecture notes.\n\n"
                    "Produce a structured 'Project Security Profile' that captures THIS "
                    "project's stated security stance — what it considers a vulnerability, "
                    "what it explicitly delegates (to deployment manager, reverse proxy, IdP, "
                    "etc.), what components are documented as dev-only, what trade-offs are "
                    "documented as intentional, and any documented severity / remediation "
                    "policies.\n\n"
                    "This profile will be used by an audit-triage step that decides which "
                    "security findings to keep, drop, or reclassify. Be precise — quote "
                    "document references verbatim where possible. Do NOT invent or extrapolate; "
                    "only include things the docs actually state.\n\n"
                    "Output EXACTLY this structure:\n\n"
                    "# Project Security Profile\n\n"
                    "## Trust Boundaries\n"
                    "Who/what the project considers trusted vs. untrusted.\n\n"
                    "## Explicitly Delegated Controls\n"
                    "Things the project documents as NOT its responsibility.\n"
                    "Format: - **<control>**: delegated to <party>. Source: <doc>:<section>\n\n"
                    "## Dev-Only Components\n"
                    "Code paths documented as for development/testing only.\n"
                    "Format: - **<component>** at <path>: <reason>. Source: <doc>\n\n"
                    "## Documented Design Decisions\n"
                    "Intentional security trade-offs.\n"
                    "Format: - **<decision>**: <rationale>. Source: <doc>\n\n"
                    "## Documented Policies (commonly mis-flagged as missing)\n"
                    "Format: - **<policy>** documented in <doc>: <one-line summary>\n\n"
                    "## Out-of-Scope ASVS Categories\n"
                    "Categories not applicable to this project's architecture.\n"
                    "Format: - **ASVS <chapter>**: <reason>\n\n"
                    "## Severity / Remediation Policy (if documented)\n"
                    "If the project documents its own severity scale or remediation timeframes, "
                    "summarize. Otherwise omit this section.\n\n"
                    "---\n\nSource documents:\n\n"
                )

                async def _attempt_synthesis(docs_subset, attempt_label):
                    docs_section = "\n\n---\n\n".join(
                        f"### Document: {path}\n\n{content}"
                        for path, content in docs_subset.items()
                    )
                    prompt_chars = len(PROFILE_PROMPT) + len(docs_section)
                    print(f"[filter] synthesis {attempt_label}: "
                          f"{len(docs_subset)} docs, {prompt_chars} chars total")
                    result, _ = await call_llm(
                        provider=REASON_PROVIDER,
                        model=REASON_MODEL,
                        messages=[{"role": "user", "content": PROFILE_PROMPT + docs_section}],
                        parameters={
                            # Bedrock-Opus requires temperature=1 when
                            # reasoning_effort (extended thinking) is set.
                            # Setting temperature<1 with thinking enabled is
                            # a 400 BadRequest.
                            "temperature": 1.0,
                            "reasoning_effort": "medium",
                            "max_tokens": 16000,
                        },
                        timeout=600,
                    )
                    return result

                profile = None
                last_error = None
                last_traceback = ""
                attempts_tried = []
                # First attempt: all included docs
                try:
                    profile = await _attempt_synthesis(policy_docs, "attempt 1 (full)")
                    attempts_tried.append(("attempt 1 (full)", len(policy_docs), "ok"))
                except Exception as e:
                    import traceback as _tb
                    last_error = e
                    last_traceback = _tb.format_exc()
                    attempts_tried.append((
                        "attempt 1 (full)", len(policy_docs),
                        f"{type(e).__name__}: {str(e) or '(no message)'}",
                    ))
                    print(f"[filter] attempt 1 FAILED: {type(e).__name__}: {e}")
                    print(last_traceback)

                # Retry with priority-1 + priority-2 docs only, in case the
                # first attempt failed due to input size.
                if not profile or len(profile) < 100:
                    reduced = {
                        label: content
                        for label, content in policy_docs.items()
                        if any(
                            (pri, key) for pri, key, _ in included_summary
                            if pri <= 2 and label.endswith(key)
                        )
                    }
                    # Fallback heuristic: if filter above produced nothing
                    # (label matching missed), keep the smallest half by char count
                    if not reduced:
                        items = sorted(policy_docs.items(), key=lambda kv: len(kv[1]))
                        keep = max(1, len(items) // 2)
                        reduced = dict(items[:keep])
                    if reduced and reduced != policy_docs:
                        try:
                            profile = await _attempt_synthesis(
                                reduced,
                                f"attempt 2 (reduced to {len(reduced)} priority docs)",
                            )
                            attempts_tried.append((
                                "attempt 2 (reduced)", len(reduced), "ok",
                            ))
                            last_error = None  # success on retry
                        except Exception as e:
                            import traceback as _tb
                            last_error = e
                            last_traceback = _tb.format_exc()
                            attempts_tried.append((
                                f"attempt 2 (reduced to {len(reduced)})",
                                len(reduced),
                                f"{type(e).__name__}: {str(e) or '(no message)'}",
                            ))
                            print(f"[filter] attempt 2 FAILED: {type(e).__name__}: {e}")

                if profile and len(profile) > 100:
                    try:
                        cache_ns.set(profile_cache_key, profile)
                    except Exception as e:
                        print(f"[filter] WARN: profile cache write failed: {e}")
                    print(f"[filter] profile synthesized ({len(profile)} chars)")
                elif last_error is not None:
                    # All attempts raised. Write a self-describing failure
                    # profile so the artifact tells us what happened without
                    # needing access to orchestrator logs.
                    err_type = type(last_error).__name__
                    err_msg = (str(last_error) or "(no message)")[:800]
                    attempt_lines = "\n".join(
                        f"- {label}: {n_docs} docs → {status}"
                        for label, n_docs, status in attempts_tried
                    )
                    included_lines = "\n".join(
                        f"- tier {p}, {sz} chars: `{k}`"
                        for p, k, sz in sorted(included_summary)[:30]
                    )
                    skipped_lines = "\n".join(
                        f"- tier {p}, {sz} chars: `{k}`"
                        for p, _lbl, k, sz in skipped_for_budget[:30]
                    ) or "_(none)_"
                    profile = (
                        f"# Project Security Profile\n\n"
                        f"*Profile generation failed across all retry attempts. The relevance "
                        f"filter is operating without project-specific authority for this run, "
                        f"so no findings were dropped.*\n\n"
                        f"## Failure details\n\n"
                        f"- **Error type:** `{err_type}`\n"
                        f"- **Error message:** `{err_msg}`\n"
                        f"- **Profile hash:** `{profile_hash}`\n"
                        f"- **Total chars across attempted docs:** {total_chars} "
                        f"(budget {TOTAL_CHAR_BUDGET})\n\n"
                        f"## Attempts\n\n{attempt_lines}\n\n"
                        f"## Docs included in attempt 1\n\n{included_lines}\n\n"
                        f"## Docs skipped for budget\n\n{skipped_lines}\n\n"
                        f"## Last traceback\n\n```\n{last_traceback[:3000]}\n```\n"
                    )
                else:
                    profile = (
                        f"# Project Security Profile\n\n"
                        f"*Profile synthesis returned empty content.*\n\n"
                        f"- Profile hash: `{profile_hash}`\n"
                        f"- Docs sent: {len(policy_docs)}\n"
                        f"- Total chars: {total_chars}\n"
                    )

        # ═══════════════════════════════════════════════════════════════
        # PHASE 2 — Per-chapter triage with confidence scoring
        # ═══════════════════════════════════════════════════════════════
        print("\n[filter] === Phase 2: Per-chapter triage ===")

        try:
            all_report_keys = reports_ns.list_keys() or []
        except Exception as e:
            print(f"[filter] ERROR listing reports namespace: {e}")
            all_report_keys = []

        section_keys = [k for k in all_report_keys if re.search(r'(?:^|/)(\d+\.\d+\.\d+)\.md$', k)]
        print(f"[filter] found {len(section_keys)} per-section reports")

        if not section_keys:
            return {
                "outputText": (
                    "Relevance filter: no per-section reports found in "
                    f"{reports_namespace}; nothing to filter.\n"
                ),
                "filteredReportsNamespace": filtered_ns_name,
            }

        chapter_groups = {}
        for key in section_keys:
            m = re.search(r'(\d+)\.\d+\.\d+\.md$', key)
            if not m:
                continue
            chapter = m.group(1)
            chapter_groups.setdefault(chapter, []).append(key)

        batches = []
        for chapter, keys in sorted(chapter_groups.items()):
            current = []
            current_size = 0
            for key in sorted(keys):
                content = _read_ns_value(reports_ns, key) or ""
                size = len(content)
                if current and current_size + size > batch_max_chars:
                    batches.append((chapter, current))
                    current = []
                    current_size = 0
                current.append(key)
                current_size += size
            if current:
                batches.append((chapter, current))

        print(f"[filter] {len(chapter_groups)} chapters → {len(batches)} batches")

        # Safety net for the defense-in-depth escape hatch. The prompt
        # forbids resurrecting a scope-carved-out finding as a Low
        # "defense-in-depth gap"; this post-pass catches the pattern in
        # case the LLM emits it anyway. Detection requires (a) the
        # description acknowledges a profile carve-out applies AND
        # (b) the description invokes defense-in-depth framing AND
        # (c) the surviving severity is Low or Info. All three together
        # are the exact escape-hatch shape we observed on the
        # logging-log4net F-009 (Telnet bind) and F-010 (SMTP header)
        # findings. Findings matching the pattern are moved from kept
        # to dropped with confidence=medium so they land in the human
        # review queue rather than being silently scrubbed.
        def _is_did_escape_hatch(finding):
            desc = (finding.get("description") or "").lower()
            if not desc:
                return False
            sev = (finding.get("severity") or "").strip().lower()
            if sev not in ("low", "info"):
                return False
            carve_phrases = (
                "trust boundary",
                "out of scope",
                "delegated to",
                "deployment concern",
                "deployment manager",
                "deployer's responsibility",
                "deployer is responsible",
                "administrator-controlled",
                "administrator controlled",
                "configuration-controlled",
                "configuration controlled",
                "dev-only",
                "per profile",
                "per the profile",
                "downgraded from",
                "documented design decision",
                "profile delegates",
            )
            did_phrases = (
                "defense-in-depth",
                "defense in depth",
                "as defense in",
                "as a defense-in-depth",
                "as a defense in depth",
                "defense-in-depth gap",
                "defense in depth gap",
            )
            return any(p in desc for p in carve_phrases) and any(p in desc for p in did_phrases)

        FILTER_PROMPT_TEMPLATE = (
            "You are a security audit triage reviewer.\n\n"
            "You have the project's own Security Profile (synthesized from the "
            "project's documented security stance) and a batch of ASVS audit "
            "reports. For each finding in each report, decide one of:\n\n"
            "- **KEEP**: real, in-scope finding for this project's threat model. "
            "Pass through unchanged.\n"
            "- **DOWNGRADE**: real finding whose root cause is in scope but whose "
            "severity is overstated. Adjust severity and add a one-line note in "
            "the description. Use DOWNGRADE only when the underlying threat is "
            "real for this project — not as a way to keep a scope-carved-out "
            "finding alive at lower severity.\n"
            "- **DROP**: explicitly out of scope per the profile (delegated to "
            "deployment manager, dev-only component, documented design decision, "
            "documentation already exists, ASVS category not applicable). Provide "
            "a one-line reason that cites the profile section.\n\n"
            "**Distinguishing DROP from DOWNGRADE**: ask whether the profile "
            "addresses the finding's ROOT CAUSE (the data flow, the trust "
            "assumption, the threat-model premise) or only its severity. If "
            "the profile makes the threat premise moot — for example, the "
            "finding's exploit requires an untrusted data path that the "
            "profile documents as not existing, or a trust boundary the "
            "profile documents as not crossed — that is DROP. If the profile "
            "reduces but does not eliminate the practical impact — for "
            "example, the exploit requires authenticated access or a "
            "deployer-controlled precondition that does not eliminate the "
            "underlying defect — that is DOWNGRADE.\n\n"
            "**Defense-in-depth is not an escape hatch.** When a finding's "
            "premise is carved out by the profile (no untrusted data path "
            "exists, the surface is configuration-only, the component is "
            "dev-only, the concern is delegated to the deployer), the correct "
            "action is DROP. Recasting such a finding as a Low 'defense-in-"
            "depth gap' is forbidden. If you find yourself writing a "
            "downgrade note of the shape \"profile says X is out of scope, "
            "BUT as defense-in-depth...\" or \"trust boundary excludes this, "
            "HOWEVER...\" or \"DOWNGRADED to Low because [profile carve-out], "
            "but...\" — stop and use DROP instead. The finding's own "
            "acknowledgement of the carve-out is itself evidence the carve-out "
            "applies; do not then resurrect the finding at lower severity. "
            "Library-improvement suggestions that would be nice to have but "
            "are not vulnerabilities under the project's threat model belong "
            "in DROP with a reason like 'feature request, not vulnerability "
            "per profile carve-out', not in DOWNGRADE.\n\n"
            "For every DROP, also assign a CONFIDENCE level:\n"
            "- **high**: the profile EXPLICITLY addresses this finding type (e.g. "
            "the profile literally says 'TLS is deployment manager's responsibility' "
            "and the finding is about TLS).\n"
            "- **medium**: the profile implies the finding is out of scope but "
            "doesn't directly name it.\n"
            "- **low**: dropping based on a more general inference. Queued for "
            "human review.\n\n"
            "When a DROP reflects a project decision, also promote that decision "
            "to the section's positive-controls list.\n\n"
            "If ALL findings in a section drop, change the ASVS status from "
            "Fail/Partial to N/A or Pass as appropriate.\n\n"
            "If the profile does not explicitly OR implicitly address a finding, "
            "KEEP it. Do NOT drop on speculation alone.\n\n"
            "Output STRICTLY this JSON (no prose, no markdown fences):\n\n"
            "{\n"
            '  "reports": [\n'
            "    {\n"
            '      "key": "<original report key>",\n'
            '      "asvs_section": "<X.Y.Z>",\n'
            '      "asvs_status": "<Pass|Partial|Fail|N/A>",\n'
            '      "kept_findings": [ { ...full finding object, unchanged or downgraded... } ],\n'
            '      "dropped_findings": [\n'
            '        {"original_id": "...", "title": "...", "severity": "...",\n'
            '         "reason": "<cite profile section>", "confidence": "<high|medium|low>"}\n'
            "      ],\n"
            '      "promoted_positive_controls": [\n'
            '        {"control": "<description>", "source": "Dropped finding <id>"}\n'
            "      ]\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
            "Preserve finding fields verbatim when keeping. Required keep-fields: "
            "finding_id, title, severity, description, recommended_remediation, "
            "asvs_section, affected_files, cwe (if present).\n\n"
            "═══ PROJECT SECURITY PROFILE ═══\n\n"
            "{profile}\n\n"
            "═══ ASVS AUDIT REPORTS — CHAPTER {chapter} ═══\n\n"
            "{reports}\n"
        )

        sem = _asyncio.Semaphore(4)
        per_key_results = {}
        failed_batches = []

        async def filter_batch(batch_idx, chapter, keys):
            async with sem:
                reports = {}
                for key in keys:
                    content = _read_ns_value(reports_ns, key)
                    if content:
                        reports[key] = content
                if not reports:
                    return batch_idx, chapter, keys, None, "empty batch"

                blob = json.dumps({"ph": profile_hash, "r": reports}, sort_keys=True)
                batch_hash = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
                batch_cache_key = f"filter:{chapter}:{batch_hash}"

                try:
                    cached = cache_ns.get(batch_cache_key)
                except Exception:
                    cached = None
                if cached and isinstance(cached, dict) and cached.get("reports"):
                    print(f"[filter] batch {batch_idx + 1}/{len(batches)} ch{chapter}: cache hit ({len(reports)} reports)")
                    return batch_idx, chapter, keys, cached, None

                reports_section = "\n\n---\n\n".join(
                    f"## Report: {k}\n\n{v}" for k, v in reports.items()
                )
                prompt = (FILTER_PROMPT_TEMPLATE
                          .replace("{profile}", profile)
                          .replace("{chapter}", chapter)
                          .replace("{reports}", reports_section))

                print(f"[filter] batch {batch_idx + 1}/{len(batches)} ch{chapter}: "
                      f"triaging {len(reports)} reports ({len(prompt)} chars)...")

                try:
                    raw, _ = await call_llm(
                        provider=REASON_PROVIDER,
                        model=REASON_MODEL,
                        messages=[{"role": "user", "content": prompt}],
                        parameters={
                            # See profile-synthesis comment: temperature
                            # must be 1.0 when reasoning_effort is set.
                            "temperature": 1.0,
                            "reasoning_effort": "medium",
                            "max_tokens": 32000,
                        },
                        timeout=900,
                    )
                except Exception as e:
                    return batch_idx, chapter, keys, None, f"LLM call failed: {e}"

                obj_text = _extract_json_object(raw)
                if not obj_text:
                    return batch_idx, chapter, keys, None, "no JSON in response"
                try:
                    parsed = json.loads(obj_text)
                except json.JSONDecodeError as e:
                    return batch_idx, chapter, keys, None, f"JSON parse failed: {e}"

                if not isinstance(parsed, dict) or "reports" not in parsed:
                    return batch_idx, chapter, keys, None, "missing 'reports' key"

                try:
                    cache_ns.set(batch_cache_key, parsed)
                except Exception as e:
                    print(f"[filter]   WARN: batch cache write failed: {e}")

                return batch_idx, chapter, keys, parsed, None

        gather_results = await _asyncio.gather(*[
            filter_batch(i, chapter, keys) for i, (chapter, keys) in enumerate(batches)
        ])

        for batch_idx, chapter, keys, result, err in gather_results:
            if err or result is None:
                print(f"[filter] batch {batch_idx + 1} (ch{chapter}) failed: {err}")
                failed_batches.append((chapter, keys, err))
                continue
            for rep in result.get("reports", []) or []:
                k = rep.get("key")
                if not k:
                    continue
                per_key_results[k] = rep

        # ═══════════════════════════════════════════════════════════════
        # PHASE 3 — Write filtered reports + 4 artifacts
        # ═══════════════════════════════════════════════════════════════
        print(f"\n[filter] === Phase 3: Writing filtered reports to {filtered_ns_name} ===")

        total_kept = 0
        total_dropped = 0
        sections_written = 0
        sections_passthrough = 0
        all_drop_entries = []

        for key in section_keys:
            rep = per_key_results.get(key)
            if rep is None:
                original = _read_ns_value(reports_ns, key)
                if original is not None:
                    try:
                        filtered_ns.set(key, original)
                        sections_passthrough += 1
                    except Exception as e:
                        print(f"[filter] WARN: failed to pass-through {key}: {e}")
                continue

            section_id = rep.get("asvs_section", "")
            if not section_id:
                m = re.search(r'(\d+\.\d+\.\d+)\.md$', key)
                section_id = m.group(1) if m else ""
            new_status = rep.get("asvs_status", "")
            kept = rep.get("kept_findings", []) or []
            dropped = rep.get("dropped_findings", []) or []
            promoted = rep.get("promoted_positive_controls", []) or []

            # Safety net: catch defense-in-depth escape-hatch downgrades the
            # prompt rule missed. These get moved from kept to dropped with
            # confidence=medium so a human reviewer can see them in the
            # review queue and confirm the post-pass got it right.
            escape_hatch_drops = []
            survivors = []
            for f in kept:
                if _is_did_escape_hatch(f):
                    escape_hatch_drops.append(f)
                else:
                    survivors.append(f)
            if escape_hatch_drops:
                kept = survivors
                for f in escape_hatch_drops:
                    dropped.append({
                        "original_id": f.get("finding_id") or f.get("id") or "?",
                        "title": f.get("title", "?"),
                        "severity": f.get("severity", "?"),
                        "reason": (
                            "defense-in-depth escape hatch: finding "
                            "acknowledges a profile carve-out applies but was "
                            "kept at Low with DiD framing. Filter prompt rule "
                            "requires DROP in this case; post-pass corrected. "
                            "Queued for review."
                        ),
                        "confidence": "medium",
                    })
                print(f"[filter] {key}: post-pass dropped "
                      f"{len(escape_hatch_drops)} defense-in-depth escape-hatch "
                      f"finding(s)")

            total_kept += len(kept)
            total_dropped += len(dropped)

            for d in dropped:
                all_drop_entries.append({
                    "section": section_id,
                    "finding_id": d.get("original_id") or d.get("id") or "?",
                    "title": d.get("title", "?"),
                    "severity": d.get("severity", "?"),
                    "reason": d.get("reason", "(no reason given)"),
                    "confidence": (d.get("confidence") or "high").lower(),
                })

            new_md = _rebuild_report_md(section_id, new_status, kept, dropped, promoted)
            try:
                filtered_ns.set(key, new_md)
                sections_written += 1
            except Exception as e:
                print(f"[filter] WARN: failed to write {key}: {e}")

        drop_log_md = _build_drop_log_md(all_drop_entries, profile_hash)
        # Extract bare filenames of uploaded audit_guidance docs so the
        # suggested-guidance builder can recognize paraphrased citations
        # that drop the `audit_guidance:{ns}::` prefix (the LLM writes
        # the citation either form when generating drop reasons).
        known_guidance_filenames = {
            label.split("::", 1)[1]
            for label in policy_docs
            if label.startswith("audit_guidance:") and "::" in label
        }
        suggested_md = await _build_suggested_guidance_md(
            all_drop_entries,
            known_guidance_filenames=known_guidance_filenames,
        )
        review_md = _build_review_queue_md(all_drop_entries, profile_hash)

        # If any guidance namespaces were rejected as cross-project
        # leakage, prepend a visible banner to the security profile
        # artifact so the operator notices when looking at filter
        # output (rejection is also logged to stdout during run).
        if rejected_guidance_namespaces and owner_repo_root:
            base_part = owner_repo_root.split("/", 1)[-1]
            banner_lines = [
                "> ⚠️  **Guidance namespace mismatch — content rejected**",
                ">",
                f"> The filter rejected {len(rejected_guidance_namespaces)} "
                f"`audit_guidance:*` namespace(s) because their project "
                f"component does not match this repo "
                f"(`{owner_repo_root}`):",
                ">",
            ]
            for gns, project in rejected_guidance_namespaces:
                banner_lines.append(
                    f"> - `{gns}` (project=`{project}`)"
                )
            banner_lines.extend([
                ">",
                "> Guidance from these namespaces was **not loaded**, "
                "and policies from those projects did not affect this "
                "run's drops. If intentional cross-project reuse, "
                "rename the namespace to match this repo basename or "
                "org. Otherwise, set "
                f"`supplementalData=audit_guidance:{base_part}` in "
                f"the orchestrator input for the correct namespace.",
                "",
                "",
            ])
            profile = "\n".join(banner_lines) + profile

        artifacts = {
            "_security_profile.md": profile,
            "_filter_drop_log.md": drop_log_md,
            "_suggested_audit_guidance.md": suggested_md,
            "_review_queue.md": review_md,
        }
        for fname, body in artifacts.items():
            try:
                filtered_ns.set(fname, body)
            except Exception as e:
                print(f"[filter] WARN: failed to write artifact {fname}: {e}")

        # ═══════════════════════════════════════════════════════════════
        # PHASE 4 — Push artifacts to private repo (optional)
        # ═══════════════════════════════════════════════════════════════
        pushed = []
        push_skipped_reason = None
        if private_repo and pat:
            print(f"\n[filter] === Phase 4: Pushing artifacts to {private_repo}/{output_directory} ===")
            for fname, body in artifacts.items():
                path = f"{output_directory.rstrip('/')}/{fname}"
                ok = await _push_to_private_repo(
                    path, body,
                    f"asvs_relevance_filter: update {fname} [source: {source_id}]",
                )
                if ok:
                    pushed.append(fname)
                    print(f"[filter]   pushed {path}")
                else:
                    print(f"[filter]   FAILED to push {path}")
        else:
            push_skipped_reason = (
                "private_repo not provided" if not private_repo
                else "pat not provided"
            )
            print(f"\n[filter] === Phase 4 skipped ({push_skipped_reason}) ===")

        review_count = len([e for e in all_drop_entries
                            if e.get("confidence", "").lower() in ("medium", "low")])

        summary_lines = [
            "asvs_relevance_filter complete.",
            f"  source reports:       {len(section_keys)}",
            f"  filtered & written:   {sections_written}",
            f"  passed through:       {sections_passthrough}",
            f"  failed batches:       {len(failed_batches)}",
            f"  findings kept:        {total_kept}",
            f"  findings dropped:     {total_dropped}",
            f"  drops needing review: {review_count}",
            f"  policy docs used:     {len(policy_docs)} ({github_root_hits} from GitHub repo root)",
            f"  profile hash:         {profile_hash}",
            f"  filtered namespace:   {filtered_ns_name}",
        ]
        if pushed:
            summary_lines.append(
                f"  pushed to:            {private_repo}/{output_directory}/ "
                f"({len(pushed)} artifacts)"
            )
        elif push_skipped_reason:
            summary_lines.append(f"  private repo push:    skipped ({push_skipped_reason})")

        summary = "\n".join(summary_lines) + "\n"
        print("\n" + summary)

        return {
            "outputText": summary,
            "filteredReportsNamespace": filtered_ns_name,
        }

    except Exception as e:
        import traceback as _tb
        err_type = type(e).__name__
        err_msg = str(e) or "(no message)"
        tb_str = _tb.format_exc()
        print(f"\n!!! asvs_relevance_filter FATAL: {err_type}: {err_msg}", flush=True)
        print(f"Traceback:\n{tb_str}", flush=True)
        return {
            "outputText": f"Error: asvs_relevance_filter raised {err_type}: {err_msg}\n\n{tb_str}"
        }
    finally:
        try:
            await http_client.aclose()
        except Exception:
            pass