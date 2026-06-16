# asvs_compare_open_issues_prs
#
# Runs after consolidation. For each finding in the consolidated report,
# decides whether an OPEN issue already tracks it or an OPEN pull request
# already addresses it, using the commit-pinned snapshot produced by
# asvs_fetch_issues_prs. Emits an annotation report; it does NOT modify or
# delete findings (annotate-and-link, never suppress — a wrongly-hidden
# finding is worse than a duplicate).
#
# Pipeline position: orchestrator calls this after asvs_consolidate succeeds.
# It reads the rendered consolidated.md from the reports namespace (the
# findings already live there as "#### FINDING-NNN" blocks with an attribute
# table carrying Severity / CWE / Files), and the snapshot from
# issues_prs:{repo}@{sha}.
#
# Two-stage matching (keeps cost bounded — never all-pairs LLM):
#   1. Deterministic pre-filter per finding -> a few candidate issues/PRs.
#      Signals, strongest first:
#        - file-path overlap (finding Files vs PR changed_files)  [strongest]
#        - CWE match (finding CWE vs issue/PR title+body)
#        - keyword overlap (finding title tokens vs issue/PR title)
#      Only findings with >=1 candidate go to stage 2.
#   2. LLM adjudication (Sonnet) on the candidates for that one finding:
#      "does this issue TRACK / this PR ADDRESS the finding, or is it merely
#       in the same area?" Returns a verdict per candidate.
#
# Outcomes per finding: tracked_by (open issue), addressed_by (open PR),
# or none. "Open PR addresses" always means "fix in flight — verify",
# never "resolved".
#
# Inputs (inputText = JSON object):
#   repo                (required): owner/repo
#   sha                 (required): commit_hash — selects the snapshot
#                                   namespace issues_prs:{repo}@{sha}
#   reports_namespace   (required): where consolidated.md lives
#   consolidated_key    (optional, default "consolidated.md")
#   max_candidates_per_finding (optional, default 5)
#
# Output (outputText = JSON): annotation report (see result shape at end)
# plus a human-readable markdown summary under "report_md".
#
# Models: Sonnet for adjudication only (cheap pre-filter is pure Python).


async def run(input_dict, tools):
    import json
    import re

    def _err(msg):
        return {"outputText": json.dumps({"error": msg})}

    try:
        input_text = input_dict.get("inputText", "")
        if not input_text:
            return _err("inputText is required (JSON with repo, sha, reports_namespace)")
        try:
            params = json.loads(input_text)
        except Exception as e:
            return _err(f"inputText must be valid JSON: {e}")
        if not isinstance(params, dict):
            return _err("inputText must be a JSON object")

        repo = (params.get("repo") or "").strip().strip("/")
        sha = (params.get("sha") or "").strip()
        reports_namespace = (params.get("reports_namespace") or "").strip()
        consolidated_key = (params.get("consolidated_key") or "consolidated.md").strip()
        max_candidates = int(params.get("max_candidates_per_finding", 5))

        if not repo or not sha or not reports_namespace:
            return _err("repo, sha, and reports_namespace are all required")

        # ----- Load the snapshot -----
        snap_ns_name = f"issues_prs:{repo}@{sha}"
        snap_ns = data_store.use_namespace(snap_ns_name)
        snap_keys = []
        try:
            snap_keys = snap_ns.list_keys()
        except Exception as e:
            return _err(f"could not read snapshot {snap_ns_name}: "
                        f"{type(e).__name__}: {e}")
        if not snap_keys:
            return _err(f"snapshot {snap_ns_name} is empty — was "
                        f"asvs_fetch_issues_prs run for this commit?")

        issues, prs = [], []
        for k in snap_keys:
            if k == "__meta__":
                continue
            try:
                rec = json.loads(snap_ns.get(k))
            except Exception:
                continue
            if rec.get("type") == "pr":
                prs.append(rec)
            elif rec.get("type") == "issue":
                issues.append(rec)

        # ----- Load findings: prefer the structured JSON that asvs_consolidate
        # persists (clean, has real affected_files + CWE + severity), and fall
        # back to parsing consolidated.md only if that namespace is absent
        # (reports generated before consolidate started persisting). -----
        findings = []
        sf_ns_name = f"consolidated_findings:{reports_namespace}"
        try:
            sf_ns = data_store.use_namespace(sf_ns_name)
            raw = sf_ns.get("findings")
            if raw:
                structured = json.loads(raw)
                for f in structured:
                    af = f.get("affected_files") or []
                    files = []
                    for x in af:
                        if isinstance(x, dict):
                            p = x.get("file") or ""
                        else:
                            p = str(x)
                        p = re.sub(r"[:\s(].*$", "", p).strip().strip("`")
                        if p:
                            files.append(p)
                    findings.append({
                        "id": f.get("global_id") or f.get("finding_id") or "FINDING-?",
                        "title": f.get("title") or "",
                        "severity": f.get("severity") or "Info",
                        "cwe": (f.get("cwe") or "").strip() if f.get("cwe") not in (None, "null") else "",
                        "files": files,
                        "description": (f.get("description") or "")[:1000],
                    })
                print(f"[compare] loaded {len(findings)} structured finding(s) "
                      f"from {sf_ns_name}", flush=True)
        except Exception as e:
            print(f"[compare] no structured findings ({type(e).__name__}); "
                  f"will parse consolidated.md", flush=True)
            findings = []

        if not findings:
            # Fallback: parse the rendered report.
            rep_ns = data_store.use_namespace(reports_namespace)
            md = None
            try:
                md = rep_ns.get(consolidated_key)
            except Exception:
                md = None
            if not md:
                try:
                    for k in rep_ns.list_keys():
                        if k.endswith(consolidated_key):
                            md = rep_ns.get(k)
                            break
                except Exception:
                    pass
            if not md:
                return _err(f"no structured findings at {sf_ns_name} and could "
                            f"not find {consolidated_key} in {reports_namespace}; "
                            f"nothing to compare")
            findings = _parse_findings(md, re)
        if not findings:
            return {"outputText": json.dumps({
                "repo": repo, "sha": sha,
                "summary": {"findings": 0, "tracked": 0, "addressed": 0,
                            "unaddressed": 0},
                "note": "no FINDING blocks parsed from consolidated.md",
                "annotations": [],
            })}

        # ----- Stage 1: deterministic pre-filter -----
        def _norm_path(p):
            return (p or "").strip().strip("`").lstrip("/").lower()

        def _basename(p):
            p = _norm_path(p)
            return p.rsplit("/", 1)[-1] if p else ""

        def _tokens(text):
            return set(re.findall(r"[a-z0-9]{4,}", (text or "").lower()))

        STOP = {"the","and","via","with","from","into","that","this","when",
                "where","which","could","should","using","unsafe","missing",
                "issue","finding","security","vulnerability"}

        candidates_by_finding = {}
        for fnd in findings:
            f_files = [_norm_path(x) for x in fnd["files"] if x]
            f_basenames = {_basename(x) for x in f_files if x}
            f_cwe = (fnd["cwe"] or "").upper().replace(" ", "")
            f_kw = _tokens(fnd["title"]) - STOP

            scored = []
            for item in issues + prs:
                score = 0
                reasons = []
                # file-path overlap (PRs carry changed_files; strongest)
                changed = [_norm_path(x) for x in item.get("changed_files", [])]
                if changed and f_files:
                    overlap = set(changed) & set(f_files)
                    base_overlap = {_basename(x) for x in changed} & f_basenames
                    if overlap:
                        score += 5 * len(overlap); reasons.append("path-exact")
                    elif base_overlap:
                        score += 2 * len(base_overlap); reasons.append("path-basename")
                # CWE in title/body
                hay = f"{item.get('title','')} {item.get('body','')}".upper().replace(" ", "")
                if f_cwe and f_cwe in hay:
                    score += 3; reasons.append("cwe")
                # keyword overlap in title
                it_kw = _tokens(item.get("title", "")) - STOP
                kw_overlap = f_kw & it_kw
                if len(kw_overlap) >= 2:
                    score += len(kw_overlap); reasons.append("keywords")
                if score > 0:
                    scored.append((score, item, reasons))

            scored.sort(key=lambda t: t[0], reverse=True)
            top = scored[:max_candidates]
            if top:
                candidates_by_finding[fnd["id"]] = (fnd, top)

        # ----- Stage 2: LLM adjudication per finding with candidates -----
        annotations = []
        tracked = addressed = 0

        SONNET_PROVIDER = "bedrock"
        SONNET_MODEL = "us.anthropic.claude-sonnet-4-6"
        SONNET_PARAMS = {"temperature": 0.7, "max_tokens": 4096}

        for fid, (fnd, top) in candidates_by_finding.items():
            cand_lines = []
            for i, (score, item, reasons) in enumerate(top):
                kind = item["type"].upper()
                cf = item.get("changed_files", [])
                cf_str = (", ".join(cf[:8]) + (" ..." if len(cf) > 8 else "")) if cf else "(n/a)"
                cand_lines.append(
                    f"[{i}] {kind} #{item['number']}: {item.get('title','')}\n"
                    f"    labels: {', '.join(item.get('labels') or []) or '(none)'}\n"
                    f"    changed_files: {cf_str}\n"
                    f"    body: {(item.get('body') or '')[:500]}"
                )
            prompt = (
                "You are triaging whether an existing OPEN GitHub issue or pull "
                "request already covers a security audit finding.\n\n"
                f"FINDING {fnd['id']}: {fnd['title']}\n"
                f"Severity: {fnd['severity']}  CWE: {fnd['cwe'] or 'n/a'}\n"
                f"Files: {', '.join(fnd['files']) or 'n/a'}\n"
                f"Description: {fnd['description'][:800]}\n\n"
                "CANDIDATES:\n" + "\n\n".join(cand_lines) + "\n\n"
                "For each candidate decide its relationship to the finding:\n"
                "- TRACKS: an issue describing this same problem (not yet fixed)\n"
                "- ADDRESSES: a PR whose changes plausibly fix this finding "
                "(in flight — not proof of resolution)\n"
                "- RELATED: same area/file but does NOT cover this finding\n"
                "- UNRELATED\n\n"
                "Be strict: same file or same CWE is NOT enough for TRACKS/"
                "ADDRESSES — the candidate must concern the same specific "
                "weakness. Return ONLY JSON: "
                '{"verdicts":[{"index":N,"relation":"TRACKS|ADDRESSES|RELATED|'
                'UNRELATED","confidence":"high|medium|low","why":"<=20 words"}]}'
            )
            messages = [{"role": "user", "content": prompt}]
            verdicts = []
            try:
                raw, _ = await call_llm(
                    provider=SONNET_PROVIDER, model=SONNET_MODEL,
                    messages=messages, parameters=SONNET_PARAMS, timeout=120,
                )
                m = re.search(r"\{[\s\S]*\}", raw or "")
                if m:
                    verdicts = json.loads(m.group()).get("verdicts", [])
            except Exception as e:
                print(f"[compare] adjudication failed for {fid}: "
                      f"{type(e).__name__}: {e}", flush=True)
                verdicts = []

            tracked_by, addressed_by, related = [], [], []
            for v in verdicts:
                idx = v.get("index")
                if not isinstance(idx, int) or idx < 0 or idx >= len(top):
                    continue
                item = top[idx][1]
                rel = (v.get("relation") or "").upper()
                ref = {"number": item["number"], "type": item["type"],
                       "title": item.get("title"), "url": item.get("url"),
                       "confidence": v.get("confidence"), "why": v.get("why")}
                if rel == "TRACKS":
                    tracked_by.append(ref)
                elif rel == "ADDRESSES":
                    addressed_by.append(ref)
                elif rel == "RELATED":
                    related.append(ref)

            if tracked_by:
                tracked += 1
            if addressed_by:
                addressed += 1
            annotations.append({
                "finding_id": fnd["id"], "title": fnd["title"],
                "severity": fnd["severity"],
                "tracked_by": tracked_by, "addressed_by": addressed_by,
                "related": related,
            })

        # findings with no candidates at all are unaddressed
        annotated_ids = {a["finding_id"] for a in annotations}
        for fnd in findings:
            if fnd["id"] not in annotated_ids:
                annotations.append({
                    "finding_id": fnd["id"], "title": fnd["title"],
                    "severity": fnd["severity"],
                    "tracked_by": [], "addressed_by": [], "related": [],
                })

        unaddressed = sum(1 for a in annotations
                          if not a["tracked_by"] and not a["addressed_by"])

        annotations.sort(key=lambda a: a["finding_id"])
        report_md = _render_md(repo, sha, findings, annotations)

        print(f"[compare] {len(findings)} findings: {tracked} tracked by open "
              f"issue, {addressed} addressed by open PR, {unaddressed} "
              f"unaddressed (vs {len(issues)} issues / {len(prs)} PRs @ {sha})",
              flush=True)

        return {"outputText": json.dumps({
            "repo": repo, "sha": sha,
            "snapshot": snap_ns_name,
            "summary": {"findings": len(findings), "tracked": tracked,
                        "addressed": addressed, "unaddressed": unaddressed,
                        "open_issues": len(issues), "open_prs": len(prs)},
            "annotations": annotations,
            "report_md": report_md,
        }, indent=2)}

    except Exception as e:
        import json as _json
        return {"outputText": _json.dumps({
            "error": f"{type(e).__name__}: {str(e) or '(no message)'}"})}


def _parse_findings(md, re):
    """Parse '#### FINDING-NNN: Title' blocks out of consolidated.md, pulling
    Severity / CWE / Files from the attribute table and the Description text.
    Tolerant of LLM-rendered markdown variation."""
    findings = []
    # Split on the finding headers, keeping the header with its block.
    parts = re.split(r"(?m)^####\s+FINDING-(\d+)\s*:\s*(.+?)\s*$", md)
    # parts = [pre, id1, title1, body1, id2, title2, body2, ...]
    i = 1
    while i + 2 < len(parts) + 1 and i + 2 <= len(parts):
        if i + 2 > len(parts):
            break
        fid_num = parts[i]
        title = parts[i + 1].strip()
        body = parts[i + 2] if i + 2 < len(parts) else ""
        def _field(name):
            m = re.search(rf"(?im)^\s*[|*-]*\s*{name}\s*[:|]\s*(.+?)\s*\|?\s*$", body)
            if m:
                return m.group(1).strip().strip("|").strip()
            return ""
        severity = _field("Severity")
        # strip emoji/markdown noise from severity
        severity = re.sub(r"[^\w]", "", severity).strip() or severity.strip()
        for sv in ("Critical", "High", "Medium", "Low", "Info", "Informational"):
            if sv.lower() in (severity or "").lower():
                severity = sv
                break
        cwe_raw = _field("CWE")
        cwe_m = re.search(r"CWE[-\s]?(\d+)", cwe_raw or body, re.IGNORECASE)
        cwe = f"CWE-{cwe_m.group(1)}" if cwe_m else ""
        files_raw = _field("Files") or _field("File")
        files = []
        for chunk in re.split(r"[,\n]", files_raw):
            c = chunk.strip().strip("`").strip()
            c = re.sub(r"[:\s(].*$", "", c)   # drop :line and trailing
            if c and "/" in c or (c and "." in c):
                files.append(c)
        # description = first prose paragraph after the table
        desc = ""
        dm = re.search(r"(?is)Description\s*[:|]?\s*(.+?)(?:\n\s*\n|Remediation|####|---)", body)
        if dm:
            desc = re.sub(r"\s+", " ", dm.group(1)).strip()
        findings.append({
            "id": f"FINDING-{fid_num}", "title": title, "severity": severity or "Info",
            "cwe": cwe, "files": files, "description": desc,
        })
        i += 3
    return findings


def _render_md(repo, sha, findings, annotations):
    lines = [f"# Cross-Reference: Findings vs Open Issues/PRs",
             f"", f"Repository: `{repo}`  ", f"Commit: `{sha}`  ",
             f"Findings cross-referenced against the commit-pinned snapshot of "
             f"open issues and PRs.", ""]
    by_id = {a["finding_id"]: a for a in annotations}
    for fnd in findings:
        a = by_id.get(fnd["id"], {})
        lines.append(f"## {fnd['id']}: {fnd['title']}  ({fnd['severity']})")
        tb = a.get("tracked_by") or []
        ab = a.get("addressed_by") or []
        rel = a.get("related") or []
        if tb:
            for r in tb:
                lines.append(f"- **Tracked by open issue** #{r['number']} "
                             f"({r.get('confidence','?')}): {r.get('title','')} "
                             f"— {r.get('why','')}")
        if ab:
            for r in ab:
                lines.append(f"- **Possibly addressed by open PR** #{r['number']} "
                             f"({r.get('confidence','?')} — verify, in flight): "
                             f"{r.get('title','')} — {r.get('why','')}")
        if rel:
            refs = ", ".join(f"#{r['number']}" for r in rel)
            lines.append(f"- Related (same area, does not cover): {refs}")
        if not tb and not ab:
            lines.append(f"- No open issue or PR appears to address this — "
                         f"candidate for filing.")
        lines.append("")
    return "\n".join(lines)