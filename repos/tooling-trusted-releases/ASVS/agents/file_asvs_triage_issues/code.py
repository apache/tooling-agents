from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        github_repo = input_dict["github_repo"]
        github_token = input_dict["github_token"]
        commit_hash = input_dict["commit_hash"]
        issues_url = input_dict["issues_url"]
        triage_content = input_dict["triage_content"]

        issues_filed = []
        issues_skipped = []
        issues_consolidated = []
        errors = []

        api_base = "https://api.github.com"
        gh_headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        # Convert GitHub blob URL to raw URL if needed
        raw_url = issues_url
        if "github.com" in raw_url and "/blob/" in raw_url:
            raw_url = raw_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")

        # ═══════════════════════════════════════════════════════════════════
        # Step 1: Parse triage content FIRST
        # ═══════════════════════════════════════════════════════════════════

        triage = []
        skip_label_kw = {'documentation', 'priority', 'discussion', 'long-term', 'longterm'}

        for line in triage_content.strip().replace('\r\n', '\n').split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or re.match(r'^[-|:=\s]+$', line):
                continue
            if re.match(r'^\|?\s*(Finding|ID|#|Num|Number)\s*\|', line, re.IGNORECASE):
                continue

            # ── Table format (pipe-delimited) ──
            if '|' in line:
                parts = [p.strip() for p in line.split('|') if p.strip()]
                if len(parts) >= 2:
                    id_m = re.search(r'(\d+)', parts[0])
                    if id_m:
                        rest_text = ' - '.join(parts[1:])
                        disp_m = re.match(
                            r'(Todo|Fixed|Done|N/?A|Skip\w*|Ignore\w*|Won\'?t\s*Fix|Deferred|Accepted)\s*[-\u2013\u2014:.]?\s*(.*)',
                            rest_text, re.IGNORECASE
                        )
                        if disp_m:
                            triage.append({
                                'finding_id': id_m.group(1),
                                'disposition': disp_m.group(1).strip(),
                                'commentary': re.sub(r'^[-\u2013\u2014:.]\s*', '', disp_m.group(2)).strip(),
                                'raw_line': line
                            })
                            continue

            # ── Free-form format ──
            id_m = re.match(r'(?:FINDING[-_]?\s*)?(\d+)\s*[-\u2013\u2014:.]\s*(.*)', line, re.IGNORECASE)
            if not id_m:
                id_m = re.match(r'(?:FINDING[-_]?\s*)?(\d+)\s+(.*)', line, re.IGNORECASE)
            if not id_m:
                continue

            fid = id_m.group(1)
            rest = re.sub(r'^[-\u2013\u2014:.]\s*', '', id_m.group(2)).strip()

            disp_m = re.match(
                r'(Todo|Fixed|Done|N/?A|Skip\w*|Ignore\w*|Won\'?t\s*Fix|Deferred|Accepted)\s*[-\u2013\u2014:.]?\s*(.*)',
                rest, re.IGNORECASE
            )
            if disp_m:
                triage.append({
                    'finding_id': fid,
                    'disposition': disp_m.group(1).strip(),
                    'commentary': re.sub(r'^[-\u2013\u2014:.]\s*', '', disp_m.group(2)).strip(),
                    'raw_line': line
                })
            else:
                words = rest.split(None, 1)
                triage.append({
                    'finding_id': fid,
                    'disposition': words[0] if words else 'Unknown',
                    'commentary': re.sub(r'^[-\u2013\u2014:.]\s*', '', words[1]).strip() if len(words) > 1 else '',
                    'raw_line': line
                })

        print(f"Parsed {len(triage)} triage entries", flush=True)
        if not triage:
            return {
                "summary": "No triage entries could be parsed from the provided content.",
                "issues_filed": [], "issues_skipped": [], "issues_consolidated": [],
                "errors": ["No triage entries could be parsed"]
            }

        # ═══════════════════════════════════════════════════════════════════
        # Step 2: Filter to Todo entries and collect needed finding IDs
        # ═══════════════════════════════════════════════════════════════════

        todo_entries = []
        needed_ids = set()

        for entry in triage:
            fid = entry['finding_id']
            disp = entry['disposition']
            comm_lower = entry['commentary'].lower()

            if disp.lower() != 'todo':
                issues_skipped.append({"finding_id": fid, "reason": f"Disposition: {disp}"})
                continue

            first_word = re.sub(r'^[\s\-]+', '', comm_lower).split()[0].rstrip('.,;:-') if comm_lower.strip().lstrip('-').strip() else ''
            if first_word in ('asfquart', 'asfpy'):
                issues_skipped.append({"finding_id": fid, "reason": f"Refers to {first_word}"})
                continue

            todo_entries.append(entry)
            needed_ids.add(fid)

            rel_m = re.search(
                r'(?:related\s+to|adjacent\s+to)\s+(?:FINDING[-_]?\s*)?(\d+)',
                entry['commentary'], re.IGNORECASE
            )
            if rel_m:
                needed_ids.add(rel_m.group(1))

        if not todo_entries:
            return {
                "summary": f"No Todo findings to process out of {len(triage)} triage entries.",
                "issues_filed": [], "issues_skipped": issues_skipped,
                "issues_consolidated": [], "errors": [],
            }

        print(f"{len(todo_entries)} Todo entries, {len(needed_ids)} finding IDs needed", flush=True)

        # ═══════════════════════════════════════════════════════════════════
        # Step 3: Fetch issues markdown
        # ═══════════════════════════════════════════════════════════════════

        print(f"Fetching issues markdown from: {raw_url}", flush=True)
        fetch_headers = {"User-Agent": "ASVS-Issue-Filer", "Accept": "text/plain"}
        if github_token:
            fetch_headers["Authorization"] = f"token {github_token}"

        try:
            resp = await http_client.get(raw_url, headers=fetch_headers, follow_redirects=True, timeout=30.0)
            resp.raise_for_status()
            issues_md = resp.text
            print(f"Fetched {len(issues_md)} characters of issues markdown", flush=True)
        except Exception as e:
            return {
                "summary": f"Failed to fetch issues markdown: {e}",
                "issues_filed": [], "issues_skipped": issues_skipped,
                "issues_consolidated": [], "errors": [f"Failed to fetch issues markdown: {e}"]
            }

        # ═══════════════════════════════════════════════════════════════════
        # Step 4: Parse ONLY the FINDING sections whose IDs we need
        # ═══════════════════════════════════════════════════════════════════

        finding_pattern = re.compile(r'^##\s+(?:Issue:\s*)?FINDING-(\d+)\s*[-\u2013\u2014:]\s*(.+?)(?:\n|$)', re.MULTILINE)
        all_matches = list(finding_pattern.finditer(issues_md))

        findings = {}

        for i, m in enumerate(all_matches):
            fid = m.group(1)
            if fid not in needed_ids:
                continue

            title = m.group(2).strip()
            section_start = m.end()
            section_end = all_matches[i + 1].start() if i + 1 < len(all_matches) else len(issues_md)
            body_text = issues_md[section_start:section_end].strip()

            # Extract labels
            lbl_match = re.search(r'\*{0,2}Labels\*{0,2}\s*:\s*(.+)', body_text)
            raw_lbls = []
            if lbl_match:
                raw_lbls = [l.strip().strip('`').strip('*').strip() for l in lbl_match.group(1).split(',') if l.strip()]

            proc_labels = []
            for lbl in raw_lbls:
                ll = lbl.lower()
                if ll == 'bug':
                    continue
                elif ll == 'security':
                    proc_labels.append('security')
                elif ll.startswith('priority:'):
                    proc_labels.append(lbl.split(':', 1)[1].strip())
                elif ll.startswith('asvs-level:'):
                    lvl = lbl.split(':', 1)[1].strip()
                    if 'asvs' not in proc_labels:
                        proc_labels.append('asvs')
                    proc_labels.append(lvl)
                else:
                    proc_labels.append(lbl)
            proc_labels.append(commit_hash)

            desc_match = re.search(r'#+\s*Description\s*\n(.*)', body_text, re.DOTALL)
            if desc_match:
                desc = desc_match.group(1).strip()
            elif lbl_match:
                desc = body_text[lbl_match.end():].strip()
            else:
                desc = body_text

            findings[fid] = {'title': title, 'labels': proc_labels, 'description': desc}

        print(f"Parsed {len(findings)}/{len(needed_ids)} needed findings "
              f"(out of {len(all_matches)} total in file)", flush=True)

        if not findings:
            print("WARNING: No matching findings found in issues markdown", flush=True)

        # ═══════════════════════════════════════════════════════════════════
        # Step 5: Build consolidation map (with chain resolution)
        # ═══════════════════════════════════════════════════════════════════

        consol_map_raw = {}
        for entry in todo_entries:
            m = re.search(
                r'(?:related\s+to|adjacent\s+to)\s+(?:FINDING[-_]?\s*)?(\d+)',
                entry['commentary'], re.IGNORECASE
            )
            if m:
                target = m.group(1)
                consol_map_raw[entry['finding_id']] = target

        def resolve_target(fid, cmap, visited=None):
            if visited is None:
                visited = set()
            if fid in visited:
                return fid
            visited.add(fid)
            if fid in cmap:
                return resolve_target(cmap[fid], cmap, visited)
            return fid

        consol_map = {}
        for fid in consol_map_raw:
            t = resolve_target(fid, consol_map_raw)
            if t != fid:
                consol_map[fid] = t

        print(f"Consolidation map (resolved): {consol_map}", flush=True)

        # ═══════════════════════════════════════════════════════════════════
        # Step 6: Helper functions
        # ═══════════════════════════════════════════════════════════════════

        LABEL_COLORS = {
            'security': 'e11d48', 'critical': 'd73a4a', 'high': 'ff6600',
            'medium': 'f59e0b', 'low': '22c55e', 'asvs': '6366f1',
            'L1': '8b5cf6', 'L2': '8b5cf6', 'L3': '8b5cf6',
            'documentation': '0075ca', 'discussion': '0e8a16',
            'priority': 'ff6600', 'long term goal': '7c3aed',
            'LLM': '1d76db',
        }

        created_labels_cache = set()

        async def ensure_label(name):
            if name in created_labels_cache:
                return
            color = LABEL_COLORS.get(name, 'bfd4f2')
            try:
                await http_client.post(
                    f"{api_base}/repos/{github_repo}/labels",
                    headers=gh_headers,
                    json={"name": name, "color": color},
                    timeout=10.0,
                )
            except Exception:
                pass
            created_labels_cache.add(name)

        async def fetch_gh_issue(url):
            try:
                m = re.search(r'github\.com/([^/]+/[^/]+)/issues/(\d+)', url)
                if m:
                    r = await http_client.get(
                        f"{api_base}/repos/{m.group(1)}/issues/{m.group(2)}",
                        headers=gh_headers, timeout=15.0
                    )
                    if r.status_code == 200:
                        return r.json()
            except Exception:
                pass
            return None

        async def compare_issues(f_title, f_desc, issue_data):
            ex_title = issue_data.get('title', '')
            ex_body = (issue_data.get('body', '') or '')[:3000]
            is_open = issue_data.get('state', '') == 'open'

            try:
                prompt = (
                    "Compare these two security findings.\n\n"
                    f"EXISTING GitHub issue (state: {'open' if is_open else 'closed'}):\n"
                    f"Title: {ex_title}\nBody excerpt: {ex_body}\n\n"
                    f"NEW finding:\nTitle: {f_title}\nDescription excerpt: {f_desc[:3000]}\n\n"
                    "Are these: \"same\" (exact same vulnerability), \"related\" "
                    "(related but distinct), or \"different\" (unrelated)?\n"
                    "Reply with ONE word: same, related, or different."
                )
                content, _ = await call_llm(
                    provider="bedrock",
                    model="us.anthropic.claude-sonnet-4-5-20250929-v1:0",
                    messages=[{"role": "user", "content": prompt}],
                    parameters={"temperature": 1, "reasoning_effort": "medium", "max_tokens": 32117},
                )
                r = content.strip().lower()
                if 'same' in r:
                    return 'same', is_open
                elif 'related' in r:
                    return 'related', is_open
                return 'different', is_open
            except Exception as e:
                errors.append(f"LLM comparison failed ({e}), falling back to heuristic")
                def normalize(text):
                    return set(re.findall(r'\w+', (text or '').lower()))
                existing_words = normalize(ex_title + ' ' + ex_body)
                new_words = normalize(f_title + ' ' + f_desc)
                if new_words:
                    overlap = len(existing_words & new_words) / len(new_words)
                    if overlap > 0.7:
                        return 'same', is_open
                    elif overlap > 0.4:
                        return 'related', is_open
                return 'different', is_open

        # ═══════════════════════════════════════════════════════════════════
        # Step 7: Core issue-filing function
        # ═══════════════════════════════════════════════════════════════════

        filed_map = {}

        non_username_words = {
            'documentation', 'priority', 'discussion', 'this', 'that',
            'the', 'need', 'needs', 'should', 'also', 'see', 'check', 'add',
            'fix', 'update', 'review', 'test', 'investigate', 'consider',
            'related', 'adjacent', 'similar', 'same', 'duplicate', 'existing',
            'http', 'https', 'we', 'it', 'is', 'are', 'was', 'has', 'have',
            'will', 'would', 'could', 'can', 'may', 'not', 'and', 'or', 'but',
            'for', 'from', 'with', 'about', 'todo', 'done', 'fixed', 'skip',
            'term', 'goal', 'note', 'notes', 'open', 'close', 'closed',
            'new', 'old', 'all', 'some', 'any', 'no', 'yes', 'true', 'false',
            'confirm', 'audit_guidance', 'low', 'long-term', 'in-line', 'inline',
        }

        async def file_issue_for_finding(fid, comm):
            comm_lower = comm.lower()

            if fid not in findings:
                errors.append(f"FINDING-{fid} not found in issues markdown")
                return False

            finding = findings[fid]
            title = finding['title']
            description = finding['description']
            labels = list(finding['labels'])
            assignees = []

            # ── Detect assignee: only explicit @username mentions ──
            for at_m in re.finditer(r'@([a-zA-Z][\w-]{0,38})', comm):
                username = at_m.group(1)
                if username.lower() not in non_username_words:
                    assignees.append(username)

            # ── Extra labels from commentary keywords ──
            if 'documentation' in comm_lower:
                labels.append('documentation')
            if 'discussion' in comm_lower:
                labels.append('discussion')
            if 'long-term' in comm_lower or 'long term' in comm_lower:
                labels.append('long term goal')

            # Priority override: "low" in commentary replaces finding's priority labels
            if re.search(r'\blow\b', comm_lower):
                priority_labels = {'critical', 'high', 'medium', 'low'}
                labels = [l for l in labels if l.lower() not in priority_labels]
                labels.append('low')
            elif re.search(r'\bpriority\b', comm_lower):
                labels.append('priority')

            # audit_guidance (covers "inline audit_guidance", "in-line audit_guidance") → LLM label
            if 'audit_guidance' in comm_lower:
                labels.append('LLM')

            # ── Check GitHub issue links ──
            gh_link_m = re.search(r'(https?://github\.com/[^\s)\]>]+/issues/\d+)', comm)
            related_link = None

            if gh_link_m:
                existing_url = gh_link_m.group(1).rstrip('.,;')
                print(f"  Checking linked issue: {existing_url}", flush=True)
                existing_issue = await fetch_gh_issue(existing_url)

                if existing_issue:
                    comparison, is_open = await compare_issues(title, description, existing_issue)
                    print(f"  Comparison result: {comparison}, is_open: {is_open}", flush=True)

                    if comparison == 'same' and is_open:
                        issues_skipped.append({
                            "finding_id": fid,
                            "reason": f"Duplicate of open issue: {existing_url}"
                        })
                        return False
                    elif comparison in ('related', 'same'):
                        related_link = existing_url

            # ── Build issue body ──
            body = description

            for other_id, target_id in consol_map.items():
                if target_id == fid and other_id in findings:
                    cf = findings[other_id]
                    body += (
                        f"\n\n---\n\n### Consolidated: FINDING-{other_id} - {cf['title']}"
                        f"\n\n{cf['description']}"
                    )

            if related_link:
                body += f"\n\n---\n\n**Related issue:** {related_link}"

            if comm:
                temp = comm
                for a in assignees:
                    temp = re.sub(r'@?' + re.escape(a), '', temp, count=1, flags=re.IGNORECASE)
                if gh_link_m:
                    temp = temp.replace(gh_link_m.group(1).rstrip('.,;'), '')
                for kw_pat in [r'\bdocumentation\b', r'\bpriority\b', r'\bdiscussion\b', r'\blong[- ]term\b', r'\baudit_guidance\b', r'\blow\b']:
                    temp = re.sub(kw_pat, '', temp, flags=re.IGNORECASE)
                temp = re.sub(r'(?:related\s+to|adjacent\s+to)\s+(?:FINDING[-_]?\s*)?\d+', '', temp, flags=re.IGNORECASE)
                temp = re.sub(r'[-\u2013\u2014:.,\s]+', ' ', temp).strip()
                if temp and len(temp) > 1:
                    body += f"\n\n---\n\n**Triage notes:** {comm}"

            # Deduplicate labels
            seen_labels = set()
            unique_labels = []
            for l in labels:
                key = l.lower()
                if key not in seen_labels:
                    seen_labels.add(key)
                    unique_labels.append(l)
            labels = unique_labels

            for lbl in labels:
                await ensure_label(lbl)

            # Truncate body at GitHub's 65536-char limit
            if len(body) > 65000:
                body = body[:64900] + "\n\n---\n*[Truncated]*"

            # ── Create the GitHub issue ──
            try:
                payload = {"title": title[:256], "body": body, "labels": labels}
                if assignees:
                    payload["assignees"] = list(set(assignees))

                print(f"  Creating: \"{title[:80]}\" | labels={labels} | assignees={assignees}", flush=True)

                r = await http_client.post(
                    f"{api_base}/repos/{github_repo}/issues",
                    headers=gh_headers, json=payload, timeout=30.0
                )

                if r.status_code == 422 and assignees:
                    print(f"  Got 422, retrying without assignees...", flush=True)
                    payload.pop("assignees", None)
                    assignees = []
                    r = await http_client.post(
                        f"{api_base}/repos/{github_repo}/issues",
                        headers=gh_headers, json=payload, timeout=30.0
                    )

                r.raise_for_status()
                result = r.json()
                gh_url = result.get('html_url', '')
                filed_map[fid] = gh_url

                issues_filed.append({
                    "finding_id": fid,
                    "title": title,
                    "github_url": gh_url,
                    "labels": labels,
                    "assignees": list(set(assignees))
                })
                print(f"  \u2713 {gh_url}", flush=True)
                await asyncio.sleep(1)
                return True

            except Exception as e:
                err_msg = f"Failed to create issue for FINDING-{fid}: {e}"
                try:
                    err_msg += f" | Response: {r.text[:300]}"
                except Exception:
                    pass
                errors.append(err_msg)
                return False

        # ═══════════════════════════════════════════════════════════════════
        # Step 8: Pass 1 — non-consolidated Todo entries
        # ═══════════════════════════════════════════════════════════════════

        print(f"\n=== Pass 1: {len(todo_entries) - len(consol_map_raw)} non-consolidated ===", flush=True)

        for entry in todo_entries:
            fid = entry['finding_id']
            if fid in consol_map:
                continue
            print(f"\nFINDING-{fid}: Todo | {entry['commentary']}", flush=True)
            await file_issue_for_finding(fid, entry['commentary'])

        # ═══════════════════════════════════════════════════════════════════
        # Step 9: Pass 2 — consolidated entries
        # ═══════════════════════════════════════════════════════════════════

        print(f"\n=== Pass 2: {len(consol_map)} consolidated ===", flush=True)

        for entry in todo_entries:
            fid = entry['finding_id']
            if fid not in consol_map:
                continue

            target = consol_map[fid]
            if target in filed_map:
                issues_consolidated.append({"finding_id": fid, "consolidated_into": target})
                print(f"FINDING-{fid}: Consolidated into FINDING-{target} ({filed_map[target]})", flush=True)
            else:
                print(f"\nFINDING-{fid}: Target {target} not filed; filing independently", flush=True)
                await file_issue_for_finding(fid, entry['commentary'])

        # ═══════════════════════════════════════════════════════════════════
        # Step 10: Summary
        # ═══════════════════════════════════════════════════════════════════

        summary = (
            f"Processed {len(triage)} triage entries for {github_repo}. "
            f"{len(todo_entries)} Todo (of {len(triage)} total). "
            f"Parsed {len(findings)}/{len(needed_ids)} needed findings "
            f"(out of {len(all_matches)} in file). "
            f"Filed {len(issues_filed)} issues, skipped {len(issues_skipped)}, "
            f"consolidated {len(issues_consolidated)} findings."
        )
        if errors:
            summary += f" Encountered {len(errors)} errors."

        print(f"\n{'='*60}\n{summary}", flush=True)

        return {
            "summary": summary,
            "issues_filed": issues_filed,
            "issues_skipped": issues_skipped,
            "issues_consolidated": issues_consolidated,
            "errors": errors
        }

    finally:
        await http_client.aclose()