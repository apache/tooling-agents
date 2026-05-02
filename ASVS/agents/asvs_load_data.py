# asvs_load_data

from agent_factory.remote_mcp_client import RemoteMCPClient
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient(timeout=60.0)
    try:
        import csv
        import io
        import re
        import asyncio

        # =============================================================
        # Read inputs from their own fields. Anything in inputText is
        # also accepted as a fallback for backwards compatibility.
        # =============================================================
        def _coerce_bool(v, default=False):
            if isinstance(v, bool):
                return v
            if v is None:
                return default
            return str(v).strip().lower() in ("true", "1", "yes", "y", "on")

        TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+$")

        def _normalize_tag(s):
            if s is None:
                return None
            s = str(s).strip()
            if not s or not TAG_RE.match(s):
                return None
            return s if s.startswith("v") else f"v{s}"

        # Primary: discrete fields (which is how this agent's UI is wired).
        version_raw = input_dict.get("version") or input_dict.get("tag") or ""
        clear_raw = input_dict.get("clear")
        if clear_raw is None:
            clear_raw = input_dict.get("clearExisting")
        token_raw = input_dict.get("githubToken") or input_dict.get("token") or ""
        enrich_raw = input_dict.get("enrichMarkdown")

        # Fallback: parse inputText for the same keys (one per line, k: v).
        input_text = (input_dict.get("inputText") or "").strip()
        if input_text:
            for raw_line in input_text.split("\n"):
                line = raw_line.strip()
                if not line or ":" not in line:
                    continue
                k, _, v = line.partition(":")
                k = k.strip().lower()
                v = v.strip()
                if k in ("version", "tag") and not version_raw:
                    version_raw = v
                elif k in ("clear", "clear_existing", "clearexisting") and clear_raw is None:
                    clear_raw = v
                elif k in ("token", "github_token", "githubtoken") and not token_raw:
                    token_raw = v
                elif k in ("enrich_markdown", "enrichmarkdown", "markdown") and enrich_raw is None:
                    enrich_raw = v

        tag = _normalize_tag(version_raw) or "v5.0.0"
        if version_raw and _normalize_tag(version_raw) is None:
            return {"outputText": (
                f"Error: invalid version '{version_raw}' (expected vN.N.N or N.N.N)"
            )}
        clear_existing = _coerce_bool(clear_raw, default=False)
        github_token = (token_raw or "").strip()
        enrich_markdown = _coerce_bool(enrich_raw, default=True)

        ver = tag.lstrip("v")
        if not ver.startswith("5."):
            return {"outputText": (
                f"Error: only ASVS v5.x is supported (got {tag}). "
                f"v4 has a different file layout."
            )}

        csv_url = (
            f"https://raw.githubusercontent.com/OWASP/ASVS/{tag}/5.0/docs_en/"
            f"OWASP_Application_Security_Verification_Standard_{ver}_en.csv"
        )

        gh_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if github_token:
            gh_headers["Authorization"] = f"Bearer {github_token}"

        print(f"Loading ASVS {tag}", flush=True)
        print(f"  CSV: {csv_url}", flush=True)
        print(f"  clear_existing: {clear_existing}", flush=True)
        print(f"  enrich_markdown: {enrich_markdown}", flush=True)

        # =============================================================
        # Fetch + validate CSV
        # =============================================================
        csv_resp = await http_client.get(csv_url, follow_redirects=False)
        if csv_resp.status_code != 200:
            return {"outputText": (
                f"Error fetching CSV ({csv_resp.status_code}): {csv_url}\n"
                f"Tag '{tag}' may not exist, or the CSV may not be at the expected path "
                f"in this version. Check https://github.com/OWASP/ASVS/tree/{tag}/5.0/docs_en\n"
                f"Response body (first 500 chars): {csv_resp.text[:500]}"
            )}

        csv_text = csv_resp.content.decode("utf-8-sig", errors="replace")

        EXPECTED_HEADER = "chapter_id,chapter_name,section_id,section_name,req_id,req_description,L"
        first_line = csv_text.splitlines()[0] if csv_text else ""
        if first_line.strip() != EXPECTED_HEADER:
            return {"outputText": (
                f"Error: response from {csv_url} is not the expected ASVS CSV.\n"
                f"Expected header:\n  {EXPECTED_HEADER}\n"
                f"Got first line:\n  {first_line[:200]}"
            )}

        # =============================================================
        # Parse CSV
        # =============================================================
        chapters = {}
        sections = {}
        requirements = {}

        reader = csv.DictReader(io.StringIO(csv_text))
        rows_seen = 0
        for row in reader:
            rows_seen += 1
            chapter_id = row["chapter_id"].lstrip("V").strip()
            section_id = row["section_id"].lstrip("V").strip()
            req_id = row["req_id"].lstrip("V").strip()
            try:
                level = int(row["L"])
            except (ValueError, KeyError):
                level = 1

            chapters.setdefault(chapter_id, {
                "chapter_id": chapter_id,
                "chapter_name": row["chapter_name"].strip(),
                "control_objective": "",
            })
            sections.setdefault(section_id, {
                "section_id": section_id,
                "section_name": row["section_name"].strip(),
                "chapter_id": chapter_id,
                "description": "",
            })
            requirements[req_id] = {
                "req_id": req_id,
                "req_description": row["req_description"].strip(),
                "level": level,
                "section_id": section_id,
                "chapter_id": chapter_id,
            }

        print(f"  Parsed: {rows_seen} rows -> {len(chapters)} chapters, "
              f"{len(sections)} sections, {len(requirements)} requirements", flush=True)

        if not requirements:
            return {"outputText": f"Error: CSV parsed but produced 0 requirements. URL: {csv_url}"}

        # =============================================================
        # Markdown enrichment for control_objective and section descriptions.
        # The CSV doesn't carry these and the JSON file only carries
        # structural metadata; chapter intros and section blurbs live only
        # in the per-chapter markdown files at 5.0/en/0x*-V*-*.md.
        # =============================================================
        ch_enriched = 0
        sec_enriched = 0
        md_skipped_reason = None

        if enrich_markdown:
            api_base = f"https://api.github.com/repos/OWASP/ASVS"
            print(f"  Listing chapter markdown files...", flush=True)
            # Markdown lives in 5.0/en/ — the docs_en/ folder is for
            # generated artifacts (CSV/JSON/PDF/DOCX) only.
            list_resp = await http_client.get(
                f"{api_base}/contents/5.0/en?ref={tag}",
                headers=gh_headers,
            )
            if list_resp.status_code != 200:
                md_skipped_reason = f"contents API returned {list_resp.status_code}"
                if list_resp.status_code in (403, 429):
                    md_skipped_reason += " (rate-limited; pass githubToken to raise the limit)"
                print(f"  WARNING: {md_skipped_reason}; skipping markdown enrichment "
                      f"(tried 5.0/en/)", flush=True)
            else:
                items = list_resp.json()
                # Match chapter files: 0x10-V1-Encoding.md, 0x11-V2-..., etc.
                md_re = re.compile(r"^0x[0-9a-fA-F]+-V(\d+)[-.].*\.md$")
                md_files = []
                for it in items:
                    if it.get("type") != "file":
                        continue
                    name = it.get("name", "")
                    m = md_re.match(name)
                    if m and it.get("download_url"):
                        md_files.append((int(m.group(1)), name, it["download_url"]))
                md_files.sort()
                print(f"  Found {len(md_files)} chapter markdown files", flush=True)

                sem = asyncio.Semaphore(4)

                async def _fetch_md(name, url):
                    async with sem:
                        try:
                            r = await http_client.get(url, headers=gh_headers, follow_redirects=True)
                            if r.status_code == 200:
                                return name, r.text
                            print(f"    {name}: HTTP {r.status_code}", flush=True)
                        except Exception as e:
                            print(f"    {name}: fetch failed ({type(e).__name__}: {e})", flush=True)
                        return name, None

                fetched = await asyncio.gather(*[_fetch_md(n, u) for _, n, u in md_files])

                # =====================================================
                # Markdown layout (v5):
                #   # V<N> <Chapter Name>
                #   <control objective paragraph(s)>
                #   ## V<N>.<M> <Section Name>
                #   <section description paragraph(s)>
                #   | # | Description | L |   <-- requirement table starts
                # =====================================================
                chapter_h_re = re.compile(r"^# V(\d+)\s+(.+?)\s*$", re.MULTILINE)
                section_h_re = re.compile(r"^## V(\d+\.\d+)\s+(.+?)\s*$", re.MULTILINE)
                table_start_re = re.compile(r"^\s*\|\s*#\s*\|", re.MULTILINE)

                def _clean(text):
                    # Drop a "## Control Objective" sub-header if present.
                    text = re.sub(r"^##\s+Control Objective\s*$", "", text, flags=re.MULTILINE)
                    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
                    return "\n\n".join(paragraphs).strip()

                for name, md_text in fetched:
                    if not md_text:
                        continue
                    ch_m = chapter_h_re.search(md_text)
                    if not ch_m:
                        continue
                    chapter_id = ch_m.group(1)

                    sec_matches = list(section_h_re.finditer(md_text))

                    # Chapter control objective: between # V<N> and the first ## V<N>.<M>
                    co_start = ch_m.end()
                    co_end = sec_matches[0].start() if sec_matches else len(md_text)
                    co = _clean(md_text[co_start:co_end])
                    if co and chapter_id in chapters:
                        chapters[chapter_id]["control_objective"] = co
                        ch_enriched += 1

                    # Section descriptions
                    for i, sm in enumerate(sec_matches):
                        section_id = sm.group(1)
                        sd_start = sm.end()
                        sd_end = sec_matches[i + 1].start() if i + 1 < len(sec_matches) else len(md_text)
                        body = md_text[sd_start:sd_end]
                        tm = table_start_re.search(body)
                        if tm:
                            body = body[:tm.start()]
                        sd = _clean(body)
                        if sd and section_id in sections:
                            sections[section_id]["description"] = sd
                            sec_enriched += 1

                print(f"  Markdown enrichment: {ch_enriched}/{len(chapters)} chapters, "
                      f"{sec_enriched}/{len(sections)} sections", flush=True)

        # =============================================================
        # Write to data store
        # =============================================================
        asvs_ns = data_store.use_namespace("asvs")

        cleared_count = 0
        existing = asvs_ns.list_keys() or []
        existing_asvs = [k for k in existing if k.startswith("asvs:")]
        if clear_existing:
            if existing_asvs:
                print(f"  Clearing {len(existing_asvs)} existing 'asvs:*' keys", flush=True)
                for k in existing_asvs:
                    asvs_ns.delete(k)
                cleared_count = len(existing_asvs)
        else:
            if existing_asvs:
                print(f"  Skipping clear; {len(existing_asvs)} existing 'asvs:*' keys "
                      f"will be overwritten in place where IDs match", flush=True)

        print(f"  Writing {len(chapters)} chapters...", flush=True)
        for chapter_id, ch in chapters.items():
            asvs_ns.set(f"asvs:chapters:{chapter_id}", ch)

        print(f"  Writing {len(sections)} sections...", flush=True)
        for section_id, sec in sections.items():
            asvs_ns.set(f"asvs:sections:{section_id}", sec)

        print(f"  Writing {len(requirements)} requirements...", flush=True)
        for req_id, req in requirements.items():
            asvs_ns.set(f"asvs:requirements:{req_id}", req)

        # =============================================================
        # Sanity check
        # =============================================================
        sample_req_id = sorted(
            requirements.keys(), key=lambda s: [int(p) for p in s.split(".")]
        )[0]
        sample_req = asvs_ns.get(f"asvs:requirements:{sample_req_id}")
        sample_sec = asvs_ns.get(f"asvs:sections:{sample_req.get('section_id','')}") if sample_req else None
        sample_ch = asvs_ns.get(f"asvs:chapters:{sample_req.get('chapter_id','')}") if sample_req else None

        sanity_ok = bool(
            sample_req and sample_req.get("req_description") and sample_req.get("level")
            and sample_sec and sample_sec.get("section_name")
            and sample_ch and sample_ch.get("chapter_name")
        )

        levels = {1: 0, 2: 0, 3: 0}
        for r in requirements.values():
            lv = r.get("level")
            if lv in levels:
                levels[lv] += 1

        summary_lines = [
            f"ASVS {tag} loaded into data_store namespace 'asvs'",
            f"  Source URL:   {csv_url}",
            f"  Chapters:     {len(chapters)}",
            f"  Sections:     {len(sections)}",
            f"  Requirements: {len(requirements)}",
            f"    L1: {levels[1]}",
            f"    L2: {levels[2]}",
            f"    L3: {levels[3]}",
            f"  Cleared first: {cleared_count} existing keys" if clear_existing else "  Cleared first: no (clear=false)",
            f"  Chapter objectives populated:    {ch_enriched}/{len(chapters)}",
            f"  Section descriptions populated:  {sec_enriched}/{len(sections)}",
            f"  Sanity check (read-back of {sample_req_id}): {'OK' if sanity_ok else 'FAILED'}",
        ]
        if md_skipped_reason:
            summary_lines.append(f"  Markdown enrichment skipped: {md_skipped_reason}")
        if sample_req:
            summary_lines.append(
                f"  Sample req {sample_req_id}: L{sample_req.get('level','?')} — "
                f"{sample_req.get('req_description','')[:120]}"
            )

        result = "\n".join(summary_lines)
        print(result, flush=True)
        return {"outputText": result}

    finally:
        await http_client.aclose()