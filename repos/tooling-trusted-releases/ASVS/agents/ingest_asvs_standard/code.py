# ingest_asvs_standard
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        url = "https://cdn.asvs.ee/standards/v5.0.0.json"

        try:
            response = await http_client.get(url)
            response.raise_for_status()
            source = response.json()
        except Exception as e:
            return {"outputText": f"Failed to fetch ASVS source JSON: {e}"}

        if "chapters" not in source:
            return {"outputText": "Malformed source JSON: missing 'chapters' key at top level."}

        def strip_v(s):
            if isinstance(s, str) and s.startswith("V"):
                return s[1:]
            return s

        chapters_records = {}
        sections_records = {}
        requirements_records = {}
        section_index = {}
        chapter_sections_index = {}
        chapter_reqs_index = {}
        all_req_ids = set()
        all_section_ids = set()
        all_chapter_ids = set()
        errors = []

        for chapter in source["chapters"]:
            for field in ("chapter_id", "chapter_name", "control_objective", "references", "sections"):
                if field not in chapter:
                    errors.append(f"Chapter missing required field '{field}': {json.dumps(chapter)[:200]}")
            if errors:
                break

            ch_id = strip_v(chapter["chapter_id"])
            if "V" in ch_id:
                errors.append(f"chapter_id still contains 'V' after stripping: {ch_id}")
                break
            if ch_id in all_chapter_ids:
                errors.append(f"Duplicate chapter_id: {ch_id}")
                break
            all_chapter_ids.add(ch_id)

            chapters_records[f"asvs:chapters:{ch_id}"] = {
                "chapter_id": ch_id,
                "chapter_name": chapter["chapter_name"],
                "control_objective": chapter["control_objective"],
                "references": chapter["references"]
            }

            collected_section_ids = []
            collected_req_ids = []

            for section in chapter.get("sections", []):
                for field in ("section_id", "section_name", "description", "requirements"):
                    if field not in section:
                        errors.append(f"Section missing required field '{field}' in chapter {ch_id}: {json.dumps(section)[:200]}")
                if errors:
                    break

                sec_id = strip_v(section["section_id"])
                if sec_id in all_section_ids:
                    errors.append(f"Duplicate section_id: {sec_id}")
                    break
                all_section_ids.add(sec_id)

                sections_records[f"asvs:sections:{sec_id}"] = {
                    "section_id": sec_id,
                    "chapter_id": ch_id,
                    "section_name": section["section_name"],
                    "description": section["description"]
                }

                collected_section_ids.append(sec_id)
                section_req_ids = []

                for req in section.get("requirements", []):
                    for field in ("req_id", "req_description", "level"):
                        if field not in req:
                            errors.append(f"Requirement missing required field '{field}' in section {sec_id}: {json.dumps(req)[:200]}")
                    if errors:
                        break

                    req_id = req["req_id"]
                    level = req["level"]
                    if level not in (1, 2, 3):
                        errors.append(f"Invalid level '{level}' for requirement {req_id}. Must be 1, 2, or 3.")
                        break
                    if req_id in all_req_ids:
                        errors.append(f"Duplicate req_id: {req_id}")
                        break
                    all_req_ids.add(req_id)
                    if req_id.startswith("V"):
                        errors.append(f"req_id has unexpected 'V' prefix: {req_id}")
                        break

                    requirements_records[f"asvs:requirements:{req_id}"] = {
                        "req_id": req_id,
                        "section_id": sec_id,
                        "chapter_id": ch_id,
                        "req_description": req["req_description"],
                        "level": level
                    }
                    section_req_ids.append(req_id)
                    collected_req_ids.append(req_id)

                if errors:
                    break
                section_index[sec_id] = section_req_ids

            if errors:
                break
            chapter_sections_index[ch_id] = collected_section_ids
            chapter_reqs_index[ch_id] = collected_req_ids

        if errors:
            return {"outputText": f"Ingestion aborted due to errors:\n" + "\n".join(errors)}

        # Validation
        for req_key, req_rec in requirements_records.items():
            if req_rec["section_id"] not in all_section_ids:
                errors.append(f"Requirement {req_rec['req_id']} references non-existent section_id {req_rec['section_id']}")
            if req_rec["chapter_id"] not in all_chapter_ids:
                errors.append(f"Requirement {req_rec['req_id']} references non-existent chapter_id {req_rec['chapter_id']}")

        for sec_key, sec_rec in sections_records.items():
            if sec_rec["chapter_id"] not in all_chapter_ids:
                errors.append(f"Section {sec_rec['section_id']} references non-existent chapter_id {sec_rec['chapter_id']}")

        for ch_id in all_chapter_ids:
            if "V" in ch_id:
                errors.append(f"Stored chapter_id contains 'V': {ch_id}")
        for sec_id in all_section_ids:
            if "V" in sec_id:
                errors.append(f"Stored section_id contains 'V': {sec_id}")

        for sec_id, req_ids in section_index.items():
            actual_reqs = [r["req_id"] for r in requirements_records.values() if r["section_id"] == sec_id]
            if sorted(req_ids) != sorted(actual_reqs):
                errors.append(f"Section index mismatch for {sec_id}")

        for ch_id, sec_ids in chapter_sections_index.items():
            actual_secs = [s["section_id"] for s in sections_records.values() if s["chapter_id"] == ch_id]
            if sorted(sec_ids) != sorted(actual_secs):
                errors.append(f"Chapter sections index mismatch for {ch_id}")

        for ch_id, req_ids in chapter_reqs_index.items():
            actual_reqs = [r["req_id"] for r in requirements_records.values() if r["chapter_id"] == ch_id]
            if sorted(req_ids) != sorted(actual_reqs):
                errors.append(f"Chapter reqs index mismatch for {ch_id}")

        if errors:
            return {"outputText": f"Validation failed, ingestion aborted:\n" + "\n".join(errors)}

        ns = data_store.use_namespace("asvs")
        ns.set_many(chapters_records)
        ns.set_many(sections_records)
        ns.set_many(requirements_records)

        index_records = {}
        for sec_id, req_ids in section_index.items():
            index_records[f"asvs:section_index:{sec_id}"] = req_ids
        for ch_id, sec_ids in chapter_sections_index.items():
            index_records[f"asvs:chapter_sections_index:{ch_id}"] = sec_ids
        for ch_id, req_ids in chapter_reqs_index.items():
            index_records[f"asvs:chapter_reqs_index:{ch_id}"] = req_ids
        ns.set_many(index_records)

        total_chapters = len(chapters_records)
        total_sections = len(sections_records)
        total_requirements = len(requirements_records)
        total_indexes = len(index_records)

        level_counts = {1: 0, 2: 0, 3: 0}
        for req_rec in requirements_records.values():
            level_counts[req_rec["level"]] += 1

        summary_lines = [
            f"ASVS v{source.get('version', 'unknown')} ingestion completed successfully.",
            f"",
            f"Records stored:",
            f"  - Chapters:     {total_chapters}",
            f"  - Sections:     {total_sections}",
            f"  - Requirements: {total_requirements}",
            f"  - Index keys:   {total_indexes}",
            f"",
            f"Requirements by level:",
            f"  - Level 1: {level_counts[1]}",
            f"  - Level 2: {level_counts[2]}",
            f"  - Level 3: {level_counts[3]}",
            f"",
            f"All validation checks passed:",
            f"  ✓ All IDs globally unique",
            f"  ✓ All referential integrity constraints satisfied",
            f"  ✓ All level values are 1, 2, or 3",
            f"  ✓ All indexes contain correct child IDs",
            f"  ✓ No stored ID contains a 'V' prefix",
        ]

        return {"outputText": "\n".join(summary_lines)}

    finally:
        await http_client.aclose()
