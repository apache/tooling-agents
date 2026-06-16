# asvs_aggregate
#
# Runs after all per-component consolidations finish. Takes the surviving
# actionable findings from every component and groups them by root cause
# so the final report shows one aggregate finding per architectural issue
# rather than N near-duplicates.
#
# Matches the CVE aggregation policy that many ASF projects document:
# "CVEs issued based on the underlying architectural root cause rather
# than the number of affected endpoints or exploit payloads."
#
# Pure-Python grouping, no LLM call. The grouping key is deterministic
# based on (CWE, normalized title pattern, normalized file pattern).
#
# Input:
#   repo: owner/repo string
#   component_results: JSON list of per-component result records, each
#                      with "namespace" and "consolidated_report_uri"
#
# Output (JSON in outputText):
#   {
#     "aggregates": [
#       {
#         "aggregate_id": "AGG-001",
#         "cwe": "CWE-79",
#         "title": "[3 components] XSS via direct innerHTML interpolation",
#         "severity": "High",   # max of constituent severities
#         "components_affected": ["superset-frontend", "legacy-charts"],
#         "constituent_findings": [
#           {
#             "component": "superset-frontend",
#             "finding_id": "FINDING-001",
#             "title": "Unsanitized data interpolated into Datamaps popup HTML",
#             "file": "plugins/legacy-plugin-chart-world-map/src/WorldMap.ts",
#             "severity": "High"
#           },
#           ...
#         ]
#       },
#       ...
#     ],
#     "singletons": [...],   # findings appearing in only 1 component (passthrough)
#     "summary": {
#       "total_findings": int,
#       "aggregates_created": int,
#       "findings_aggregated": int,
#       "singletons": int
#     }
#   }


async def run(input_dict, tools):
    import json
    import re

    try:
        # Inputs arrive as a JSON object in inputText (same convention as
        # asvs_guidance_upload / asvs_push_github):
        #   inputText: {"repo": "owner/repo", "component_results": [...]}
        # component_results may be a list (preferred) or a JSON-string for
        # backward tolerance.
        input_text = input_dict.get("inputText", "")
        if not input_text:
            return {"outputText": json.dumps({
                "error": "inputText is required (JSON with 'repo' and 'component_results')"})}
        try:
            params = json.loads(input_text)
        except Exception as e:
            return {"outputText": json.dumps({"error": f"inputText must be valid JSON: {e}"})}
        if not isinstance(params, dict):
            return {"outputText": json.dumps({"error": "inputText must be a JSON object"})}

        repo = (params.get("repo") or "").strip()
        component_results = params.get("component_results", [])
        # Tolerate component_results being a JSON-encoded string.
        if isinstance(component_results, str):
            try:
                component_results = json.loads(component_results)
            except Exception as e:
                return {"outputText": json.dumps({
                    "error": f"component_results string must be valid JSON: {e}"})}
        if not isinstance(component_results, list):
            return {"outputText": json.dumps({
                "error": "component_results must be a JSON array",
            })}

        # ----- Collect all findings -----
        # Each component_result entry tells us where to find that component's
        # consolidated report. The findings are stored in the per-component
        # consolidate output namespace.
        all_findings = []
        for cr in component_results:
            component = cr.get("component") or cr.get("name")
            namespace = cr.get("namespace") or cr.get("subnamespace")
            if not component or not namespace:
                continue

            # Read the consolidated findings for this component from the
            # findings storage namespace
            findings_ns_name = f"consolidate_findings:{namespace}"
            try:
                ns = data_store.use_namespace(findings_ns_name)
                for key in ns.list_keys():
                    raw = ns.get(key)
                    finding = json.loads(raw)
                    finding["_component"] = component
                    all_findings.append(finding)
            except Exception as e:
                print(
                    f"[aggregate] could not read findings for {component} "
                    f"({findings_ns_name}): {type(e).__name__}: {e}",
                    flush=True,
                )
                continue

        print(
            f"[aggregate] {len(all_findings)} total findings across "
            f"{len(component_results)} component(s)",
            flush=True,
        )

        # ----- Group by normalized key -----
        groups = {}   # group_key -> list of findings
        for f in all_findings:
            group_key = _compute_group_key(f)
            groups.setdefault(group_key, []).append(f)

        # ----- Build aggregates -----
        aggregates = []
        singletons = []
        agg_counter = 1

        for group_key, findings in groups.items():
            if len(findings) < 2:
                # Singleton — pass through with no aggregation
                singletons.extend(findings)
                continue

            # Build aggregate record
            severity = _max_severity([f.get("severity", "Info") for f in findings])
            components_affected = sorted(set(f["_component"] for f in findings))
            cwe = group_key[0]
            title_pattern = group_key[1]

            agg = {
                "aggregate_id": f"AGG-{agg_counter:03d}",
                "cwe": cwe,
                "title": f"[{len(components_affected)} components] {title_pattern}",
                "severity": severity,
                "components_affected": components_affected,
                "constituent_findings": [
                    {
                        "component": f["_component"],
                        "finding_id": f.get("finding_id") or f.get("id"),
                        "title": f.get("title"),
                        "file": _primary_file(f),
                        "severity": f.get("severity"),
                    }
                    for f in findings
                ],
            }
            aggregates.append(agg)
            agg_counter += 1

        # ----- Sort aggregates by severity then count -----
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Informational": 4}
        aggregates.sort(key=lambda a: (
            sev_order.get(a["severity"], 99),
            -len(a["constituent_findings"]),
        ))

        # ----- Print summary -----
        findings_aggregated = sum(len(a["constituent_findings"]) for a in aggregates)
        print(
            f"[aggregate] created {len(aggregates)} aggregate(s) covering "
            f"{findings_aggregated} finding(s); {len(singletons)} singleton(s)",
            flush=True,
        )
        for agg in aggregates:
            print(
                f"  - {agg['aggregate_id']} [{agg['severity']}] "
                f"({len(agg['constituent_findings'])} components): "
                f"{agg['title'][:80]}",
                flush=True,
            )

        result = {
            "aggregates": aggregates,
            "singletons": singletons,
            "summary": {
                "total_findings": len(all_findings),
                "aggregates_created": len(aggregates),
                "findings_aggregated": findings_aggregated,
                "singletons": len(singletons),
            },
        }

        return {"outputText": json.dumps(result, indent=2, sort_keys=True)}

    except Exception as e:
        import json as _json
        err_type = type(e).__name__
        err_msg = str(e) or "(no message)"
        return {"outputText": _json.dumps({"error": f"{err_type}: {err_msg}"})}


def _compute_group_key(finding):
    """
    Build a deterministic grouping key from a finding. Returns a tuple of
    (cwe, title_pattern, file_pattern). Findings with the same key are
    grouped into an aggregate.
    """
    cwe = finding.get("cwe") or finding.get("CWE") or "CWE-?"

    # Normalize title: strip project/component-specific names that vary
    # across components but don't change the architectural root cause.
    title = finding.get("title", "")
    title_pattern = _normalize_title(title)

    # Normalize file: drop component prefix, compress numbered segments
    file_path = _primary_file(finding)
    file_pattern = _normalize_file(file_path)

    return (cwe, title_pattern, file_pattern)


def _normalize_title(title):
    """
    Strip project-specific names so 'XSS in WorldMap chart' and 'XSS in
    BubbleMap chart' both reduce to 'XSS in <chart>'.

    Heuristic: drop CamelCase words that look like proper nouns
    (PascalCase identifiers, likely class names or product names).
    Replace them with a single token.
    """
    import re
    # Replace PascalCase identifiers (likely component-specific names)
    # with <name> placeholders
    normalized = re.sub(r"\b[A-Z][a-z]+(?:[A-Z][a-z]+)+\b", "<name>", title)
    # Collapse multiple <name>s into one
    normalized = re.sub(r"(?:<name>\s*)+", "<name>", normalized)
    # Collapse whitespace
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _normalize_file(file_path):
    """
    Strip the component prefix and compress variable parts so that
    'frontend/src/plugin/world-map.ts' and 'frontend/src/plugin/bubble-map.ts'
    both reduce to 'src/plugin/<name>.ts'.
    """
    import re
    if not file_path:
        return ""
    # Replace numeric segments
    normalized = re.sub(r"/\d+(?=/|$)", "/<n>", file_path)
    # Replace likely-variable last segment before extension
    normalized = re.sub(
        r"/[a-z][a-z0-9_-]+\.([a-z]+)$",
        r"/<name>.\1",
        normalized,
        flags=re.IGNORECASE,
    )
    return normalized


def _primary_file(finding):
    """Extract the primary file path from a finding's affected_files."""
    files = finding.get("affected_files") or finding.get("files") or []
    if not files:
        return ""
    first = files[0]
    if isinstance(first, dict):
        return first.get("file", "")
    return str(first)


def _max_severity(severities):
    """Return the max severity from a list (severity is qualitative)."""
    order = ["Critical", "High", "Medium", "Low", "Info", "Informational"]
    for sev in order:
        if sev in severities:
            return sev
    return "Info"