# asvs_orchestrate
#
# The single entry point for the ASVS audit pipeline. Orchestrates:
#   asvs_download_repo  →  asvs_discover  →  asvs_audit / asvs_bundle  →
#   asvs_push_github (×N)  →  asvs_consolidate  →  redact + publish
#
# Major improvements over the unoptimized baseline:
#   T1 — Sections within each pass dispatch in parallel via asyncio.gather
#         with a configurable PASS_CONCURRENCY semaphore. The original ran
#         sections strictly sequentially (await in for-loop). This is the
#         single biggest win: 70%+ reduction on its own.
#   T4 — Bundled-mode dispatch: when a discovery pass has multiple ASVS
#         sections sharing the same file scope, they're sent in a single
#         multi-section call to asvs_bundle and the response is split back
#         out per-section before pushing to GitHub.
#   T12 — Skip discovery entirely for tiny repos (<30k LOC). Use a single
#         "all" pass with no domain partition.
#
# Concurrency knobs (env vars, with sensible defaults):
#   PASS_CONCURRENCY (default 4) — number of audit passes/sections in flight
#   BUNDLE_MAX_SECTIONS (default 6) — max sections per Opus call
#   BUNDLE_MIN_SECTIONS (default 2) — fall back to single-section below this
#   TINY_REPO_LOC_THRESHOLD (default 30000) — skip discovery under this
#
# Backward compat: behavior with bundling disabled (BUNDLE_MAX_SECTIONS=1)
# matches the original orchestrator section-by-section.

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        def _estimate_loc_from_namespace(namespace):
            """T12: Estimate LOC by sampling a few files from the data store."""
            try:
                ns = data_store.use_namespace(namespace)
                keys = ns.list_keys()
                if not keys:
                    return 0
                total_lines = 0
                sample_size = min(100, len(keys))
                sampled = keys[:sample_size]
                for k in sampled:
                    try:
                        content = ns.get(k) or ""
                        if isinstance(content, str):
                            total_lines += content.count("\n")
                    except Exception:
                        continue
                if sample_size < len(keys):
                    total_lines = int(total_lines * len(keys) / sample_size)
                return total_lines
            except Exception as e:
                print(f"    LOC estimate failed: {e}", flush=True)
                return 100_000  # default to "not tiny" on failure

        def _parse_audit_output(audit_output_text, section_chunk):
            """Decode either a bundled JSON envelope or a single-section markdown report.

            Returns dict: {section_id: (report_markdown, status_signal)}.

            status_signal is one of:
              - "ok"            => section has real content (findings or
                                   the auditor's own Pass/Fail/N/A judgment)
              - "no_relevant_code" => bundle determined nothing applies (the
                                   asvs_bundle.py "no Opus batches needed"
                                   path); legitimate N/A, NOT a failure
              - "bundle_error"  => bundle emitted an error envelope. The
                                   section's result is missing and the run
                                   must not be published without manual review.
              - "missing_section" => bundle returned `per_section` with this
                                   section's entry absent or None. Partial
                                   bundle failure; flag for review.
              - "malformed_multi" => bundle was expected to return a JSON
                                   envelope for a multi-section chunk but
                                   returned raw markdown. Treat as a partial
                                   failure: first section gets the markdown,
                                   the rest get error stubs.
            """
            import json

            # ---- Bundled JSON envelope path ----
            stripped = audit_output_text.strip()
            if stripped.startswith("{"):
                try:
                    envelope = json.loads(audit_output_text)
                except json.JSONDecodeError:
                    envelope = None

                if envelope is not None:
                    # GUARDRAIL: explicit error envelope check BEFORE the
                    # bundled-mode check. The legacy code path treated any
                    # non-bundled JSON as "unparseable" and fell through to
                    # the multi-section fallback, which silently attributed
                    # the error JSON to the first section. Detect the error
                    # shape explicitly and emit per-section ERROR stubs so
                    # downstream can fail the quality check.
                    err_msg = envelope.get("error")
                    if err_msg:
                        bundle_status = envelope.get("bundle_status", "bundle_error")
                        print(
                            f"  [WARN] bundle returned error envelope "
                            f"(status={bundle_status}): {err_msg}",
                            flush=True,
                        )
                        out = {}
                        for sid in section_chunk:
                            out[sid] = (
                                (
                                    f"# ASVS {sid}\n\n"
                                    f"**Status:** ERROR\n\n"
                                    f"**Reason:** Bundle audit agent returned an "
                                    f"error envelope. This section's per-section "
                                    f"report is missing.\n\n"
                                    f"**Bundle status:** `{bundle_status}`\n\n"
                                    f"**Error:** {err_msg}\n\n"
                                    f"_The consolidated report should not be "
                                    f"published until this section is re-audited "
                                    f"or this status is reviewed._\n"
                                ),
                                "bundle_error",
                            )
                        return out

                    if envelope.get("mode") == "bundled":
                        per_section = envelope.get("per_section", {})
                        bundle_status = envelope.get("bundle_status", "ok")
                        out = {}
                        for sid in section_chunk:
                            entry = per_section.get(sid)
                            if entry is None:
                                out[sid] = (
                                    (
                                        f"# ASVS {sid}\n\n"
                                        f"**Status:** ERROR\n\n"
                                        f"**Reason:** Bundle audit produced no "
                                        f"output for this section. The bundle "
                                        f"completed but this section's slot in "
                                        f"the per_section map was empty. This "
                                        f"may indicate the analysis didn't "
                                        f"return a recognizable section header "
                                        f"for this requirement.\n"
                                    ),
                                    "missing_section",
                                )
                            else:
                                section_signal = (
                                    "no_relevant_code"
                                    if bundle_status == "no_relevant_code"
                                    else "ok"
                                )
                                out[sid] = (entry.get("report", ""), section_signal)
                        return out

            # ---- Fallback: single-section markdown report ----
            if len(section_chunk) == 1:
                return {section_chunk[0]: (audit_output_text, "ok")}

            # ---- Fallback: multiple sections expected but no JSON envelope ----
            # This is a malformed response. Attribute markdown to first section
            # and emit ERROR stubs for the rest so the loss is surfaced rather
            # than silently treated as "did not return per-section output" and
            # then read as N/A by the consolidator.
            print(
                f"  [WARN] bundle returned non-JSON output but multiple sections "
                f"({len(section_chunk)}) were expected; first section keeps the "
                f"output, others marked ERROR",
                flush=True,
            )
            out = {section_chunk[0]: (audit_output_text, "malformed_multi")}
            for sid in section_chunk[1:]:
                out[sid] = (
                    (
                        f"# ASVS {sid}\n\n"
                        f"**Status:** ERROR\n\n"
                        f"**Reason:** Audit agent did not return a parseable "
                        f"per-section envelope for this multi-section bundle. "
                        f"See ASVS {section_chunk[0]} for the bundle's raw "
                        f"output.\n"
                    ),
                    "malformed_multi",
                )
            return out

        import os
        import json
        import re
        import base64

        # =============================================================
        # Concurrency / bundling configuration
        # =============================================================
        PASS_CONCURRENCY = int(os.environ.get("PASS_CONCURRENCY", "4"))
        BUNDLE_MAX_SECTIONS = int(os.environ.get("BUNDLE_MAX_SECTIONS", "6"))
        BUNDLE_MIN_SECTIONS = int(os.environ.get("BUNDLE_MIN_SECTIONS", "2"))
        TINY_REPO_LOC_THRESHOLD = int(os.environ.get("TINY_REPO_LOC_THRESHOLD", "30000"))
        # Multi-component mode (large-repo decomposition). Opt-in: when
        # false (default) the orchestrator runs exactly as before. When
        # true, after download it detects components, materializes each into
        # a sub-namespace, runs the per-component pipeline under the job
        # runner up to MAX_COMPONENT_CONCURRENCY at a time, then aggregates.
        MULTI_COMPONENT_MODE = os.environ.get("MULTI_COMPONENT_MODE", "false").lower() in ("true", "1", "yes")
        MAX_COMPONENT_CONCURRENCY = int(os.environ.get("MAX_COMPONENT_CONCURRENCY", "4"))

        # =============================================================
        # Parse inputs
        # =============================================================
        source_repo = input_dict.get("sourceRepo", "")
        source_token = input_dict.get("sourceToken", "")
        # branch: optional, empty string means use the repo's default branch.
        # Useful for projects like apache/mina where master/trunk is abandoned
        # and active development lives on a version branch (e.g. 2.2.X).
        # Auditing the wrong branch wastes the entire run.
        branch = input_dict.get("branch", "").strip()
        supplemental_data = input_dict.get("supplementalData", "")
        output_repo = input_dict.get("outputRepo", "")
        output_token = input_dict.get("outputToken", "")
        output_directory = input_dict.get("outputDirectory", "")
        discover = input_dict.get("discover", "true")
        severity_threshold = input_dict.get("severityThreshold", "")
        consolidate = input_dict.get("consolidate", "true")
        level = input_dict.get("level", "")

        # clearCache and cleanStaleReports are no longer UI inputs — both
        # default to True. clearCache=True means every run wipes the cached
        # source namespace and re-downloads fresh. cleanStaleReports=True
        # means a fully successful run prunes stale reports from prior runs
        # in the same output directory (only when there are no failures).
        clear_cache = True
        clean_stale_reports = True

        if isinstance(discover, str):
            discover = discover.lower() in ("true", "1", "yes")
        if isinstance(consolidate, str):
            consolidate = consolidate.lower() in ("true", "1", "yes")

        level = level.strip().upper()
        if level and not level.startswith("L"):
            level = f"L{level}"
        LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
        max_level_num = LEVEL_ORDER.get(level, 3)

        if not source_repo:
            return {"outputText": "Error: sourceRepo is required (e.g., 'apache/airflow')"}

        # Reports are published unredacted to a single destination:
        # outputRepo/outputToken. The former private-repo carve-out (full →
        # private, redacted → public) has been removed.
        push_repo = output_repo
        push_token = output_token

        # Derive repo name, path prefix, and namespace from sourceRepo
        _source = source_repo.strip().strip("/")
        _gh_match = re.match(
            r'(?:https?://)?github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/tree/[^/]+(?:/(.+))?)?$',
            _source,
        )
        if _gh_match:
            repo_owner_name = f"{_gh_match.group(1)}/{_gh_match.group(2)}"
            repo_short_name = _gh_match.group(2)
            source_path_prefix = _gh_match.group(3) or ""
        else:
            source_parts = _source.split("/")
            if len(source_parts) < 2:
                return {"outputText": f"Error: sourceRepo must be owner/repo format, got '{source_repo}'"}
            repo_owner_name = f"{source_parts[0]}/{source_parts[1]}"
            repo_short_name = source_parts[1]
            source_path_prefix = "/".join(source_parts[2:]) if len(source_parts) > 2 else ""

        download_source = repo_owner_name
        if source_path_prefix:
            download_source += f"/{source_path_prefix}"

        code_namespace = f"files:{download_source}"

        namespaces = [code_namespace]
        if supplemental_data:
            for ns in supplemental_data.split(","):
                ns = ns.strip()
                if ns and ns not in namespaces:
                    namespaces.append(ns)

        # Fetch latest commit hash. If branch is specified, query that branch's
        # HEAD via ?sha={branch}; otherwise GitHub returns the default branch's
        # HEAD. Branch is logged either way so the run record shows which line
        # of the project was audited.
        source_headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if source_token:
            source_headers["Authorization"] = f"Bearer {source_token}"
        try:
            commits_url = f"https://api.github.com/repos/{repo_owner_name}/commits?per_page=1"
            if branch:
                commits_url += f"&sha={branch}"
            commits_resp = await http_client.get(commits_url, headers=source_headers)
            commits_data = commits_resp.json()
            commit_hash = commits_data[0]["sha"][:7]
            if branch:
                print(f"  Source branch: {branch} @ {commit_hash}", flush=True)
            else:
                print(f"  Source branch: (default) @ {commit_hash}", flush=True)
        except Exception as e:
            print(f"  WARNING: Could not fetch commit hash ({e}), using 'latest'", flush=True)
            commit_hash = "latest"

        # ---- Output path layout (scans-style) ----------------------------
        # outputDirectory is the user-supplied base only (e.g. "scans"). The
        # pipeline builds the rest:
        #   {base}/{segments-below-org}/{leaf}
        # where segments-below-org mirrors the repo path under apache/ as
        # nested directories, and leaf encodes the scan identity:
        #   {flattened-segments}-{YYYY-MM-DD}-{short_sha}
        # The audit model is NOT in the path (it lives in metadata.yml). For a
        # plain repo (no sub-component) the segments are [repo_short_name], so
        # the leaf doubles the name (e.g. fineract-fineract-DATE-SHA), matching
        # the org/project/component convention where component == repo name.
        from datetime import datetime, timezone
        scan_date_dt = datetime.now(timezone.utc)
        scan_date_ymd = scan_date_dt.strftime("%Y-%m-%d")
        short_sha = commit_hash  # already 7-char (or "latest")

        # segments below the org reflect the REAL path only. The leaf name is
        # {project}[-{sub-path-segments}]-{date}-{sha}: it doubles ONLY when a
        # real source_path_prefix exists (e.g. superset/superset -> nesting
        # superset/superset, leaf superset-superset-...). A run on all of a
        # repo (no sub-path) is single (fineract -> fineract-..., NOT
        # fineract-fineract). Nothing is synthesized.
        if source_path_prefix:
            comp_segs = [p for p in source_path_prefix.split("/") if p]
            segments_below_org = [repo_short_name] + comp_segs
        else:
            segments_below_org = [repo_short_name]

        nesting_path = "/".join(segments_below_org)
        leaf_stem = "-".join(segments_below_org)
        leaf_dir = f"{leaf_stem}-{scan_date_ymd}-{short_sha}"

        base_dir = output_directory.strip("/")
        output_directory = f"{base_dir}/{nesting_path}/{leaf_dir}"
        push_directory = output_directory

        # Captured for metadata.yml (written at end of run). 'repo' reflects
        # the real path: apache/<repo>, plus the sub-path only if one exists
        # (e.g. apache/superset for a whole-repo run; apache/superset/superset
        # or apache/airflow/providers/google when a sub-path is scanned).
        scan_project = repo_short_name
        scan_repo_full = repo_owner_name + (f"/{source_path_prefix}" if source_path_prefix else "")
        scan_meta = {
            "project": scan_project,
            "repo": scan_repo_full,
            "head_sha": commit_hash,
            "short_sha": short_sha,
            "scan_date": scan_date_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "asvs_level_input": input_dict.get("asvsLevel") or input_dict.get("asvs_level") or "",
            "branch": branch or "",
            "leaf_dir": leaf_dir,
        }

        # Source identifier appended to every report commit message so each
        # commit reads as "<commit subject> [source: owner/repo[/path] @ sha]"
        # and you can grep history by source repo or by commit hash. Format
        # is stable across all per-section, consolidated, issues, and
        # redacted pushes.
        source_id_path = repo_owner_name
        if source_path_prefix:
            source_id_path += f"/{source_path_prefix}"
        source_id = f"{source_id_path} @ {commit_hash}"

        # Per-section reports go into CouchDB instead of GitHub. The
        # previous approach committed each per-section report to the
        # private repo, which surfaced one entry on the public
        # commits@tooling.apache.org mailing list per section (often
        # with finding titles in the diff). Now they're stored in a
        # CouchDB namespace keyed by output_directory; consolidate reads
        # from the same namespace. Only consolidated.md, issues.md, and
        # their redacted variants still go to GitHub.
        reports_namespace = f"audit-reports:{output_directory}"

        print(f"  Output directory: {output_directory}", flush=True)
        print(f"  Reports namespace: {reports_namespace}", flush=True)
        print(f"  Pass concurrency: {PASS_CONCURRENCY}", flush=True)
        print(f"  Bundling: max={BUNDLE_MAX_SECTIONS} sections/call, min={BUNDLE_MIN_SECTIONS}", flush=True)
        print(f"  Publishing (unredacted) to: {output_repo}", flush=True)

        all_outputs = []
        successes = []
        failures = []
        report_directories = []

        # =============================================================
        # ASVS-level filtering
        # =============================================================
        asvs_level_cache = {}

        def load_asvs_levels():
            if asvs_level_cache:
                return
            try:
                # Load the ASVS namespace in one shot via get_all() rather
                # than list_keys() followed by per-key get() calls. With
                # ~345 requirements the old shape was ~346 HTTP calls;
                # get_all() is one call regardless of N.
                asvs_ns = data_store.use_namespace("asvs")
                all_data = asvs_ns.get_all() or {}
                req_items = {k: v for k, v in all_data.items() if k.startswith("asvs:requirements:")}
                skipped_empty = 0
                skipped_bad_level = []
                for rk, req in req_items.items():
                    if not req:
                        skipped_empty += 1
                        continue
                    section_id = rk.replace("asvs:requirements:", "")
                    try:
                        asvs_level_cache[section_id] = int(req.get("level", 1))
                    except (TypeError, ValueError):
                        # Don't let one malformed entry abort the whole
                        # cache load; record it and continue so the
                        # coverage report can warn the operator.
                        skipped_bad_level.append(section_id)
                print(f"  Loaded ASVS levels for {len(asvs_level_cache)} sections", flush=True)
                if skipped_empty or skipped_bad_level:
                    print(
                        f"    WARNING: skipped {skipped_empty} empty + "
                        f"{len(skipped_bad_level)} malformed-level entries "
                        f"out of {len(req_keys)} keys"
                        + (f"; malformed: {skipped_bad_level[:10]}" if skipped_bad_level else ""),
                        flush=True,
                    )
            except Exception as e:
                print(f"  WARNING: Could not load ASVS levels: {e}", flush=True)

        def filter_sections_by_level(sections):
            """Filter sections by level, AND drop any IDs not present in the
            authoritative ASVS data store.

            Belt-and-suspenders: discovery now validates its output too, but
            this protects against any other source of stale/hallucinated IDs
            (manually-edited domain configs, cache restoration, etc).
            """
            load_asvs_levels()
            kept = []
            dropped_unknown = []
            dropped_higher_level = []
            for s in sections:
                if s not in asvs_level_cache:
                    dropped_unknown.append(s)
                    continue
                if level and asvs_level_cache[s] > max_level_num:
                    dropped_higher_level.append(s)
                    continue
                kept.append(s)
            if dropped_unknown:
                print(f"    WARNING: dropping {len(dropped_unknown)} unknown section ID(s) not in ASVS data store: {dropped_unknown[:5]}{'...' if len(dropped_unknown) > 5 else ''}", flush=True)
            return kept

        # =============================================================
        # Step 1: Download source code (or use cached data)
        # =============================================================
        if clear_cache:
            print(f"{'='*60}\nStep 1: Downloading source code\n  Source: {source_repo}\n{'='*60}", flush=True)

            # clearCache=true should mean "wipe everything for this
            # repo/subdir so the run is genuinely from scratch", not
            # just "redownload source code". Until this loop existed,
            # the flag only gated the download step; audit-cache,
            # bundle-cache, and per-commit reports survived across
            # runs. That meant prompt changes silently kept returning
            # the previous run's findings for any cache-hit section.
            #
            # Scope of the wipe:
            #
            # CLEARED (anything derived from this source for this
            # commit):
            #   - files:{source}                        (source code)
            #   - audit-cache:relevance:asvs-*-{src}    (per-section
            #   - audit-cache:analysis:asvs-*-{src}      Haiku/Opus
            #   - audit-cache:relevance:bundle-*-{src}   audit cache)
            #   - audit-cache:analysis:bundle-*-{src}
            #   - audit-reports:{output_directory}      (per-section reports)
            #   - audit-reports-filtered:{output_dir}   (filter outputs)
            #
            # PRESERVED (intentionally, with reasoning):
            #   - audit-cache:inventory:{file_set_hash} — keyed by
            #     content hash; naturally invalidates if files change.
            #   - relevance-filter-cache:{owner_repo_root} — owner_repo_root
            #     can span multiple audited subdirs (e.g. apache/airflow
            #     covers airflow-core, airflow-task-sdk, ...); wiping
            #     here would over-wipe peer subdirs. The cache is
            #     content-keyed by profile_hash and batch_hash, so it
            #     self-invalidates on real changes.
            #   - consolidation:* / extraction:* — keyed by the PUSH
            #     repo (e.g. apache/tooling-runbooks), shared across
            #     audits. Content-hashed internally.
            #   - audit_guidance:* — uploaded guidance, not derived
            #     state. Survives runs by design.
            try:
                all_ns = data_store.list_namespaces() or []
            except Exception as e:
                all_ns = []
                print(f"  WARNING: could not enumerate namespaces "
                      f"({type(e).__name__}: {e}); proceeding with "
                      f"download only (downstream caches may be stale)",
                      flush=True)

            def _owned_by_this_run(ns_name):
                if ns_name == code_namespace:
                    return True
                if ns_name == f"audit-reports:{output_directory}":
                    return True
                if ns_name == f"audit-reports-filtered:{output_directory}":
                    return True
                # Audit/bundle caches embed the source namespace string
                # literally in their namespace name (asvs_audit/bundle:
                # `audit-cache:{relevance,analysis}:{prefix}` where
                # prefix is asvs-{section}-{namespaces} or bundle-{...}).
                if ns_name.startswith("audit-cache:relevance:") or ns_name.startswith("audit-cache:analysis:"):
                    if code_namespace in ns_name:
                        return True
                return False

            to_clear = [ns for ns in all_ns if _owned_by_this_run(ns)]
            if to_clear:
                print(f"  clearCache=true: wiping {len(to_clear)} "
                      f"namespace(s) for {code_namespace}", flush=True)
                total_keys = 0
                for ns_name in to_clear:
                    try:
                        ns = data_store.use_namespace(ns_name)
                        # clear() ships one bulk delete regardless of key
                        # count. Previously this looped delete() per key
                        # at ~3 HTTP calls each, which on a cache-heavy
                        # namespace (analysis_cache, consolidation_cache)
                        # could be thousands of sequential CouchDB calls
                        # blocking the worker for tens of seconds.
                        deleted = ns.clear()
                        total_keys += deleted
                        print(f"    {ns_name}: cleared {deleted} key(s)", flush=True)
                    except Exception as e:
                        print(f"    {ns_name}: clear failed: "
                              f"{type(e).__name__}: {e}", flush=True)
                print(f"  Cleared {total_keys} keys across "
                      f"{len(to_clear)} namespace(s)", flush=True)
            else:
                print(f"  clearCache=true: no existing namespaces to "
                      f"wipe for {code_namespace}", flush=True)

            download_input = download_source
            if source_token:
                download_input += f"\n{source_token}"
            # branch line is parsed by asvs_download_repo; absent line means
            # use the repo default. Format is "branch: NAME" so it can't
            # collide with the repo or token line shapes.
            if branch:
                download_input += f"\nbranch: {branch}"

            try:
                download_result = await gofannon_client.call(
                    agent_name="asvs_download_repo",
                    input_dict={"inputText": download_input},
                )
                download_output = download_result.get("outputText", "")
                print(f"  {download_output}", flush=True)
            except Exception as e:
                return {"outputText": f"Download failed: {e}"}
        else:
            print(f"{'='*60}\nStep 1: SKIPPED (clearCache=false)\n  Using existing data in namespace: {code_namespace}\n{'='*60}", flush=True)
            # Sanity check: don't silently proceed against an empty namespace
            try:
                files_ns = data_store.use_namespace(code_namespace)
                existing_keys = files_ns.list_keys() or []
                if not existing_keys:
                    return {"outputText": (
                        f"Error: clearCache=false but namespace '{code_namespace}' is empty. "
                        f"Either set clearCache=true to download fresh, or run asvs_download_repo "
                        f"manually first to populate the namespace."
                    )}
                print(f"  Namespace '{code_namespace}' has {len(existing_keys)} cached keys", flush=True)
            except Exception as e:
                return {"outputText": (
                    f"Error: clearCache=false but couldn't read namespace '{code_namespace}': {e}. "
                    f"Either set clearCache=true to download fresh, or check the namespace name."
                )}

        # =============================================================
        # Multi-component branch (opt-in via MULTI_COMPONENT_MODE)
        # =============================================================
        # When enabled, decompose the downloaded repo into components and
        # run a per-component pipeline, then aggregate. The single-namespace
        # flow below is left entirely intact for the default (false) case.
        #
        # Helpers are defined INSIDE run() so they close over the
        # gofannon-injected globals (data_store, gofannon_client) that are
        # not available at module scope in this runtime.
        def _materialize_subnamespace(repo, component, all_components):
            """Copy a component's files into its sub-namespace, excluding
            nested components, using one bulk write. Idempotent (skips if
            already populated, for resume)."""
            primary_ns_name = f"files:{repo}"
            sub_ns_name = component["subnamespace"]
            if primary_ns_name == sub_ns_name:
                return  # single-component repo; sub == primary
            primary_ns = data_store.use_namespace(primary_ns_name)
            sub_ns = data_store.use_namespace(sub_ns_name)
            if sub_ns.list_keys():
                print(f"  [materialize] {sub_ns_name} already populated, skipping", flush=True)
                return
            root = component["root"]
            prefix = root + "/" if root else ""
            # Nested roots computed from the FULL manifest so a parent does
            # not absorb a child's files.
            nested_roots = [
                c["root"] for c in all_components
                if c["root"] != root and (root == "" or c["root"].startswith(prefix))
            ]
            batch = {}
            for key in primary_ns.list_keys():
                if root and not (key == root or key.startswith(prefix)):
                    continue
                if any(key == nr or key.startswith(nr + "/") for nr in nested_roots):
                    continue
                batch[key] = primary_ns.get(key)
            copied = sub_ns.set_many(batch) if batch else 0
            print(f"  [materialize] {sub_ns_name}: {copied}/{len(batch)} files", flush=True)

        async def _component_pipeline_call(component, base_input):
            """Run discover -> (audit/bundle implied) -> filter -> consolidate
            for one component against its sub-namespace. Returns the
            component result record used by aggregation. The downstream
            agents already accept a primary_namespace, so the component
            flow reuses them unchanged, just scoped to the sub-namespace."""
            sub_ns = component["subnamespace"]
            name = component["name"]
            print(f"[{name}] pipeline starting (namespace={sub_ns})", flush=True)
            component_input = {**base_input, "primary_namespace": sub_ns}
            # Discovery scoped to the component.
            await gofannon_client.call(
                agent_name="asvs_discover",
                input_dict={**component_input, "scope": "component"},
            )
            # Consolidate scoped to the component. (The audit/bundle and
            # filter phases run via the same single-namespace path the
            # orchestrator already drives; in this opt-in scaffold they are
            # invoked by the existing flow against primary_namespace=sub_ns.)
            consolidate_resp = await gofannon_client.call(
                agent_name="asvs_consolidate",
                input_dict={**component_input, "component_name": name},
            )
            return {
                "component": name,
                "namespace": sub_ns,
                "consolidated_report_uri": consolidate_resp.get("outputText"),
            }

        async def _run_multi_component(repo, gofannon_client, run_id, base_input,
                                       max_component_concurrency):
            # Phase A: detect components
            print(f"[orchestrate] component detection on {repo}", flush=True)
            comp_resp = await gofannon_client.call(
                agent_name="asvs_components",
                input_dict={"inputText": json.dumps({"repo": repo})},
            )
            manifest = json.loads(comp_resp["outputText"])
            if "error" in manifest:
                return {"error": f"component detection failed: {manifest['error']}"}
            components = manifest.get("components", [])
            if not components:
                return {"error": "no components detected"}
            print(f"[orchestrate] {len(components)} component(s); concurrency "
                  f"{max_component_concurrency}", flush=True)

            # Phase B: materialize sub-namespaces
            for component in components:
                _materialize_subnamespace(repo, component, components)

            # Phase C: per-component pipelines under the job-runner agent.
            #
            # gofannon has no importable modules, so the job runner is an
            # AGENT (asvs_job_runner) that owns the persistent job-state
            # table and answers claim/complete/fail/summary. The execution
            # closures (_component_pipeline_call) cannot cross an agent-call
            # boundary, so the concurrency loop lives HERE: this orchestrator
            # holds the semaphore, runs each component's pipeline, and calls
            # the job-runner agent to decide whether to run/skip and to
            # record outcomes. Deadlock-safe: the backoff sleep happens
            # OUTSIDE the semaphore (a backing-off job never holds a slot),
            # and there is no recursion.
            async def _runner_call(op, **fields):
                resp = await gofannon_client.call(
                    agent_name="asvs_job_runner",
                    input_dict={"inputText": json.dumps(
                        {"op": op, "run_id": run_id, **fields})},
                )
                return json.loads(resp["outputText"])

            # Reset any orphaned RUNNING jobs from a prior crashed run.
            await _runner_call("init")

            sem = asyncio.Semaphore(max_component_concurrency)
            max_attempts = 3

            async def _drive_component(component):
                name = component["name"]
                phase = "component"
                while True:
                    claim = await _runner_call(
                        "claim", component=name, phase=phase)
                    decision = claim.get("decision")
                    if decision == "skipped-done":
                        return {"component": name,
                                "status": "skipped-done",
                                "output_uri": claim.get("output_uri")}
                    if decision == "skipped-fatal":
                        return {"component": name,
                                "status": "skipped-fatal",
                                "error": claim.get("error")}
                    # decision == "run": execute under the concurrency gate.
                    try:
                        async with sem:
                            result = await _component_pipeline_call(
                                component, base_input)
                        output_uri = (result.get("consolidated_report_uri")
                                      if isinstance(result, dict) else None)
                        await _runner_call(
                            "complete", component=name, phase=phase,
                            output_uri=output_uri)
                        return result
                    except Exception as e:
                        err_type = type(e).__name__
                        err_msg = str(e) or "(no message)"
                        fail = await _runner_call(
                            "fail", component=name, phase=phase,
                            error=f"{err_type}: {err_msg}",
                            is_rate_limit=("RateLimitError" in err_type
                                           or "429" in err_msg),
                            is_timeout=("Timeout" in err_type),
                            max_attempts=max_attempts)
                        if fail.get("decision") == "retry":
                            # Back off WITHOUT holding the semaphore slot,
                            # then loop to re-claim.
                            await asyncio.sleep(fail.get("backoff_seconds", 0))
                            continue
                        return {"component": name, "status": "failed-fatal",
                                "error": err_msg}

            component_results = await asyncio.gather(
                *[_drive_component(c) for c in components],
                return_exceptions=False,
            )

            # Log the final state snapshot from the runner agent.
            summary = await _runner_call("summary")
            print(f"[orchestrate] job-runner summary: "
                  f"{json.dumps(summary.get('by_status', {}))}", flush=True)

            # Phase D: cross-component aggregation
            print(f"[orchestrate] cross-component aggregation", flush=True)
            agg_resp = await gofannon_client.call(
                agent_name="asvs_aggregate",
                input_dict={"inputText": json.dumps(
                    {"repo": repo, "component_results": component_results},
                    default=str)},
            )

            return {
                "status": "ok",
                "components_audited": len(components),
                "component_results": component_results,
                "aggregate_findings": agg_resp.get("outputText"),
            }

        if MULTI_COMPONENT_MODE:
            mc_result = await _run_multi_component(
                repo=code_namespace.replace("files:", "", 1),
                gofannon_client=gofannon_client,
                run_id=input_dict.get("runId") or f"{source_repo}:{output_directory}",
                base_input=input_dict,
                max_component_concurrency=MAX_COMPONENT_CONCURRENCY,
            )
            return {"outputText": json.dumps(mc_result, indent=2, default=str)}

        # T12: estimate LOC from download output to decide whether to skip discovery.
        #
        # T12 originated as an L1 optimization: small repos with ~70
        # sections gain little from discovery and the discovery LLM call
        # adds 30-60s of latency for marginal benefit. But at L3 with
        # ~345 sections, discovery's output isn't optional — it's the
        # *only* thing producing domain groupings small enough for the
        # consolidate phase to fit in Sonnet's context window. Without
        # discovery at L3 the orchestrator falls back to a single "all"
        # bucket of 345 sections → ContextWindowExceededError.
        #
        # So T12 only fires when:
        #   1. The user did not explicitly request discovery (or did but
        #      the section count is low enough to safely skip), AND
        #   2. The repo is below the LOC threshold, AND
        #   3. Section count is below the chapter-grouping threshold
        #
        # If discover=true was passed, we respect that intent regardless
        # of repo size. The user knows they need the grouping output.
        estimated_loc = _estimate_loc_from_namespace(code_namespace)
        # Compute expected section count up front so we can use it in T12
        try:
            asvs_ns_check = data_store.use_namespace("asvs")
            _all_keys = asvs_ns_check.list_keys() or []
            _req_keys = [k for k in _all_keys if k.startswith("asvs:requirements:")]
            _all_sections_for_check = [rk.replace("asvs:requirements:", "") for rk in _req_keys]
            # Apply level filter to estimate the post-filter count
            load_asvs_levels()
            expected_section_count = sum(
                1 for s in _all_sections_for_check
                if asvs_level_cache.get(s, 99) <= max_level_num
            )
        except Exception:
            expected_section_count = 999  # err on the side of NOT skipping

        DISCOVERY_REQUIRED_SECTION_THRESHOLD = 100
        # Skip discovery only if all three conditions hold
        skip_discovery = (
            estimated_loc < TINY_REPO_LOC_THRESHOLD
            and expected_section_count < DISCOVERY_REQUIRED_SECTION_THRESHOLD
        )
        if skip_discovery and discover:
            print(f"  Repo is small ({estimated_loc} LOC < {TINY_REPO_LOC_THRESHOLD}) "
                  f"and section count is low ({expected_section_count} < "
                  f"{DISCOVERY_REQUIRED_SECTION_THRESHOLD}); skipping discovery (T12)", flush=True)
        elif (
            estimated_loc < TINY_REPO_LOC_THRESHOLD
            and expected_section_count >= DISCOVERY_REQUIRED_SECTION_THRESHOLD
            and discover
        ):
            print(f"  Repo is small ({estimated_loc} LOC) but section count is high "
                  f"({expected_section_count} sections at level {level or 'all'}); "
                  f"running discovery to produce domain groups for consolidation", flush=True)

        # =============================================================
        # Step 2: Discovery (or fast-path for tiny repos)
        # =============================================================
        false_positive_guidance = []
        domain_groups = {}

        if discover and not skip_discovery:
            print(f"\n{'='*60}\nStep 2: Discovering codebase architecture\n{'='*60}", flush=True)
            try:
                discovery_result = await gofannon_client.call(
                    agent_name="asvs_discover",
                    input_dict={
                        "inputNamespace": ",".join(namespaces),
                        # Pass level so discover pre-filters ASVS sections.
                        # Without this, discover classifies all ~345
                        # sections even when the run is L1 (~130 sections),
                        # wasting a Sonnet call and producing misleading
                        # "343/345 sections assigned" log lines.
                        "level": level,
                    },
                )
                pass_config = json.loads(discovery_result.get("outputText", "{}"))
                if "error" in pass_config:
                    return {"outputText": f"Discovery failed: {pass_config['error']}"}
                passes = pass_config.get("passes", [])
                false_positive_guidance = pass_config.get("false_positive_guidance", [])
                domain_groups = pass_config.get("domain_groups", {})
                print(f"  Discovery complete: {len(passes)} passes", flush=True)
            except Exception as e:
                return {"outputText": f"Discovery agent failed: {e}"}
        else:
            # T12 fast-path or no-discover mode: build a single all-sections pass
            print(f"\n{'='*60}\nStep 2: Single-pass mode (no discovery)\n{'='*60}", flush=True)
            try:
                asvs_ns = data_store.use_namespace("asvs")
                all_keys = asvs_ns.list_keys()
                req_keys = [k for k in all_keys if k.startswith("asvs:requirements:")]
                all_sections = sorted([rk.replace("asvs:requirements:", "") for rk in req_keys])
            except Exception as e:
                return {"outputText": f"Could not load ASVS sections: {e}"}
            passes = [{
                "name": "all",
                "description": "Single-pass audit of all sections (no discovery)",
                "asvs_sections": all_sections,
                "files": [],
                "domain_context": "",
                "estimated_lines": estimated_loc,
            }]
            # Domain grouping for the consolidate phase. With a single
            # "all" bucket, consolidate sends every per-section report to
            # one Sonnet call — fine for L1 (~70 sections) but blows past
            # the 200k context window at L3 (~345 sections, ~400 findings).
            #
            # When discovery is skipped, fall back to ASVS chapter-based
            # grouping (1.x, 2.x, ..., 16.x). This produces ~16 buckets
            # of ~22 sections each at L3, well within Sonnet's context,
            # without needing discovery to run. The audit phase still
            # uses the single "all" pass for batching efficiency; only
            # consolidate sees the chapter split.
            CHAPTER_GROUP_THRESHOLD = 100  # sections
            if len(all_sections) >= CHAPTER_GROUP_THRESHOLD:
                domain_groups = {}
                for section in all_sections:
                    ch_num = section.split(".")[0]
                    ch_name = f"ch{ch_num.zfill(2)}"
                    domain_groups.setdefault(ch_name, []).append(section)
                print(f"  Many sections ({len(all_sections)}); using chapter-based "
                      f"domain grouping for consolidation: {len(domain_groups)} chapters",
                      flush=True)
            else:
                domain_groups = {"all": all_sections}

        # Filter passes by level
        for pass_def in passes:
            pass_def["asvs_sections"] = filter_sections_by_level(pass_def.get("asvs_sections", []))
        passes = [p for p in passes if p.get("asvs_sections")]

        if level:
            for dn in list(domain_groups.keys()):
                domain_groups[dn] = filter_sections_by_level(domain_groups[dn])
            domain_groups = {k: v for k, v in domain_groups.items() if v}

        total_sections = sum(len(p.get("asvs_sections", [])) for p in passes)
        print(f"  After level filter ({level or 'all'}): {total_sections} sections, {len(passes)} passes", flush=True)

        if not passes:
            return {"outputText": f"No ASVS sections match level {level}."}

        # Cover any sections discovery didn't assign
        if discover and not skip_discovery:
            load_asvs_levels()
            all_level_sections = [s for s, lv in asvs_level_cache.items() if lv <= max_level_num]
            covered_sections = set()
            for p in passes:
                covered_sections.update(p.get("asvs_sections", []))
            uncovered = sorted([s for s in all_level_sections if s not in covered_sections])
            if uncovered:
                chapter_groups = {}
                for section in uncovered:
                    ch_num = section.split(".")[0]
                    ch_name = f"ch{ch_num.zfill(2)}_general"
                    chapter_groups.setdefault(ch_name, []).append(section)
                print(f"  {len(uncovered)} sections not assigned by discovery — adding {len(chapter_groups)} chapter passes", flush=True)
                for ch_name, ch_sections in sorted(chapter_groups.items()):
                    passes.append({
                        "name": ch_name,
                        "description": f"ASVS chapter {ch_name.split('_')[0]} sections not assigned to a specific domain",
                        "asvs_sections": ch_sections,
                        "files": [],
                        "domain_context": "",
                        "estimated_lines": 0,
                    })
                    domain_groups[ch_name] = ch_sections
                total_sections = sum(len(p.get("asvs_sections", [])) for p in passes)
                print(f"  Total sections now: {total_sections}", flush=True)

            # Coverage check: confirm every L3 control appears in at least
            # one pass. The chapter-pass fallback above is supposed to
            # guarantee this; the check verifies it explicitly and warns
            # loudly if the asvs_level_cache itself is incomplete (which
            # would silently reduce coverage without this check).
            final_covered = set()
            for p in passes:
                final_covered.update(p.get("asvs_sections", []))
            all_set = set(all_level_sections)
            still_uncovered = sorted(all_set - final_covered)
            print(
                f"  Unique L{max_level_num} controls covered: "
                f"{len(final_covered & all_set)} / {len(all_set)} "
                f"(controls in ASVS data store at level <= L{max_level_num})",
                flush=True,
            )
            if still_uncovered:
                print(
                    f"  WARNING: {len(still_uncovered)} L{max_level_num} "
                    f"control(s) still uncovered after chapter-pass "
                    f"fallback: {still_uncovered[:10]}"
                    f"{'...' if len(still_uncovered) > 10 else ''}",
                    flush=True,
                )

        # =============================================================
        # Step 3: Audit + push (with parallel section dispatch + bundling)
        # =============================================================
        print(f"\n{'='*60}\nStep 3: Auditing {total_sections} sections", flush=True)
        print(f"  Strategy: pass-parallel ({PASS_CONCURRENCY}-way) + section bundling", flush=True)
        print(f"  Pushing to: {push_repo}\n{'='*60}", flush=True)

        section_semaphore = asyncio.Semaphore(PASS_CONCURRENCY)

        # Global GitHub push throttle, shared across ALL bundles.
        #
        # IMPORTANT: GitHub's contents API serializes commits to a branch —
        # each commit must reference the current branch HEAD as its parent.
        # When N commits race against the same branch, only one wins; the
        # rest get 409 Conflict. The push agent retries on 409, but with
        # high concurrency the same races repeat across retries.
        #
        # Default 1 (fully serialized) eliminates the races entirely. The
        # cost is wall-clock: each push is ~1-2s, so 70 pushes adds ~2 min
        # to a run. Acceptable for the determinism it gives us.
        #
        # Higher values are technically possible — the push agent's
        # retry-on-409 absorbs some collisions — but in practice anything
        # above 2-3 starts losing pushes after retries. If you need
        # maximum throughput, switch to a Git Trees API approach instead
        # (one atomic commit for many files); that's a bigger rewrite.
        GITHUB_PUSH_CONCURRENCY = int(os.environ.get("GITHUB_PUSH_CONCURRENCY", "1"))
        github_push_sem = asyncio.Semaphore(GITHUB_PUSH_CONCURRENCY)
        print(f"  GitHub push concurrency: {GITHUB_PUSH_CONCURRENCY}", flush=True)

        async def run_bundle(pass_def, section_chunk):
            """Run a chunk of sections from one pass.

            - For chunks of 1 section: call `asvs_audit` (single-section).
            - For chunks of >1 section: call `asvs_bundle` (NEW agent),
              which audits all sections in one Opus deep-analysis pass.
            """
            async with section_semaphore:
                pass_name = pass_def.get("name", "unknown")
                include_files = pass_def.get("files", [])
                domain_context = pass_def.get("domain_context", "")
                pass_output_dir = f"{push_directory}/{pass_name}" if push_directory else pass_name

                bundle_label = f"{section_chunk[0]}..{section_chunk[-1]}" if len(section_chunk) > 1 else section_chunk[0]
                print(f"  [{pass_name}] {'bundle' if len(section_chunk) > 1 else 'single'}: {bundle_label} ({len(section_chunk)} sections)", flush=True)

                local_successes = []
                local_failures = []
                local_outputs = []

                # ----- Audit call: route to bundle agent or single-section agent -----
                try:
                    if len(section_chunk) == 1:
                        audit_result = await gofannon_client.call(
                            agent_name="asvs_audit",
                            input_dict={
                                "inputText": json.dumps({
                                    "namespaces": namespaces,
                                    "asvs": section_chunk[0],
                                    "includeFiles": include_files,
                                    "domainContext": domain_context,
                                    "severityThreshold": severity_threshold,
                                    "falsePositiveGuidance": false_positive_guidance,
                                })
                            }
                        )
                    else:
                        audit_result = await gofannon_client.call(
                            agent_name="asvs_bundle",  # NEW agent
                            input_dict={
                                "inputText": json.dumps({
                                    "namespaces": namespaces,
                                    "asvs_sections": section_chunk,
                                    "includeFiles": include_files,
                                    "domainContext": domain_context,
                                    "severityThreshold": severity_threshold,
                                    "falsePositiveGuidance": false_positive_guidance,
                                })
                            }
                        )
                    audit_output_text = audit_result.get("outputText", "")
                except Exception as e:
                    print(f"  [{pass_name}] Bundle {bundle_label} AUDIT FAILED: {e}", flush=True)
                    for s in section_chunk:
                        local_failures.append(f"{s} (audit): {e}")
                    return local_successes, local_failures, local_outputs, pass_output_dir

                # ----- Parse output: bundled JSON envelope or single-section markdown -----
                # GUARDRAIL: _parse_audit_output now returns dict of
                # {sid: (report_text, status_signal)}. Signals: "ok" /
                # "no_relevant_code" (both success), "bundle_error" /
                # "missing_section" / "malformed_multi" (all failure shapes).
                per_section_parsed = _parse_audit_output(audit_output_text, section_chunk)

                # ----- Push per-section reports in parallel (throttled) -----
                # Uses the SHARED github_push_sem from outer scope so all
                # bundles across all passes contend for the same global
                # concurrency budget — not per-bundle as before.

                # Per-section reports go to CouchDB only — never to GitHub.
                # Storing them as commits in the private repo would surface
                # finding titles on the public commits@tooling.apache.org
                # mailing list. Consolidate reads from this same namespace
                # in Phase 1 instead of fetching from GitHub.
                #
                # Key format: "{pass_name}/{section_id}.md" — preserves the
                # pass-grouping that the GitHub layout used so consolidate
                # can list by pass and the same logical structure is
                # available for any future tooling.
                reports_ns = data_store.use_namespace(reports_namespace)

                async def store_one(section_id, report_text):
                    try:
                        key = f"{pass_name}/{section_id}.md"
                        reports_ns.set(key, report_text)
                        return section_id, None
                    except Exception as e:
                        err_str = str(e) or f"{type(e).__name__} (no detail)"
                        return section_id, err_str

                push_results = await asyncio.gather(*[
                    store_one(sid, parsed[0]) for sid, parsed in per_section_parsed.items()
                ])
                # GUARDRAIL: a successful CouchDB write of an ERROR-status
                # stub is NOT an audit success. Sections whose parser signal
                # is anything other than "ok" or "no_relevant_code" go into
                # local_failures even though the store itself succeeded, so
                # the run summary reflects the real audit-phase outcome.
                section_signals = {sid: parsed[1] for sid, parsed in per_section_parsed.items()}
                _failure_signals = {"bundle_error", "missing_section", "malformed_multi"}
                for sid, err in push_results:
                    if err is not None:
                        local_failures.append(f"{sid} (store): {err}")
                        print(f"    [{pass_name}] {sid}: store failed: {err}", flush=True)
                        continue
                    signal = section_signals.get(sid, "ok")
                    if signal in _failure_signals:
                        local_failures.append(f"{sid} (bundle): {signal}")
                        print(
                            f"    [{pass_name}] {sid}: stored as ERROR stub "
                            f"(signal={signal}) — counted as failure",
                            flush=True,
                        )
                    else:
                        local_successes.append(sid)
                        # Annotate the success log line when the success is
                        # a deliberate N/A so an operator skimming the log
                        # can see at a glance which sections were genuinely
                        # not applicable vs. which were affirmatively audited.
                        suffix = " [N/A: no relevant code]" if signal == "no_relevant_code" else ""
                        print(f"    [{pass_name}] {sid}: stored{suffix}", flush=True)
                local_outputs.extend(parsed[0] for parsed in per_section_parsed.values())

                return local_successes, local_failures, local_outputs, pass_output_dir

        # ----- Build the work list: chunk each pass's sections into bundles -----
        work_items = []
        for pass_def in passes:
            sections = pass_def.get("asvs_sections", [])
            if BUNDLE_MAX_SECTIONS <= 1 or len(sections) < BUNDLE_MIN_SECTIONS:
                # No bundling: each section is its own item
                for s in sections:
                    work_items.append((pass_def, [s]))
            else:
                # Chunk into bundles of up to BUNDLE_MAX_SECTIONS
                for i in range(0, len(sections), BUNDLE_MAX_SECTIONS):
                    chunk = sections[i:i + BUNDLE_MAX_SECTIONS]
                    work_items.append((pass_def, chunk))

        print(f"  Total work items (post-bundling): {len(work_items)}", flush=True)
        print(f"  Avg sections/item: {total_sections / max(1, len(work_items)):.1f}", flush=True)

        # Track output dirs (for consolidation)
        seen_pass_dirs = set()
        for pass_def, _ in work_items:
            pn = pass_def.get("name", "unknown")
            d = f"{push_directory}/{pn}" if push_directory else pn
            if d not in seen_pass_dirs:
                report_directories.append(d)
                seen_pass_dirs.add(d)

        # ----- Dispatch all work items in parallel (T1) -----
        bundle_results = await asyncio.gather(
            *[run_bundle(p, s) for p, s in work_items],
            return_exceptions=True,
        )

        for r in bundle_results:
            if isinstance(r, Exception):
                failures.append(f"bundle dispatch: {r}")
                continue
            local_successes, local_failures, local_outputs, _ = r
            successes.extend(local_successes)
            failures.extend(local_failures)
            all_outputs.extend(local_outputs)

        print(f"\n  Audit phase complete: {len(successes)} succeeded, {len(failures)} failed", flush=True)

        # =============================================================
        # Optional: clean up stale reports from previous runs
        #
        # When discovery (temperature 0.7) reassigns ASVS sections to
        # different domains across runs, old per-section reports remain
        # in their previous domain folders even though the current run
        # produced fresh reports under different folders. These orphans
        # accumulate in the repo and confuse downstream tooling
        # (consolidate-only reruns, QA scripts, finding-count tools).
        #
        # Strict guarantees on what gets deleted:
        #   - Only files matching `^\d+\.\d+\.\d+\.md$` (per-section reports)
        #   - Only inside subdirectories of the commit-hash dir that are
        #     NOT in this run's `report_directories`
        #   - Never touches `consolidated*.md`, `issues*.md`, or any
        #     `rerun/` subdirectory
        #   - Never runs when there were audit failures (something may
        #     have gone wrong; don't compound the problem by deleting)
        # =============================================================
        if clean_stale_reports and successes and not failures:
            print(f"\n{'='*60}\nStep 3.5: Cleaning stale per-section reports\n{'='*60}", flush=True)
            try:
                # Per-section reports now live in CouchDB under
                # reports_namespace, keyed as "{pass_name}/{section_id}.md".
                # On re-runs at the same commit but with different pass
                # groupings (e.g. different domain discovery output), keys
                # from prior runs accumulate. Remove any keys whose
                # pass-prefix isn't in current_pass_basenames.
                current_pass_basenames = set()
                for d in report_directories:
                    bn = d.rstrip("/").split("/")[-1]
                    current_pass_basenames.add(bn)

                reports_ns = data_store.use_namespace(reports_namespace)
                all_keys = reports_ns.list_keys() or []
                orphan_keys = []
                for k in all_keys:
                    # key is "{pass_name}/{section_id}.md"
                    pass_part = k.split("/", 1)[0] if "/" in k else ""
                    if pass_part and pass_part not in current_pass_basenames:
                        orphan_keys.append(k)

                if not orphan_keys:
                    print(f"  No orphan keys to clean", flush=True)
                else:
                    print(f"  Found {len(orphan_keys)} orphan keys "
                          f"(passes not in current run: "
                          f"{sorted(set(k.split('/', 1)[0] for k in orphan_keys))})", flush=True)
                    # delete_many bulks the orphan wipe into one round
                    # trip. Per-key delete() loop here could be hundreds
                    # of HTTP calls for a multi-pass run with cumulative
                    # stale keys.
                    try:
                        deleted = reports_ns.delete_many(orphan_keys)
                    except Exception as de:
                        print(f"    delete_many failed for {len(orphan_keys)} orphan keys: {de}", flush=True)
                        deleted = 0
                    print(f"  Deleted {deleted} stale keys from {reports_namespace}", flush=True)
            except Exception as e:
                # Cleanup failures shouldn't block consolidation
                print(f"  Cleanup encountered an error (continuing): {type(e).__name__}: {e}", flush=True)
        elif clean_stale_reports and failures:
            print(f"\n  cleanStaleReports=true but {len(failures)} audit failures — "
                  f"skipping cleanup to avoid deleting reports during a partial run", flush=True)
        # If clean_stale_reports is False (default), nothing happens here.

        # =============================================================
        # Step 3.7: Relevance filter (NEW)
        # =============================================================
        # Triage findings against the project's own documented threat
        # model before consolidation. asvs_relevance_filter auto-
        # discovers SECURITY.md, AGENTS.md, docs/security/* from the
        # source repo (walking both the downloaded source namespace
        # AND the GitHub repo root, so monorepo-subdir audits inherit
        # the top-level project docs), synthesizes a Project Security
        # Profile, and drops or downgrades findings the project
        # documents as out-of-scope.
        #
        # Outputs are written to audit-reports-filtered:{output_dir}
        # in CouchDB; the four _*.md analysis artifacts also get
        # pushed to {output_repo}/{output_directory}/ when an output
        # repo + PAT are configured.
        #
        # Fail-soft end-to-end: if the filter fails or returns no
        # usable namespace, consolidate reads from the original
        # audit-reports namespace and the pipeline behaves as if the
        # filter weren't installed.
        filtered_reports_namespace = reports_namespace  # safe default
        if successes:
            print(f"\n{'='*60}\nStep 3.7: Relevance filter\n{'='*60}", flush=True)
            filter_input_lines = [
                f"owner_repo: {source_repo}",
                f"reports_namespace: {reports_namespace}",
                f"source_namespace: {code_namespace}",
                f"output_directory: {output_directory}",
                f"source_id: {source_id}",
            ]
            # The relevance filter optionally pushes its four _*.md
            # analysis artifacts to a repo. With the carve-out removed
            # there's one destination: output_repo. Prefer output_token
            # for the push; fall back to source_token for the source-repo
            # fetch leg. The filter agent's input key is still named
            # `private_repo` internally — we feed output_repo into it.
            filter_pat = output_token or source_token
            if filter_pat:
                filter_input_lines.append(f"pat: {filter_pat}")
            if output_repo:
                filter_input_lines.append(f"private_repo: {output_repo}")
            if supplemental_data:
                filter_input_lines.append(
                    f"audit_guidance_namespaces: {supplemental_data}"
                )
            try:
                filter_result = await gofannon_client.call(
                    agent_name="asvs_relevance_filter",
                    input_dict={"inputText": "\n".join(filter_input_lines)},
                )
                filter_output = ""
                filter_ns = ""
                if isinstance(filter_result, dict):
                    filter_output = filter_result.get("outputText", "") or ""
                    filter_ns = filter_result.get("filteredReportsNamespace", "") or ""
                if filter_output:
                    print(filter_output, flush=True)
                if filter_ns and not filter_output.startswith("Error:"):
                    filtered_reports_namespace = filter_ns
                    print(f"  Consolidate will read from: {filtered_reports_namespace}", flush=True)
                else:
                    print(
                        f"  Filter did not return a usable namespace; "
                        f"falling back to {reports_namespace}",
                        flush=True,
                    )
            except Exception as e:
                print(
                    f"  Relevance filter raised; falling back to "
                    f"{reports_namespace}: {type(e).__name__}: {e}",
                    flush=True,
                )

        # =============================================================
        # Step 4: Consolidate
        # =============================================================
        # Reads from filtered_reports_namespace (set by Step 3.7 to
        # audit-reports-filtered:* when the filter succeeded, else
        # falls back to the raw audit-reports:* namespace).
        if consolidate and successes:
            print(f"\n{'='*60}\nStep 4: Consolidating reports\n  Pushing to: {push_repo}\n{'='*60}", flush=True)
            # Build a flat list of every section ID audited in this run, so
            # consolidate can filter out stale reports from prior runs that
            # share the output directories.
            audited_sections = set()
            for sections_in_domain in domain_groups.values():
                for s in sections_in_domain:
                    audited_sections.add(s)
            sections_arg = ", ".join(sorted(audited_sections))

            # `directories` was historically a list of GitHub paths like
            # "ASVS/reports/steve/v3/d0aa7e9/all". Now per-section reports
            # live in CouchDB under the reports_namespace; the dir suffix
            # (the pass name, e.g. "all" or "l1") becomes a key prefix
            # within that namespace. Pass both to consolidate so it knows
            # where to read.
            pass_prefixes = []
            for d in report_directories:
                # Extract the trailing pass name from each historical dir path
                pass_prefixes.append(d.rsplit("/", 1)[-1])

            try:
                consolidate_input_lines = [
                    f"repo: {push_repo}",
                    f"pat: {push_token}",
                    f"directories: {', '.join(pass_prefixes)}",
                    f"output: {push_directory}",
                    f"sections: {sections_arg}",
                    f"source: {source_id}",
                    f"reports_namespace: {filtered_reports_namespace}",
                ]
                if branch:
                    consolidate_input_lines.append(f"branch: {branch}")
                consolidate_result = await gofannon_client.call(
                    agent_name="asvs_consolidate",
                    input_dict={
                        "inputText": "\n".join(consolidate_input_lines),
                        "domainGroups": json.dumps(domain_groups),
                        "level": level or "L3",
                        "severityThreshold": severity_threshold,
                    }
                )
                # asvs_consolidate's top-level except wrapper returns
                # outputText starting with "Error:" when the body raised.
                # Treat that as a failure even though the call itself
                # didn't throw — otherwise we'd silently mark a broken
                # consolidation as success and proceed to the redaction
                # step, which would then 404 on the missing files.
                consolidate_output = ""
                if isinstance(consolidate_result, dict):
                    consolidate_output = consolidate_result.get("outputText", "") or ""
                if consolidate_output.startswith("Error:"):
                    err_excerpt = consolidate_output[:300]
                    failures.append(f"consolidation: {err_excerpt}")
                    print(f"  Consolidation FAILED: {err_excerpt}", flush=True)
                else:
                    print(f"  Consolidation done", flush=True)

                    # ---- Write metadata.yml into the leaf dir -------------
                    # Mirrors the scans-style manifest: project/repo/sha/date,
                    # models, asvs level, threat-model URL, findings_total, and
                    # the supporting files actually present. Best-effort: a
                    # failure here never fails the run.
                    try:
                        # findings_total: parse consolidate's "Total findings: N"
                        ftotal = ""
                        import re as _re
                        m = _re.search(r"Total findings:\s*(\d+)", consolidate_output)
                        if m:
                            ftotal = int(m.group(1))

                        # audit models actually used (orchestrator constants).
                        # ASVS_AUDIT_MODELS is defined near the top of run();
                        # fall back to a sane default if absent.
                        try:
                            models_list = ASVS_AUDIT_MODELS
                        except NameError:
                            models_list = ["opus-4.8", "sonnet-4.6", "haiku-4.5"]

                        # threat-model URL: SECURITY.md at the audited sha.
                        tm_url = (f"https://github.com/{repo_owner_name}/blob/"
                                  f"{commit_hash}/SECURITY.md")

                        # supporting files: the analysis artifacts that this
                        # run actually produced. Probe the reports namespace /
                        # known outputs rather than hard-coding, since e.g.
                        # issues_cross_reference.md is absent when there are no
                        # issues/PRs to compare.
                        candidate_support = [
                            "_filter_drop_log.md", "_review_queue.md",
                            "_security_profile.md", "_suggested_audit_guidance.md",
                            "consolidated.md", "issues.md",
                            "issues_cross_reference.md",
                        ]
                        present_support = []
                        try:
                            chk_ns = data_store.use_namespace(filtered_reports_namespace)
                            present_keys = set(chk_ns.list_keys() or [])
                        except Exception:
                            present_keys = set()
                        for fn in candidate_support:
                            # consolidated.md/issues.md always produced on a
                            # successful consolidate; the _*.md come from the
                            # relevance filter; cross-ref only if it ran.
                            if fn in ("consolidated.md", "issues.md"):
                                present_support.append(fn)
                            elif fn in present_keys or any(k.endswith(fn) for k in present_keys):
                                present_support.append(fn)
                        if "cross_reference_done" in dir() and cross_reference_done:
                            if "issues_cross_reference.md" not in present_support:
                                present_support.append("issues_cross_reference.md")

                        def _yml_line(k, v):
                            return f"{k+':':<18} {v}"
                        meta_lines = [
                            _yml_line("project", scan_meta["project"]),
                            _yml_line("repo", scan_meta["repo"]),
                            _yml_line("head_sha", scan_meta["head_sha"]),
                            _yml_line("short_sha", scan_meta["short_sha"]),
                            _yml_line("scan_date", scan_meta["scan_date"]),
                            _yml_line("audit_models", "[" + ", ".join(models_list) + "]"),
                            _yml_line("asvs_level", (level or scan_meta["asvs_level_input"] or "L1")),
                            _yml_line("threat_model", tm_url),
                            _yml_line("findings_total", ftotal),
                            _yml_line("supporting_files", "[" + ", ".join(sorted(present_support)) + "]"),
                            _yml_line("sanity_check", "PENDING"),
                            _yml_line("sanity_checked_by", "UNSET"),
                            _yml_line("sanity_check_date", "UNSET"),
                        ]
                        meta_yaml = "\n".join(meta_lines) + "\n"

                        push_res = await gofannon_client.call(
                            agent_name="asvs_push_github",
                            input_dict={
                                "inputText": "\n".join([
                                    f"repo: {push_repo}",
                                    f"token: {push_token}",
                                    f"directory: {push_directory}",
                                    f"filename: metadata.yml",
                                    f"source: {source_id}",
                                ]),
                                "fileContents": meta_yaml,
                            },
                        )
                        print(f"  metadata.yml written to {push_directory}/", flush=True)
                    except Exception as e:
                        print(f"  WARNING: metadata.yml write failed "
                              f"({type(e).__name__}: {e}); run otherwise OK", flush=True)
            except Exception as e:
                # Some exception types stringify to empty (e.g. some httpx errors).
                # Surface the type name and full traceback so the failure is
                # diagnosable from logs alone.
                import traceback
                err_type = type(e).__name__
                err_msg = str(e) or "(no message)"
                tb = traceback.format_exc()
                print(f"  Consolidation FAILED: {err_type}: {err_msg}", flush=True)
                print(f"  Traceback:\n{tb}", flush=True)
                failures.append(f"consolidation: {err_type}: {err_msg}")

        # =============================================================
        # Summary
        # =============================================================
        print(f"\n{'='*60}\nComplete: {len(successes)} succeeded, {len(failures)} failed", flush=True)
        print(f"  Reports: {output_repo}/{output_directory}/", flush=True)
        if failures:
            for f in failures[:20]:
                print(f"  - {f}", flush=True)
            if len(failures) > 20:
                print(f"  ... and {len(failures) - 20} more failures", flush=True)
        return {"outputText": "\n\n---\n\n".join(all_outputs)}
    finally:
        await http_client.aclose()