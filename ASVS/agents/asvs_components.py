# asvs_components
#
# Walks the file inventory of a downloaded repo and emits a manifest of
# detected components — top-level units of independent code (Python
# packages, npm packages, Go modules, etc.).
#
# Generic, language-agnostic detection based on ecosystem manifest files.
# Does not encode any project-specific knowledge.
#
# Used by the orchestrator in MULTI_COMPONENT_MODE to drive per-component
# audit pipelines instead of one monolithic pass over a giant namespace.
#
# Input (input_dict, top-level fields):
#   repo (required): owner/repo (or owner/repo/subdir), matches the
#                    namespace used by asvs_download_repo.
#
# Output (JSON in outputText):
#   {
#     "components": [
#       {
#         "name": str,           # last path segment (deduped if collision)
#         "root": str,           # path relative to repo root ("" = repo root)
#         "type": str,           # primary ecosystem (python|npm|go|rust|...)
#         "markers": [str],      # marker files that triggered detection
#         "file_count": int,
#         "byte_count": int,
#         "has_threat_model": bool,    # AGENTS.md or SECURITY.md present
#         "subnamespace": str    # files:owner/repo/<root>
#       },
#       ...
#     ],
#     "summary": {
#       "total_files": int,
#       "total_bytes": int,
#       "components_detected": int,
#       "unassigned_files": int   # files outside any detected component
#     }
#   }
#
# No LLM call. Pure I/O + heuristic over the file inventory.


async def run(input_dict, tools):
    # Imports inside run() per gofannon convention.
    import json
    import os

    try:
        repo = (input_dict.get("repo") or "").strip().strip("/")
        if not repo:
            return {"outputText": json.dumps({"error": "repo is required (e.g. 'apache/airflow')"})}

        # Validate the namespace exists. The orchestrator should have already
        # called asvs_download_repo, which writes to files:{repo}.
        primary_ns = f"files:{repo}"
        try:
            ns = data_store.use_namespace(primary_ns)
            all_keys = ns.list_keys()
        except Exception as e:
            return {"outputText": json.dumps({
                "error": f"could not read namespace {primary_ns}: {type(e).__name__}: {e}",
            })}

        if not all_keys:
            return {"outputText": json.dumps({
                "error": f"namespace {primary_ns} is empty; run asvs_download_repo first",
            })}

        # ----- Marker definitions -----
        # Each marker maps a filename to an ecosystem tag. Components inherit
        # the tag of their primary (first-matched) marker. Order matters for
        # ambiguous cases — e.g. a directory with both package.json and
        # pyproject.toml is tagged python first (because pyproject is more
        # specific than the often-present package.json for tooling).
        MARKERS = [
            # (filename, ecosystem_tag)
            ("pyproject.toml", "python"),
            ("setup.py", "python"),
            ("setup.cfg", "python"),
            ("Cargo.toml", "rust"),
            ("go.mod", "go"),
            ("pom.xml", "maven"),
            ("build.gradle", "gradle"),
            ("build.gradle.kts", "gradle"),
            ("Gemfile", "ruby"),
            ("composer.json", "php"),
            ("mix.exs", "elixir"),
            ("package.json", "npm"),
            ("CMakeLists.txt", "cmake"),
        ]
        MARKER_NAMES = set(m[0] for m in MARKERS)

        # Threat-model markers — presence indicates the component has its own
        # documented security posture and should likely get its own
        # audit_guidance namespace populated.
        THREAT_MODEL_MARKERS = {"AGENTS.md", "SECURITY.md", "THREAT_MODEL.md"}

        # ----- Walk the file inventory -----
        # For each file, record its directory and basename. We'll then find
        # Load the size index written by asvs_download_repo at ingest time
        # (files_meta:{repo} -> "sizes" -> {path: char_len}). This avoids
        # calling ns.get(key) on EVERY file just to measure it — that pulls
        # full document bodies from CouchDB and reintroduces the monolithic
        # I/O pattern multi-component mode exists to avoid. byte_count is
        # advisory (display + ordering only), so if the index is absent we
        # fall back to 0 rather than paying N body reads.
        sizes = {}
        try:
            meta_ns = data_store.use_namespace(f"files_meta:{repo}")
            raw = meta_ns.get("sizes")
            if raw:
                sizes = json.loads(raw)
        except Exception as _idx_e:
            print(
                f"[components] no size index ({type(_idx_e).__name__}); "
                f"byte_count will be 0",
                flush=True,
            )
            sizes = {}

        # directories that contain marker files.
        files_by_dir = {}   # dir_path -> list of (basename, size)
        for key in all_keys:
            size = sizes.get(key, 0)
            dir_path, basename = os.path.split(key)
            files_by_dir.setdefault(dir_path, []).append((basename, size))

        # ----- Identify component roots -----
        # A directory is a candidate component root if it contains at least
        # one marker file. Walk all dirs and check.
        candidate_roots = {}   # dir_path -> {markers: [filenames], ecosystem: tag}
        for dir_path, entries in files_by_dir.items():
            present_basenames = {b for b, _ in entries}
            matched = []
            ecosystem = None
            for marker_name, marker_tag in MARKERS:
                if marker_name in present_basenames:
                    matched.append(marker_name)
                    if ecosystem is None:
                        ecosystem = marker_tag
            if matched:
                candidate_roots[dir_path] = {
                    "markers": matched,
                    "ecosystem": ecosystem,
                }

        # ----- De-nest -----
        # A candidate root is a real component root only if it is not nested
        # inside another candidate root. Sort by depth (shallowest first),
        # then accept roots that aren't prefixes of an already-accepted root.
        sorted_candidates = sorted(candidate_roots.keys(), key=lambda d: (d.count("/"), d))
        accepted_roots = []
        for root in sorted_candidates:
            # If root is a strict subdir of any already-accepted root, skip it.
            is_nested = False
            for accepted in accepted_roots:
                if accepted == "":
                    # Repo-root is the parent of everything; only nest under
                    # it if we have other accepted roots already (i.e., we
                    # don't auto-nest the first one).
                    continue
                if root == accepted:
                    is_nested = True
                    break
                if root.startswith(accepted + "/"):
                    is_nested = True
                    break
            if not is_nested:
                accepted_roots.append(root)

        # ----- Special case: single-component repo -----
        # If detection finds nothing, OR finds only the repo-root, OR all
        # detected roots are under one common parent that itself has no
        # marker, fall back to treating the entire repo as one component.
        # This preserves the existing single-namespace behavior for repos
        # that don't have a clear multi-component structure.
        if not accepted_roots:
            accepted_roots = [""]
            candidate_roots[""] = {
                "markers": [],
                "ecosystem": "unknown",
            }

        # ----- Build component records -----
        components = []
        used_names = set()

        for root in accepted_roots:
            meta = candidate_roots.get(root, {"markers": [], "ecosystem": "unknown"})

            # Tally files and bytes under this root (excluding nested
            # components — they get their own records).
            file_count = 0
            byte_count = 0
            has_threat_model = False
            nested_roots = [r for r in accepted_roots if r != root and (root == "" or r.startswith(root + "/"))]

            for dir_path, entries in files_by_dir.items():
                # In-scope if dir_path is the root or a descendant
                if root == "":
                    in_scope = True
                else:
                    in_scope = (dir_path == root) or dir_path.startswith(root + "/")
                if not in_scope:
                    continue
                # Excluded if dir_path is inside a nested component
                excluded = any(
                    dir_path == nr or dir_path.startswith(nr + "/")
                    for nr in nested_roots
                )
                if excluded:
                    continue
                for basename, size in entries:
                    file_count += 1
                    byte_count += size
                    if basename in THREAT_MODEL_MARKERS and dir_path == root:
                        has_threat_model = True

            # Component name: last path segment of root, or "root" for
            # the whole repo. Dedupe if collisions arise across components
            # (rare but possible in deep monorepos).
            if root == "":
                base_name = "root"
            else:
                base_name = root.rstrip("/").split("/")[-1]
            name = base_name
            suffix = 2
            while name in used_names:
                name = f"{base_name}-{suffix}"
                suffix += 1
            used_names.add(name)

            subnamespace = f"files:{repo}/{root}" if root else f"files:{repo}"

            components.append({
                "name": name,
                "root": root,
                "type": meta["ecosystem"],
                "markers": meta["markers"],
                "file_count": file_count,
                "byte_count": byte_count,
                "has_threat_model": has_threat_model,
                "subnamespace": subnamespace,
            })

        # ----- Sort by file count (small to large) -----
        # Smaller components first gives faster feedback in the run and
        # cheaper aborts if something goes wrong early.
        components.sort(key=lambda c: c["file_count"])

        # ----- Summary -----
        total_files = sum(len(entries) for entries in files_by_dir.values())
        total_bytes = sum(sum(s for _, s in entries) for entries in files_by_dir.values())
        accounted_files = sum(c["file_count"] for c in components)
        unassigned_files = total_files - accounted_files

        result = {
            "components": components,
            "summary": {
                "total_files": total_files,
                "total_bytes": total_bytes,
                "components_detected": len(components),
                "unassigned_files": unassigned_files,
            },
        }

        # Diagnostic print so operators see the manifest at runtime
        print(
            f"[components] {len(components)} component(s) detected in {repo}:",
            flush=True,
        )
        for c in components:
            tm = " [threat-model]" if c["has_threat_model"] else ""
            print(
                f"  - {c['name']}: {c['type']}, "
                f"{c['file_count']} files, "
                f"{c['byte_count']:,} bytes, "
                f"root={c['root'] or '<repo>'}{tm}",
                flush=True,
            )
        if unassigned_files > 0:
            print(
                f"  ({unassigned_files} files outside any detected component "
                f"-- these are not audited)",
                flush=True,
            )

        return {"outputText": json.dumps(result, indent=2, sort_keys=True)}

    except Exception as e:
        # Catch-all inside run() per gofannon convention. See
        # asvs_guidance_upload.py for the same pattern.
        import json as _json
        err_type = type(e).__name__
        err_msg = str(e) or "(no message)"
        return {"outputText": _json.dumps({"error": f"{err_type}: {err_msg}"})}
