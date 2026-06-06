# asvs_download_repo
#
# Downloads a GitHub repo (or subdirectory) into the data store under
# namespace `files:{owner}/{repo}` (or `files:{owner}/{repo}/{path}` when
# a subdir is specified).
#
# Improvements over original:
#   - Uses GitHub's tarball endpoint (one HTTP call) instead of N per-file
#     contents/{path} calls. Cuts download from 7-15min to 1-2min on big repos
#     and reduces GitHub API quota use from N to ~2 calls per repo.
#   - Same vendor-dir / >1MB / binary filtering as original, just done locally
#     after extraction.
#   - Same input/output contract — drop-in replacement.

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    # Tarball can be large — use generous timeouts
    http_client = httpx.AsyncClient(timeout=httpx.Timeout(connect=30.0, read=600.0, write=60.0, pool=60.0))
    try:
        import io
        import os
        import tarfile

        input_text = input_dict.get("inputText", "")
        lines = input_text.strip().split("\n")

        repo = None
        token = None
        path_prefix = ""
        branch_override = ""

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("branch:"):
                branch_override = line.split(":", 1)[1].strip()
            elif line.startswith("ghp_") or line.startswith("github_pat_") or (len(line) > 30 and line.isalnum()):
                token = line
            elif "/" in line and repo is None:
                raw = line.split()[0].strip("/")
                parts = raw.split("/")
                if len(parts) >= 2:
                    repo = f"{parts[0]}/{parts[1]}"
                    if len(parts) > 2:
                        path_prefix = "/".join(parts[2:])

        if not repo:
            return {"outputText": "Error: Could not find a valid repo in format 'owner/repo' in the input."}

        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # ----- Resolve repo metadata -----
        repo_url = f"https://api.github.com/repos/{repo}"
        response = await http_client.get(repo_url, headers=headers)
        if response.status_code != 200:
            return {"outputText": f"Error fetching repo info: {response.status_code} - repo='{repo}' token_present={token is not None} - {response.text}"}
        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")
        # branch_override (passed by orchestrator) wins when set; otherwise
        # fall back to the repo's default branch. Projects with abandoned
        # master/trunk (e.g. apache/mina active development is on 2.2.X)
        # must override or the audit runs against dead code.
        target_branch = branch_override or default_branch

        # ----- Download tarball (single HTTP call) -----
        # GitHub redirects this to a CodeLoad URL — follow_redirects must be on.
        tarball_url = f"https://api.github.com/repos/{repo}/tarball/{target_branch}"
        if branch_override:
            print(f"Branch: {target_branch} (override; default is {default_branch})", flush=True)
        else:
            print(f"Branch: {target_branch} (default)", flush=True)
        if path_prefix:
            print(f"Downloading tarball: {tarball_url}", flush=True)
            print(f"  (will filter to subdirectory: {path_prefix}/)", flush=True)
        else:
            print(f"Downloading tarball: {tarball_url}", flush=True)
        tar_resp = await http_client.get(tarball_url, headers=headers, follow_redirects=True)
        if tar_resp.status_code != 200:
            return {"outputText": f"Error fetching tarball: {tar_resp.status_code} - {tar_resp.text[:500]}"}

        tar_bytes = tar_resp.content
        print(f"Tarball downloaded: {len(tar_bytes):,} bytes", flush=True)

        # ----- Filtering rules -----
        # Vendor directories (existing). These hold third-party
        # dependency source that is upstream's problem, not ours.
        VENDOR_DIRS = {
            'node_modules', 'vendor', 'third_party', 'third-party', '.git',
        }

        # Generated-output directories (NEW). Any depth in the tree.
        # These hold build artifacts, snapshot fixtures, test coverage
        # reports, and other tool-emitted content. No security audit
        # value and they bloat the file scope when committed (which they
        # sometimes are, by mistake or convention).
        GENERATED_DIRS = {
            'dist', 'build', 'out', '.next', '.nuxt', '.cache',
            '.parcel-cache', '.turbo', '.svelte-kit',
            '__snapshots__', '__generated__', '__fixtures__', 'generated',
            'coverage', 'htmlcov', '.nyc_output',
            '.pytest_cache', '.mypy_cache', '.ruff_cache',
        }

        # Vendor manifests / lockfiles (NEW). Pinned, transitively-
        # resolved dependency declarations — not authored source. The
        # supply-chain audit lives in dependency-pin policy, not in
        # ASVS code review. Matched by exact basename, anywhere in the
        # tree.
        LOCKFILE_NAMES = {
            'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
            'npm-shrinkwrap.json',
            'poetry.lock', 'uv.lock', 'Pipfile.lock',
            'Gemfile.lock', 'Cargo.lock', 'composer.lock', 'go.sum',
            'Podfile.lock', 'mix.lock', 'flake.lock',
        }

        # Data-file extensions (NEW). Below the threshold these are
        # likely config or small test fixtures and pass through. Above
        # the threshold they are almost always static data corpora
        # (GIS shapes, tabular dumps, DB exports) that have no code
        # to audit but consume large slices of the discovery agent's
        # per-batch context budget.
        DATA_FILE_EXTS = {
            '.geojson', '.topojson',
            '.csv', '.tsv',
            '.ndjson', '.jsonl',
            '.sql', '.dump',
            '.parquet', '.feather', '.arrow', '.avro',
        }
        DATA_FILE_THRESHOLD = 50_000   # 50 KB

        # Generated / minified file suffixes (NEW). Build-tool output
        # regardless of size. Source maps included because they're
        # mechanical transforms of the original source.
        GENERATED_FILE_SUFFIXES = (
            '.min.js', '.min.mjs', '.min.css',
            '.bundle.js', '.bundle.css',
            '.js.map', '.mjs.map', '.css.map', '.d.ts.map',
        )

        MAX_FILE_SIZE = 1_000_000

        ns_name = f"files:{repo}/{path_prefix}" if path_prefix else f"files:{repo}"
        files_ns = data_store.use_namespace(ns_name)

        # Clear stale data from previous runs in a single bulk op rather
        # than looping delete() per key. With ~300 files per repo, the
        # per-key loop was ~900 HTTP roundtrips to CouchDB (each delete
        # is exists-check + GET-rev + DELETE); clear() ships one bulk
        # call regardless of N.
        cleared_count = files_ns.clear()
        if cleared_count:
            print(f"Cleared {cleared_count} existing files from namespace", flush=True)

        fetched_count = 0
        skipped_binary = 0
        skipped_vendor = 0
        skipped_generated = 0
        skipped_lockfile = 0
        skipped_data = 0
        skipped_large = 0
        skipped_outside_prefix = 0
        error_count = 0
        errors = []

        # ----- Walk tarball entries -----
        # GitHub tarballs have a single top-level dir like "owner-repo-<sha>/..."
        # Strip that prefix when storing to data_store so paths match the
        # `contents/{path}` form the rest of the pipeline expects.
        #
        # Writes are accumulated in `new_files` and shipped in one bulk
        # set_many() after the walk completes. Previously this loop did
        # per-file files_ns.set() -- 439 sequential HTTP calls to
        # CouchDB for a typical Mahout-sized repo, blocking the worker
        # for tens of seconds. set_many() is one round trip.
        new_files: dict = {}
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
            members = tar.getmembers()
            print(f"Tarball contains {len(members)} members", flush=True)

            top_level_prefix = None
            for m in members:
                if m.name and "/" in m.name:
                    top_level_prefix = m.name.split("/", 1)[0] + "/"
                    break

            for member in members:
                if not member.isfile():
                    continue

                # Strip the GitHub-injected top-level dir
                rel_path = member.name
                if top_level_prefix and rel_path.startswith(top_level_prefix):
                    rel_path = rel_path[len(top_level_prefix):]
                if not rel_path:
                    continue

                # Apply path_prefix filter if requested
                if path_prefix:
                    if not (rel_path == path_prefix or rel_path.startswith(path_prefix + "/")):
                        skipped_outside_prefix += 1
                        continue

                # Vendor-dir filter
                parts = rel_path.split("/")
                if any(part.lower() in VENDOR_DIRS for part in parts[:-1]):
                    skipped_vendor += 1
                    continue

                # Generated/build-output directory filter (NEW)
                if any(part in GENERATED_DIRS for part in parts[:-1]):
                    skipped_generated += 1
                    continue

                basename = parts[-1]

                # Lockfile filter (NEW) — match by exact basename
                if basename in LOCKFILE_NAMES:
                    skipped_lockfile += 1
                    continue

                # Minified / source-map / bundle suffix filter (NEW)
                if any(basename.endswith(suffix) for suffix in GENERATED_FILE_SUFFIXES):
                    skipped_generated += 1
                    continue

                # Static-data-file filter (NEW) — extension + size gate.
                # Small data files (config-shaped JSON, small fixture
                # CSVs) pass through; large ones are static corpora and
                # are dropped.
                lower = basename.lower()
                dot_pos = lower.rfind(".")
                ext = lower[dot_pos:] if dot_pos != -1 else ""
                if ext in DATA_FILE_EXTS and member.size > DATA_FILE_THRESHOLD:
                    skipped_data += 1
                    continue

                # Size filter
                if member.size > MAX_FILE_SIZE:
                    skipped_large += 1
                    continue

                # Extract & decode
                try:
                    f = tar.extractfile(member)
                    if f is None:
                        continue
                    raw = f.read()
                    try:
                        content = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        skipped_binary += 1
                        continue
                    new_files[rel_path] = content
                    fetched_count += 1
                except Exception as e:
                    error_count += 1
                    if len(errors) < 10:
                        errors.append(f"{rel_path}: {str(e)}")

        # Ship accumulated writes in one bulk call. Two HTTP round trips
        # (a get_many for existing _revs, then one _bulk_docs) regardless
        # of how many files were fetched.
        if new_files:
            print(f"Writing {len(new_files)} files via set_many...", flush=True)
            saved = files_ns.set_many(new_files)
            if saved != len(new_files):
                print(f"  WARN: set_many saved {saved}/{len(new_files)} -- {len(new_files) - saved} keys failed and will be missing", flush=True)

        summary_lines = [
            f"Repository: {repo}",
            f"Branch audited: {target_branch}"
            + (f" (override; default is {default_branch})" if branch_override else " (default)"),
        ]
        if path_prefix:
            summary_lines.append(f"Path prefix: {path_prefix}")
        summary_lines += [
            f"Previous files cleared: {cleared_count}",
            f"Files fetched and stored: {fetched_count}",
            f"Skipped (binary): {skipped_binary}",
            f"Skipped (vendor/third-party dirs): {skipped_vendor}",
            f"Skipped (generated/build dirs and minified files): {skipped_generated}",
            f"Skipped (lockfiles): {skipped_lockfile}",
            f"Skipped (static data files > {DATA_FILE_THRESHOLD:,} bytes): {skipped_data}",
            f"Skipped (>1MB): {skipped_large}",
            f"Skipped (outside path prefix): {skipped_outside_prefix}",
            f"Errors: {error_count}",
            "",
            f"Data stored in namespace: {ns_name}",
        ]

        if errors:
            summary_lines.append("")
            summary_lines.append("First few errors:")
            for err in errors:
                summary_lines.append(f"  - {err}")

        return {"outputText": "\n".join(summary_lines)}

    finally:
        await http_client.aclose()