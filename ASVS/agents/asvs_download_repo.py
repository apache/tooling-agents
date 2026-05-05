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

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("ghp_") or line.startswith("github_pat_") or (len(line) > 30 and line.isalnum()):
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

        # ----- Download tarball (single HTTP call) -----
        # GitHub redirects this to a CodeLoad URL — follow_redirects must be on.
        tarball_url = f"https://api.github.com/repos/{repo}/tarball/{default_branch}"
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

        # ----- Filtering rules (same as original) -----
        VENDOR_DIRS = {
            'node_modules', 'vendor', 'third_party', 'third-party', '.git',
        }
        MAX_FILE_SIZE = 1_000_000

        ns_name = f"files:{repo}/{path_prefix}" if path_prefix else f"files:{repo}"
        files_ns = data_store.use_namespace(ns_name)

        # Clear stale data from previous runs
        existing_keys = files_ns.list_keys()
        if existing_keys:
            print(f"Clearing {len(existing_keys)} existing files from namespace", flush=True)
            for key in existing_keys:
                files_ns.delete(key)

        fetched_count = 0
        skipped_binary = 0
        skipped_vendor = 0
        skipped_large = 0
        skipped_outside_prefix = 0
        error_count = 0
        errors = []

        # ----- Walk tarball entries -----
        # GitHub tarballs have a single top-level dir like "owner-repo-<sha>/..."
        # Strip that prefix when storing to data_store so paths match the
        # `contents/{path}` form the rest of the pipeline expects.
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
                    files_ns.set(rel_path, content)
                    fetched_count += 1
                except Exception as e:
                    error_count += 1
                    if len(errors) < 10:
                        errors.append(f"{rel_path}: {str(e)}")

        summary_lines = [
            f"Repository: {repo}",
            f"Default branch: {default_branch}",
        ]
        if path_prefix:
            summary_lines.append(f"Path prefix: {path_prefix}")
        summary_lines += [
            f"Previous files cleared: {len(existing_keys)}",
            f"Files fetched and stored: {fetched_count}",
            f"Skipped (binary): {skipped_binary}",
            f"Skipped (vendor/third-party dirs): {skipped_vendor}",
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