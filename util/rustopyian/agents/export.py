import httpx

# --- Rustopyian Exporter ------------------------------------------------------
#
# Companion to the Rustopyian Constructinator. Takes generated files from
# data_store and pushes them to a GitHub repository in a single commit.
#
# Can be called standalone or from the Constructinator via gofannon_client.call().
#
# Inputs (via input_dict):
#   package_name  - matches the Constructinator run (e.g. "swhid-py")
#   github_repo   - target repo as "owner/repo" (e.g. "apache/swhid-py")
#   github_pat    - GitHub PAT with repo write access
#   branch        - branch to push to (default "main")
#   commit_msg    - commit message (default "Initial wrapper from Rustopyian")
#   dry_run       - set "true" to list files without pushing (default "false")

async def run(input_dict, tools):
    http_client = httpx.AsyncClient(timeout=30.0)
    try:
        import base64
        import asyncio
        package_name = input_dict.get("package_name", "").strip()
        github_repo = input_dict.get("github_repo", "").strip()
        github_pat = input_dict.get("github_pat", "").strip()
        branch = input_dict.get("branch", "main").strip() or "main"
        commit_msg = input_dict.get("commit_msg", "Initial wrapper from Rustopyian").strip() or "Initial wrapper from Rustopyian"
        dry_run = str(input_dict.get("dry_run", "false")).lower().strip() in ("true", "1", "yes")

        if not package_name:
            return {"outputText": "Error: `package_name` is required."}
        if not github_repo:
            return {"outputText": "Error: `github_repo` is required (e.g. 'apache/swhid-py')."}
        if not github_pat and not dry_run:
            return {"outputText": "Error: `github_pat` is required for pushing (or set `dry_run=true`)."}

        ns = data_store.use_namespace(f"rustopyian:{package_name}")
        all_keys = ns.list_keys()
        file_keys = sorted(k for k in all_keys if k.startswith("files/"))

        if not file_keys:
            return {"outputText": f"Error: no files found in `rustopyian:{package_name}`. "
                    f"Run the Constructinator first."}

        lines = []
        def log(msg):
            print(msg, flush=True)
            lines.append(msg)

        log(f"# Rustopyian Exporter")
        log(f"Package: **{package_name}** -> `{github_repo}`\n")
        log(f"Found **{len(file_keys)}** files in data_store:\n")

        file_map = {}
        for key in file_keys:
            filepath = key[len("files/"):]
            content = ns.get(key)
            if content is not None:
                file_map[filepath] = content
                log(f"- `{filepath}` ({len(content):,} bytes)")

        if dry_run:
            log(f"\n**Dry run** - no files pushed.")
            log(f"\nTo push, re-run with `dry_run=false`.")
            metadata = ns.get("metadata")
            if metadata:
                log(f"\n## Metadata\n")
                log(f"- Crate: {metadata.get('crate_name')} v{metadata.get('crate_version')}")
                log(f"- License: {metadata.get('crate_license')}")
                log(f"- API surface: {len(metadata.get('api_surface', []))} items")
                flagged = metadata.get("flagged_features", [])
                if flagged:
                    log(f"- Flagged features (copyleft): {', '.join(flagged)}")
            return {"outputText": "\n".join(lines)}

        # -- Push to GitHub via Git Trees API ------------------------------

        gh_headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {github_pat}",
        }
        api = f"https://api.github.com/repos/{github_repo}"

        log(f"\n## Pushing to GitHub\n")

        # Get current branch HEAD
        ref_resp = await http_client.get(
            f"{api}/git/refs/heads/{branch}", headers=gh_headers
        )

        if ref_resp.status_code == 200:
            base_sha = ref_resp.json()["object"]["sha"]
            log(f"Branch `{branch}` exists at `{base_sha[:8]}...`")
        elif ref_resp.status_code in (404, 409):
            log(f"Repo is empty - bootstrapping with initial commit...")
            # Git Data API doesn't work on empty repos. Use Contents API
            # to create one file, which initializes the repo and branch.
            bootstrap_resp = await http_client.put(
                f"{api}/contents/.gitignore",
                headers=gh_headers,
                json={
                    "message": "Initialize repository",
                    "content": base64.b64encode(b"/target/\n").decode(),
                    "branch": branch,
                },
            )
            if bootstrap_resp.status_code not in (200, 201):
                return {"outputText": "\n".join(lines) +
                        f"\n\nError bootstrapping empty repo: HTTP {bootstrap_resp.status_code}\n{bootstrap_resp.text}"}
            # Now get the commit SHA that was just created
            ref_resp2 = await http_client.get(
                f"{api}/git/refs/heads/{branch}", headers=gh_headers
            )
            if ref_resp2.status_code != 200:
                return {"outputText": "\n".join(lines) +
                        f"\n\nError: repo bootstrapped but can't read branch (HTTP {ref_resp2.status_code})"}
            base_sha = ref_resp2.json()["object"]["sha"]
            log(f"Repo initialized, branch `{branch}` at `{base_sha[:8]}...`")
        else:
            return {"outputText": "\n".join(lines) +
                    f"\n\nError: failed to get branch `{branch}` (HTTP {ref_resp.status_code})"}

        # Create blobs for each file
        tree_entries = []
        for filepath, content in sorted(file_map.items()):
            blob_resp = await http_client.post(
                f"{api}/git/blobs",
                headers=gh_headers,
                json={
                    "content": base64.b64encode(content.encode()).decode(),
                    "encoding": "base64",
                },
            )
            if blob_resp.status_code not in (200, 201):
                log(f"**Error** creating blob for `{filepath}`: HTTP {blob_resp.status_code}")
                continue

            blob_sha = blob_resp.json()["sha"]
            tree_entries.append({
                "path": filepath,
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha,
            })
            log(f"  blob `{filepath}` -> `{blob_sha[:8]}...`")
            await asyncio.sleep(0.1)

        # Create tree
        tree_payload = {"tree": tree_entries}
        commit_resp = await http_client.get(
            f"{api}/git/commits/{base_sha}", headers=gh_headers
        )
        if commit_resp.status_code == 200:
            tree_payload["base_tree"] = commit_resp.json()["tree"]["sha"]

        tree_resp = await http_client.post(
            f"{api}/git/trees", headers=gh_headers, json=tree_payload
        )
        if tree_resp.status_code not in (200, 201):
            return {"outputText": "\n".join(lines) +
                    f"\n\nError creating tree: HTTP {tree_resp.status_code}\n{tree_resp.text}"}

        tree_sha = tree_resp.json()["sha"]
        log(f"\nTree: `{tree_sha[:8]}...`")

        # Create commit
        commit_payload = {"message": commit_msg, "tree": tree_sha, "parents": [base_sha]}

        new_commit_resp = await http_client.post(
            f"{api}/git/commits", headers=gh_headers, json=commit_payload
        )
        if new_commit_resp.status_code not in (200, 201):
            return {"outputText": "\n".join(lines) +
                    f"\n\nError creating commit: HTTP {new_commit_resp.status_code}\n{new_commit_resp.text}"}

        new_commit_sha = new_commit_resp.json()["sha"]
        log(f"Commit: `{new_commit_sha[:8]}...`")

        # Update branch ref
        ref_update = await http_client.patch(
            f"{api}/git/refs/heads/{branch}",
            headers=gh_headers,
            json={"sha": new_commit_sha},
        )

        if ref_update.status_code not in (200, 201):
            return {"outputText": "\n".join(lines) +
                    f"\n\nError updating ref: HTTP {ref_update.status_code}\n{ref_update.text}"}

        log(f"\nPushed **{len(tree_entries)}** files to "
            f"[{github_repo}](https://github.com/{github_repo}/tree/{branch}) "
            f"on branch `{branch}`.")

        log(f"\n---\n")
        log(f"Next: clone the repo, run `maturin develop`, fix any compiler errors, "
            f"run `cargo fmt`, and push.")

        return {"outputText": "\n".join(lines)}

    finally:
        await http_client.aclose()