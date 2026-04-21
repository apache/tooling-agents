# download_github_repo_to_datastore
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
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
            "X-GitHub-Api-Version": "2022-11-28"
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        repo_url = f"https://api.github.com/repos/{repo}"
        response = await http_client.get(repo_url, headers=headers)

        if response.status_code != 200:
            return {"outputText": f"Error fetching repo info: {response.status_code} - repo='{repo}' token_present={token is not None} - {response.text}"}

        repo_info = response.json()
        default_branch = repo_info.get("default_branch", "main")

        tree_url = f"https://api.github.com/repos/{repo}/git/trees/{default_branch}?recursive=1"
        response = await http_client.get(tree_url, headers=headers)

        if response.status_code != 200:
            return {"outputText": f"Error fetching repo tree: {response.status_code} - {response.text}"}

        tree_data = response.json()
        tree_items = tree_data.get("tree", [])
        files_to_fetch = [item for item in tree_items if item.get("type") == "blob"]

        # Filter by path prefix if provided
        if path_prefix:
            files_to_fetch = [item for item in files_to_fetch if item.get("path", "").startswith(path_prefix + "/") or item.get("path", "") == path_prefix]
            print(f"Path prefix '{path_prefix}': {len(files_to_fetch)} files match", flush=True)

        files_ns = data_store.use_namespace(f"files:{repo}")

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
        error_count = 0
        errors = []

        VENDOR_DIRS = {
            'node_modules', 'vendor', 'third_party', 'third-party',
            '.git',
        }

        MAX_FILE_SIZE = 1_000_000

        import base64

        for item in files_to_fetch:
            file_path = item.get("path", "")
            file_size = item.get("size", 0)

            parts = file_path.split("/")
            if any(part.lower() in VENDOR_DIRS for part in parts[:-1]):
                skipped_vendor += 1
                continue

            if file_size > MAX_FILE_SIZE:
                skipped_large += 1
                continue

            try:
                content_url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={default_branch}"
                file_response = await http_client.get(content_url, headers=headers)

                if file_response.status_code == 200:
                    file_data = file_response.json()
                    content_b64 = file_data.get("content", "")

                    if content_b64:
                        try:
                            content = base64.b64decode(content_b64).decode("utf-8")
                            files_ns.set(file_path, content)
                            fetched_count += 1
                        except UnicodeDecodeError:
                            skipped_binary += 1
                    else:
                        skipped_binary += 1
                else:
                    error_count += 1
                    if len(errors) < 10:
                        errors.append(f"{file_path}: {file_response.status_code}")
            except Exception as e:
                error_count += 1
                if len(errors) < 10:
                    errors.append(f"{file_path}: {str(e)}")

        summary_lines = [
            f"Repository: {repo}",
            f"Default branch: {default_branch}",
        ]
        if path_prefix:
            summary_lines.append(f"Path prefix: {path_prefix}")
        summary_lines += [
            f"Previous files cleared: {len(existing_keys)}",
            f"Total files in scope: {len(files_to_fetch)}",
            f"Files fetched and stored: {fetched_count}",
            f"Skipped (binary): {skipped_binary}",
            f"Skipped (vendor/third-party dirs): {skipped_vendor}",
            f"Skipped (>1MB): {skipped_large}",
            f"Errors: {error_count}",
            f"",
            f"Data stored in namespace: files:{repo}",
        ]

        if errors:
            summary_lines.append("")
            summary_lines.append("First few errors:")
            for err in errors:
                summary_lines.append(f"  - {err}")

        return {"outputText": "\n".join(summary_lines)}

    finally:
        await http_client.aclose()