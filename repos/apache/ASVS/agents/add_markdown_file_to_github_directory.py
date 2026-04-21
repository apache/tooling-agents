# add_markdown_file_to_github_directory

from agent_factory.remote_mcp_client import RemoteMCPClient
import litellm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json
        import re
        import base64
        from datetime import datetime, timezone

        input_text = (input_dict.get("inputText") or "").strip()
        commit_message = input_dict.get("commitMessage") or "Add markdown file"
        file_contents = input_dict.get("fileContents") or ""

        def _maybe_json(s: str):
            try:
                return json.loads(s)
            except Exception:
                return None

        def _strip_quotes(s: str) -> str:
            s = s.strip()
            if (len(s) >= 2) and ((s[0] == s[-1]) and s[0] in ("'", '"')):
                return s[1:-1].strip()
            return s

        def _find_kv(text: str, key: str):
            patterns = [
                rf'(?im)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$',
                rf'(?im)^\s*{re.escape(key)}\s*=\s*(.+?)\s*$',
                rf'(?is)"{re.escape(key)}"\s*:\s*"([^"]+)"',
                rf"(?is)'{re.escape(key)}'\s*:\s*'([^']+)'",
            ]
            for pat in patterns:
                m = re.search(pat, text)
                if m:
                    return _strip_quotes(m.group(1))
            return None

        def _parse_owner_repo(text: str):
            repo = _find_kv(text, "repo") or _find_kv(text, "repository") or _find_kv(text, "full_name")
            if repo and "/" in repo:
                parts = repo.strip().strip("/").split("/")
                if len(parts) >= 2:
                    return parts[-2], parts[-1]
            m = re.search(r'(?i)\bgithub\.com/([^/\s]+)/([^/\s#?]+)', text)
            if m:
                return m.group(1), m.group(2)
            m = re.search(r'(?i)\b([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)\b', text)
            if m:
                return m.group(1), m.group(2)
            return None, None

        cfg = _maybe_json(input_text)
        if not isinstance(cfg, dict):
            cfg = {}

        token = (
            cfg.get("token") or cfg.get("github_token") or cfg.get("githubToken")
            or _find_kv(input_text, "token") or _find_kv(input_text, "github_token")
            or _find_kv(input_text, "githubToken")
        )

        api_base = (
            cfg.get("api_base") or cfg.get("apiBase") or cfg.get("github_api_base")
            or _find_kv(input_text, "api_base") or _find_kv(input_text, "apiBase")
            or _find_kv(input_text, "github_api_base") or "https://api.github.com"
        ).rstrip("/")

        owner = cfg.get("owner") or _find_kv(input_text, "owner")
        repo_name = cfg.get("repo_name") or cfg.get("repo") or cfg.get("repository") or _find_kv(input_text, "repo_name")
        if repo_name and isinstance(repo_name, str) and "/" in repo_name and not owner:
            owner, repo_name = repo_name.split("/", 1)

        if not owner or not repo_name:
            o2, r2 = _parse_owner_repo(input_text)
            owner = owner or o2
            repo_name = repo_name or r2

        directory = (
            cfg.get("directory") or cfg.get("dir") or cfg.get("path")
            or _find_kv(input_text, "directory") or _find_kv(input_text, "dir")
            or _find_kv(input_text, "path") or ""
        ).strip()

        branch = cfg.get("branch") or _find_kv(input_text, "branch") or None

        file_name = (
            cfg.get("fileName") or cfg.get("filename") or cfg.get("file_name")
            or _find_kv(input_text, "fileName") or _find_kv(input_text, "filename")
            or _find_kv(input_text, "file_name")
        )

        file_path = (
            cfg.get("filePath") or cfg.get("filepath")
            or _find_kv(input_text, "filePath") or _find_kv(input_text, "filepath")
        )

        if not token:
            return {"outputText": "Error: No GitHub token found in inputText (expected keys like token/github_token)."}
        if not owner or not repo_name:
            return {"outputText": "Error: Could not determine GitHub owner/repo from inputText (expected owner+repo or owner/repo)."}
        if not directory and not file_path:
            return {"outputText": "Error: No target directory/path provided in inputText (expected directory/dir/path or filePath)."}
        if not file_contents:
            return {"outputText": "Error: fileContents is empty."}

        if file_path:
            final_path = file_path.strip().lstrip("/")
        else:
            dir_clean = directory.strip().strip("/")
            if file_name:
                name = file_name.strip().lstrip("/")
            else:
                ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                name = f"new_file_{ts}.md"
            if not name.lower().endswith(".md"):
                name = f"{name}.md"
            final_path = f"{dir_clean}/{name}" if dir_clean else name

        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        }

        get_url = f"{api_base}/repos/{owner}/{repo_name}/contents/{final_path}"
        params = {}
        if branch:
            params["ref"] = branch

        existing_sha = None
        existing_resp = await http_client.get(get_url, headers=headers, params=params)
        if existing_resp.status_code == 200:
            try:
                existing_json = existing_resp.json()
                existing_sha = existing_json.get("sha")
            except Exception:
                pass

        put_url = f"{api_base}/repos/{owner}/{repo_name}/contents/{final_path}"
        payload = {
            "message": commit_message,
            "content": base64.b64encode(file_contents.encode("utf-8")).decode("utf-8"),
        }
        if existing_sha:
            payload["sha"] = existing_sha
        if branch:
            payload["branch"] = branch

        resp = await http_client.put(put_url, headers=headers, json=payload)
        try:
            resp.raise_for_status()
        except Exception:
            try:
                return {"outputText": json.dumps(resp.json(), indent=2, sort_keys=True)}
            except Exception:
                return {"outputText": resp.text}

        try:
            return {"outputText": json.dumps(resp.json(), indent=2, sort_keys=True)}
        except Exception:
            return {"outputText": resp.text}

    finally:
        await http_client.aclose()