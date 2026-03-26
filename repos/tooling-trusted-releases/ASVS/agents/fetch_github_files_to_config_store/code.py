from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        lines = input_dict["inputText"].strip().split("\n")
        repo = lines[0].strip()
        files_str = lines[1].strip()
        branch = lines[2].strip()
        token = lines[3].strip() if len(lines) > 3 else None
        files = [f.strip() for f in files_str.split(",") if f.strip()]
        config_ns = data_store.use_namespace("config")
        headers = {
            "Accept": "application/vnd.github.v3.raw",
            "User-Agent": "gofannon-agent"
        }
        if token:
            headers["Authorization"] = f"token {token}"
        fetched_files = []
        errors = []
        for file_path in files:
            url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
            response = await http_client.get(url, headers=headers, follow_redirects=True)
            if response.status_code == 200:
                content = response.text
                file_name = file_path.split("/")[-1]
                key = file_name
                existing = config_ns.get(key)
                if existing is not None:
                    config_ns.delete(key)
                config_ns.set(key, {"content": content, "repo": repo, "branch": branch, "path": file_path})
                fetched_files.append(file_path)
            else:
                errors.append(f"{file_path} (HTTP {response.status_code})")
        result_parts = []
        if fetched_files:
            result_parts.append(f"Successfully fetched and stored {len(fetched_files)} file(s) in 'config' namespace: {', '.join(fetched_files)}")
        if errors:
            result_parts.append(f"Failed to fetch {len(errors)} file(s): {', '.join(errors)}")
        return {"outputText": "\n".join(result_parts) if result_parts else "No files processed."}
    finally:
        await http_client.aclose()
