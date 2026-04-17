# fetch_audit_guidance
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        lines = input_dict["inputText"].strip().split("\n")
        repo = lines[0].strip()
        subdir = lines[1].strip().strip("/")
        token = lines[2].strip() if len(lines) > 2 and lines[2].strip() else None
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GofannonAgent"
        }
        if token:
            headers["Authorization"] = f"token {token}"
        ns = data_store.use_namespace("audit_guidance")
        async def fetch_directory(path):
            url = f"https://api.github.com/repos/{repo}/contents/{path}"
            response = await http_client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            items = response.json()
            if isinstance(items, dict):
                items = [items]
            files_stored = []
            for item in items:
                if item["type"] == "file":
                    download_url = item["download_url"]
                    file_response = await http_client.get(download_url, headers=headers, follow_redirects=True)
                    file_response.raise_for_status()
                    content = file_response.text
                    key = item["path"]
                    existing = ns.get(key)
                    if existing is not None:
                        ns.delete(key)
                    ns.set(key, {
                        "content": content,
                        "name": item["name"],
                        "path": item["path"],
                        "sha": item["sha"],
                        "size": item["size"]
                    })
                    files_stored.append(key)
                elif item["type"] == "dir":
                    sub_files = await fetch_directory(item["path"])
                    files_stored.extend(sub_files)
            return files_stored
        files_stored = await fetch_directory(subdir)
        summary_lines = [f"Successfully stored {len(files_stored)} file(s) from '{repo}/{subdir}' into namespace 'audit_guidance':"]
        for f in files_stored:
            summary_lines.append(f"  - {f}")
        return {"outputText": "\n".join(summary_lines)}
    finally:
        await http_client.aclose()
