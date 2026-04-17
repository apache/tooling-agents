# fetch_and_compile_github_open_issues
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx


async def run(input_dict, tools):
    from urllib.parse import urlparse, parse_qs

    mcpc = {url: RemoteMCPClient(remote_url=url) for url in tools.keys()}
    http_client = httpx.AsyncClient()

    try:
        raw_url = input_dict.get("inputText", "").strip()
        labels_filter = input_dict.get("labels", "").strip()

        parsed = urlparse(raw_url)
        url_path = parsed.path.rstrip("/")

        if not labels_filter:
            import re
            from urllib.parse import unquote
            query_params = parse_qs(parsed.query)

            if "q" in query_params:
                q_value = unquote(query_params["q"][0])
                label_matches = re.findall(r'label[:\s]"([^"]+)"|label[:\s](\S+)', q_value)
                extracted = [quoted or unquoted for quoted, unquoted in label_matches]
                if extracted:
                    labels_filter = ",".join(extracted)

            if not labels_filter:
                if "label" in query_params:
                    labels_filter = ",".join(query_params["label"])
                elif "labels" in query_params:
                    labels_filter = ",".join(query_params["labels"])

        if url_path.endswith("/issues"):
            url_path = url_path[: -len("/issues")]

        parts = url_path.lstrip("/").split("/")
        if len(parts) < 2:
            return {"outputText": f"Could not parse owner/repo from URL: {raw_url}"}

        owner = parts[0]
        repo = parts[1]

        all_issues = []
        page = 1
        per_page = 100

        while True:
            api_url = (
                f"https://api.github.com/repos/{owner}/{repo}/issues"
                f"?state=open&per_page={per_page}&page={page}"
            )
            if labels_filter:
                api_url += f"&labels={labels_filter}"

            headers = {
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "Gofannon-Agent",
            }

            response = await http_client.get(api_url, headers=headers)

            if response.status_code != 200:
                return {
                    "outputText": f"GitHub API error: {response.status_code} - {response.text}"
                }

            issues_page = response.json()

            if not issues_page:
                break

            for issue in issues_page:
                if "pull_request" not in issue:
                    all_issues.append(issue)

            if len(issues_page) < per_page:
                break

            page += 1

        label_note = f" (filtered by: {labels_filter})" if labels_filter else ""
        markdown_lines = [
            f"# Open Issues for {owner}/{repo}{label_note}",
            "",
            f"**Total open issues:** {len(all_issues)}",
            "",
            "---",
            "",
        ]

        for issue in all_issues:
            number = issue.get("number", "N/A")
            title = issue.get("title", "No title")
            body = issue.get("body", "") or "_No description provided._"
            created = issue.get("created_at", "Unknown")
            updated = issue.get("updated_at", "Unknown")
            author = issue.get("user", {}).get("login", "Unknown")
            labels = ", ".join(l.get("name", "") for l in issue.get("labels", [])) or "None"
            assignees = ", ".join(a.get("login", "") for a in issue.get("assignees", [])) or "None"
            issue_url = issue.get("html_url", "")

            markdown_lines.extend([
                f"## #{number}: {title}",
                "",
                f"- **URL:** {issue_url}",
                f"- **Author:** {author}",
                f"- **Labels:** {labels}",
                f"- **Assignees:** {assignees}",
                f"- **Created:** {created}",
                f"- **Updated:** {updated}",
                "",
                "### Description",
                "",
                body,
                "",
                "---",
                "",
            ])

        markdown_content = "\n".join(markdown_lines)

        issues_ns = data_store.use_namespace("open_issues")
        store_key = f"{owner}/{repo}"
        issues_ns.set_many({
            store_key: {
                "markdown": markdown_content,
                "issue_count": len(all_issues),
                "repo": f"{owner}/{repo}",
                "labels_filter": labels_filter or None,
            }
        })

        return {"outputText": markdown_content}

    finally:
        await http_client.aclose()
