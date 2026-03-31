Processes an ASVS security triage file and files GitHub issues for findings that need attention. Takes a triage file (pasted text), a raw issues markdown URL from GitHub, a target repo, a commit hash, and a GitHub token. For each triaged finding marked "Todo", files a GitHub issue with the correct title, description, labels, and assignees according to the triage disposition rules.

You will read through this triage file. Each row of the file starts with a finding id, then a disposition like Todo or Fixed, sometimes with commentary. There is a raw list of potential issues at https://github.com/apache/tooling-agents/blob/main/repos/tooling-trusted-releases/ASVS/reports/da901ba/issues-L1-L2.md, each titled FINDING-id, where id maps to the finding id in the triage file. I want the agent to take in a github owner/repo and token, commit hash and a link to the raw issues file on github, as well as an input field for the triage file pasted in. the framework I am making the agent with is gofannon, source code attached as a zip. read through that so you understand how things work. I want the agent, for every finding in the triage file, to decide whether to file an issue on the repo given. use the formatting in the raw issues file for the issue to be filed: for the issue title strip off everything up to whatever is after "FINDING-id - ", and use the markdown after Description for the body of the description field. Add labels according to the labels for each issue: for example for "Labels: bug, security, priority:critical, asvs-level:L1, asvs-level:L2" ignore the "bug" label, but add a security label, add a label for "critical" in this case, add "asvs" as a label, add "L1" as a label in this case, and add the given commit hash as a label. if a triaged finding's disposition is anything but Todo, do not file an issue. if it says Todo - sbp, file the issue and assign to @sbp. if it says related to or adjacent to something, find what it's related to and consolidate all triaged findings into the one they refer to. if it says asfquart or asfpy, do nothing. if it says documentation, priority, discussion, or long-term, label with documentation, priority, discussion or "long term goal". if it just links to an existing github issue, look for the contents of that issue and decide if it is an open issue that is exactly the same issue or if it's related. if it's exactly the same, do nothing. if it's related, add a link to the existing issue in the new issue. otherwise, if it just says Todo with nothing else, just file the issue as written in the raw issues file. if it says Todo with anything else, file the issue as written in the raw issues file but add the information in the rest of the line to the bottom of the issue description.

input schema:
{
    "type": "object",
    "properties": {
        "github_repo": {
            "type": "string",
            "description": "GitHub owner/repo, e.g. 'apache/creadur-rat'"
        },
        "github_token": {
            "type": "string",
            "description": "GitHub personal access token with repo scope"
        },
        "commit_hash": {
            "type": "string",
            "description": "Short commit hash to add as a label to every filed issue, e.g. 'da901ba'"
        },
        "issues_url": {
            "type": "string",
            "description": "URL to the raw issues markdown file on GitHub (use the raw.githubusercontent.com URL so it returns plain text)"
        },
        "triage_content": {
            "type": "string",
            "description": "Full text of the triage file pasted in. Each line: finding_id followed by a disposition like Todo or Fixed, optionally with commentary."
        }
    },
    "required": ["github_repo", "github_token", "commit_hash", "issues_url", "triage_content"]
}

output schema:
{
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "Human-readable summary of all actions taken"
        },
        "issues_filed": {
            "type": "array",
            "description": "List of issues that were successfully created on GitHub",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string" },
                    "title": { "type": "string" },
                    "github_url": { "type": "string" },
                    "labels": { "type": "array", "items": { "type": "string" } },
                    "assignees": { "type": "array", "items": { "type": "string" } }
                }
            }
        },
        "issues_skipped": {
            "type": "array",
            "description": "Findings that were not filed and why",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string" },
                    "reason": { "type": "string" }
                }
            }
        },
        "issues_consolidated": {
            "type": "array",
            "description": "Findings folded into another finding's issue",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": { "type": "string" },
                    "consolidated_into": { "type": "string" }
                }
            }
        },
        "errors": {
            "type": "array",
            "description": "Any errors encountered",
            "items": { "type": "string" }
        }
    },
    "required": ["summary", "issues_filed", "issues_skipped", "issues_consolidated", "errors"]
}