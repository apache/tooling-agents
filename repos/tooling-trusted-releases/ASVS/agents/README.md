# ASVS Pipeline Agents

Each subdirectory contains one Gofannon agent used in the ASVS security audit pipeline.

| Agent | Role | Pipeline step |
|-------|------|---------------|
| [`ingest_asvs_standard`](ingest_asvs_standard/) | Fetch and ingest ASVS v5.0.0 requirements into data store | Setup |
| [`download_github_repo_to_datastore`](download_github_repo_to_datastore/) | Download all files from a GitHub repo into data store | Setup |
| [`fetch_audit_guidance`](fetch_audit_guidance/) | Download a GitHub subdirectory into `audit_guidance` namespace | Setup |
| [`fetch_github_files_to_config_store`](fetch_github_files_to_config_store/) | Download specific files into `config` namespace | Setup |
| [`fetch_and_compile_github_open_issues`](fetch_and_compile_github_open_issues/) | Fetch open GitHub issues into `open_issues` namespace | Setup |
| [`orchestrate_asvs_audit_to_github`](orchestrate_asvs_audit_to_github/) | Loop over sections, call audit agent, push reports to GitHub | Orchestration |
| [`run_asvs_security_audit`](run_asvs_security_audit/) | Core audit agent — 6-step analysis pipeline per ASVS requirement | Audit |
| [`add_markdown_file_to_github_directory`](add_markdown_file_to_github_directory/) | Create or update a markdown file in a GitHub repo | Utility |
| [`consolidate_asvs_security_audit_reports`](consolidate_asvs_security_audit_reports/) | Multi-directory consolidation with level tracking and deduplication | Post-processing |

## File structure

Each agent directory contains:

- **`prompt.md`** — the original prompt/description used when creating the agent in Gofannon
- **`code.py`** — the production agent code (paste directly into Gofannon's code editor)

## Creating agents in Gofannon

1. Navigate to `http://localhost:3000`
2. Click "Create Agent"
3. Paste the contents of `prompt.md` as the agent description
4. Set the compose model (typically Sonnet) and invokable model as appropriate
5. Click "Generate" to get initial code, then replace it with the contents of `code.py`
6. Test in sandbox, then deploy
