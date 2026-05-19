# asvs_guidance_ingest
#
# Fetches one file from a GitHub repo's root (or anywhere in the tree)
# and stores it in CouchDB under the audit_guidance namespace for that
# repo. One agent call = one file landed.
#
# Storage layout (matches asvs_guidance_upload's convention):
#   namespace: audit_guidance:{short repo name}
#   key:       {filename}
#   value:     decoded file contents
#
# Examples:
#   ingest("apache/airflow", "AGENTS.md")
#     → audit_guidance:airflow → AGENTS.md
#   ingest("apache/airflow", "airflow-core/docs/security/security_model.rst")
#     → audit_guidance:airflow → airflow-core/docs/security/security_model.rst
#
# The "short repo name" is the segment after the slash in `repo` (i.e.,
# the GitHub repository name without owner). Owner is used only to
# locate the file on GitHub, not in the CouchDB namespace, so multiple
# forks of the same repo collapse to one guidance namespace by design.
# If you need to differentiate forks or branches, override by calling
# asvs_guidance_upload directly with an explicit `namespace` field.
#
# Pair with the orchestrator's `supplementalData: audit_guidance:{repo}`
# input on the audit run, and (post the supplemental-namespace filter
# fix) the file will load fully into every Opus call regardless of
# discovery's file scope.
#
# Inputs (input_dict, top-level fields):
#   repo     (required): owner/repo, e.g. "apache/airflow".
#                        Accepts plain "owner/repo", a github.com URL,
#                        or a github tree URL — the regex handles all
#                        three; only the first two segments matter.
#   token    (optional): GitHub PAT for private repos or to lift the
#                        60/hr anonymous rate limit. Omit for public
#                        repos with low traffic.
#   filename (required): path to the file relative to the repo root.
#                        For root-level files, just the filename
#                        ("AGENTS.md"). For nested files, include the
#                        path ("docs/security/security_model.rst").
#
# Output:
#   outputText: success summary with namespace, key, and size, or
#               "Error: <message>" on failure.
#
# Example invocation:
#
#   await gofannon_client.call(
#       agent_name="asvs_guidance_ingest",
#       input_dict={
#           "repo": "apache/airflow",
#           "token": GITHUB_TOKEN,
#           "filename": "AGENTS.md",
#       },
#   )
#   # → Stored at audit_guidance:airflow → AGENTS.md
#   # → Use supplementalData: audit_guidance:airflow on airflow audit runs.


async def run(input_dict, tools):
    # Imports go INSIDE run() because gofannon recompiles the function in
    # a fresh namespace at invocation time — module-level imports at the
    # top of the file don't survive. Without these, you get errors like
    # "name 'base64' is not defined" the first time the runtime hits one.
    # Same lesson as the consolidate agent's error wrapper earlier in
    # the project.
    import base64
    import re

    import httpx

    try:
        # --- Parse inputs ---
        # Top-level input_dict fields: repo (required), filename
        # (required), token (optional). No JSON envelope — these come
        # straight off input_dict.
        repo = (input_dict.get("repo") or "").strip().strip("/")
        token = (input_dict.get("token") or "").strip()
        filename = (input_dict.get("filename") or "").strip().lstrip("/")

        if not repo:
            return {"outputText": "Error: 'repo' is required (e.g., 'apache/airflow')"}
        if not filename:
            return {"outputText": "Error: 'filename' is required (e.g., 'AGENTS.md')"}

        # --- Resolve owner / short name from various repo input shapes ---
        # Accept "owner/repo", "github.com/owner/repo[/...]", or
        # "https://github.com/owner/repo[/...]". Only the first two
        # segments are meaningful; any subdirectory the user tacked on
        # is ignored (project-level guidance applies repo-wide, not
        # per-subcomponent).
        gh_match = re.match(
            r"(?:https?://)?github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
            repo,
        )
        if gh_match:
            owner, repo_short = gh_match.group(1), gh_match.group(2)
        else:
            parts = repo.split("/")
            if len(parts) < 2:
                return {
                    "outputText": (
                        f"Error: 'repo' must be in owner/repo form, got '{repo}'"
                    )
                }
            owner, repo_short = parts[0], parts[1]

        # Reject control characters in components that flow into the
        # CouchDB key/namespace.
        for arg_name, arg_value in (
            ("repo_short", repo_short),
            ("filename", filename),
        ):
            if any(ch in arg_value for ch in ("\n", "\r", "\t", "\0")):
                return {
                    "outputText": (
                        f"Error: '{arg_name}' contains illegal whitespace/control "
                        f"characters"
                    )
                }

        # --- Fetch from GitHub Contents API ---
        # https://docs.github.com/en/rest/repos/contents#get-repository-content
        api_url = f"https://api.github.com/repos/{owner}/{repo_short}/contents/{filename}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                resp = await client.get(api_url, headers=headers)
            except Exception as e:
                err_type = type(e).__name__
                err_msg = str(e) or "(no message)"
                return {
                    "outputText": (
                        f"Error: GitHub fetch failed: {err_type}: {err_msg}"
                    )
                }

        # Map the common HTTP failure modes to actionable messages
        # rather than letting raw status codes / response bodies surface.
        if resp.status_code == 404:
            return {
                "outputText": (
                    f"Error: '{filename}' not found in {owner}/{repo_short} (404). "
                    f"Check the filename spelling and the path; for files outside "
                    f"the repo root, include the relative path "
                    f"(e.g., 'docs/security/security_model.rst')."
                )
            }
        if resp.status_code == 401:
            return {
                "outputText": (
                    "Error: GitHub authentication failed (401). Token invalid, "
                    "expired, or lacks read access to the repo."
                )
            }
        if resp.status_code == 403:
            err_body = resp.text[:300]
            return {
                "outputText": (
                    f"Error: GitHub forbidden (403). Likely rate-limited "
                    f"(anonymous limit is 60/hour — pass a token to lift it) "
                    f"or token lacks the contents:read scope. Body: {err_body}"
                )
            }
        if resp.status_code != 200:
            return {
                "outputText": (
                    f"Error: GitHub returned HTTP {resp.status_code}: "
                    f"{resp.text[:300]}"
                )
            }

        try:
            data = resp.json()
        except Exception as e:
            return {"outputText": f"Error: GitHub response was not JSON: {e}"}

        # The Contents API returns a list for directories. Directories
        # aren't supported here — keep the agent's contract one-file-
        # per-call so failures are easy to diagnose.
        if isinstance(data, list):
            return {
                "outputText": (
                    f"Error: '{filename}' resolved to a directory in "
                    f"{owner}/{repo_short}. This agent ingests single files; "
                    f"call once per file you want stored."
                )
            }
        if not isinstance(data, dict):
            return {
                "outputText": (
                    f"Error: unexpected GitHub response shape: {type(data).__name__}"
                )
            }

        if data.get("type") != "file":
            return {
                "outputText": (
                    f"Error: '{filename}' is not a regular file "
                    f"(type={data.get('type', 'unknown')!r})."
                )
            }

        encoding = data.get("encoding", "")
        content_b64 = data.get("content", "")
        if encoding != "base64":
            return {
                "outputText": (
                    f"Error: unexpected encoding '{encoding}' (expected 'base64')"
                )
            }

        try:
            content_bytes = base64.b64decode(content_b64)
        except Exception as e:
            return {"outputText": f"Error: failed to base64-decode file content: {e}"}

        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "outputText": (
                    f"Error: file content is not valid UTF-8. Guidance docs "
                    f"should be plain text (markdown, RST, plain text). Binary "
                    f"files are not supported."
                )
            }

        if not content.strip():
            return {
                "outputText": (
                    f"Error: file is empty. Refusing to store an empty guidance "
                    f"document — would silently provide no context to audits."
                )
            }

        # --- Store in CouchDB under audit_guidance:{repo_short} ---
        namespace = f"audit_guidance:{repo_short}"
        key = filename

        try:
            ns = data_store.use_namespace(namespace)
            ns.set(key, content)
        except Exception as e:
            err_type = type(e).__name__
            err_msg = str(e) or "(no message)"
            return {
                "outputText": (
                    f"Error: failed to write to {namespace} → {key}: "
                    f"{err_type}: {err_msg}"
                )
            }

        size = len(content)
        return {
            "outputText": (
                f"Fetched {owner}/{repo_short}/{filename} ({size} chars) and "
                f"stored at {namespace} → {key}. To use during {repo_short} "
                f"audits, pass supplementalData: {namespace} to the orchestrator."
            )
        }

    except Exception as e:
        # Catch-all so unexpected failures surface as Error: messages
        # rather than empty outputText. MUST live inside run() — the
        # gofannon runtime recompiles run() in a fresh namespace, so
        # module-level wrappers don't survive (lesson from the
        # consolidate agent earlier in this project).
        err_type = type(e).__name__
        err_msg = str(e) or "(no message)"
        return {"outputText": f"Error: {err_type}: {err_msg}"}