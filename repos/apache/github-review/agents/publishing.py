from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        owner = input_dict.get("owner", "apache")
        all_repos_raw = input_dict.get("all_repos", "false")
        repos_str = input_dict.get("repos", "").strip()
        github_pat = input_dict.get("github_pat", "").strip()
        clear_cache_raw = input_dict.get("clear_cache", "false")

        all_repos = str(all_repos_raw).lower().strip() in ("true", "1", "yes")
        clear_cache = str(clear_cache_raw).lower().strip() in ("true", "1", "yes")

        if not github_pat and (all_repos or not repos_str):
            return {"outputText": "Error: `github_pat` is required for org-wide scanning. "
                    "Unauthenticated GitHub API limit is 60 req/hr — too low for this agent.\n\n"
                    "Create a fine-grained PAT with **Contents: read** at https://github.com/settings/tokens"}

        if not all_repos and not repos_str:
            return {"outputText": "Error: provide a comma-separated repo list in `repos`, "
                    "or set `all_repos` to `true` to scan the entire org."}

        provider = "bedrock"
        model = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        configured_params = {"temperature": 0, "reasoning_effort": "disable", "max_tokens": 2048}

        GITHUB_API = "https://api.github.com"
        gh_headers = {"Accept": "application/vnd.github.v3+json"}
        if github_pat:
            gh_headers["Authorization"] = f"token {github_pat}"

        classification_cache = data_store.use_namespace(f"ci-classification:{owner}")
        workflow_content_cache = data_store.use_namespace(f"ci-workflows:{owner}")
        report_ns = data_store.use_namespace(f"ci-report:{owner}")

        if clear_cache:
            print("Clearing cached data...", flush=True)
            for ns in [classification_cache, workflow_content_cache, report_ns]:
                for key in ns.list_keys():
                    ns.delete(key)
            print("Cache cleared.", flush=True)

        # --- Preflight ---
        print("Running preflight checks...", flush=True)
        preflight_resp = await http_client.get(f"{GITHUB_API}/rate_limit", headers=gh_headers, timeout=15.0)

        if preflight_resp.status_code == 401:
            return {"outputText": "Error: GitHub PAT is invalid or expired (HTTP 401).\n"
                    "Check your token at https://github.com/settings/tokens"}

        if preflight_resp.status_code == 200:
            rate_data = preflight_resp.json()
            core = rate_data.get("resources", {}).get("core", {})
            remaining = core.get("remaining", "?")
            limit = core.get("limit", "?")
            print(f"  GitHub API: {remaining}/{limit} requests remaining", flush=True)
            if isinstance(remaining, int) and remaining < 50:
                print(f"  WARNING: Very low rate limit remaining!", flush=True)

        if repos_str:
            test_repo = repos_str.split(",")[0].strip()
            test_url = f"{GITHUB_API}/repos/{owner}/{test_repo}/contents/.github/workflows"
            print(f"  Testing access: {test_url}", flush=True)
            test_resp = await http_client.get(test_url, headers=gh_headers, timeout=15.0)
            print(f"  Response: HTTP {test_resp.status_code}", flush=True)
            if test_resp.status_code == 404:
                root_resp = await http_client.get(
                    f"{GITHUB_API}/repos/{owner}/{test_repo}", headers=gh_headers, timeout=15.0)
                if root_resp.status_code == 404:
                    return {"outputText": f"Error: repo `{owner}/{test_repo}` not found (HTTP 404)."}
            elif test_resp.status_code == 403:
                return {"outputText": f"Error: HTTP 403 accessing `{owner}/{test_repo}`.\n{test_resp.text[:300]}"}

        print("Preflight complete.\n", flush=True)


        CLASSIFICATION_PROMPT = (
            "You are an expert at analyzing GitHub Actions workflow YAML files. "
            "Examine the workflow and determine whether it publishes/deploys artifacts to any package registry or artifact repository.\n\n"
            "Respond ONLY with a JSON object (no markdown fences, no explanation):\n"
            "{\n"
            '  "publishes_to_registry": true/false,\n'
            '  "category": "release_artifact|snapshot_artifact|ci_infrastructure|documentation|none",\n'
            '  "ecosystems": [],\n'
            '  "publish_actions": [],\n'
            '  "publish_commands": [],\n'
            '  "trigger": "",\n'
            '  "auth_method": "",\n'
            '  "security_notes": [],\n'
            '  "workflow_name": "",\n'
            '  "summary": "",\n'
            '  "confidence": "high|medium|low"\n'
            "}\n\n"
            "CATEGORY DEFINITIONS — choose exactly one:\n"
            "- release_artifact: Publishing versioned release packages to PUBLIC registries that end users consume. "
            "Examples: Maven Central, PyPI (twine upload), Docker Hub, npm, crates.io, NuGet, RubyGems, Apache SVN dist, Helm repos. "
            "Also includes release candidates pushed to these registries.\n"
            "- snapshot_artifact: Publishing snapshot/nightly builds to staging registries. "
            "Examples: Apache Snapshots Maven repo, nightly Docker images to GCR/ECR, nightly Python wheels to GCS/S3, pre-release SDK containers.\n"
            "- ci_infrastructure: Pushing Docker images used ONLY for CI/CD build caching, test execution, or build acceleration. "
            "These are NOT consumed by end users. "
            "Examples: CI cache images to GHCR, test container images to GCR for integration tests, "
            "self-hosted runner images, benchmark containers, Flink/Spark test containers. "
            "Key signal: images pushed to ghcr.io/{org}/{repo} with cache tags, or test images to gcr.io/{org}-testing/*.\n"
            "- documentation: Publishing docs, websites, metrics dashboards, coverage reports. "
            "Examples: S3 sync of docs, GitHub Pages deploy, GCS website upload, Codecov upload.\n"
            "- none: Workflow does not publish anything to any registry or external location. "
            "This includes: uploading to GitHub Actions artifact storage (actions/upload-artifact) which is ephemeral, "
            "git push to branches within the same repo, creating GitHub Release notes without downloadable binaries.\n\n"
            "IMPORTANT DISTINCTIONS:\n"
            "- A workflow that pushes CI cache images to GHCR is ci_infrastructure, NOT release_artifact.\n"
            "- A workflow that uploads docs to S3 is documentation, NOT release_artifact.\n"
            "- A workflow that pushes test catalog data to a git branch is none (it's just a git commit).\n"
            "- A workflow that uploads wheels to GCS for staging (not PyPI) is snapshot_artifact.\n"
            "- A workflow that creates a GitHub Release with notes is none unless it also attaches downloadable artifacts.\n"
            "- Coverage uploads (Codecov) are documentation, not publishing.\n"
            "- Upload to GitHub Actions artifacts (actions/upload-artifact) is none — that's ephemeral CI storage, not a registry.\n\n"
            "ECOSYSTEM VALUES — use ONLY these exact strings:\n"
            "maven_central (for ALL Maven repos including Apache Snapshots, Nexus staging, etc.), "
            "pypi, docker_hub, npm, crates_io, nuget, rubygems, apache_dist, helm, "
            "ghcr, gcr, gcs, s3, github_pages, github_packages, github_releases\n"
            "DO NOT invent new ecosystem names like 'maven_snapshots' or 'apache_snapshots' — "
            "use maven_central for all Maven/Gradle/Nexus publishing.\n\n"
            "SECURITY ANALYSIS — be precise about the TRUST LEVEL of interpolated values:\n\n"
            "CRITICAL (real injection risk from untrusted external input):\n"
            "  Direct ${{ }} interpolation of UNTRUSTED user input in a `run:` block. "
            "Untrusted input includes: github.event.pull_request.title, github.event.issue.body, "
            "github.event.comment.body, github.event.pull_request.head.ref, github.event.review.body, "
            "or any value controllable by external contributors who are not committers.\n\n"
            "LOW (secret/credential leakage risk — values are trusted but should use env: pattern):\n"
            "  Direct ${{ secrets.* }} interpolation in a `run:` block. The secret value is trusted "
            "(not attacker-controlled), but direct interpolation risks leaking it in logs if GitHub's "
            "automatic masking is bypassed. Best practice: pass through env: block.\n\n"
            "LOW (trusted committer input — not externally exploitable):\n"
            "  Direct ${{ github.event.inputs.* }} interpolation in `run:` blocks for workflow_dispatch workflows "
            "that are only triggerable by repository committers/maintainers. The inputs are free-form text "
            "but from trusted sources. Main risk is accidental command injection from malformed version strings, "
            "not malicious exploitation. Note: if the workflow is triggerable by external contributors, "
            "this becomes CRITICAL.\n\n"
            "LOW (GitHub-controlled values):\n"
            "  github.actor, github.sha, github.repository, github.ref directly in `run:` blocks. "
            "Not user-injectable.\n\n"
            "SAFE (do NOT flag):\n"
            "  - Values passed through `env:` blocks then referenced as shell variables.\n"
            "  - ${{ }} used only in `with:` blocks passed to actions.\n"
            "  - ${{ }} used in `concurrency.group` (not a shell execution context).\n\n"
            "For each note, return a STRING prefixed with [CRITICAL], [LOW], or [INFO].\n"
            "Example: \"[LOW] secrets.NEXUS_PW directly interpolated in run block at step 'Auth'. "
            "Trusted value but risks log leakage. Use env: block instead.\"\n\n"
            "If no publishing detected, set publishes_to_registry to false, category to \"none\", and ecosystems to []."
        )

        prompt_tokens = count_tokens(CLASSIFICATION_PROMPT, provider, model)
        ctx_window = get_context_window(provider, model)
        max_yaml_tokens = int(ctx_window * 0.75) - prompt_tokens - 300


        async def github_get(url, params=None, max_retries=5):
            last_resp = None
            for attempt in range(max_retries):
                try:
                    resp = await http_client.get(url, headers=gh_headers, params=params, timeout=30.0)
                    last_resp = resp
                except Exception as e:
                    print(f"  HTTP error (attempt {attempt+1}): {str(e)[:100]}", flush=True)
                    if attempt < max_retries - 1:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return None

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    print(f"  Rate limited, waiting {retry_after}s...", flush=True)
                    await asyncio.sleep(min(retry_after, 120))
                    continue

                if resp.status_code == 403:
                    remaining = resp.headers.get("X-RateLimit-Remaining", "")
                    if remaining == "0":
                        print(f"  Rate limit exhausted, waiting 60s...", flush=True)
                        await asyncio.sleep(60)
                        continue

                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining:
                    try:
                        rem_int = int(remaining)
                        if rem_int < 50:
                            print(f"  WARNING: {rem_int} API requests remaining", flush=True)
                            await asyncio.sleep(5)
                        elif rem_int < 100:
                            await asyncio.sleep(2)
                    except ValueError:
                        pass

                return resp
            return last_resp


        def parse_classification(raw_text):
            cleaned = raw_text.strip()
            if cleaned.startswith("```"):
                first_nl = cleaned.find("\n")
                cleaned = cleaned[first_nl + 1:] if first_nl != -1 else cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()
            if not cleaned.startswith("{"):
                start = cleaned.find("{")
                if start != -1:
                    cleaned = cleaned[start:]
            if not cleaned.endswith("}"):
                end = cleaned.rfind("}")
                if end != -1:
                    cleaned = cleaned[:end + 1]
            return json.loads(cleaned)


        def safe_str(val):
            if val is None:
                return ""
            if isinstance(val, dict):
                return json.dumps(val)
            if isinstance(val, list):
                return ", ".join(str(v) for v in val)
            return str(val).strip()


        def normalize_note(note):
            if isinstance(note, str):
                return note.strip()
            if isinstance(note, dict):
                risk = note.get("risk_level") or note.get("risk") or note.get("level") or "INFO"
                desc = note.get("description") or note.get("details") or note.get("detail") or str(note)
                return f"[{risk}] {desc}".strip()
            return str(note).strip()


        def downgrade_contradictions(text):
            """Refine severity based on what the note actually describes."""
            if "[CRITICAL]" not in text:
                return text
            text_lower = text.lower()

            # Env-mediated patterns are safe, not even LOW
            env_phrases = [
                "env-mediated", "safe pattern", "passed through env",
                "through env: block", "through env block", "env: block first",
                "via env", "in env block", "environment variable usage",
                "env block passed to", "via environment variable",
                "environment variable",
            ]
            for phrase in env_phrases:
                if phrase.lower() in text_lower:
                    return text.replace("[CRITICAL]", "[INFO-DOWNGRADED]")

            # Secrets interpolation — trusted values, leakage risk only
            secret_phrases = [
                "secrets.", "secret.", "nexus_user", "nexus_pw", "nexus_password",
                "dockerhub_token", "dockerhub_user", "pypi_api_token",
                "gpg_private_key", "gpg_passphrase", "gpg_secret_key",
                "svn_username", "svn_password",
            ]
            for phrase in secret_phrases:
                if phrase.lower() in text_lower:
                    return text.replace("[CRITICAL]", "[LOW-LEAKAGE]")

            # workflow_dispatch inputs from committers — trusted but sloppy
            dispatch_phrases = [
                "workflow_dispatch input", "inputs.release", "inputs.rc",
                "inputs.apache_id", "inputs.apache_password", "inputs.repo_token",
                "inputs.version", "inputs.branch", "github.event.inputs.",
            ]
            for phrase in dispatch_phrases:
                if phrase.lower() in text_lower:
                    return text.replace("[CRITICAL]", "[LOW-TRUSTED-INPUT]")

            return text


        ECOSYSTEM_ALIASES = {
            "maven_snapshots": "maven_central",
            "apache_snapshots": "maven_central",
            "maven": "maven_central",
            "nexus": "maven_central",
            "docker": "docker_hub",
            "dockerhub": "docker_hub",
            "github_artifacts": "github_actions_artifacts",
        }

        def normalize_ecosystem(eco):
            eco = safe_str(eco).lower().strip().replace(" ", "_")
            return ECOSYSTEM_ALIASES.get(eco, eco)


        TRUSTED_PUBLISHING_ECOSYSTEMS = {
            "pypi": {
                "label": "PyPI",
                "mechanism": "OIDC Trusted Publisher via pypa/gh-action-pypi-publish",
                "docs": "https://docs.pypi.org/trusted-publishers/",
            },
            "npm": {
                "label": "npm",
                "mechanism": "npm provenance with OIDC",
                "docs": "https://docs.npmjs.com/generating-provenance-statements",
            },
            "nuget": {
                "label": "NuGet",
                "mechanism": "Sigstore-based Trusted Publishing",
                "docs": "https://devblogs.microsoft.com/nuget/introducing-trusted-publishers/",
            },
            "rubygems": {
                "label": "RubyGems",
                "mechanism": "OIDC Trusted Publisher",
                "docs": "https://guides.rubygems.org/trusted-publishing/",
            },
            "crates_io": {
                "label": "crates.io",
                "mechanism": "OIDC Trusted Publishing",
                "docs": "https://doc.rust-lang.org/cargo/reference/registry-authentication.html",
            },
        }

        TOKEN_PATTERNS = [
            "token", "password", "secret", "api_key", "apikey",
            "nexus_user", "nexus_pw", "pypi_api_token",
        ]

        def uses_long_lived_token(auth_str):
            auth_lower = auth_str.lower()
            if "oidc" in auth_lower or "trusted publisher" in auth_lower or "id-token" in auth_lower:
                return False
            for pat in TOKEN_PATTERNS:
                if pat in auth_lower:
                    return True
            return False


        def sanitize_md(value):
            if not value:
                return "N/A"
            return str(value).replace("|", "∣").replace("\n", " ").strip()


        def truncate_yaml(content):
            yaml_tokens = count_tokens(content, provider, model)
            if yaml_tokens <= max_yaml_tokens:
                return content
            lines_list = content.split("\n")
            truncated = []
            running = 0
            for line in lines_list:
                lt = count_tokens(line, provider, model)
                if running + lt > max_yaml_tokens:
                    truncated.append("# ... [TRUNCATED] ...")
                    break
                truncated.append(line)
                running += lt
            return "\n".join(truncated)


        CATEGORY_LABELS = {
            "release_artifact": "Release Artifacts",
            "snapshot_artifact": "Snapshot / Nightly Artifacts",
            "ci_infrastructure": "CI Infrastructure Images",
            "documentation": "Documentation / Websites",
            "none": "Non-publishing",
        }


        # ===== STEP 1: Get repo list =====
        if all_repos:
            print(f"Fetching all repos for {owner}...", flush=True)
            repo_names = []
            skipped_archived = 0
            page = 1
            while True:
                resp = await github_get(
                    f"{GITHUB_API}/orgs/{owner}/repos",
                    params={"per_page": 100, "page": page, "sort": "pushed", "type": "public"})
                if resp is None or resp.status_code != 200:
                    break
                page_data = resp.json()
                if not page_data or not isinstance(page_data, list):
                    break
                for r in page_data:
                    if isinstance(r, dict) and "name" in r:
                        if r.get("archived"):
                            skipped_archived += 1
                        else:
                            repo_names.append(r["name"])
                if 'rel="next"' not in resp.headers.get("Link", ""):
                    break
                page += 1
                await asyncio.sleep(0.3)
            print(f"Found {len(repo_names)} active repos ({skipped_archived} archived skipped)", flush=True)
        else:
            repo_names = [r.strip() for r in repos_str.split(",") if r.strip()]
            print(f"Using provided list of {len(repo_names)} repos", flush=True)

        if not repo_names:
            return {"outputText": f"# CI Registry Publishing Analysis: {owner}\n\nNo repositories found."}

        print(f"\nStarting workflow scan of {len(repo_names)} repos...\n", flush=True)

        # ===== STEP 2: Fetch workflows and classify =====
        all_results = {}
        stats = {"repos_scanned": 0, "repos_with_workflows": 0, "total_workflows": 0,
                 "total_classified": 0, "cache_hits": 0, "errors": []}

        for repo_idx, repo_name in enumerate(repo_names):
            stats["repos_scanned"] += 1

            if (repo_idx + 1) % 25 == 0 or repo_idx == 0:
                print(f"[{repo_idx + 1}/{len(repo_names)}] Scanning {repo_name}... "
                      f"({stats['total_workflows']} wfs, {stats['total_classified']} classified, "
                      f"{stats['cache_hits']} cached)", flush=True)

            meta_key = f"__meta__:{repo_name}"
            cached_meta = classification_cache.get(meta_key)

            if cached_meta and cached_meta.get("complete"):
                wf_names = cached_meta.get("workflows", [])
                if wf_names:
                    repo_results = []
                    for wf_name in wf_names:
                        cached = classification_cache.get(f"{repo_name}:{wf_name}")
                        if cached:
                            repo_results.append(cached)
                            stats["cache_hits"] += 1
                    if repo_results:
                        all_results[repo_name] = repo_results
                        stats["repos_with_workflows"] += 1
                        stats["total_workflows"] += len(repo_results)
                        stats["total_classified"] += len(repo_results)
                continue

            resp = await github_get(f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/.github/workflows")

            if resp is None:
                stats["errors"].append(f"{owner}/{repo_name}: network error")
                continue
            if resp.status_code == 404:
                classification_cache.set(meta_key, {"complete": True, "workflows": []})
                continue
            if resp.status_code != 200:
                stats["errors"].append(f"{owner}/{repo_name}: HTTP {resp.status_code}")
                continue

            try:
                dir_listing = resp.json()
            except Exception:
                classification_cache.set(meta_key, {"complete": True, "workflows": []})
                continue

            if not isinstance(dir_listing, list):
                classification_cache.set(meta_key, {"complete": True, "workflows": []})
                continue

            yaml_files = [f for f in dir_listing
                          if isinstance(f, dict) and f.get("name", "").endswith((".yml", ".yaml"))]

            if not yaml_files:
                classification_cache.set(meta_key, {"complete": True, "workflows": []})
                continue

            stats["repos_with_workflows"] += 1
            repo_results = []
            workflow_names = []

            for wf_file in yaml_files:
                wf_name = wf_file.get("name", "unknown")
                workflow_names.append(wf_name)
                stats["total_workflows"] += 1

                wf_cache_key = f"{repo_name}:{wf_name}"
                cached_cls = classification_cache.get(wf_cache_key)
                if cached_cls:
                    repo_results.append(cached_cls)
                    stats["total_classified"] += 1
                    stats["cache_hits"] += 1
                    continue

                raw_url = wf_file.get("download_url")
                yaml_content = None
                if raw_url:
                    try:
                        content_resp = await http_client.get(raw_url, follow_redirects=True, timeout=30.0)
                        if content_resp.status_code == 200:
                            yaml_content = content_resp.text
                    except Exception:
                        pass

                if yaml_content is None:
                    repo_results.append({"file": wf_name, "error": "Could not fetch", "publishes_to_registry": None})
                    continue

                workflow_content_cache.set(f"{repo_name}/{wf_name}", yaml_content)
                yaml_content = truncate_yaml(yaml_content)

                llm_response = None
                try:
                    messages = [{"role": "user", "content": (
                        f"{CLASSIFICATION_PROMPT}\n\n---\n"
                        f"File: {owner}/{repo_name}/.github/workflows/{wf_name}\n---\n\n{yaml_content}"
                    )}]

                    llm_response, _ = await call_llm(
                        provider=provider, model=model, messages=messages,
                        parameters=configured_params, user_service=None, user_id=None)

                    classification = parse_classification(llm_response)
                    classification["file"] = wf_name
                    repo_results.append(classification)
                    classification_cache.set(wf_cache_key, classification)
                    stats["total_classified"] += 1

                except json.JSONDecodeError:
                    repo_results.append({"file": wf_name, "error": "JSON parse error",
                                         "raw_response": (llm_response or "")[:300], "publishes_to_registry": None})
                    stats["errors"].append(f"{owner}/{repo_name}/.github/workflows/{wf_name}: JSON parse error")
                except Exception as e:
                    repo_results.append({"file": wf_name, "error": str(e)[:200], "publishes_to_registry": None})
                    stats["errors"].append(f"{owner}/{repo_name}/.github/workflows/{wf_name}: {str(e)[:80]}")

                await asyncio.sleep(0.3)

            if repo_results:
                all_results[repo_name] = repo_results
            classification_cache.set(meta_key, {"complete": True, "workflows": workflow_names})

        print(f"\n{'=' * 60}", flush=True)
        print(f"Scan complete! {stats['repos_scanned']} repos, {stats['total_classified']} classified "
              f"({stats['cache_hits']} cached), {len(stats['errors'])} errors", flush=True)
        print(f"{'=' * 60}\n", flush=True)

        # ===== STEP 3: Build report =====

        report_title = (f"CI Registry Publishing Analysis: {owner}/{repo_names[0]}"
                        if len(repo_names) == 1
                        else f"CI Registry Publishing Analysis: {owner}")

        lines = []
        lines.append(f"Scanned **{stats['repos_scanned']}** repositories, "
                     f"**{stats['repos_with_workflows']}** had GitHub Actions workflow files, "
                     f"**{stats['total_workflows']}** total workflows analyzed.\n")

        # --- Collect workflows by category ---
        by_category = {"release_artifact": [], "snapshot_artifact": [], "ci_infrastructure": [], "documentation": []}
        ecosystem_counts = {}
        security_notes_all = []
        publishing_repos = set()

        for repo, workflows in all_results.items():
            for w in workflows:
                if not w.get("publishes_to_registry"):
                    continue

                cat = safe_str(w.get("category")).lower().strip()
                ecosystems_raw = [normalize_ecosystem(e) for e in (w.get("ecosystems") or [])]

                if cat == "snapshot_artifact" and all(e == "github_actions_artifacts" for e in ecosystems_raw):
                    continue

                if cat not in by_category:
                    cat = "release_artifact"

                entry = {"repo": repo, **w}
                entry["ecosystems"] = ecosystems_raw
                by_category[cat].append(entry)

                # Only count as "publishing" for supply-chain purposes if release or snapshot
                if cat in ("release_artifact", "snapshot_artifact"):
                    publishing_repos.add(repo)

                for eco in ecosystems_raw:
                    if eco and eco != "github_actions_artifacts":
                        ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + 1

                for raw_note in (w.get("security_notes") or []):
                    note = downgrade_contradictions(normalize_note(raw_note)) if raw_note else ""
                    if note:
                        security_notes_all.append({"repo": repo, "file": w.get("file", "?"), "note": note, "category": cat})

        release_wfs = by_category["release_artifact"]
        snapshot_wfs = by_category["snapshot_artifact"]
        ci_wfs = by_category["ci_infrastructure"]
        doc_wfs = by_category["documentation"]

        # --- Executive Summary ---
        lines.append("## Executive Summary\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Repositories scanned | {stats['repos_scanned']} |")
        lines.append(f"| Repositories with workflows | {stats['repos_with_workflows']} |")
        lines.append(f"| Total workflow files | {stats['total_workflows']} |")
        lines.append(f"| **Repos publishing to registries** | **{len(publishing_repos)}** |")
        lines.append(f"| Release artifact workflows | {len(release_wfs)} |")
        lines.append(f"| Snapshot / nightly workflows | {len(snapshot_wfs)} |")
        lines.append(f"| CI infrastructure image workflows | {len(ci_wfs)} |")
        lines.append(f"| Documentation / website workflows | {len(doc_wfs)} |")
        lines.append(f"| Security notes flagged | {len(security_notes_all)} |")
        lines.append("")

        # --- Ecosystem Distribution ---
        release_ecosystems = {}
        for w in release_wfs + snapshot_wfs:
            for eco in (w.get("ecosystems") or []):
                if eco and eco != "github_actions_artifacts":
                    release_ecosystems[eco] = release_ecosystems.get(eco, 0) + 1

        if release_ecosystems:
            lines.append("## Package Ecosystem Distribution (releases + snapshots only)\n")
            total_re = sum(release_ecosystems.values())
            lines.append("| Ecosystem | Workflows | Percentage |")
            lines.append("|-----------|-----------|------------|")
            for eco, count in sorted(release_ecosystems.items(), key=lambda x: -x[1]):
                pct = (count / total_re * 100) if total_re > 0 else 0
                lines.append(f"| {eco} | {count} | {pct:.1f}% |")
            lines.append("")

        # --- Trusted Publishing Opportunities ---
        tp_opportunities = []
        for w in release_wfs + snapshot_wfs:
            ecosystems = w.get("ecosystems") or []
            auth = safe_str(w.get("auth_method"))
            for eco in ecosystems:
                if eco in TRUSTED_PUBLISHING_ECOSYSTEMS and uses_long_lived_token(auth):
                    tp_info = TRUSTED_PUBLISHING_ECOSYSTEMS[eco]
                    tp_opportunities.append({
                        "repo": w.get("repo", "?"), "file": w.get("file", "?"),
                        "ecosystem": eco, "ecosystem_label": tp_info["label"],
                        "current_auth": auth, "mechanism": tp_info["mechanism"],
                        "docs": tp_info["docs"], "category": safe_str(w.get("category")),
                    })

        if tp_opportunities:
            lines.append("## Trusted Publishing Migration Opportunities\n")
            lines.append("These workflows publish to ecosystems that support OIDC Trusted Publishing "
                         "but currently use long-lived API tokens or passwords. "
                         "Migrating to Trusted Publishing eliminates stored secrets and reduces supply-chain risk.\n")

            tp_by_eco = {}
            for opp in tp_opportunities:
                tp_by_eco.setdefault(opp["ecosystem"], []).append(opp)

            for eco, opps in sorted(tp_by_eco.items()):
                info = TRUSTED_PUBLISHING_ECOSYSTEMS[eco]
                lines.append(f"### {info['label']}\n")
                lines.append(f"**Available mechanism:** {info['mechanism']}")
                lines.append(f"**Documentation:** {info['docs']}\n")
                lines.append("| Repository | Workflow | Current Auth | Category |")
                lines.append("|------------|----------|-------------|----------|")
                for opp in sorted(opps, key=lambda x: (x["repo"], x["file"])):
                    cat_label = CATEGORY_LABELS.get(opp["category"], opp["category"])
                    lines.append(f"| {opp['repo']} | `{opp['file']}` | {sanitize_md(opp['current_auth'])} | {cat_label} |")
                lines.append("")
        else:
            lines.append("## Trusted Publishing Migration Opportunities\n")
            lines.append("No workflows found that could migrate to Trusted Publishing.\n")

        # --- Release Workflows ---
        if release_wfs:
            lines.append("## Release Artifact Workflows\n")
            lines.append("These workflows publish versioned packages to public registries consumed by end users.\n")
            lines.append("| Repository | Workflow | Ecosystems | Trigger | Auth |")
            lines.append("|------------|----------|------------|---------|------|")
            for w in sorted(release_wfs, key=lambda x: (x["repo"], x.get("file", ""))):
                eco_str = ", ".join(w.get("ecosystems", [])) or "—"
                lines.append(
                    f"| {w['repo']} | `{w.get('file', '?')}` | {sanitize_md(eco_str)} "
                    f"| {sanitize_md(safe_str(w.get('trigger')))} "
                    f"| {sanitize_md(safe_str(w.get('auth_method')))} |")
            lines.append("")

        # --- Snapshot Workflows ---
        if snapshot_wfs:
            lines.append("## Snapshot / Nightly Artifact Workflows\n")
            lines.append("These workflows publish snapshot or nightly builds to staging registries.\n")
            lines.append("| Repository | Workflow | Ecosystems | Trigger | Auth |")
            lines.append("|------------|----------|------------|---------|------|")
            for w in sorted(snapshot_wfs, key=lambda x: (x["repo"], x.get("file", ""))):
                eco_str = ", ".join(w.get("ecosystems", [])) or "—"
                lines.append(
                    f"| {w['repo']} | `{w.get('file', '?')}` | {sanitize_md(eco_str)} "
                    f"| {sanitize_md(safe_str(w.get('trigger')))} "
                    f"| {sanitize_md(safe_str(w.get('auth_method')))} |")
            lines.append("")

        # --- CI Infrastructure (collapsed) ---
        if ci_wfs:
            lines.append("## CI Infrastructure Image Workflows\n")
            lines.append("These workflows push Docker images used only for CI build caching, test execution, "
                         "or build acceleration. They do not publish end-user artifacts.\n")
            lines.append(f"<details>\n<summary>Show {len(ci_wfs)} CI infrastructure workflows</summary>\n")
            lines.append("| Repository | Workflow | Target | Summary |")
            lines.append("|------------|----------|--------|---------|")
            for w in sorted(ci_wfs, key=lambda x: (x["repo"], x.get("file", ""))):
                eco_str = ", ".join(w.get("ecosystems", [])) or "—"
                lines.append(f"| {w['repo']} | `{w.get('file', '?')}` | {sanitize_md(eco_str)} | {sanitize_md(safe_str(w.get('summary')))} |")
            lines.append(f"\n</details>\n")

        # --- Documentation (collapsed) ---
        if doc_wfs:
            lines.append("## Documentation / Website Workflows\n")
            lines.append(f"<details>\n<summary>Show {len(doc_wfs)} documentation workflows</summary>\n")
            lines.append("| Repository | Workflow | Target | Summary |")
            lines.append("|------------|----------|--------|---------|")
            for w in sorted(doc_wfs, key=lambda x: (x["repo"], x.get("file", ""))):
                eco_str = ", ".join(w.get("ecosystems", [])) or "—"
                lines.append(f"| {w['repo']} | `{w.get('file', '?')}` | {sanitize_md(eco_str)} | {sanitize_md(safe_str(w.get('summary')))} |")
            lines.append(f"\n</details>\n")

        # --- Security Notes by severity ---
        critical_notes = [sn for sn in security_notes_all if "[CRITICAL]" in sn["note"]]
        leakage_notes = [sn for sn in security_notes_all if "[LOW-LEAKAGE]" in sn["note"]]
        trusted_input_notes = [sn for sn in security_notes_all if "[LOW-TRUSTED-INPUT]" in sn["note"]]
        downgraded_notes = [sn for sn in security_notes_all if "[INFO-DOWNGRADED]" in sn["note"]]
        low_notes = [sn for sn in security_notes_all if sn["note"].startswith("[LOW]")]

        if critical_notes:
            lines.append("## Security: Critical — Untrusted Input Injection\n")
            lines.append("Direct `${{ }}` interpolation of **untrusted external input** in `run:` blocks. "
                         "These are real script injection vectors exploitable by external contributors.\n")
            for sn in critical_notes:
                lines.append(f"- **{owner}/{sn['repo']}** (`{sn['file']}`): {sn['note']}")
            lines.append("")

        if leakage_notes:
            lines.append("## Security: Credential Leakage Risk\n")
            lines.append("Direct `${{ secrets.* }}` interpolation in `run:` blocks. The values are trusted "
                         "(not attacker-controlled) but direct interpolation risks leaking them in logs if "
                         "GitHub's automatic masking is bypassed. Best practice: pass through `env:` block.\n")
            lines.append(f"<details>\n<summary>Show {len(leakage_notes)} credential leakage findings</summary>\n")
            for sn in leakage_notes:
                lines.append(f"- **{owner}/{sn['repo']}** (`{sn['file']}`): {sn['note']}")
            lines.append(f"\n</details>\n")

        if trusted_input_notes:
            lines.append("## Security: Trusted Committer Input\n")
            lines.append("Direct `${{ github.event.inputs.* }}` interpolation in `run:` blocks for "
                         "`workflow_dispatch` workflows only triggerable by committers. Not externally exploitable, "
                         "but could cause issues with malformed input values.\n")
            lines.append(f"<details>\n<summary>Show {len(trusted_input_notes)} trusted input findings</summary>\n")
            for sn in trusted_input_notes:
                lines.append(f"- **{owner}/{sn['repo']}** (`{sn['file']}`): {sn['note']}")
            lines.append(f"\n</details>\n")

        if downgraded_notes:
            lines.append("## Security: Auto-Downgraded Findings\n")
            lines.append("Initially flagged but the note describes an env-mediated pattern (safe). Verify manually.\n")
            lines.append(f"<details>\n<summary>Show {len(downgraded_notes)} downgraded findings</summary>\n")
            for sn in downgraded_notes:
                lines.append(f"- **{owner}/{sn['repo']}** (`{sn['file']}`): {sn['note']}")
            lines.append(f"\n</details>\n")

        if low_notes:
            lines.append("## Security: Low Risk\n")
            lines.append("GitHub-controlled values used directly in `run:` blocks.\n")
            lines.append(f"<details>\n<summary>Show {len(low_notes)} low-risk findings</summary>\n")
            for sn in low_notes:
                lines.append(f"- **{owner}/{sn['repo']}** (`{sn['file']}`): {sn['note']}")
            lines.append(f"\n</details>\n")

        # --- Detailed Results (release + snapshot) ---
        lines.append("## Detailed Results: Release & Snapshot Workflows\n")
        detail_count = 0

        for repo in sorted(all_results.keys()):
            repo_release = [w for w in (release_wfs + snapshot_wfs) if w.get("repo") == repo]
            if not repo_release:
                continue

            detail_count += 1
            repo_ecosystems = set()
            for w in repo_release:
                repo_ecosystems.update([e for e in (w.get("ecosystems") or []) if e])

            cat_counts = {}
            for w in repo_release:
                c = safe_str(w.get("category"))
                cat_counts[c] = cat_counts.get(c, 0) + 1
            cat_summary = ", ".join(f"{CATEGORY_LABELS.get(c, c)}: {n}" for c, n in cat_counts.items())

            lines.append(f"### {owner}/{repo}\n")
            lines.append(f"**{len(repo_release)}** release/snapshot workflows | "
                         f"Ecosystems: **{', '.join(sorted(repo_ecosystems)) if repo_ecosystems else 'none'}** | "
                         f"{cat_summary}\n")

            for w in repo_release:
                display_name = safe_str(w.get("workflow_name")) or w.get("file", "unknown")
                cat_label = CATEGORY_LABELS.get(safe_str(w.get("category")), "Unknown")
                lines.append(f"**`{w.get('file', '?')}`** — {sanitize_md(display_name)} [{cat_label}]")
                lines.append(f"- **Summary**: {sanitize_md(safe_str(w.get('summary')))}")
                lines.append(f"- **Ecosystems**: {', '.join(w.get('ecosystems', [])) or 'N/A'}")
                lines.append(f"- **Trigger**: {sanitize_md(safe_str(w.get('trigger')))}")
                lines.append(f"- **Auth**: {sanitize_md(safe_str(w.get('auth_method')))}")
                lines.append(f"- **Confidence**: {safe_str(w.get('confidence')) or 'N/A'}")
                if w.get("publish_actions"):
                    lines.append(f"- **GitHub Actions**: {', '.join(f'`{a}`' for a in w['publish_actions'])}")
                if w.get("publish_commands"):
                    lines.append(f"- **Commands**: {', '.join(f'`{c}`' for c in w['publish_commands'])}")
                sec_notes = w.get("security_notes") or []
                notable = [downgrade_contradictions(normalize_note(n)) for n in sec_notes
                           if n and any(tag in downgrade_contradictions(normalize_note(n))
                                        for tag in ["[CRITICAL]", "[LOW-LEAKAGE]", "[LOW-TRUSTED-INPUT]"])]
                if notable:
                    lines.append(f"- **Security**: {'; '.join(notable)}")
                lines.append("")

        if detail_count == 0:
            lines.append("*No release or snapshot publishing workflows detected.*\n")

        # --- Non-publishing repos ---
        # Repos that have doc/CI workflows are covered above; only list truly non-publishing repos
        repos_with_any_output = set(publishing_repos)
        for w in ci_wfs + doc_wfs:
            repos_with_any_output.add(w.get("repo", ""))
        non_publishing = sorted([r for r in all_results.keys() if r not in repos_with_any_output])
        if non_publishing:
            lines.append("## Repositories with Workflows (No Publishing Detected)\n")
            lines.append(f"{len(non_publishing)} repositories had workflow files but no publishing of any kind.\n")
            lines.append(f"<details>\n<summary>Show {len(non_publishing)} repos</summary>\n")
            for repo in non_publishing:
                wfs = all_results[repo]
                wf_names = ", ".join([w.get("file", "?") for w in wfs])
                lines.append(f"- **{repo}**: {wf_names}")
            lines.append(f"\n</details>\n")

        # --- Errors ---
        if stats["errors"]:
            lines.append("## Errors\n")
            lines.append(f"{len(stats['errors'])} issues encountered:\n")
            for err in stats["errors"][:100]:
                lines.append(f"- `{err}`")
            if len(stats["errors"]) > 100:
                lines.append(f"\n*...and {len(stats['errors']) - 100} more.*")
            lines.append("")

        lines.append("---\n")
        lines.append(f"*Cached in `ci-classification:{owner}`. "
                     f"Set `clear_cache` to `true` to force a fresh scan.*")

        report_body = "\n".join(lines)

        # --- TOC ---
        def to_anchor(text):
            anchor = text.lower().strip()
            anchor = re.sub(r'[^\w\s-]', '', anchor)
            anchor = re.sub(r'\s+', '-', anchor)
            anchor = re.sub(r'-+', '-', anchor)
            return anchor.strip('-')

        toc_lines = [f"# {report_title}\n", "## Contents\n"]
        toc_lines.append(f"- [Executive Summary](#{to_anchor('Executive Summary')})")
        if release_ecosystems:
            toc_lines.append(f"- [Package Ecosystem Distribution](#{to_anchor('Package Ecosystem Distribution releases snapshots only')})")
        if tp_opportunities:
            toc_lines.append(f"- [Trusted Publishing Opportunities](#{to_anchor('Trusted Publishing Migration Opportunities')}) ({len(tp_opportunities)})")
        if release_wfs:
            toc_lines.append(f"- [Release Artifact Workflows](#{to_anchor('Release Artifact Workflows')}) ({len(release_wfs)})")
        if snapshot_wfs:
            toc_lines.append(f"- [Snapshot / Nightly Workflows](#{to_anchor('Snapshot Nightly Artifact Workflows')}) ({len(snapshot_wfs)})")
        if ci_wfs:
            toc_lines.append(f"- [CI Infrastructure Workflows](#{to_anchor('CI Infrastructure Image Workflows')}) ({len(ci_wfs)})")
        if doc_wfs:
            toc_lines.append(f"- [Documentation Workflows](#{to_anchor('Documentation Website Workflows')}) ({len(doc_wfs)})")
        if critical_notes:
            toc_lines.append(f"- [Security: Critical](#{to_anchor('Security Critical Untrusted Input Injection')}) ({len(critical_notes)})")
        if leakage_notes:
            toc_lines.append(f"- [Security: Credential Leakage](#{to_anchor('Security Credential Leakage Risk')}) ({len(leakage_notes)})")
        if trusted_input_notes:
            toc_lines.append(f"- [Security: Trusted Input](#{to_anchor('Security Trusted Committer Input')}) ({len(trusted_input_notes)})")
        if downgraded_notes:
            toc_lines.append(f"- [Security: Downgraded](#{to_anchor('Security Auto-Downgraded Findings')}) ({len(downgraded_notes)})")
        if low_notes:
            toc_lines.append(f"- [Security: Low Risk](#{to_anchor('Security Low Risk')}) ({len(low_notes)})")
        toc_lines.append(f"- [Detailed Results](#{to_anchor('Detailed Results Release Snapshot Workflows')})")
        for repo in sorted(all_results.keys()):
            if any(w.get("repo") == repo for w in (release_wfs + snapshot_wfs)):
                toc_lines.append(f"  - [{owner}/{repo}](#{to_anchor(f'{owner}/{repo}')})")
        if non_publishing:
            toc_lines.append(f"- [Non-publishing Repos](#{to_anchor('Repositories with Workflows No Publishing Detected')})")
        if stats["errors"]:
            toc_lines.append(f"- [Errors](#{to_anchor('Errors')})")

        toc = "\n".join(toc_lines)
        full_report = toc + "\n\n---\n\n" + report_body

        report_ns.set("latest_report", full_report)
        report_ns.set("latest_stats", {
            "repos_scanned": stats["repos_scanned"],
            "repos_with_workflows": stats["repos_with_workflows"],
            "total_workflows": stats["total_workflows"],
            "publishing_repos": sorted(publishing_repos),
            "by_category": {k: len(v) for k, v in by_category.items()},
            "ecosystem_counts": ecosystem_counts,
            "security_notes_count": len(security_notes_all),
            "critical_count": len(critical_notes),
            "leakage_count": len(leakage_notes),
            "trusted_input_count": len(trusted_input_notes),
            "downgraded_count": len(downgraded_notes),
            "trusted_publishing_opportunities": len(tp_opportunities),
        })

        return {"outputText": full_report}

    finally:
        await http_client.aclose()