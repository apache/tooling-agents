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

        if not github_pat:
            return {"outputText": "Error: `github_pat` is required.\n"
                    "Create a fine-grained PAT with **Contents: read** at https://github.com/settings/tokens"}

        if not all_repos and not repos_str:
            return {"outputText": "Error: provide `repos` or set `all_repos` to `true`."}

        GITHUB_API = "https://api.github.com"
        gh_headers = {"Accept": "application/vnd.github.v3+json",
                      "Authorization": f"token {github_pat}"}

        workflow_cache = data_store.use_namespace(f"ci-workflows:{owner}")
        classification_cache = data_store.use_namespace(f"ci-classification:{owner}")

        if clear_cache:
            print("Clear cache requested — will re-fetch all workflows and composites.", flush=True)

        # --- Preflight ---
        preflight_resp = await http_client.get(f"{GITHUB_API}/rate_limit", headers=gh_headers, timeout=15.0)
        if preflight_resp.status_code == 401:
            return {"outputText": "Error: GitHub PAT is invalid or expired (HTTP 401)."}
        if preflight_resp.status_code == 200:
            rate = preflight_resp.json().get("resources", {}).get("core", {})
            print(f"GitHub API: {rate.get('remaining', '?')}/{rate.get('limit', '?')} remaining", flush=True)

        # --- GitHub GET with retry/rate-limit handling ---
        async def github_get(url, params=None):
            for attempt in range(5):
                try:
                    resp = await http_client.get(url, headers=gh_headers, params=params, timeout=30.0)
                except Exception as e:
                    print(f"  HTTP error (attempt {attempt+1}): {str(e)[:80]}", flush=True)
                    if attempt < 4:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return None

                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", "60"))
                    print(f"  Rate limited, waiting {wait}s...", flush=True)
                    await asyncio.sleep(min(wait, 120))
                    continue

                if resp.status_code == 403:
                    if resp.headers.get("X-RateLimit-Remaining", "") == "0":
                        print(f"  Rate limit exhausted, waiting 60s...", flush=True)
                        await asyncio.sleep(60)
                        continue

                remaining = resp.headers.get("X-RateLimit-Remaining")
                if remaining:
                    try:
                        rem = int(remaining)
                        if rem < 50:
                            print(f"  WARNING: {rem} API requests remaining", flush=True)
                            await asyncio.sleep(5)
                        elif rem < 100:
                            await asyncio.sleep(2)
                    except ValueError:
                        pass

                return resp
            return None

        # --- Step 1: Get repo list ---
        if all_repos:
            print(f"Fetching all repos for {owner}...", flush=True)
            repo_names = []
            skipped = 0
            page = 1
            while True:
                resp = await github_get(
                    f"{GITHUB_API}/orgs/{owner}/repos",
                    params={"per_page": 100, "page": page, "sort": "pushed", "type": "public"})
                if resp is None or resp.status_code != 200:
                    break
                data = resp.json()
                if not data or not isinstance(data, list):
                    break
                for r in data:
                    if isinstance(r, dict) and "name" in r:
                        if r.get("archived"):
                            skipped += 1
                        else:
                            repo_names.append(r["name"])
                if 'rel="next"' not in resp.headers.get("Link", ""):
                    break
                page += 1
                await asyncio.sleep(0.3)
            print(f"Found {len(repo_names)} active repos ({skipped} archived skipped)", flush=True)
        else:
            repo_names = [r.strip() for r in repos_str.split(",") if r.strip()]
            print(f"Using provided list of {len(repo_names)} repos", flush=True)

        if not repo_names:
            return {"outputText": "No repositories found."}

        # --- Build index of what's already cached ---
        print("Building cache index...", flush=True)
        if clear_cache:
            all_cached_keys = set()
            print("  Cache bypassed (clear_cache=true)", flush=True)
        else:
            all_cached_keys = set(workflow_cache.list_keys())
            print(f"  {len(all_cached_keys)} keys in workflow cache", flush=True)

        def has_prefetch(repo_name):
            if clear_cache:
                return False
            meta = workflow_cache.get(f"__prefetch__:{repo_name}")
            return meta and meta.get("complete")

        def has_composites(repo_name):
            if clear_cache:
                return False
            meta = workflow_cache.get(f"__composites__:{repo_name}")
            return meta and meta.get("complete")

        def is_classified(repo_name):
            if clear_cache:
                return False
            meta = classification_cache.get(f"__meta__:{repo_name}")
            return meta and meta.get("complete")

        # --- Semaphore for concurrent fetches ---
        api_sem = asyncio.Semaphore(10)

        # --- Step 2: Prefetch workflows ---
        stats = {"repos": 0, "wf_skipped": 0, "wf_fetched": 0, "wf_no_workflows": 0,
                 "wf_yaml_cached": 0, "wf_yaml_existed": 0,
                 "ca_skipped": 0, "ca_fetched": 0, "ca_repos_with": 0, "ca_total": 0,
                 "errors": 0}

        async def fetch_single_yaml(repo_name, wf_name, download_url):
            """Fetch one YAML file if not already cached."""
            cache_key = f"{repo_name}/{wf_name}"
            if cache_key in all_cached_keys:
                return True, True  # success, was_cached

            async with api_sem:
                try:
                    resp = await http_client.get(download_url, follow_redirects=True, timeout=30.0)
                    if resp.status_code == 200:
                        workflow_cache.set(cache_key, resp.text)
                        all_cached_keys.add(cache_key)
                        return True, False  # success, newly fetched
                except Exception:
                    pass
            return False, False

        for idx, repo_name in enumerate(repo_names):
            stats["repos"] += 1

            if (idx + 1) % 50 == 0 or idx == 0:
                print(f"[{idx + 1}/{len(repo_names)}] Prefetching {repo_name}... "
                      f"({stats['wf_fetched']} fetched, {stats['wf_skipped']} skipped, "
                      f"{stats['wf_yaml_cached']} YAMLs, "
                      f"{stats['ca_total']} composites)", flush=True)

            # ---- Workflows ----
            if is_classified(repo_name) or has_prefetch(repo_name):
                stats["wf_skipped"] += 1
            else:
                resp = await github_get(
                    f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/.github/workflows")

                if resp is None:
                    stats["errors"] += 1
                elif resp.status_code == 404:
                    workflow_cache.set(f"__prefetch__:{repo_name}",
                                       {"complete": True, "workflows": []})
                    stats["wf_no_workflows"] += 1
                elif resp.status_code != 200:
                    stats["errors"] += 1
                else:
                    try:
                        dir_listing = resp.json()
                    except Exception:
                        dir_listing = None

                    if not dir_listing or not isinstance(dir_listing, list):
                        workflow_cache.set(f"__prefetch__:{repo_name}",
                                           {"complete": True, "workflows": []})
                        stats["wf_no_workflows"] += 1
                    else:
                        yaml_files = [f for f in dir_listing
                                      if isinstance(f, dict)
                                      and f.get("name", "").endswith((".yml", ".yaml"))]

                        if not yaml_files:
                            workflow_cache.set(f"__prefetch__:{repo_name}",
                                               {"complete": True, "workflows": []})
                            stats["wf_no_workflows"] += 1
                        else:
                            # Fetch all YAML concurrently
                            tasks = []
                            wf_names = []
                            for wf_file in yaml_files:
                                wf_name = wf_file.get("name", "unknown")
                                wf_names.append(wf_name)
                                dl_url = wf_file.get("download_url")
                                if dl_url:
                                    tasks.append(fetch_single_yaml(repo_name, wf_name, dl_url))

                            results = await asyncio.gather(*tasks, return_exceptions=True)
                            for r in results:
                                if isinstance(r, Exception):
                                    stats["errors"] += 1
                                else:
                                    success, was_cached = r
                                    if success:
                                        if was_cached:
                                            stats["wf_yaml_existed"] += 1
                                        else:
                                            stats["wf_yaml_cached"] += 1

                            workflow_cache.set(f"__prefetch__:{repo_name}",
                                               {"complete": True, "workflows": wf_names})
                            stats["wf_fetched"] += 1

            # ---- Composite actions ----
            if has_composites(repo_name):
                stats["ca_skipped"] += 1
            else:
                resp = await github_get(
                    f"{GITHUB_API}/repos/{owner}/{repo_name}/git/trees/HEAD?recursive=1")

                composite_names = []
                if resp and resp.status_code == 200:
                    try:
                        tree = resp.json().get("tree", [])
                        action_files = [
                            item["path"] for item in tree
                            if item.get("path", "").startswith(".github/actions/")
                            and item.get("path", "").endswith(("/action.yml", "/action.yaml"))
                            and item.get("type") == "blob"
                        ]

                        for action_path in action_files:
                            action_name = action_path.replace(".github/actions/", "").rsplit("/", 1)[0]
                            short_path = f".github/actions/{action_name}/action.yml"
                            cache_key = f"{repo_name}/{short_path}"

                            # Already cached?
                            if cache_key in all_cached_keys:
                                composite_names.append(short_path)
                                continue

                            # Fetch it
                            async with api_sem:
                                aresp = await github_get(
                                    f"{GITHUB_API}/repos/{owner}/{repo_name}/contents/{action_path}")
                                if aresp and aresp.status_code == 200:
                                    try:
                                        dl_url = aresp.json().get("download_url")
                                        if dl_url:
                                            dl_resp = await http_client.get(
                                                dl_url, follow_redirects=True, timeout=10.0)
                                            if dl_resp.status_code == 200:
                                                workflow_cache.set(cache_key, dl_resp.text)
                                                all_cached_keys.add(cache_key)
                                                composite_names.append(short_path)
                                                stats["ca_total"] += 1
                                    except Exception:
                                        pass

                    except Exception as e:
                        print(f"  Error scanning tree for {repo_name}: {str(e)[:80]}", flush=True)

                if composite_names:
                    stats["ca_repos_with"] += 1

                workflow_cache.set(f"__composites__:{repo_name}", {
                    "complete": True,
                    "actions": composite_names,
                })
                stats["ca_fetched"] += 1

        print(f"\n{'=' * 60}", flush=True)
        print(f"Prefetch complete!", flush=True)
        print(f"  Repos processed: {stats['repos']}", flush=True)
        print(f"  Workflows:", flush=True)
        print(f"    Skipped (already done): {stats['wf_skipped']}", flush=True)
        print(f"    Newly fetched: {stats['wf_fetched']}", flush=True)
        print(f"    No workflows: {stats['wf_no_workflows']}", flush=True)
        print(f"    YAML files cached: {stats['wf_yaml_cached']} (already existed: {stats['wf_yaml_existed']})", flush=True)
        print(f"  Composite actions:", flush=True)
        print(f"    Skipped (already done): {stats['ca_skipped']}", flush=True)
        print(f"    Repos scanned: {stats['ca_fetched']}", flush=True)
        print(f"    Repos with composites: {stats['ca_repos_with']}", flush=True)
        print(f"    Action files cached: {stats['ca_total']}", flush=True)
        print(f"  Errors: {stats['errors']}", flush=True)
        print(f"{'=' * 60}\n", flush=True)

        return {"outputText": json.dumps(stats, indent=2)}

    finally:
        await http_client.aclose()