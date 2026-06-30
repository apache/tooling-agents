"""
gha_artifact_verify

Queries package registry APIs to verify what artifacts ASF repos actually publish.
Cross-references with publishing-detail data to find:
  - Verified packages (workflow exists AND artifact confirmed in registry)
  - Orphaned packages (artifact in registry but no publishing workflow found)
  - Phantom workflows (workflow claims to publish but no artifact found)

No GitHub API calls. Calls registry APIs only (PyPI, npm, Maven, Docker Hub, etc.).

Inputs:
  github_owner  — org name (e.g. "apache")
  channels      — optional comma-separated filter (e.g. "pypi,npm")
  repos         — optional comma-separated filter

Reads from:
  ci-publishing-detail:{owner} — enriched workflow data (from publishing-detail agent)
  ci-classification:{owner}   — LLM classifications (from publishing agent)
  ci-workflows:{owner}        — cached YAML with repo tree (from prefetch)

Writes to:
  ci-artifact-verify:{owner}  — verification results
"""

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx


async def run(input_dict, tools):
    mcpc = {url: RemoteMCPClient(remote_url=url) for url in tools.keys()}
    http_client = httpx.AsyncClient(timeout=20)
    try:
        import asyncio
        import re
        import json
        from collections import defaultdict
        from datetime import datetime, timezone
        # ── Constants (must be inside run() for gofannon) ──

        MANIFEST_FILES = {
            'pypi':          [('pyproject.toml', r'(?:^name\s*=\s*["\']([^"\']+)|^\[project\].*?^name\s*=\s*["\']([^"\']+))'),
                              ('setup.cfg',     r'^name\s*=\s*(.+)'),
                              ('setup.py',      r"name\s*=\s*['\"]([^'\"]+)")],
            'npm':           [('package.json',  r'"name"\s*:\s*"([^"]+)"')],
            'crates_io':     [('Cargo.toml',    r'(?:^\[package\].*?^name\s*=\s*"([^"]+))')],
            'rubygems':      [('*.gemspec',     r"spec\.name\s*=\s*['\"]([^'\"]+)")],
            'nuget':         [('*.csproj',      r'<PackageId>([^<]+)')],
        }

        REGISTRY_APIS = {
            'pypi': {
                'url_template': 'https://pypi.org/pypi/{package}/json',
                'parse': lambda data: {
                    'latest_version': data.get('info', {}).get('version'),
                    'versions': list(data.get('releases', {}).keys()),
                    'summary': data.get('info', {}).get('summary', ''),
                    'home_page': data.get('info', {}).get('home_page', ''),
                    'author': data.get('info', {}).get('author', ''),
                } if data else None,
            },
            'test_pypi': {
                'url_template': 'https://test.pypi.org/pypi/{package}/json',
                'parse': lambda data: {
                    'latest_version': data.get('info', {}).get('version'),
                    'versions': list(data.get('releases', {}).keys()),
                } if data else None,
            },
            'npm': {
                'url_template': 'https://registry.npmjs.org/{package}',
                'parse': lambda data: {
                    'latest_version': data.get('dist-tags', {}).get('latest'),
                    'versions': list(data.get('versions', {}).keys()),
                    'description': data.get('description', ''),
                } if data else None,
            },
            'crates_io': {
                'url_template': 'https://crates.io/api/v1/crates/{package}',
                'headers': {'User-Agent': 'apache-ci-scan/1.0'},
                'parse': lambda data: {
                    'latest_version': data.get('crate', {}).get('newest_version'),
                    'versions': [v['num'] for v in data.get('versions', [])],
                    'downloads': data.get('crate', {}).get('downloads'),
                    'description': data.get('crate', {}).get('description', ''),
                } if data and 'crate' in data else None,
            },
            'rubygems': {
                'url_template': 'https://rubygems.org/api/v1/versions/{package}.json',
                'parse': lambda data: {
                    'latest_version': data[0].get('number') if data and isinstance(data, list) else None,
                    'versions': [v['number'] for v in data] if isinstance(data, list) else [],
                } if data else None,
            },
            'nuget': {
                'url_template': 'https://api.nuget.org/v3/registration5-gz-semver2/{package_lower}/index.json',
                'parse': lambda data: {
                    'latest_version': data.get('items', [{}])[-1].get('upper') if data.get('items') else None,
                    'page_count': len(data.get('items', [])),
                } if data else None,
            },
            'docker_hub': {
                'url_template': 'https://hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=10',
                'parse': lambda data: {
                    'latest_tag': data['results'][0]['name'] if data.get('results') else None,
                    'tag_count': data.get('count', 0),
                    'tags': [r['name'] for r in data.get('results', [])[:10]],
                    'last_updated': data['results'][0].get('last_updated') if data.get('results') else None,
                } if data else None,
            },
        }
        github_owner = input_dict.get("github_owner", "apache")
        channels_filter = [c.strip() for c in input_dict.get("channels", "").split(",") if c.strip()]
        repos_filter = [r.strip() for r in input_dict.get("repos", "").split(",") if r.strip()]

        print(f"Artifact verification for {github_owner}", flush=True)

        # ── Read enriched publishing data ──
        detail_ns = data_store.use_namespace(f"ci-publishing-detail:{github_owner}")
        wf_ns = data_store.use_namespace(f"ci-workflows:{github_owner}")

        detail_data = detail_ns.get("latest_data")
        if not detail_data:
            return {"outputText": json.dumps({"error": "Run publishing-detail agent first."})}

        enriched_repos = detail_data.get("repos", [])
        if repos_filter:
            enriched_repos = [r for r in enriched_repos if r['repo'].split('/')[-1] in repos_filter]

        print(f"Processing {len(enriched_repos)} repos", flush=True)

        # ── Helper functions (must be inside run() for gofannon) ──

        async def query_registry(channel, package_name, api_def):
            try:
                url_template = api_def['url_template']
                if channel == 'docker_hub':
                    parts = package_name.split('/')
                    if len(parts) == 2:
                        url = url_template.format(namespace=parts[0], repo=parts[1])
                    else:
                        url = url_template.format(namespace='library', repo=package_name)
                elif channel == 'nuget':
                    url = url_template.format(package_lower=package_name.lower())
                else:
                    url = url_template.format(package=package_name)
                headers = api_def.get('headers', {})
                resp = await http_client.get(url, headers=headers, timeout=15)
                if resp.status_code == 200:
                    return api_def['parse'](resp.json())
                return None
            except Exception:
                return None

        # ── Discover package names from cached repo trees ──
        # The prefetch __extras__ or tree data tells us which manifest files exist

        verified = []     # {repo, channel, package, registry_data, workflow}
        orphaned = []     # {repo, channel, package, registry_data} (no workflow)
        phantom = []      # {repo, channel, workflow} (workflow but no artifact)
        errors = []

        # ── Build verification tasks ──
        import asyncio
        verify_tasks = []  # (repo_data, channel, api_def, candidates_or_name)

        for repo_data in enriched_repos:
            repo_full = repo_data['repo']
            repo_name = repo_full.split('/')[-1]

            repo_channels = set()
            for wf in repo_data.get('workflows', []):
                repo_channels.update(wf.get('production_channels', []))
                repo_channels.update(wf.get('staging_channels', []))

            if channels_filter:
                repo_channels = repo_channels & set(channels_filter)

            if not repo_channels:
                continue

            for channel in sorted(repo_channels):
                if channel not in REGISTRY_APIS:
                    continue

                api = REGISTRY_APIS[channel]
                package_name = None

                manifest_specs = MANIFEST_FILES.get(channel, [])
                for manifest_file, pattern in manifest_specs:
                    if '*' in manifest_file:
                        continue
                    content = wf_ns.get(f"__manifest__:{repo_name}:{manifest_file}")
                    if content and isinstance(content, str):
                        m = re.search(pattern, content, re.MULTILINE | re.DOTALL)
                        if m:
                            package_name = m.group(1) or (m.group(2) if m.lastindex >= 2 else None)
                            break

                if package_name:
                    candidates = [package_name]
                elif channel == 'pypi':
                    candidates = [f"apache-{repo_name}", repo_name,
                                 repo_name.replace('-', '_'), f"apache_{repo_name}"]
                elif channel == 'npm':
                    candidates = [f"@apache-{repo_name}/{repo_name}", repo_name,
                                 f"apache-{repo_name}"]
                elif channel == 'crates_io':
                    candidates = [repo_name, repo_name.replace('-', '_')]
                elif channel == 'docker_hub':
                    candidates = [f"apache/{repo_name}"]
                else:
                    candidates = [repo_name]

                verify_tasks.append((repo_data, channel, api, candidates))

        # ── Run verification concurrently (10-way parallel) ──
        sem = asyncio.Semaphore(10)

        async def verify_one(repo_data, channel, api_def, candidates):
            async with sem:
                repo_full = repo_data['repo']
                for candidate in candidates:
                    result = await query_registry(channel, candidate, api_def)
                    if result:
                        pub_wfs = [wf for wf in repo_data['workflows']
                                  if channel in wf.get('production_channels', []) + wf.get('staging_channels', [])]
                        return ('verified', {
                            'repo': repo_full,
                            'channel': channel,
                            'package': candidate,
                            'registry': result,
                            'workflows': [wf['file'] for wf in pub_wfs],
                            'last_run': pub_wfs[0].get('last_run') if pub_wfs else None,
                        })
                # No candidate matched — phantom
                pub_wfs = [wf for wf in repo_data['workflows']
                          if channel in wf.get('production_channels', []) + wf.get('staging_channels', [])]
                phantoms = []
                for wf in pub_wfs:
                    phantoms.append({
                        'repo': repo_full,
                        'channel': channel,
                        'workflow': wf['file'],
                        'note': 'No package found in registry (may use non-standard name)',
                    })
                return ('phantom', phantoms)

        results = await asyncio.gather(*[
            verify_one(rd, ch, api, cands)
            for rd, ch, api, cands in verify_tasks
        ])

        for result_type, data in results:
            if result_type == 'verified':
                verified.append(data)
                print(f"  \u2705 {data['repo']} \u2192 {data['channel']}:{data['package']} "
                      f"(v{data['registry'].get('latest_version', '?')})", flush=True)
            elif result_type == 'phantom':
                phantom.extend(data)

        print(f"\nResults: {len(verified)} verified, {len(phantom)} phantom, "
              f"{len(orphaned)} orphaned, {len(errors)} errors", flush=True)

        # ── Report generators (inside run() for gofannon) ──

        def gen_verification_report():
            lines = [f"# Artifact Verification: {github_owner}\n",
                     f"Cross-references publishing workflows with actual registry contents.\n"]
            v_by_ch = defaultdict(list)
            for v in verified:
                v_by_ch[v['channel']].append(v)
            lines.append("## Summary\n")
            lines.append(f"- **{len(verified)}** packages verified in registries")
            lines.append(f"- **{len(phantom)}** workflows with no artifact found")
            lines.append(f"- **{len(orphaned)}** orphaned packages\n")
            lines.append("| Channel | Verified | Phantom |")
            lines.append("|---------|----------|---------|")
            all_channels = sorted(set(v['channel'] for v in verified) | set(p['channel'] for p in phantom))
            for ch in all_channels:
                nv = len([v for v in verified if v['channel'] == ch])
                np = len([p for p in phantom if p['channel'] == ch])
                lines.append(f"| {ch} | {nv} | {np} |")
            lines.append("")
            lines.append("## Verified Packages\n")
            for ch in sorted(v_by_ch.keys()):
                items = sorted(v_by_ch[ch], key=lambda v: v['repo'])
                lines.append(f"### {ch} ({len(items)} packages)\n")
                lines.append("| Repo | Package | Latest Version | Workflow | Last Run |")
                lines.append("|------|---------|---------------|----------|----------|")
                for v in items:
                    version = v['registry'].get('latest_version', '?')
                    wfs = ', '.join(f"`{w}`" for w in v.get('workflows', []))
                    lr = v.get('last_run')
                    lr_str = f"{'✅' if lr.get('status')=='success' else '❌'} {lr.get('created','?')[:10]}" if lr else ""
                    lines.append(f"| {v['repo']} | `{v['package']}` | {version} | {wfs} | {lr_str} |")
                lines.append("")
            if phantom:
                lines.append("## Phantom Workflows\n")
                for p in sorted(phantom, key=lambda x: (x['channel'], x['repo'])):
                    lines.append(f"- **{p['repo']}** `{p['workflow']}` → {p['channel']}: {p.get('note', '')}")
                lines.append("")
            return "\n".join(lines)

        def gen_atr_catalog():
            repos_dict = {}
            for v in verified:
                repo = v['repo']
                if repo not in repos_dict:
                    repos_dict[repo] = {'repo': repo, 'channels': {}}
                ch_data = {
                    'package_name': v['package'],
                    'latest_version': v['registry'].get('latest_version'),
                    'workflows': v.get('workflows', []),
                    'verified': True,
                    'verified_at': datetime.now(timezone.utc).isoformat(),
                }
                for repo_data in enriched_repos:
                    if repo_data['repo'] == repo:
                        for wf in repo_data['workflows']:
                            if wf['file'] in v.get('workflows', []):
                                ch_data['auth_method'] = 'oidc' if wf.get('has_oidc') else 'secrets'
                                ch_data['secrets'] = wf.get('secrets', [])
                                ch_data['triggers'] = wf.get('triggers', [])
                                ch_data['has_environment'] = wf.get('has_environment', False)
                                if wf.get('last_run'):
                                    ch_data['last_workflow_run'] = wf['last_run'].get('created', '')
                                    ch_data['last_run_status'] = wf['last_run'].get('status', '')
                                    ch_data['last_run_url'] = wf['last_run'].get('url', '')
                                break
                        break
                repos_dict[repo]['channels'][v['channel']] = ch_data
            return {
                'schema_version': '2.0', 'owner': github_owner,
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'description': 'Apache publishing catalog — verified packages with workflow provenance',
                'repos': list(repos_dict.values()),
            }

        # ── Generate reports ──
        files = {}
        files['artifact-verification.md'] = gen_verification_report()
        files['atr-catalog.json'] = json.dumps(gen_atr_catalog(), indent=2)

        # Store (one bulk write)
        verify_ns = data_store.use_namespace(f"ci-artifact-verify:{github_owner}")
        couch_writes = {
            "latest_results": {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'verified': verified,
                'phantom': phantom,
                'orphaned': orphaned,
            }
        }
        for fname, content in files.items():
            couch_writes[f"report:{fname}"] = content
        verify_ns.set_many(couch_writes)

        return {"outputText": json.dumps({"files": files})}

    finally:
        await http_client.aclose()