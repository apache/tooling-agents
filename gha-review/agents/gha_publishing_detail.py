"""
gha_publishing_detail

Enriches publishing analysis with data the LLM classifier cannot reliably extract:
  4. Test vs production target classification (parsed from YAML URLs)
  3. Workflow run history from GitHub API (last run, status, trigger, link)
  2. Complete secret inventory per workflow (regex over cached YAML)
  1. Exact action references with SHA vs mutable tag

Returns JSON with multiple report files for the orchestrator to push.

Inputs:
  github_owner  — org name (e.g. "apache")
  read_pat      — GitHub PAT for API calls (workflow runs)
  repos         — optional comma-separated filter
  channels      — optional comma-separated filter
"""

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx
import re
import json
from collections import defaultdict
from datetime import datetime, timezone


async def run(input_dict, tools):
    mcpc = {url: RemoteMCPClient(remote_url=url) for url in tools.keys()}
    http_client = httpx.AsyncClient()
    try:
        import asyncio

        # ── Constants (must be inside run() for gofannon) ──

        CHANNEL_DETECT = {
            'pypi':             ('PyPI',                ['pypa/gh-action-pypi-publish'],
                                 ['twine upload','python -m twine'], ['pypi.org','upload.pypi.org']),
            'test_pypi':        ('TestPyPI',            [], [], ['test.pypi.org']),
            'npm':              ('npm',                 [], ['npm publish'], ['registry.npmjs.org']),
            'maven_central':    ('Maven Central',       [],
                                 ['mvn deploy','mvn -B deploy','./gradlew publish'],
                                 ['repo1.maven.org','oss.sonatype.org/service/local/staging',
                                  'repository.apache.org/service/local/staging']),
            'maven_snapshots':  ('Maven Snapshots',     [], [],
                                 ['oss.sonatype.org/content/repositories/snapshots',
                                  'repository.apache.org/content/repositories/snapshots']),
            'docker_hub':       ('Docker Hub',          ['docker/build-push-action','docker/login-action'],
                                 ['docker push'], ['docker.io/']),
            'ghcr':             ('ghcr.io',             [], [], ['ghcr.io/']),
            'crates_io':        ('crates.io',           ['rust-lang/crates-io-auth-action'],
                                 ['cargo publish'], ['crates.io']),
            'nuget':            ('NuGet',               ['NuGet/login'],
                                 ['dotnet nuget push'], ['api.nuget.org']),
            'github_releases':  ('GitHub Releases',
                                 ['softprops/action-gh-release','actions/create-release',
                                  'goreleaser/goreleaser-action','marvinpinto/action-automatic-releases'],
                                 [], []),
            'apache_dist_release': ('Apache dist (release)', [], [],
                                    ['dist.apache.org/repos/dist/release']),
            'apache_dist_dev':  ('Apache dist (dev)',    [], [],
                                 ['dist.apache.org/repos/dist/dev']),
            'nightlies':        ('Apache Nightlies',    [], [], ['nightlies.apache.org']),
            'helm':             ('Helm',                ['helm/chart-releaser-action'],
                                 ['helm push','helm package'], []),
            'rubygems':         ('RubyGems',            ['rubygems/release-gem'],
                                 ['gem push'], ['rubygems.org']),
            'conda':            ('Conda',               [], ['conda upload','conda_upload'],
                                 ['anaconda.org']),
            'vscode_marketplace': ('VS Code Marketplace', ['HaaLeo/publish-vscode-extension'],
                                   ['vsce publish'], []),
            'github_pages':     ('GitHub Pages',
                                 ['actions/deploy-pages','peaceiris/actions-gh-pages',
                                  'JamesIves/github-pages-deploy-action'], [], []),
            'github_packages':  ('GitHub Packages',     [], [], ['.pkg.github.com']),
            'atr':              ('Apache Trusted Releases',
                                 ['apache/tooling-actions/upload-to-atr',
                                  'apache/tooling-actions/release-on-atr'], [], []),
            'jfrog':            ('JFrog Artifactory',   [], [], ['jfrog.io/artifactory']),
            'puppet_forge':     ('Puppet Forge',        ['voxpupuli/gha-puppet'],
                                 ['puppet module build'], ['forge.puppet.com']),
        }

        PRODUCTION_CHANNELS = {
            'pypi','npm','maven_central','docker_hub','crates_io','nuget',
            'github_releases','apache_dist_release','helm','rubygems',
            'vscode_marketplace','puppet_forge',
        }

        STAGING_CHANNELS = {
            'test_pypi','maven_snapshots','apache_dist_dev','nightlies',
            'ghcr','github_packages','github_pages',
        }

        DOCS_CHANNELS = {'github_pages'}

        github_owner = input_dict.get("github_owner", "apache")
        read_pat = input_dict.get("read_pat", "")
        repos_filter = [r.strip() for r in input_dict.get("repos", "").split(",") if r.strip()]
        channels_filter = [c.strip() for c in input_dict.get("channels", "").split(",") if c.strip()]

        print(f"Publishing detail enrichment for {github_owner}", flush=True)

        # ── parse_workflow must be inside run() for gofannon ──
        def parse_workflow(yaml_content, wf_file, repo_name):
            action_refs = []
            for m in re.finditer(r'uses:\s*([^@\s]+)@([a-f0-9]{40}|[^\s#]+)', yaml_content):
                action_refs.append({
                    'action': m.group(1).strip(),
                    'version': m.group(2).strip(),
                    'pinned': bool(re.match(r'^[a-f0-9]{40}$', m.group(2).strip())),
                })
            secrets = sorted(set(re.findall(
                r'\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}', yaml_content)))
            triggers = []
            first_600 = yaml_content[:600]
            if re.search(r'\bpull_request_target\b', first_600):
                triggers.append('pull_request_target')
            elif re.search(r'\bpull_request\b', first_600):
                triggers.append('pull_request')
            if re.search(r'\bpush\b', first_600):
                triggers.append('push')
            if re.search(r'\bschedule\b', first_600):
                cron = re.search(r"cron:\s*['\"]([^'\"]+)['\"]", yaml_content[:800])
                triggers.append(f"schedule ({cron.group(1) if cron else '?'})")
            if re.search(r'\bworkflow_dispatch\b', first_600):
                triggers.append('workflow_dispatch')
            if re.search(r'^\s+release:', first_600, re.MULTILINE):
                triggers.append('release')
            detected = set()
            yl = yaml_content.lower()
            for ch_key, (_, act_pats, cmd_pats, url_pats) in CHANNEL_DETECT.items():
                for p in act_pats:
                    if p.lower() in yl:
                        detected.add(ch_key); break
                else:
                    for p in cmd_pats:
                        if p.lower() in yl:
                            detected.add(ch_key); break
                    else:
                        for p in url_pats:
                            if p.lower() in yl:
                                detected.add(ch_key); break
            return {
                'file': wf_file,
                'triggers': triggers,
                'channels': sorted(detected),
                'production_channels': sorted(detected & PRODUCTION_CHANNELS),
                'staging_channels': sorted(detected & STAGING_CHANNELS),
                'action_refs': action_refs,
                'secrets': secrets,
                'has_environment': bool(re.search(r'environment:\s*\S+', yaml_content)),
                'has_oidc': bool(re.search(r'id-token:\s*write', yaml_content)),
                'github_url': f"https://github.com/{github_owner}/{repo_name}/blob/HEAD/.github/workflows/{wf_file}",
            }

        wf_ns = data_store.use_namespace(f"ci-workflows:{github_owner}")
        cls_ns = data_store.use_namespace(f"ci-classification:{github_owner}")

        all_wf_keys = wf_ns.list_keys()
        prefetch_keys = [k for k in all_wf_keys if k.startswith("__prefetch__:")]
        if not prefetch_keys:
            return {"outputText": json.dumps({"error": "No cached workflows. Run prefetch first."})}

        repo_names = sorted(set(k.replace("__prefetch__:", "") for k in prefetch_keys))
        if repos_filter:
            repo_names = [r for r in repo_names if r in repos_filter]

        github_headers = {"Accept": "application/vnd.github+json"}
        if read_pat:
            github_headers["Authorization"] = f"Bearer {read_pat}"

        # ── Bulk-read all CouchDB data ──

        # 1. All prefetch metadata
        all_prefetch = wf_ns.get_many(prefetch_keys) if prefetch_keys else {}
        print(f"  Bulk-read {len(all_prefetch)} prefetch keys", flush=True)

        # 2. All classification data (keys are __meta__:{repo} and {repo}:{wf_name})
        all_cls_keys = cls_ns.list_keys()
        all_cls = cls_ns.get_many(all_cls_keys) if all_cls_keys else {}
        print(f"  Bulk-read {len(all_cls)} classification keys", flush=True)

        # 3. All workflow YAML — build key list from prefetch metadata
        yaml_keys = []
        for repo_name in repo_names:
            prefetch = all_prefetch.get(f"__prefetch__:{repo_name}")
            if not prefetch or not isinstance(prefetch, dict):
                continue
            for wf_file in prefetch.get("workflows", []):
                yaml_keys.append(f"{repo_name}/{wf_file}")
        all_yaml = wf_ns.get_many(yaml_keys) if yaml_keys else {}
        print(f"  Bulk-read {len(all_yaml)} YAML keys", flush=True)

        # ── Process each repo (pure in-memory, no CouchDB calls) ──
        enriched_repos = []
        repos_needing_runs = []

        for repo_name in repo_names:
            prefetch = all_prefetch.get(f"__prefetch__:{repo_name}")
            if not prefetch or not isinstance(prefetch, dict):
                continue
            wf_files = prefetch.get("workflows", [])
            if not wf_files:
                continue

            # Build per-workflow classification lookup from __meta__ + {repo}:{wf} keys
            wf_cls = {}
            meta = all_cls.get(f"__meta__:{repo_name}")
            if meta and isinstance(meta, dict):
                for wf_name in meta.get("workflows", []):
                    cls_data = all_cls.get(f"{repo_name}:{wf_name}")
                    if cls_data and isinstance(cls_data, dict):
                        wf_cls[wf_name] = cls_data

            repo_wfs = []
            for wf_file in wf_files:
                yaml_content = all_yaml.get(f"{repo_name}/{wf_file}")
                if not yaml_content or not isinstance(yaml_content, str):
                    continue

                cat = wf_cls.get(wf_file, {}).get("category", "unknown")
                wf_data = parse_workflow(yaml_content, wf_file, repo_name)
                wf_data['category'] = cat

                if not wf_data['channels'] and cat in ('unknown', 'ci_check', 'documentation'):
                    continue

                repo_wfs.append(wf_data)

            if not repo_wfs:
                continue

            all_ch = set()
            for wf in repo_wfs:
                all_ch.update(wf['channels'])

            if channels_filter and not any(c in all_ch for c in channels_filter):
                continue

            for wf in repo_wfs:
                wf['last_run'] = None
                wf['recent_runs'] = []

            enriched_repos.append({
                'repo': f"{github_owner}/{repo_name}",
                'channels': sorted(all_ch),
                'workflows': repo_wfs,
            })
            repos_needing_runs.append((repo_name, repo_wfs))

        # ── Fetch run history concurrently (10-way parallel) ──
        if read_pat and repos_needing_runs:
            sem = asyncio.Semaphore(10)

            async def fetch_runs(repo_name, repo_wfs):
                async with sem:
                    try:
                        url = f"https://api.github.com/repos/{github_owner}/{repo_name}/actions/runs?per_page=30"
                        resp = await http_client.get(url, headers=github_headers, timeout=15)
                        if resp.status_code == 200:
                            runs_by_file = defaultdict(list)
                            for r in resp.json().get("workflow_runs", []):
                                fname = r.get("path", "").split("/")[-1]
                                runs_by_file[fname].append({
                                    'status': r.get('conclusion', r.get('status', '?')),
                                    'trigger': r.get('event', '?'),
                                    'created': r.get('created_at', ''),
                                    'url': r.get('html_url', ''),
                                })
                            for wf in repo_wfs:
                                wf['last_run'] = (runs_by_file.get(wf['file'], [None]) or [None])[0]
                                wf['recent_runs'] = runs_by_file.get(wf['file'], [])[:5]
                    except Exception as e:
                        print(f"  API error {repo_name}: {e}", flush=True)

            await asyncio.gather(*[fetch_runs(rn, wfs) for rn, wfs in repos_needing_runs])
            print(f"  Fetched run history for {len(repos_needing_runs)} repos (10-way parallel)", flush=True)

        print(f"Enriched {len(enriched_repos)} repos", flush=True)

        # ── Helper functions (must be inside run() for gofannon) ──

        def _run_link(wf):
            lr = wf.get('last_run')
            if not lr:
                return "no run data"
            icon = "✅" if lr['status'] == 'success' else "❌" if lr['status'] == 'failure' else "⏳"
            date = lr['created'][:10] if lr.get('created') else '?'
            return f"{icon} {date} ({lr['trigger']}) — [view]({lr['url']})"

        def gen_overview(repos, owner):
            lines = [f"# Publishing Detail: {owner}\n",
                     f"Enriched analysis of **{len(repos)}** repositories with publishing workflows.\n"]
            total_wfs = sum(len(r['workflows']) for r in repos)
            all_secrets = defaultdict(set)
            ch_repos = defaultdict(set)
            unpinned = []
            for repo in repos:
                for wf in repo['workflows']:
                    for ch in wf.get('production_channels', []):
                        ch_repos[ch].add(repo['repo'])
                    for ch in wf.get('staging_channels', []):
                        ch_repos[ch].add(repo['repo'])
                    for s in wf.get('secrets', []):
                        if s != 'GITHUB_TOKEN':
                            all_secrets[s].add(repo['repo'])
                    for ref in wf.get('action_refs', []):
                        if not ref['pinned']:
                            for _, (_, pats, _, _) in CHANNEL_DETECT.items():
                                if any(p in ref['action'] for p in pats):
                                    unpinned.append((repo['repo'], wf['file'], ref['action'], ref['version']))
            lines.append("## Overview\n")
            lines.append(f"- **{len(repos)}** repos with publishing workflows")
            lines.append(f"- **{total_wfs}** workflows analyzed")
            lines.append(f"- **{len(all_secrets)}** distinct stored secrets")
            lines.append(f"- **{len(unpinned)}** unpinned publishing actions\n")
            lines.append("## Channels\n")
            lines.append("| Channel | Repos | Type |")
            lines.append("|---------|-------|------|")
            for ch in sorted(ch_repos):
                display = CHANNEL_DETECT.get(ch, (ch,))[0]
                ctype = "Production" if ch in PRODUCTION_CHANNELS else "Staging"
                lines.append(f"| {display} | {len(ch_repos[ch])} | {ctype} |")
            lines.append("")
            lines.append("## Per-Repository Detail\n")
            for repo in sorted(repos, key=lambda r: r['repo']):
                lines.append(f"### {repo['repo']}\n")
                lines.append(f"Channels: {', '.join(repo['channels'])}\n")
                for wf in sorted(repo['workflows'], key=lambda w: w['file']):
                    lines.append(f"#### [`{wf['file']}`]({wf['github_url']}) ({wf['category']})\n")
                    lines.append(f"- **Triggers:** {', '.join(wf['triggers']) or 'unknown'}")
                    if wf.get('production_channels'):
                        lines.append(f"- **Production:** {', '.join(wf['production_channels'])}")
                    if wf.get('staging_channels'):
                        lines.append(f"- **Staging:** {', '.join(wf['staging_channels'])}")
                    if wf.get('has_oidc'):
                        lines.append(f"- **Auth:** OIDC")
                    if wf.get('secrets'):
                        lines.append(f"- **Secrets:** `{'`, `'.join(wf['secrets'])}`")
                    if wf.get('has_environment'):
                        lines.append(f"- **Environment protection:** yes")
                    pub_acts = [r for r in wf.get('action_refs', [])
                                if any(p in r['action'] for ch in CHANNEL_DETECT.values() for p in ch[1])]
                    for ref in pub_acts:
                        pin = "📌" if ref['pinned'] else "⚠️"
                        lines.append(f"- **Action:** {pin} `{ref['action']}@{ref['version']}`")
                    lines.append(f"- **Last run:** {_run_link(wf)}")
                    lines.append("")
            return "\n".join(lines)

        def gen_risks(repos, owner):
            lines = [f"# Publishing Security Risks: {owner}\n"]
            pr_pub = []; push_pub = []; cron_pub = []; semrel = []
            secret_blast = defaultdict(set)
            for repo in repos:
                for wf in repo['workflows']:
                    prod = set(wf.get('production_channels', []))
                    if not prod: continue
                    trigs = wf.get('triggers', [])
                    secs = wf.get('secrets', [])
                    for s in secs:
                        if s != 'GITHUB_TOKEN': secret_blast[s].add(repo['repo'])
                    if 'pull_request' in trigs:
                        pr_pub.append((repo['repo'], wf['file'], sorted(prod), secs, trigs))
                    if 'push' in trigs and wf['category'] == 'release_artifact':
                        if 'release' not in trigs:
                            push_pub.append((repo['repo'], wf['file'], sorted(prod), secs, trigs))
                    if any(t.startswith('schedule') for t in trigs):
                        cron_pub.append((repo['repo'], wf['file'], sorted(prod), secs, trigs))
                    for ref in wf.get('action_refs', []):
                        if 'semantic-release' in ref['action'].lower():
                            semrel.append((repo['repo'], wf['file'], sorted(prod), secs))
            lines.append(f"## 1. Pull Request Triggers on Production Publishing ({len(pr_pub)} workflows)\n")
            lines.append("**CRITICAL** — fork PRs may access publishing secrets.\n")
            for r, f, chs, secs, trigs in sorted(pr_pub):
                lines.append(f"- **{r}** `{f}` → {', '.join(chs)}")
                if secs: lines.append(f"  - Secrets: `{'`, `'.join(secs)}`")
            lines.append("")
            lines.append(f"## 2. Auto-Publish on Push to Default Branch ({len(push_pub)} workflows)\n")
            lines.append("**HIGH** — no human gate (tag/release) before production publishing.\n")
            for r, f, chs, secs, trigs in sorted(push_pub):
                lines.append(f"- **{r}** `{f}` → {', '.join(chs)}")
            lines.append("")
            shared = [(s, rs) for s, rs in sorted(secret_blast.items(), key=lambda x: -len(x[1])) if len(rs) >= 3]
            lines.append(f"## 3. Shared Secrets ({len(shared)} names across 3+ repos)\n")
            lines.append("**HIGH** — org-level secrets create blast radius.\n")
            for s, rs in shared:
                lines.append(f"- `{s}` — {len(rs)} repos")
            lines.append("")
            lines.append(f"## 4. Cron + Production Secrets ({len(cron_pub)} workflows)\n")
            lines.append("**MEDIUM-HIGH** — scheduled runs with publishing credentials.\n")
            for r, f, chs, secs, trigs in sorted(cron_pub):
                sched = [t for t in trigs if t.startswith('schedule')]
                lines.append(f"- **{r}** `{f}` → {', '.join(chs)} | {', '.join(sched)}")
            lines.append("")
            lines.append(f"## 5. Semantic-Release ({len(semrel)} workflows)\n")
            lines.append("**MEDIUM-HIGH** — auto-version + auto-publish.\n")
            for r, f, chs, secs in sorted(semrel):
                lines.append(f"- **{r}** `{f}` → {', '.join(chs)}")
            lines.append("")
            return "\n".join(lines)

        def gen_channel_report(ch_key, display_name, items, all_repos, owner):
            repos_in_ch = sorted(set(r for r, _ in items))
            lines = [f"# {display_name}: {owner}\n",
                     f"**{len(repos_in_ch)}** repos, **{len(items)}** workflows.\n"]
            oidc = set(); secret = {}
            for r, wf in items:
                if wf.get('has_oidc'): oidc.add(r)
                elif wf.get('secrets') and any(s != 'GITHUB_TOKEN' for s in wf['secrets']):
                    secret[r] = ', '.join(s for s in wf['secrets'] if s != 'GITHUB_TOKEN')
            lines.append("## Authentication\n")
            if oidc:
                lines.append(f"**OIDC ({len(oidc)}):** {', '.join(sorted(oidc))}\n")
            if secret:
                lines.append(f"**Secrets ({len(secret)}):**\n")
                for r in sorted(secret):
                    lines.append(f"- {r} — `{secret[r]}`")
                lines.append("")
            lines.append("## Workflows\n")
            lines.append("| Repo | File | Type | Triggers | Target | Last Run |")
            lines.append("|------|------|------|----------|--------|----------|")
            for r, wf in sorted(items, key=lambda x: x[0]):
                cat = wf.get('category', '?').replace('_artifact', '')
                trigs = ', '.join(wf.get('triggers', ['?']))[:40]
                target = "prod" if wf.get('production_channels') else "staging"
                lr = _run_link(wf)
                lines.append(f"| {r} | [`{wf['file']}`]({wf['github_url']}) | {cat} | {trigs} | {target} | {lr} |")
            lines.append("")
            lines.append("## Detail\n")
            cur = None
            for r, wf in sorted(items, key=lambda x: x[0]):
                if r != cur:
                    cur = r; lines.append(f"### {r}\n")
                lines.append(f"**[`{wf['file']}`]({wf['github_url']})** ({wf['category']})\n")
                lines.append(f"- Triggers: {', '.join(wf.get('triggers', []))}")
                if wf.get('secrets'):
                    lines.append(f"- Secrets: `{'`, `'.join(wf['secrets'])}`")
                if wf.get('has_oidc'):
                    lines.append(f"- Auth: OIDC")
                pub_acts = [ref for ref in wf.get('action_refs', [])
                            if any(p in ref['action'] for _, (_, ps, _, _) in CHANNEL_DETECT.items() for p in ps)]
                for ref in pub_acts:
                    pin = "📌" if ref['pinned'] else "⚠️"
                    lines.append(f"- Action: {pin} `{ref['action']}@{ref['version']}`")
                lines.append(f"- Last run: {_run_link(wf)}")
                lines.append("")
            return "\n".join(lines)

        # ── Generate all reports ──
        files = {}
        files['publishing-detail.md'] = gen_overview(enriched_repos, github_owner)
        files['publishing-risks.md'] = gen_risks(enriched_repos, github_owner)

        ch_wfs = defaultdict(list)
        for repo in enriched_repos:
            for wf in repo['workflows']:
                for ch in wf['channels']:
                    ch_wfs[ch].append((repo['repo'], wf))

        for ch_key, items in ch_wfs.items():
            if ch_key in DOCS_CHANNELS:
                continue
            display = CHANNEL_DETECT.get(ch_key, (ch_key,))[0]
            fname = f"channel-{ch_key.replace('_', '-')}.md"
            files[fname] = gen_channel_report(ch_key, display, items, enriched_repos, github_owner)

        # Store in CouchDB (one bulk write)
        detail_ns = data_store.use_namespace(f"ci-publishing-detail:{github_owner}")
        couch_writes = {"latest_data": {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'repos': enriched_repos,
        }}
        for fname, content in files.items():
            couch_writes[f"report:{fname}"] = content
        detail_ns.set_many(couch_writes)

        print(f"Generated {len(files)} report files", flush=True)

        return {"outputText": json.dumps({"files": files})}

    finally:
        await http_client.aclose()