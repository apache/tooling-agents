# discover_codebase_architecture

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json
        import re

        input_namespace = input_dict.get("inputNamespace", "")

        namespaces = [ns.strip() for ns in input_namespace.split(",") if ns.strip()]
        if not namespaces:
            all_ns = data_store.list_namespaces()
            file_ns = [ns for ns in all_ns if ns.startswith("files:")]
            if file_ns:
                namespaces = file_ns

        if not namespaces:
            return {"outputText": json.dumps({"error": f"No namespaces provided. Available: {data_store.list_namespaces()}"})}

        repo_name = "unknown"
        for ns in namespaces:
            if ns.startswith("files:"):
                repo_name = ns.replace("files:", "")
                break

        print(f"Discovering architecture for: {repo_name}", flush=True)
        print(f"Namespaces: {namespaces}", flush=True)

        # =============================================================
        # Model configuration
        # =============================================================
        PROVIDER = "bedrock"
        MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        PARAMS = {"temperature": 0.7, "max_tokens": 16384}
        CONTEXT_WINDOW = get_context_window(PROVIDER, MODEL)
        SAFE_LIMIT = int(CONTEXT_WINDOW * 0.40)

        # =============================================================
        # Step 1: Read file paths and previews
        # =============================================================
        print("\n=== Step 1: Reading file paths and previews ===", flush=True)

        SKIP_DIRS = {
            'node_modules', 'vendor', 'third_party', 'third-party',
            'dist', 'build', 'out', 'target',
            '__pycache__', '.pytest_cache', '.mypy_cache', 'coverage', '.next', '.nuxt',
            'assets', 'images', 'img', 'static/images', 'static/fonts', 'static/webfonts',
            'public/images', 'fonts', 'webfonts',
            '.github/workflows',
            'venv', '.venv', 'env', '.env',
            '.git', '.idea', '.vscode',
        }
        SKIP_FILES = {
            'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock',
            'composer.lock', 'pnpm-lock.yaml', 'Gemfile.lock', 'uv.lock',
            'LICENSE', 'LICENSE.md', 'LICENSE.txt',
            'README.md', 'README.rst', 'README.txt', 'README',
            'CHANGELOG.md', 'CHANGELOG', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md',
            '.gitignore', '.dockerignore', '.prettierrc', '.eslintrc', '.editorconfig',
            '.npmrc', '.yarnrc',
        }
        SKIP_EXTENSIONS = {
            '.min.js', '.min.css', '.bundle.js', '.bundle.css',
            '.map', '.css', '.scss', '.less', '.sass', '.styl',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
            '.mp3', '.mp4', '.wav', '.avi', '.mov', '.webm', '.ogg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.tar', '.gz', '.rar', '.7z', '.lock',
            '.exe', '.dll', '.so', '.dylib', '.pyc', '.pyo', '.class', '.o', '.obj',
        }

        def should_skip_file(filepath):
            path_lower = filepath.lower()
            parts = filepath.split('/')
            for part in parts[:-1]:
                if part.lower() in SKIP_DIRS:
                    return True
            filename = parts[-1] if parts else ''
            if filename in SKIP_FILES:
                return True
            for ext in SKIP_EXTENSIONS:
                if path_lower.endswith(ext):
                    return True
            return False

        all_files = {}
        for ns in namespaces:
            ns_store = data_store.use_namespace(ns)
            keys = ns_store.list_keys()
            file_contents = ns_store.get_many(keys) if keys else {}
            for k, v in file_contents.items():
                if v is not None and not should_skip_file(k):
                    content = v if isinstance(v, str) else json.dumps(v, default=str) if v else ""
                    all_files[k] = content

        print(f"Total code files: {len(all_files)}", flush=True)

        if not all_files:
            return {"outputText": json.dumps({"error": f"No code files found in namespaces {namespaces}"})}

        file_previews = {}
        for path, content in all_files.items():
            lines = content.split('\n')
            file_previews[path] = '\n'.join(lines[:30])

        total_lines = sum(len(content.split('\n')) for content in all_files.values())
        print(f"Total lines: {total_lines}", flush=True)

        # =============================================================
        # Step 2: Architecture classification (Sonnet, batched)
        # =============================================================
        print("\n=== Step 2: Architecture classification ===", flush=True)

        CLASSIFY_PROMPT = """You are a security architect analyzing a codebase structure.

Given the file paths and code previews below, identify the codebase's security architecture.

Return ONLY a JSON object with this structure:
{
  "framework": "e.g., FastAPI, Django, Flask, Express, Spring",
  "language": "e.g., Python, Java, JavaScript",
  "auth_systems": [
    {"name": "description", "files": ["path1", "path2"]}
  ],
  "api_layers": [
    {"name": "description", "files": ["path1", "path2"]}
  ],
  "data_layer": {
    "database": "e.g., SQLAlchemy, Django ORM",
    "encryption": "e.g., Fernet, bcrypt",
    "secrets": "e.g., Vault, env vars, config file",
    "files": ["path1", "path2"]
  },
  "execution_model": {
    "description": "e.g., async web server, task workers, DAG executor",
    "files": ["path1", "path2"]
  },
  "security_relevant_areas": [
    {"area": "short name", "description": "what it does", "files": ["path1", "path2"]}
  ],
  "trust_model": "one paragraph describing who is trusted and what boundaries exist"
}
"""
        template_tokens = count_tokens(CLASSIFY_PROMPT, PROVIDER, MODEL)
        preview_budget = SAFE_LIMIT - template_tokens

        path_list = "\n".join(sorted(all_files.keys()))
        path_tokens = count_tokens(path_list, PROVIDER, MODEL)

        if path_tokens + template_tokens < SAFE_LIMIT:
            entries = []
            current_tokens = 0
            for path in sorted(all_files.keys()):
                entry = f"\n--- {path} ---\n{file_previews[path]}\n"
                entry_tokens = count_tokens(entry, PROVIDER, MODEL)
                if current_tokens + entry_tokens > preview_budget:
                    break
                entries.append(entry)
                current_tokens += entry_tokens
            classify_content = CLASSIFY_PROMPT + "\nFILES:\n" + "".join(entries)
        else:
            classify_content = CLASSIFY_PROMPT + f"\nFILE PATHS ({len(all_files)} files):\n" + path_list

        print(f"  Classification prompt: {count_tokens(classify_content, PROVIDER, MODEL)} tokens", flush=True)

        architecture = {}
        for attempt in range(2):
            try:
                result, _ = await call_llm(
                    provider=PROVIDER, model=MODEL,
                    messages=[{"role": "user", "content": classify_content}],
                    parameters=PARAMS,
                    timeout=300,
                )
                json_match = re.search(r'\{[\s\S]*\}', result)
                if json_match:
                    architecture = json.loads(json_match.group())
                    print(f"  Framework: {architecture.get('framework', '?')}", flush=True)
                    print(f"  Auth systems: {len(architecture.get('auth_systems', []))}", flush=True)
                    print(f"  Security areas: {len(architecture.get('security_relevant_areas', []))}", flush=True)
                    break
            except Exception as e:
                if attempt == 0:
                    print(f"  Attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                    await asyncio.sleep(5)
                else:
                    print(f"  Classification FAILED: {e}", flush=True)

        if not architecture:
            return {"outputText": json.dumps({"error": "Failed to classify codebase architecture"})}

        # =============================================================
        # Step 3: Generate security domains (Sonnet)
        # =============================================================
        print("\n=== Step 3: Generating security domains ===", flush=True)

        asvs_sections_available = []
        try:
            asvs_ns = data_store.use_namespace("asvs")
            all_keys = asvs_ns.list_keys()
            req_keys = [k for k in all_keys if k.startswith("asvs:requirements:")]
            for rk in sorted(req_keys):
                req = asvs_ns.get(rk)
                if req:
                    section_id = rk.replace("asvs:requirements:", "")
                    req_level = req.get("level", "?")
                    desc = req.get("req_description", "")[:100]
                    asvs_sections_available.append(f"{section_id} (L{req_level}): {desc}")
        except Exception as e:
            print(f"  WARNING: Could not load ASVS sections: {e}", flush=True)

        asvs_list = "\n".join(asvs_sections_available[:200])

        DOMAIN_PROMPT = f"""Based on this codebase architecture, generate security audit domains.

## Codebase Architecture
{json.dumps(architecture, indent=2, default=str)}

## Available ASVS Sections
{asvs_list}

## Instructions

Generate security domains that reflect THIS codebase's actual architecture.
Each domain should:
1. Have a short snake_case name
2. Map to specific ASVS sections from the list above
3. List the files that belong to it (use exact paths from the architecture data)
4. Include a context paragraph that an auditor needs to understand this domain

Group ASVS sections by the code area they'd be testing, NOT by ASVS chapter number.

CRITICAL: **Every single ASVS section listed above MUST appear in exactly one domain.**
Do NOT skip sections. If a section doesn't fit neatly into an architecture-specific
domain, assign it to a "general_security" domain. Count your sections — the total
across all domains must equal the number of sections listed above.

Return ONLY a JSON object:
{{
  "domains": [
    {{
      "name": "snake_case_name",
      "description": "what this domain covers",
      "asvs_sections": ["X.Y.Z", ...],
      "files": ["path/to/file.py", ...],
      "context": "paragraph explaining the architecture of this domain for auditors"
    }}
  ],
  "total_sections_assigned": 999
}}"""

        domains = []
        for attempt in range(2):
            try:
                result, _ = await call_llm(
                    provider=PROVIDER, model=MODEL,
                    messages=[{"role": "user", "content": DOMAIN_PROMPT}],
                    parameters={**PARAMS, "max_tokens": 32000},
                    timeout=300,
                )
                json_match = re.search(r'\{[\s\S]*\}', result)
                if json_match:
                    domain_result = json.loads(json_match.group())
                    domains = domain_result.get("domains", [])
                    assigned_count = sum(len(d.get("asvs_sections", [])) for d in domains)
                    print(f"  Generated {len(domains)} domains, {assigned_count}/{len(asvs_sections_available)} sections assigned", flush=True)
                    for d in domains:
                        print(f"    {d['name']}: {len(d.get('asvs_sections', []))} sections, {len(d.get('files', []))} files", flush=True)
                    break
            except Exception as e:
                if attempt == 0:
                    print(f"  Attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                    await asyncio.sleep(5)
                else:
                    print(f"  Domain generation FAILED: {e}", flush=True)

        if not domains:
            return {"outputText": json.dumps({"error": "Failed to generate security domains"})}

        for domain in domains:
            line_count = 0
            for path in domain.get("files", []):
                if path in all_files:
                    line_count += len(all_files[path].split('\n'))
            domain["estimated_lines"] = line_count

        # =============================================================
        # Step 4: Generate false positive guidance (Sonnet)
        # =============================================================
        print("\n=== Step 4: Generating false positive guidance ===", flush=True)

        FP_PROMPT = f"""Based on this codebase architecture, identify patterns that an ASVS security auditor would INCORRECTLY flag as vulnerabilities.

## Codebase Architecture
{json.dumps(architecture, indent=2, default=str)}

For each false positive pattern, write a concise statement:
"[What auditor would flag] is intentional because [reason] — auditors should focus on [what matters instead]"

Return ONLY a JSON array of strings:
[
  "Pattern X is intentional because Y — auditors should focus on Z instead",
  ...
]"""

        false_positive_guidance = []
        try:
            result, _ = await call_llm(
                provider=PROVIDER, model=MODEL,
                messages=[{"role": "user", "content": FP_PROMPT}],
                parameters=PARAMS,
                timeout=120,
            )
            json_match = re.search(r'\[[\s\S]*\]', result)
            if json_match:
                false_positive_guidance = json.loads(json_match.group())
                print(f"  Generated {len(false_positive_guidance)} patterns", flush=True)
        except Exception as e:
            print(f"  False positive generation failed ({type(e).__name__}), continuing without", flush=True)

        # =============================================================
        # Step 5: Assemble output
        # =============================================================
        domain_groups = {}
        for domain in domains:
            domain_groups[domain["name"]] = domain.get("asvs_sections", [])

        passes = []
        for domain in domains:
            passes.append({
                "name": domain["name"],
                "description": domain.get("description", ""),
                "asvs_sections": domain.get("asvs_sections", []),
                "files": domain.get("files", []),
                "domain_context": domain.get("context", ""),
                "estimated_lines": domain.get("estimated_lines", 0),
            })
        passes.sort(key=lambda p: p["estimated_lines"])

        pass_config = {
            "repository": repo_name,
            "architecture_summary": architecture.get("trust_model", ""),
            "framework": architecture.get("framework", ""),
            "language": architecture.get("language", ""),
            "total_files": len(all_files),
            "total_lines": total_lines,
            "passes": passes,
            "domain_groups": domain_groups,
            "false_positive_guidance": false_positive_guidance,
        }

        discovery_ns = data_store.use_namespace(f"discovery:{repo_name}")
        discovery_ns.set("pass_config", pass_config)
        discovery_ns.set("architecture", architecture)

        print(f"\n=== Discovery complete ===", flush=True)
        print(f"Repository: {repo_name}", flush=True)
        print(f"Domains: {len(domains)}", flush=True)
        for p in passes:
            print(f"  {p['name']}: {len(p['asvs_sections'])} sections, {p['estimated_lines']} lines", flush=True)

        return {"outputText": json.dumps(pass_config, indent=2, default=str)}

    finally:
        await http_client.aclose()