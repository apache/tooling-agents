# run_asvs_security_audit
from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json
        import re
        from datetime import date
        audit_date = date.today().strftime("%b %d, %Y")

        # Parse input
        input_text = input_dict.get("inputText", "")
        params = {}
        if input_text.strip().startswith('{'):
            try:
                params = json.loads(input_text)
            except json.JSONDecodeError:
                pass

        if not params.get('namespace') and not params.get('namespaces'):
            match = re.search(r'(?:namespaces?|ns)[:\s]+([^\n]+?)(?:\s+asvs|$)', input_text, re.IGNORECASE)
            if match:
                raw = match.group(1).strip()
                if ',' in raw:
                    params['namespaces'] = [n.strip() for n in raw.split(',')]
                else:
                    params['namespace'] = raw
            else:
                match = re.search(r'(?:namespace|ns)[:\s]+([^\s,]+)', input_text, re.IGNORECASE)
                if match:
                    params['namespace'] = match.group(1)

        if not params.get('asvs') and not params.get('asvs_section'):
            match = re.search(r'(?:asvs[-_]?section|asvs)[:\s]+(\d+(?:\.\d+)*)', input_text, re.IGNORECASE)
            if match:
                params['asvs'] = match.group(1)

        namespaces = params.get('namespaces') or ([params.get('namespace')] if params.get('namespace') else [])
        asvs = params.get('asvs') or params.get('asvs_section', '')

        if not namespaces:
            all_ns = data_store.list_namespaces()
            file_ns = [ns for ns in all_ns if ns.startswith("files:")]
            if file_ns:
                namespaces = file_ns

        if not namespaces:
            return {"outputText": f"Error: No namespaces provided or found in data store. Available namespaces: {data_store.list_namespaces()}"}

        if not asvs:
            return {"outputText": "Error: No ASVS requirement specified. Please provide an asvs parameter (e.g., asvs: 5.3.2)"}

        # Extract repo name from namespaces for report metadata
        repo_name = "unknown"
        for ns in namespaces:
            if ns.startswith("files:"):
                repo_name = ns.replace("files:", "")
                break

        print(f"Namespaces: {namespaces}", flush=True)
        print(f"ASVS: {asvs}", flush=True)

        # =============================================================
        # Model configuration
        # =============================================================
        SONNET_PROVIDER = "bedrock"
        SONNET_MODEL = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
        SONNET_PARAMS = {"temperature": 0.7, "max_tokens": 16384}

        OPUS_PROVIDER = "bedrock"
        OPUS_MODEL = "us.anthropic.claude-opus-4-6-v1"
        OPUS_PARAMS = {"temperature": 1, "reasoning_effort": "medium", "max_tokens": 64000}

        SONNET_CONTEXT = get_context_window(SONNET_PROVIDER, SONNET_MODEL)
        OPUS_CONTEXT = get_context_window(OPUS_PROVIDER, OPUS_MODEL)

        # Concurrency limits
        sonnet_semaphore = asyncio.Semaphore(5)
        opus_semaphore = asyncio.Semaphore(2)

        # Checkpointing namespaces
        cache_key_prefix = f"asvs-{asvs}-{'-'.join(namespaces)}"
        relevance_cache_ns = data_store.use_namespace(f"audit-cache:relevance:{cache_key_prefix}")
        inventory_cache_ns = data_store.use_namespace(f"audit-cache:inventory:{cache_key_prefix}")
        analysis_cache_ns = data_store.use_namespace(f"audit-cache:analysis:{cache_key_prefix}")

        # =============================================================
        # Step 0: Load ASVS requirement context from data store
        # =============================================================
        print("\n=== Step 0: Loading ASVS requirement context ===", flush=True)
        asvs_description = ""
        try:
            asvs_ns = data_store.use_namespace("asvs")
            req = asvs_ns.get(f"asvs:requirements:{asvs}")
            if req:
                parts = [f"ASVS Requirement {asvs}"]
                if req.get("req_description"):
                    parts.append(f"Description: {req['req_description']}")
                if req.get("level"):
                    parts.append(f"Level: {req['level']}")
                # Section context
                sec_id = req.get("section_id", "")
                if sec_id:
                    sec = asvs_ns.get(f"asvs:sections:{sec_id}")
                    if sec:
                        parts.append(f"Section: {sec.get('section_name', '')}")
                        if sec.get("description"):
                            parts.append(f"Section Description: {sec['description']}")
                # Chapter context
                ch_id = req.get("chapter_id", "")
                if ch_id:
                    ch = asvs_ns.get(f"asvs:chapters:{ch_id}")
                    if ch:
                        parts.append(f"Chapter: {ch.get('chapter_name', '')}")
                        if ch.get("control_objective"):
                            parts.append(f"Control Objective: {ch['control_objective']}")
                asvs_description = "\n".join(parts)
                print(f"  Loaded: {asvs_description[:200]}", flush=True)
            else:
                print(f"  WARNING: No data found for asvs:requirements:{asvs}", flush=True)
        except Exception as e:
            print(f"  ERROR reading ASVS data store: {e}", flush=True)

        if not asvs_description:
            asvs_description = f"ASVS Requirement {asvs} (requirement description not available in data store)"
            print(f"  FALLING BACK to minimal description", flush=True)

        # =============================================================
        # Step 1: Read files from data store
        # =============================================================
        print("\n=== Step 1: Reading files from data store ===", flush=True)

        all_files = {}
        for ns in namespaces:
            ns_store = data_store.use_namespace(ns)
            keys = ns_store.list_keys()
            print(f"Namespace '{ns}': {len(keys)} keys", flush=True)
            file_contents = ns_store.get_many(keys) if keys else {}
            for k, v in file_contents.items():
                if v is not None:
                    content = v if isinstance(v, str) else json.dumps(v, default=str) if v else ""
                    all_files[k] = content

        print(f"Total files loaded: {len(all_files)}", flush=True)

        if not all_files:
            return {"outputText": f"Error: No files found in namespaces {namespaces}. Available namespaces: {data_store.list_namespaces()}"}

        # Skip non-code files
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

        filtered_files = {}
        skipped_count = 0
        for key, content in all_files.items():
            if should_skip_file(key):
                skipped_count += 1
                continue
            filtered_files[key] = content

        print(f"Filtered: {len(filtered_files)} files to analyze, {skipped_count} skipped", flush=True)

        if not filtered_files:
            return {"outputText": f"Error: All {len(all_files)} files were filtered out. Check skip rules."}

        # =============================================================
        # Step 2: Relevance filtering (Sonnet, parallel, checkpointed)
        # =============================================================
        print("\n=== Step 2: Relevance filtering (Sonnet, parallel) ===", flush=True)

        cached_relevance = relevance_cache_ns.get("scores")
        if cached_relevance:
            relevance_scores = cached_relevance
            print(f"  Using cached relevance scores for {len(relevance_scores)} files", flush=True)
        else:
            file_previews = {}
            for path, content in filtered_files.items():
                lines = content.split('\n')
                file_previews[path] = '\n'.join(lines[:200])

            SAFE_SONNET_LIMIT = int(SONNET_CONTEXT * 0.40)

            relevance_prompt_template = f"""You are a security auditor performing file relevance filtering.

ASVS Requirement: {asvs}
{asvs_description}

Below are file paths with previews (first ~200 lines) from a codebase.
Rate each file's relevance to the ASVS requirement above on a scale of 0-10:
- 10: Directly implements or should implement controls for this requirement
- 7-9: Contains related security controls, data handling, or configuration
- 4-6: May contain relevant patterns indirectly
- 1-3: Unlikely to be relevant
- 0: Definitely not relevant

Return ONLY a JSON object mapping file paths to relevance scores (integer 0-10).
Example: {{"src/auth.py": 9, "src/utils.py": 3}}

FILES TO EVALUATE:
"""

            template_tokens = count_tokens(relevance_prompt_template, SONNET_PROVIDER, SONNET_MODEL)
            preview_budget = SAFE_SONNET_LIMIT - template_tokens

            preview_batches = []
            current_batch = {}
            current_tokens = 0
            for path, preview in file_previews.items():
                entry = f"\n--- {path} ---\n{preview}\n"
                entry_tokens = count_tokens(entry, SONNET_PROVIDER, SONNET_MODEL)
                if current_tokens + entry_tokens > preview_budget and current_batch:
                    preview_batches.append(current_batch)
                    current_batch = {}
                    current_tokens = 0
                current_batch[path] = entry
                current_tokens += entry_tokens
            if current_batch:
                preview_batches.append(current_batch)

            print(f"  Relevance filtering: {len(preview_batches)} batches", flush=True)

            relevance_scores = {}

            async def filter_batch(i, batch):
                async with sonnet_semaphore:
                    entries_text = "".join(batch.values())
                    prompt = relevance_prompt_template + entries_text
                    messages = [{"role": "user", "content": prompt}]
                    for attempt in range(2):
                        try:
                            content_resp, _ = await call_llm(
                                provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                messages=messages, parameters=SONNET_PARAMS,
                                timeout=120,
                            )
                            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content_resp, re.DOTALL)
                            if json_match:
                                scores = json.loads(json_match.group())
                                print(f"    Batch {i+1}: scored {len(scores)} files", flush=True)
                                return scores
                        except Exception as e:
                            if attempt == 0:
                                print(f"    Batch {i+1} attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                                await asyncio.sleep(5)
                            else:
                                print(f"    Batch {i+1} FAILED: {e}", flush=True)
                    # Fallback: default score 5 (passes relevance threshold)
                    # This is bad — it means these files bypass filtering and inflate
                    # Opus batch count. The retry above should prevent this.
                    print(f"    WARNING: Batch {i+1} defaulting {len(batch)} files to score=5", flush=True)
                    return {path: 5 for path in batch}

            batch_results = await asyncio.gather(*[
                filter_batch(i, batch)
                for i, batch in enumerate(preview_batches)
            ])
            for scores in batch_results:
                relevance_scores.update(scores)

            relevance_cache_ns.set("scores", relevance_scores)

        # Filter to relevant files (score >= 4)
        relevant_files = {}
        for path, content in filtered_files.items():
            score = relevance_scores.get(path, 5)
            if isinstance(score, (int, float)) and score >= 4:
                relevant_files[path] = content

        if len(relevant_files) < 3 and filtered_files:
            for path, content in filtered_files.items():
                score = relevance_scores.get(path, 5)
                if isinstance(score, (int, float)) and score >= 2:
                    relevant_files[path] = content

        print(f"  Relevant files: {len(relevant_files)} (from {len(filtered_files)})", flush=True)

        sorted_relevant = sorted(relevant_files.keys(), key=lambda p: relevance_scores.get(p, 0), reverse=True)

        # =============================================================
        # Step 3: Code inventory (Sonnet, parallel, checkpointed)
        # =============================================================
        print("\n=== Step 3: Code inventory (Sonnet, parallel) ===", flush=True)

        cached_inventory = inventory_cache_ns.get("result")
        if cached_inventory:
            code_inventory = cached_inventory
            print(f"  Using cached inventory ({len(code_inventory)} chars)", flush=True)
        else:
            inventory_prompt_template = f"""You are a security code analyst. Extract a structured code inventory from each file below.

For each file, produce:
1. **Imports** — list all imports (especially security-related: auth, crypto, validators, sanitizers, path handling)
2. **Classes** — name, base classes, key methods with signatures
3. **Functions** — name, parameters (with types if available), decorators, line numbers (approximate)
4. **Security-relevant patterns** — validators, auth checks, path operations, file operations, crypto operations
5. **Routes/endpoints** — any URL routing, decorators like @app.route, @router.get, etc.
6. **Configuration** — security-relevant config values, environment variables

Return the inventory as structured markdown. Be thorough but concise.

FILES:
"""

            SAFE_SONNET_LIMIT_INV = int(SONNET_CONTEXT * 0.40)
            inv_template_tokens = count_tokens(inventory_prompt_template, SONNET_PROVIDER, SONNET_MODEL)
            inv_budget = SAFE_SONNET_LIMIT_INV - inv_template_tokens

            inv_batches = []
            current_batch = {}
            current_tokens = 0
            for path in sorted_relevant:
                content = relevant_files[path]
                entry = f"\n--- {path} ---\n{content}\n"
                entry_tokens = count_tokens(entry, SONNET_PROVIDER, SONNET_MODEL)
                if entry_tokens > inv_budget:
                    if current_batch:
                        inv_batches.append(current_batch)
                        current_batch = {}
                        current_tokens = 0
                    inv_batches.append({path: entry})
                    continue
                if current_tokens + entry_tokens > inv_budget and current_batch:
                    inv_batches.append(current_batch)
                    current_batch = {}
                    current_tokens = 0
                current_batch[path] = entry
                current_tokens += entry_tokens
            if current_batch:
                inv_batches.append(current_batch)

            print(f"  Code inventory: {len(inv_batches)} batches", flush=True)

            async def inventory_batch(i, batch):
                async with sonnet_semaphore:
                    entries_text = "".join(batch.values())
                    prompt = inventory_prompt_template + entries_text
                    messages = [{"role": "user", "content": prompt}]

                    msg_tokens = count_message_tokens(messages, SONNET_PROVIDER, SONNET_MODEL)
                    if msg_tokens > int(SONNET_CONTEXT * 0.80):
                        items = list(batch.items())
                        mid = len(items) // 2
                        results = []
                        for sub_items in [items[:mid], items[mid:]]:
                            sub_text = "".join([v for _, v in sub_items])
                            sub_messages = [{"role": "user", "content": inventory_prompt_template + sub_text}]
                            try:
                                resp, _ = await call_llm(
                                    provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                    messages=sub_messages, parameters=SONNET_PARAMS,
                                    timeout=300,
                                )
                                results.append(resp)
                            except Exception as e:
                                print(f"    Inventory sub-batch failed: {e}", flush=True)
                        return "\n\n".join(results)

                    for attempt in range(2):
                        try:
                            resp, _ = await call_llm(
                                provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                messages=messages, parameters=SONNET_PARAMS,
                                timeout=300,
                            )
                            print(f"    Inventory batch {i+1} complete", flush=True)
                            return resp
                        except Exception as e:
                            if attempt == 0:
                                print(f"    Inventory batch {i+1} attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                                await asyncio.sleep(5)
                            else:
                                print(f"    Inventory batch {i+1} FAILED: {e}", flush=True)
                                return ""

            inventory_results = await asyncio.gather(*[
                inventory_batch(i, batch)
                for i, batch in enumerate(inv_batches)
            ])
            code_inventory = "\n\n---\n\n".join([r for r in inventory_results if r])
            inventory_cache_ns.set("result", code_inventory)

        print(f"  Inventory total: {len(code_inventory)} chars", flush=True)

        # =============================================================
        # Step 4: Deep security analysis (Opus, checkpointed, with retry)
        # =============================================================
        print("\n=== Step 4: Deep security analysis (Opus) ===", flush=True)

        analysis_system_prompt = f"""You are an expert application security auditor performing a comprehensive security audit against ASVS requirements.

## ASVS Requirement Under Audit
{asvs_description}

## Audit Instructions

Follow ALL of these analysis requirements:

### Core Principle: Existence ≠ Application
For each security control found:
- Document where it's DEFINED
- Map ALL entry points that should use it
- Verify it's actually CALLED at each entry point
- Flag coverage gaps (control exists but not applied = CRITICAL)

### Gap Type Classification
| Gap Type | Description | Severity |
|----------|-------------|----------|
| Type A | Entry point with NO control | Standard vulnerability |
| Type B | Control EXISTS but NOT CALLED | CRITICAL (false confidence) |
| Type C | Control CALLED but RESULT IGNORED | CRITICAL |
| Type D | Control CALLED but AFTER sensitive operation | CRITICAL |

### Related Function Analysis
When you find a vulnerability, IMMEDIATELY search for:
- Singular/plural variants
- Sync/async variants
- Public/private variants
- Same-file functions with similar parameters or operations

### False Positive Prevention
Before finalizing each finding:
1. Where does this input ACTUALLY originate? Is it truly user-controllable?
2. Is there validation applied EARLIER in the call chain?
3. Can an external attacker actually control this value?
4. If you listed something as a positive pattern, don't also list it as a vulnerability

### Exclusions
Do NOT report:
- Database-sourced values without injection path
- Already-validated inputs
- Developer tooling/test code
- Issues requiring prior compromise
- Theoretical issues without specific exploit
- Test/example code

### Output Requirements
For each finding, provide:
- Severity level (CRITICAL/HIGH/MEDIUM/LOW)
- Finding ID (format: ASVS-{asvs.replace('.', '')}-SEV-NNN)
- Exact file location and function name with line numbers
- Vulnerable code quote
- Data flow (source → sink → missing control)
- Proof of concept (specific malicious request)
- Impact description
- Remediation with code example

Also provide:
- Security Controls Inventory with coverage analysis
- Critical File Review tables
- Positive Security Patterns
- Architecture Observations
- Prioritized Recommendations

Be thorough but precise. If something is done correctly, acknowledge it as a positive pattern - don't invent issues."""

        SAFE_OPUS_LIMIT = int(OPUS_CONTEXT * 0.40)
        system_tokens = count_tokens(analysis_system_prompt, OPUS_PROVIDER, OPUS_MODEL)
        inventory_section = f"\n\n## Code Inventory (extracted by pre-analysis)\n\n{code_inventory}\n\n"
        inventory_tokens = count_tokens(inventory_section, OPUS_PROVIDER, OPUS_MODEL)
        user_template = "## Source Code Files\n\nAnalyze the following files for security issues related to the ASVS requirement:\n\n"
        user_template_tokens = count_tokens(user_template, OPUS_PROVIDER, OPUS_MODEL)

        # Always cap inventory to 15% of safe limit to leave room for code content.
        # Without this cap, a 180K char inventory eats ~45K tokens, leaving only
        # ~33K for code — forcing 11+ tiny Opus batches and more Bedrock failures.
        max_inv_tokens = int(SAFE_OPUS_LIMIT * 0.15)
        if inventory_tokens > max_inv_tokens:
            print(f"  Truncating inventory from {inventory_tokens} to {max_inv_tokens} tokens", flush=True)
            inv_lines = code_inventory.split('\n')
            truncated_inv = ""
            for line in inv_lines:
                candidate = truncated_inv + line + "\n"
                if count_tokens(candidate, OPUS_PROVIDER, OPUS_MODEL) > max_inv_tokens:
                    break
                truncated_inv = candidate
            inventory_section = f"\n\n## Code Inventory (extracted by pre-analysis, truncated)\n\n{truncated_inv}\n\n"
            inventory_tokens = count_tokens(inventory_section, OPUS_PROVIDER, OPUS_MODEL)

        opus_content_budget = SAFE_OPUS_LIMIT - system_tokens - inventory_tokens - user_template_tokens

        print(f"  Opus content budget: {opus_content_budget} tokens", flush=True)

        # Create batches of file content for Opus
        opus_batches = []
        current_batch = {}
        current_tokens = 0
        for path in sorted_relevant:
            content = relevant_files[path]
            entry = f"\n### File: `{path}`\n```\n{content}\n```\n"
            entry_tokens = count_tokens(entry, OPUS_PROVIDER, OPUS_MODEL)
            if entry_tokens > opus_content_budget:
                if current_batch:
                    opus_batches.append(current_batch)
                    current_batch = {}
                    current_tokens = 0
                opus_batches.append({path: entry})
                continue
            if current_tokens + entry_tokens > opus_content_budget and current_batch:
                opus_batches.append(current_batch)
                current_batch = {}
                current_tokens = 0
            current_batch[path] = entry
            current_tokens += entry_tokens
        if current_batch:
            opus_batches.append(current_batch)

        print(f"  Deep analysis: {len(opus_batches)} batches", flush=True)

        async def analyze_batch(i, batch):
            cache_key = f"batch-{i}"
            cached = analysis_cache_ns.get(cache_key)
            if cached:
                print(f"    Opus batch {i+1}: cached", flush=True)
                return cached

            async with opus_semaphore:
                entries_text = "".join(batch.values())
                user_content = user_template + entries_text + inventory_section
                messages = [
                    {"role": "user", "content": analysis_system_prompt + "\n\n" + user_content}
                ]

                msg_tokens = count_message_tokens(messages, OPUS_PROVIDER, OPUS_MODEL)
                limit = int(OPUS_CONTEXT * 0.80)
                print(f"    Opus batch {i+1}/{len(opus_batches)}: {msg_tokens} tokens, {len(batch)} files", flush=True)

                if msg_tokens > limit:
                    items = list(batch.items())
                    if len(items) > 1:
                        mid = len(items) // 2
                        results = []
                        for half_label, half_items in [("a", items[:mid]), ("b", items[mid:])]:
                            half_text = "".join([v for _, v in half_items])
                            half_user = user_template + half_text + inventory_section
                            half_messages = [{"role": "user", "content": analysis_system_prompt + "\n\n" + half_user}]
                            for attempt in range(3):
                                try:
                                    resp, _ = await call_llm(
                                        provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                        messages=half_messages, parameters=OPUS_PARAMS,
                                        timeout=1800,
                                    )
                                    results.append(resp)
                                    print(f"      Sub-batch {half_label} complete", flush=True)
                                    break
                                except Exception as e:
                                    if attempt < 2:
                                        wait = 15 * (attempt + 1)
                                        print(f"      Sub-batch {half_label} attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                                        await asyncio.sleep(wait)
                                    else:
                                        print(f"      Sub-batch {half_label} FAILED after 3 attempts: {e}", flush=True)
                                        results.append(f"[Analysis failed for sub-batch {i+1}{half_label}: {str(e)[:200]}]")
                        combined = "\n\n---\n\n".join(results)
                        analysis_cache_ns.set(cache_key, combined)
                        return combined
                    else:
                        # Single large file — try without inventory
                        key, entry_val = items[0]
                        slim_messages = [{"role": "user", "content": analysis_system_prompt + "\n\n" + user_template + entry_val}]
                        for attempt in range(3):
                            try:
                                resp, _ = await call_llm(
                                    provider=OPUS_PROVIDER, model=OPUS_MODEL,
                                    messages=slim_messages, parameters=OPUS_PARAMS,
                                    timeout=1800,
                                )
                                analysis_cache_ns.set(cache_key, resp)
                                return resp
                            except Exception as e:
                                if attempt < 2:
                                    wait = 15 * (attempt + 1)
                                    print(f"      Single file attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                                    await asyncio.sleep(wait)
                                else:
                                    print(f"      Single file FAILED after 3 attempts: {e}", flush=True)
                                    return f"[Analysis failed for {key}: {str(e)[:200]}]"

                # Normal path — retry up to 3 times
                for attempt in range(3):
                    try:
                        resp, _ = await call_llm(
                            provider=OPUS_PROVIDER, model=OPUS_MODEL,
                            messages=messages, parameters=OPUS_PARAMS,
                            timeout=1800,
                        )
                        analysis_cache_ns.set(cache_key, resp)
                        print(f"    Opus batch {i+1} complete", flush=True)
                        return resp
                    except Exception as e:
                        if attempt < 2:
                            wait = 15 * (attempt + 1)
                            print(f"    Opus batch {i+1} attempt {attempt+1} failed ({type(e).__name__}), retrying in {wait}s...", flush=True)
                            await asyncio.sleep(wait)
                        else:
                            print(f"    Opus batch {i+1} FAILED after 3 attempts: {e}", flush=True)
                            return f"[Analysis failed for batch {i+1}: {str(e)[:200]}]"

        # Run Opus batches (limited concurrency via semaphore)
        analysis_results = await asyncio.gather(*[
            analyze_batch(i, batch)
            for i, batch in enumerate(opus_batches)
        ])

        analysis_results = [r for r in analysis_results if r and not r.startswith("[Analysis failed")]
        print(f"  Analysis complete: {len(analysis_results)} results", flush=True)

        if not analysis_results:
            return {"outputText": "Error: All analysis batches failed. No results to report."}

        # =============================================================
        # Step 5: Consolidation if needed (Sonnet)
        # =============================================================
        if len(analysis_results) > 1:
            print(f"\n=== Step 5: Consolidating {len(analysis_results)} results (Sonnet) ===", flush=True)

            CONSOLIDATION_TEMPLATE = f"""You are consolidating multiple security audit batch results into a single unified analysis.

ASVS Requirement: {asvs}
{asvs_description}

## Consolidation Rules:
1. DEDUPLICATE - Merge findings describing the same vulnerability
2. CHECK CONTRADICTIONS - If something appears as a positive pattern in ANY batch, remove from findings
3. VERIFY DATA ORIGINS - Remove findings where source is database/config without user injection path
4. CONSISTENT SEVERITY - Ensure similar issues have same severity
5. REMOVE OUT-OF-SCOPE - Exclude test files, dev scripts
6. VERIFY COMPLETENESS - For each vulnerability, confirm related functions were checked

Consolidate these analysis results into a single comprehensive security audit report.
Preserve all specific findings with their exact code references, but merge duplicates.
Include a "Consolidation Notes" section documenting what was removed/merged and why.

BATCH RESULTS TO CONSOLIDATE:
"""

            consolidation_params = {**SONNET_PARAMS, "max_tokens": 16384}
            template_tokens_cons = count_tokens(CONSOLIDATION_TEMPLATE, SONNET_PROVIDER, SONNET_MODEL)
            max_cons_content = int(SONNET_CONTEXT * 0.40) - template_tokens_cons

            consolidation_round = 0
            MAX_CONSOLIDATION_ROUNDS = 5
            batch_results = analysis_results[:]

            while len(batch_results) > 1:
                consolidation_round += 1
                prev_count = len(batch_results)
                next_level = []
                group = []
                group_tokens = 0

                for result in batch_results:
                    result_tokens = count_tokens(result, SONNET_PROVIDER, SONNET_MODEL)
                    if group and (group_tokens + result_tokens) > max_cons_content:
                        for attempt in range(2):
                            try:
                                cons_prompt = CONSOLIDATION_TEMPLATE + "\n---\n".join(group)
                                consolidated, _ = await call_llm(
                                    provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                    messages=[{"role": "user", "content": cons_prompt}],
                                    parameters=consolidation_params,
                                    timeout=300,
                                )
                                next_level.append(consolidated)
                                break
                            except Exception as e:
                                if attempt == 0:
                                    print(f"    Consolidation attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                                    await asyncio.sleep(5)
                                else:
                                    print(f"    Consolidation failed, keeping individual results", flush=True)
                                    next_level.extend(group)
                        group = []
                        group_tokens = 0
                    group.append(result)
                    group_tokens += result_tokens

                if group:
                    if len(group) == 1 and not next_level:
                        next_level.append(group[0])
                    else:
                        for attempt in range(2):
                            try:
                                cons_prompt = CONSOLIDATION_TEMPLATE + "\n---\n".join(group)
                                consolidated, _ = await call_llm(
                                    provider=SONNET_PROVIDER, model=SONNET_MODEL,
                                    messages=[{"role": "user", "content": cons_prompt}],
                                    parameters=consolidation_params,
                                    timeout=300,
                                )
                                next_level.append(consolidated)
                                break
                            except Exception as e:
                                if attempt == 0:
                                    print(f"    Consolidation attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                                    await asyncio.sleep(5)
                                else:
                                    print(f"    Consolidation failed, keeping individual results", flush=True)
                                    next_level.extend(group)

                print(f"    Round {consolidation_round}: {prev_count} -> {len(next_level)}", flush=True)
                batch_results = next_level

                if len(batch_results) >= prev_count:
                    print(f"    No progress, stopping", flush=True)
                    break
                if consolidation_round >= MAX_CONSOLIDATION_ROUNDS:
                    print(f"    Max rounds reached", flush=True)
                    break

            consolidated_analysis = "\n\n---\n\n".join(batch_results)
        else:
            consolidated_analysis = analysis_results[0]

        # =============================================================
        # Step 6: Format report (Sonnet)
        # =============================================================
        print("\n=== Step 6: Formatting report (Sonnet) ===", flush=True)

        def count_findings(content):
            counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            counts["Critical"] = len(re.findall(r'###\s*\[CRITICAL\]', content, re.IGNORECASE))
            counts["High"] = len(re.findall(r'###\s*\[HIGH\]', content, re.IGNORECASE))
            counts["Medium"] = len(re.findall(r'###\s*\[MEDIUM\]', content, re.IGNORECASE))
            counts["Low"] = len(re.findall(r'###\s*\[LOW\]', content, re.IGNORECASE))
            if sum(counts.values()) == 0:
                counts["Critical"] += len(re.findall(r'###[^\n]*-CRIT-', content, re.IGNORECASE))
                counts["High"] += len(re.findall(r'###[^\n]*-HIGH-', content, re.IGNORECASE))
                counts["Medium"] += len(re.findall(r'###[^\n]*-MED-', content, re.IGNORECASE))
                counts["Low"] += len(re.findall(r'###[^\n]*-LOW-', content, re.IGNORECASE))
            if sum(counts.values()) == 0:
                counts["Critical"] += len(re.findall(r'\*\*Severity\*\*:\s*Critical', content, re.IGNORECASE))
                counts["High"] += len(re.findall(r'\*\*Severity\*\*:\s*High', content, re.IGNORECASE))
                counts["Medium"] += len(re.findall(r'\*\*Severity\*\*:\s*Medium', content, re.IGNORECASE))
                counts["Low"] += len(re.findall(r'\*\*Severity\*\*:\s*Low', content, re.IGNORECASE))
            return counts

        findings_count = count_findings(consolidated_analysis)
        file_list = "\n".join([f"- `{p}` (relevance: {relevance_scores.get(p, '?')})" for p in sorted_relevant])

        format_prompt = f"""You are formatting a security audit report into clean, professional markdown.

ASVS Requirement: {asvs}
{asvs_description}

## Formatting Requirements

Format the analysis below into the following structure. Preserve ALL specific findings, code references,
line numbers, and technical details exactly as provided. Do not add, remove, or modify any findings.

Required structure:
1. **Executive Summary** — with these EXACT metadata values (do NOT invent names):
   - **Repository:** {repo_name}
   - **Audit Date:** {audit_date}
   - **Auditor:** Tooling Agents
   - **ASVS Requirement:** {asvs} — {asvs_description[:500]}
   - Files analyzed: {len(relevant_files)} relevant out of {len(filtered_files)} total, {skipped_count} skipped
   - Finding counts table
2. **Security Controls Inventory** — each control with location, purpose, coverage status
3. **Critical File Review** — tables for key files showing all security-sensitive functions reviewed
4. **Findings** — grouped by severity (Critical → High → Medium → Low), each with:
   - ID (format: ASVS-{asvs.replace('.', '')}-SEV-NNN)
   - Location with file, function, line numbers
   - Related functions checked
   - Description, vulnerable code, data flow, PoC, impact, remediation
5. **Positive Security Patterns** — what's done well
6. **Architecture Observations**
7. **Recommendations Summary** — Immediate/Short-term/Long-term
8. **Appendix: Files Analyzed** — collapsible list

Finding counts detected: Critical={findings_count['Critical']}, High={findings_count['High']}, Medium={findings_count['Medium']}, Low={findings_count['Low']}

## Files Analyzed
{file_list}

## Analysis to Format

{consolidated_analysis}"""

        format_messages = [{"role": "user", "content": format_prompt}]
        format_tokens = count_message_tokens(format_messages, SONNET_PROVIDER, SONNET_MODEL)
        sonnet_limit = int(SONNET_CONTEXT * 0.80)

        print(f"  Format prompt: {format_tokens} tokens (limit: {sonnet_limit})", flush=True)

        if format_tokens <= sonnet_limit:
            for attempt in range(2):
                try:
                    final_report, _ = await call_llm(
                        provider=SONNET_PROVIDER, model=SONNET_MODEL,
                        messages=format_messages, parameters=SONNET_PARAMS,
                        timeout=600,
                    )
                    break
                except Exception as e:
                    if attempt == 0:
                        print(f"  Formatting attempt 1 failed ({type(e).__name__}), retrying...", flush=True)
                        await asyncio.sleep(5)
                    else:
                        print(f"  Formatting failed, using raw analysis: {e}", flush=True)
                        final_report = consolidated_analysis
        else:
            print(f"  Format prompt too large, using raw analysis with header", flush=True)
            header = f"""# Security Audit Report

## Executive Summary

| Field | Value |
|-------|-------|
| **Repository** | {repo_name} |
| **Audit Date** | {audit_date} |
| **Auditor** | Tooling Agents |
| **ASVS Requirement** | {asvs} — {asvs_description[:500]} |
| **Files Analyzed** | {len(relevant_files)} relevant / {len(filtered_files)} total |
| **Files Skipped** | {skipped_count} |
| **Analysis Batches** | {len(opus_batches)} |

### Findings Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {findings_count['Critical']} |
| 🟠 High | {findings_count['High']} |
| 🟡 Medium | {findings_count['Medium']} |
| 🟢 Low | {findings_count['Low']} |

---

"""
            appendix = f"""

---

## Appendix: Files Analyzed

<details>
<summary>Click to expand ({len(relevant_files)} files)</summary>

{file_list}

</details>
"""
            final_report = header + consolidated_analysis + appendix

        # Save report
        report_ns = data_store.use_namespace("audit-reports")
        report_key = f"asvs-{asvs}-{'-'.join(namespaces)}"
        report_ns.set(report_key, {
            "asvs": asvs,
            "namespaces": namespaces,
            "files_analyzed": len(relevant_files),
            "files_total": len(filtered_files),
            "files_skipped": skipped_count,
            "findings": findings_count,
            "report": final_report[:50000],
        })

        print(f"\n=== Done: {len(final_report)} chars ===", flush=True)
        return {"outputText": final_report}

    finally:
        await http_client.aclose()
