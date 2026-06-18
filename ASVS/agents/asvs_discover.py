# asvs_discover
#
# Scans a downloaded codebase, classifies its security architecture, and
# generates an audit plan: passes (groups of ASVS sections sharing a file
# scope), domain groupings, and false-positive guidance.
#
# Improvements over original:
#   - Steps 3 (security domains) and 4 (false positive guidance) both depend
#     only on the Step 2 architecture output. They are independent of each
#     other but were called sequentially. Now run in parallel via
#     asyncio.gather, saving ~1-2 minutes per repo.
#   - Same I/O contract — drop-in replacement.
#
# Note: discovery is only ~0.5% of pipeline wall-clock. Bigger wins live in
# asvs_audit / asvs_bundle and the orchestrator.

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx

async def run(input_dict, tools):
    mcpc = { url : RemoteMCPClient(remote_url = url) for url in tools.keys() }
    http_client = httpx.AsyncClient()
    try:
        import json
        import re

        def _repair_truncated_json(s):
            """Best-effort repair of JSON truncated mid-structure (the model
            hit its output token cap). Walks the string tracking string/escape
            state and the bracket stack, drops any trailing partial token after
            the last complete element, and closes open strings/arrays/objects.
            Returns a repaired string or None if it can't form anything valid.
            Defined inside run() per the gofannon recompile convention (module-
            level helpers are not in scope when run() executes)."""
            if not s:
                return None
            stack = []
            in_str = False
            escaped = False
            last_safe = None  # index just after the last completed value/element
            for i, ch in enumerate(s):
                if in_str:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == '"':
                        in_str = False
                        last_safe = i + 1
                    continue
                if ch == '"':
                    in_str = True
                elif ch in "{[":
                    stack.append("}" if ch == "{" else "]")
                elif ch in "}]":
                    if stack:
                        stack.pop()
                    last_safe = i + 1
                elif ch in ",":
                    last_safe = i  # cut BEFORE a dangling comma
                elif ch.strip() == "" or ch.isdigit() or ch in "tfnaluersTFN.-+eE":
                    if ch in "0123456789}]\"":
                        last_safe = i + 1
            # Truncate to the last structurally-safe point, then close opens.
            if last_safe is None:
                return None
            head = s[:last_safe].rstrip().rstrip(",")
            # Recompute the open-bracket stack for the truncated head, since
            # last_safe may sit inside nested structure.
            stack2 = []
            in_str = False
            escaped = False
            for ch in head:
                if in_str:
                    if escaped:
                        escaped = False
                    elif ch == "\\":
                        escaped = True
                    elif ch == '"':
                        in_str = False
                    continue
                if ch == '"':
                    in_str = True
                elif ch in "{[":
                    stack2.append("}" if ch == "{" else "]")
                elif ch in "}]":
                    if stack2:
                        stack2.pop()
            if in_str:
                head += '"'
            head += "".join(reversed(stack2))
            return head

        input_namespace = input_dict.get("inputNamespace", "")

        # ASVS level filtering — if set, exclude sections above this
        # level from discover's analysis so we don't waste a Sonnet call
        # classifying sections the audit phase will immediately throw
        # away. Same parsing rules the orchestrator uses for its own
        # post-discovery filter ("1" → "L1", lowercase OK, empty = no
        # filter / treat as L3).
        level = (input_dict.get("level") or "").strip().upper()
        if level and not level.startswith("L"):
            level = f"L{level}"
        LEVEL_ORDER = {"L1": 1, "L2": 2, "L3": 3}
        max_level_num = LEVEL_ORDER.get(level, 3)

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
        # Sonnet 4.6: 1M context (up from 200K). CONTEXT_WINDOW and
        # SAFE_LIMIT below recompute against 1M via get_context_window, so
        # the classification batcher packs far more files per call and emits
        # many fewer batches over a large tree. max_tokens 16384 -> 32768
        # (the domain-generation call already overrides to 32000); under the
        # 64000 output ceiling.
        MODEL = "us.anthropic.claude-sonnet-4-6"
        PARAMS = {"temperature": 0.7, "max_tokens": 32768}
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
            if not ns.startswith("files:"):
                # Supplemental namespaces (audit_guidance:*, threat-model docs,
                # vendored-lib code, etc.) are loaded by the audit/bundle phase
                # as additional context. Discover only classifies primary
                # source code, so skip non-primary namespaces here.
                print(f"  [discover] skipping non-primary namespace for classification: {ns}", flush=True)
                continue
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
        # Previously: single Sonnet call with as many file previews as
        # would fit, OR path-only mode when even the path list barely
        # fit. For big repos (airflow-core ~2,332 files), the previews
        # mode silently truncated to the first N files that fit, and
        # the path-only mode forced Sonnet to classify the architecture
        # from filenames alone. Both produced poor architecture data,
        # which downstream caused Step 3 to hallucinate file paths
        # because it had nothing accurate to anchor against.
        #
        # Now: chunk files into preview-sized batches, classify each
        # in parallel, then merge the partial architectures. Every
        # file gets a preview-level look. Same downstream contract —
        # `architecture` ends up as a single merged dict.
        print("\n=== Step 2: Architecture classification (batched) ===", flush=True)

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

Use EXACT file paths from the FILES section. Do not abbreviate, normalize, or
invent paths — downstream tooling uses these as cache and audit keys.
"""

        template_tokens = count_tokens(CLASSIFY_PROMPT, PROVIDER, MODEL)
        preview_budget = SAFE_LIMIT - template_tokens

        # Build batches of files-with-previews that each fit within budget.
        # Order by path for stable batching across re-runs.
        arch_batches = []
        current_entries = []
        current_tokens = 0
        for path in sorted(all_files.keys()):
            entry = f"\n--- {path} ---\n{file_previews[path]}\n"
            entry_tokens = count_tokens(entry, PROVIDER, MODEL)
            if current_tokens + entry_tokens > preview_budget and current_entries:
                arch_batches.append(current_entries)
                current_entries = []
                current_tokens = 0
            current_entries.append(entry)
            current_tokens += entry_tokens
        if current_entries:
            arch_batches.append(current_entries)

        print(f"  Batches: {len(arch_batches)} ({sum(len(b) for b in arch_batches)} files with previews)", flush=True)

        async def classify_batch(i, entries):
            content = CLASSIFY_PROMPT + f"\n\nFILES (batch {i+1}/{len(arch_batches)}):\n" + "".join(entries)
            # Retries are handled centrally in call_llm (rate-limit and
            # timeout backoff). If call_llm exhausts retries the batch is
            # dropped from the merge — the same behavior as before, just
            # with proper backoff getting us there.
            try:
                result, _ = await call_llm(
                    provider=PROVIDER, model=MODEL,
                    messages=[{"role": "user", "content": content}],
                    parameters=PARAMS,
                    timeout=300,
                )
                json_match = re.search(r'\{[\s\S]*\}', result)
                if json_match:
                    partial = json.loads(json_match.group())
                    print(f"  Batch {i+1}: {len(partial.get('auth_systems', []))} auth, "
                          f"{len(partial.get('api_layers', []))} api, "
                          f"{len(partial.get('security_relevant_areas', []))} areas",
                          flush=True)
                    return partial
            except Exception as e:
                print(f"  Batch {i+1} FAILED: {e}", flush=True)
            return None

        partial_architectures = await asyncio.gather(*[
            classify_batch(i, b) for i, b in enumerate(arch_batches)
        ])
        partial_architectures = [p for p in partial_architectures if p]

        if not partial_architectures:
            return {"outputText": json.dumps({"error": "Failed to classify codebase architecture (all batches failed)"})}

        # Deterministic merge: dedupe arrays by name/area, union files lists,
        # first-wins for scalars, take the most-complete dict for nested objects.
        # Programmatic merge is preferred over an LLM synthesis call because it
        # is reproducible, free, and can't introduce its own hallucinations.
        def _merge_architectures(parts):
            if len(parts) == 1:
                return parts[0]
            merged = {
                "framework": "",
                "language": "",
                "auth_systems": [],
                "api_layers": [],
                "data_layer": {},
                "execution_model": {},
                "security_relevant_areas": [],
                "trust_model": "",
            }
            # Scalar fields: first non-empty wins
            for p in parts:
                for k in ("framework", "language", "trust_model"):
                    if not merged[k] and p.get(k):
                        merged[k] = p[k]
            # Array-of-dict fields: dedupe by identifying key, union files
            for arr_key, id_key in (
                ("auth_systems", "name"),
                ("api_layers", "name"),
                ("security_relevant_areas", "area"),
            ):
                by_id = {}
                for p in parts:
                    for item in p.get(arr_key, []) or []:
                        if not isinstance(item, dict):
                            continue
                        ident = item.get(id_key, "") or ""
                        if ident not in by_id:
                            by_id[ident] = dict(item)
                        else:
                            existing_files = set(by_id[ident].get("files", []) or [])
                            existing_files.update(item.get("files", []) or [])
                            by_id[ident]["files"] = sorted(existing_files)
                merged[arr_key] = list(by_id.values())
            # Dict fields: pick the most complete (most keys with non-empty values)
            for k in ("data_layer", "execution_model"):
                best = {}
                best_score = -1
                for p in parts:
                    candidate = p.get(k) or {}
                    if not isinstance(candidate, dict):
                        continue
                    score = sum(1 for v in candidate.values() if v)
                    if score > best_score:
                        best = candidate
                        best_score = score
                merged[k] = best
            return merged

        architecture = _merge_architectures(partial_architectures)
        print(f"  Merged from {len(partial_architectures)} batch(es):", flush=True)
        print(f"    Framework: {architecture.get('framework', '?')}", flush=True)
        print(f"    Auth systems: {len(architecture.get('auth_systems', []))}", flush=True)
        print(f"    API layers: {len(architecture.get('api_layers', []))}", flush=True)
        print(f"    Security-relevant areas: {len(architecture.get('security_relevant_areas', []))}", flush=True)

        if not architecture:
            return {"outputText": json.dumps({"error": "Failed to classify codebase architecture"})}

        # =============================================================
        # Steps 3 & 4: domains and false-positive guidance run in PARALLEL
        # (both depend only on `architecture`)
        # =============================================================
        print("\n=== Steps 3 & 4: Domains + false-positive guidance (parallel) ===", flush=True)

        # ----- Step 3 prep -----
        asvs_sections_available = []
        sections_dropped_above_level = 0
        try:
            # Single get_all() load instead of list_keys + per-key
            # get(). With ~345 ASVS requirements, the old shape made
            # ~346 sequential CouchDB calls; get_all() is one round
            # trip regardless of N.
            asvs_ns = data_store.use_namespace("asvs")
            all_data = asvs_ns.get_all() or {}
            req_items = {k: v for k, v in all_data.items() if k.startswith("asvs:requirements:")}
            for rk in sorted(req_items.keys()):
                req = req_items[rk]
                if req:
                    section_id = rk.replace("asvs:requirements:", "")
                    # ASVS req levels are integers (1, 2, 3). Skip
                    # anything above the requested max; sections with
                    # missing/non-int levels default to 1 so they're
                    # always included rather than silently dropped.
                    try:
                        req_level_num = int(req.get("level", 1))
                    except (TypeError, ValueError):
                        req_level_num = 1
                    if req_level_num > max_level_num:
                        sections_dropped_above_level += 1
                        continue
                    req_level = req.get("level", "?")
                    desc = req.get("req_description", "")[:100]
                    asvs_sections_available.append(f"{section_id} (L{req_level}): {desc}")
            if level:
                print(
                    f"  Filtered ASVS sections to level {level}: "
                    f"{len(asvs_sections_available)} included, "
                    f"{sections_dropped_above_level} dropped above L{max_level_num}",
                    flush=True,
                )
        except Exception as e:
            print(f"  WARNING: Could not load ASVS sections: {e}", flush=True)

        # Show the model EVERY section, not just the first 200. ASVS v5 has
        # ~345 sections; truncating caused the model to hallucinate plausible-
        # looking IDs (e.g., "2.4.5") to fill out the "every section must appear
        # in exactly one domain" constraint, which downstream caused audits to
        # run against nonexistent requirements.
        asvs_list = "\n".join(asvs_sections_available)
        valid_section_ids = {
            line.split(" ", 1)[0] for line in asvs_sections_available
        }

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

        async def call_for_domains():
            # Retries handled centrally in call_llm. On exhaustion the
            # discover step returns an error envelope and the orchestrator
            # aborts the audit — preferable to silently proceeding with
            # bogus domain assignments.
            # (A) max_tokens raised from 32000 to 64000. The domain JSON echoes
            # every file path into per-domain "files" arrays, so output size
            # scales with repo file count, not domain count. On very large
            # repos (e.g. hadoop) 32000 truncated the JSON mid-structure and
            # json.loads failed with a cryptic "Expecting ',' delimiter". 64000
            # is near Sonnet's practical output ceiling — it covers the large
            # repos but is NOT unbounded; a big enough repo can still overflow,
            # which is what (B) below handles gracefully.
            try:
                result, _ = await call_llm(
                    provider=PROVIDER, model=MODEL,
                    messages=[{"role": "user", "content": DOMAIN_PROMPT}],
                    parameters={**PARAMS, "max_tokens": 64000},
                    timeout=900,
                )
            except Exception as e:
                print(f"  Domains FAILED (LLM call): {type(e).__name__}: {e}",
                      flush=True)
                return None

            # (B) Truncation-tolerant parse. call_llm returns only (content,
            # thoughts) — no finish_reason — so truncation can't be detected
            # from API metadata; it's detected structurally here. Three tiers:
            #   1. parse the matched {...} as-is (the normal path);
            #   2. if that fails, attempt to REPAIR likely-truncated JSON by
            #      closing unterminated strings/arrays/objects, then re-parse;
            #   3. if repair also fails, emit a PRECISE diagnostic (output size
            #      + offset) so the failure reads as "truncated/too large",
            #      not a cryptic delimiter error.
            json_match = re.search(r'\{[\s\S]*\}', result)
            if not json_match:
                print(f"  Domains FAILED: no JSON object found in domain "
                      f"output ({len(result)} chars)", flush=True)
                return None
            raw = json_match.group()
            try:
                return json.loads(raw)
            except json.JSONDecodeError as e:
                repaired = _repair_truncated_json(raw)
                if repaired is not None:
                    try:
                        parsed = json.loads(repaired)
                        print(f"  WARNING: domain JSON was truncated/malformed "
                              f"at ~char {e.pos} of {len(raw)}; recovered "
                              f"{len(parsed.get('domains', []))} domain(s) via "
                              f"repair. Some sections/files may be missing — "
                              f"the orchestrator's chapter-pass fallback will "
                              f"cover any unassigned sections.", flush=True)
                        return parsed
                    except json.JSONDecodeError:
                        pass
                # Unrecoverable. Make the cause unambiguous in the log.
                near = raw[max(0, e.pos - 60):e.pos + 60]
                print(f"  Domains FAILED: domain JSON unparseable at char "
                      f"{e.pos}/{len(raw)} ({e.msg}). This is almost certainly "
                      f"TRUNCATION — the model hit the output token cap while "
                      f"emitting per-domain file lists for a very large repo. "
                      f"Context near the break: ...{near}...", flush=True)
                return None

        async def call_for_fp_guidance():
            try:
                result, _ = await call_llm(
                    provider=PROVIDER, model=MODEL,
                    messages=[{"role": "user", "content": FP_PROMPT}],
                    parameters=PARAMS,
                    timeout=300,
                )
                json_match = re.search(r'\[[\s\S]*\]', result)
                if json_match:
                    return json.loads(json_match.group())
            except Exception as e:
                print(f"  FP guidance failed ({type(e).__name__}), continuing without", flush=True)
            return []

        # Parallelism saves ~1-2 minutes per discovery (was sequential)
        domain_result, false_positive_guidance = await asyncio.gather(
            call_for_domains(),
            call_for_fp_guidance(),
        )

        if not domain_result:
            return {"outputText": json.dumps({"error": "Failed to generate security domains"})}

        domains = domain_result.get("domains", [])
        assigned_count = sum(len(d.get("asvs_sections", [])) for d in domains)
        print(f"  Generated {len(domains)} domains, {assigned_count}/{len(asvs_sections_available)} sections assigned", flush=True)

        # Validate discovery output against the authoritative ASVS set.
        # The model occasionally hallucinates section IDs (e.g., "2.4.5" when
        # v5 has no such requirement). Drop any unrecognized IDs so they don't
        # leak into the audit phase as wasted Opus calls.
        if valid_section_ids:
            total_dropped = 0
            for d in domains:
                requested = d.get("asvs_sections", [])
                valid = [s for s in requested if s in valid_section_ids]
                dropped = [s for s in requested if s not in valid_section_ids]
                if dropped:
                    total_dropped += len(dropped)
                    print(f"    {d['name']}: dropping {len(dropped)} hallucinated section(s): {dropped[:5]}{'...' if len(dropped) > 5 else ''}", flush=True)
                d["asvs_sections"] = valid
            if total_dropped:
                print(f"  Dropped {total_dropped} hallucinated section IDs from discovery output", flush=True)

        # Same validation as ASVS section IDs: drop any file paths that
        # don't exist in `all_files`. The domain LLM hallucinates paths
        # (truncated prefixes, made-up subdirs, glob patterns it thinks
        # are valid), and unvalidated they reach bundle/audit as
        # includeFiles, which fnmatch'es zero keys and aborts with "No
        # files found in namespaces". Dropping them here at the source
        # means the bundle either gets a smaller valid list, or an empty
        # list which it correctly treats as "no filter applied" and
        # audits the full primary namespace.
        total_files_dropped = 0
        for d in domains:
            requested = d.get("files", [])
            valid_files = [f for f in requested if f in all_files]
            dropped_files = [f for f in requested if f not in all_files]
            if dropped_files:
                total_files_dropped += len(dropped_files)
                print(
                    f"    {d['name']}: dropping {len(dropped_files)} "
                    f"hallucinated file path(s): {dropped_files[:3]}"
                    f"{'...' if len(dropped_files) > 3 else ''}",
                    flush=True,
                )
            d["files"] = valid_files
            if requested and not valid_files:
                print(
                    f"    {d['name']}: ALL {len(requested)} file paths "
                    f"were hallucinated — bundle will scan full namespace "
                    f"for this domain (slower but produces findings)",
                    flush=True,
                )
        if total_files_dropped:
            print(
                f"  Dropped {total_files_dropped} hallucinated file paths "
                f"from discovery output",
                flush=True,
            )

        for d in domains:
            print(f"    {d['name']}: {len(d.get('asvs_sections', []))} sections, {len(d.get('files', []))} files", flush=True)

        if not domains:
            return {"outputText": json.dumps({"error": "Failed to generate security domains"})}

        for domain in domains:
            line_count = 0
            for path in domain.get("files", []):
                if path in all_files:
                    line_count += len(all_files[path].split('\n'))
            domain["estimated_lines"] = line_count

        print(f"  Generated {len(false_positive_guidance)} false-positive patterns", flush=True)

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