# read_and_triage
#
# Gofannon agent: GitHub issue triage bot — Phase 1
#
# Reads open issues for a given repository, comprehends the code at HEAD,
# and posts a per-issue triage comment. If the agent understands the
# problem and it relates to this repo's code or docs, the comment includes
# a proposed plan and draft diffs. Otherwise it leaves a brief "no action"
# comment.
#
# This is the read-and-comment iteration. PR-writing is Phase 3.
#
# What changed from v1 (Phase 0 → Phase 1):
#   • Repo source now arrives via a single tarball fetch instead of N
#     contents/{path} calls. Cached in data_store namespace files:{repo}
#     and tagged with the source SHA via meta:{repo}/head_sha. Re-runs at
#     the same SHA are essentially free.
#   • File selection per issue now uses Haiku-style relevance scoring
#     against 200-line previews, returning numerical 0-10 scores instead
#     of a free-form path list. Adapted from asvs_audit.py Step 2.
#   • Threshold-based picking with fallback: keep ≥4, fall back to ≥2 if
#     fewer than 3 files clear the bar.
#   • Per-issue relevance scores cached in
#     triage-cache:relevance:{repo}@{sha7}:issue-{n}.
#   • Skip lists (dirs, files, extensions) lifted from asvs_audit so the
#     namespace shape matches what the ASVS pipeline produces.
#
# Same input schema as v1, with three new optional fields:
#   relevance_provider, relevance_model     defaults to bedrock + claude-haiku-4-5
#   force_redownload                         default false
# Same output schema.
#
# Sandbox globals it uses (provided by gofannon):
#   - http_client    httpx.AsyncClient — created locally with longer timeouts
#                    here because tarballs of large repos take a while
#   - call_llm       centralized LLM gateway (NOT litellm directly)
#   - data_store     persistent KV store, namespaced
#   - get_context_window, count_tokens — for relevance-batch sizing
#   - asyncio, json, re

from agent_factory.remote_mcp_client import RemoteMCPClient
from services.llm_service import call_llm
import httpx


async def run(input_dict, tools):
    mcpc = {url: RemoteMCPClient(remote_url=url) for url in tools.keys()}
    # Tarball can be many MB on large repos; the default 5s read timeout
    # will fail on anything bigger than ~50KB/s. Match asvs_download_repo's
    # posture so we don't time out mid-extraction.
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=30.0, read=600.0, write=60.0, pool=60.0)
    )
    try:
        # ---------- sentinels ----------
        # Posted in every triage comment. Used to detect prior runs of this agent
        # so we don't re-comment on the same issue. Bump only when the comment
        # format changes.
        SENTINEL_TRIAGE = "<!-- gofannon-issue-triage-bot v2 -->"
        # Posted in standalone "see also" comments on issues that are part of a
        # duplicate/related cluster but for which we are NOT posting a fresh
        # triage comment (because they were already triaged or have an open PR).
        # Separate sentinel so the two comment types are independently
        # idempotent.
        SENTINEL_RELATED = "<!-- gofannon-issue-triage-bot v2 related -->"


        # ---------- module-level helpers ----------

        # Skip lists lifted from asvs_audit.py so the data-store namespace shape
        # matches what the ASVS pipeline produces. Anything we filter here is
        # excluded from BOTH the tarball-extraction step and the relevance-pass
        # previews — they don't go into data_store at all.
        SKIP_DIRS = {
            'node_modules', 'vendor', 'third_party', 'third-party',
            'dist', 'build', 'out', 'target',
            '__pycache__', '.pytest_cache', '.mypy_cache', 'coverage', '.next', '.nuxt',
            'assets', 'images', 'img', 'static/images', 'static/fonts', 'static/webfonts',
            'public/images', 'fonts', 'webfonts',
            '.github/workflows',
            'venv', '.venv', 'env', '.env',
            '.git', '.idea', '.vscode',
            'htmlcov',  # gofannon's own htmlcov is huge; ATR has none but keep for safety
        }
        SKIP_FILES = {
            'package-lock.json', 'yarn.lock', 'poetry.lock', 'Cargo.lock',
            'composer.lock', 'pnpm-lock.yaml', 'Gemfile.lock', 'uv.lock',
            'pdm.lock', 'go.sum',
            'LICENSE', 'LICENSE.md', 'LICENSE.txt',
            'CHANGELOG.md', 'CHANGELOG', 'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md',
            '.gitignore', '.dockerignore', '.prettierrc', '.eslintrc', '.editorconfig',
            '.npmrc', '.yarnrc',
            # Note: README.md is intentionally NOT skipped here. Triage may
            # legitimately reference it ("docs say X but code does Y"). The ASVS
            # discovery filter does skip it, but for triage that filter is too
            # aggressive.
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


        def _should_skip_file(filepath):
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


        # ---------- relevance scoring (lifted from asvs_audit.py Step 2) ----------

        _RELEVANCE_PROMPT_TEMPLATE = """You are a senior engineer triaging a GitHub issue. Given an issue and previews of files in the repository, rate each file's relevance to the issue.

        ISSUE #{number}: {title}

        ISSUE BODY:
        {body}

        Below are file paths with previews (first ~200 lines) from the repository.
        Rate each file's relevance to this issue on a scale of 0-10:
        - 10: Directly contains the code, config, or docs the issue is about
        - 7-9: Contains closely related code that would likely change for any fix
        - 4-6: May contain relevant context or patterns indirectly
        - 1-3: Unlikely to be relevant to this issue
        - 0: Definitely not relevant

        Return ONLY a JSON object mapping file paths to integer relevance scores.
        Example: {{"src/auth.py": 9, "src/utils.py": 3}}

        FILES TO EVALUATE:
        """


        async def _score_relevance(
            *, repo, head_sha, issue_number, issue_title, issue_body, all_files,
            provider, model,
        ):
            """Per-issue relevance scoring with previews + caching.

            Returns {path: int 0-10}. Cached at
            triage-cache:relevance:{repo}@{sha7}:issue-{n} so re-runs of the same
            issue at the same SHA skip the LLM calls entirely. Within a fresh run,
            files are batched under the SAFE_LIMIT (40% of the relevance model's
            context window) and batches dispatch in parallel.

            Adapted from asvs_audit.py lines 559-665. Two notable differences:
              • Issue context replaces ASVS requirement context.
              • Scores returned for ALL files seen — caller does the threshold
                + fallback logic. Keeps this function single-purpose.
            """
            cache_ns = data_store.use_namespace(
                f"triage-cache:relevance:{repo}@{head_sha[:7]}"
            )
            cache_key = f"issue-{issue_number}"
            cached = cache_ns.get(cache_key)
            if cached:
                print(f"  Issue #{issue_number}: relevance cache hit", flush=True)
                return cached

            # Build 200-line previews. For files shorter than 200 lines, include
            # the whole file. The preview cost is paid once per file per run; we
            # don't cache previews because they're cheap to recompute from the
            # in-memory all_files dict.
            file_previews = {}
            for path, content in all_files.items():
                if not content:
                    continue
                lines = content.split('\n')
                file_previews[path] = '\n'.join(lines[:200])

            if not file_previews:
                cache_ns.set(cache_key, {})
                return {}

            # 40% of context window leaves room for the prompt template, the
            # response, and a safety margin. Same proportion the ASVS pipeline
            # uses (it works well across Haiku, Sonnet, and Opus).
            try:
                context_window = get_context_window(provider, model)
            except Exception:
                context_window = 200_000  # safe default for Claude-class models
            safe_limit = int(context_window * 0.40)

            template = _RELEVANCE_PROMPT_TEMPLATE.format(
                number=issue_number,
                title=issue_title,
                body=(issue_body or "(no body)")[:8000],
            )
            try:
                template_tokens = count_tokens(template, provider, model)
            except Exception:
                template_tokens = len(template) // 3
            preview_budget = max(1024, safe_limit - template_tokens)

            # Batch by token budget. A single oversized file (rare given our 1MB
            # cap and 200-line truncation, but possible for dense one-line files)
            # is sent in its own batch with a placeholder rather than dropped.
            batches = []
            current = {}
            current_tokens = 0
            for path in sorted(file_previews.keys()):
                preview = file_previews[path]
                entry = f"\n--- {path} ---\n{preview}\n"
                try:
                    entry_tokens = count_tokens(entry, provider, model)
                except Exception:
                    entry_tokens = len(entry) // 3

                if entry_tokens > preview_budget:
                    placeholder = f"\n--- {path} ---\n[file too large for preview]\n"
                    if current:
                        batches.append(current)
                        current = {}
                        current_tokens = 0
                    batches.append({path: placeholder})
                    continue

                if current_tokens + entry_tokens > preview_budget and current:
                    batches.append(current)
                    current = {}
                    current_tokens = 0
                current[path] = entry
                current_tokens += entry_tokens
            if current:
                batches.append(current)

            print(
                f"  Issue #{issue_number}: relevance scoring {len(file_previews)} files "
                f"in {len(batches)} batch(es)",
                flush=True,
            )

            # Bound concurrent LLM calls. 5 matches the ASVS sonnet_semaphore
            # default; in practice for a single issue we rarely have more than
            # 1-3 batches anyway.
            semaphore = asyncio.Semaphore(5)

            async def score_one_batch(idx, batch):
                async with semaphore:
                    entries_text = "".join(batch.values())
                    prompt = template + entries_text
                    for attempt in range(2):
                        try:
                            content_resp, _ = await call_llm(
                                provider=provider, model=model,
                                messages=[{"role": "user", "content": prompt}],
                                parameters={"temperature": 0.3, "max_tokens": 8192},
                                user_service=None, user_id=None,
                            )
                            parsed = _parse_relevance_json(content_resp)
                            if parsed is not None:
                                return parsed
                        except Exception as e:
                            if attempt == 0:
                                print(
                                    f"    batch {idx+1} attempt 1 failed "
                                    f"({type(e).__name__}); retrying",
                                    flush=True,
                                )
                                await asyncio.sleep(2)
                            else:
                                print(
                                    f"    batch {idx+1} failed: {e}; defaulting to 5",
                                    flush=True,
                                )
                    return {p: 5 for p in batch}

            batch_results = await asyncio.gather(
                *[score_one_batch(i, b) for i, b in enumerate(batches)]
            )

            # Sanitize: keep paths that exist in all_files and clamp scores to
            # integers in [0, 10]. Anything else (hallucinated paths, non-numeric
            # scores) is dropped.
            scores = {}
            for partial in batch_results:
                for p, s in partial.items():
                    if p not in all_files:
                        continue
                    try:
                        v = int(round(float(s)))
                    except (ValueError, TypeError):
                        continue
                    scores[p] = max(0, min(10, v))

            cache_ns.set(cache_key, scores)
            return scores


        def _parse_relevance_json(text):
            """Find the first JSON object in the model's response and return it.

            Tolerant of code fences, leading/trailing prose, and balanced-brace
            nesting in string values. Returns None on failure (caller decides
            whether to retry or fall back).
            """
            if not text:
                return None
            s = text.strip()
            # Strip code fences if present
            if s.startswith("```"):
                s = re.sub(r"^```(?:json)?\s*", "", s)
                if s.endswith("```"):
                    s = s[: -len("```")].strip()

            # Walk balanced top-level {...} blocks, tracking string state so
            # quoted braces don't confuse depth tracking. Same approach as
            # asvs_consolidate._extract_finding_json, simplified.
            n = len(s)
            i = 0
            while i < n:
                if s[i] != '{':
                    i += 1
                    continue
                depth = 0
                in_str = False
                esc = False
                for j in range(i, n):
                    c = s[j]
                    if in_str:
                        if esc:
                            esc = False
                        elif c == '\\':
                            esc = True
                        elif c == '"':
                            in_str = False
                        continue
                    if c == '"':
                        in_str = True
                    elif c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            chunk = s[i:j+1]
                            try:
                                return json.loads(chunk)
                            except Exception:
                                # Try the lenient path: fix single-quoted JSON,
                                # trailing commas. Same fixups as
                                # asvs_consolidate.parse_llm_json.
                                try:
                                    fixed = re.sub(r"(?<=[{,\[])\s*'([^']+)'\s*:", r' "\1":', chunk)
                                    fixed = re.sub(r":\s*'([^']*)'", r': "\1"', fixed)
                                    fixed = re.sub(r",\s*([}\]])", r"\1", fixed)
                                    return json.loads(fixed)
                                except Exception:
                                    break
                i += 1
            return None


        # ---------- structural discovery (one per SHA, cached) ----------
        # These three passes build the agent's mental model of the repo.
        # They run ONCE per HEAD SHA and are cached. Every per-issue
        # analysis downstream gets all three as context — that's where
        # the depth comes from vs. the v1 "score previews + analyze"
        # approach. Same shape as asvs_discover + asvs_audit Step 3.

        _ARCHITECTURE_PROMPT = """You are a senior engineer mapping the structure of an unfamiliar codebase. Given the file paths and previews below, identify what this software is and how it's organized.

Return ONLY a JSON object (no surrounding prose, no markdown fences) with this structure:
{
  "framework": "e.g., FastAPI, Quart, Django, Express, Spring",
  "language": "e.g., Python, TypeScript, Go",
  "purpose": "one paragraph describing what this software does end-to-end",
  "auth_systems": [{"name": "short description", "files": ["path1", "path2"]}],
  "api_layers": [{"name": "short description", "files": ["path1", "path2"]}],
  "data_layer": {
    "database": "e.g., SQLAlchemy, plain SQL, no DB",
    "storage": "e.g., S3, local filesystem, blob store",
    "files": ["path1", "path2"]
  },
  "execution_model": {
    "description": "e.g., async web server, Celery workers, scheduled tasks",
    "files": ["path1", "path2"]
  },
  "key_subsystems": [
    {"name": "short name", "description": "what it does", "files": ["path1", "path2"]}
  ],
  "trust_model": "one paragraph describing who is trusted and what boundaries exist"
}

Use the actual file paths from the input. Be specific — name the framework, name the database, name the subsystems.

FILES:
"""

        async def _discover_architecture(*, repo, head_sha, all_files,
                                          provider, model):
            """Architecture classification, single LLM call, cached per SHA.

            Returns the JSON object above as a Python dict. {} on failure.
            """
            cache_ns = data_store.use_namespace(
                f"discovery:{repo}@{head_sha[:7]}"
            )
            cached = cache_ns.get("architecture")
            if cached:
                print(f"  Architecture: cache hit", flush=True)
                return cached

            # Use 100-line previews (was 200) — enough to identify
            # framework imports, class shapes, and route patterns
            # without spending tokens on bodies. Halves token cost
            # per file, roughly doubling fileset coverage.
            previews = {}
            for path, content in sorted(all_files.items()):
                if not content:
                    continue
                lines = content.split('\n')
                previews[path] = '\n'.join(lines[:100])

            if not previews:
                return {}

            try:
                ctx = get_context_window(provider, model)
            except Exception:
                ctx = 200_000
            # 70% safe limit (was 40%). The 40% convention from the
            # batch-processing template exists to leave room for
            # hierarchical consolidation; this pass is a single
            # one-shot with a small (~2K) JSON response, so we can
            # use the bigger share of the window for content.
            safe_limit = int(ctx * 0.70)
            try:
                template_tokens = count_tokens(
                    _ARCHITECTURE_PROMPT, provider, model
                )
            except Exception:
                template_tokens = len(_ARCHITECTURE_PROMPT) // 3
            budget = safe_limit - template_tokens

            # Sort files by architectural informativeness so that the
            # most signal-dense files get included even when the budget
            # cuts off the tail. Configs and entry points first, then
            # files matching architectural keywords, then the rest.
            def _arch_priority(path):
                parts = path.split('/')
                name = parts[-1].lower()
                depth = len(parts) - 1
                # Top-level config / build files — strongest signal
                if depth == 0 and name in (
                    "pyproject.toml", "package.json", "requirements.txt",
                    "setup.py", "setup.cfg", "cargo.toml", "go.mod",
                    "go.sum", "pom.xml", "build.gradle", "build.gradle.kts",
                    "composer.json", "gemfile", "manifest.in", "makefile",
                    "dockerfile", "compose.yaml", "compose.yml",
                    "docker-compose.yml", "docker-compose.yaml",
                ):
                    return (0, depth, name)
                # Top-level entry points
                if depth == 0 and name in (
                    "main.py", "app.py", "server.py", "__init__.py",
                    "__main__.py", "index.js", "index.ts", "main.go",
                    "main.rs", "main.java",
                ):
                    return (1, depth, name)
                # Package-level entry points (one directory deep)
                if depth == 1 and name in (
                    "__init__.py", "main.py", "app.py", "server.py",
                    "__main__.py",
                ):
                    return (2, depth, name)
                # Files whose path contains architectural keywords
                arch_keywords = (
                    "auth", "api/", "/api", "model", "route", "handler",
                    "controller", "/db/", "schema", "config", "settings",
                    "middleware", "permission", "security",
                )
                path_lower = path.lower()
                if any(kw in path_lower for kw in arch_keywords):
                    return (3, depth, path_lower)
                # Everything else, shallower paths first
                return (10, depth, path_lower)

            entries = []
            used = 0
            included = 0
            ordered_paths = sorted(previews.keys(), key=_arch_priority)
            for path in ordered_paths:
                entry = f"\n--- {path} ---\n{previews[path]}\n"
                try:
                    t = count_tokens(entry, provider, model)
                except Exception:
                    t = len(entry) // 3
                if used + t > budget:
                    # Out of budget; fall back to path-only entries for
                    # the rest so the model knows they exist
                    remaining = ordered_paths[included:]
                    short = "\nADDITIONAL FILES (no preview, exists):\n"
                    short += "\n".join(f"- {p}" for p in sorted(remaining))
                    try:
                        short_tokens = count_tokens(short, provider, model)
                    except Exception:
                        short_tokens = len(short) // 3
                    if used + short_tokens <= budget:
                        entries.append(short)
                    break
                entries.append(entry)
                used += t
                included += 1

            print(
                f"  Architecture discovery: 1 LLM call over {included}/"
                f"{len(previews)} files (with previews)",
                flush=True,
            )

            prompt = _ARCHITECTURE_PROMPT + "".join(entries)
            try:
                text, _ = await call_llm(
                    provider=provider, model=model,
                    messages=[{"role": "user", "content": prompt}],
                    parameters={"temperature": 0.2, "max_tokens": 4096},
                    user_service=None, user_id=None,
                )
            except Exception as exc:
                print(f"  Architecture discovery failed: {exc}", flush=True)
                return {}

            parsed = _parse_relevance_json(text)
            if not isinstance(parsed, dict):
                print(f"  Architecture parse failed; got: {text[:200]}",
                      flush=True)
                return {}
            cache_ns.set("architecture", parsed)
            return parsed


        _DOMAINS_PROMPT_TEMPLATE = """You are partitioning a codebase into application domains so issues can be routed to the right area for triage.

Given the architecture summary and the file list below, group the files into between {lo} and {hi} application DOMAINS for this {hint}. A domain is a coherent area of functionality (e.g., "vote_management", "release_lifecycle", "key_signing") — distinct from a low-level concern like "database access" or "logging".

Use the file count and architectural complexity as guidance: prefer fewer, broader domains for small repos and more focused domains for large complex codebases. Combine related sub-features into one domain when they share a coherent purpose; split when subsystems are large and distinct enough to be triaged independently.

ARCHITECTURE SUMMARY:
{architecture_json}

Return ONLY a JSON object (no markdown fences, no surrounding prose):
{{
  "domains": [
    {{
      "name": "snake_case_short_name",
      "description": "one or two sentences about what this domain does",
      "files": ["path1", "path2"],
      "concerns": ["short list", "of issue topics", "that land here"]
    }}
  ]
}}

Rules:
- Each file should appear in EXACTLY ONE domain.
- Configs, migrations, shared utilities go in an "infrastructure" or "shared" domain.
- Use snake_case names. Be specific to this codebase (not generic categories).
- Stay between {lo} and {hi} domains total.

FILE LIST:
"""

        async def _partition_domains(*, repo, head_sha, all_files,
                                      architecture, provider, model):
            """Single LLM call to group files into application domains.
            Cached per SHA. Returns {"domains": [...]}.
            """
            cache_ns = data_store.use_namespace(
                f"discovery:{repo}@{head_sha[:7]}"
            )
            cached = cache_ns.get("domains")
            if cached:
                print(f"  Domains: cache hit", flush=True)
                return cached

            if not all_files:
                return {"domains": []}

            file_list_text = "\n".join(f"- {p}" for p in sorted(all_files.keys()))
            arch_json = (json.dumps(architecture, indent=2)
                          if architecture else "{}")

            # Scale the suggested domain count by codebase size.
            # Small repos get a tight range so they don't over-partition;
            # huge repos get room to express their actual subsystem count.
            n_files = len(all_files)
            if n_files <= 100:
                lo, hi, hint = 3, 6, "small codebase"
            elif n_files <= 500:
                lo, hi, hint = 5, 10, "moderate codebase"
            elif n_files <= 2000:
                lo, hi, hint = 7, 14, "substantial codebase"
            elif n_files <= 5000:
                lo, hi, hint = 10, 20, "large codebase"
            else:
                lo, hi, hint = 12, 30, "very large codebase"

            prompt = (_DOMAINS_PROMPT_TEMPLATE.format(
                lo=lo, hi=hi, hint=hint, architecture_json=arch_json,
            ) + file_list_text)

            print(
                f"  Domain partitioning: 1 LLM call over {n_files} files "
                f"(target {lo}-{hi} domains, {hint})",
                flush=True,
            )

            try:
                text, _ = await call_llm(
                    provider=provider, model=model,
                    messages=[{"role": "user", "content": prompt}],
                    parameters={"temperature": 0.2, "max_tokens": 8192},
                    user_service=None, user_id=None,
                )
            except Exception as exc:
                print(f"  Domain partitioning failed: {exc}", flush=True)
                return {"domains": []}

            parsed = _parse_relevance_json(text)
            if not isinstance(parsed, dict) or "domains" not in parsed:
                return {"domains": []}

            valid = set(all_files.keys())
            cleaned_domains = []
            for d in parsed.get("domains", []) or []:
                if not isinstance(d, dict):
                    continue
                files = [f for f in (d.get("files") or []) if f in valid]
                if not files:
                    continue
                cleaned_domains.append({
                    "name": str(d.get("name", "unnamed")).strip(),
                    "description": str(d.get("description", "")).strip(),
                    "files": files,
                    "concerns": [str(c).strip() for c in (d.get("concerns") or [])],
                })
            result = {"domains": cleaned_domains}
            cache_ns.set("domains", result)
            print(f"  Domains: {len(cleaned_domains)} partitions", flush=True)
            return result


        _INVENTORY_PROMPT = """You are cataloging code files for use by another engineer who will read your output instead of the source. For each file below, produce a structured summary that captures what's there — be CONCRETE and use the file's ACTUAL identifiers (function names, class names, line ranges).

For each file, output exactly this format:

### path/to/file.py
**Purpose:** one sentence — what this file does
**Public API:**
- `function_name(args)` (lines X-Y) — what it does
- `ClassName` (lines X-Y) — what it represents
**Concerns:** brief comma-separated list of issue topics this file might be relevant to

Be concise but specific. Don't paraphrase function names — use them verbatim. If line numbers are uncertain, give your best estimate.

FILES:
"""

        async def _build_inventory(*, repo, head_sha, all_files,
                                    provider, model):
            """Per-file structured catalog. Cached by file-set hash so
            it's compatible with what asvs_audit would produce.
            Returns {path: markdown_summary_block}.
            """
            import hashlib
            file_set_hash = hashlib.sha256(
                "\n".join(sorted(all_files.keys())).encode("utf-8")
            ).hexdigest()[:16]

            cache_ns = data_store.use_namespace(
                f"audit-cache:inventory:{file_set_hash}"
            )
            cached = cache_ns.get("triage_inventory")
            if cached:
                print(
                    f"  Inventory: cache hit (file-set {file_set_hash}, "
                    f"{len(cached)} files)",
                    flush=True,
                )
                return cached

            previews = {}
            for path, content in all_files.items():
                if not content:
                    continue
                lines = content.split('\n')
                previews[path] = '\n'.join(lines[:200])
            if not previews:
                return {}

            try:
                ctx = get_context_window(provider, model)
            except Exception:
                ctx = 200_000
            safe_limit = int(ctx * 0.40)
            try:
                template_tokens = count_tokens(_INVENTORY_PROMPT, provider, model)
            except Exception:
                template_tokens = len(_INVENTORY_PROMPT) // 3
            budget = safe_limit - template_tokens

            batches = []
            current = {}
            current_tokens = 0
            for path in sorted(previews.keys()):
                preview = previews[path]
                entry = f"\n--- {path} ---\n{preview}\n"
                try:
                    t = count_tokens(entry, provider, model)
                except Exception:
                    t = len(entry) // 3
                if t > budget:
                    short = '\n'.join(preview.split('\n')[:50])
                    placeholder = f"\n--- {path} ---\n{short}\n[truncated]\n"
                    if current:
                        batches.append(current)
                        current = {}; current_tokens = 0
                    batches.append({path: placeholder})
                    continue
                if current_tokens + t > budget and current:
                    batches.append(current)
                    current = {}; current_tokens = 0
                current[path] = entry
                current_tokens += t
            if current:
                batches.append(current)

            print(
                f"  Inventory: building over {len(previews)} files in "
                f"{len(batches)} batch(es)",
                flush=True,
            )

            sem = asyncio.Semaphore(5)
            async def _one_batch(idx, batch):
                async with sem:
                    entries_text = "".join(batch.values())
                    prompt = _INVENTORY_PROMPT + entries_text
                    for attempt in range(2):
                        try:
                            text, _ = await call_llm(
                                provider=provider, model=model,
                                messages=[{"role": "user", "content": prompt}],
                                parameters={
                                    "temperature": 0.1,
                                    "max_tokens": 8192,
                                },
                                user_service=None, user_id=None,
                            )
                            return text or ""
                        except Exception as e:
                            if attempt == 0:
                                print(
                                    f"    Inventory batch {idx+1} attempt 1 "
                                    f"failed ({type(e).__name__}); retrying",
                                    flush=True,
                                )
                                await asyncio.sleep(2)
                            else:
                                print(
                                    f"    Inventory batch {idx+1} failed: {e}",
                                    flush=True,
                                )
                                return ""

            results = await asyncio.gather(
                *[_one_batch(i, b) for i, b in enumerate(batches)]
            )

            # Parse: each file's block starts with "### path/to/file.py"
            inventory = {}
            current_path = None
            current_block = []
            for chunk in results:
                for line in chunk.split('\n'):
                    m = re.match(r'^###\s+(.+?)\s*$', line)
                    if m:
                        if current_path and current_path in all_files:
                            inventory[current_path] = '\n'.join(current_block).strip()
                        candidate = m.group(1).strip()
                        current_path = candidate if candidate in all_files else None
                        current_block = []
                    else:
                        if current_path:
                            current_block.append(line)
            if current_path and current_path in all_files:
                inventory[current_path] = '\n'.join(current_block).strip()

            cache_ns.set("triage_inventory", inventory)
            print(f"  Inventory: cataloged {len(inventory)} files",
                  flush=True)
            return inventory


        # ---------- per-issue: domain classification + grounded analysis ----------

        _DOMAIN_CLASSIFY_PROMPT_TEMPLATE = """You are routing a GitHub issue to the right area of a codebase for triage.

Given the issue and the list of application domains, identify which domain(s) the issue touches. An issue may touch 1-3 domains; pick the smallest set that captures it.

ISSUE #{number}: {title}

ISSUE BODY:
{body}

DOMAINS:
{domains_text}

Return ONLY a JSON object (no surrounding prose, no markdown fences):
{{
  "domains": [
    {{"name": "domain_name", "rationale": "one sentence why"}}
  ]
}}

Use the exact domain names from the list above. If genuinely no domain fits (issue is unrelated to this codebase), return {{"domains": []}}.
"""

        async def _classify_issue_domains(
            *, repo, head_sha, issue_number, issue_title, issue_body,
            domains, provider, model,
        ):
            """Returns list of {"name": str, "rationale": str} for the
            domains this issue touches. Cached per issue per SHA.
            """
            cache_ns = data_store.use_namespace(
                f"triage-cache:domain:{repo}@{head_sha[:7]}"
            )
            cache_key = f"issue-{issue_number}"
            cached = cache_ns.get(cache_key)
            if cached:
                return cached

            if not domains.get("domains"):
                return []

            domains_text = "\n".join(
                f"- {d['name']}: {d['description']}"
                + (f" (concerns: {', '.join(d.get('concerns', []))})"
                    if d.get("concerns") else "")
                for d in domains["domains"]
            )

            prompt = _DOMAIN_CLASSIFY_PROMPT_TEMPLATE.format(
                number=issue_number,
                title=issue_title,
                body=(issue_body or "(no body)")[:6000],
                domains_text=domains_text,
            )

            try:
                text, _ = await call_llm(
                    provider=provider, model=model,
                    messages=[{"role": "user", "content": prompt}],
                    parameters={"temperature": 0.2, "max_tokens": 1024},
                    user_service=None, user_id=None,
                )
            except Exception as exc:
                print(
                    f"  Issue #{issue_number}: domain classify failed: {exc}",
                    flush=True,
                )
                return []

            parsed = _parse_relevance_json(text)
            if not isinstance(parsed, dict):
                cache_ns.set(cache_key, [])
                return []

            valid_names = {d["name"] for d in domains["domains"]}
            chosen = []
            for entry in parsed.get("domains", []) or []:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", "")).strip()
                if name in valid_names:
                    chosen.append({
                        "name": name,
                        "rationale": str(entry.get("rationale", "")).strip(),
                    })
            cache_ns.set(cache_key, chosen)
            return chosen


        _RELEVANCE_INVENTORY_TEMPLATE = """You are choosing which files in a codebase are most relevant to a specific GitHub issue.

ISSUE #{number}: {title}

ISSUE BODY:
{body}

Below are file inventories — concise structured summaries of what each file contains. Rate each file 0-10 for how likely a fix or response to this issue would touch it:
- 10: Almost certainly contains the code the issue is about
- 7-9: Highly likely to be involved in any fix
- 4-6: Plausibly relevant; worth inspecting
- 1-3: Unlikely
- 0: Not relevant

Return ONLY a JSON object mapping file paths to integer scores. Example: {{"src/auth.py": 9, "src/utils.py": 3}}

FILE INVENTORIES:
"""

        async def _score_relevance_v2(
            *, repo, head_sha, issue_number, issue_title, issue_body,
            inventory, candidate_paths, all_files,
            provider, model,
        ):
            """Score files using inventory entries (not raw previews).
            `candidate_paths` is a list — usually the union of files
            from the issue's classified domains, or all files if no
            domain classification produced results.

            Cached per issue per SHA. Falls back to whole-corpus scoring
            if the candidate set is empty.
            """
            cache_ns = data_store.use_namespace(
                f"triage-cache:relevance:{repo}@{head_sha[:7]}"
            )
            cache_key = f"issue-{issue_number}"
            cached = cache_ns.get(cache_key)
            if cached:
                print(
                    f"  Issue #{issue_number}: relevance cache hit",
                    flush=True,
                )
                return cached

            # Build entries — use inventory if available, fall back to
            # previews for files we don't have an inventory entry for.
            entries = {}
            for path in candidate_paths:
                if path not in all_files:
                    continue
                inv = inventory.get(path)
                if inv:
                    entries[path] = (
                        f"\n=== {path} ===\n{inv}\n"
                    )
                else:
                    content = all_files.get(path) or ""
                    preview = '\n'.join(content.split('\n')[:80])
                    entries[path] = (
                        f"\n=== {path} ===\n[no inventory; preview]\n{preview}\n"
                    )

            if not entries:
                cache_ns.set(cache_key, {})
                return {}

            try:
                ctx = get_context_window(provider, model)
            except Exception:
                ctx = 200_000
            safe_limit = int(ctx * 0.40)
            template = _RELEVANCE_INVENTORY_TEMPLATE.format(
                number=issue_number,
                title=issue_title,
                body=(issue_body or "(no body)")[:6000],
            )
            try:
                template_tokens = count_tokens(template, provider, model)
            except Exception:
                template_tokens = len(template) // 3
            budget = max(1024, safe_limit - template_tokens)

            batches = []
            current = {}
            current_tokens = 0
            for path in sorted(entries.keys()):
                entry = entries[path]
                try:
                    t = count_tokens(entry, provider, model)
                except Exception:
                    t = len(entry) // 3
                if t > budget:
                    placeholder = f"\n=== {path} ===\n[entry too large]\n"
                    if current:
                        batches.append(current)
                        current = {}; current_tokens = 0
                    batches.append({path: placeholder})
                    continue
                if current_tokens + t > budget and current:
                    batches.append(current)
                    current = {}; current_tokens = 0
                current[path] = entry
                current_tokens += t
            if current:
                batches.append(current)

            print(
                f"  Issue #{issue_number}: relevance scoring "
                f"{len(entries)} files (inventory) in "
                f"{len(batches)} batch(es)",
                flush=True,
            )

            sem = asyncio.Semaphore(5)
            async def _one_batch(idx, batch):
                async with sem:
                    body_text = "".join(batch.values())
                    prompt = template + body_text
                    for attempt in range(2):
                        try:
                            text, _ = await call_llm(
                                provider=provider, model=model,
                                messages=[{"role": "user", "content": prompt}],
                                parameters={
                                    "temperature": 0.3,
                                    "max_tokens": 4096,
                                },
                                user_service=None, user_id=None,
                            )
                            parsed = _parse_relevance_json(text)
                            if parsed is not None:
                                return parsed
                        except Exception as e:
                            if attempt == 0:
                                await asyncio.sleep(2)
                            else:
                                print(
                                    f"    relevance batch {idx+1} failed: {e}",
                                    flush=True,
                                )
                    return {p: 5 for p in batch}

            results = await asyncio.gather(
                *[_one_batch(i, b) for i, b in enumerate(batches)]
            )

            scores = {}
            for partial in results:
                for p, s in partial.items():
                    if p not in all_files:
                        continue
                    try:
                        v = int(round(float(s)))
                    except (ValueError, TypeError):
                        continue
                    scores[p] = max(0, min(10, v))

            cache_ns.set(cache_key, scores)
            return scores


        # ---------- cross-issue context: open PRs + duplicate clusters ----------

        # GitHub's close-keyword convention: "fixes #123", "closes: #123",
        # "resolved #123", etc., automatically link a PR to an issue. Case-
        # insensitive. Optional colon, multiple keywords accepted.
        # (See https://docs.github.com/en/issues/tracking-your-work-with-issues/
        # linking-a-pull-request-to-an-issue-using-a-keyword)
        _CLOSE_KEYWORD_RE = re.compile(
            r"(?i)\b(?:fix(?:es|ed)?|close[sd]?|resolve[sd]?)\s*[:]?\s*#(\d+)"
        )


        def _parse_close_keywords(text):
            """Return [issue_number, ...] for close-keyword references in text."""
            if not text:
                return []
            seen = []
            for m in _CLOSE_KEYWORD_RE.finditer(text):
                try:
                    n = int(m.group(1))
                except (ValueError, TypeError):
                    continue
                if n not in seen:
                    seen.append(n)
            return seen


        async def _fetch_pr_links(gh_get, owner, name):
            """Map open PRs to the issues they say they fix.

            Returns {issue_number: [{number, title, html_url}, ...]} where each
            PR appears under every issue its title or body links to via close
            keywords. ONE search query (paginated) regardless of repo issue
            count — far cheaper than per-issue timeline lookups.

            Note: misses PRs linked only via the GitHub UI's Development
            sidebar without close keywords in the body. That's the rarer case
            in conventional OSS workflows.
            """
            pr_links = {}
            seen_pr_numbers = set()
            page = 1
            while True:
                r = await gh_get(
                    "/search/issues",
                    params={
                        "q": f"repo:{owner}/{name} is:pr is:open",
                        "per_page": "100",
                        "page": str(page),
                    },
                )
                data = r.json()
                items = data.get("items") or []
                if not items:
                    break
                for pr in items:
                    num = pr.get("number")
                    if not num or num in seen_pr_numbers:
                        continue
                    seen_pr_numbers.add(num)
                    text = (pr.get("title") or "") + "\n" + (pr.get("body") or "")
                    for issue_num in _parse_close_keywords(text):
                        pr_links.setdefault(issue_num, []).append({
                            "number": num,
                            "title": pr.get("title") or "",
                            "html_url": pr.get("html_url") or "",
                        })
                if len(items) < 100:
                    break
                page += 1
                if page > 10:  # cap at ~1000 PRs; absurd for any normal repo
                    break
            return pr_links


        async def _detect_related_issues(*, repo, issues, provider, model):
            """Cluster open issues into duplicate/related groups via one LLM call.

            Returns {issue_number: {"others": [int], "kind": "duplicate"|"related",
            "rationale": str}}. Issues NOT part of any cluster are absent from
            the map. Clustering is cached by a stable hash of the issue corpus
            (numbers + titles + body excerpts) — so a re-run with the same
            issues skips the LLM call entirely. The cache invalidates
            automatically when any issue body changes or new issues appear.

            Single LLM call regardless of cluster size. For ~50 issues at ~600
            chars body each that's ~15K input tokens; for ~500 issues, ~150K
            tokens — fits a 200K context model with room to spare.
            """
            if len(issues) < 2:
                return {}

            # Stable corpus hash for caching.
            import hashlib
            corpus_parts = sorted(
                f"{i.get('number')}|{(i.get('title') or '')[:200]}|{(i.get('body') or '')[:600]}"
                for i in issues
            )
            corpus_hash = hashlib.sha256(
                "\n".join(corpus_parts).encode("utf-8")
            ).hexdigest()[:16]

            cache_ns = data_store.use_namespace(f"triage-cache:related:{repo}")
            cached = cache_ns.get(f"corpus-{corpus_hash}")
            if cached is not None:
                print(
                    f"  Related-issue clustering: cache hit "
                    f"(corpus-{corpus_hash})",
                    flush=True,
                )
                # JSON serialization of the data store stringifies dict
                # keys on round-trip. Convert them back to int so the
                # downstream `related_map.get(issue_number_int)` lookup
                # works and the cluster_count sort doesn't compare ints
                # against strings.
                normalized = {}
                if isinstance(cached, dict):
                    for k, v in cached.items():
                        try:
                            normalized[int(k)] = v
                        except (ValueError, TypeError):
                            continue
                return normalized

            issue_descs = []
            for it in issues:
                n = it.get("number")
                t = (it.get("title") or "")[:200]
                b = (it.get("body") or "(no body)")[:600]
                issue_descs.append(f"[#{n}] Title: {t}\nBody: {b}")
            body_text = "\n\n".join(issue_descs)

            prompt = (
                "You are reviewing GitHub issues for an open-source project. "
                "Identify groups of issues that are duplicates or closely "
                "related.\n\n"
                "Two issues belong to the same cluster if they:\n"
                "  - Describe the same bug or symptom, or\n"
                "  - Affect the same specific component or workflow, or\n"
                "  - Would likely be resolved by the same change or set of "
                "changes.\n\n"
                "Issues that just touch the same broad area (e.g., 'auth', "
                "'docs', 'CLI') but describe different problems are NOT "
                "related and should NOT be grouped.\n\n"
                f"ISSUES:\n\n{body_text}\n\n"
                "Return ONLY a JSON object with this exact shape (no surrounding "
                "prose, no markdown fences):\n"
                '{"clusters": [\n'
                '  {"issues": [1, 5, 12], "kind": "duplicate", '
                '"rationale": "one short sentence"},\n'
                '  {"issues": [3, 7], "kind": "related", "rationale": "..."}\n'
                "]}\n\n"
                "Rules:\n"
                "  - Only include clusters of 2 or more issues.\n"
                "  - An issue should appear in at most one cluster.\n"
                '  - Use "duplicate" when the issues describe the same '
                'underlying problem; "related" when they\'re distinct but '
                "tightly coupled.\n"
                '  - If no two issues are related, return {"clusters": []}.'
            )

            print(
                f"  Related-issue clustering: 1 LLM call over {len(issues)} issues",
                flush=True,
            )

            try:
                text, _ = await call_llm(
                    provider=provider, model=model,
                    messages=[{"role": "user", "content": prompt}],
                    parameters={"temperature": 0.2, "max_tokens": 4096},
                    user_service=None, user_id=None,
                )
            except Exception as exc:
                print(f"    clustering call failed: {exc}", flush=True)
                cache_ns.set(f"corpus-{corpus_hash}", {})
                return {}

            parsed = _parse_relevance_json(text)
            if not isinstance(parsed, dict):
                cache_ns.set(f"corpus-{corpus_hash}", {})
                return {}

            clusters_raw = parsed.get("clusters") or []
            valid_issue_nums = {it.get("number") for it in issues}

            clusters_by_issue = {}
            seen_issues = set()  # an issue may appear in at most one cluster

            for cluster in clusters_raw:
                if not isinstance(cluster, dict):
                    continue
                issue_nums = cluster.get("issues") or []
                if not isinstance(issue_nums, list):
                    continue
                clean_nums = []
                for n in issue_nums:
                    try:
                        ni = int(n)
                    except (ValueError, TypeError):
                        continue
                    if ni in valid_issue_nums and ni not in seen_issues:
                        clean_nums.append(ni)
                if len(clean_nums) < 2:
                    continue
                kind = str(cluster.get("kind", "related")).lower()
                if kind not in ("duplicate", "related"):
                    kind = "related"
                rationale = str(cluster.get("rationale", "")).strip()[:300]
                for n in clean_nums:
                    seen_issues.add(n)
                    others = [m for m in clean_nums if m != n]
                    clusters_by_issue[n] = {
                        "others": others,
                        "kind": kind,
                        "rationale": rationale,
                    }

            cache_ns.set(f"corpus-{corpus_hash}", clusters_by_issue)
            return clusters_by_issue


        def _build_related_comment(related_info, *, head_sha, branch, sentinel):
            """Standalone 'see also' comment posted on issues we're not
            actively triaging (already triaged elsewhere, or has open PR), but
            that are part of a duplicate/related cluster. Idempotent via its
            own sentinel — if SENTINEL_RELATED is already on the issue we
            don't post again.
            """
            others = related_info.get("others") or []
            kind = related_info.get("kind", "related")
            rationale = related_info.get("rationale", "")
            refs = ", ".join(f"#{n}" for n in others)
            label = (
                "may be a **duplicate** of (or share root cause with)"
                if kind == "duplicate"
                else "appears **related** to"
            )
            lines = [
                sentinel,
                "",
                f"_Automated cross-reference — analyzed at `{branch}@{head_sha[:8]}`_",
                "",
                f"This issue {label}: {refs}.",
            ]
            if rationale:
                lines.append("")
                lines.append(f"**Rationale:** {rationale}")
            lines.append("")
            lines.append("---")
            lines.append(
                "*Posted by a triage agent. A human reviewer should confirm "
                "whether these issues should be merged or cross-linked manually.*"
            )
            return "\n".join(lines)


        # ---------- staleness assessment ----------

        def _compute_staleness_metrics(issue, comments):
            """Compute age and activity metrics for an issue. Returns a
            dict the deep-analysis prompt can consume to assess
            staleness.

            comments is the raw GitHub /comments response (list of
            dicts with created_at). issue is the GitHub issue dict.

            Returns ints for day-counts; None when timestamp data is
            missing or unparseable. The prompt handles None gracefully.
            """
            from datetime import datetime, timezone

            def parse_ts(s):
                if not s or not isinstance(s, str):
                    return None
                try:
                    return datetime.fromisoformat(s.replace("Z", "+00:00"))
                except Exception:
                    return None

            now = datetime.now(timezone.utc)

            def days_since(d):
                if d is None:
                    return None
                return (now - d).days

            created = parse_ts(issue.get("created_at"))
            updated = parse_ts(issue.get("updated_at"))

            # Find the most recent comment timestamp from non-bot
            # authors, plus the most recent overall.
            human_ts = None
            any_ts = None
            human_count = 0
            for c in (comments or []):
                ts = parse_ts(c.get("created_at"))
                if ts is None:
                    continue
                if any_ts is None or ts > any_ts:
                    any_ts = ts
                user = (c.get("user") or {})
                user_type = (user.get("type") or "").lower()
                login = (user.get("login") or "").lower()
                # Skip bots — GitHub marks them as type "Bot", and
                # also skip our own sentinel comments which are
                # written by the agent's auth identity.
                is_bot = (
                    user_type == "bot"
                    or login.endswith("[bot]")
                    or "<!-- gofannon-issue-triage-bot" in (c.get("body") or "")
                )
                if is_bot:
                    continue
                human_count += 1
                if human_ts is None or ts > human_ts:
                    human_ts = ts

            return {
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "last_comment_at": (
                    any_ts.isoformat() if any_ts else None
                ),
                "last_human_comment_at": (
                    human_ts.isoformat() if human_ts else None
                ),
                "days_since_created": days_since(created),
                "days_since_updated": days_since(updated),
                "days_since_last_comment": days_since(any_ts),
                "days_since_last_human_activity": days_since(human_ts),
                "human_comment_count": human_count,
            }


        # ---------- analysis v2 (grounded in architecture + inventory) ----------

        _ANALYSIS_SYSTEM = """You are a senior engineer triaging a GitHub issue against a codebase you have a structured understanding of.

## Core Principle: Ground every claim in the actual code.
For every finding, you must point to WHERE in the code it lives — exact file path, function or class name, and approximate line range. If you can't cite specific code, the issue may be new functionality (in which case explain WHERE such code would belong) or it may not relate to this codebase at all.

## Triage Type Classification
Pick the most accurate category:

| Type | When to use | Action |
|------|-------------|--------|
| `bug_fix` | Existing code has wrong behavior; you can identify the responsible code | Cite existing code; propose patch |
| `new_feature` | Functionality doesn't exist; you can identify where it would go | Cite extension points; propose patch |
| `refactor` | Code works but the issue is about quality/structure | Cite the code in question; propose patch |
| `documentation` | Code is fine but docs are wrong/missing | Cite docs (or note where docs are needed); propose patch |
| `question` | Issue asks for clarification, not a code change | No patch; explain |
| `discussion` | Open-ended RFC; no clear answer | No patch; summarize positions |
| `unrelated` | Issue is not about this repository | No patch; explain why |
| `unclear` | You don't have enough context to triage | No patch; list what you'd need |

## Citation Discipline
For every existing-code citation:
- Use REAL function/class names from the inventory you were given. If you cannot find the symbol in the inventory or the source, do NOT cite it — say "I don't see this in the inventory" instead.
- Quote the actual snippet (5-30 lines, exact verbatim from the source).
- State the role: `implements_current_behavior`, `needs_modification`, or `extension_point`.

## Patch Discipline
For each diff you propose:
- Anchor it to a real file. If the file doesn't exist in the repo, mark it as a new file.
- Make diffs surgical — show ONLY the changed regions, not the whole file.
- Keep diffs minimal and clearly motivated. They are starting points for human review.

## What NOT to do
- Don't invent function names. If you can't see something in the inventory or source, say so.
- Don't propose patches against files you haven't read the source for.
- Don't claim the issue is `actionable` just because you can write SOME diff. Lower-confidence diffs go in `open_questions` instead, with `classification` of `no_action`.

## Staleness Assessment
For every issue, also assess whether it appears stale and whether closing it should be considered.

An issue is likely **stale** when one or more apply:
- It was opened more than 180 days ago AND has had no human activity in the last 90 days
- The code referenced in the issue body has been substantially rewritten or removed (the symbols/files mentioned no longer exist, or your `existing_code` citations are mostly empty despite the issue describing concrete code)
- The architecture has shifted in a way that obsoletes the issue's premise (e.g., the issue references a framework or subsystem that's been replaced)

An issue is **NOT stale** when:
- There's been any human comment activity in the last 30 days (regardless of issue age)
- The issue is a long-running design conversation with continued engagement
- The code described in the issue body still exists in the current source

Set `recommend_close: true` ONLY when the issue is stale AND closing is the right next step — i.e., the requested change is no longer relevant to the current code, OR no one has engaged for so long that the implicit signal is that it's been abandoned. Provide a clear `rationale` tied to specific observations: cite which files have changed, what activity gap exists, what aspect of the issue's premise no longer holds.

If you're uncertain (e.g., the issue is old but the code still matches the description), set `is_stale: false` and explain in the rationale.

## Output Format
Return STRICT JSON only — no surrounding prose, no markdown fences:

{
  "triage_type": "bug_fix" | "new_feature" | "refactor" | "documentation" | "question" | "discussion" | "unrelated" | "unclear",
  "classification": "actionable" | "no_action" | "unrelated",
  "confidence": "high" | "medium" | "low",
  "summary": "2-5 sentences: what the issue asks, what you found, what's needed",
  "existing_code": [
    {
      "path": "...",
      "symbol": "function_or_class_name",
      "lines": "approx-X-Y",
      "snippet": "...verbatim from source...",
      "role": "implements_current_behavior" | "needs_modification" | "extension_point",
      "explanation": "one sentence on relevance"
    }
  ],
  "new_code_locations": [
    {"path": "...", "anchor": "after symbol X" | "new file", "rationale": "..."}
  ],
  "approach": "one or two paragraphs describing how the change should work",
  "diffs": [
    {"path": "...", "rationale": "one sentence", "diff": "unified diff with proper hunk headers"}
  ],
  "open_questions": ["thing 1", "thing 2"],
  "staleness": {
    "is_stale": true | false,
    "rationale": "one to three sentences explaining the assessment, citing specific signals",
    "recommend_close": true | false
  }
}

If `triage_type` is `question`, `discussion`, `unrelated`, or `unclear`: set `classification` to `no_action` (or `unrelated` for the unrelated case), populate `existing_code` with anything relevant you found, and set `diffs` to [].
"""


        def _format_inventory_block(picked_paths, inventory):
            """Render inventory entries for the picked files as a
            markdown block the analysis prompt can consume."""
            parts = []
            for p in picked_paths:
                inv = inventory.get(p)
                if inv:
                    parts.append(f"### {p}\n{inv}")
                else:
                    parts.append(f"### {p}\n(no inventory entry available)")
            return "\n\n".join(parts) if parts else "(no inventory available)"


        def _format_domains_block(issue_domains, domains_dict):
            """Render the per-issue domain context as a markdown block."""
            if not issue_domains:
                return "(no specific domain identified)"
            by_name = {d["name"]: d for d in domains_dict.get("domains", [])}
            parts = []
            for entry in issue_domains:
                name = entry["name"]
                d = by_name.get(name, {})
                parts.append(
                    f"- **{name}**: {d.get('description', '(no description)')}\n"
                    f"  _Why this issue touches it:_ {entry.get('rationale', '')}"
                )
            return "\n".join(parts)


        def _analysis_prompt(repo, head_sha, number, title, body, html_url,
                              file_blobs, architecture, issue_domains,
                              domains_dict, inventory, staleness_metrics):
            files_section_parts = []
            for fb in file_blobs:
                files_section_parts.append(
                    f"=== file: {fb['path']} ===\n{fb['content']}\n"
                )
            files_section = (
                "\n".join(files_section_parts)
                if files_section_parts
                else "(no files were selected as relevant)"
            )

            arch_text = (
                json.dumps(architecture, indent=2)
                if architecture
                else "(architecture summary unavailable)"
            )

            domains_block = _format_domains_block(issue_domains, domains_dict)
            inventory_block = _format_inventory_block(
                [fb["path"] for fb in file_blobs], inventory
            )

            # Format the age metrics for the staleness assessment
            sm = staleness_metrics or {}
            def _fmt_age(label, ts, days):
                if days is None:
                    return f"- {label}: (unavailable)"
                ts_str = f" ({ts})" if ts else ""
                return f"- {label}: {days} days ago{ts_str}"
            age_block = "\n".join([
                _fmt_age("Issue created", sm.get("created_at"),
                         sm.get("days_since_created")),
                _fmt_age("Last update", sm.get("updated_at"),
                         sm.get("days_since_updated")),
                _fmt_age("Last comment (any)", sm.get("last_comment_at"),
                         sm.get("days_since_last_comment")),
                _fmt_age("Last human activity", sm.get("last_human_comment_at"),
                         sm.get("days_since_last_human_activity")),
                f"- Human comments on issue: {sm.get('human_comment_count', 0)}",
            ])

            return (
                f"REPOSITORY: {repo} @ {head_sha[:8]}\n\n"
                f"# Architecture\n{arch_text}\n\n"
                f"# Application Domains This Issue Touches\n{domains_block}\n\n"
                f"# File Inventory (for the files you're about to read)\n"
                f"{inventory_block}\n\n"
                f"# ISSUE\n"
                f"**#{number}: {title}**\n"
                f"URL: {html_url}\n\n"
                f"## Issue age and activity\n{age_block}\n\n"
                f"## Issue body\n{(body or '(no body)')[:8000]}\n\n"
                f"# Source files (full content)\n\n{files_section}\n\n"
                f"# Your Task\n"
                f"Follow the system instructions to produce a structured "
                f"JSON triage. Cite real code with line ranges. Assess "
                f"staleness using both the age/activity metrics and your "
                f"code analysis. Be honest about what you do not understand."
            )


        def _parse_analysis(text):
            """Parse v2 structured analysis. Tolerates code fences.
            Returns a normalized dict with all expected keys present."""
            s = (text or "").strip()
            if s.startswith("```"):
                s = re.sub(r"^```(?:json)?\s*", "", s)
                if s.endswith("```"):
                    s = s[: -len("```")].strip()
            data = _parse_relevance_json(s) or {}

            triage_type = str(data.get("triage_type", "unclear")).lower()
            valid_types = {"bug_fix", "new_feature", "refactor",
                           "documentation", "question", "discussion",
                           "unrelated", "unclear"}
            if triage_type not in valid_types:
                triage_type = "unclear"

            cls = str(data.get("classification", "no_action")).lower()
            if cls not in {"actionable", "no_action", "unrelated"}:
                cls = "no_action"
            conf = str(data.get("confidence", "medium")).lower()
            if conf not in {"high", "medium", "low"}:
                conf = "medium"

            existing = []
            for e in data.get("existing_code", []) or []:
                if not isinstance(e, dict):
                    continue
                role = str(e.get("role", "")).strip()
                if role not in {"implements_current_behavior",
                                "needs_modification", "extension_point"}:
                    role = "implements_current_behavior"
                existing.append({
                    "path": str(e.get("path", "")).strip(),
                    "symbol": str(e.get("symbol", "")).strip(),
                    "lines": str(e.get("lines", "")).strip(),
                    "snippet": str(e.get("snippet", "")),
                    "role": role,
                    "explanation": str(e.get("explanation", "")).strip(),
                })

            new_locs = []
            for n in data.get("new_code_locations", []) or []:
                if not isinstance(n, dict):
                    continue
                new_locs.append({
                    "path": str(n.get("path", "")).strip(),
                    "anchor": str(n.get("anchor", "")).strip(),
                    "rationale": str(n.get("rationale", "")).strip(),
                })

            diffs = []
            for d in data.get("diffs", []) or []:
                if not isinstance(d, dict):
                    continue
                diffs.append({
                    "path": str(d.get("path", "")).strip(),
                    "rationale": str(d.get("rationale", "")).strip(),
                    "diff": str(d.get("diff", "")),
                })

            open_qs = [str(q).strip() for q in (data.get("open_questions") or [])
                       if str(q).strip()]

            # Staleness object — defaults to "not stale, do not close"
            # when missing or malformed, so a model that omits the
            # field doesn't accidentally trigger close-recommendations.
            staleness_raw = data.get("staleness") or {}
            if not isinstance(staleness_raw, dict):
                staleness_raw = {}
            staleness = {
                "is_stale": bool(staleness_raw.get("is_stale", False)),
                "rationale": str(staleness_raw.get("rationale", "")).strip(),
                "recommend_close": bool(staleness_raw.get("recommend_close", False)),
            }
            # Defensive: don't recommend closing without is_stale=true.
            # Lets the rest of the comment renderer trust this invariant.
            if staleness["recommend_close"] and not staleness["is_stale"]:
                staleness["is_stale"] = True

            return {
                "triage_type": triage_type,
                "classification": cls,
                "confidence": conf,
                "summary": str(data.get("summary", "")).strip()
                            or "(no summary produced)",
                "existing_code": existing,
                "new_code_locations": new_locs,
                "approach": str(data.get("approach", "")).strip(),
                "diffs": diffs,
                "open_questions": open_qs,
                "staleness": staleness,
            }


        def _ground_citations(parsed, all_files):
            """Replace LLM-claimed line ranges with ranges computed by
            matching the actual snippet text against the source file.

            Drops citations whose snippets don't appear in the cited
            file (real text hallucinations, distinct from line-number
            errors). Keeps citations where we can match the snippet
            even if the line range was wrong — fixes the line range,
            preserves the substance.

            The model's snippet text is verbatim accurate in practice
            (verified against ATR source); only its line annotations
            are unreliable. So this post-processor turns the
            unreliable metadata into a derived-from-source value.
            """
            grounded = []
            dropped = 0
            for cite in parsed.get("existing_code", []) or []:
                if not isinstance(cite, dict):
                    continue
                path = (cite.get("path") or "").strip()
                snippet = cite.get("snippet") or ""
                if not path or not snippet.strip():
                    continue
                if path not in all_files:
                    # Path doesn't exist in the repo — hallucinated path
                    dropped += 1
                    continue
                source = all_files[path]
                snippet_lines = snippet.split("\n")

                # Pick an anchor line we can search for. Prefer
                # def/class/decorator lines (typically unique within
                # a file). Fall back to the longest non-trivial line.
                anchor = None
                for line in snippet_lines:
                    stripped = line.strip()
                    if stripped.startswith(
                        ("def ", "async def ", "class ", "@")
                    ):
                        anchor = line
                        break
                if not anchor:
                    non_empty = [l for l in snippet_lines if l.strip()]
                    if non_empty:
                        anchor = max(non_empty, key=len)

                if not anchor or not anchor.strip():
                    cite["lines"] = "(line range not verified)"
                    grounded.append(cite)
                    continue

                # Search for the anchor in the source. Try exact match
                # first; if that fails, try matching without leading
                # whitespace (handles snippets that were unindented or
                # re-indented).
                idx = source.find(anchor)
                if idx == -1:
                    stripped_anchor = anchor.strip()
                    if len(stripped_anchor) > 10:
                        idx2 = source.find(stripped_anchor)
                        if idx2 != -1:
                            idx = source.rfind("\n", 0, idx2) + 1

                if idx == -1:
                    # Genuine hallucination: snippet content not in file.
                    # Don't render this citation.
                    dropped += 1
                    continue

                start_line = source[:idx].count("\n") + 1
                end_line = start_line + len(snippet_lines) - 1
                cite["lines"] = f"{start_line}-{end_line}"
                grounded.append(cite)

            if dropped:
                print(
                    f"  Citation grounding: dropped {dropped} unverifiable "
                    f"citation(s) (snippet not found in source)",
                    flush=True,
                )

            parsed["existing_code"] = grounded
            return parsed


        def _build_comment(parsed, *, head_sha, branch, files_examined,
                           sentinel, related_info=None, issue_domains=None,
                           staleness_metrics=None):
            """v2 comment format: structured sections for existing-code
            citations, new-code locations, approach, patches, open questions.
            Includes a staleness assessment section when the model
            recommends closing or flags the issue as stale.
            """
            triage_type = parsed.get("triage_type", "unclear")
            cls = parsed["classification"]
            conf = parsed["confidence"]
            summary = parsed["summary"]
            staleness = parsed.get("staleness") or {}

            domain_names = (
                ", ".join(f"`{e['name']}`" for e in (issue_domains or []))
                if issue_domains else "_(none identified)_"
            )

            # Build header — flag stale issues prominently in the type
            # line so a maintainer scanning a long thread sees it.
            type_line = (
                f"**Type:** `{triage_type}`  •  "
                f"**Classification:** `{cls}`  •  "
                f"**Confidence:** `{conf}`"
            )
            if staleness.get("recommend_close"):
                type_line += "  •  ⚠️ **Stale — consider closing**"
            elif staleness.get("is_stale"):
                type_line += "  •  ⚠️ **Possibly stale**"

            lines = [
                sentinel,
                "",
                f"**Automated triage** — analyzed at `{branch}@{head_sha[:8]}`",
                "",
                type_line,
                f"**Application domain(s):** {domain_names}",
                "",
                "### Summary",
                summary,
                "",
            ]

            existing = parsed.get("existing_code") or []
            if existing:
                lines.append("### Where this lives in the code today")
                lines.append("")
                for e in existing:
                    lines.append(
                        f"#### `{e['path']}` — `{e['symbol']}` "
                        f"(lines {e['lines']})"
                    )
                    role_label = {
                        "implements_current_behavior": "_currently does this_",
                        "needs_modification": "_needs modification_",
                        "extension_point": "_extension point_",
                    }.get(e["role"], "")
                    if role_label:
                        lines.append(role_label)
                    if e.get("explanation"):
                        lines.append(e["explanation"])
                    if e.get("snippet"):
                        lines.append("")
                        lines.append("```python")
                        lines.append(e["snippet"])
                        lines.append("```")
                    lines.append("")

            new_locs = parsed.get("new_code_locations") or []
            if new_locs:
                lines.append("### Where new code would go")
                for n in new_locs:
                    lines.append(
                        f"- `{n['path']}` — {n['anchor']}"
                    )
                    if n.get("rationale"):
                        lines.append(f"  {n['rationale']}")
                lines.append("")

            approach = (parsed.get("approach") or "").strip()
            if approach:
                lines.append("### Proposed approach")
                lines.append(approach)
                lines.append("")

            diffs = parsed.get("diffs") or []
            if cls == "actionable" and diffs:
                lines.append("### Suggested patches")
                lines.append("")
                for d in diffs:
                    lines.append(f"#### `{d['path']}`")
                    if d.get("rationale"):
                        lines.append(d["rationale"])
                    lines.append("")
                    diff_text = d["diff"].strip()
                    if diff_text:
                        lines.append("````diff")
                        lines.append(diff_text)
                        lines.append("````")
                    lines.append("")

            open_qs = parsed.get("open_questions") or []
            if open_qs:
                lines.append("### Open questions")
                for q in open_qs:
                    lines.append(f"- {q}")
                lines.append("")

            # Staleness section — only renders when there's something
            # for the maintainer to act on (recommend_close or is_stale).
            # When the issue is fresh and engaged, we skip this entirely.
            if staleness.get("is_stale") or staleness.get("recommend_close"):
                lines.append("### Staleness assessment")
                lines.append("")
                sm = staleness_metrics or {}
                age_bits = []
                if sm.get("days_since_created") is not None:
                    age_bits.append(
                        f"opened {sm['days_since_created']} days ago"
                    )
                if sm.get("days_since_last_human_activity") is not None:
                    age_bits.append(
                        f"last human comment "
                        f"{sm['days_since_last_human_activity']} days ago"
                    )
                elif sm.get("human_comment_count", 0) == 0:
                    age_bits.append("no human comments since opening")
                if age_bits:
                    lines.append(f"_{'; '.join(age_bits)}._")
                    lines.append("")
                if staleness.get("rationale"):
                    lines.append(staleness["rationale"])
                    lines.append("")
                if staleness.get("recommend_close"):
                    lines.append(
                        "**Recommendation: consider closing this issue.** "
                        "If the maintainer agrees, the agent's "
                        "assessment above provides the rationale to "
                        "include in a closing comment."
                    )
                    lines.append("")

            if cls == "no_action" and not diffs:
                lines.append(
                    "_The agent reviewed this issue and is not proposing "
                    "patches in this run. Review the existing-code "
                    "citations and open questions above before deciding "
                    "next steps._"
                )
                lines.append("")
            elif cls == "unrelated":
                lines.append(
                    "_The agent reviewed this issue and concluded it is "
                    "not related to the code, configuration, or "
                    "documentation in this repository._"
                )
                lines.append("")

            if files_examined:
                lines.append("### Files examined")
                for p in files_examined:
                    lines.append(f"- `{p}`")
                lines.append("")

            if related_info and related_info.get("others"):
                others = related_info["others"]
                kind = related_info.get("kind", "related")
                rationale = related_info.get("rationale", "")
                refs = ", ".join(f"#{n}" for n in others)
                label = (
                    "may be a duplicate of (or share root cause with)"
                    if kind == "duplicate"
                    else "appears related to"
                )
                lines.append("### Related issues")
                lines.append(f"This issue {label}: {refs}.")
                if rationale:
                    lines.append("")
                    lines.append(f"_{rationale}_")
                lines.append("")

            lines.append("---")
            lines.append(
                "*Draft from a triage agent. A human reviewer should "
                "validate before merging any change. The agent did not "
                "run tests or verify diffs apply.*"
            )
            return "\n".join(lines)


        def _result_row(number, title, classification, summary, files_examined,
                        comment_body, comment_url, posted, *,
                        linked_prs=None, related_issues=None,
                        recommend_close=False, is_stale=False):
            return {
                "number": number or 0,
                "title": title or "",
                "classification": classification,
                "summary": summary,
                "files_examined": files_examined,
                "comment_body": comment_body,
                "comment_url": comment_url,
                "posted": bool(posted),
                "linked_prs": list(linked_prs) if linked_prs else [],
                "related_issues": list(related_issues) if related_issues else [],
                "is_stale": bool(is_stale),
                "recommend_close": bool(recommend_close),
            }


        def _empty_result(repo, error_msg):
            return {
                "outputText": f"Triage failed: {error_msg}",
                "repo": repo,
                "branch": "",
                "head_sha": "",
                "issues_processed": 0,
                "issues_commented": 0,
                "issues_skipped": 0,
                "errors": [{"issue_number": 0, "error": error_msg}],
                "results": [],
            }

        import io
        import tarfile

        # ---------- 1. inputs ----------
        # Hardcoded tier configuration. These match what the gofannon
        # UI's Invokable Models registration should reference.
        # Per-model parameters (temperature, max_tokens, reasoning_effort)
        # are configured per invokable model in the gofannon UI.
        provider = "bedrock"
        model = "us.anthropic.claude-opus-4-6-v1"               # deep analysis
        relevance_provider = "bedrock"
        relevance_model = "us.anthropic.claude-haiku-4-5-20251001-v1:0"  # cheap-batch passes
        discovery_provider = "bedrock"
        discovery_model = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"  # structural discovery

        # Hardcoded operational limits. These are not exposed as inputs
        # because their reasonable values rarely vary and exposing them
        # adds UI clutter. If a use case demands tuning, promote back
        # to inputs.
        max_issues = 0          # 0 = no cap (process all open issues)
        issue_filter = set()    # empty = no filtering by issue number
        max_files_per_issue = 8 # files passed to deep analysis per issue

        # User-facing inputs (operational behavior knobs)
        repo = (input_dict.get("repo") or "").strip()
        token = (input_dict.get("github_token") or "").strip()
        dry_run = bool(input_dict.get("dry_run", False))
        skip_already_triaged = bool(input_dict.get("skip_already_triaged", True))
        branch_input = (input_dict.get("branch") or "").strip()
        force_redownload = bool(input_dict.get("force_redownload", False))
        # Assignee filter: when set, only triage issues assigned to this
        # GitHub username. Maps to /issues?assignee=USERNAME. Special
        # values "*" (any assignee) and "none" (unassigned only) are
        # passed through to GitHub's API as-is. Empty string = no
        # filter, triage everything (existing behavior).
        assignee = (input_dict.get("assignee") or "").strip()
        # Label applied to every issue the agent examines. Idempotent on
        # GitHub's side (re-adding an existing label is a no-op). Pass
        # an empty string to disable labeling entirely. Default
        # "gh-helper" matches the existing convention; the agent will
        # auto-create the label in the repo if it doesn't exist.
        if "label" in input_dict:
            label = (input_dict.get("label") or "").strip()
        else:
            label = "gh-helper"
        # skip_when_pr_open: skip triage for any issue that has an open PR
        # using close-keywords (fixes/closes/resolves #N). Catches the
        # "someone is already working on this" case to avoid duplicate
        # effort. Disable to triage anyway (e.g., to second-guess a
        # stalled PR).
        skip_when_pr_open = bool(input_dict.get("skip_when_pr_open", True))
        # detect_related_issues: run a single LLM clustering pass over
        # all open issues to find duplicates and related groups.
        # Cross-references are added to triage comments and posted as
        # standalone "see also" comments on skipped issues. Disable to
        # save the one extra LLM call.
        detect_related_issues = bool(input_dict.get("detect_related_issues", True))

        if "/" not in repo:
            return _empty_result(repo, "input 'repo' must look like 'owner/name'")
        if not token:
            return _empty_result(repo, "input 'github_token' is required")

        owner, name = repo.split("/", 1)

        # Sentinels live at module scope (SENTINEL_TRIAGE / SENTINEL_RELATED)
        # so helpers below can reference them too.

        gh_headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "gofannon-issue-triage/1",
        }

        async def gh_get(path, *, accept=None, params=None, follow_redirects=False):
            h = dict(gh_headers)
            if accept:
                h["Accept"] = accept
            url = path if path.startswith("http") else f"https://api.github.com{path}"
            r = await http_client.get(
                url, headers=h, params=params, follow_redirects=follow_redirects
            )
            if r.status_code >= 400:
                raise RuntimeError(f"GET {url} -> {r.status_code}: {r.text[:500]}")
            return r

        async def gh_post(path, *, json_body=None):
            url = path if path.startswith("http") else f"https://api.github.com{path}"
            r = await http_client.post(url, headers=gh_headers, json=json_body)
            if r.status_code >= 400:
                raise RuntimeError(f"POST {url} -> {r.status_code}: {r.text[:500]}")
            return r

        async def ensure_repo_label(label_name):
            """Idempotent: create the label on the repo if missing.
            Swallows errors — 422 means it already exists, anything else
            we log and let per-issue add calls surface their own errors.
            Bypasses gh_post because gh_post raises on 4xx.
            """
            if not label_name:
                return
            try:
                url = f"https://api.github.com/repos/{owner}/{name}/labels"
                r = await http_client.post(
                    url, headers=gh_headers,
                    json={
                        "name": label_name,
                        "color": "ededed",
                        "description": (
                            "Triaged by the gofannon issue triage agent"
                        ),
                    },
                )
                if r.status_code not in (201, 422):
                    print(
                        f"WARN: ensure_repo_label({label_name!r}) "
                        f"-> {r.status_code}: {r.text[:200]}",
                        flush=True,
                    )
            except Exception as exc:
                print(f"WARN: ensure_repo_label failed: {exc}", flush=True)

        async def add_issue_label(issue_number, label_name):
            """Add a label to an issue. Idempotent on GitHub's side
            (re-adding an existing label is a no-op). Wrapped in try/
            except so a label failure doesn't break the run.
            """
            if not label_name:
                return
            try:
                await gh_post(
                    f"/repos/{owner}/{name}/issues/{issue_number}/labels",
                    json_body={"labels": [label_name]},
                )
            except Exception as exc:
                print(
                    f"WARN: failed to label #{issue_number} "
                    f"with {label_name!r}: {exc}",
                    flush=True,
                )

        # ---------- 2. resolve branch + HEAD sha ----------
        if branch_input:
            branch = branch_input
        else:
            branch = (await gh_get(f"/repos/{owner}/{name}")).json()["default_branch"]
        head_sha = (await gh_get(f"/repos/{owner}/{name}/branches/{branch}")).json()[
            "commit"
        ]["sha"]

        # ---------- 3. tarball download with SHA freshness check ----------
        # The data store carries one canonical snapshot per repo, tagged
        # with its source SHA in a sibling meta namespace. If the tag
        # matches current HEAD, we skip the download entirely.
        files_ns = data_store.use_namespace(f"files:{repo}")
        meta_ns = data_store.use_namespace(f"meta:{repo}")
        stored_sha = meta_ns.get("head_sha")
        existing_keys = files_ns.list_keys()

        needs_download = (
            force_redownload
            or stored_sha != head_sha
            or not existing_keys
        )

        if needs_download:
            print(
                f"Downloading tarball for {repo} at {head_sha[:8]} "
                f"(stored_sha={stored_sha and stored_sha[:8]!r})",
                flush=True,
            )
            tarball_url = f"/repos/{owner}/{name}/tarball/{head_sha}"
            tar_resp = await gh_get(tarball_url, follow_redirects=True)
            tar_bytes = tar_resp.content
            print(f"Tarball: {len(tar_bytes):,} bytes", flush=True)

            # Clear the previous snapshot before writing the new one.
            for k in existing_keys:
                files_ns.delete(k)

            stored = 0
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
                members = tar.getmembers()
                # GitHub tarballs prefix every entry with a single
                # top-level dir like "owner-repo-<sha>/...". Strip it.
                top_prefix = None
                for m in members:
                    if m.name and "/" in m.name:
                        top_prefix = m.name.split("/", 1)[0] + "/"
                        break

                for member in members:
                    if not member.isfile():
                        continue
                    rel_path = member.name
                    if top_prefix and rel_path.startswith(top_prefix):
                        rel_path = rel_path[len(top_prefix):]
                    if not rel_path:
                        continue
                    if _should_skip_file(rel_path):
                        continue
                    if member.size > 1_000_000:  # 1MB cap matches asvs_download_repo
                        continue
                    try:
                        f = tar.extractfile(member)
                        if f is None:
                            continue
                        raw = f.read()
                        try:
                            content = raw.decode("utf-8")
                        except UnicodeDecodeError:
                            continue
                        files_ns.set(rel_path, content)
                        stored += 1
                    except Exception:
                        continue

            meta_ns.set("head_sha", head_sha)
            meta_ns.set("file_count", stored)
            print(f"Stored {stored} files in files:{repo}", flush=True)
        else:
            print(
                f"Cache hit: files:{repo} already at {head_sha[:8]} "
                f"({len(existing_keys)} files); skipping download",
                flush=True,
            )

        # ---------- 4. load all files into memory for the run ----------
        # Single batch read — the data store proxy supports get_many for
        # this. The whole snapshot fits in memory for repos under ~1M LOC;
        # ATR is well below that.
        all_keys = files_ns.list_keys()
        all_files_raw = files_ns.get_many(all_keys) if all_keys else {}
        all_files = {}
        for k, v in all_files_raw.items():
            if v is None:
                continue
            all_files[k] = v if isinstance(v, str) else json.dumps(v, default=str)
        valid_paths = set(all_files.keys())
        print(f"Loaded {len(all_files)} files for analysis", flush=True)

        if not all_files:
            return _empty_result(
                repo, f"no files found in namespace files:{repo} after extraction"
            )

        # ---------- 4.5. structural discovery (one per SHA, cached) ----------
        # These three passes build the agent's mental model of the repo
        # and feed every per-issue analysis. All cached at SHA level so
        # subsequent runs at the same HEAD are free.
        print("Building repo understanding (architecture, domains, inventory)...",
              flush=True)
        architecture = await _discover_architecture(
            repo=repo, head_sha=head_sha, all_files=all_files,
            provider=discovery_provider, model=discovery_model,
        )
        domains_dict = await _partition_domains(
            repo=repo, head_sha=head_sha, all_files=all_files,
            architecture=architecture,
            provider=discovery_provider, model=discovery_model,
        )
        inventory = await _build_inventory(
            repo=repo, head_sha=head_sha, all_files=all_files,
            provider=discovery_provider, model=discovery_model,
        )

        # ---------- 5. fetch open issues (paginate, drop PRs) ----------
        issues = []
        page = 1
        while True:
            issue_params = {"state": "open", "per_page": "100", "page": str(page)}
            if assignee:
                issue_params["assignee"] = assignee
            r = await gh_get(
                f"/repos/{owner}/{name}/issues",
                params=issue_params,
            )
            batch = r.json()
            if not batch:
                break
            for it in batch:
                if "pull_request" in it:  # /issues returns PRs too
                    continue
                if issue_filter and it.get("number") not in issue_filter:
                    continue
                issues.append(it)
            if len(batch) < 100:
                break
            page += 1
            if page > 50:  # hard safety cap
                break

        if max_issues:
            issues = issues[:max_issues]

        # ---------- 6. cross-issue context: open PRs + duplicate/related clusters ----------
        # Both run once for the whole batch and feed every issue's
        # decision-making in step 7. Cheap relative to the per-issue
        # work that follows.
        pr_links = {}  # {issue_number: [{number, title, html_url}]}
        if skip_when_pr_open:
            try:
                pr_links = await _fetch_pr_links(gh_get, owner, name)
                if pr_links:
                    print(
                        f"Found {sum(len(v) for v in pr_links.values())} "
                        f"PR→issue link(s) across {len(pr_links)} issues",
                        flush=True,
                    )
            except Exception as exc:
                print(f"WARN: PR-link scan failed: {exc}", flush=True)

        related_map = {}  # {issue_number: {others, kind, rationale}}
        if detect_related_issues and len(issues) >= 2:
            try:
                related_map = await _detect_related_issues(
                    repo=repo,
                    issues=issues,
                    provider=relevance_provider,
                    model=relevance_model,
                )
                if related_map:
                    cluster_count = len({tuple(sorted([n] + v["others"]))
                                          for n, v in related_map.items()})
                    print(
                        f"Found {cluster_count} issue cluster(s) covering "
                        f"{len(related_map)} issues",
                        flush=True,
                    )
            except Exception as exc:
                print(f"WARN: related-issue clustering failed: {exc}", flush=True)

        # ---------- 7. per-issue triage ----------

        # Ensure the repo has the label before we try applying it.
        # Idempotent and dry_run-aware. Skipping this is safe — per-issue
        # add calls will report their own errors if it failed.
        if label and not dry_run:
            await ensure_repo_label(label)

        results = []
        errors = []
        posted = 0
        skipped = 0

        for issue in issues:
            number = issue.get("number")
            title = issue.get("title", "")
            body = issue.get("body") or ""
            html_url = issue.get("html_url", "")
            comments_url = issue.get("comments_url") or ""

            try:
                # 7a. fetch existing comments once for both sentinel checks
                existing_comments = []
                if comments_url:
                    cr = await gh_get(comments_url)
                    existing_comments = cr.json()
                already_triaged = any(
                    SENTINEL_TRIAGE in (c.get("body") or "")
                    for c in existing_comments
                )
                already_has_related = any(
                    SENTINEL_RELATED in (c.get("body") or "")
                    for c in existing_comments
                )

                # 7b. cross-issue context for THIS issue
                related_info = related_map.get(number)
                related_others = related_info["others"] if related_info else []
                linked_pr_list = pr_links.get(number, [])
                linked_pr_numbers = [p["number"] for p in linked_pr_list]

                # 7c. decide path: full triage, skip+related, skip-only
                skip_reason = None
                if skip_already_triaged and already_triaged:
                    skip_reason = "skipped"
                    skip_summary = "Already triaged by this agent."
                elif skip_when_pr_open and linked_pr_list:
                    skip_reason = "pr_in_progress"
                    pr_str = ", ".join(f"#{p['number']}" for p in linked_pr_list)
                    skip_summary = (
                        f"Open PR(s) appear to address this issue: {pr_str}. "
                        f"Skipping triage to avoid duplicating effort."
                    )

                if skip_reason is not None:
                    # SKIP path. We don't run relevance/analysis. We may
                    # still post a standalone "see also" comment if this
                    # issue is part of a duplicate cluster and we haven't
                    # already posted one.
                    skipped += 1
                    comment_body = ""
                    comment_url = ""
                    did_post = False
                    if related_others and not already_has_related:
                        comment_body = _build_related_comment(
                            related_info,
                            head_sha=head_sha, branch=branch,
                            sentinel=SENTINEL_RELATED,
                        )
                        if not dry_run:
                            pr_resp = await gh_post(
                                f"/repos/{owner}/{name}/issues/{number}/comments",
                                json_body={"body": comment_body},
                            )
                            comment_url = pr_resp.json().get("html_url", "")
                            did_post = True
                    results.append(
                        _result_row(
                            number, title, skip_reason, skip_summary,
                            [], comment_body, comment_url, did_post,
                            linked_prs=linked_pr_numbers,
                            related_issues=related_others,
                        )
                    )
                    if label and not dry_run:
                        await add_issue_label(number, label)
                    continue

                # 7d. domain classification (which application area(s) does
                # this issue touch?) — narrows the relevance search
                issue_domains = await _classify_issue_domains(
                    repo=repo, head_sha=head_sha, issue_number=number,
                    issue_title=title, issue_body=body,
                    domains=domains_dict,
                    provider=relevance_provider, model=relevance_model,
                )

                # Build candidate file set: union of files in chosen domains.
                # If no domain matched, fall back to all files (v1 behavior).
                if issue_domains:
                    candidate_paths = set()
                    by_name = {d["name"]: d for d in domains_dict.get("domains", [])}
                    for entry in issue_domains:
                        d = by_name.get(entry["name"])
                        if d:
                            candidate_paths.update(d.get("files", []))
                    candidate_paths = list(candidate_paths)
                    if not candidate_paths:
                        candidate_paths = list(all_files.keys())
                else:
                    candidate_paths = list(all_files.keys())

                # 7e. relevance scoring v2 — uses inventory, scoped to domains
                relevance_scores = await _score_relevance_v2(
                    repo=repo, head_sha=head_sha, issue_number=number,
                    issue_title=title, issue_body=body,
                    inventory=inventory,
                    candidate_paths=candidate_paths,
                    all_files=all_files,
                    provider=relevance_provider, model=relevance_model,
                )

                # 7f. pick top-K with score ≥ 4, fall back to ≥ 2 if too few
                ranked = [
                    (p, s) for p, s in relevance_scores.items()
                    if isinstance(s, (int, float)) and s >= 4
                ]
                if len(ranked) < 3:
                    ranked = [
                        (p, s) for p, s in relevance_scores.items()
                        if isinstance(s, (int, float)) and s >= 2
                    ]
                ranked.sort(key=lambda x: x[1], reverse=True)
                ranked = ranked[:max_files_per_issue]
                picked = [p for p, _ in ranked]

                # 7g. build file_blobs from in-memory cache (no more API calls)
                file_blobs = []
                for p in picked:
                    content = all_files.get(p, "")
                    if not content:
                        continue
                    if len(content) > 30_000:
                        content = content[:30_000] + "\n\n[... file truncated ...]"
                    file_blobs.append({"path": p, "content": content})

                # 7h. deep analysis (with architecture + domains + inventory + age)
                staleness_metrics = _compute_staleness_metrics(
                    issue, existing_comments
                )
                analysis_user = _analysis_prompt(
                    repo, head_sha, number, title, body, html_url, file_blobs,
                    architecture, issue_domains, domains_dict, inventory,
                    staleness_metrics,
                )
                # Note: temperature, max_tokens, and reasoning_effort
                # for this call are configured per-model in the
                # gofannon UI (Invokable Models section). The values
                # below are defaults the agent expresses; UI config
                # takes precedence. Recommended UI settings for the
                # Opus invokable: temperature=1, reasoning_effort=high,
                # max_tokens=32768.
                analysis_text, _ = await call_llm(
                    provider=provider,
                    model=model,
                    messages=[
                        {"role": "system", "content": _ANALYSIS_SYSTEM},
                        {"role": "user", "content": analysis_user},
                    ],
                    parameters={"temperature": 0.1, "max_tokens": 16384},
                    user_service=None,
                    user_id=None,
                )
                parsed = _parse_analysis(analysis_text)
                # Ground the citations: replace LLM-claimed line ranges
                # with ranges computed by matching snippets against the
                # actual source. Drops citations with snippets that
                # don't appear in the cited file.
                parsed = _ground_citations(parsed, all_files)

                # 7i. comment body — v2 grounded format
                comment_body = _build_comment(
                    parsed,
                    head_sha=head_sha, branch=branch,
                    files_examined=[b["path"] for b in file_blobs],
                    sentinel=SENTINEL_TRIAGE,
                    related_info=related_info,
                    issue_domains=issue_domains,
                    staleness_metrics=staleness_metrics,
                )

                # 7i. post (or skip in dry run)
                comment_url = ""
                did_post = False
                if not dry_run:
                    pr_resp = await gh_post(
                        f"/repos/{owner}/{name}/issues/{number}/comments",
                        json_body={"body": comment_body},
                    )
                    comment_url = pr_resp.json().get("html_url", "")
                    did_post = True
                    posted += 1
                    if label:
                        await add_issue_label(number, label)

                results.append(
                    _result_row(
                        number, title,
                        parsed.get("classification", "no_action"),
                        parsed.get("summary", ""),
                        [b["path"] for b in file_blobs],
                        comment_body, comment_url, did_post,
                        linked_prs=linked_pr_numbers,
                        related_issues=related_others,
                        is_stale=parsed.get("staleness", {}).get(
                            "is_stale", False
                        ),
                        recommend_close=parsed.get("staleness", {}).get(
                            "recommend_close", False
                        ),
                    )
                )

            except Exception as exc:
                errors.append({"issue_number": number, "error": str(exc)})
                results.append(
                    _result_row(
                        number, title, "error",
                        f"Triage failed: {exc}",
                        [], "", "", False,
                        linked_prs=pr_links.get(number, [])
                            and [p["number"] for p in pr_links.get(number, [])]
                            or [],
                        related_issues=(
                            related_map.get(number, {}).get("others", [])
                            if related_map else []
                        ),
                    )
                )

        # Human-readable summary for gofannon's outputText slot. The
        # structured fields are still returned alongside for programmatic
        # consumption (e.g. by downstream agents reading via
        # gofannon_client.call).
        output_text = (
            f"Triage of {repo} @ {branch}@{head_sha[:8]}\n"
            f"Issues processed: {len(issues)}\n"
            f"Comments posted:  {posted}\n"
            f"Skipped:          {skipped}\n"
            f"Errors:           {len(errors)}\n"
        )
        if errors:
            output_text += "\nFirst error: "
            output_text += errors[0].get("error", "(no detail)")[:300]

        return {
            "outputText": output_text,
            "repo": repo, "branch": branch, "head_sha": head_sha,
            "issues_processed": len(issues),
            "issues_commented": posted,
            "issues_skipped": skipped,
            "errors": errors,
            "results": results,
        }

    finally:
        await http_client.aclose()