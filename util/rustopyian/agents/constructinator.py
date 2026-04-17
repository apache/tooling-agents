from services.llm_service import call_llm
import httpx

# --- Rustopyian Constructinator -----------------------------------------------
#
# Gofannon agent that takes a Rust crate and produces a PyO3/maturin
# Python wrapper project.
#
# Inputs (via input_dict):
#   crate_name      - crate name on crates.io (e.g. "swhid")
#   crate_repo      - GitHub repo URL (e.g. "https://github.com/swhid/swhid-rs")
#   package_name    - Python package name (default: "{crate_name}-py")
#   github_pat      - GitHub PAT for reading source (optional, raises rate limits)
#   output_repo     - GitHub repo to push to, as "owner/repo" (optional)
#   output_token    - GitHub PAT with repo write access for pushing (optional)
#   output_branch   - branch to push to (default "main")
#   license         - wrapper license (default "Apache-2.0")
#   license_header  - per-file license header text (default: ASF header)
#   copyleft_ok     - set "true" to allow copyleft deps (default "false")
#   publish         - set "true" to push to output_repo (default "false")


async def run(input_dict, tools):
    http_client = httpx.AsyncClient(timeout=30.0)
    try:
        import json
        import re
        import asyncio
        import base64

        COPYLEFT_LICENSES = {
            "GPL-2.0", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER",
            "GPL-3.0", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
            "AGPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER",
            "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
            "SSPL-1.0", "EUPL-1.1", "EUPL-1.2",
            "MPL-2.0",
        }
        GPL_FAMILY = {l for l in COPYLEFT_LICENSES if l.startswith(("GPL", "AGPL", "LGPL"))}
        crate_name = input_dict.get("crate_name", "").strip()
        crate_repo = input_dict.get("crate_repo", "").strip().rstrip("/")
        package_name = input_dict.get("package_name", "").strip()
        github_pat = input_dict.get("github_pat", "").strip()
        output_repo = input_dict.get("output_repo", "").strip()
        output_token = input_dict.get("output_token", "").strip()
        output_branch = input_dict.get("output_branch", "main").strip() or "main"
        wrapper_license = input_dict.get("license", "Apache-2.0").strip()
        license_header = input_dict.get("license_header", (
            "Licensed to the Apache Software Foundation (ASF) under one\n"
            "or more contributor license agreements.  See the NOTICE file\n"
            "distributed with this work for additional information\n"
            "regarding copyright ownership.  The ASF licenses this file\n"
            "to you under the Apache License, Version 2.0 (the\n"
            "\"License\"); you may not use this file except in compliance\n"
            "with the License.  You may obtain a copy of the License at\n"
            "\n"
            "  http://www.apache.org/licenses/LICENSE-2.0\n"
            "\n"
            "Unless required by applicable law or agreed to in writing,\n"
            "software distributed under the License is distributed on an\n"
            "\"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n"
            "KIND, either express or implied.  See the License for the\n"
            "specific language governing permissions and limitations\n"
            "under the License."
        )).strip()
        copyleft_ok = str(input_dict.get("copyleft_ok", "false")).lower().strip() in ("true", "1", "yes")
        publish = str(input_dict.get("publish", "false")).lower().strip() in ("true", "1", "yes")

        if not crate_name:
            return {"outputText": "Error: `crate_name` is required (e.g. 'swhid')."}
        if not crate_repo:
            return {"outputText": "Error: `crate_repo` is required (e.g. 'https://github.com/swhid/swhid-rs')."}
        if not package_name:
            package_name = f"{crate_name}-py"

        module_name = package_name.replace("-", "_")
        gh_headers = {"Accept": "application/vnd.github.v3+json"}
        if github_pat:
            gh_headers["Authorization"] = f"token {github_pat}"

        ns = data_store.use_namespace(f"rustopyian:{package_name}")
        lines = []
        flagged_deps = []

        def log(msg):
            print(msg, flush=True)
            lines.append(msg)

        log(f"# Rustopyian Constructinator")
        log(f"Wrapping **{crate_name}** -> **{package_name}**\n")

        # -- 1. Fetch crate metadata from crates.io -----------------------

        log("## Step 1: Fetch crate metadata\n")
        crates_resp = await http_client.get(f"https://crates.io/api/v1/crates/{crate_name}")
        if crates_resp.status_code != 200:
            return {"outputText": f"Error: crate `{crate_name}` not found on crates.io (HTTP {crates_resp.status_code})."}

        crate_meta = crates_resp.json()
        crate_info = crate_meta.get("crate", {})
        latest_version = crate_meta.get("versions", [{}])[0] if crate_meta.get("versions") else {}
        crate_version = latest_version.get("num", "unknown")
        crate_license = latest_version.get("license", crate_info.get("license", "unknown"))

        log(f"- Crate: **{crate_name}** v{crate_version}")
        log(f"- License: `{crate_license}`")
        log(f"- Description: {crate_info.get('description', 'N/A')}")
        log(f"- Repository: {crate_repo}\n")

        # -- 2. License audit ----------------------------------------------

        log("## Step 2: License audit\n")

        license_parts = re.split(r"[/\s]+", crate_license.upper().replace("OR", "/"))
        crate_copyleft = [l for l in license_parts if l in COPYLEFT_LICENSES]

        if crate_copyleft and not copyleft_ok:
            log(f"**BLOCKED**: crate `{crate_name}` is `{crate_license}` (copyleft).")
            log(f"Set `copyleft_ok=true` to override.")
            return {"outputText": "\n".join(lines)}

        deps_resp = await http_client.get(
            f"https://crates.io/api/v1/crates/{crate_name}/{crate_version}/dependencies"
        )
        if deps_resp.status_code == 200:
            deps_data = deps_resp.json().get("dependencies", [])
            for dep in deps_data:
                dep_name = dep.get("crate_id", "unknown")
                optional = dep.get("optional", False)
                kind = dep.get("kind", "normal")

                dep_resp = await http_client.get(f"https://crates.io/api/v1/crates/{dep_name}")
                if dep_resp.status_code == 200:
                    dep_meta = dep_resp.json()
                    dep_versions = dep_meta.get("versions", [])
                    dep_license = dep_versions[0].get("license", "unknown") if dep_versions else "unknown"
                    dep_license_parts = re.split(r"[/\s]+", dep_license.upper().replace("OR", "/"))
                    dep_copyleft_hits = [l for l in dep_license_parts if l in GPL_FAMILY]

                    if dep_copyleft_hits:
                        flagged_deps.append({
                            "name": dep_name, "license": dep_license,
                            "optional": optional, "kind": kind,
                            "flags": dep_copyleft_hits,
                        })
                await asyncio.sleep(0.2)

        if flagged_deps:
            log("### Copyleft dependencies found:\n")
            log("| Dependency | License | Optional | Flags |")
            log("|------------|---------|----------|-------|")
            for fd in flagged_deps:
                opt = "yes" if fd["optional"] else "**NO**"
                log(f"| {fd['name']} | {fd['license']} | {opt} | {', '.join(fd['flags'])} |")
            log("")
            non_optional_gpl = [fd for fd in flagged_deps if not fd["optional"]]
            if non_optional_gpl and not copyleft_ok:
                log("**BLOCKED**: non-optional copyleft dependencies detected.")
                return {"outputText": "\n".join(lines)}
            log("*Optional copyleft deps can be avoided by not enabling their feature flags.*\n")
        else:
            log("No copyleft dependencies found. All clear.\n")

        # -- 3. Fetch public API surface -----------------------------------

        log("## Step 3: Analyze public API\n")

        repo_match = re.match(r"https://github\.com/([^/]+)/([^/]+)", crate_repo)
        if not repo_match:
            return {"outputText": f"Error: cannot parse GitHub owner/repo from `{crate_repo}`"}
        gh_owner, gh_repo = repo_match.group(1), repo_match.group(2)

        cargo_toml = ""
        cargo_resp = await http_client.get(
            f"https://api.github.com/repos/{gh_owner}/{gh_repo}/contents/Cargo.toml",
            headers=gh_headers,
        )
        if cargo_resp.status_code == 200:
            cargo_toml = base64.b64decode(cargo_resp.json()["content"]).decode()
            log(f"Fetched `Cargo.toml` ({len(cargo_toml)} bytes)")

        rust_source = ""
        for src_path in ["src/lib.rs", "lib.rs"]:
            src_resp = await http_client.get(
                f"https://api.github.com/repos/{gh_owner}/{gh_repo}/contents/{src_path}",
                headers=gh_headers,
            )
            if src_resp.status_code == 200:
                rust_source = base64.b64decode(src_resp.json()["content"]).decode()
                log(f"Fetched `{src_path}` ({len(rust_source)} bytes)")
                break

        api_docs = ""
        for doc_path in ["REFERENCE.md", "README.md"]:
            doc_resp = await http_client.get(
                f"https://api.github.com/repos/{gh_owner}/{gh_repo}/contents/{doc_path}",
                headers=gh_headers,
            )
            if doc_resp.status_code == 200:
                api_docs = base64.b64decode(doc_resp.json()["content"]).decode()
                log(f"Fetched `{doc_path}` ({len(api_docs)} bytes)")
                break

        if not rust_source and not api_docs:
            return {"outputText": "\n".join(lines) +
                    "\n\nError: could not fetch source or docs from the repo."}

        # -- 4. Generate wrapper via LLM -----------------------------------

        log("\n## Step 4: Generate PyO3 wrapper\n")

        license_header_rust = ""
        license_header_python = ""
        if license_header:
            license_header_rust = "\n".join(f"// {l}" for l in license_header.strip().split("\n")) + "\n\n"
            license_header_python = "\n".join(f"# {l}" for l in license_header.strip().split("\n")) + "\n\n"

        generation_prompt = f"""You are generating a Python wrapper for a Rust crate using PyO3 and maturin.

CRATE: {crate_name} v{crate_version}
LICENSE: {crate_license}
WRAPPER PACKAGE: {package_name} (module: {module_name})
WRAPPER LICENSE: {wrapper_license}

Here is the Rust source (lib.rs):
```rust
{rust_source[:8000]}
```

Here is the Cargo.toml:
```toml
{cargo_toml[:2000]}
```

{f"Here is the API documentation:{chr(10)}```{chr(10)}{api_docs[:6000]}{chr(10)}```" if api_docs else "No additional API documentation available."}

TASK: Generate a complete PyO3 wrapper project. Output a JSON object with these keys:
- "lib_rs": The complete src/lib.rs file with PyO3 bindings.
- "init_py": The python/{module_name}/__init__.py file re-exporting from the native module.
- "init_pyi": Type stubs (.pyi) for the module with full docstrings.
- "cargo_toml": The Cargo.toml for the wrapper crate.
- "pyproject_toml": The pyproject.toml for maturin.
- "test_py": A pytest test file exercising every wrapped function.
- "readme_md": A README.md for the wrapper package. Include: what this wraps and why, installation (uv/pip from git, from source with maturin), quick start with code examples showing expected output, how to use as a dependency in requirements.txt and pyproject.toml, API reference table, development instructions, and license info. Use the same structure as a well-documented PyPI package.
- "api_surface": A JSON array of {{"name": "...", "kind": "function|class|method|enum", "rust_path": "...", "python_name": "..."}} for each wrapped item.
- "flagged_features": A JSON array of feature flags that pull in copyleft deps and should NOT be enabled.

CRITICAL RULES:
1. Check actual import paths - types may be in submodules (e.g. crate::error::ErrorType not crate::ErrorType).
2. Use DiskDirectoryBuilder / builder patterns if Directory::new() takes Vec<Entry> not a path.
3. LineRange/ByteRange fields may be u64, not u32.
4. The #[pyclass] enum needs name = "..." to not expose as PyEnumName in Python.
5. Add __eq__, __hash__, __repr__, __str__ to all wrapped types.
6. Do NOT enable any feature that depends on GPL/copyleft libraries.
7. Map I/O errors to PyOSError, parse errors to PyValueError.
8. Use py.allow_threads() around filesystem I/O operations.

Output ONLY valid JSON, no markdown fences, no explanation outside the JSON.
Keep test_py concise - one or two tests per wrapped function, not exhaustive.
For large crates, wrap the primary public API (pub types, pub functions) not internal helpers."""

        log("Calling LLM to generate wrapper code...")

        llm_messages = [
            {"role": "system", "content": "You are an expert Rust/Python developer specializing in PyO3 bindings. Output only valid JSON."},
            {"role": "user", "content": generation_prompt},
        ]

        response_content, thoughts = await call_llm(
            provider="anthropic",
            model="claude-sonnet-4-20250514",
            messages=llm_messages,
            parameters={"max_tokens": 64000, "temperature": 0},
        )

        # Detect truncation and attempt continuation
        cleaned = response_content.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```\w*\n?", "", cleaned)
            cleaned = re.sub(r"\n?```$", "", cleaned)

        if not cleaned.endswith("}"):
            log("Response appears truncated — requesting continuation...")
            continuation, _ = await call_llm(
                provider="anthropic",
                model="claude-sonnet-4-20250514",
                messages=llm_messages + [
                    {"role": "assistant", "content": response_content},
                    {"role": "user", "content": "Your JSON was truncated. Continue from exactly where you left off. Output ONLY the remaining JSON text, nothing else."},
                ],
                parameters={"max_tokens": 64000, "temperature": 0},
            )
            cleaned = cleaned + continuation.strip()
            log(f"Continuation received ({len(continuation)} chars)")

        try:
            generated = json.loads(cleaned, strict=False)
        except json.JSONDecodeError as e:
            log(f"\n**Warning**: LLM response was not valid JSON: {e}")
            ns.set("llm_raw_response", cleaned)
            generated = {}

        if not generated:
            return {"outputText": "\n".join(lines) +
                    "\n\nLLM did not return parseable output. Raw response stored in data_store."}

        # -- 5. Assemble project files -------------------------------------

        log("\n## Step 5: Assemble project\n")

        files = {}
        if generated.get("lib_rs"):
            files["src/lib.rs"] = license_header_rust + generated["lib_rs"]
        if generated.get("cargo_toml"):
            files["Cargo.toml"] = generated["cargo_toml"]
        if generated.get("pyproject_toml"):
            files["pyproject.toml"] = generated["pyproject_toml"]
        if generated.get("init_py"):
            files[f"python/{module_name}/__init__.py"] = license_header_python + generated["init_py"]
        if generated.get("init_pyi"):
            files[f"python/{module_name}/__init__.pyi"] = license_header_python + generated["init_pyi"]
        if generated.get("test_py"):
            files[f"tests/test_{module_name}.py"] = license_header_python + generated["test_py"]
        if generated.get("readme_md"):
            files["README.md"] = generated["readme_md"]

        files[".gitignore"] = "/target/\nCargo.lock\n__pycache__/\n*.pyc\n*.pyo\n*.egg-info/\ndist/\nbuild/\n*.so\n*.dylib\n*.dll\n.idea/\n.vscode/\n*.swp\n.DS_Store\nThumbs.db\n"

        ci_content = """name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ["3.9", "3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v5
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      - name: Build and install
        shell: bash
        run: |
          pip install maturin pytest
          maturin build
          pip install target/wheels/*.whl
      - name: Run tests
        run: pytest tests/ -v

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - name: Rust fmt
        run: cargo fmt --check
      - name: Clippy
        run: cargo clippy -- -D warnings

  wheels:
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    needs: [test, lint]
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Build wheels (Linux)
        if: runner.os == 'Linux'
        uses: PyO3/maturin-action@v1
        with:
          args: --release --out dist --interpreter python3.9 python3.10 python3.11 python3.12 python3.13
          manylinux: auto
      - name: Build wheels (macOS / Windows)
        if: runner.os != 'Linux'
        uses: PyO3/maturin-action@v1
        with:
          args: --release --out dist
      - uses: actions/upload-artifact@v7
        with:
          name: wheels-${{ matrix.os }}
          path: dist/
"""
        files[".github/workflows/ci.yml"] = license_header_python + ci_content

        for filepath, content in files.items():
            ns.set(f"files/{filepath}", content)

        api_surface = generated.get("api_surface", [])
        flagged_features = generated.get("flagged_features", [])

        ns.set("metadata", {
            "crate_name": crate_name, "crate_version": crate_version,
            "crate_license": crate_license, "package_name": package_name,
            "module_name": module_name, "wrapper_license": wrapper_license,
            "api_surface": api_surface, "flagged_features": flagged_features,
            "flagged_deps": flagged_deps, "file_count": len(files),
        })

        log(f"Generated **{len(files)}** files:")
        for fp in sorted(files.keys()):
            log(f"- `{fp}` ({len(files[fp]):,} bytes)")

        # -- 6. API surface report -----------------------------------------

        log(f"\n## Step 6: API surface\n")
        if api_surface:
            log("| Python name | Kind | Rust path |")
            log("|-------------|------|-----------|")
            for item in api_surface:
                log(f"| `{item.get('python_name', '?')}` | {item.get('kind', '?')} | `{item.get('rust_path', '?')}` |")
        if flagged_features:
            log(f"\n### Features NOT enabled (copyleft deps):\n")
            for feat in flagged_features:
                log(f"- `{feat}`")

        # -- 7. Push to GitHub (optional) ----------------------------------

        if publish and output_repo and output_token:
            log(f"\n## Step 7: Push to GitHub\n")
            log(f"Calling exporter to push to `{output_repo}`...\n")
            try:
                export_result = await gofannon_client.call(
                    agent_name="rustopyian_export",
                    input_dict={
                        "package_name": package_name,
                        "github_repo": output_repo,
                        "github_pat": output_token,
                        "branch": output_branch,
                        "commit_msg": f"Initial {package_name} wrapper from Rustopyian Constructinator",
                    }
                )
                export_text = export_result.get("outputText", "")
                log(export_text)
            except Exception as e:
                log(f"**Export failed**: {e}")
                log(f"Files are still in data_store - run the exporter manually.")
        else:
            log(f"\n---\n")
            log(f"Files stored in data_store namespace `rustopyian:{package_name}`.")
            if output_repo and output_token and not publish:
                log(f"Credentials provided but `publish` is not set. Set `publish=true` to push.")
            elif not output_repo:
                log(f"Set `output_repo`, `output_token`, and `publish=true` to push to GitHub.")
            log(f"\nTo push manually, run the **rustopyian_export** agent with:")
            log(f"```")
            log(f"package_name: {package_name}")
            log(f"github_repo: owner/repo")
            log(f"github_pat: ghp_...")
            log(f"```")

        log(f"\n## Next steps\n")
        log(f"1. Clone the repo and run `maturin develop` to find compile errors")
        log(f"2. Fix `src/lib.rs` based on compiler output")
        log(f"3. Run `cargo fmt` before committing")
        log(f"4. Run `pytest tests/ -v` once it compiles")

        return {"outputText": "\n".join(lines)}

    finally:
        await http_client.aclose()