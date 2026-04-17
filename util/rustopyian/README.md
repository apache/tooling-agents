# Rustopyian Constructinator

A [Gofannon](https://github.com/apache/gofannon) agent that takes a Rust crate and produces a Python wrapper project using [PyO3](https://pyo3.rs) and [maturin](https://www.maturin.rs).

Rust crate goes in, Python package comes out.

## Agents

Two Gofannon agents work together:

- **`rustopyian`** (Constructinator) — fetches crate metadata, audits licenses, generates wrapper code via LLM, stores files in data_store, optionally pushes to GitHub
- **`rustopyian_export`** (Exporter) — reads generated files from data_store and pushes them to a GitHub repo via the Git Trees API

The Constructinator calls the Exporter automatically when `publish=true` is set along with `output_repo` and `output_token`. You can also run the Exporter separately.

## Prerequisites

- A Gofannon webapp installation with an LLM provider configured (the Constructinator uses Claude Sonnet)
- A GitHub repo created to receive the generated project (can be empty)
- A GitHub PAT with write access to that repo

### GitHub PAT permissions

For **fine-grained PATs** (recommended), the token needs these repository permissions:

- **Contents: Read and write** — for creating blobs, trees, and commits
- **Workflows: Read and write** — for pushing `.github/workflows/` files

For **classic PATs**, the `repo` scope covers both.

The token must be scoped to the target repository.

## Constructinator inputs

Create an agent in Gofannon using `rustopyian.py` and configure these inputs:

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `crate_name` | **yes** | — | Crate name on crates.io (e.g. `swhid`) |
| `crate_repo` | **yes** | — | Source GitHub repo URL (e.g. `https://github.com/swhid/swhid-rs`) |
| `package_name` | no | `{crate_name}-py` | Python package name |
| `github_pat` | no | — | GitHub PAT for reading source (raises API rate limits) |
| `output_repo` | no | — | GitHub repo to push to, as `owner/repo` (e.g. `apache/swhid-py`) |
| `output_token` | no | — | GitHub PAT with write access to `output_repo` |
| `output_branch` | no | `main` | Branch to push to |
| `license` | no | `Apache-2.0` | License for the generated wrapper |
| `license_header` | no | ASF header | Per-file license header text (added to all source files) |
| `copyleft_ok` | no | `false` | Set `true` to allow copyleft dependencies |
| `publish` | no | `false` | Set `true` to push generated files to `output_repo` |

### Minimal run (generate only, no push)

```
crate_name:     swhid
crate_repo:     https://github.com/swhid/swhid-rs
```

Files are stored in data_store. You retrieve them manually or run the Exporter.

### Full run (generate + push to GitHub)

```
crate_name:     swhid
crate_repo:     https://github.com/swhid/swhid-rs
package_name:   swhid-py
github_pat:     ghp_readtoken123
output_repo:    apache/swhid-py
output_token:   ghp_writetoken456
output_branch:  main
publish:        true
```

The ASF license header is added to all generated source files by default. Override with `license_header` or set it to empty to omit.

## Exporter inputs

Create a second agent in Gofannon using `rustopyian_export.py`. The Constructinator calls it automatically, but you can also run it standalone:

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `package_name` | **yes** | — | Must match the Constructinator run (e.g. `swhid-py`) |
| `github_repo` | **yes** | — | Target repo as `owner/repo` |
| `github_pat` | **yes** | — | GitHub PAT with write access |
| `branch` | no | `main` | Branch to push to |
| `commit_msg` | no | `Initial wrapper from Rustopyian` | Commit message |
| `dry_run` | no | `false` | Set `true` to list files without pushing |

### Preview what would be pushed

```
package_name:   swhid-py
github_repo:    apache/swhid-py
dry_run:        true
```

### Push to a repo

```
package_name:   swhid-py
github_repo:    apache/swhid-py
github_pat:     ghp_writetoken456
```

## What gets generated

| File | Description |
|------|-------------|
| `src/lib.rs` | PyO3 bindings wrapping the crate's public API |
| `Cargo.toml` | Rust dependencies (target crate + PyO3) |
| `pyproject.toml` | Python package metadata for maturin |
| `python/{module}/__init__.py` | Re-exports from the native module |
| `python/{module}/__init__.pyi` | Type stubs for IDE support |
| `tests/test_{module}.py` | Pytest test suite |
| `.github/workflows/ci.yml` | CI for Linux, macOS, Windows × Python 3.9–3.13 |
| `.gitignore` | Rust + Python ignores |

## After the agents run

The generated code is a starting point. The LLM does its best to map the Rust API to Python, but it may get import paths, type sizes, or builder patterns wrong.

```bash
# 1. Clone the repo
git clone https://github.com/apache/swhid-py.git
cd swhid-py

# 2. Install prerequisites
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
uv venv && source .venv/bin/activate
uv pip install maturin pytest

# 3. Build — the compiler tells you what's wrong
maturin develop

# 4. Fix src/lib.rs based on compiler errors, repeat until clean

# 5. Format and test
cargo fmt
pytest tests/ -v

# 6. Commit
git add -A && git commit -m "fix: compile errors from initial generation"
git push
```

### Common compiler errors

Based on building [swhid-py](https://github.com/apache/swhid-py):

| Error | Fix |
|-------|-----|
| `cannot find type Error in crate` | Type is in a submodule: `crate::error::Error` not `crate::Error` |
| `mismatched types: expected u64, found u32` | Struct fields are `u64`, not `u32` — update the PyO3 function signature |
| `this method takes 1 argument but 2 were supplied` | Method takes a struct (`LineRange`), not separate args |
| `expected Vec<Entry>, found &PathBuf` | Use `DiskDirectoryBuilder::new(path)` not `Directory::new(path)` |
| `cannot import name ObjectType ... did you mean PyObjectType?` | Missing `#[pyclass(name = "ObjectType")]` on the enum |

## License audit

The agent checks every dependency's license:

| License family | Action |
|----------------|--------|
| GPL-2.0/3.0, AGPL-3.0 | **Block** (unless `copyleft_ok=true`) |
| LGPL-2.0/2.1/3.0 | **Block** (unless `copyleft_ok=true`) |
| MPL-2.0 | **Flag** (weak copyleft) |
| MIT, Apache-2.0, BSD, ISC | Pass |

Optional dependencies behind feature flags are flagged but don't block. The agent records which features to avoid.

## CI workflow details

The generated CI encodes lessons from building swhid-py across all three platforms:

- `shell: bash` on build steps (PowerShell doesn't expand `*.whl` globs)
- Split wheel builds: explicit `--interpreter python3.9 ... python3.13` on Linux (manylinux container), plain `--release --out dist` on macOS/Windows (avoids Python 3.14 which PyO3 0.23 doesn't support)
- `actions/checkout@v5`, `actions/upload-artifact@v7` (Node 24)
- No `maturin[patchelf]` (patchelf can't build on Windows)

## Data store layout

All data lives under the namespace `rustopyian:{package_name}`:

```
rustopyian:swhid-py/
  files/src/lib.rs
  files/Cargo.toml
  files/pyproject.toml
  files/python/swhid_py/__init__.py
  files/python/swhid_py/__init__.pyi
  files/tests/test_swhid_py.py
  files/.gitignore
  files/.github/workflows/ci.yml
  metadata                          # crate info, API surface, flagged deps
  llm_raw_response                  # only if JSON parsing failed
```

Retrieve manually:

```python
ns = data_store.use_namespace("rustopyian:swhid-py")
ns.list_keys()                          # see everything
ns.get("files/src/lib.rs")              # get a specific file
ns.get("metadata")["api_surface"]       # wrapped API items
```

## Background

Built as the "Rustopyian Constructinator" — a conveyor belt where a Rust crate goes in and a Python package comes out. The first project through the pipeline was [swhid-py](https://github.com/apache/swhid-py), Python bindings for the SWHID v1.2 reference implementation. The lessons from that build (license auditing, API mismatch patterns, CI platform quirks) are encoded directly into the agent's LLM prompt and static templates.

See [apache/tooling-trusted-releases#1154](https://github.com/apache/tooling-trusted-releases/issues/1154) for the original discussion.