# Zizmor — GitHub Actions Workflow Audit

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Tool:** [zizmor](https://github.com/woodruffw/zizmor) — supply-chain security auditor for GitHub Actions workflows
**Findings:** **0**

## Result

Zizmor reported zero findings across the project's GitHub Actions workflows.

## Why this is the expected result

The project follows GitHub Actions supply-chain best practices:

- **Every action reference is pinned to a 40-character commit SHA**, not a tag or branch. Tags can be force-moved, branches can be replaced — SHAs cannot. See [dependencies.md → GitHub Actions](./dependencies.md#github-actions--pinned-to-commit-shas) for the full pin list.
- **Zizmor itself runs in pre-commit** (`github.com/woodruffw/zizmor-pre-commit v1.24.1`), so any new workflow addition is audited before it lands. This is enforced via `.pre-commit-config.yaml` — see [dependencies.md](./dependencies.md#pre-commit-hooks--pre-commit-configyaml).
- **CodeQL is enabled** (`.github/workflows/codeql.yaml`) for ongoing static analysis of the application code.
- **An allowlist check** (`.github/workflows/allowlistchecker.yml`) uses `apache/infrastructure-actions/allowlist-check` — an ASF-controlled action — to constrain which contributors can trigger workflows on their PRs.

## Workflows present

| Workflow | Purpose |
|---|---|
| `allowlistchecker.yml` | ASF allowlist enforcement on PRs |
| `analyze.yml` | Lint and analysis (uv, biome, cache) |
| `build.yml` | Build pipeline (uv, setup-python) |
| `codeql.yaml` | CodeQL static analysis |
| `generatesbom.yml` | SBOM generation via anchore/sbom-action and Docker buildx |

## Cross-references

- Full SHA-pinned action list → [dependencies.md](./dependencies.md#github-actions--pinned-to-commit-shas)
- Pre-commit hook list (including zizmor) → [dependencies.md](./dependencies.md#pre-commit-hooks--pre-commit-configyaml)
