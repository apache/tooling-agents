# Repository Overview

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Analyzed:** 2026-05-07
**Branch:** `main`

Tools matched: 21 of 516 checked. Files inspected: 714.

## Languages

| Language | Confidence | Notes |
|---|---|---|
| Python | medium | Primary backend language |
| JavaScript | medium | Frontend |
| TypeScript | medium | Frontend (`tsconfig.json`) |

## Package management

| Tool | Lockfile | Config |
|---|---|---|
| [uv](https://docs.astral.sh/uv/) | `uv.lock` | `pyproject.toml` |

Run `uv sync` to install (alternative: `uv pip install -r requirements.txt`).

## Runtime versions

- Python: **3.13** (`.python-version`, CI matrix)

## Tooling

### Build

- **[Sass](https://sass-lang.com)** — CSS preprocessor
- **aiohttp** — async HTTP (Apache-2.0)
- **cryptography** — pyca cryptographic primitives
- **requests** — HTTP client

### Containers

- **[Docker](https://www.docker.com)** — `.dockerignore`, `docker-compose.yml`
- **[Docker Compose](https://docs.docker.com/compose/)** — multi-container orchestration
  - Run: `docker compose up`

### Database

- **[SQLite](https://www.sqlite.org)** — embedded RDBMS
- **[Alembic](https://alembic.sqlalchemy.org)** — migrations (`alembic.ini`)
  - Run: `alembic upgrade head` · `alembic revision --autogenerate`

### Dependency management bot

- **[Dependabot](https://docs.github.com/en/code-security/dependabot)** — `.github/dependabot.yml`

### Environment

- **[pyenv](https://github.com/pyenv/pyenv)** — `.python-version`

### Lint / format

- **[Ruff](https://docs.astral.sh/ruff/)** — Python linter & formatter (`ruff check .` / `ruff check --fix .`)
- **[pre-commit](https://pre-commit.com)** — `.pre-commit-config.yaml`; runs via `make check`
- **[Stylelint](https://stylelint.io)** — `.stylelintrc.json`, `.stylelintignore`

### Test

- **[pytest](https://pytest.org)** — Python tests; configured in `pyproject.toml`
  - Run: `pytest` · `python -m pytest`
- Test directory: `tests/`

### Type checking

- **[Pyright](https://microsoft.github.io/pyright/)** — Python static type checker
- **[tsc](https://www.typescriptlang.org)** — TypeScript checker (`tsc --noEmit`)

### CI

- **[GitHub Actions](https://github.com/features/actions)** — `.github/workflows/`

## Make targets (`Makefile`)

The project uses Make as the primary task runner. Selected targets:

| Target | Purpose |
|---|---|
| `make build` | Build the project |
| `make build-alpine` | Build Alpine container image |
| `make build-bootstrap` | Build Bootstrap CSS asset |
| `make build-docs` | Build documentation |
| `make build-playwright` | Build Playwright e2e harness |
| `make build-ts` | Compile TypeScript |
| `make check` / `check-light` / `check-heavy` / `check-extra` / `check-clean` | Lint/format/static checks |
| `make certs` / `certs-local` | Generate certificates |
| `make docs` | Generate docs |
| `make e2e` / `e2e-clean` | End-to-end tests |
| `make generate-version` | Stamp version |
| `make ipython` | Interactive shell |
| `make run-alpine` | Run inside Alpine container |
| `make run-playwright` / `run-playwright-slow` | Run Playwright tests |
| `make serve` / `serve-local` / `atr.server` | Run server |
| `make sync` / `sync-all` | uv dependency sync |
| `make unit` | Unit tests |
| `make update-deps` | Update dependencies |

## Style

Indentation configured via `.editorconfig`.

## Resources

- README: `README.md`
- License: `LICENSE` (Apache-2.0)
- Notice: `NOTICE`
- Contributing: `CONTRIBUTING.md`
- Governance: `GOVERNANCE.md`
- Support: `SUPPORT.md`
- Security: `SECURITY.md` — see [maintainers.md](./maintainers.md#security-contact-use-this-first)

## Git

- Default branch: `main`
- Remote: https://github.com/apache/tooling-trusted-releases
