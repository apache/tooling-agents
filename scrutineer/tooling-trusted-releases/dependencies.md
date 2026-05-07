# Direct Dependencies

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Analyzed:** 2026-05-07

This document covers the **direct, declared** dependencies in the project's manifests. For the full transitive component graph (including pinned lockfile versions and integrity hashes), see [sbom.md](./sbom.md).

## Python (PyPI) — `pyproject.toml`

Runtime dependencies declared in `pyproject.toml`:

| Package | Constraint |
|---|---|
| aiofiles | >=24.1.0,<26.0.0 |
| aiohttp | >=3.13.4 |
| aioshutil | >=1.5,<2.0 |
| aiosmtplib | >=4.0.0,<6.0.0 |
| aiosqlite | >=0.21.0,<0.23.0 |
| aiozipstream | >=0.4,<0.5 |
| alembic | >=1.14,<2.0.0 |
| asfquart | git+https://github.com/apache/infrastructure-asfquart.git@sbp-server-side-sessions |
| asyncssh | >=2.20.0,<3.0.0 |
| blake3 | >=1.0.8 |
| blockbuster | >=1.5.23,<2.0.0 |
| cmarkgfm | >=2024.11.20 |
| cryptography | >=46.0,<47.0.0 |
| cvss | >=3.6,<4.0.0 |
| cyclonedx-python-lib | >=11.0.0 |
| dnspython | >=2.7.0,<3.0.0 |
| dulwich | >=1.0.0 |
| dunamai | >=1.23.0 |
| email-validator | >=2.2.0,<3.0.0 |
| exarch | >=0.2.7 |
| gitignore-parser | >=0.1.12,<0.2.0 |
| greenlet | >=3.1.1,<4.0.0 |
| htpy | >=25.7.0,<26.0.0 |
| hypercorn | >=0.17,<1.0.0 |
| hyperscan | >=0.8.0 |
| ldap3 | ==2.10.2rc3 |
| packaging | >=25.0 |
| psutil | >=7.2.1 |
| puremagic | >=1.30 |
| pydantic-xml | >=2.17.2,<3.0.0 |
| pyjwt | >=2.10.1,<3.0.0 |
| python-decouple | >=3.8,<4.0.0 |
| quart-rate-limiter | >=0.12.1 |
| quart-schema | >=0.21,<1.0.0 |
| quart-wtforms | >=1.0.3,<2.0.0 |
| requests | >=2.33.0 |
| rich | >=14.0.0 |
| rpgp-py | ==0.19.7 |
| semver | >=3.0.4 |
| sqlmodel | >=0.0.24,<0.1.0 |
| ssh-audit | >=3.3.0 |
| standard-imghdr | >=3.13.0 |
| strictyaml | >=1.7.3 |
| structlog | >=25.5.0 |
| yyjson | >=4.0.6 |

Notable security-relevant choices: `defusedxml` for XML, `strictyaml` for YAML (safe subset), `cryptography` and `pyjwt` from pyca, `blake3` for hashing, `asyncssh` for SSH, `cyclonedx-python-lib` for SBOMs, `cvss` for vulnerability scoring.

## GitHub Actions — pinned to commit SHAs

All workflow actions are pinned to full commit SHAs (zizmor best practice). See [zizmor.md](./zizmor.md).

| Action | SHA | Used in |
|---|---|---|
| `actions/checkout` | `de0fac2e4500dabe0009e67214ff5f5447ce83dd` | `allowlistchecker.yml`, `analyze.yml`, `build.yml`, `codeql.yaml`, `generatesbom.yml` |
| `actions/setup-python` | `a309ff8b426b58ec0e2a45f0f869d46889d02405` | `analyze.yml`, `build.yml` |
| `actions/cache` | `27d5ce7f107fe9357f9df03efb73ab90386fccae` | `analyze.yml`, `build.yml` |
| `astral-sh/setup-uv` | `08807647e7069bb48b6ef5acd8ec9567f424441b` | `analyze.yml`, `build.yml` |
| `biomejs/setup-biome` | `4c91541eaada48f67d7dbd7833600ce162b68f51` | `analyze.yml` |
| `apache/infrastructure-actions/allowlist-check` | `4e9c961f587f72b170874b6f5cd4ac15f7f26eb8` | `allowlistchecker.yml` |
| `github/codeql-action/init` | `267c4672a565967e4531438f2498370de5e8a98d` | `codeql.yaml` |
| `github/codeql-action/analyze` | `267c4672a565967e4531438f2498370de5e8a98d` | `codeql.yaml` |
| `advanced-security/dismiss-alerts` | `046d6b48d2e43cf563f96f67332c47c432eff83e` | `codeql.yaml` |
| `docker/setup-buildx-action` | `4d04d5d9486b7bd6fa91e7baf45bbb4f8b9deedd` | `generatesbom.yml` |
| `docker/build-push-action` | `bcafcacb16a39f128d818304e6c9c0c18556b85f` | `generatesbom.yml` |
| `anchore/sbom-action` | `e22c389904149dbc22b58101806040fa8d37a610` | `generatesbom.yml` |

## pre-commit hooks — `.pre-commit-config.yaml`

| Hook | Version |
|---|---|
| github.com/Lucas-C/pre-commit-hooks | v1.5.6 |
| github.com/igorshubovych/markdownlint-cli | v0.48.0 |
| github.com/oxc-project/mirrors-oxlint | v1.60.0 |
| github.com/pre-commit/pre-commit-hooks | v6.0.0 |
| github.com/pypa/pip-audit | v2.10.0 |
| github.com/rtts/djhtml | 3.0.11 |
| github.com/shellcheck-py/shellcheck-py | v0.11.0.1 |
| github.com/thibaudcolas/pre-commit-stylelint | v17.11.0 |
| github.com/woodruffw/zizmor-pre-commit | v1.24.1 |

`pip-audit` and `zizmor` running in pre-commit is a notable supply-chain hygiene signal.

## Docker base images

| Image | Tag | Manifest |
|---|---|---|
| `python` | `3.13.7-alpine3.22` | `Dockerfile.alpine` |
| `alpine` | `edge` | `bootstrap/context/Dockerfile` |
| `mcr.microsoft.com/playwright/python` | `v1.58.0-noble` | `tests/Dockerfile.e2e`, `tests/Dockerfile.playwright` |

## npm — `bootstrap/source/package.json`

This is an internal CSS build asset (not published to npm). Direct dependencies:

| Package | Version |
|---|---|
| bootstrap | 5.3.8 |
| mermaid | 11.14.0 |

The lockfile pulls in the full Bootstrap and Mermaid transitive trees (d3, cytoscape, dompurify, marked, katex, etc.) — see [sbom.md](./sbom.md) for the complete list.

## Cross-references

- Pinned lockfile versions and integrity hashes → [sbom.md](./sbom.md)
- Workflow security audit → [zizmor.md](./zizmor.md)
- Vulnerability advisories for these dependencies → [advisories.md](./advisories.md)
