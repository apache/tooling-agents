# Published Packages

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Generated:** 2026-05-07

## Summary

**This repository does not publish any packages to any registry.** It is internal Apache infrastructure tooling deployed as a continuously delivered service.

## Manifests found

| Path | Type | Project name | Version | Published? | Reason |
|---|---|---|---|---|---|
| `pyproject.toml` | python | `tooling-trusted-releases` | 0.0.1 | **No** | No `[build-system]` section in `pyproject.toml`; not found on PyPI |
| `bootstrap/source/package.json` | npm | — | — | **No** | No name or version fields; contains only dependencies (bootstrap, mermaid) |
| `Dockerfile.alpine` | docker | `tooling-trusted-release` | — | **No** | Docker image built with `push: false` in CI; no registry push configured |

## Registries checked

| Registry | URL | Result |
|---|---|---|
| PyPI | https://pypi.org/project/tooling-trusted-releases/ | not found |

## Why this matters

The absence of published packages has two security implications:

1. **No supply-chain exposure to downstream consumers.** No external project pulls this code as a dependency, so a compromise of this repo would not propagate to other projects through the package registry channel. This matches the [dependents](./dependents.md) finding of zero runtime dependents.

2. **No registry-level advisory surface.** Tools like OSV, GHSA, Dependabot, and pip-audit can only report advisories against published packages. A vulnerability in ATR would be tracked through the ASF security disclosure process — see [advisories.md](./advisories.md) and [maintainers.md](./maintainers.md#security-contact-use-this-first).

The deployed ATR service itself remains a meaningful attack surface — see [security-deep-dive.md](./security-deep-dive.md) for that analysis.

## Cross-references

- Manifest discovery detail → [metadata.md](./metadata.md)
- Downstream exposure → [dependents.md](./dependents.md)
- Advisory surface → [advisories.md](./advisories.md)
