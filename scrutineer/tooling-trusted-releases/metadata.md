# Repository Metadata

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Analyzed:** 2026-05-07

## Manifests found

| Path | Type | Project name | Version | Published? | Reason |
|---|---|---|---|---|---|
| `pyproject.toml` | python | `tooling-trusted-releases` | 0.0.1 | **No** | No `[build-system]` section; not found on PyPI |
| `bootstrap/source/package.json` | npm | — | — | **No** | No name/version fields; declares only `bootstrap` and `mermaid` dependencies |
| `Dockerfile.alpine` | docker | `tooling-trusted-release` | — | **No** | CI builds image with `push: false`; no registry push configured |

## Registries checked

| Registry | URL | Result |
|---|---|---|
| PyPI | https://pypi.org/project/tooling-trusted-releases/ | not_found |

## Summary

This repository does not publish any packages to any registry. It is internal Apache infrastructure tooling — no publishing configuration in `pyproject.toml`, no npm package identity, and Docker images built locally only. As of 2026-05-07 the project is in alpha development and is operated as a deployed service rather than distributed as a library.

## Cross-references

- Publication detail → [packages.md](./packages.md)
- Downstream exposure → [dependents.md](./dependents.md)
- Project layout and tooling → [repo-overview.md](./repo-overview.md)

## Note on metadata extraction

A separate metadata extractor reported a parse error during automated harvesting (`json: cannot unmarshal object into Go struct field .languages of type []string`). Language detection was therefore performed by the repo-overview pass instead — see [repo-overview.md → Languages](./repo-overview.md#languages). All other manifest data above is unaffected.
