# Downstream Dependents

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Generated:** 2026-05-07

## Summary

| Metric | Value |
|---|---|
| Total packages produced | 1 |
| Total runtime dependents | **0** |
| Total exposure risk | None identified |

## Detail

### `tooling-trusted-releases` (PyPI)

| Field | Value |
|---|---|
| Version | 0.0.1 |
| Ecosystem | pypi |
| Manifest | `pyproject.toml` |
| Published? | **No** |
| Publish URL | — |
| Type | application |
| Source | github-dependents-api |
| Total runtime dependents | **0** |
| Top dependents | — |

ATR is an end-user web application — Apache Trusted Releases — not a reusable library. It is not published to PyPI and has zero known runtime dependents.

### `source` (npm)

| Field | Value |
|---|---|
| Manifest | `bootstrap/source/package.json` |
| Published? | No |
| Description | Internal Bootstrap CSS build asset |
| Total dependents | 0 |

This is an internal build artifact for compiling Bootstrap CSS, not a publishable npm package.

## Implication for security

There is no downstream exposure risk: no third-party project consumes any artefact of this repository as a library. The attack surface is the deployed ATR service itself, accessed via web UI / SSH / API endpoints described in [security-deep-dive.md → Trust boundaries](./security-deep-dive.md#trust-boundaries).

## Cross-references

- Publication status detail → [packages.md](./packages.md)
- Manifest discovery and registry checks → [metadata.md](./metadata.md)
