# Security Advisories

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Generated:** 2026-05-07

## Summary

| Metric | Count |
|---|---|
| Total advisories for this repo | **0** |
| Critical | 0 |
| High | 0 |
| Moderate | 0 |
| Low | 0 |
| GHSA | 0 |
| CVE | 0 |
| OSV | 0 |

**No security advisories have been published for this repository or for any internal package it produces.**

## Repository facts

| Field | Value |
|---|---|
| Name | tooling-trusted-releases |
| Full name | apache/tooling-trusted-releases |
| URL | [github.com/apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases) |
| Description | Apache Trusted Releases (ATR) — a prototype service for verifying and distributing Apache releases securely |
| License | Apache-2.0 |

## Packages produced

| Name | Ecosystem | Version | Published? | Notes |
|---|---|---|---|---|
| `tooling-trusted-releases` | PyPI | 0.0.1 | **No** | Defined in `pyproject.toml`; deployed as a continuously deployed service rather than a published library. |

Because the package is not published to any registry, ecosystem-level advisories cannot exist for it.

## Sources checked

| Source | Result |
|---|---|
| [GitHub Security Advisories (repo)](https://github.com/apache/tooling-trusted-releases/security/advisories) | No published advisories |
| [GitHub Advisory Database (pip)](https://github.com/advisories?query=type%3Areviewed+ecosystem%3Apip+tooling-trusted-releases) | 0 advisories matched |
| [OSV — PyPI](https://osv.dev/list?q=tooling-trusted-releases&ecosystem=PyPI) | No results |
| [GitHub Security Overview](https://github.com/apache/tooling-trusted-releases/security) | 0 published advisories; Dependabot/code-scanning/secret-scanning counts not publicly visible |
| Scrutineer advisories API | Empty — see [security-deep-dive.md → Prior art](./security-deep-dive.md#prior-art) |

## Security policy

| Field | Value |
|---|---|
| Has a `SECURITY.md`? | Yes |
| Reporting channel | **security@apache.org** |
| Scope | ATR application (web interface and API) and documentation |
| Out of scope | Third-party dependencies (report to that project); ASF infrastructure not specific to ATR (root@apache.org) |
| Supported versions | Current production version only (continuously deployed) |

See [maintainers.md → Security contact](./maintainers.md#security-contact-use-this-first) for the full reporting process.

## Notes

This repository is in alpha development as of January 2026. The package is not published to any public registry, which explains the absence of ecosystem-level advisories. Dependency-level advisories (i.e., CVEs in the libraries ATR depends on) are not enumerated here — they would be discovered through tools like `pip-audit` (already in the pre-commit chain — see [dependencies.md](./dependencies.md#pre-commit-hooks--pre-commit-configyaml)) or GitHub Dependabot.

## Cross-references

- Reporting process and maintainer contacts → [maintainers.md](./maintainers.md)
- Components subject to upstream advisories → [sbom.md](./sbom.md)
- Prior art search detail → [security-deep-dive.md → Prior art](./security-deep-dive.md#prior-art)
