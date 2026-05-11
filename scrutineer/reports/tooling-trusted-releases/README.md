# Apache Trusted Releases — Security Assessment

Repository: [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
Commit analyzed: `837830e8a0a0b9989ec3decbdf2eb2f82a3f6640`
Date: **2026-05-07**

## What this is

Apache Trusted Releases (ATR) is a server-side web application operated by ASF Infrastructure for managing the Apache release process. It exposes a web UI (OAuth-authenticated), an SSH server (public-key authenticated), and a REST API (JWT-authenticated). It is **not** published as a library — it is a deployed service in alpha development.

The reports below capture a security review of the codebase at the commit above, plus dependency, maintainer, and prior-art context. No exploitable findings were identified in the deep-dive, and no CVE/GHSA advisories exist for the repository or any internal package.

## Report index

| Report | Summary | Findings |
|---|---|---|
| [Security deep-dive](./security-deep-dive.md) | Trust boundaries, all 54 security-relevant sinks, ruled-out analysis | 0 exploitable |
| [Semgrep static analysis](./semgrep.md) | 120 raw Semgrep alerts (mostly Jinja `href` template variables) | 119 medium, 1 high — see analyst notes |
| [Zizmor (GH Actions)](./zizmor.md) | GitHub Actions workflow audit | 0 |
| [GitHub Advisories & CVEs](./advisories.md) | GHSA / OSV / GitHub Security tab review | 0 |
| [Repository overview](./repo-overview.md) | Languages, tools, build/test/lint stack | informational |
| [Maintainers](./maintainers.md) | Active maintainers, security contact, comms channels | informational |
| [Direct dependencies](./dependencies.md) | pyproject.toml + GitHub Actions + npm + Docker | informational |
| [Software Bill of Materials (CycloneDX)](./sbom.md) | Full transitive component listing | informational |
| [Published packages](./packages.md) | Registry publication status | none published |
| [Downstream dependents](./dependents.md) | Reverse-dependency exposure | 0 dependents |
| [Subprojects](./subprojects.md) | Sub-component scan | none detected |
| [Repo metadata](./metadata.md) | Manifest discovery, registry checks | informational |

## Headline takeaways

**No exploitable security findings.** The deep-dive enumerated 54 security-relevant sinks across command execution, file I/O, path handling, archive extraction, deserialisation, templating, network, and cryptography. Every sink ruled out at one of three steps: hardcoded inputs, validated inputs through the `safe` type hierarchy, or trusted upstream principals. The application demonstrates strong defensive engineering: cascading `safe.RelPath` / `safe.StatePath` validation, no `shell=True`, no `eval`/`exec`/`pickle`, `defusedxml` for XML, `strictyaml` with explicit schema, hardened TLS (1.2+, `CERT_REQUIRED`), and the `htpy` HTML builder which auto-escapes children.

**Semgrep noise.** The 119 medium-severity Semgrep alerts are all the `var-in-href` and `template-unescaped-with-safe` rules firing on Jinja templates. Inspection in context (see [semgrep.md](./semgrep.md)) shows the variables in `href` attributes are server-generated URLs (built from validated `safe.ProjectKey`/`safe.VersionKey` and `url_for`-equivalent paths), not arbitrary user input — they cannot carry a `javascript:` URI. The single high-severity finding is in a `.pyi` type stub which is not executed code. These are best treated as defense-in-depth opportunities (CSP header, `url_for` helpers) rather than active vulnerabilities. Note: Semgrep's Flask rules misidentify the framework — ATR uses Quart, not Flask — but the autoescape semantics are the same.

**Reporting a vulnerability.** Per [SECURITY.md](https://github.com/apache/tooling-trusted-releases/blob/main/SECURITY.md), email **security@apache.org** — one plain-text email per vulnerability. Do not use public GitHub issues. The lead maintainer is Sean B. Palmer ([@sbp](https://github.com/sbp)) with ~79% of commits; Alastair McFarlane (`arm@apache.org`) and Dave Fisher are the next most responsive. See [maintainers.md](./maintainers.md) for full context.

**No published packages, no dependents.** ATR is a deployed service, not a library. It is not on PyPI, npm, or any other registry, and no downstream code depends on it. The attack surface is the deployed instance itself.

## Trust model at a glance

- **ASF committers** (web UI / SSH): conditionally trusted, scoped to their own projects
- **Public users**: read-only access to release downloads and checklists
- **Admins**: elevated access for key management and system maintenance
- **External APIs** (OSV, GitHub OIDC, LDAP, SVN): trusted data sources over hardened TLS

See [security-deep-dive.md → Trust Boundaries](./security-deep-dive.md#trust-boundaries) for the full table.

## Cross-references

- The dependency lists in [dependencies.md](./dependencies.md) and [sbom.md](./sbom.md) overlap intentionally: the first is the human-readable direct list from `pyproject.toml`, the second is the full CycloneDX transitive graph.
- [Repo overview](./repo-overview.md) and [metadata](./metadata.md) both describe the project layout but from different angles: the first is tooling/build-stack focused, the second is publication-status focused.
- The deep-dive's [ruled-out section](./security-deep-dive.md#ruled-out-sinks) is the right cross-reference for any Semgrep finding — most overlap with sinks already analysed there.
