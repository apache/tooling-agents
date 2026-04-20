# Apache CI Security: Action Required

## Goal

Identify CI pipelines across 634 Apache GitHub repositories that could be exploited to compromise published packages or leak secrets. **197** repos publish to registries including npm, PyPI, Maven Central, Docker Hub, and crates.io.

## High Risk: Publishing Repos

**2** repos that publish packages have HIGH-severity findings.

- **apache/beam** (apache_dist, docker_hub, gcr, gcs, github_releases, maven_central, pypi)
- **apache/gluten** (apache_dist)

## Latent Risk: Composite Action Injection in Publishing Repos

**6** repos that publish packages have composite actions that interpolate `inputs.*` in shell blocks. Not exploitable today — callers pass trusted values — but one unsafe caller away from shell injection.

- **apache/arrow** (apache_dist, github_releases)
- **apache/camel-k** (docker_hub, maven_central)
- **apache/camel-k-runtime** (maven_central)
- **apache/datafusion-ballista** (ghcr)
- **apache/datafusion-comet** (ghcr)
- **apache/flink-kubernetes-operator** (maven_central)

## Systemic Issues

**Trusted publishing migration.** 79 repos use long-lived secrets (NPM_TOKEN, PYPI_API_TOKEN, etc.) to publish to registries that support OIDC. Migrating to trusted publishing eliminates stored secrets entirely. ([migration details](publishing.md#trusted-publishing-migration-opportunities))

**Unpinned actions.** 493 repos reference GitHub Actions by mutable tag instead of SHA pin. A compromised action tag (like the [tj-actions/changed-files incident](https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-attack)) would execute in every affected workflow. ([finding details](security.md#medium-findings))

**No workflow review gates.** 1193 repos have no CODEOWNERS file. Any committer can modify workflow files — adding triggers, weakening permissions, or introducing injection patterns — without mandatory security review.

## Recommended Actions

1. **Migrate to trusted publishing this quarter.** Start with PyPI (easiest — `pypa/gh-action-pypi-publish` supports OIDC natively) then npm (`--provenance` flag). Eliminates the highest-value secrets from CI.

2. **Investigate HIGH findings in publishing repos.** The 2 repos above have HIGH-severity issues that need review.

3. **Audit composite action callers.** 6 publishing repos have composite actions that interpolate `inputs.*` in shell blocks. Verify no workflow passes untrusted values (PR title, branch name, comment body) to these actions.

4. **Pin actions to SHA in publishing repos first.** Use [StepSecurity/secure-repo](https://github.com/step-security/secure-repo) to bulk-pin actions. Prioritize the 197 repos that publish packages.

## Full Analysis

- [review.md](review.md) — combined risk assessment with attack scenarios
- [publishing.md](publishing.md) — which repos publish what, where, and how
- [security.md](security.md) — all 4610 security findings by repo
- [json-export.json](json-export.json) — machine-readable data ([query examples](README.md#jq-examples))
- [README.md](README.md) — report guide, JSON schema, jq commands

---

*634 repos scanned, 2387 workflows analyzed, 197 publish to registries, 4610 security findings.*