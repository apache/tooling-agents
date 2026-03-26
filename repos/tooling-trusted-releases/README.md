# tooling-trusted-releases

Agent work targeting the [Apache Trusted Releases (ATR)](https://github.com/apache/tooling-trusted-releases) codebase.

ATR is a release management tool for verifying and distributing Apache releases securely. The Tooling team has adopted [ASVS v5.0.0](https://github.com/OWASP/ASVS) as the security standard, targeting L1 and L2 compliance for the beta release.

## Agent areas

| Area | Description | Status |
|------|-------------|--------|
| [ASVS](ASVS/) | Automated ASVS L1/L2 security audit pipeline | Active pilot |

## Target repositories

The audit pipeline analyzes code from multiple repositories that make up the ATR ecosystem:

- **apache/tooling-trusted-releases** — main ATR application (Quart/Python)
- **apache/infrastructure-asfquart** — ASF Quart framework library
- **apache/infrastructure-asfpy** — ASF Python utility library

All three are loaded into the Gofannon data store and analyzed together for each ASVS requirement.
