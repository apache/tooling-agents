# Apache Tooling Agents

*AI-driven security auditing and code review for ASF projects*

<a href="https://github.com/apache/tooling-agents/blob/main/LICENSE">
  <img alt="Apache License" src="https://img.shields.io/github/license/apache/tooling-agents" /></a>

## Pipelines

### [ASVS Security Audit](ASVS/)

Automated [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) compliance auditing for any GitHub-hosted codebase. Downloads source code, discovers the architecture, runs per-requirement security analysis with Claude, and produces a consolidated report with deduplicated findings and GitHub issues. In production — piloted on ATR and Apache Steve.

### [GitHub Actions Review](gha-review/)

Automated security scan of GitHub Actions workflows across an entire GitHub organization. Combines LLM classification (which repos publish what, where) with static pattern matching (12 check types from CRITICAL to INFO) to identify exploitable workflows, supply chain risks, and policy violations. Scanned 2,500+ Apache repos.

Both pipelines run on [Gofannon](https://github.com/The-AI-Alliance/gofannon) — see [docs/gofannon](docs/gofannon/) for platform setup.

## Repository Structure

```
├── ASVS/                  # ASVS security audit pipeline
│   ├── agents/            # Pipeline agent code (6 agents)
│   ├── audit_guidance/    # Project-specific false positive guidance
│   ├── reports/           # Audit output organized by project and commit
│   └── rerun-sections.sh  # QA: re-run failed sections, re-consolidate
├── gha-review/            # GitHub Actions security review
│   ├── agents/            # Review pipeline agents (7 agents + tests)
│   └── reports/           # Review output
├── docs/
│   ├── gofannon/          # Gofannon setup and agent development guide
│   ├── tooling/           # Security tooling landscape and comparisons
│   ├── roadmap/           # Eval framework, multi-spec expansion plans
│   └── how-to-contribute.md
└── util/                  # Utility scripts
```

## Documentation

- **[ASVS Pipeline Reference](ASVS/README.md)** — inputs, agent reference, QA and remediation, troubleshooting
- **[GHA Review Reference](gha-review/README.md)** — agent architecture, check types, report guide
- **[Security Tooling Landscape](docs/tooling/)** — comparison with Scorecard, OSS-CRS, Strix, zizmor, and others
- **[Roadmap](docs/roadmap/)** — eval framework, ASVS applicability, multi-spec expansion (CWE Top 25, API Top 10, ASF Baseline, SLSA)

## Getting Involved

### Join the Conversation

1. **Mailing list**: Say hello at 📧 [dev@tooling.apache.org](mailto:dev@tooling.apache.org)
   *(Subscribe by sending an email with empty subject and body to [dev-subscribe@tooling.apache.org](mailto:dev-subscribe@tooling.apache.org) and replying to the automated response, per the [ASF mailing list how-to](https://apache.org/foundation/mailinglists.html))*

2. **Slack**: `#tooling-discuss` on the [ASF Slack](https://the-asf.slack.com/archives/C086X8CKEMB)

3. **Issues**: Use [GitHub Issues](https://github.com/apache/tooling-agents/issues) to ask questions, suggest approaches, or report bugs

### Contribute

- [**How to contribute**](docs/how-to-contribute.md)
- **Request an audit**: Just ask on the mailing list or Slack — we handle everything. No tokens, no setup needed.
- **Write audit guidance**: Help reduce false positives for your project — see [audit_guidance/README.md](ASVS/audit_guidance/README.md)

**Note:** Please introduce yourself on the mailing list before submitting a PR; this helps us deter spam and means your contribution won't be overlooked.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

---

*Part of the [Apache Tooling Initiative](https://tooling.apache.org/).*