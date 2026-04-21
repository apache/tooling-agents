# Apache Tooling Agents

*Exploring AI-driven approaches to security auditing and code review*

<a href="https://github.com/apache/tooling-agents/blob/main/LICENSE">
  <img alt="Apache License" src="https://img.shields.io/github/license/apache/tooling-agents" /></a>

We're using this repository to discuss ideas, gather community input, and prototype approaches. Nothing here is production-ready yet.

## What This Is

This repository is a space for the Apache community to explore how AI agents might help with automated security auditing and code review. We're interested in questions like:

- How can agents help ASF projects achieve security and other compliance?
- What existing tools work well, and where are the gaps?
- What should we build versus adopt?

We're gathering input, prototyping ideas, and working toward tooling that could benefit the broader Apache ecosystem. **Your participation is welcome**, whether that's joining the discussion, sharing experiences, or contributing code.

## Projects

### [ASVS Security Audit](ASVS/)

Automated OWASP ASVS compliance auditing for any GitHub-hosted codebase. An orchestration pipeline downloads source code, discovers the codebase architecture, runs per-requirement security analysis, and produces a consolidated report with GitHub issues. See the [ASVS README](ASVS/README.md) for the full pipeline reference.

### [GitHub Actions Review](gha-review/)

Automated scan of GitHub Actions workflows across an organization to identify security vulnerabilities in CI/CD pipelines, find publishing channels, and flag policy violations. See the [GitHub Review README](gha-review/README.md) for agent details and check definitions.

## Repository Structure

```
├── ASVS/                  # ASVS security audit pipeline
│   ├── agents/            # Pipeline agent code (6 agents)
│   ├── audit_guidance/    # Project-specific false positive guidance
│   └── reports/           # Audit output organized by project and commit
├── gha-review/            # GitHub Actions security review
│   ├── agents/            # Review pipeline agents (7 agents + tests)
│   └── reports/           # Review output
├── docs/                  # Platform documentation
│   ├── gofannon/          # Gofannon setup and agent development guide
│   └── how-to-contribute.md
└── util/                  # Utility scripts
```

## Getting Involved

Community feedback is encouraged! Whether you're an ASF committer, contributor, or just interested in security tooling:

### Join the Conversation

1. **Introduce yourself on the mailing list**: Say hello at 📧 [dev@tooling.apache.org](mailto:dev@tooling.apache.org)
   *(Subscribe by sending an email with empty subject and body to [dev-subscribe@tooling.apache.org](mailto:dev-subscribe@tooling.apache.org) and replying to the automated response, per the [ASF mailing list how-to](https://apache.org/foundation/mailinglists.html))*

2. **Share ideas or file issues**: Use [GitHub Issues](https://github.com/apache/tooling-agents/issues) to ask questions, suggest approaches, or start a discussion

3. **Try things out**: Experiment with the tools we're evaluating and share what you learn

### Contribute Code or Docs

- [**How to contribute**](docs/how-to-contribute.md)
- **Documentation helps**: Add research notes or proposals to [`docs/`](docs/)
- **Evaluate tools**: Try existing tooling on your project and report back

**Note:** Please introduce yourself on the mailing list before submitting a PR; this helps us deter spam and means your contribution won't be overlooked.

## Community

- **Mailing List**: [dev@tooling.apache.org](mailto:dev@tooling.apache.org) ([subscribe](mailto:dev-subscribe@tooling.apache.org))
- **Slack**: `#tooling-discuss` on the [ASF Slack](https://the-asf.slack.com/archives/C086X8CKEMB)
- **Issues**: [GitHub Issues](https://github.com/apache/tooling-agents/issues)

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Related Work

- [Alpha-Omega Project](https://alpha-omega.dev): Improving OSS security
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/): The security standard we're targeting
- [OpenSSF Scorecard](https://securityscorecards.dev): Automated security health checks
- [VEX](https://github.com/vex-generation-toolset): Automated CVE detection
- [AI Alliance](https://thealliance.ai): Open AI innovation community
- [Gofannon](https://github.com/The-AI-Alliance/gofannon): Agent-building workflow

---

*Part of the [Apache Tooling Initiative](https://tooling.apache.org/).*
For more information about the ASF, visit [https://www.apache.org/](https://www.apache.org/).