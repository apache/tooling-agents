# Apache Tooling Agents

*Exploring AI-driven approaches to security auditing and code review*

<a href="https://github.com/apache/tooling-agents/blob/main/LICENSE">
  <img alt="Apache License" src="https://img.shields.io/github/license/apache/tooling-agents" /></a>

We're using this repository to discuss ideas, gather community input, and prototype approaches. Nothing here is production-ready yet.

## What This Is

This repository is a space for the Apache community to explore how AI agents might help with automated security auditing and code review. We're interested in questions like:

- How can agents help ASF projects achieve [OWASP ASVS](https://owasp.org/ASVS/) compliance?
- What existing tools work well, and where are the gaps?
- What should we build versus adopt?

We're gathering input, prototyping ideas, and working toward tooling that could benefit the broader Apache ecosystem. **Your participation is welcome**, whether that's joining the discussion, sharing experiences, or contributing code.

## Areas of Interest

We're currently exploring several directions:

- **ASVS Compliance Automation**: Can agents help verify security requirements across codebases?
- **Reducing Manual Overhead**: How do we help teams maintain security without slowing development?
- **Actionable Guidance**: What does useful, prioritized remediation output look like?
- **Reusable Patterns**: What can we build once that benefits many ASF projects?

## What We're Evaluating

### Existing Tooling

These are already available and we're assessing how well they fit our needs:

- **GitHub Security Features**: Dependabot, code scanning, secret scanning (already in use across ASF)
- **[OpenSSF Scorecard](https://securityscorecards.dev)**: Security health checks via CLI or GitHub Actions
- **[Alpha-Omega VEX](https://github.com/vex-generation-toolset)**: Agent-driven CVE analysis with call graphs (in pilot with Apache Solr)
- **[AI Alliance Gofannon](https://github.com/The-AI-Alliance/gofannon)**: Agent builder for prototyping workflows

### Ideas Under Discussion

- Automated ASVS L1/L2 compliance verification
- Commit-level security review with agent assistance
- Prompt-based audit workflow configuration
- Integration patterns for CI/CD pipelines

## ASVS Background

We're using [ASVS v5.0.0](https://owasp.org/ASVS/) as our reference standard, organized into categories like:

| Category | Focus Area |
|----------|------------|
| Server-Side Execution | Input validation, injection prevention |
| Cross-Site Scripting | Output encoding, DOM security |
| Weak Cryptography | Algorithm selection, key management |
| External Access | Network security, API protection |
| Credential Security | Authentication, session management |
| Denial of Service | Resource limits, rate limiting |

See [`docs/ASVS/`](docs/ASVS/) for our compliance tracking, research notes, and issue templates.

## Repository Structure

```
├── src/           # Prototypes and experimental implementations
├── docs/          # Research, proposals, and planning
│   └── ASVS/      # ASVS compliance tracking and analysis
├── util/          # Utility scripts for evaluation
└── examples/      # Sample configurations and workflows
```

## Getting Involved

Community feedback is encouraged! Whether you're an ASF committer, contributor, or just interested in security tooling:

### Join the Conversation

1. **Introduce yourself on the mailing list**: Say hello at 📧 [dev@tooling.apache.org](mailto:dev@tooling.apache.org
   *(Subscribe by sending an email with empty subject and body to [dev-subscribe@tooling.apache.org](mailto:dev-subscribe@tooling.apache.org) and replying to the automated response, per the [ASF mailing list how-to](https://apache.org/foundation/mailinglists.html))*

2. **Share ideas or file issues**: Use [GitHub Issues](https://github.com/apache/tooling-agents/issues) to ask questions, suggest approaches, or start a discussion

3. **Try things out**: Experiment with the tools we're evaluating and share what you learn

### Contribute Code or Docs

- [**How to contribute**](docs/how-to-contribute.md)
- **Prototypes welcome**: Experimental code in [`src/`](src/) doesn't need to be polished
- **Documentation helps**: Add research notes or proposals to [`docs/`](docs/)
- **Evaluate tools**: Try existing tooling on your project and report back

**Note:** Please introduce yourself on the mailing list before submitting a PR; this helps us deter spam and means your contribution won't be overlooked.

## Rough Roadmap

This is tentative and will evolve based on community input.

### Now: Research, Discussion, and Prototyping
- Gathering requirements and use cases
- Evaluating existing tools
- Identifying gaps and opportunities
- Experiment with agent-based approaches
- Build proof-of-concept integrations
- Test with real ASF codebases

### Next: Pilot & Iteration
- Trial with Apache Trusted Releases (ATR) and other willing projects
- Gather feedback and refine
- Determine what's worth building out further

## Community

- **Mailing List**: [dev@tooling.apache.org](mailto:dev@tooling.apache.org) ([subscribe](mailto:dev-subscribe@tooling.apache.org))
- **Slack**: `#tooling-discuss` on the [ASF Slack](https://the-asf.slack.com/archives/C086X8CKEMB)
- **Issues**: [GitHub Issues](https://github.com/apache/tooling-agents/issues)

## License

This project is licensed under the [Apache License 2.0](LICENSE).

## Related Work

- [Alpha-Omega Project](https://alpha-omega.dev): Improving OSS security
- [OWASP ASVS](https://owasp.org/ASVS/): The security standard we're targeting
- [OpenSSF Scorecard](https://securityscorecards.dev): Automated security health checks
- [VEX](https://github.com/vex-generation-toolset): Automated CVE detection
- [AI Alliance](https://thealliance.ai): Open AI innovation community
- [Gofannon](https://github.com/The-AI-Alliance/gofannon): Agent-building workflow

---

*Part of the [Apache Tooling Initiative](https://tooling.apache.org/).*
For more information about the ASF, visit [https://www.apache.org/](https://www.apache.org/).
