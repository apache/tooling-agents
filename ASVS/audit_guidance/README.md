# Audit Guidance

Project-specific context that helps the ASVS audit pipeline produce accurate results. Each project provides guidance documents explaining architecture decisions, security controls, and known patterns that auditors — human or LLM — need to understand.

## Why This Exists

As we built and iterated on the ASVS audit pipeline, we learned that LLMs consistently misinterpret certain architectural patterns. Common examples:

- A Python app delegating authentication to an upstream reverse proxy gets flagged for "missing rate limiting" even though rate limiting is handled at the infrastructure layer.
- A JWT implementation using a non-standard claim format gets flagged as insecure when the format is intentional and documented.
- XML parsing that looks dangerous in isolation is safe because the input is pre-validated by an earlier stage.
- Session handling that appears to lack write protections actually uses a framework-specific pattern the LLM hasn't seen before.

These aren't bugs in the pipeline — they're places where an LLM lacks the project-specific context to make a correct judgment. Audit guidance documents provide that context.

## File Format

Guidance files should be **markdown** (`.md`). Markdown is the best format here for several reasons: LLMs are heavily trained on it and parse its structure (headings, lists, code blocks, links) reliably; humans can read and review it without tooling; it diffs cleanly in pull requests; and the audit pipeline already handles it natively. Use plain prose with headings and bullets — no special schema or front-matter required.

## What Goes in These Documents

Each document should explain a specific architectural decision or security control, covering:

- What the pattern is and where it appears in the code
- Why it exists or why it's acceptable
- What the auditor should look for instead
- References to specific files or functions (using `/ref/path/to/file:function_name` format)

The goal is to give the LLM enough context to distinguish between a genuine finding and a false positive. Be specific — vague guidance like "authentication is handled correctly" doesn't help. Concrete guidance like "rate limiting is enforced by quart-rate-limiter in `server.py:_app_setup_rate_limits` at 100 req/min per key" does.

## Where Guidance Can Live

Four places, each suited to different content. Projects can use any combination of them; the audit pipeline merges all available sources at run time.

### `AUDIT_GUIDANCE.md` in the project's repo

Sits alongside `AGENTS.md` at the repo root. Travels with the code in the same git history, gets reviewed in the same PRs, evolves at the same pace as the codebase it describes — no drift between what the guidance says and what the code does. The audit pipeline picks it up when it clones the target repo.

### `tooling-agents/ASVS/audit_guidance/<project>/`

Hosted here in tooling-agents. The directory layout below (`audit_guidance/tooling-trusted-releases/`, etc.) is exactly this case. Useful when guidance is being iterated on jointly with the Tooling team, when a project hasn't adopted `AUDIT_GUIDANCE.md` yet, or when one team's audit-relevant context spans multiple project repos.

A project can use both repo-hosted and tooling-agents-hosted guidance simultaneously. Common pattern: the project owns `AUDIT_GUIDANCE.md` for architecture-level context that changes as the code changes; Tooling maintains additional files under `audit_guidance/<project>/` for cross-project security patterns or while a project ramps up on the convention.

### Private guidance via `supplementalData` namespaces

For content that can't be published — guidance detailed enough about authentication, authorization, key-handling, or threat-model internals that disclosure would weaken the protection it describes. The audit pipeline accepts a `supplementalData` parameter listing CouchDB namespaces; content in those namespaces is loaded alongside the public guidance.

Trusted Releases uses this today: sensitive auth/authz guidance lives in a private repo, an ingestion step loads it into a private CouchDB namespace under the appropriate scope, and audit runs that need it pass `supplementalData: ["<namespace>"]`. Findings can reference the guidance without leaking it; the report cites "guidance namespace X says…" rather than reproducing the content.

Default to public. Most architectural context — even most security-relevant context — is safe to publish, and publishing it gets you the lifecycle benefits. Private guidance is for the narrow band where disclosure itself is the risk.

### Inline `# audit_guidance` comments in source files

For point-of-use clarification — when the right place to explain a pattern is right next to the code that does it. Auditors see the comment when they read the source, no separate document needed.

```python
# audit_guidance: XML parsing here is safe because input is pre-validated
# by the archive extraction step which rejects non-UTF8 content.
tree = ET.parse(validated_path)
```

Best for narrow, local context (one function, one block). Standalone guidance docs are better for cross-cutting architectural decisions that span many files. The two work well together: standalone docs cover the architecture; inline comments catch the specific spots where an auditor needs the context to reach the code under analysis.

## Directory Structure

When guidance is hosted here in tooling-agents, each project gets its own subdirectory named to match the project's repo or identifier:

```
audit_guidance/
├── tooling-trusted-releases/                    ← ATR guidance
│   ├── assorted-guidance.md
│   ┊── ~~authentication-security.md~~          ← held in private guidance
│   ┊── ~~authorization-security.md~~           ← held in private guidance
├── steve/                                       ← Apache Steve guidance (future)
│   └── ...
└── README.md                                    ← this file
```

The dotted hyphens (`┊──`) and strikethrough on the auth/authz files indicate that those files exist but live in a private CouchDB namespace rather than the public tree, loaded into the audit at run time via `supplementalData`. The placeholders stay listed here so anyone reading the directory knows the guidance exists and where to find it.

The orchestrator loads all available guidance for the target project — from any of the four sources above — into the data store before starting the audit. The audit agent includes the merged guidance in its prompt context when analyzing each ASVS section.
