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
- References to specific files or functions, written as standard markdown links (e.g. `[\`server.py\`](server.py)` or `[\`_app_setup_rate_limits\`](server.py#L42)`) so they survive refactors and the rest of the agent ecosystem can follow them

The goal is to give the LLM enough context to distinguish between a genuine finding and a false positive. Be specific — vague guidance like "authentication is handled correctly" doesn't help. Concrete guidance like "rate limiting is enforced by quart-rate-limiter in [`server.py`](server.py) at 100 req/min per key" does.

## Where Guidance Can Live

Five places, each suited to different content. Projects can use any combination of them; the audit pipeline merges all available sources at run time.

### `AGENTS.md` in the project's repo

The portable, agent-ecosystem-standard location. Every modern agentic scanner reads `AGENTS.md`, so security context placed there serves more than just this audit pipeline — code-review agents, refactor agents, doc agents all benefit from the same description of the project's security model.

The audit pipeline reads `AGENTS.md` from the cloned repo's root and looks for security-relevant context. Airflow's `AGENTS.md` is a good model: a "Security Model" section that distinguishes actual vulnerabilities, known limitations, and deployment hardening opportunities, with pointers to the authoritative security docs in the project. The audit pipeline picks up that section without the project having to maintain a separate ASVS-specific file.

A project can also use `AGENTS.md` as a pointer rather than a container — referencing where the real security documentation lives and letting the auditor follow the link. Either way, `AGENTS.md` is checked first.

### `AUDIT_GUIDANCE.md` in the project's repo

When the project wants a dedicated, audit-targeted file alongside `AGENTS.md`. Useful when the security context is large enough or specific enough that mixing it into `AGENTS.md` would crowd the rest of the agent guidance out, or when ASVS-specific content (like "this project supports L1 but not L3") doesn't naturally belong in a general agents file.

Same lifecycle benefits as `AGENTS.md`: travels with the code, reviewed in PRs, evolves with the codebase. Picked up automatically when the audit pipeline clones the repo.

### `tooling-agents/ASVS/audit_guidance/<project>/`

Hosted here in tooling-agents. Useful when guidance is being iterated on jointly with the Tooling team, when a project hasn't published its own guidance yet, or when one team's audit-relevant context spans multiple project repos. The Tooling team owns updates here, so projects don't have to take a PR every time the auditor's guidance shifts.

The directory layout below (`audit_guidance/tooling-trusted-releases/`, etc.) is exactly this case. A project can use both repo-hosted and tooling-agents-hosted guidance simultaneously: the project owns its `AGENTS.md` / `AUDIT_GUIDANCE.md` for stable architecture context; Tooling maintains additional files under `audit_guidance/<project>/` for iterations that don't warrant a project PR each time.

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

## Picking a Source

`AGENTS.md` should usually come first — it's portable across the agent ecosystem, it's already where the project documents its broader agent contract, and projects shouldn't have to maintain a separate file just for ASVS. Treat ASVS-specific notes inside `AGENTS.md` (level support, scanner-specific carve-outs) as a recognized convention rather than a separate file unless they grow large enough to crowd out the rest.

When `AGENTS.md` would get crowded or the project prefers separation, `AUDIT_GUIDANCE.md` next to it works equally well — same lifecycle, just a different file.

`tooling-agents/ASVS/audit_guidance/<project>/` is for the cases where Tooling owns the iteration. Projects that don't want to take a PR every time the auditor's interpretation shifts can let Tooling maintain the file here, with the understanding that those updates won't show up to other agents reading the project repo.

`supplementalData` namespaces handle the sensitive content. Inline comments handle the local spots.

The pipeline merges all available sources, so these choices aren't exclusive — a project might have a Security Model section in `AGENTS.md`, a private namespace for auth/authz internals, and a few inline comments at known false-positive spots. All flow into the same audit context.

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

The orchestrator loads all available guidance for the target project — from any of the five sources above — into the data store before starting the audit. The audit agent includes the merged guidance in its prompt context when analyzing each ASVS section.
