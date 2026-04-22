# Audit Guidance

Project-specific context that helps the ASVS audit pipeline produce accurate results. Each project gets its own subdirectory with documents explaining architecture decisions, security controls, and known patterns that auditors — human or LLM — need to understand.

## Why This Exists

As we built and iterated on the ASVS audit pipeline, we learned that LLMs consistently misinterpret certain architectural patterns. Common examples:

- A Python app delegating authentication to an upstream reverse proxy gets flagged for "missing rate limiting" even though rate limiting is handled at the infrastructure layer.
- A JWT implementation using a non-standard claim format gets flagged as insecure when the format is intentional and documented.
- XML parsing that looks dangerous in isolation is safe because the input is pre-validated by an earlier stage.
- Session handling that appears to lack write protections actually uses a framework-specific pattern the LLM hasn't seen before.

These aren't bugs in the pipeline — they're places where an LLM lacks the project-specific context to make a correct judgment. Audit guidance documents provide that context.

## What Goes in These Documents

Each document should explain a specific architectural decision or security control, covering:

- What the pattern is and where it appears in the code
- Why it exists or why it's acceptable
- What the auditor should look for instead
- References to specific files or functions (using `/ref/path/to/file:function_name` format)

The goal is to give the LLM enough context to distinguish between a genuine finding and a false positive. Be specific — vague guidance like "authentication is handled correctly" doesn't help. Concrete guidance like "rate limiting is enforced by quart-rate-limiter in `server.py:_app_setup_rate_limits` at 100 req/min per key" does.

## Inline Source Comments

In addition to these documents, adding `# audit_guidance` comments directly above problem areas in source code helps the LLM understand intent at the point of analysis. For example:

```python
# audit_guidance: XML parsing here is safe because input is pre-validated
# by the archive extraction step which rejects non-UTF8 content.
tree = ET.parse(validated_path)
```

The combination of standalone guidance documents (loaded into the data store) and inline comments (visible when the LLM reads the source) catches most false positive patterns.

## Directory Structure

Each project should have its own subdirectory named to match the project's repo or identifier:

```
audit_guidance/
├── tooling-trusted-releases/     ← ATR guidance
│   ├── assorted-guidance.md
│   ├── authentication-security.md
│   └── authorization-security.md
├── steve/                        ← Apache Steve guidance (future)
│   └── ...
└── README.md                     ← this file
```

The orchestrator loads all guidance files for the target project into the data store before starting the audit. The audit agent includes them in its prompt context when analyzing each ASVS section.

## Current Guidance

The files at the top level of this directory are ATR (tooling-trusted-releases) guidance from the initial pilot. They should eventually be moved into a `tooling-trusted-releases/` subdirectory as more projects are onboarded.