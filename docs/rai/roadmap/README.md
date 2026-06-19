# RAI Roadmap

A proposed architecture to support the Responsible AI Initiative: a governed way
for Apache projects to use language models, agents, and tools, with the catalog,
metrics, and routing intelligence to keep it accountable.

## The architecture

See [architecture.md](architecture.md) for the full description, and
[Foundational AI Tooling for the ASF](Foundational-AI-Tooling-for-the-ASF.md)
for a progress report on what Tooling has built toward this platform. 

In brief:

- **Clients** — the 200+ Apache projects and Foundation committees and operations that consume the platform.
- **Services** — `agents`, `mcp`, and the `llm` gateway that all model calls
  funnel through.
- **Models** — first-party, Bedrock, and ASF-hosted backends.
- **Advisor** — the catalog, metrics, and routing decisions that make the
  platform governed and observable.

![ASF AI platform architecture](architecture.svg)

The proposal leaves open the formation of project committees which could include **LLM gateway and model management**, **agent harnesses**, and **MCP server frameworks**, which map directly onto the `llm`, `agents`, and `mcp` boxes above, and a **cross-cutting governance layer** which maps onto the `advisor` box.

## Implementations

Early work already maps onto some of the boxes above:

- **`llm` gateway — [llmao / Hayward](https://github.com/andrewmusselman/llmao)** A thin litellm-proxy gateway fronted by asfquart: ASF identity, per-PMC budgets, a model catalog with governance metadata, and an OpenAI-compatible API. asfquart owns identity and per-PMC authorization; litellm owns the catalog, budgets, metering, and the API; the project is the seam between them plus a thin portal.
- **`agents` — [tooling-gofannon](https://github.com/apache/tooling-gofannon)**. A provider- and model-agnostic toolkit and web application for prototyping AI agents and the lightweight web UIs that wrap them, with model access through LiteLLM.

## Related

- [Foundational AI Tooling for the ASF](Foundational-AI-Tooling-for-the-ASF.md) — progress report on what Tooling has delivered and what's next.
- [../README.md](../README.md) — what RAI is.
- [../../platform/](../../platform/) — runbooks for the agent runtime and
  self-hosted model serving the architecture depends on.
- [../../security-pipeline/](../../security-pipeline/) — the security audit
  pipeline.