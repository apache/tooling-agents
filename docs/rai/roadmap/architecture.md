# Platform Architecture

A foundation-level platform that gives Apache projects governed access to language
models, agents, and tools. Projects are clients at the top; a **services** layer
handles their requests; an **advisor** layer underneath provides the catalog,
metrics, and routing intelligence that keeps the platform governed and observable.

## At a glance

![ASF AI platform architecture: Apache projects (clients) call the services layer of agents, mcp, and llm. llm routes to models — first-party, Bedrock, and ASF-hosted. Advisor holds catalog, metrics, and routing decisions, exchanging requests with services and consuming their logs.](architecture.svg)

Solid arrows are **requests** (and their responses); the dashed arrow is **log
consumption**.

## The layers

**Clients — Projects, Foundation committees and operations.** Every project and Foundation committee can consume this 
platform. They make requests into the services layer and get responses back. A
client can also reach `llm` directly when it just needs a model, without going
through agents or tools.

**Services — agents, mcp, and llm.** The request-handling layer:

- `agents` — agentic workflows a project runs. An agent can call tools (`mcp`)
  and can call models (`llm`) directly.
- `mcp` — Model Context Protocol tool/server management. Tool invocations that
  need a model call `llm` in turn.
- `llm` — the governed gateway for all model calls. Every path that touches a
  model funnels through here, which is what makes the platform meterable and
  governable.

Model traffic reaches `llm` several ways — from a client, from an agent, or via an
`mcp` tool — but it always ends at `llm` before reaching a model.

**Models — where llm sends calls.** The `llm` service routes outward to three
classes of backend:

- `first-party` — external provider APIs (OpenAI, Anthropic, and similar).
- `bedrock` — models served through AWS Bedrock.
- `asf-hosted` — open-weight models the foundation runs on its own infrastructure.

**Advisor — the governance and intelligence layer.** Sits beneath services and
provides three things:

- `catalog` — the registry of approved models with their licensing, openness, and
  provenance metadata.
- `metrics` — usage, cost, latency, and other observability data.
- `routing decisions` — the policy that informs which model a request should go to.

Advisor relates to services two ways: it **consumes logs** from the services layer
(the dashed edge) to populate metrics and inform routing, and it **answers
requests** from services (the solid two-way edge) — for example, `llm` reading the
catalog or asking for a routing decision.

## Why it's shaped this way

The platform separates **handling requests** (services) from **governing them**
(advisor). Services stay focused on doing the work; advisor owns the catalog,
metrics, and routing intelligence as a distinct concern. Because every model call
funnels through `llm`, the foundation gets one place to meter, govern, and route —
without forcing projects to change how they call agents or tools.

This is also why the platform stays **vendor-neutral**: the `llm` gateway and the
`models` layer behind it mean no single provider is load-bearing, and projects
keep their freedom to choose.
