# Foundational AI Tooling for the ASF

*A progress report on the governed AI platform Tooling is building — and what it already does for Apache projects today.*

Prepared for the Responsible AI Initiative · **Apache Tooling**

---

## Executive Summary

### One layer to log into, for the whole Foundation

Apache projects are adopting AI the way the rest of the world is: quickly, unevenly, and with everyone wiring up their own accounts, keys, and budgets. That works for one project but falls apart at Apache scale. This report describes what Apache Tooling is building to replace that with a single, governed, self-serve layer, shows what is already in use, and indicates what to build next.

| | | |
|:--:|:--:|:--:|
| **20** | **2,500+** | **4,912** |
| projects given ASVS security audits, with capacity to run dozens per day | Apache repos scanned for CI/CD supply-chain risk | workflows analyzed for runner waste across 1,216 repos |

The platform has four parts, each mapping to a real need: **agents** (Gofannon) so subject-matter experts build their own tools without standing up infrastructure; an **LLM gateway** (llmao) so projects share governed model access instead of personal keys; **MCP** tool federation so those agents reach real systems safely; and an **advisor** layer so the Foundation can see and steer cost, quality, and routing. Two of the four are already in users' hands.

> **The through-line**
> 
> Today the security pipeline runs on AWS Bedrock credits and hand-managed keys. As llmao matures, the same pipeline points at the gateway instead, getting model choice and per-project token budgeting for free, and proving out half of the platform.

---

## Section 1 — ASF Foundation Needs

Before describing tools, it is worth being precise about the problems they exist to solve. These are Foundation-level needs — they show up across projects, and no single project can solve them alone.

**Access without chaos.** AI models cost money and require credentials. Left to itself, every project signs up for its own provider accounts, holds its own API keys, and pays its own way — or more commonly, can't, and goes without. There is no shared catalog of what's approved, no view of what's being spent, and no way for the Foundation to extend a donated pool of credits across projects fairly. The need is *sanctioned, metered, shared access*: one place a committer logs into with their Apache identity and uses approved models, with cost attributed to their project.

**Leverage without headcount.** Most projects don't have someone to build AI tooling. They have domain experts — the people who know the codebase, the release process, the security posture — who could describe exactly what an assistant should do but can't stand up an agent framework to do it. The need is a way for *subject-matter experts to compose tools themselves*, preview them, and put them to work, without committing to a framework or running servers.

**Safety at the supply chain.** Apache ships software the world depends on. That makes its CI/CD pipelines, its release workflows, and its source code high-value targets. Projects are swamped, and the volume of low-quality AI-generated contributions and supply-chain attacks is rising. The need is *continuous, automated assessment* — security audits, workflow review, provenance checking — that scales to hundreds of projects without hundreds of security engineers.

**Privacy and PII as a first-class concern.** Much of what the Foundation might want AI help with — private mailing lists, security coordination, membership discussions — carries personally identifiable information. Feeding that to a hosted model whose provider may log or retain prompts is materially different from a human reading the same archive. The need is a *data-handling story*: the ability to keep sensitive content on models the Foundation controls, and to make that choice explicitly rather than by accident.

**Stewardship the Board can defend.** A multi-year, multi-million-dollar AI commitment needs accountable numbers: what was spent, on what, with what result. The need is an *observability and governance layer* that tracks delivery against spend, holds the catalog of what's approved, and keeps the whole thing vendor-neutral so no single provider becomes load-bearing.

---

## Section 2 — Current Situation Report

What exists today, in use or in active development. These pipelines have run against real Apache code and produced real findings.

### ASVS Security Audit Pipeline — `In use`

The pipeline takes any GitHub-hosted codebase, downloads the source, auto-discovers its architecture, runs per-requirement security analysis against **OWASP ASVS v5.0.0** with Claude, triages findings against the project's own security policies to cut false positives, and produces a consolidated report with deduplicated findings and ready-to-file GitHub issues. Critical findings are redacted from public reports and emailed privately to the PMC; a leak-check quarantines anything that would expose a vulnerability before publication.

It has produced full audits for **20 projects** so far — Airflow, Superset, Mina, Mahout, Steve, asfquart, log4net, trusted-releases, and others — several across multiple components and commits, with **capacity to run dozens per day**. It is being piloted broadly and rolled out across all projects.

> **Real output — Apache Superset, ASVS L3**
> 
> 26 findings from 345 per-requirement source reports; 12 turned into actionable issues. Top risks included plaintext credentials written to a log file, a bypassable regex SVG sanitizer permitting stored XSS, a missing zip-bomb guard on Parquet uploads, and password change without current-password re-verification. Zero criticals, one high — the kind of grounded, specific result a PMC can act on the same day.

Today the pipeline is **funded out of AWS Bedrock credits** with hand-managed model access. As llmao matures it will draw model choice and per-project token budgeting from the gateway instead — making it the gateway's first internal customer and removing the last piece of bespoke credential handling.

### GitHub Actions Security Review — `Delivered and in review`

This pipeline scans every `.github/` workflow across an entire GitHub organization, caches the YAML, and runs two passes: an LLM classifier that labels each workflow (release, snapshot, CI, docs) and identifies which repos publish what and where, and a static analyzer that pattern-matches **12 security checks** from CRITICAL to INFO — `pull_request_target` checkout of PR head, script injection in `run` blocks, over-broad `GITHUB_TOKEN` permissions, unpinned actions, composite-action injection, and more.

> **Real output — the Apache org scan**
> 
> 634 repositories assessed; **197 publish packages** to npm, PyPI, Maven Central, Docker Hub, and crates.io. Found 2 publishing repos with high-severity findings, 6 with latent composite-action injection risk, 79 still using long-lived secrets where OIDC trusted publishing is available, 493 referencing actions by mutable tag instead of SHA pin, and 1,193 with no CODEOWNERS gate on workflow changes. Each finding is specific and tied to an action a PMC or Infra can take.

### GitHub Actions Runner Usage Analysis — `Delivered and in review`

A cost-and-waste companion to the security review: it analyzes runner usage across the org to find workflows burning CI minutes on redundant matrix combinations, missing concurrency controls, and inefficient triggers. Donated CI capacity is finite; this is how the Foundation finds where it's being wasted.

> **Real output — runner analysis**
> 
> 4,912 workflows across 1,216 repositories analyzed; 5,220 efficiency issues detected. The heaviest consumers — Beam, Spark, and others with hundreds of workflows and large matrix expansions — are ranked by estimated runner waste so Infra can target the highest-impact fixes first.

### GitHub Issue Triage Agent (gh-helper) — `Experiment in development`

A Gofannon agent that reads a repository's open issues, builds a structured map of the codebase, and posts per-issue triage comments that **cite real code with line ranges**, propose grounded patches, and flag stale issues for closure. It grounds every citation against the actual source — replacing the model's claimed line numbers with real ones and dropping hallucinated citations entirely — and it reads prior human discussion on the issue so it reflects decisions the team has already made rather than re-proposing them. This is the "read-and-comment" iteration; the next opens PRs.

---

## Section 3 — Gap Analysis

Mapping what exists against what the Foundation needs makes the gaps precise and shows they are concentrated in two of the four platform layers.

| Need | What exists | Gap |
|---|---|---|
| **Expert-built tooling** | Gofannon: agents, web UIs, multi-provider. In use for the pipelines below. | Breadth of use cases; a shared library of reusable skills and agent definitions. |
| **Shared, metered model access** | llmao proof of concept: gateway, per-PMC budgets, catalog, metering, OpenAI-compatible API. | Hardening to production at `llm.apache.org`; real ASF OAuth wiring; migrating the security pipeline onto it. |
| **Safe tool federation** | Early MCP servers from ComDev and the Incubator (see Section 5). | **MCP management layer.** Federation, registry, and governance over many servers. |
| **Privacy / PII handling** | Self-hosted and Bedrock options identified; vast.ai PoC underway (Section 4). | A settled data-handling policy and a controlled-model path wired into the gateway. |
| **Cost & quality stewardship** | Per-project budgets in llmao; run telemetry in the pipelines. | **Advisor layer.** Foundation-wide catalog, metrics, routing, and defensible eval numbers. |
| **Continuous security assessment** | ASVS audit, GHA review, runner analysis: all delivered. | Rollout to all projects (underway); more specs; eval infrastructure to defend the numbers. |

The **application work is furthest along** (security pipelines delivered, agents in use), the **gateway is a working proof of concept**, and the open layers are **MCP management** and the **advisor**.

---

## Section 4 — The Foundational Layer: Four Pieces

These four components are the substrate. Together they replace personal accounts and scattered token usage with one layer the whole Foundation logs into and manages its AI needs through, self-serve for projects, governable for the Foundation.

![ASF AI platform architecture](architecture.svg)

*The platform: Apache projects and the Foundation as clients; agents, mcp, and the llm gateway as services; first-party, Bedrock, and ASF-hosted models behind the gateway; and advisor providing catalog, metrics, and routing. Bold borders mark the pieces already in use.*

### agents — the workbench · *Gofannon · in use*

A provider- and model-agnostic toolkit and web application for prototyping AI agents and the lightweight web UIs that wrap them, with an API layer callable by other systems. Subject-matter experts compose tools, data sources, and decision paths through a guided interface, preview agent behavior in real time, and hand off working agent-driven experiences without committing to a single framework or provider. Every pipeline in Section 2 runs on it.

### llm — the gateway · *llmao / Hayward · in proof of concept*

The chokepoint every model call funnels through. A thin gateway that pairs **asfquart** (ASF identity and per-PMC authorization) with the **litellm proxy** (catalog, budgets, metering, OpenAI-compatible API). The only bespoke code is the seam mapping an ASF project to a billing team. Everything else is delegated to systems that already do it well.

A committer signs in with their Apache identity, picks an approved model, and makes a call that's metered and billed to their project. The model catalog carries governance metadata: license, openness, weights provenance; so the choice is informed. It speaks the OpenAI API, so existing clients work by changing one URL.

### mcp — tool federation · *build-or-adopt decision open*

The layer that lets agents reach real systems — issue trackers, mailing-list archives, release metadata — through the Model Context Protocol, safely and with governance. This is in concept mode, but it is not starting from nothing: ComDev and the Incubator have already shipped working MCP servers (see Section 5). The open question is how to manage many such servers under one governed, discoverable layer: the same build-thin-versus-adopt question llmao already answered for the gateway.

### advisor — governance & intelligence · *in design*

The layer that makes the platform accountable: the catalog of approved models and their metadata, the metrics on usage and cost and latency, and routing decisions that pick models by policy, cost, and capability. Per-project budgets and run telemetry already exist; the advisor unifies them into a Foundation-wide view the Board can act on, and underwrites quality claims with defensible eval numbers.

---

## Section 4a — Models and the Privacy Question

The gateway is deliberately agnostic about where a model runs. That is not just flexibility for its own sake; it is how the Foundation answers the privacy and PII question on its own terms. The `models` layer behind the gateway has three classes, and the difference between them is a data-handling decision as much as a capability one.

**First-party providers.** The hosted frontier models (OpenAI, Anthropic, and others) reached directly through their APIs. Best raw capability, but prompts leave ASF control and may be logged or retained by the provider. Appropriate for public code and non-sensitive work; the wrong choice for internal, Member/Committee/Board-private content.

**AWS Bedrock.** Frontier models served through AWS Bedrock, where the data-handling terms differ from the consumer APIs and prompts are not used to train provider models. This is what funds and runs the security pipeline today, and it is a meaningfully safer home for sensitive content than the first-party consumer APIs, a candidate **safe data layer** for work that touches private material.

**ASF-hosted models.** Open-weight models the Foundation runs on its own rented infrastructure, where prompts never leave a controlled environment at all. We are running a **proof of concept on vast.ai**, standing up open-weight models on rented GPUs and exercising them through the gateway as another set of models to call, alongside Bedrock and the first-party providers. For the most sensitive content including private list summarization and private committee discussions, a model the Foundation hosts itself is the strongest privacy posture available, and the experiment is about proving that path is practical.

> **Cost, speed, and quality**
> 
> Model choice at Apache scale, especially with the varied workloads and volume of calls needed, is a challenge answered by this Foundational layer. Gofannon out of the box allows agents to make calls to all of these categories of providers, and llmao shares the same agnostic stance toward providers, including ASF-hosted models, enabling the Foundation to guide a balance of the right tool for every job, governing cost and monitoring speed and quality performance.   

---

## Section 5 — What Projects Can Build: Agent Use Cases

The security pipelines are the first agents, not the only ones. Once a project has the workbench and the gateway, the question becomes: what would a maintainer actually want an assistant to do? These are the kinds of questions agents answer well.

> **"A vulnerability just dropped in a dependency. Which of our repos are exposed, and where?"**  
> A dependency-triage agent maps the advisory to the project's actual usage, citing the files and call sites, instead of a maintainer grepping by hand across a monorepo.

> **"We have 400 stale issues. Which are still real, which are duplicates, and which can close?"**  
> Exactly what gh-helper does today: grounded per-issue triage with code citations, duplicate clustering, and staleness assessment, reflecting decisions already made in the thread.

> **"Is this incoming PR a genuine contribution or low-quality AI slop?"**  
> A contribution-quality agent assesses whether a PR addresses its stated issue, follows project conventions, and contains real changes: the rising-volume problem the RAI initiative names directly.

> **"Summarize what happened on our private security list this month."**  
> A sanctioned summarization agent gives a PMC a digest of private mailing-list activity, controlling access through ASF identity, routed to a privacy-appropriate model, and metered.

> **"Does this incubating podling's release meet license and provenance requirements?"**  
> A provenance-and-license agent checks an incubator release against ASF policy, clearance work that today consumes scarce IPMC attention.

> **"Our CI is slow and expensive. What should we fix first?"**  
> The runner analysis already does this at org scale; a per-project agent turns it into specific, ranked workflow edits a maintainer can apply.

The common thread: each is a question a domain expert can *state* precisely but couldn't previously *automate* without infrastructure. The workbench plus the gateway closes that gap.

---

## Section 6 — What MCP Federation Unlocks: Tool Server Use Cases

If agents are the workers, MCP servers are the governed connections that let an agent reach real systems. A management layer over many such servers is what turns one-off integrations into a catalog any project can draw on. ComDev and the Incubator have already built servers worth federating.

**Already built, by the community:**

> **ComDev — PonyMail MCP**  
> A server exposing the Apache PonyMail mailing-list archive: search lists, fetch threads, and export mbox, with ASF OAuth for private lists and, notably, a **built-in privacy guard** that blocks private and security lists by default so an LLM can't accidentally ingest private data. Exactly the data-handling instinct the platform needs, already expressed in a tool.

> **Incubator — IPMC MCP**  
> A server composing podling lifecycle, health, report, mail, release, and trademark signals into oversight tools: which podlings need attention, where reporting gaps are, whether a release's artifacts and votes check out, graduation readiness. It keeps source facts separate from derived opinion, with an explainability object so an IPMC member can challenge any judgment.

**What a management layer would unlock:**

> **"Across every ASF system, what does this agent need — and what is it allowed to touch?"**  
> A registry and governance layer means an agent declares the tools it needs and the Foundation controls which servers, lists, and repos it can actually reach — one place to grant and audit, instead of per-agent credentials.

> **"Give my project the same mail, release, and trademark tools the Incubator built, without re-implementing them."**  
> Federation means a server built by one community is discoverable and reusable by all; the IPMC's release-evidence tooling becomes available to any PMC checking its own releases.

> **"Make sure no tool server can leak private content to a hosted model."**  
> A governed layer enforces the PonyMail privacy instinct everywhere: private-by-default blocks, and routing that pairs sensitive tools with ASF-hosted models.

---

## Section 7 — Future Work

Where the effort goes next, across the open layers and the projects that grow out of this foundation.

### MCP management — `In design`

The federation and governance layer over the MCP servers the community is already producing. ComDev's PonyMail server and the Incubator's IPMC server prove the demand and the pattern; the work is a registry, discovery, and governance layer that manages many servers under one controlled, auditable surface, with the same build-thin instinct that shaped llmao.

### Advisor — `In design`

Unify the existing per-project budgets and run telemetry into a Foundation-wide catalog, metrics surface, and policy-driven routing, including the privacy routing described in Section 4a. This is the layer that lets the Board see delivery against spend and lets the platform make the safe model choice automatically.

### Touchstone — eval & operational QA — `Potential TLP`

The measurement layer that makes AI-pipeline numbers defensible: fixtures, a scoring harness, LLM-as-judge for semantic comparison, regression detection, error classification, automated issue-filing, and run telemetry. Conceived inside the security pipeline, it is generic with respect to *what* it measures, which is the argument for it being its own project. Foundation-credible claims like "false-positive rate dropped from 18% to 12%" require the eval code to be reviewed and operated independently of the pipeline it grades.

### Magpie — a skills & agents library — `New TLP`

A library of reusable skills and `agents.md` definitions that projects can pick up and adapt so a good triage agent or release-checker built by one project becomes a starting point for all of them. The workbench lets experts build; Magpie lets them share.

### Continued agent use cases — `Ongoing`

The agents in Section 5 are a backlog, not a wishlist. gh-helper's next iteration opens PRs rather than just commenting. Contribution-quality assessment, dependency triage, sanctioned summarization, and incubator provenance checking each become their own agent on the shared substrate — every one metered through the gateway and measured through the advisor.

> **On TLP work product and contributions**
> 
> Touchstone, Magpie, and the community MCP servers are or will be their own top-level projects, and a great deal of their work product can flow into Tooling's solutions: eval harnesses, shared skills, federated tool servers. Tooling welcomes these contributions and intends to build on them. But the foundational layer cannot be *dependent* on any single TLP's roadmap or release cadence: the gateway, the workbench, and the assessment pipelines have to stand on their own, with TLP work product adopted where it strengthens them rather than load-bearing beneath them.

---

> **The shape of it**
> 
> Foundation-managed access and assessment from above; self-serve tool-building in the middle; a shared library and grass-roots agents below. One identity, one governed path to models, one place to see the cost and the quality. That is what sets the ASF free from the chaos of individual accounts and scattered token usage, and we are already on our way there.
