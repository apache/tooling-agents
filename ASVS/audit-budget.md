# ASVS Audit Pipeline — Wall-Clock Estimate per Apache Repo

## TL;DR

Running the `orchestrate_asvs_audit_to_github` pipeline at the **recommended depth per repo** (deeper for higher-risk projects, lighter for lower-risk ones), against all 11 audit targets:

| Concurrency | Wall-clock | Equivalent |
|---|---|---|
| 1 audit at a time | **~511 hours** | ~64 working days · ~13 weeks · **~3 months** |
| 2 audits in parallel | ~256 hours | ~32 days · ~6.4 weeks |
| 4 audits in parallel | ~128 hours | ~16 days · ~3.2 weeks |

Estimated finding count across the whole sweep: **~2,300 issues** at TR-rate density (Critical: ~180, High: ~430, Medium: ~1,500, Low: ~270, Info: ~16). The ~24/kLOC steve/v3 rate would extrapolate to ~28,000 findings — treated as a worst-case upper bound rather than a central estimate.

`apache/sling` is excluded from these numbers — it's an aggregator pointing at ~350 separate `apache/sling-*` repos, not a single auditable codebase.

---

## Calibration

Two reference points were given:

| Reference | LOC | Sections | Severities | Findings | Wall-clock |
|---|---|---|---|---|---|
| trusted-releases | 120 k | 253 (L1+L2) | 5 (Crit/High/Med/Low/Info) | 314 | ~48 h |
| steve/v3 | 10 k | 345 (L1+L2+L3) | 3 (Crit/High/Med) | 240 | 28 h |

ASVS section counts (additional requirements per level): L1=70 · L2=+183 · L3=+92. So L1+L2 = 253 sections, L1+L2+L3 = 345 sections.

Severity distributions you reported:

- **trusted-releases**: 6.1% C · 14.3% H · 45.9% M · 31.8% L · 1.9% Info
- **steve/v3**: 8.8% C · 28.7% H · 62.5% M

Two implied finding-density rates:

- TR rate: **2.6 findings / kLOC** (all severities), or 1.73/kLOC if you only count C+H+M
- S3 rate: **24 findings / kLOC** for C+H+M only — about 14× the TR rate

The TR rate is treated as the central baseline (mature, publicly-audited Apache projects). The S3 rate is treated as an upper bound applicable when the codebase is materially less mature than the trusted-releases comparison.

---

## Per-agent time model

Working through the pipeline (`orchestrate_asvs_audit_to_github`) I see five callable agents. The fitted per-agent formulas — chosen so the TR and S3 reference runs both reproduce exactly — are:

| Agent | Time formula | What drives it |
|---|---|---|
| `download_github_repo_to_data_store` | 5 min + 0.05 min/kLOC | One GitHub Contents API GET per file (rate-limit / I/O bound). Filters vendor dirs and >1 MB files. |
| `discover_codebase_architecture` | ~15 min flat | One-shot per repo. Steps: read paths/previews, classify architecture (Sonnet), generate security domains (Sonnet w/ max_tokens=32k), generate false-positive guidance. ~5–10 LLM calls regardless of repo size. |
| `run_asvs_security_audit` (×N_sections) | **3.6 min/section + 13.7 min/kLOC** total | The dominant bucket (≈90% of wall-clock). Per-call: relevance filter (Sonnet, parallel batches, semaphore=5, **cached**), code inventory (Sonnet, batched, cached), **deep analysis (Opus, reasoning_effort=high, max_tokens=64k, semaphore=2)**, multi-batch consolidation, format. Wall-clock per call ranges from ~3 min (small section, cached) to ~12 min (big LOC scope per pass). |
| `consolidate_asvs_security_audit_reports` | 30 min + 0.3 min/section + 0.6 min/finding | Phase 1 read all per-section reports · Phase 2 extract findings (Sonnet, semaphore=5) · Phase 3 domain-grouped consolidation (Heavy w/ reasoning_effort=medium, semaphore=3) · Phase 3.5 cross-domain dedup · Phase 4 final merge & report. Issue write-up is folded into Phase 4. |
| `add_markdown_file_to_github_directory` | ~5 min total (negligible) | One PUT per section + per consolidation file. ~1–3 sec each. |

### Calibration check (formulas reproduce both reference runs exactly)

| Reference | download | discovery | audit | consol | push | **Total** |
|---|---|---|---|---|---|---|
| trusted-releases (predicted) | 0.18 h | 0.25 h | **42.58 h** | 4.91 h | 0.08 h | **48.00 h** |
| trusted-releases (actual) | — | — | — | — | — | ~48 h ✓ |
| steve/v3 (predicted) | 0.09 h | 0.25 h | **22.98 h** | 4.62 h | 0.08 h | **28.03 h** |
| steve/v3 (actual) | — | — | — | — | — | 28 h ✓ |

### Where the time goes (across the recommended hybrid)

| Agent | Hours | % of total |
|---|---|---|
| `run_asvs_security_audit` | 460.6 | 90.2 % |
| `consolidate_asvs_security_audit_reports` | 44.8 | 8.8 % |
| `discover_codebase_architecture` | 2.8 | 0.5 % |
| `download_github_repo_to_data_store` | 1.9 | 0.4 % |
| `add_markdown_file_to_github_directory` | 0.9 | 0.2 % |
| **Total** | **511.0** | **100 %** |

Practical implication: optimization effort should target Step 4 (Opus deep analysis) of `run_asvs_security_audit` — better caching across sections that share a file scope, raising the Opus semaphore, or smarter relevance pre-filtering would have outsized impact. Everything else is rounding error.

---

## Production-LOC re-estimates

Tests, vendored code, generated stubs, translation `.po` files, and example/fixture apps stripped where layout permitted. cloc raw totals were larger.

| Project | Prod LOC | Risk tier |
|---|---|---|
| airflow/airflow-core | 150,000 | High |
| airflow/providers/google | 90,000 | High |
| airflow/task-sdk | 20,000 | High |
| superset (backend) | 140,000 | High |
| superset (frontend) | 150,000 | Medium |
| grails-core | 230,000 | High |
| directory-server | 140,000 | **Critical** |
| directory-ldap-api | 170,000 | **Critical** |
| mina | 20,000 | High |
| log4net | 33,000 | Medium |
| mahout | 22,000 | Low–Med |
| sling (aggregator) | 0 | n/a |

---

## Master table — recommended depth per repo

| Project | LOC | Tier | Level | Severity | N_sec | Est. findings | **Hours** | Days |
|---|---|---|---|---|---|---|---|---|
| grails-core | 230 k | High | L1+L2+L3 | C/H/M | 345 | 398 | **80.0** | 10.0 |
| directory-ldap-api | 170 k | **Critical** | L1+L2+L3 | All | 345 | 442 | **66.7** | 8.3 |
| airflow-core | 150 k | High | L1+L2+L3 | C/H/M | 345 | 260 | **60.3** | 7.5 |
| directory-server | 140 k | **Critical** | L1+L2+L3 | All | 345 | 364 | **59.1** | 7.4 |
| superset (backend) | 140 k | High | L1+L2+L3 | C/H/M | 345 | 242 | **57.8** | 7.2 |
| superset (frontend) | 150 k | Medium | L1+L2 | C/H/M | 253 | 260 | **54.3** | 6.8 |
| airflow/providers/google | 90 k | High | L1+L2 | C/H/M | 253 | 156 | **39.5** | 4.9 |
| airflow/task-sdk | 20 k | High | L1+L2+L3 | All | 345 | 52 | **28.4** | 3.6 |
| mina | 20 k | High | L1+L2+L3 | C/H/M | 345 | 35 | **28.3** | 3.5 |
| log4net | 33 k | Medium | L1+L2 | C/H/M | 253 | 57 | **25.5** | 3.2 |
| mahout | 22 k | Low–Med | L1 | C/H/M | 70 | 38 | **10.9** | 1.4 |
| sling | — | n/a | (rescope) | — | — | — | — | — |
| **TOTAL** | | | | | | **~2,300** | **~511 h** | **~64 d** |

Rationale for level/severity choice per tier:

- **Critical (Directory cluster)** — deepest practical depth, full severity scope. Identity-infrastructure issues are worth catching even at Low/Info.
- **High** — full L3 + C/H/M for the bigger or trust-boundary projects (airflow-core, grails, superset backend, mina, task-sdk); L2 + C/H/M when the surface is mostly thin SDK-wrapper code (providers/google).
- **task-sdk** is small enough that running L3 + all severities only costs ~28 h — and it's the trust boundary between user-DAG code execution and the scheduler control plane, which is high-leverage.
- **Medium** (superset frontend, log4net) — L1+L2, C/H/M is a reasonable middle ground.
- **Low-Med (mahout, the quantum toolkit)** — small, narrow surface, no production deployment maturity yet → L1 + C/H/M is enough.

---

## Floor table — L1 + Critical only for every repo

Same projects, same agent pipeline, but at the absolute minimum scenario: L1 (70 sections) and Critical-only severity threshold across the board. This is "what's the cheapest run that's still useful?"

| Project | LOC | N_sec | Est. Critical findings | **Hours** | Days |
|---|---|---|---|---|---|
| grails-core | 230 k | 70 | 37 | **58.5** | 7.3 |
| directory-ldap-api | 170 k | 70 | 27 | **44.7** | 5.6 |
| airflow-core | 150 k | 70 | 24 | **40.1** | 5.0 |
| superset (frontend) | 150 k | 70 | 24 | **40.1** | 5.0 |
| superset (backend) | 140 k | 70 | 22 | **37.8** | 4.7 |
| directory-server | 140 k | 70 | 22 | **37.8** | 4.7 |
| airflow/providers/google | 90 k | 70 | 14 | **26.2** | 3.3 |
| log4net | 33 k | 70 | 5 | **13.1** | 1.6 |
| mahout | 22 k | 70 | 3 | **10.5** | 1.3 |
| airflow/task-sdk | 20 k | 70 | 3 | **10.1** | 1.3 |
| mina | 20 k | 70 | 3 | **10.1** | 1.3 |
| sling | — | — | — | — | — |
| **TOTAL** | | | **~184** | **~329 h** | **~41 d** |

Wall-clock for the floor scenario:

| Concurrency | Time | Equivalent |
|---|---|---|
| 1 audit at a time | ~329 h | ~41 days · ~8.2 weeks · ~1.9 months |
| 2 in parallel | ~165 h | ~21 days · ~4.1 weeks |
| 4 in parallel | ~82 h | ~10 days · ~2.1 weeks |

### Floor vs. recommended — what you give up

| Metric | Floor (L1 + Crit) | Recommended hybrid | Delta |
|---|---|---|---|
| Total wall-clock (solo) | **329 h** | **511 h** | −182 h (−36 %) |
| Total findings projected | **~184** | **~2,300** | −2,116 (−92 %) |
| Critical findings | ~184 | ~180 | ≈ same |
| High findings | 0 | ~430 | −430 |
| Medium findings | 0 | ~1,500 | −1,500 |
| Low/Info findings | 0 | ~290 | −290 |
| ASVS coverage | 70 of 345 reqs (20 %) | 70–345 per repo | — |

**Key insight: you lose 36% of the wall-clock cost but 92% of the findings.** The Critical-only severity filter is the dominant lever — it cuts the finding count by ~16× because Critical is only 6.1% of the all-severity TR distribution. Roughly the same number of Critical findings emerge either way (~180 vs ~184); what you lose is everything below.

This scenario is appropriate as:
- A **first pass** to triage which repos warrant deeper attention before committing the full ~511 h.
- A **time-boxed sweep** if there's a hard deadline — gets you a Critical-only report card across all 11 repos in ~41 days solo, ~10 days with 4 parallel runs.
- A **regression check** after fixes from a prior deeper audit — if previous Critical findings are remediated, this confirms no new Criticals slipped in.

It is **not** appropriate as a final audit deliverable for the Critical-tier projects (Directory cluster) or for SDLC certification — High and Medium findings often combine into Critical-equivalent attack chains, and ASVS L1 alone leaves L2/L3 controls uninspected.

---

## Per-project deep-dive

Each section: chosen scenario, per-agent breakdown, projected findings.

### `apache/grails-core`
*Web framework on Spring/Groovy/Hibernate · 230 k LOC across 79 modules*

**Scenario**: L1+L2+L3 / Critical+High+Medium · 345 sections · ~398 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 16.5 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **73.2 h** (4393 min) |
| consolidate_asvs_security_audit_reports | 6.2 h (372 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **80.0 h ≈ 10 days** |

Projected findings (TR-rate, C/H/M only, renormalized): **C ≈ 37 · H ≈ 86 · M ≈ 276**.
Largest single budget item on the list — driven by sheer LOC of framework code that needs auditing across all 345 ASVS sections. Biggest candidates for ROI: `grails-databinding*`, `grails-encoder`, `grails-gsp`, `grails-converters`. If schedule pressure forces a trim, dropping to L1+L2 saves ~21 h (gets to ~59 h).

### `apache/directory-ldap-api`
*LDAP/ASN.1 protocol library · 170 k LOC*

**Scenario**: L1+L2+L3 / All severities · 345 sections · ~442 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 13.5 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **59.5 h** (3571 min) |
| consolidate_asvs_security_audit_reports | 6.6 h (399 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **66.7 h ≈ 8.3 days** |

Projected findings (TR-rate, all severities): **C ≈ 27 · H ≈ 63 · M ≈ 203 · L ≈ 141 · Info ≈ 8**.
ASN.1, LDAP codec, DN parsing, DSML XML — these are exactly the parsers that justify L3 + all-severity scope. The severity-scope choice probably underestimates findings density here; auth-infra parsers tend to surface issues. Budget for the upper end of the range; consider adding 20–30% margin.

### `apache/airflow/airflow-core`
*Workflow orchestration server + UI · 150 k LOC (≈ 80 k Py + 70 k TS)*

**Scenario**: L1+L2+L3 / Critical+High+Medium · 345 sections · ~260 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 12.5 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **55.0 h** (3297 min) |
| consolidate_asvs_security_audit_reports | 4.8 h (290 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **60.3 h ≈ 7.5 days** |

Projected findings: **C ≈ 24 · H ≈ 56 · M ≈ 180**.
The discovery step matters here — there are two REST stacks (`api/` legacy + `api_fastapi/` new) that should each be a separate domain. Verify `discover_codebase_architecture` produces sane domain groupings before committing to the run; a bad partition forces the consolidation phase to do more cross-domain dedup work.

### `apache/directory-server`
*LDAP server with embedded Kerberos KDC · 140 k LOC*

**Scenario**: L1+L2+L3 / All severities · 345 sections · ~364 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 12.0 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **52.7 h** (3160 min) |
| consolidate_asvs_security_audit_reports | 5.9 h (352 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **59.1 h ≈ 7.4 days** |

Projected findings (all sev): **C ≈ 22 · H ≈ 52 · M ≈ 167 · L ≈ 116 · Info ≈ 7**.
The `interceptors/` module (where authn/authz checks live) and `kerberos-codec/` should be the highest-priority files in the `includeFiles` for sensitive ASVS sections. Architecturally clean module split (`protocol-ldap`, `protocol-dns`, `protocol-dhcp`, etc.) means discovery should produce clean domains.

### `apache/superset` (backend)
*Analytics/BI server · 140 k Python production*

**Scenario**: L1+L2+L3 / Critical+High+Medium · 345 sections · ~242 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 12.0 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **52.7 h** (3160 min) |
| consolidate_asvs_security_audit_reports | 4.6 h (279 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **57.8 h ≈ 7.2 days** |

Projected findings: **C ≈ 22 · H ≈ 52 · M ≈ 168**.
Hot zones: `sqllab/`, `db_engine_specs/` (75 driver shims), `jinja_context.py`, `security/`, `embedded/`. Audit `superset-frontend` separately (next entry). Note: `superset-websocket`, `superset-embedded-sdk`, `helm/`, and `docker/` are excluded from this LOC count and have their own threat models if you want to add them in.

### `apache/superset` (frontend)
*TypeScript/React dashboard UI · 150 k LOC production*

**Scenario**: L1+L2 / Critical+High+Medium · 253 sections · ~260 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 12.5 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 253) | **49.4 h** (2966 min) |
| consolidate_asvs_security_audit_reports | 4.4 h (262 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **54.3 h ≈ 6.8 days** |

Projected findings: **C ≈ 24 · H ≈ 56 · M ≈ 180**.
For a frontend, L3 ASVS requirements (which target server-side concerns like crypto module hardening, advanced session management) add little value — L1+L2 covers the relevant XSS / CSRF / DOM-injection / postMessage / CSP territory. Scope to `src/` and `packages/`; deprioritize the 40+ `plugins/` directories unless specifically scoped.

### `apache/airflow/providers/google`
*GCP integration provider · 90 k Python production*

**Scenario**: L1+L2 / Critical+High+Medium · 253 sections · ~156 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 9.5 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 253) | **35.7 h** (2144 min) |
| consolidate_asvs_security_audit_reports | 3.3 h (200 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **39.5 h ≈ 4.9 days** |

Projected findings: **C ≈ 14 · H ≈ 34 · M ≈ 108**.
Mostly thin SDK wrappers around `google-cloud-*`. Risk surface is concentrated in credential handling, IAM scope minimization, and SSRF/data-exfiltration via misconfigured operators. L3 doesn't add much for SDK wrappers — L2 captures the relevant ASVS coverage. ~118k of the 128k cloc-reported LOC is in the `cloud/` subtree; targeting `includeFiles` to `cloud/hooks/`, `cloud/operators/`, and `common/` would tighten scope.

### `apache/airflow/task-sdk`
*Worker-side execution SDK · 20 k Python production*

**Scenario**: L1+L2+L3 / All severities · 345 sections · ~52 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 6.0 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **25.3 h** (1516 min) |
| consolidate_asvs_security_audit_reports | 2.7 h (165 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **28.4 h ≈ 3.6 days** |

Projected findings (all sev): **C ≈ 3 · H ≈ 7 · M ≈ 24 · L ≈ 17 · Info ≈ 1**.
Small enough that running L3 + all-severity is cheap, and it's the trust boundary between user-DAG code execution and the scheduler control plane (`api/`, `execution_time/`, `crypto.py`, `serde/`). High return on a relatively small budget.

### `apache/mina`
*Java NIO network framework · 20 k LOC*

**Scenario**: L1+L2+L3 / Critical+High+Medium · 345 sections · ~35 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 6.0 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 345) | **25.3 h** (1516 min) |
| consolidate_asvs_security_audit_reports | 2.6 h (155 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **28.3 h ≈ 3.5 days** |

Projected findings: **C ≈ 3 · H ≈ 8 · M ≈ 24**.
ASVS-style auditing of a low-level framework is partially mismatched — many ASVS requirements assume an application context — but the HTTP/2 codec, SSL filter defaults, and buffer-handling primitives are all worth running through. Low LOC means cheap audit; the `core/` filter chain plus `http2/` codec are the high-value targets.

### `apache/logging-log4net`
*.NET logging library · 33 k C# production*

**Scenario**: L1+L2 / Critical+High+Medium · 253 sections · ~57 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 6.7 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 253) | **22.7 h** (1363 min) |
| consolidate_asvs_security_audit_reports | 2.3 h (140 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **25.5 h ≈ 3.2 days** |

Projected findings: **C ≈ 5 · H ≈ 12 · M ≈ 40**.
Library code rather than an application, so L3's app-layer requirements add little. Specific things to verify in the `Appender/` directory: any JNDI-style lookup interpolation in `PatternLayout`/`DynamicPatternLayout`, parameter handling in `AdoNetAppender`, header injection in `SmtpAppender`, XXE risk in `XmlLayoutSchemaLog4j`, plus the `TelnetAppender` (a network listener inside a logger).

### `apache/mahout`
*Quantum-computing toolkit (qumat + QDP) · 22 k LOC (Python + Rust + CUDA)*

**Scenario**: L1 / Critical+High+Medium · 70 sections · ~38 findings projected

| Agent | Wall-clock |
|---|---|
| download_github_repo_to_data_store | 6.1 min |
| discover_codebase_architecture | 15.0 min |
| run_asvs_security_audit (× 70) | **9.2 h** (553 min) |
| consolidate_asvs_security_audit_reports | 1.2 h (74 min) |
| add_markdown_file_to_github_directory | 5 min |
| **TOTAL** | **10.9 h ≈ 1.4 days** |

Projected findings: **C ≈ 3 · H ≈ 8 · M ≈ 26**.
Note: this is **not** the legacy Mahout (Hadoop/Spark big-data ML) — it's been completely rebooted as a quantum-computing toolkit. The actual surface is small: Python wrapper around Qiskit/Cirq/Braket SDKs, plus a Rust + CUDA "Quantum Data Plane". ASVS L1 is appropriate; L2/L3 requirements largely don't apply (no web app, no auth, no session management). Spend audit attention on the FFI layer (`qdp-python/`), `unsafe` Rust, and `qdp-core/remote.rs` rather than running ASVS L3 against it.

### `apache/sling` — RESCOPE NEEDED

The `apache/sling` repository itself is **an aggregator only** — 1,897 LOC of mostly Markdown + Groovy build scripts pointing at ~350 separate `apache/sling-*` repositories. There is no monolithic Sling codebase to audit; whoever specified "audit Sling" needs to identify which Sling components are actually in scope. Typical important ones:

- `sling-org-apache-sling-api` — the public Sling API
- `sling-org-apache-sling-auth-core`, `-auth-form`, `-auth-oauth-client`, `-auth-saml2` — auth modules
- `sling-org-apache-sling-app-cms` — reference CMS app
- `sling-org-apache-sling-resourceresolver` — request-to-resource mapping
- `sling-org-apache-sling-servlets-*` — servlet handling
- `sling-org-apache-sling-scripting-*` — scripting engines (XSS / template-injection territory)

Once a target sub-list exists, the same model applies per sub-repo.

---

## Sensitivity — what scenario choice does to one example

`airflow-core` (150 k LOC) at every (level × severity) combination:

| Level | Severity | Sections | Est. findings | Hours | Days |
|---|---|---|---|---|---|
| L1 | Critical only | 70 | 24 | 40.1 | 5.0 |
| L1 | C+H | 70 | 80 | 40.6 | 5.1 |
| L1 | C+H+M | 70 | 260 | 42.4 | 5.3 |
| L1 | All | 70 | 390 | 43.7 | 5.5 |
| L1+L2 | Critical only | 253 | 24 | 52.0 | 6.5 |
| L1+L2 | C+H | 253 | 80 | 52.5 | 6.6 |
| L1+L2 | C+H+M | 253 | 260 | 54.3 | 6.8 |
| L1+L2 | All | 253 | 390 | 55.6 | 7.0 |
| L1+L2+L3 | Critical only | 345 | 24 | 58.0 | 7.2 |
| L1+L2+L3 | C+H | 345 | 80 | 58.5 | 7.3 |
| L1+L2+L3 | C+H+M | 345 | 260 | **60.3** | 7.5 |
| L1+L2+L3 | All | 345 | 390 | 61.6 | 7.7 |

Notable observations:

- **Level matters more than severity for wall-clock.** L1 → L1+L2+L3 adds ~18 hours (more sections to run); broadest severity → narrowest severity within the same level only saves ~3 hours (mostly write-up time).
- **Once you've paid for L3 sections, picking up Low/Info severities is nearly free** — only ~1.3 h extra. If you have the Critical-tier projects on L3 anyway, broadening to all severities for them costs almost nothing.
- The minimum useful run is roughly L1 + Critical-only (~40 h for a 150 k repo), but the marginal cost to L1+L2 + C/H/M is only ~14 h and surfaces ~10× more findings.

---

## Caveats — things that will move these numbers

The model is a 2-point linear fit — useful for budgeting, not for SLA-grade promises.

**Will run faster than predicted (~0.5×–0.8× the estimate):**
- Repetitive Python/SDK-wrapper code (providers/google, parts of superset) compresses well in the inventory step.
- Caching helpers when the same files are scoped into multiple passes/sections (the agent does cache relevance + inventory + per-batch analysis).
- High Opus availability — the `opus_semaphore=2` is a hard cap; if you raise it, audit step shrinks proportionally.

**Will run slower than predicted (~1.3×–2× the estimate):**
- Dense protocol parsers (ASN.1, Kerberos, BER/DER, HTTP/2 framing) — Opus reasoning_effort=high genuinely takes longer on this kind of code, the calibration runs probably didn't have much of it.
- Bedrock rate-limits or transient errors — the agent retries with 15s/30s/45s backoff, so a few failures multiply quickly.
- Discovery producing too many or too few domains — over-fragmentation increases per-section overhead; under-fragmentation forces big Opus batches that hit the 80% context limit and split.
- Steve/v3-style finding density (24/kLOC vs 2.6/kLOC) — would push consolidation phase up by 4–6× because of the per-finding write-up cost. Does not affect audit step.

**Capacity / ops considerations:**
- 64 person-days of LLM time at the bedrock pricing implied by `claude-opus-4-6-v1` with reasoning_effort=high and max_tokens=64k is non-trivial spend. Budget separately.
- The orchestrator pushes per-section reports during the run, so partial progress is preserved if anything dies mid-audit. Restarts use the relevance/inventory caches but re-do the deep-analysis batches that didn't get cached.
- For the recommended hybrid run, the GitHub PUT volume is ~3,200 file writes (one per section × 11 repos plus consolidation files). Well under GitHub's API limits but worth noting if running through a low-quota PAT.

**Apache-PMC carve-out mode** (the `privateRepo`+`notifyEmail` path in the orchestrator) adds ~5–15% on top per repo for the redaction phase + email step. Not included in the numbers above.
