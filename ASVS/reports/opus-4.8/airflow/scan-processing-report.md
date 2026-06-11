<!--
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
-->

# ASVS opus-4.8 Airflow scans — processing report

Security-team processing summary for the three `opus-4.8` (Opus 4.8 + audit-guidance) ASVS scans of Apache Airflow. Processed 2026-06-11. Per-finding triage discussion lives on the source issues ([#23](https://github.com/apache/tooling-agents/issues/23), [#24](https://github.com/apache/tooling-agents/issues/24), [#34](https://github.com/apache/tooling-agents/issues/34)); this is the cross-scan overview.

## Per-scan summary

| Scan | Issue | Findings | Severities | Outcome |
|---|---|---:|---|---|
| `airflow-core/cc63c83` | #23 | 31 | 4 Medium · 27 Low | 1 hardening PR (apache/airflow#68388, incl. FINDING-029), 1 folded into an existing internal tracker, 2 already-fixed, 27 no-action |
| `task-sdk/b82b881` | #24 | 7 | 1 Medium · 5 Low · 1 Info | 0 PRs / 0 trackers — all no-action |
| `providers/google/7d95a3c` | #34 | 3 | 1 Medium · 2 Low | 1 docs hardening PR (apache/airflow#68391), 2 no-action |
| **Total** | | **41** | **6 Medium (14.6%) · 34 Low (82.9%) · 1 Info (2.4%)** · 0 Critical/High | **2 PRs · 0 CVEs · 0 new trackers** |

## Disposition breakdown (41 findings)

| Disposition | Count | % |
|---|---:|---:|
| Hardening PR shipped (defense-in-depth / consistency) | 3 | 7.3% |
| Folded into an existing internal security tracker | 1 | 2.4% |
| Already fixed upstream (prior PR) | 2 | 4.9% |
| **No action** (by-design / out-of-scope / not-reachable / not-security / info) | **35** | **85.4%** |

Within the 35 no-action findings:

- **~29 by-design / out-of-scope** — trusted-actor (DAG author, connection-configuration user, operator), deployment-manager responsibility (TLS, cookie `Secure`/`__Host-` prefixes, security headers), or **mitigated upstream** (uvicorn/`h11` rejects CR/LF in headers, `httpx` strips cross-origin `Authorization` on redirects, the default JSON log renderer escapes control characters).
- **3 not-reachable / scanner premise unsupported** — concurrency races on code paths that aren't driven from multiple in-process threads; "missing authentication" on endpoints that are unauthenticated by design.
- **2 not-security correctness/reliability** — a documented-intentional task-state tradeoff; a token-lifetime bookkeeping bug whose only impact is availability (the token cannot outlive the provider's server-side expiry).
- **1 informational** — a process-lifetime cache whose exposure window is bounded by a short-lived per-task process.

## Severity vs. reality

- **6 Medium findings → 0 survived as vulnerabilities.** Every Medium was downgraded after a code-level deep-read + trust-boundary analysis (the actor turned out to be trusted, the behavior intentional/documented, the race unreachable, or the precondition an IdP/deployment-lifecycle responsibility).
- **0 Critical/High, 0 CVEs, 0 new security trackers** across all 41 findings.
- The two PRs are **defense-in-depth / consistency hardening**, not fixes for exploitable vulnerabilities.

## What the scanner is good for

**Strengths**

- **Coverage / checklist sweep.** It systematically walks ASVS controls and reliably flags places where a control is *implicit rather than explicitly asserted* — relying on a library's safe default instead of pinning it, a redaction applied at sibling sinks but not this one, an error path not gated on the configured `expose_stacktrace`, a denial that fails closed but isn't logged. This produced the two genuine hardening PRs and confirmed two already-shipped fixes.
- **Hygiene prompts.** Strong at "you're relying on a safe default — make it explicit" and "this sink lacks the protection its siblings have."
- **The audit-guidance round is markedly better than earlier ones.** Prior L1/L3 runs on the same components produced 100–200 findings dominated by by-design noise; this opus-4.8 + `audit_guidance` round produced 31 / 7 / 3, with most trusted-actor and deployment-manager categories pre-filtered before triage.

**Limitations**

- **No threat-model awareness.** It scores ASVS-control gaps without modeling Airflow's trust boundaries, so it cannot distinguish a trusted role (DAG author, connection-configuration user, operator, internal worker↔scheduler channel) from an external attacker. This is why ~85% required no action.
- **Systematic severity over-claim.** Titles assert "multiple threads", "missing authentication", "account takeover", "CR/LF injection" that collapse on a code read (the threads don't exist, the auth is intentional, the email claim is unforgeable, `h11` blocks the injection). Every Medium needed a human downgrade.
- **Blind to upstream mitigations** (`h11`, `httpx`, the JSON log renderer) — it evaluates application code in isolation.
- **No de-duplication** against already-shipped fixes or the project's documented Security Model.

## Net assessment

For this codebase and round, the scanner functioned as a **defense-in-depth / hygiene coverage tool, not a vulnerability finder**: 41 findings yielded 0 vulnerabilities and 2 hardening PRs. Its output is only safe to consume through a **mandatory human deep-read + trust-boundary triage** — every finding's `consolidated.md` evidence read against the Security Model, with severity treated as a starting hypothesis rather than a verdict. Used that way it is a useful recurring checklist; consumed naively (auto-importing findings) it would have generated roughly 41 trackers and dozens of unwarranted PRs for zero real vulnerabilities.
