# Apache GitHub CI Security Review

Automated analysis of GitHub Actions workflows across the Apache Software Foundation's repositories, answering two questions:

1. **Which projects publish packages to registries from CI?** (npm, PyPI, Maven Central, Docker Hub, crates.io, etc.)
2. **What are the security risks in those CI pipelines?**

## Reports at a Glance

| Report | File | What It Covers | Size |
|--------|------|---------------|------|
| **Executive Brief** | `brief.md` | One-page action plan — start here | ~2–4 KB |
| **Combined Review** | `review.md` | Full cross-reference with attack scenarios | ~5–15 KB |
| **Publishing Analysis** | `publishing.md` | Which repos publish what, where, how, trusted publishing status | ~500 KB–1 MB |
| **Security Scan** | `security.md` | Per-repo vulnerability findings with severity and details | ~1–2 MB |
| **JSON Export** | `json-export.json` | Machine-readable structured data combining both analyses | ~5–15 MB |

---

## Reading Order

**If you have 2 minutes:** Read the Executive Brief. It tells you what's exploitable, what to fix, and when.

**If you have 15 minutes:** Read the Combined Review. It has the full risk tiering, vulnerability type breakdown, and attack scenarios.

**If you're triaging a specific repo:** Search the JSON with `jq` (examples below) or find the repo's section in either markdown report.

**If you're planning remediation:** Start with the Executive Brief for priorities, then use the JSON to generate tickets per repo.

---

## 1. Executive Brief ([`brief.md`](brief.md))

The one-pager. The Brief agent reads the same data as the Combined Review but strips everything except what needs action. No tables, no collapsible sections, no LOW/INFO noise.

### Sections

| Section | What It Shows |
|---------|--------------|
| **Goal** | What was scanned, how many repos publish packages |
| **Exploitable Now** | CRITICAL findings only — repos where external contributors can execute code with publishing secrets today. Each entry names the repo, file, and what registries it publishes to. |
| **High Risk: Publishing Repos** | Repos that publish AND have HIGH-severity findings |
| **Latent Risk: Composite Action Injection** | Publishing repos with composite actions that interpolate inputs — not exploitable today, one unsafe caller away |
| **Systemic Issues** | Org-wide problems: trusted publishing migration, unpinned actions, missing CODEOWNERS |
| **Recommended Actions** | Numbered, timeframed: "fix this week", "this quarter", etc. |
| **Full Analysis** | Links to all other reports |

### How to Read It

- **Share this with leadership and the security team.** It's designed to be read in 2 minutes and forwarded without explanation.
- **"Exploitable Now" is your P0 list.** These need fixes this week.
- **"Recommended Actions" are ordered by urgency and impact.** Each one links to details.
- Everything else is in the linked reports for whoever needs to dig in.

---

## 2. Combined Review ([`review.md`](review.md))

The entry point. The Review agent generates this by cross-referencing data from the Publishing Analysis and Security Scan.

### Sections

| Section | What It Shows |
|---------|--------------|
| **At a Glance** | Dashboard: repos scanned, publishing count, finding totals, top ecosystems |
| **Findings by Vulnerability Type** | Aggregate table of all vulnerability types found, with counts and severity. Each row links to an attack scenario. |
| **Attack Scenarios** | For each vulnerability type: what it is, how an attacker exploits it, step-by-step example |
| **Immediate Attention Required** | CRITICAL/HIGH repos that *also publish packages* — highest supply-chain risk |
| **Non-Publishing Repos with HIGH Findings** | HIGH-severity repos that don't publish (CI-only risk, no supply-chain impact) |
| **Moderate Risk** | Publishing repos with MEDIUM findings (typically unpinned actions) |
| **Low Risk** | Publishing repos with only LOW/INFO findings |
| **Trusted Publishing Opportunities** | Repos using long-lived tokens where OIDC is available |
| **Key Recommendations** | Numbered action items with links to details |

### How to Read It

- **Immediate Attention repos** are your P0s — they publish packages AND have exploitable vulnerabilities
- **Non-Publishing HIGH repos** are P1s — important but no supply-chain blast radius
- Everything links to the detailed repo sections in the publishing and security reports
- The "Attack Scenarios" section is designed to be shared with developers who need to understand *why* a finding matters

---

## 3. Publishing Analysis ([`publishing.md`](publishing.md))

The Publishing agent generates this by fetching every workflow YAML file and classifying it with an LLM.

### Sections

| Section | What It Shows |
|---------|--------------|
| **Executive Summary** | Counts: repos scanned, workflows, publishing repos, by category |
| **Package Ecosystem Distribution** | Which registries are targeted, how many workflows per ecosystem |
| **Already Using Trusted Publishing** | Repos that have already adopted OIDC — the success stories |
| **Trusted Publishing Migration Opportunities** | Repos still using long-lived tokens where OIDC is available, grouped by ecosystem with current auth method |
| **Release Artifact Workflows** | Table: every workflow that publishes versioned packages to public registries |
| **Snapshot / Nightly Workflows** | Table: every workflow that publishes snapshot/nightly builds |
| **CI Infrastructure Workflows** | Collapsed: Docker images used only for CI build caching/testing |
| **Documentation Workflows** | Collapsed: docs, websites, coverage uploads |
| **Security Notes** | LLM-identified security concerns in publishing workflows, grouped by severity |
| **Detailed Results** | Per-repo breakdown: every publishing workflow with summary, ecosystems, trigger, auth method, commands |
| **Non-publishing Repos** | Repos with workflows that don't publish anything |

### How to Read It

- **Ecosystem Distribution** tells you your attack surface breadth — npm-heavy orgs have different risks than Maven-heavy ones
- **Already Using Trusted Publishing** shows what good looks like — reference these when asking teams to migrate
- **Trusted Publishing Migration Opportunities** is your remediation backlog — grouped by ecosystem so you can tackle one registry at a time
- **Detailed Results** is where you go for a specific repo — it has the LLM-generated summary of what each workflow does, which is often clearer than reading the YAML

### Category Definitions

| Category | Meaning | Supply-Chain Risk |
|----------|---------|-------------------|
| `release_artifact` | Publishes versioned packages to public registries (npm, PyPI, Maven Central, Docker Hub, crates.io, NuGet, RubyGems) | **High** — end users consume these |
| `snapshot_artifact` | Publishes snapshot/nightly builds to staging registries | **Medium** — developers consume these |
| `ci_infrastructure` | Pushes Docker images for CI build caching or test execution only | **Low** — internal use only |
| `documentation` | Deploys docs, websites, coverage reports | **None** — no executable artifacts |
| `none` | No publishing detected | **None** |

---

## 4. Security Scan ([`security.md`](security.md))

The Security agent generates this by pattern-matching on cached workflow YAML. Zero LLM calls — pure static analysis.

### Sections

| Section | What It Shows |
|---------|--------------|
| **Executive Summary** | Severity breakdown: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| **Findings by Check Type** | Which checks found what, with counts |
| **CRITICAL / HIGH / MEDIUM / LOW / INFO Findings** | All findings grouped by severity |
| **Detailed Results by Repository** | Per-repo: all findings sorted by severity with file and detail |

### Check Types (Severity Order)

| Check | Severity | What It Detects |
|-------|----------|-----------------|
| `prt_checkout` | CRITICAL–LOW | `pull_request_target` + checkout of PR head code. CRITICAL if broad permissions + auto-trigger. MEDIUM if one mitigating factor (limited perms or maintainer-gated). LOW if both. |
| `self_hosted_runner` | HIGH | Self-hosted runners exposed to PR triggers — persistent compromise risk |
| `unpinned_actions` | MEDIUM | Third-party actions (outside `actions/*`, `github/*`, `apache/*`) referenced by mutable tags instead of SHA pins — supply chain risk |
| `composite_action_unpinned` | MEDIUM | Third-party unpinned actions inside composite actions — harder to audit. Same ASF exemption as above. |
| `composite_action_input_injection` | MEDIUM | Composite action interpolates `inputs.*` in `run:` blocks — latent injection surface, exploitable only if callers pass untrusted values |
| `run_block_injection` | LOW | Direct `${{ }}` interpolation in `run:` blocks — trusted values but bad hygiene |
| `composite_action_injection` | LOW | Same as above but inside composite actions |
| `broad_permissions` | LOW | GITHUB_TOKEN with more scopes than needed |
| `missing_codeowners` | LOW | No CODEOWNERS file — workflow changes bypass security review |
| `codeowners_gap` | LOW | CODEOWNERS exists but doesn't cover `.github/` |
| `missing_dependency_updates` | LOW | No dependabot.yml or renovate.json — ASF policy requires automated dependency management |
| `cache_poisoning` | INFO | `actions/cache` with PR trigger — theoretical cache poisoning |
| `third_party_actions` | INFO | Actions from outside `actions/*`, `github/*`, `apache/*` namespaces |

### How to Read It

- **CRITICAL findings are confirmed vulnerabilities** — PR head checkout with broad permissions and no maintainer gate. An external contributor can exploit these by opening a PR.
- **HIGH findings are active risks** — self-hosted runner exposure, write-all permissions, or other patterns that could be exploited with existing triggers
- **MEDIUM findings are supply chain hygiene and latent risks** — unpinned actions (real attacks have exploited this, e.g., tj-actions/changed-files, March 2025) and composite action injection patterns that are not exploitable today but become dangerous if a future caller passes untrusted input
- **LOW/INFO are best practices** — important for defense-in-depth but not urgent

---

## 5. JSON Export ([`json-export.json`](json-export.json))

Machine-readable structured data combining everything from the Publishing Analysis and Security Scan. Generated by the JSON Export agent with zero LLM calls.

### Schema

```
{
  "schema_version": "1.0",
  "owner": "apache",
  "generated_at": "2026-04-03T09:30:00Z",

  "check_definitions": {                    // Attack scenarios for each check type
    "<check_name>": {
      "label": "Human-Readable Name",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "description": "What this check detects",
      "attack": "How an attacker exploits it",
      "example": "Step-by-step attack example"
    }
  },

  "summary": {
    "repos_scanned": 2501,
    "repos_with_workflows": 1202,
    "total_workflows": 4731,
    "repos_publishing": 343,
    "ecosystem_counts": {                   // All ecosystems (including docs/CI)
      "npm": 150, "docker_hub": 80, ...
    },
    "category_counts": {
      "release_artifact": 324,
      "snapshot_artifact": 171,
      "ci_infrastructure": 91,
      "documentation": 310
    },
    "trusted_publishing_opportunities": 113,
    "security": {
      "total_findings": 5357,
      "repos_with_findings": 1203,
      "severity_counts": {
        "CRITICAL": 22, "HIGH": 283, "MEDIUM": 1180,
        "LOW": 1872, "INFO": 2000
      },
      "check_counts": {
        "missing_codeowners": 1176,
        "unpinned_actions": 1109, ...
      }
    }
  },

  "repos": [                                // One entry per repo
    {
      "repo": "apache/kafka",
      "has_workflows": true,
      "total_workflows": 22,
      "publishes_to_registry": true,        // release or snapshot only
      "ecosystems": ["docker_hub"],         // publishing ecosystems
      "category_counts": {
        "release_artifact": 2
      },
      "trusted_publishing": {
        "migration_needed": false,          // uses long-lived token for OIDC-capable ecosystem?
        "eligible_ecosystems": []           // which ecosystems could migrate
      },
      "security": {
        "total_findings": 9,
        "worst_severity": "CRITICAL",       // worst across all findings
        "severity_counts": {"CRITICAL": 1, "MEDIUM": 4, "LOW": 2, "INFO": 2},
        "check_counts": {"composite_action_unpinned": 3, "prt_checkout": 2, ...}
      },
      "workflows": [                        // publishing workflows only
        {
          "file": "docker_promote.yml",
          "workflow_name": "Promote Release Candidate Docker Image",
          "publishes": true,
          "category": "release_artifact",
          "ecosystems": ["docker_hub"],
          "trigger": "workflow_dispatch",
          "auth_method": "secrets.DOCKERHUB_USER and secrets.DOCKERHUB_TOKEN",
          "publish_actions": ["docker/login-action@5e57cd..."],
          "publish_commands": ["docker buildx imagetools create ..."],
          "summary": "Promotes RC Docker images to final release on Docker Hub.",
          "confidence": "high",
          "security_notes": ["[LOW] github.event.inputs directly interpolated..."]
        }
      ],
      "findings": [                         // all security findings
        {
          "severity": "CRITICAL",
          "check": "prt_checkout",
          "file": "pr-labeled.yml",
          "detail": "pull_request_target trigger with checkout of PR head code...",
          "line": 47                         // line number in workflow file (optional)
        },
        {
          "severity": "LOW",
          "check": "run_block_injection",
          "file": "build.yml",
          "detail": "(3x) ...",
          "lines": [12, 38, 55]              // multiple line numbers when deduplicated (optional)
        }
      ]
    }
  ]
}
```

---

## jq Examples

All examples assume the JSON file is `json-export.json`.

### Organization Overview

```bash
# High-level summary
jq '{
  repos_scanned: .summary.repos_scanned,
  publishing: .summary.repos_publishing,
  findings: .summary.security.total_findings,
  critical: .summary.security.severity_counts.CRITICAL,
  high: .summary.security.severity_counts.HIGH
}' json-export.json

# Top 10 ecosystems
jq '.summary.ecosystem_counts | to_entries | sort_by(-.value) | .[0:10] | from_entries' json-export.json

# Top vulnerability types by count
jq -r '.summary.security.check_counts | to_entries | sort_by(-.value) | .[0:10] | .[] | "\(.value)\t\(.key)"' json-export.json
```

### Find Repos by Vulnerability

```bash
# All repos with CRITICAL findings
jq '[.repos[] | select(.security.worst_severity == "CRITICAL") | .repo]' json-export.json

# All repos with a specific check type (e.g., prt_checkout)
jq '[.repos[] | select(.security.check_counts.prt_checkout > 0) | {repo, count: .security.check_counts.prt_checkout}]' json-export.json

# Repos with composite action injection that also publish
jq '[.repos[] | select(.publishes_to_registry and .security.check_counts.composite_action_input_injection > 0) | {repo, ecosystems, findings: .security.total_findings}]' json-export.json

# All repos missing CODEOWNERS that publish to npm
jq '[.repos[] | select(.security.check_counts.missing_codeowners > 0 and (.ecosystems | index("npm"))) | .repo]' json-export.json
```

### Full Repo Summary

```bash
# Everything about a specific repo
jq '.repos[] | select(.repo == "apache/kafka")' json-export.json

# Repo security summary (no workflow/finding details)
jq '.repos[] | select(.repo == "apache/kafka") | {repo, publishes: .publishes_to_registry, ecosystems, security, trusted_publishing}' json-export.json

# Just findings for a repo, sorted by severity
jq '.repos[] | select(.repo == "apache/kafka") | .findings | sort_by(if .severity == "CRITICAL" then 0 elif .severity == "HIGH" then 1 elif .severity == "MEDIUM" then 2 elif .severity == "LOW" then 3 else 4 end)' json-export.json

# Findings with line numbers (for linking to source)
jq '[.repos[] | select(.repo == "apache/solr") | .findings[] | select(.line) | {file, line, severity, check}]' json-export.json
```

### Publishing Analysis

```bash
# All repos that publish to PyPI
jq '[.repos[] | select(.ecosystems | index("pypi")) | {repo, workflows: [.workflows[] | select(.ecosystems | index("pypi")) | {file, auth_method}]}]' json-export.json

# Repos needing trusted publishing migration
jq '[.repos[] | select(.trusted_publishing.migration_needed) | {repo, ecosystems: .trusted_publishing.eligible_ecosystems}]' json-export.json

# All release workflows across the org
jq '[.repos[] | .repo as $r | .workflows[] | select(.category == "release_artifact") | {repo: $r, file, ecosystems, trigger}]' json-export.json

# Repos publishing to Docker Hub with their auth methods
jq '[.repos[] | select(.ecosystems | index("docker_hub")) | {repo, workflows: [.workflows[] | select(.ecosystems | index("docker_hub")) | {file, auth_method}]}]' json-export.json
```

### Triage and Remediation

```bash
# Priority list: repos sorted by risk (CRITICAL first, then HIGH, then by finding count)
jq '[.repos[] | select(.security.total_findings > 0) | {
  repo,
  worst: .security.worst_severity,
  findings: .security.total_findings,
  publishes: .publishes_to_registry,
  ecosystems
}] | sort_by([
  (if .worst == "CRITICAL" then 0 elif .worst == "HIGH" then 1 elif .worst == "MEDIUM" then 2 else 3 end),
  (-.findings)
])' json-export.json

# Repos with CRITICAL or HIGH that publish — your P0 list
jq '[.repos[] | select(
  .publishes_to_registry and
  (.security.worst_severity == "CRITICAL" or .security.worst_severity == "HIGH")
) | {repo, worst: .security.worst_severity, ecosystems, findings: .security.total_findings}]' json-export.json

# Generate a remediation CSV
jq -r '.repos[] | select(.security.total_findings > 0) |
  [.repo, .security.worst_severity, (.security.total_findings | tostring),
   (.publishes_to_registry | tostring), (.ecosystems | join(";")),
   (.trusted_publishing.migration_needed | tostring)] | @csv' json-export.json

# Get the attack scenario for a specific check
jq '.check_definitions.prt_checkout' json-export.json
```

### Aggregate Statistics

```bash
# How many repos publish to each ecosystem?
jq '[.repos[] | select(.publishes_to_registry) | .ecosystems[]] | group_by(.) | map({(.[0]): length}) | add' json-export.json

# Severity distribution across publishing vs non-publishing repos
jq '{
  publishing: ([.repos[] | select(.publishes_to_registry) | .security.severity_counts // {} | to_entries[]] | group_by(.key) | map({(.[0].key): (map(.value) | add)}) | add),
  non_publishing: ([.repos[] | select(.publishes_to_registry | not) | .security.severity_counts // {} | to_entries[]] | group_by(.key) | map({(.[0].key): (map(.value) | add)}) | add)
}' json-export.json

# Count repos by worst severity
jq '[.repos[] | .security.worst_severity] | group_by(.) | map({(.[0]): length}) | add' json-export.json

# Repos with the most findings
jq '[.repos[] | select(.security.total_findings > 0) | {repo, findings: .security.total_findings}] | sort_by(-.findings) | .[0:20]' json-export.json
```

---

## Agent Architecture

Six agents share data via CouchDB namespaces:

```
Pre-fetch ──→   ci-workflows:{owner}        (YAML cache + composite actions)
       │
Publishing ──→  ci-classification:{owner}   (LLM classifications)
       │        ci-report:{owner}           (report + stats)
       │
Security ──→    ci-security:{owner}         (findings + stats)
       │
Review ──→      ci-combined:{owner}         (combined report)
       │
Brief ──→       ci-combined:{owner}         (executive brief)
       │
JSON Export ──→ ci-combined:{owner}         (JSON export)
```

**Run order:** Pre-fetch → Publishing → Security → then any of: Review, Brief, JSON Export

- **Pre-fetch** fetches all workflow YAML and composite action files from GitHub. No LLM calls. Run once, then everything reads from cache.
- **Publishing** classifies each workflow with an LLM call (Sonnet). Cached per-workflow — reruns only classify new/changed workflows.
- **Security** runs pattern-matching security checks on cached YAML. No LLM calls. Reads composite actions from prefetch cache.
- **Review** cross-references Publishing and Security data to produce the combined markdown report. No LLM calls, no API calls.
- **Brief** produces the one-page action plan from the same data. No LLM calls, no API calls.
- **JSON Export** reads the same data stores and produces structured JSON. No LLM calls, no API calls.

### Caching

All data is cached in CouchDB. After the initial run:

- **Re-running Pre-fetch** skips repos already cached (checks `__prefetch__` and `__composites__` meta keys)
- **Re-running Publishing** skips workflows already classified (checks `__meta__` and per-workflow keys)
- **Re-running Security** with `clear_cache: true` re-scans everything from cached YAML (fast — no API calls)
- **Review and JSON Export** always regenerate from current data (seconds to run)
- **Brief** always regenerates from current data (seconds to run)

### Input Schemas

| Agent | Inputs | Purpose |
|-------|--------|---------|
| Pre-fetch | `github_owner`, `read_pat` | Cache workflow YAML from GitHub |
| Publishing | `github_owner`, `redacted_severity` | LLM-classify workflows |
| Security | `github_owner`, `redacted_severity` | Pattern-match security checks |
| Review | `github_owner`, `redacted_severity` | Combined risk assessment |
| Brief | `github_owner`, `redacted_severity` | Executive action plan |
| JSON Export | `github_owner`, `redacted_severity` | Machine-readable export |
| Orchestrator | `github_owner`, `read_pat`, `write_private_repo`, `write_private_directory`, `write_private_pat`, `write_public_repo`, `write_public_directory`, `write_public_pat`, `redacted_severity` | Full pipeline |

Only Pre-fetch hits the GitHub API. All other agents read from CouchDB cache.

Set `redacted_severity` to `CRITICAL` to generate public reports with CRITICAL findings omitted. Leave empty for full reports. When set, agents skip CouchDB writes to preserve the full data for other agents to read.

---

## Limitations

- **LLM classification accuracy**: The Publishing agent uses Sonnet to classify workflows. Complex multi-stage workflows or unusual patterns may be misclassified. The `confidence` field in the JSON indicates the LLM's self-reported certainty.
- **Static analysis only**: The Security agent pattern-matches on YAML text. It does not resolve reusable workflow inputs, evaluate conditional expressions, or trace data flow across jobs. The `prt_checkout` check parses the `ref:` parameter, workflow permissions, and event types to assess severity, but complex indirection (e.g., ref passed through an intermediate variable or permissions inherited from org settings) may not be fully captured.
- **Point-in-time snapshot**: Results reflect workflow files at scan time. Repos may have changed since.
- **Composite action nesting**: Composite actions that call *other* composite actions are not recursively analyzed — only the top-level `.github/actions/*/action.yml` files are checked.
- **No runtime verification**: The analysis does not verify whether secrets are actually configured, whether branch protection rules prevent direct pushes, or whether the GITHUB_TOKEN permissions are effective given org-level settings.