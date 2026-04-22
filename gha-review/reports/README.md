# Apache GitHub CI Security Review

Automated analysis of GitHub Actions workflows across the Apache Software Foundation's repositories, answering two questions:

1. **Which projects publish packages to registries from CI?** (npm, PyPI, Maven Central, Docker Hub, crates.io, etc.)
2. **What are the security risks in those CI pipelines?**

> **Note:** Some high-severity findings may be omitted from this public report while remediation is in progress. The full unredacted analysis is available to ASF infrastructure and security teams.

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

**If you have 2 minutes:** Read the Executive Brief. It tells you what needs attention and when.

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
| **High Risk: Publishing Repos** | Repos that publish AND have HIGH-severity findings |
| **Latent Risk: Composite Action Injection** | Publishing repos with composite actions that interpolate inputs — not exploitable today, one unsafe caller away |
| **Systemic Issues** | Org-wide problems: trusted publishing migration, unpinned actions, missing CODEOWNERS |
| **Recommended Actions** | Numbered, timeframed: "fix this week", "this quarter", etc. |
| **Full Analysis** | Links to all other reports |

### How to Read It

- **Share this with leadership and the security team.** It's designed to be read in 2 minutes and forwarded without explanation.
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
| **Immediate Attention Required** | HIGH repos that *also publish packages* — highest supply-chain risk |
| **Non-Publishing Repos with HIGH Findings** | HIGH-severity repos that don't publish (CI-only risk, no supply-chain impact) |
| **Moderate Risk** | Publishing repos with MEDIUM findings (typically unpinned actions) |
| **Low Risk** | Publishing repos with only LOW/INFO findings |
| **Trusted Publishing Opportunities** | Repos using long-lived tokens where OIDC is available |
| **Key Recommendations** | Numbered action items with links to details |

### How to Read It

- **Immediate Attention repos** are your top priorities — they publish packages AND have exploitable vulnerabilities
- **Non-Publishing HIGH repos** are next — important but no supply-chain blast radius
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
| **Executive Summary** | Severity breakdown: HIGH, MEDIUM, LOW, INFO |
| **Findings by Check Type** | Which checks found what, with counts |
| **HIGH / MEDIUM / LOW / INFO Findings** | All findings grouped by severity |
| **Detailed Results by Repository** | Per-repo: all findings sorted by severity with file and detail |

### Check Types (Severity Order)

| Check | Severity | What It Detects |
|-------|----------|-----------------|
| `prt_checkout` | HIGH–LOW | `pull_request_target` + checkout of PR head code. Severity depends on permissions and trigger type. |
| `self_hosted_runner` | HIGH–LOW | Self-hosted runners exposed to PR triggers — persistent compromise risk. Severity depends on permissions and trigger type. |
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

- **HIGH findings are active risks** — self-hosted runner exposure, PR target checkout with broad permissions, or other patterns that could be exploited
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
      "severity": "HIGH|MEDIUM|LOW|INFO",
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
    "ecosystem_counts": {
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
      "total_findings": 4200,
      "repos_with_findings": 1190,
      "severity_counts": {
        "HIGH": 195, "MEDIUM": 599,
        "LOW": 2487, "INFO": 1321
      },
      "check_counts": {
        "missing_codeowners": 1176,
        "unpinned_actions": 498, ...
      }
    }
  },

  "repos": [                                // One entry per repo
    {
      "repo": "apache/commons-lang",
      "has_workflows": true,
      "total_workflows": 5,
      "publishes_to_registry": true,
      "ecosystems": ["maven_central"],
      "category_counts": {
        "release_artifact": 1
      },
      "trusted_publishing": {
        "migration_needed": false,
        "eligible_ecosystems": []
      },
      "security": {
        "total_findings": 4,
        "worst_severity": "MEDIUM",
        "severity_counts": {"MEDIUM": 1, "LOW": 2, "INFO": 1},
        "check_counts": {"unpinned_actions": 1, "missing_codeowners": 1, "missing_dependency_updates": 1, "third_party_actions": 1}
      },
      "workflows": [
        {
          "file": "maven-release.yml",
          "workflow_name": "Release to Maven Central",
          "publishes": true,
          "category": "release_artifact",
          "ecosystems": ["maven_central"],
          "trigger": "workflow_dispatch",
          "auth_method": "secrets.NEXUS_USER / secrets.NEXUS_PW",
          "publish_actions": [],
          "publish_commands": ["mvn deploy -P apache-release"],
          "summary": "Publishes release artifacts to Maven Central via Nexus staging.",
          "confidence": "high",
          "security_notes": []
        }
      ],
      "findings": [
        {
          "severity": "MEDIUM",
          "check": "unpinned_actions",
          "file": "(repo-wide)",
          "detail": "3 unpinned third-party action refs (outside actions/*/github/*/apache/*)."
        },
        {
          "severity": "LOW",
          "check": "missing_codeowners",
          "file": "(missing)",
          "detail": "No CODEOWNERS file. Workflow changes have no mandatory review."
        },
        {
          "severity": "LOW",
          "check": "missing_dependency_updates",
          "file": "(missing)",
          "detail": "No dependabot.yml or renovate.json found."
        },
        {
          "severity": "INFO",
          "check": "third_party_actions",
          "file": "(repo-wide)",
          "detail": "3 third-party actions: codecov/codecov-action, ..."
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
  high: .summary.security.severity_counts.HIGH,
  medium: .summary.security.severity_counts.MEDIUM
}' json-export.json

# Top 10 ecosystems
jq '.summary.ecosystem_counts | to_entries | sort_by(-.value) | .[0:10] | from_entries' json-export.json

# Top vulnerability types by count
jq -r '.summary.security.check_counts | to_entries | sort_by(-.value) | .[0:10] | .[] | "\(.value)\t\(.key)"' json-export.json
```

### Find Repos by Vulnerability

```bash
# All repos with HIGH findings
jq '[.repos[] | select(.security.worst_severity == "HIGH") | .repo]' json-export.json

# All repos with a specific check type (e.g., self_hosted_runner)
jq '[.repos[] | select(.security.check_counts.self_hosted_runner > 0) | {repo, count: .security.check_counts.self_hosted_runner}]' json-export.json

# Repos with composite action injection that also publish
jq '[.repos[] | select(.publishes_to_registry and .security.check_counts.composite_action_input_injection > 0) | {repo, ecosystems, findings: .security.total_findings}]' json-export.json

# All repos missing CODEOWNERS that publish to npm
jq '[.repos[] | select(.security.check_counts.missing_codeowners > 0 and (.ecosystems | index("npm"))) | .repo]' json-export.json
```

### Full Repo Summary

```bash
# Everything about a specific repo
jq '.repos[] | select(.repo == "apache/commons-lang")' json-export.json

# Repo security summary (no workflow/finding details)
jq '.repos[] | select(.repo == "apache/commons-lang") | {repo, publishes: .publishes_to_registry, ecosystems, security, trusted_publishing}' json-export.json

# Just findings for a repo, sorted by severity
jq '.repos[] | select(.repo == "apache/commons-lang") | .findings | sort_by(if .severity == "HIGH" then 0 elif .severity == "MEDIUM" then 1 elif .severity == "LOW" then 2 else 3 end)' json-export.json

# Findings with line numbers (for linking to source)
jq '[.repos[] | select(.repo == "apache/commons-lang") | .findings[] | select(.line) | {file, line, severity, check}]' json-export.json
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
# Priority list: repos sorted by risk (HIGH first, then by finding count)
jq '[.repos[] | select(.security.total_findings > 0) | {
  repo,
  worst: .security.worst_severity,
  findings: .security.total_findings,
  publishes: .publishes_to_registry,
  ecosystems
}] | sort_by([
  (if .worst == "HIGH" then 0 elif .worst == "MEDIUM" then 1 else 2 end),
  (-.findings)
])' json-export.json

# Repos with HIGH that publish — your priority list
jq '[.repos[] | select(
  .publishes_to_registry and
  .security.worst_severity == "HIGH"
) | {repo, worst: .security.worst_severity, ecosystems, findings: .security.total_findings}]' json-export.json

# Generate a remediation CSV
jq -r '.repos[] | select(.security.total_findings > 0) |
  [.repo, .security.worst_severity, (.security.total_findings | tostring),
   (.publishes_to_registry | tostring), (.ecosystems | join(";")),
   (.trusted_publishing.migration_needed | tostring)] | @csv' json-export.json

# Get the attack scenario for a specific check
jq '.check_definitions.self_hosted_runner' json-export.json
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

Seven agents share data via CouchDB namespaces:

```
Pre-fetch ──→   ci-workflows:{github_owner}   (YAML cache + composites + extras)
       │
Publishing ──→  ci-classification:{github_owner}   (LLM classifications)
       │        ci-report:{github_owner}           (report + stats)
       │
Security ──→    ci-security:{github_owner}         (findings + stats)
       │
Review ──→      ci-combined:{github_owner}         (combined report)
       │
Brief ──→       ci-combined:{github_owner}         (executive brief)
       │
JSON Export ──→ ci-combined:{github_owner}         (JSON export)

Orchestrator    Runs all of the above, pushes private + public reports to GitHub
```

**Run order:** Pre-fetch → Publishing → Security → then any of: Review, Brief, JSON Export

- **Pre-fetch** fetches all workflow YAML and composite action files from GitHub. No LLM calls. Run once, then everything reads from cache.
- **Publishing** classifies each workflow with an LLM call (Sonnet). Cached per-workflow — reruns only classify new/changed workflows.
- **Security** runs pattern-matching security checks on cached YAML. No LLM calls. Reads composite actions and extras from prefetch cache.
- **Review** cross-references Publishing and Security data to produce the combined markdown report. No LLM calls, no API calls.
- **Brief** produces the one-page action plan from the same data. No LLM calls, no API calls.
- **JSON Export** reads the same data stores and produces structured JSON. No LLM calls, no API calls.

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

Set `redacted_severity` to `CRITICAL` to generate public reports with findings at that severity omitted. Leave empty for full reports. When set, agents skip CouchDB writes to preserve the full data for other agents to read.

---

## Limitations

- **LLM classification accuracy**: The Publishing agent uses Sonnet to classify workflows. Complex multi-stage workflows or unusual patterns may be misclassified. The `confidence` field in the JSON indicates the LLM's self-reported certainty.
- **Static analysis only**: The Security agent pattern-matches on YAML text. It does not resolve reusable workflow inputs, evaluate conditional expressions, or trace data flow across jobs. The `prt_checkout` check parses the `ref:` parameter, workflow permissions, and event types to assess severity, but complex indirection (e.g., ref passed through an intermediate variable or permissions inherited from org settings) may not be fully captured.
- **Point-in-time snapshot**: Results reflect workflow files at scan time. Repos may have changed since.
- **Composite action nesting**: Composite actions that call *other* composite actions are not recursively analyzed — only the top-level `.github/actions/*/action.yml` files are checked.
- **No runtime verification**: The analysis does not verify whether secrets are actually configured, whether branch protection rules prevent direct pushes, or whether the GITHUB_TOKEN permissions are effective given org-level settings.