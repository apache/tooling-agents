# How tooling-agents Complements ATR

ATR and tooling-agents are both developed by the Apache Tooling team. They operate at different stages of the software lifecycle and catch different classes of issues. Neither replaces the other — together they provide end-to-end security coverage from development through distribution.

## What ATR Verifies

ATR runs a verification pipeline on release artifacts before they reach mirrors. From the source code (`atr/tasks/checks/`):

**GPG signature verification** (`signature.py`) — Full cryptographic verification, not just "does .asc exist." ATR imports the PMC's public signing keys from the database, verifies the detached signature using `gnupg.GPG.verify_file()`, and confirms the signing key has an Apache UID. A valid signature from a non-ASF key is rejected. Reports key ID, fingerprint, timestamp, and trust level.

**Hash verification** (`hashing.py`) — Computes SHA-256 or SHA-512 from the actual artifact bytes and compares against the published hash file using timing-safe `secrets.compare_digest`. MD5 is forbidden; SHA-1 is deprecated. Hash mismatch is a blocker (not just a warning).

**Source-to-release comparison** (`compare.py`) — Clones the tagged Git source using `dulwich` and compares the file tree against the release archive. Catches unauthorized file additions, modifications, or deletions between the tagged source and what's actually in the release.

**License header enforcement** (`license.py`) — Scans source files across 25+ language patterns for Apache License headers. Checks for LICENSE and NOTICE file presence. Supports policy-configurable modes including Apache RAT integration.

**Release path validation** (`paths.py`) — Enforces ASF release policy: `.asc` signature required for every artifact, `.sha256` or `.sha512` required, `.md5` forbidden, binary `.sig` forbidden. Validates file naming and directory structure.

**CycloneDX SBOM generation** (`sbom/`) — Generates a CycloneDX Software Bill of Materials from the release, including component inventory, license data, and conformance scoring.

**OSV vulnerability scanning** (`sbom/osv.py`) — Queries the OSV API using PackageURLs extracted from the SBOM to identify known vulnerabilities in dependencies. Covers CVE, GHSA, and 30+ other vulnerability databases.

## What ATR Can't See

ATR operates on release artifacts. It doesn't have access to:

- **Source code logic** — SQL injection, XSS, authentication bypass, race conditions, and other code-level vulnerabilities are invisible at the artifact level. A perfectly signed release can contain critically vulnerable code.
- **CI/CD pipeline security** — ATR verifies the output of the build, not the build process itself. A compromised CI pipeline can produce a tampered artifact that a legitimate committer then signs and releases through ATR.
- **Development practices** — Whether the project has SECURITY.md, uses Dependabot, pins GHA actions to SHAs, or follows ASF OAuth patterns. ATR checks the release, not the repo.
- **Build provenance** — ATR verifies that a human (committer) signed the artifact. It doesn't verify that the build system was tamper-resistant or that the artifact is reproducible.

## Three Layers of Assurance

```
Development                    Build                        Distribution
┌────────────────────┐   ┌──────────────────┐   ┌──────────────────────┐
│  tooling-agents    │   │  tooling-agents  │   │  ATR                 │
│                    │   │  (SLSA assess.)  │   │                      │
│  • Code security   │   │  • Provenance    │   │  • GPG signature     │
│    (ASVS, CWE)     │   │    generation?   │   │    verification      │
│  • CI/CD security  │──▶│  • Build         │──▶│  • SHA-256/512 hash  │
│    (GHA Review)    │   │    isolation?    │   │  • Source-to-release  │
│  • ASF practices   │   │  • Reproducible  │   │    tree comparison   │
│    (Baseline)      │   │    builds?       │   │  • License/NOTICE    │
│                    │   │                  │   │  • SBOM + OSV scan   │
│                    │   │                  │   │  • TP provenance     │
└────────────────────┘   └──────────────────┘   └──────────────────────┘
```

## Per-Tool Complement

### ASVS / CWE Security Audit → ATR

The security audit pipeline checks the code inside the artifact. ATR checks the artifact itself.

| tooling-agents finds | ATR finds | Gap without both |
|---|---|---|
| SQL injection, XSS, auth bypass | — | Vulnerable code ships in signed releases |
| Missing rate limiting, weak crypto | — | ATR's OSV scan catches known CVEs but not novel vulnerabilities in project code |
| Hardcoded secrets in source | Source-to-release tree comparison (partial) | Secrets in git history may not appear in the release archive |
| Insecure session management | — | Application security is invisible to release verification |

### GHA Review → ATR

GHA Review checks the security of the build pipeline that produces the artifact ATR verifies.

| tooling-agents finds | ATR finds | Gap without both |
|---|---|---|
| Exploitable CI workflows (prt_checkout) | — | Compromised CI can produce a tampered artifact that a committer then signs and ATR accepts |
| Unpinned third-party actions | — | A compromised action can inject code into the build output before signing |
| Self-hosted runner exposure | — | Persistent build environment compromise |
| Missing CODEOWNERS on `.github/` | — | Anyone with merge access can change the release workflow |

### ASF Baseline → ATR

ASF Baseline is the shift-left version of ATR's release checks. Both care about the same things, but at different stages.

| ASF Baseline checks (development) | ATR checks (release) | Relationship |
|---|---|---|
| "Does the release workflow have a signing step?" | GPG signature verified against PMC keys with Apache UID check | Baseline catches missing signing before ATR rejects the release |
| "Are license headers in all source files?" | License header scan across 25+ language patterns | Both check headers — Baseline at commit time, ATR at release time |
| "Does CI check license compatibility?" | LICENSE/NOTICE presence, policy-configurable enforcement | Baseline enforces in CI so issues don't reach ATR |
| "Are dependencies scanned for vulnerabilities?" | OSV vulnerability scanning via SBOM PackageURLs | Both check deps — Baseline ensures scanning is in CI, ATR runs it at release |
| "Is SECURITY.md present?" | — | ATR doesn't check repo structure, only release artifacts |
| "Are GHA actions SHA-pinned?" | — | ATR doesn't check CI configuration |

### SLSA → ATR

SLSA has two sides: assessment (is the project configured for provenance?) and verification (does this artifact have valid provenance?). tooling-agents handles assessment by checking workflow files. ATR already does partial verification through its Trusted Publisher integration — it captures OIDC provenance payloads (commit SHA, workflow ref, runner environment) and exposes a `/signature/provenance` API.

| SLSA assessment (tooling-agents) | ATR already verifies | Gap: L3 |
|---|---|---|
| "Does the workflow generate provenance?" | ✅ Captures TP payload with build metadata | — |
| "Is provenance platform-authenticated?" | ✅ TP payload is OIDC-authenticated (though stored in ATR format, not SLSA format) | — |
| "Was the build environment ephemeral?" | — | ✅ tooling-agents checks for self-hosted runners |
| "Were build inputs fully declared?" | Source-to-release tree comparison (partial) | ✅ tooling-agents analyzes build config |
| "Is the build reproducible?" | Hash verification (SHA-256/512) | ✅ tooling-agents analyzes build system |

For projects already using ATR with GitHub Trusted Publishing, L1 and most of L2 are covered. The SLSA assessment from tooling-agents focuses on L3 — build environment properties that ATR can't see from the artifact alone.

## The Full Pipeline

For a project with all tools active:

```
1. Developer writes code
   └─ ASVS/CWE audit catches vulnerabilities in the code

2. Developer pushes to GitHub
   └─ GHA Review ensures CI workflows aren't exploitable
   └─ ASF Baseline checks license headers, SECURITY.md, SHA-pinned actions

3. CI runs, builds the artifact
   └─ SLSA verifies the build produced provenance, was isolated, is reproducible

4. Committer signs and submits the release
   └─ ATR verifies:
      • GPG signature against PMC keys (Apache UID required)
      • SHA-256/512 hash integrity
      • Source-to-release file tree match
      • License headers and LICENSE/NOTICE presence
      • SBOM generation and OSV vulnerability scan

5. Release reaches mirrors and end users
```

Without tooling-agents, steps 1–3 are unchecked. The code, CI, and build process are unverified — ATR only sees the final artifact.

## What Projects Get

| If a project uses... | They get... |
|---|---|
| ATR only | Release verification at distribution time |
| ATR + ASVS audit | Secure code inside verified artifacts |
| ATR + GHA Review | Secure build pipelines producing verified artifacts |
| ATR + ASF Baseline | Shift-left release checks — fix issues before they reach ATR |
| ATR + SLSA | Human attestation (ATR) + machine attestation (SLSA) |
| **All of the above** | Code security → CI security → build integrity → release verification |

## No Integration Required

tooling-agents and ATR don't need to integrate technically. They operate independently at different stages. The connection is informational:

- **ASF Baseline findings** predict ATR friction — "fix this now or ATR will reject your release later"
- **SLSA assessment** tells projects what's missing between "ATR accepts my release" and "my build process is tamper-resistant"
- **ASVS/CWE findings** address a class of risk ATR doesn't cover — the security of the code itself
- **GHA Review findings** address build pipeline security that ATR assumes is sound