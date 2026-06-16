# ASVS Applicability: Web Applications, Libraries, and Backend Services

## Summary

OWASP ASVS v5.0.0 is explicitly designed for web applications. It's an excellent fit for projects like ATR and Steve — server-rendered web apps with authentication, session management, and user-facing endpoints. For libraries, CLI tools, and backend services without HTTP interfaces, ASVS has significant coverage gaps and many requirements that simply don't apply. This isn't a limitation of the pipeline — it's a limitation of the standard itself.

See the [ASVS pipeline documentation](../../ASVS/README.md) for how the pipeline works, and the [spec expansion plans](specs/) for how we plan to address this.

## Where ASVS Fits

ASVS v5.0.0 organizes 345 requirements across 17 chapters. The chapters map cleanly to web application concerns:

| Chapter | Topic | Web App Relevance |
|---------|-------|-------------------|
| 1 | Input Validation | Direct — HTTP parameters, form data, file uploads |
| 2 | Authentication | Direct — login flows, credential management |
| 3 | Session Management | Direct — cookies, tokens, session fixation |
| 4 | Access Control | Direct — authorization checks on endpoints |
| 5 | Output Encoding | Direct — XSS prevention, template rendering |
| 6 | Credential & Secret Management | Direct — password hashing, key storage |
| 7 | Session & Token Security | Direct — JWT, OAuth, CSRF tokens |
| 8 | Data Protection | Direct — PII handling, encryption at rest |
| 9 | Communication Security | Direct — TLS configuration, certificate pinning |
| 10 | Authorization | Direct — RBAC, permission checks |
| 11 | Cryptographic Controls | Broad — applies to any code using crypto |
| 12 | Transport Layer Security | Direct — HTTPS enforcement, HSTS |
| 13 | API & Web Services | Direct — REST/GraphQL security |
| 14 | Configuration | Broad — headers, error pages, server config |
| 15 | Build & Deployment | Broad — dependency management, CI/CD |
| 16 | Logging & Monitoring | Broad — audit trails, security event logging |
| 17 | Error Handling | Broad — exception handling, information leakage |

For a web app like ATR (Quart/Python, JWT auth, REST API, user-facing UI) or Steve (Quart/Python, OAuth, election management, document serving), nearly every chapter is directly applicable. The pipeline produces high-quality findings because the requirements align with the code's actual concerns.

## Where ASVS Doesn't Fit

### Libraries

A library like Apache Commons Lang, Arrow, or Parquet has no HTTP interface, no authentication system, no session management, and no user-facing UI. For a typical library:

| Chapter | Applicability | Why |
|---------|--------------|-----|
| 1 (Input Validation) | Partial | Libraries validate inputs, but not HTTP parameters |
| 2 (Authentication) | Not applicable | Libraries don't authenticate users |
| 3 (Session Management) | Not applicable | No sessions |
| 4 (Access Control) | Not applicable | No endpoints to protect |
| 5 (Output Encoding) | Not applicable | No HTML rendering |
| 6 (Credential Management) | Rarely | Unless the library handles credentials |
| 7 (Session & Token Security) | Not applicable | No tokens |
| 8 (Data Protection) | Partial | Memory handling, sensitive data in logs |
| 9 (Communication) | Partial | Only if library makes network calls |
| 10 (Authorization) | Not applicable | No users to authorize |
| 11 (Cryptography) | Full | If the library uses crypto |
| 12 (TLS) | Partial | Only if library manages TLS connections |
| 13 (API Security) | Not applicable | No API endpoints |
| 14 (Configuration) | Partial | Safe defaults, secure configuration |
| 15 (Build & Deployment) | Full | Dependency management, supply chain |
| 16 (Logging) | Partial | Sensitive data in log output |
| 17 (Error Handling) | Partial | Information leakage in exceptions |

Roughly 40-50% of ASVS requirements would be "Not applicable" for a typical library. Running the full pipeline would produce hundreds of "N/A" reports and a small number of findings concentrated in chapters 11, 15, and 17. The signal-to-noise ratio would be poor.

### Backend Services Without HTTP

A backend service like an Airflow DAG processor, a Kafka consumer, or a batch job runner might have internal APIs but no user-facing HTTP interface. ASVS assumes an HTTP request/response model throughout — many requirements reference "the application" receiving requests from "users" through "endpoints."

For these services, the applicable chapters are typically 6 (secrets), 8 (data protection), 11 (crypto), 15 (build), 16 (logging), and 17 (error handling). Authentication and session management chapters are irrelevant unless the service exposes an API.

### Infrastructure and Configuration Tools

Projects like Puppet modules, Terraform providers, or Ansible roles don't have a runtime — they generate configuration. ASVS has almost no coverage for configuration-as-code security concerns like privilege escalation in generated configs, secret injection patterns, or infrastructure drift detection.

## What's Missing from ASVS for Non-Web Projects

Even within the chapters that partially apply to libraries and backend services, ASVS has gaps:

**Memory safety** — ASVS has no requirements for buffer overflow prevention, use-after-free, integer overflow, or other memory safety concerns. For C/C++ libraries, these are the primary security risks. This is where tools like OSS-CRS (fuzzing) complement ASVS auditing.

**Supply chain integrity** — Chapter 15 covers dependency management at a high level, but doesn't address reproducible builds, SBOM generation, provenance attestation, or artifact signing in depth. The OpenSSF SLSA framework and Scorecard are better fits here.

**API contract security** — For libraries, the security boundary is the API surface: what happens when callers pass malicious inputs to public functions. ASVS doesn't model this — it assumes the application controls both sides of the interface.

**Concurrency and state** — Race conditions, TOCTOU bugs, deadlocks, and shared state corruption are critical for libraries and backend services. ASVS has minimal coverage (a few requirements about server-side race conditions in chapter 1).

**Serialization safety** — Deserialization vulnerabilities are a major concern for libraries that parse data formats (XML, JSON, YAML, Protocol Buffers). ASVS covers this lightly in input validation but doesn't go deep on format-specific attacks.

## Alternative Standards

| Standard | Best For | Coverage |
|----------|----------|----------|
| **OWASP ASVS v5.0.0** | Web applications | Authentication, sessions, access control, input/output, crypto, logging |
| **CWE Top 25** | Any software | Language-agnostic vulnerability patterns (injection, overflow, race conditions) |
| **OWASP SAMM** | Organizations | Software development lifecycle maturity (not code-level) |
| **OpenSSF Scorecard** | Any OSS project | Project hygiene (branch protection, SAST, dependency management) |
| **NIST SSDF** | Any software | Secure development practices (process-level, not code-level) |
| **OWASP MASVS** | Mobile apps | Mobile-specific: local storage, network, platform interaction |
| **SLSA** | Build systems | Supply chain integrity, provenance, reproducibility |

For libraries specifically, the CWE Top 25 is a better fit than ASVS — it covers memory safety, injection, race conditions, and other vulnerability classes that apply regardless of whether the code has an HTTP interface.

## Recommendation: How to Frame the Pipeline

When offering the ASVS pipeline to ASF projects, the framing should be:

**For web applications** (ATR, Steve, Airflow UI, Superset, any project with HTTP endpoints and user authentication): "We'll run a full ASVS L1-L3 audit against your codebase. This covers authentication, session management, access control, input validation, cryptography, logging, and more — 345 requirements total."

**For libraries and backend services**: "ASVS is designed for web applications, so many requirements won't apply to your project. We can still run it — the pipeline handles 'Not applicable' gracefully — but the findings will be concentrated in a few areas (crypto, error handling, dependency management, logging). For a more targeted assessment, we'd recommend complementing with Scorecard for project hygiene and, for C/C++ projects, OSS-CRS for memory safety fuzzing."

**For projects with mixed components** (e.g., Airflow has a web UI, a scheduler, worker processes, and a CLI): "We can scope the audit to the web-facing components using the path prefix feature: `apache/airflow/airflow/www` instead of the full repo. This gives you the most relevant ASVS coverage without generating hundreds of N/A reports for the scheduler and worker code."

## Future: Beyond ASVS

If the pipeline proves valuable and we want to extend it to non-web projects, the architecture supports it. The audit agent takes a requirement specification and code — it doesn't have to be ASVS. See the [spec expansion plans](specs/) for detailed implementation plans. In summary, we could:

1. **Create a "Library Security Profile"** — a curated subset of ASVS (chapters 11, 15, 16, 17) plus CWE Top 25 entries relevant to the project's language. Load this into the data store alongside ASVS.

2. **Add CWE-based auditing** — instead of ASVS sections, audit against CWE entries. The agent architecture is the same: requirement + code → analysis. The discovery agent would need to map CWEs to code areas instead of ASVS sections.

3. **Project-type detection** — the `discover_codebase_architecture` agent could classify the project type (web app, library, CLI tool, backend service) and recommend which audit profile to use.

None of this requires changes to the core pipeline — just new requirement data in the data store and updated discovery prompts.