# Security Deep-Dive

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Commit:** `837830e8a0a0b9989ec3decbdf2eb2f82a3f6640`
**Date:** 2026-05-07
**Spec version:** 12 · **Model:** claude-opus-4-6
**Files reviewed:** 137 · **Languages:** Python

## Executive summary

**Findings: 0 exploitable.** All 54 security-relevant sinks ruled out across three analysis steps. The codebase demonstrates strong defensive engineering through a comprehensive `safe.SafeType` hierarchy for path and identifier validation, with no use of `eval`/`exec`/`pickle`/`shell=True` or unsafe reflection.

## Scope and boundaries

ATR is a server application — not a library. Users interact via three authenticated channels (web UI/OAuth, SSH/public key, REST API/JWT) and outbound calls go to several trusted external APIs (OSV, GitHub OIDC, LDAP, SVN).

The trust model treats ASF committers and committee members as **partially trusted** — they are identified via OAuth/LDAP and can only act on projects they are authorized for, but their input is still validated. Public unauthenticated users can view checklists and download files but cannot modify state. Admins have elevated access. External APIs are trusted as data sources but their content is consumed defensively, not blindly executed.

### Trust boundaries

| Actor | Trust | Controls | Source |
|---|---|---|---|
| ASF Committer (web UI) | conditional | File uploads, release management, vote initiation, SBOM uploads, revision tagging, template editing for own projects. Validated through safe types (`ProjectKey`, `VersionKey`, `RelPath`, etc.). | `atr/web.py:62`; `atr/blueprints/common.py` |
| Public (unauthenticated web) | none | URL path segments for download and checklist routes. Validated through `safe.ProjectKey`, `safe.VersionKey`, `safe.RelPath`. | `atr/get/download.py:82`; `atr/get/checklist.py:37` |
| SSH client (committer or GitHub Actions) | conditional | rsync command string including project path, version path, optional tag. Validated through steps 3-6 in `ssh.py`, then `safe.ProjectKey` / `safe.VersionKey`. | `atr/ssh.py:319` |
| REST API client (JWT) | conditional | Structured JSON payloads validated by Pydantic models and quart-schema. File content as base64, file paths as `safe.RelPath`. | `atr/api/__init__.py`; `atr/jwtoken.py:133` |
| Admin user (web UI) | full | Key imports, JWT validation, system maintenance. `atr/user.py:is_admin()`. | `atr/admin/__init__.py`; `atr/blueprints/admin.py` |
| External API (OSV, GitHub OIDC, LDAP, SVN) | trusted | Vulnerability data, OIDC tokens, user directory info, release source files. Hardened TLS (1.2+, `CERT_REQUIRED`). | `atr/sbom/osv.py`; `atr/jwtoken.py:174`; `atr/ldap.py`; `atr/svn/__init__.py` |
| Committee member (release policy author) | conditional | Release policy templates (checklist markdown, vote/announce email bodies), file tag mappings (glob patterns). Scoped to their own committee's projects. | `atr/storage/writers/policy.py`; `atr/construct.py` |

## Sink primitives identified

| Class | Primitives |
|---|---|
| Command execution | `subprocess.run`, `subprocess.check_output`, `asyncio.create_subprocess_exec` |
| File operations | `open`, `aiofiles.open`, `quart.send_file`, `aiofiles.os.rename`, `aiofiles.os.remove`, `aioshutil.rmtree`, `aioshutil.move` |
| Path handling | `os.path.join`, `pathlib.Path.__truediv__`, `Path.resolve`, `Path.relative_to`, `safe.StatePath.__truediv__` |
| Archive extraction | `exarch.extract_archive`, `exarch.list_archive` |
| Deserialisation | `defusedxml.ElementTree.fromstring`, `strictyaml.load`, `json.loads`, `pydantic.model_validate` |
| Template | `markupsafe.Markup`, `cmarkgfm.github_flavored_markdown_to_html`, `str.replace` for variable substitution, htpy element children (auto-escaped) |
| Network | `aiohttp.ClientSession.get`/`.post` |
| Cryptography | `jwt.encode`/`decode`, `hashlib.sha3_256`/`sha512`, `hmac.compare_digest`, `secrets.token_hex`, `asyncssh.generate_private_key` |
| Shared mutable state | module-level dicts and variables |
| Concurrency | dict check-then-insert without lock |
| Resource consumption | `glob.glob`, `exarch.SecurityConfig` |
| Validation | `safe.RelPath`, `safe.StatePath`, `_validate_file_tag_mappings()` |

The codebase **does not** use any code-execution primitives (no `eval`, `exec`, `compile`, `__import__`), **does not** use `shell=True` in any subprocess call, **does not** use `pickle`/`marshal`/unsafe YAML, and **does not** use reflection with user-controlled attribute names. The `htpy` HTML builder auto-escapes all string children. `cmarkgfm` uses `CMARK_OPT_SAFE` (the only mode in the Python binding) which strips raw HTML, `javascript:`, and `data:` URLs.

## Sink inventory

54 sinks were enumerated. Below is the full table; each was evaluated and ruled out — see [Ruled-out sinks](#ruled-out-sinks) for the reasoning grouped by sink family.

| ID | Location | Class | Primitive | Consumes |
|---|---|---|---|---|
| S1 | `atr/tasks/checks/rat.py:207` | Command execution | `subprocess.run()` | Hardcoded RAT command + internal archive path + XML output path |
| S2 | `atr/tasks/checks/rat.py:427` | Command execution | `subprocess.check_output()` | Hardcoded `java -version` |
| S3 | `atr/tasks/checks/rat.py:437` | Command execution | `subprocess.run()` | Hardcoded `java -version` (fallback) |
| S4 | `atr/tasks/checks/rat.py:448` | Command execution | `subprocess.run()` | Hardcoded `which java` |
| S5 | `atr/tasks/checks/compare.py:275` | Command execution | `subprocess.run()` | rsync `--dry-run` with two `safe.StatePath` args |
| S6 | `atr/sbom/sbomqs.py:40` | Command execution | `subprocess.run()` | sbomqs with internal pipeline temp path |
| S7 | `atr/sbom/cyclonedx.py:49` | Command execution | `subprocess.run()` | cyclonedx-cli with internal file path + controlled env |
| S8 | `atr/svn/__init__.py:147` | Command execution | `asyncio.create_subprocess_exec()` | svn subcommand with caller-supplied path or URL |
| S9 | `atr/manager.py:162` | Command execution | `asyncio.create_subprocess_exec()` | Hardcoded python worker script path |
| S10 | `atr/ssh.py:735` | Command execution | `asyncio.create_subprocess_exec()` | rsync argv validated through steps 3-6, paths via `safe.ProjectKey`/`VersionKey` |
| S11 | `atr/tasks/sbom.py:236` | Command execution | `asyncio.create_subprocess_exec()` | sbomqs score with internal file path |
| S12 | `atr/tasks/sbom.py:427` | Command execution | `asyncio.create_subprocess_exec()` | syft with internal extract dir |
| S13 | `atr/tasks/svn.py:139` | Command execution | `asyncio.create_subprocess_exec()` | svn export with constant base URL + validated svn_url path |
| S14 | `atr/admin/__init__.py:1533` | Command execution | `asyncio.create_subprocess_exec()` | `keys_import.py` with `asf_uid` from OAuth session |
| S15 | `atr/get/download.py:227` | File operations | `quart.send_file()` | release dir + validated `safe.RelPath` |
| S16 | `atr/get/published.py:109` | File operations | `quart.send_file()` | downloads dir + validated `safe.RelPath` (test mode only) |
| S17 | `atr/storage/writers/release.py:747` | File operations | `aiofiles.open()` | `safe.StatePath / safe.RelPath(file.filename)` from multipart upload |
| S18 | `atr/storage/writers/release.py:705` | File operations | `aiofiles.open()` | base64 content + `safe.StatePath / safe.RelPath` from API |
| S19 | `atr/util.py:247` | File operations | `aiofiles.open()` | atomic write to caller-supplied path |
| S20 | `atr/hashes.py:39` | File operations | `aiofiles.open()` | internal hash-pipeline file path |
| S21 | `atr/storage/writers/keys.py:704` | File operations | `aiofiles.open()` | KEYS file path from managed state dir |
| S22 | `atr/get/docs.py:87` | File operations | `aiofiles.open()` | docs file validated via `resolve().relative_to(docs_root)` |
| S23 | `atr/get/download.py:213` | Path handling | `safe.StatePath.__truediv__()` | release dir / validated path from URL param |
| S24 | `atr/get/docs.py:69` | Path handling | `pathlib.Path.__truediv__()` | docs_dir / page from URL param, then resolve+relative_to check |
| S25 | `atr/get/published.py:119` | Path handling | `safe.StatePath.__truediv__()` | downloads_path / URL param (test mode only) |
| S26 | `atr/paths.py:159` | Path handling | `safe.StatePath.__truediv__()` | revision base / file_name from caller |
| S27 | `atr/models/safe.py:120` | Path handling | `StatePath.__truediv__()` | the validation primitive itself (RelPath + boundary check) |
| S28 | `atr/archives.py:60` | Archive extraction | `exarch.extract_archive()` | managed-storage archive with `SecurityConfig` limits |
| S29 | `atr/tasks/quarantine.py:213` | Archive extraction | `exarch.extract_archive()` | quarantined archive to staging with limits |
| S30 | `atr/tasks/sbom.py:403` | Archive extraction | `archives.extract()` | SBOM artifact archive to temp with `max_size` |
| S31 | `atr/construct.py:167-172` | Template | `str.replace()` | checklist markdown — project/committee names, revision, version, URLs |
| S32 | `atr/construct.py:246-267` | Template | `str.replace()` | vote email — project/committee names, URLs, duration, revision, ASF ID, fullname |
| S33 | `atr/construct.py:114-127` | Template | `str.replace()` | announce email — committee/project names, download URL, revision, user info |
| S34 | `atr/get/checklist.py:75` | Template | `Markup(cmarkgfm.github_flavored_markdown_to_html())` | substituted checklist markdown to HTML |
| S35 | `atr/get/sbom.py:567` | Template | `Markup(cmarkgfm.github_flavored_markdown_to_html())` | OSV/CycloneDX vulnerability details to HTML |
| S36 | `atr/get/docs.py:90` | Template | `markupsafe.Markup()` | developer-committed HTML in `docs/` |
| S37 | `atr/util.py:373` | Network | `aiohttp.ClientSession()` | hardened SSL context (TLS 1.2+, CERT_REQUIRED, hostname check) |
| S38 | `atr/jwtoken.py:174` | Network | `aiohttp.ClientSession.get()` | GitHub OIDC well-known endpoint, domain-whitelisted |
| S39 | `atr/sbom/osv.py:214` | Network | `aiohttp.ClientSession.get()` | OSV API URL with vuln ID |
| S40 | `atr/pubsub.py:84` | Network | `aiohttp.ClientSession()` | PubSub conn from configuration |
| S41 | `atr/jwtoken.py:89` | Cryptography | `jwt.encode()` | HS256 with claims (sub, iss, aud, iat, nbf, exp, jti) |
| S42 | `atr/jwtoken.py:130` | Cryptography | `jwt.decode(verify_signature=False)` | unverified decode for logging UID only |
| S43 | `atr/jwtoken.py:133` | Cryptography | `jwt.decode()` | full verification — signature, issuer, audience, expiration, required claims |
| S44 | `atr/jwtoken.py:213` | Cryptography | `jwt.decode()` | GitHub OIDC, JWKS, RS256, issuer/audience validation |
| S45 | `atr/noisy.py:230` | Cryptography | `hmac.compare_digest()` | timing-safe token comparison |
| S46 | `atr/ssh.py:244` | Cryptography | `asyncssh.generate_private_key()` | Ed25519 SSH host key |
| S47 | `atr/svn/__init__.py:136` | Deserialisation | `defusedxml.ElementTree.fromstring()` | `svn log --xml` stdout |
| S48 | `atr/storage/writers/policy.py:124` | Deserialisation | `strictyaml.load()` | committee form input with explicit schema |
| S49 | `atr/ssh.py:73-74` | Shared mutable state | module-level dict | rate-limit buckets |
| S50 | `atr/db/__init__.py:52-53` | Shared mutable state | module-level variable | SQLAlchemy engine + sessionmaker (set once at init) |
| S51 | `atr/ssh.py:303-316` | Concurrency | dict check-then-insert | rate-limit bucket without explicit lock (relies on GIL) |
| S52 | `atr/ssh.py:604-606` | Resource consumption | `glob.glob()` | file_tag_mappings patterns expanded against release dir |
| S53 | `atr/archives.py:96-113` | Resource consumption | `exarch.SecurityConfig` | extraction limits (size, count, ratio, depth) |
| S54 | `atr/storage/writers/policy.py:387-393` | Validation | `_validate_file_tag_mappings()` | committee mapping dict — checks traversal but not glob meta |

## Ruled-out sinks

All 54 sinks were ruled out at one of three steps:
- **Step 1** — *Internal*: no external input reaches the sink.
- **Step 2** — *Validated*: external input reaches the sink but is validated, scoped, or constrained such that exploitation requires capabilities the actor already has.
- **Step 3** — *Library-mitigated*: the sink delegates to a hardened library with built-in defenses against the relevant attack class.

### S1, S2, S3, S4, S9 — Hardcoded server-side tool invocations · Step 1
RAT and Java version checks are invoked with hardcoded command names. RAT (S1) gets archive paths constructed internally from validated `safe.StatePath` values within managed storage. S9 starts a worker via `sys.executable` + an internal module path. All five use array-based subprocess (no shell interpretation).

### S5 — Internal rsync tree comparison · Step 1
The dry-run rsync at `compare.py:275` takes two `safe.StatePath` arguments — a shallow git clone dir and an archive extraction dir, both constructed internally. Neither incorporates user strings.

### S6, S7, S11, S12 — SBOM tool invocations · Step 1
sbomqs/cyclonedx-cli/syft are invoked with temp file paths created by the SBOM pipeline. S11 verifies the path ends in `.cdx.json` and exists within managed state. All array-based subprocess.

### S8, S13 — SVN commands · Step 2
The SVN runner (S8) is generic; callers pass server-config values (token, paths). The export command (S13) builds URL as `f"{_SVN_BASE_URL}/{args.svn_url!s}"` where the base is the constant `https://dist.apache.org/repos/dist`. The `--` separator at line 97 prevents argument injection. `create_subprocess_exec` (no shell).

### S10 — rsync over SSH with multi-step validated argv · Step 2
The argv has passed four validation steps before execution: command structure check, `safe.ProjectKey` and `safe.VersionKey` validation (alphanumeric + limited chars), permission check. For writes the destination is rewritten to a `safe.StatePath`; for reads it is replaced with the validated release dir. The authenticated SSH user can only access releases within their authorized scope.

### S14 — keys_import.py with OAuth UID · Step 2
`asf_uid` originates from the OAuth session (`UserSession.uid`). The OAuth provider (ASF identity) is the authoritative trusted source. Even if the UID were unusual, `create_subprocess_exec` passes each argument as a separate execv element — no argument injection.

### S15, S23 — Release file download · Step 2
`download.py:213,227` constructs full path from release dir (`safe.StatePath`) + validated `safe.RelPath` from URL. `RelPath` rejects absolute paths, `..`, dotfiles, SCM dirs, double slashes, non-ASCII. `StatePath.__truediv__` re-validates and enforces `resolve().is_relative_to()`. Served with `as_attachment=True` and `application/octet-stream`. Comment at line 228 documents intent.

### S16, S25 — Test-only published file serving · Step 2
Gated behind `config.is_test_mode()` (returns 404 otherwise). Even in test mode, path uses `safe.StatePath / path`. Unreachable in production.

### S17, S18 — File uploads · Step 2
Multipart upload filename through `safe.RelPath(file.filename)` then `safe.StatePath.__truediv__` boundary check. API base64 path uses Pydantic `safe.RelPath`. Cannot escape the revision dir.

### S19, S20, S21 — Internal file I/O · Step 1
Atomic write utility, hash computation, KEYS file from committee storage — all internal callers with managed-state paths.

### S22, S24, S36 — Developer-committed docs · Step 1
`docs/` HTML files are part of the deployment artefact, not user-writable at runtime. Path traversal is blocked via `resolve().relative_to(docs_root)`. No upload path targets this directory.

### S26, S27 — Safe path operators (defensive primitives) · Step 1
These are the validation mechanisms themselves, not vulnerable sinks. `StatePath.__truediv__` validates every join through `RelPath` and re-checks the result stays within the managed root. The hierarchy is comprehensive: character whitelist, NFC normalisation, control-char rejection, traversal blocking, absolute-path rejection, resolve-based boundary enforcement.

### S28, S29, S30 — Archive extraction via exarch · Step 3
`exarch.SecurityConfig` (`archives.py:96-113`) sets limits: max file size, total size, 100k members, 100:1 compression ratio, 32 path depth, no hardlinks, no absolute paths. Symlinks are allowed but exarch constrains them to extraction root (line 103 comment). Destinations are managed dirs (revision temp, quarantine staging, SBOM temp). Library prevents zip-slip, zip-bomb, symlink escape.

### S31, S32, S33 — Template substitution · Step 2
`{{VARIABLE}}` placeholders in committee-authored templates. Substituted values are admin-set names, system URLs, validated `revision_tag`/`version_key`, OAuth-provided `asf_uid`, LDAP-provided `fullname`. No untrusted external data. Output contexts are plain-text email bodies and markdown processed by cmarkgfm in SAFE mode.

### S34 — Checklist HTML rendering · Step 2
Substituted markdown through `cmarkgfm.github_flavored_markdown_to_html()` (`CMARK_OPT_SAFE` is the only mode — replaces raw HTML with `<!-- raw HTML omitted -->`, sanitises `javascript:` and `data:`). Template is committee-authored for their own project; a malicious template only affects that committee's pages.

### S35 — Vulnerability details rendering · Step 2
Markdown sources: (1) the OSV API (`https://api.osv.dev`), a public security database maintained by Google, and (2) committee-uploaded CycloneDX SBOMs for their own projects. Same `CMARK_OPT_SAFE` processing. The `vuln_summary` is passed as plain string to htpy (auto-escaped).

### S37, S40 — Internal HTTPS clients · Step 1
`util.py:373` uses `create_secure_ssl_context()` (TLS 1.2+, CERT_REQUIRED, check_hostname). `pubsub.py:84` uses configuration URLs. Not user-controlled.

### S38 — OIDC discovery · Step 2
Fetches `.well-known/openid-configuration` from JWT `iss` claim. Function rejects dangerous JWT headers (`jku`, `x5u`, `jwk`) at lines 170-172. JWKS URI domain is whitelist-checked at line 205. Scheme must be HTTPS at line 209. The `iss` comes from a GitHub Actions OIDC token already authenticated through the SSH public-key flow.

### S39 — OSV API queries · Step 2
URL is `f"{_OSV_API_BASE}/vulns/{vuln_id}"` with `_OSV_API_BASE = "https://api.osv.dev/v1"` constant. `vuln_id` is a GHSA/CVE identifier; cannot redirect.

### S41, S43, S44, S45, S46 — Cryptographic operations · Step 1
JWT encode (HS256, 256-bit secret from `secrets.token_hex`), JWT decode with full verification + required claims, GitHub OIDC verification (RS256 + JWKS), `hmac.compare_digest`, Ed25519 SSH host key. All standard, correctly parameterised.

### S42 — Unverified JWT decode for logging · Step 1
`verify_signature=False` is used solely to extract `sub` for log messages before the verified decode at line 133. Unverified claims never reach authorization decisions. If verification fails, request is rejected.

### S47 — XML parsing · Step 1
`defusedxml.ElementTree.fromstring()` on stdout of local `svn log --xml`. Hardened against XXE, billion-laughs, etc.

### S48 — YAML parsing · Step 1
`strictyaml.load()` with explicit schema. strictyaml is a YAML subset — no tags, anchors, aliases, or arbitrary object construction. Schema restricts to map-of-strings-to-sequences-of-strings.

### S49, S50 — Module-level shared state · Step 1
SQLAlchemy engine/sessionmaker (S50) set exactly once during init, read-only thereafter. Rate-limit buckets (S49) are bounded by the cleanup loop and the GIL provides practical atomicity for single dict ops. Cannot be poisoned by one request to affect another's authorization.

### S51 — Rate-limit TOCTOU · Step 2
Theoretical window between length check and append; under CPython GIL the window is extremely narrow. Worst case: one extra connection in a 60-second window — the same user could retry anyway. Rate limit is defense-in-depth, not an authorization boundary.

### S52 — Glob expansion · Step 2
Patterns from `file_tag_mappings` set by committee members for their own projects. `_validate_file_tag_mappings()` (S54) checks `..`. Glob operates on `f"{source_dir}/{pattern}"` with `source_dir` a validated release-dir `safe.StatePath`. Even with `*`/`?`/`[...]`, expansion is bounded to the release tree; results go to rsync `--sender` for the authenticated committer who already has read access.

### S53 — Defensive resource limit configuration · Step 1
Not a sink — this is the mitigation for S28-S30.

### S54 — Glob meta validation gap · Step 2
Validation rejects `..` but not glob meta. Author and consumer of the patterns are the same trust principal (project committee). Glob result set is contained within the project's own release dir. Defense-in-depth gap, not an exploitable vulnerability.

## Prior art

Searched the Scrutineer advisories, dependents, and packages APIs — all returned empty. No prior CVE or GHSA advisories exist for this repository, and no downstream packages depend on it. The repo is alpha-stage internal ASF tooling, not a published library. See [advisories.md](./advisories.md) and [dependents.md](./dependents.md).

## Reach

This is a server application deployed by ASF Infrastructure, not a published library. Standard reach analysis (downstream dependent count) does not apply. The attack surface is the deployed instance: web UI, SSH server, REST API. All write operations require authentication; only download and checklist viewing are public.
