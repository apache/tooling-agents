# Semgrep Static Analysis Findings

**Repository:** [apache/tooling-trusted-releases](https://github.com/apache/tooling-trusted-releases)
**Total findings:** 120 (119 medium, 1 high)
**Rules triggered:** 3

## Summary

| Rule | Severity | CWE | Count |
|---|---|---|---|
| `generic.html-templates.security.var-in-href` | Medium | CWE-79 (XSS) | 102 |
| `python.flask.security.xss.audit.template-unescaped-with-safe` | Medium | CWE-79 (XSS) | 17 |
| `python.lang.security.use-defused-xml` | High | CWE-611 (XXE) | 1 |

## Analyst commentary — read before triaging

Cross-reference all of these with [security-deep-dive.md → Ruled-out sinks](./security-deep-dive.md#ruled-out-sinks). The deep-dive examined the full data flow into these sinks and found no exploitable issue. The Semgrep alerts are **structural pattern matches**, not data-flow proofs.

**Three reasons most of these are non-exploitable:**

1. **The framework is Quart, not Flask.** The Semgrep `python.flask.*` rules misidentify the framework. Quart and Flask share Jinja2 autoescape semantics, so the rule still applies in principle — but the rule's recommendation to use `url_for()` is already followed throughout (it's the same function in Quart).

2. **Variables in `href` are server-built URLs, not user-controllable strings.** The 102 `var-in-href` alerts fire on patterns like `<a href="{{ download_url }}">` where `download_url` is constructed server-side from validated `safe.ProjectKey` / `safe.VersionKey` / `safe.RelPath` values. The deep-dive establishes that these safe types reject character classes that would be needed for `javascript:` URI injection (no colons in the validated identifier sets, no full-URL substitution into href). A `javascript:` URI cannot reach these placeholders.

3. **The `| safe` filter is applied to system-generated HTML.** The 17 `template-unescaped-with-safe` alerts fire on `{{ x | safe }}` patterns. Inspection (and deep-dive sinks S34/S35/S36) shows these are: (a) markdown that has already been processed by `cmarkgfm` in `CMARK_OPT_SAFE` mode (which strips raw HTML and `javascript:`/`data:` URLs), (b) developer-committed HTML in `docs/` that is not user-writable at runtime, or (c) htpy-built HTML which auto-escapes children.

**The single high-severity finding (F120) is in a `.pyi` type stub** (`src/typestubs/py_serializable/__init__.pyi:5`). Type stubs are not executable code — they are consumed only by Pyright/mypy. The alert is referencing the stub's `import xml.etree.ElementTree`, which is the type signature being declared, not actual XML parsing. The actual XML parsing in the application uses `defusedxml` (deep-dive S47).

**Recommendations (defense-in-depth, not vulnerability fixes):**

- Add a Content Security Policy (CSP) header that restricts `script-src` and forbids inline scripts. This would render `var-in-href` exploitation impossible even if a bug were introduced.
- Consider auditing each `| safe` use to confirm it is documented and necessary; some could be replaced with htpy-rendered children to reduce review surface.
- Suppress the F120 stub finding via Semgrep `nosemgrep` annotation or path exclusion to reduce noise.

## Findings — full list

### Rule: `generic.html-templates.security.var-in-href` (102 findings, Medium, CWE-79)

> Detected a template variable used in an anchor tag with the `href` attribute. This allows a malicious actor to input the `javascript:` URI and is subject to cross-site scripting (XSS) attacks.

| ID | File:Line |
|---|---|
| F1 | `src/atr/admin/templates/all-releases.html:27` |
| F2 | `src/atr/admin/templates/data-browser.html:69` |
| F3 | `src/atr/templates/check-selected-path-table.html:51` |
| F5 | `src/atr/templates/check-selected-path-table.html:73` |
| F6 | `src/atr/templates/check-selected-path-table.html:77` |
| F7 | `src/atr/templates/check-selected-path-table.html:80` |
| F8 | `src/atr/templates/check-selected-path-table.html:83` |
| F9 | `src/atr/templates/check-selected-path-table.html:86` |
| F10 | `src/atr/templates/check-selected-path-table.html:102` |
| F11 | `src/atr/templates/check-selected-path-table.html:117` |
| F12 | `src/atr/templates/check-selected-path-table.html:120` |
| F13 | `src/atr/templates/check-selected-release-info.html:10` |
| F14 | `src/atr/templates/check-selected-release-info.html:28` |
| F15 | `src/atr/templates/check-selected-release-info.html:44` |
| F16 | `src/atr/templates/check-selected-release-info.html:48` |
| F17 | `src/atr/templates/check-selected-release-info.html:57` |
| F18 | `src/atr/templates/check-selected-release-info.html:65` |
| F19 | `src/atr/templates/check-selected-release-info.html:70` |
| F20 | `src/atr/templates/check-selected-release-info.html:71` |
| F21 | `src/atr/templates/check-selected-release-info.html:79` |
| F22 | `src/atr/templates/check-selected-release-info.html:87` |
| F23 | `src/atr/templates/check-selected-release-info.html:92` |
| F24 | `src/atr/templates/check-selected-release-info.html:93` |
| F25 | `src/atr/templates/check-selected-release-info.html:101` |
| F26 | `src/atr/templates/check-selected-release-info.html:109` |
| F27 | `src/atr/templates/check-selected-release-info.html:119` |
| F28 | `src/atr/templates/check-selected-release-info.html:121` |
| F29 | `src/atr/templates/check-selected-release-info.html:124` |
| F30 | `src/atr/templates/check-selected-release-info.html:127` |
| F31 | `src/atr/templates/check-selected-vote-email.html:44` |
| F32 | `src/atr/templates/check-selected.html:37` |
| F35 | `src/atr/templates/check-selected.html:176` |
| F37 | `src/atr/templates/check-selected.html:233` |
| F41 | `src/atr/templates/committee-directory.html:96` |
| F42 | `src/atr/templates/committee-directory.html:123` |
| F43 | `src/atr/templates/committee-directory.html:157` |
| F44 | `src/atr/templates/committee-view.html:32` |
| F45 | `src/atr/templates/committee-view.html:48` |
| F46 | `src/atr/templates/committee-view.html:65` |
| F47 | `src/atr/templates/download-all.html:10` |
| F48 | `src/atr/templates/download-all.html:65` |
| F49 | `src/atr/templates/download-all.html:90` |
| F50 | `src/atr/templates/download-all.html:100` |
| F51 | `src/atr/templates/draft-tools.html:8` |
| F55 | `src/atr/templates/error.html:35` |
| F56–F92 | `src/atr/templates/includes/topnav.html` (lines 5, 33, 43, 47, 59, 64, 70, 88, 92, 118, 122, 126, 130, 134, 150, 155, 159, 216, 221, 226, 231, 236, 241, 247, 256, 261, 266, 274, 279, 284, 289, 297, 302, 307, 312, 317, 321) |
| F94 | `src/atr/templates/index-committer.html:90` |
| F95 | `src/atr/templates/index-committer.html:94` |
| F96 | `src/atr/templates/index-committer.html:99` |
| F97 | `src/atr/templates/index-committer.html:107` |
| F98 | `src/atr/templates/index-committer.html:148` |
| F99 | `src/atr/templates/notfound.html:30` |
| F100 | `src/atr/templates/project-select.html:14` |
| F101 | `src/atr/templates/projects.html:45` |
| F102 | `src/atr/templates/release-select.html:9` |
| F103 | `src/atr/templates/release-select.html:45` |
| F104 | `src/atr/templates/releases-finished.html:9` |
| F105 | `src/atr/templates/releases-finished.html:24` |
| F106 | `src/atr/templates/releases-finished.html:28` |
| F107 | `src/atr/templates/releases.html:32` |
| F108 | `src/atr/templates/report-selected-path.html:24` |
| F109 | `src/atr/templates/report-selected-path.html:27` |
| F110 | `src/atr/templates/report-selected-path.html:114` |
| F111 | `src/atr/templates/report-selected-path.html:301` |
| F112 | `src/atr/templates/resolve-tabulated.html:9` |
| F113 | `src/atr/templates/resolve-tabulated.html:47` |
| F114 | `src/atr/templates/resolve-tabulated.html:115` |
| F115 | `src/atr/templates/resolve-tabulated.html:157` |
| F116 | `src/atr/templates/user-ssh-keys.html:13` |
| F117 | `src/atr/templates/user-ssh-keys.html:14` |
| F118 | `src/atr/templates/user-ssh-keys.html:23` |
| F119 | `src/atr/templates/user-ssh-keys.html:29` |

The largest concentration (37 findings) is in `src/atr/templates/includes/topnav.html`, the shared top navigation template — these are all internal route URLs from the Quart routing system. A single CSP header on the application would address the entire class.

### Rule: `python.flask.security.xss.audit.template-unescaped-with-safe` (17 findings, Medium, CWE-79)

> Detected a segment of a Flask template where autoescaping is explicitly disabled with `| safe` filter. This allows rendering of raw HTML in this segment.

| ID | File:Line | Likely overlap with deep-dive sink |
|---|---|---|
| F4 | `src/atr/templates/check-selected-path-table.html:67` | rendered check-status HTML |
| F33 | `src/atr/templates/check-selected.html:119` | check status |
| F34 | `src/atr/templates/check-selected.html:138` | check status |
| F36 | `src/atr/templates/check-selected.html:180` | check status |
| F38 | `src/atr/templates/check-selected.html:239` | check status |
| F39 | `src/atr/templates/check-selected.html:240` | check status |
| F40 | `src/atr/templates/check-selected.html:245` | check status |
| F52 | `src/atr/templates/draft-tools.html:32` | rendered tool HTML |
| F53 | `src/atr/templates/draft-tools.html:41` | rendered tool HTML |
| F54 | `src/atr/templates/draft-tools.html:49` | rendered tool HTML |
| F93 | `src/atr/templates/includes/topnav.html:384` | nav-rendered HTML |

(F4 and F36 also appear in the var-in-href list; F33–F40 are the cluster around `check-selected.html`.)

These overlap with deep-dive sinks **S34** (checklist HTML rendering) and **S35** (vulnerability detail rendering) — both ruled out at Step 2 because the markdown is processed through cmarkgfm's `CMARK_OPT_SAFE` mode.

### Rule: `python.lang.security.use-defused-xml` (1 finding, **High**, CWE-611)

> The Python documentation recommends using `defusedxml` instead of `xml` because the native Python `xml` library is vulnerable to XML External Entity (XXE) attacks.

| ID | File:Line |
|---|---|
| F120 | `src/typestubs/py_serializable/__init__.pyi:5` |

This is a **type stub file** (`.pyi`), not executable code. The `import xml.etree.ElementTree` it contains is the type signature being declared by the stub for the `py_serializable` library. The actual XML parsing in ATR uses `defusedxml.ElementTree.fromstring()` — see deep-dive sink **S47** at `atr/svn/__init__.py:136`. **Recommendation:** suppress with `# nosemgrep` or exclude `**/*.pyi` from the relevant rule.

## Recommended remediation summary

| Action | Effort | Impact |
|---|---|---|
| Add CSP header (`Content-Security-Policy: default-src 'self'; script-src 'self'`) | Low | Eliminates `var-in-href` exploit path globally |
| Audit each `\| safe` filter use for documentation comment | Low–Med | Reduces review surface for future contributors |
| Exclude `**/*.pyi` from `use-defused-xml` rule | Trivial | Removes the false-positive high-severity finding |
| Configure Semgrep to identify Quart routing as Flask-equivalent | Low | Reduces noise in future scans |

## Cross-references

- Full data-flow analysis of these template sinks → [security-deep-dive.md](./security-deep-dive.md)
- Specifically S31–S36 (templating) and S47 (XML parsing)
