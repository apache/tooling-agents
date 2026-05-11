#!/usr/bin/env python3
"""
Build the WSTG spec dataset for the multi-spec audit pipeline.

Produces two artifacts:

  1. wstg-spec.json
     A flat list of all WSTG requirements, conforming to the multi-spec
     architecture's data store schema. Drop this into the `wstg` namespace,
     one key per entry: `wstg:requirements:{id}` → entry.

  2. wstg-spec-static.json
     Same data, filtered to entries where static_review_applicable is True.
     This is the recommended subset for the existing static-review pipeline.
     The remaining ~12 runtime-only entries stay in the full dataset for
     future use by a runtime/DAST audit agent.

Schema (matches the architecture doc):

    id                          required, "WSTG-INPV-05"
    title                       required, human-readable
    description                 required, short summary; full content at url
    level                       required, 1/2/3 (assigned in catalog)
    spec                        required, "wstg"
    spec_version                "latest" (WSTG doesn't tag stable versions
                                in /latest/; pin to a commit SHA in prod)
    category                    section name, e.g. "input validation"
    languages                   ["all"] — WSTG is language-agnostic
    cross_references            mapping of foreign spec → list of req IDs
    detection_methods           hints (kept short; full guidance at url)
    static_review_applicable    True/False — pipeline filter
    parent_id                   non-null for sub-tests (e.g. SQL-by-DBMS)
    canonical_url               public OWASP page URL
    source_url                  GitHub source markdown URL
    section_path                "4.7.5" or "4.7.5.1"

Usage:
    python build_spec.py --out-dir ./out

To load into the data store:
    spec_ns = data_store.use_namespace("wstg")
    for entry in json.load(open("wstg-spec.json")):
        spec_ns.set(f"wstg:requirements:{entry['id']}", entry)
"""

import argparse
import json
import sys
from pathlib import Path

from wstg_catalog import (
    WSTG_TESTS,
    CROSS_REFERENCES,
    derive_id,
    parent_id,
    canonical_url,
    github_url,
    category,
)


# Short detection hints per top-level test. These are starter prompts for the
# audit agent — the agent should fetch the canonical URL for the full
# methodology when needed. Keys are WSTG IDs; missing entries get a generic
# "see canonical_url" hint at build time.
DETECTION_HINTS = {
    "WSTG-CONF-06":  ["Look for route definitions accepting unintended HTTP methods (TRACE, OPTIONS, PUT, DELETE) without explicit handling."],
    "WSTG-CONF-07":  ["Search for HSTS header configuration; verify max-age >= 31536000 and includeSubDomains."],
    "WSTG-CONF-12":  ["Search for Content-Security-Policy header configuration; verify no 'unsafe-inline'/'unsafe-eval' in script-src."],
    "WSTG-CONF-14":  ["Check for X-Content-Type-Options: nosniff, X-Frame-Options or CSP frame-ancestors, Referrer-Policy, Permissions-Policy."],
    "WSTG-ATHN-01":  ["Find login forms / auth endpoints. Verify they require HTTPS and that credentials never appear in URLs or query strings."],
    "WSTG-ATHN-02":  ["Search for hardcoded credentials, default admin accounts, sample users in seed/migration files, README admin creds."],
    "WSTG-ATHN-09":  ["Locate password reset / change flows. Check token entropy, single-use, expiry, rate limiting, lack of user enumeration in responses."],
    "WSTG-ATHN-11":  ["Identify MFA enrollment and verification code paths. Check rate limiting, code reuse, fallback weakening, recovery code handling."],
    "WSTG-ATHZ-01":  ["Find file path / include / template-load operations using user input. Check for ../, encoded traversal, absolute path acceptance."],
    "WSTG-ATHZ-02":  ["Compare auth checks across endpoints. Look for missing decorators, role checks bypassed by parameter manipulation, IDOR-adjacent gaps."],
    "WSTG-ATHZ-03":  ["Look for role/privilege fields in user input or session data that are trusted without server-side verification."],
    "WSTG-ATHZ-04":  ["Find handlers that load resources by ID from user input without an ownership/permission check."],
    "WSTG-SESS-02":  ["Search session/cookie configuration. Verify Secure, HttpOnly, SameSite are set; check Path and Domain scoping."],
    "WSTG-SESS-03":  ["Check that login regenerates session IDs (no fixation). Look for session_regenerate_id, login.session.cycle, etc."],
    "WSTG-SESS-05":  ["Identify state-changing endpoints (POST/PUT/PATCH/DELETE). Verify CSRF token middleware or SameSite=Strict cookie posture."],
    "WSTG-SESS-07":  ["Find session timeout configuration; verify both idle and absolute timeouts are enforced."],
    "WSTG-SESS-10":  ["Locate JWT issuance and verification. Check algorithm allowlist (no 'none', no HS/RS confusion), expiry, signing-key rotation, claim validation."],
    "WSTG-INPV-01":  ["Find templates rendering user input without escaping. Check for raw|safe filters, dangerouslySetInnerHTML, innerHTML assignments."],
    "WSTG-INPV-02":  ["Trace user input that is persisted (DB, file, cache) and later rendered. Check for escaping at output, not just input."],
    "WSTG-INPV-05":  ["Find query construction with string interpolation/concatenation. Flag .format/f-strings/% with user input, raw cursor.execute, ORM raw()."],
    "WSTG-INPV-07":  ["Look for XML parsing (lxml, xml.etree, defusedxml absence). Check for external entity disabling, DTD disabling."],
    "WSTG-INPV-11":  ["Search for eval, exec, compile, Function() constructor, vm.runInContext — flag any with user-influenced input."],
    "WSTG-INPV-12":  ["Search for shell invocation: subprocess with shell=True, os.system, popen, Runtime.exec, child_process.exec — flag user-influenced args."],
    "WSTG-INPV-18":  ["Find template engine usage (Jinja2, Twig, ERB, Handlebars). Flag template strings constructed from user input."],
    "WSTG-INPV-19":  ["Find HTTP client calls (requests.get, urllib, fetch, axios) with URL or host derived from user input. Check for allowlist / metadata-IP blocking."],
    "WSTG-INPV-20":  ["Find ORM/serializer bulk-assign patterns (Model(**data), update(**data), Object.assign). Check for explicit field allowlists."],
    "WSTG-ERRH-01":  ["Find global exception handlers. Check that responses don't leak stack traces, query fragments, file paths, or internal IPs in production."],
    "WSTG-ERRH-02":  ["Search for debug/development settings active in production paths (DEBUG=True, app.debug, NODE_ENV checks)."],
    "WSTG-CRYP-03":  ["Find HTTP (non-S) requests, plaintext credential storage, plaintext PII in logs, unencrypted DB columns for sensitive fields."],
    "WSTG-CRYP-04":  ["Search for MD5, SHA1, DES, RC4, ECB mode, hardcoded IVs, hardcoded keys, weak random (random.random for security)."],
    "WSTG-CLNT-01":  ["Find client-side use of location.hash, document.URL, window.name written to innerHTML, document.write, eval, or Function()."],
    "WSTG-CLNT-07":  ["Search for Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true; reflected origins without allowlist."],
    "WSTG-CLNT-09":  ["Verify pages set X-Frame-Options or CSP frame-ancestors, especially state-changing or auth-sensitive pages."],
    "WSTG-APIT-02":  ["For each API endpoint accepting an object ID, verify ownership/permission check before action."],
    "WSTG-APIT-03":  ["Find API responses that return whole records. Check for serializer field allowlists; flag select_all / *.dict() patterns."],
    "WSTG-APIT-04":  ["Compare admin vs user endpoint authorization. Look for endpoints whose only protection is URL obscurity or client-side hiding."],
}


def short_description(title: str) -> str:
    """One-line description for the audit agent prompt header. The full
    methodology lives at canonical_url and should be fetched on demand."""
    return f"OWASP WSTG: {title}. Full methodology at canonical_url."


def build_entry(section, sub, sub_sub, title, slug, level, static_app):
    wid = derive_id(section, sub, sub_sub)
    pid = parent_id(section, sub, sub_sub)
    xrefs = CROSS_REFERENCES.get(wid, {})
    detect = DETECTION_HINTS.get(wid, [f"See methodology at {canonical_url(section, slug)}"])

    entry = {
        "id":                       wid,
        "title":                    title,
        "description":              short_description(title),
        "level":                    level,
        "spec":                     "wstg",
        "spec_version":             "latest",
        "category":                 category(section),
        "languages":                ["all"],
        "cross_references":         xrefs,
        "detection_methods":        detect,
        "static_review_applicable": static_app,
        "canonical_url":            canonical_url(section, slug),
        "source_url":               github_url(section, slug),
        "section_path":             (f"4.{section}.{sub}" if sub_sub is None
                                     else f"4.{section}.{sub}.{sub_sub}"),
    }
    if pid is not None:
        entry["parent_id"] = pid
    return entry


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default="./out", help="Where to write JSON")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    full = [build_entry(*t) for t in WSTG_TESTS]

    # Sanity: IDs must be unique
    ids = [e["id"] for e in full]
    assert len(ids) == len(set(ids)), "duplicate WSTG IDs detected"

    static = [e for e in full if e["static_review_applicable"]]
    runtime = [e for e in full if not e["static_review_applicable"]]

    (out / "wstg-spec.json").write_text(json.dumps(full, indent=2) + "\n")
    (out / "wstg-spec-static.json").write_text(json.dumps(static, indent=2) + "\n")

    # Coverage report
    by_level = {1: 0, 2: 0, 3: 0}
    by_cat = {}
    xref_count = 0
    for e in full:
        by_level[e["level"]] += 1
        by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
        if e["cross_references"]:
            xref_count += 1

    print(f"Wrote {out}/wstg-spec.json ({len(full)} entries)")
    print(f"Wrote {out}/wstg-spec-static.json ({len(static)} entries)")
    print()
    print(f"Total tests:           {len(full)}")
    print(f"Static-applicable:     {len(static)}")
    print(f"Runtime-only:          {len(runtime)}")
    print(f"With cross-references: {xref_count}")
    print()
    print("By level:")
    for lvl in (1, 2, 3):
        print(f"  L{lvl}: {by_level[lvl]}")
    print()
    print("By category:")
    for cat in sorted(by_cat):
        print(f"  {cat:40s} {by_cat[cat]}")
    print()
    print("Runtime-only tests (excluded from static audit):")
    for e in runtime:
        print(f"  {e['id']:18s} {e['title']}")


if __name__ == "__main__":
    sys.exit(main())
