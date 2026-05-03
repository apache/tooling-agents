#!/usr/bin/env python3
"""
Tally ASVS audit findings by severity across all requirement reports.

Walks a root directory looking for markdown files that contain an ASVS audit
report with a "Finding Summary" severity table (Critical / High / Medium /
Low), parses the counts, and writes a summary markdown grouped by
requirement and by category.

Usage:
    python tally_findings.py [root_dir] [-o output.md]

Example layout it expects:
    ./python_rust_ffi_boundary/2.2.1.md
    ./python_rust_ffi_boundary/2.2.2.md
    ./auth/3.1.1.md
    ...
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

SEVERITIES = ["Critical", "High", "Medium", "Low"]

# Matches rows like:  | Critical | 0 | — |   or   | **Critical** | **0** | ... |
ROW_RE = re.compile(
    r"^\|\s*\**\s*(Critical|High|Medium|Low)\s*\**\s*"
    r"\|\s*\**\s*(\d+)\s*\**\s*\|",
    re.IGNORECASE,
)

# Matches the report header, e.g. "# ASVS 2.2.1 Security Audit Report"
HEADER_RE = re.compile(r"#\s*ASVS\s+([\d.]+)", re.IGNORECASE)


def parse_file(path: Path):
    """Return (requirement, {severity: count}) or (None, None) if not a report."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None

    header = HEADER_RE.search(text)
    if not header:
        return None, None
    requirement = header.group(1)

    counts = {sev: 0 for sev in SEVERITIES}
    found_any = False
    for line in text.splitlines():
        m = ROW_RE.match(line.strip())
        if m:
            counts[m.group(1).capitalize()] = int(m.group(2))
            found_any = True

    if not found_any:
        return None, None
    return requirement, counts


def category_for(path: Path, root: Path) -> str:
    """Top-level directory under root, or '(root)' if the file sits at root."""
    rel_parts = path.relative_to(root).parts
    return rel_parts[0] if len(rel_parts) > 1 else "(root)"


def requirement_sort_key(req: str):
    """Sort '2.2.1' numerically rather than lexicographically."""
    try:
        return tuple(int(p) for p in req.split("."))
    except ValueError:
        return (10**9, req)


def build_summary(rows, totals, by_category):
    lines = ["# ASVS Audit Findings Summary", ""]
    lines.append(f"_Generated from {len(rows)} requirement report(s)._")
    lines.append("")

    # Overall
    lines.append("## Overall Totals")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    grand = 0
    for sev in SEVERITIES:
        lines.append(f"| {sev} | {totals[sev]} |")
        grand += totals[sev]
    lines.append(f"| **Total** | **{grand}** |")
    lines.append("")

    # Per requirement
    lines.append("## By Requirement")
    lines.append("")
    lines.append("| Category | Requirement | Critical | High | Medium | Low | Total |")
    lines.append("|----------|-------------|---------:|-----:|-------:|----:|------:|")
    for category, requirement, counts in sorted(
        rows, key=lambda r: (r[0], requirement_sort_key(r[1]))
    ):
        total = sum(counts[s] for s in SEVERITIES)
        lines.append(
            f"| {category} | {requirement} | "
            f"{counts['Critical']} | {counts['High']} | "
            f"{counts['Medium']} | {counts['Low']} | {total} |"
        )
    lines.append("")

    # Per category
    lines.append("## By Category")
    lines.append("")
    lines.append("| Category | Critical | High | Medium | Low | Total |")
    lines.append("|----------|---------:|-----:|-------:|----:|------:|")
    for category in sorted(by_category):
        c = by_category[category]
        total = sum(c[s] for s in SEVERITIES)
        lines.append(
            f"| {category} | {c['Critical']} | {c['High']} | "
            f"{c['Medium']} | {c['Low']} | {total} |"
        )
    lines.append("")

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", nargs="?", default=".", help="Root directory to scan")
    p.add_argument(
        "-o", "--output",
        default="audit_summary.md",
        help="Output markdown path (default: audit_summary.md)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print each parsed/skipped file",
    )
    args = p.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    output_path = Path(args.output).resolve()

    rows = []
    totals = {sev: 0 for sev in SEVERITIES}
    by_category = defaultdict(lambda: {sev: 0 for sev in SEVERITIES})
    skipped = []

    for path in sorted(root.rglob("*.md")):
        if path.resolve() == output_path:
            continue
        requirement, counts = parse_file(path)
        if not requirement:
            skipped.append(path)
            if args.verbose:
                print(f"skip  {path.relative_to(root)}")
            continue
        category = category_for(path, root)
        rows.append((category, requirement, counts))
        for sev in SEVERITIES:
            totals[sev] += counts[sev]
            by_category[category][sev] += counts[sev]
        if args.verbose:
            print(f"parse {path.relative_to(root)} -> {requirement} {counts}")

    if not rows:
        print("warning: no ASVS reports found", file=sys.stderr)

    summary = build_summary(rows, totals, by_category)
    output_path.write_text(summary, encoding="utf-8")

    print(f"Parsed {len(rows)} report(s); skipped {len(skipped)} non-report .md file(s).")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
