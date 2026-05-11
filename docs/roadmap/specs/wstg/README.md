# `wstg` spec — implementation

Implementation of the OWASP Web Security Testing Guide spec for the
multi-spec audit pipeline. For the spec rationale, level/category
breakdown, discovery agent integration, and effort estimates, see
[../wstg.md](../wstg.md).

## Files

```
wstg/
├── wstg_catalog.py     Source-of-truth catalog. 125 tests as Python tuples,
│                       plus the curated CROSS_REFERENCES dict and the
│                       ID-derivation / URL-building helpers.
├── build_spec.py       Reads the catalog, emits the namespace JSON. Also
│                       carries DETECTION_HINTS — short prompts attached
│                       to each entry to anchor the audit agent.
└── out/
    ├── wstg-spec.json         All 125 entries.
    └── wstg-spec-static.json  115 entries with static_review_applicable=True.
                               This is what the static pipeline ingests.
```

Source: <https://github.com/OWASP/www-project-web-security-testing-guide/tree/master/latest>

## Building

```bash
python3 build_spec.py --out-dir ./out
```

Prints a coverage summary (counts by level, by category, list of
runtime-only entries) so changes to the catalog are easy to eyeball.

No dependencies beyond the Python stdlib.

## Ingestion

```python
import json
from data_store import use_namespace

spec_ns = use_namespace("wstg")
for entry in json.load(open("out/wstg-spec-static.json")):
    spec_ns.set(f"wstg:requirements:{entry['id']}", entry)
```

Then the orchestrator includes `wstg` in its `specs` input:

```json
{
  "namespaces": ["files:apache/steve/v3"],
  "specs": "asvs,wstg"
}
```

The audit agent looks up `wstg:requirements:WSTG-INPV-05` exactly as it
looks up `asvs:requirements:5.3.4`. No spec-specific code changes
needed — the architecture's promise of spec-agnostic agents holds.

## Maintenance

When OWASP adds or removes a test (the `latest/` tree drifts; this
happens a few times per year):

1. Add or modify a tuple in `WSTG_TESTS` in `wstg_catalog.py`. Tuple
   format is `(section, sub, sub_sub, title, page_slug, level,
   static_applicable)`.
2. Add cross-references to `CROSS_REFERENCES` if the test maps cleanly
   to an existing foreign-spec requirement.
3. Add a `DETECTION_HINTS` entry in `build_spec.py` if the test is
   static-applicable and high-frequency.
4. Re-run `build_spec.py`, re-ingest the namespace.

The catalog is intentionally a flat list of tuples so future
LLM-assisted maintenance (give the model the new TOC, ask it to diff
against `WSTG_TESTS`) is mechanical.

## Notes

**Versioning.** `spec_version` is hardcoded to `"latest"`. For
reproducible audits, change this to a Git commit SHA from the OWASP
repo before each run. See the versioning caveat in
[../wstg.md](../wstg.md) for context.

**Description hydration.** The `description` field in each entry is a
one-liner pointing at `canonical_url`. The audit agent should fetch the
full WSTG page at audit time. If you'd rather pre-fetch and inline the
methodology (Summary + How-to-Test sections), add a `--enrich` flag to
`build_spec.py` that hydrates each entry with full content. Trade-off:
~10× larger namespace, no runtime fetch dependency.

**Cross-references are curated, not exhaustive.** OWASP stripped the
WSTG↔ASVS mapping appendix from the `latest/` tree, so the
`CROSS_REFERENCES` dict in `wstg_catalog.py` is hand-built. After a few
end-to-end runs, mine the consolidator's "potential dedup candidates"
output for new pairs to add.
