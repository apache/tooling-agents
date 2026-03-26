# ASVS Data Ingestion Instructions

## Purpose

You are responsible for fetching the ASVS source JSON and loading it into the document store. The source contains a nested hierarchy (chapters > sections > requirements) that must be flattened into three separate collections.

## Source

Fetch the source JSON from:

```
https://cdn.asvs.ee/standards/v5.0.0.json
```

## ID Normalization

The source JSON uses a "V" prefix on `chapter_id` and `section_id` values (e.g. `"V1"`, `"V1.2"`). **Strip the "V" prefix during ingestion.** All stored IDs must be plain numbers.

## Target Collections

Create three collections in the `asvs` namespace:

### `chapters` — key: `asvs:chapters:{chapter_id}`
Fields: chapter_id, chapter_name, control_objective, references

### `sections` — key: `asvs:sections:{section_id}`
Fields: section_id, chapter_id, section_name, description

### `requirements` — key: `asvs:requirements:{req_id}`
Fields: req_id, section_id, chapter_id, req_description, level

## Index Keys

Create auxiliary indexes for efficient lookups:

| Index key pattern | Value | Purpose |
|---|---|---|
| `asvs:section_index:{section_id}` | `["1.2.1", "1.2.2", ...]` | All req_ids in a section |
| `asvs:chapter_sections_index:{chapter_id}` | `["1.1", "1.2", ...]` | All section_ids in a chapter |
| `asvs:chapter_reqs_index:{chapter_id}` | `["1.1.1", "1.1.2", ...]` | All req_ids in a chapter |

## Validation

After ingestion, verify:
- All IDs globally unique
- All referential integrity constraints satisfied
- All level values are 1, 2, or 3
- All indexes contain correct child IDs
- No stored ID contains a "V" prefix

## Error Handling

If the source JSON is malformed, abort and report which record caused the failure. Do not partially commit.
