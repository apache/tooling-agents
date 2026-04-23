# OWASP API Security Top 10 Integration

## Overview

The [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/) addresses security risks specific to APIs. Many ASF projects are API-first (Airflow REST API, Solr, CouchDB, Kafka Connect REST) where the primary interface isn't a browser-rendered page but a programmatic API consumed by other services.

ASVS covers many of the same concerns, but the API Top 10 frames them from an API-specific perspective — excessive data exposure through API responses, mass assignment from unvalidated request bodies, broken function-level authorization on API endpoints. This framing produces more actionable findings for API-heavy projects.

## The 10 Requirements

| ID | Name | ASVS Overlap | Unique Value |
|---|---|---|---|
| API1 | Broken Object Level Authorization | 4.1, 4.2, 10.x | API-specific IDOR patterns |
| API2 | Broken Authentication | 2.x, 7.x | API token/key lifecycle, stateless auth |
| API3 | Broken Object Property Level Authorization | 4.x, 8.x | Mass assignment, excessive data in responses |
| API4 | Unrestricted Resource Consumption | 2.4 (partial) | Rate limiting, pagination, query complexity |
| API5 | Broken Function Level Authorization | 4.x, 10.x | Admin vs user API endpoint separation |
| API6 | Unrestricted Access to Sensitive Business Flows | Minimal | Business logic abuse via API automation |
| API7 | Server Side Request Forgery | 1.x (partial) | SSRF specific to API integrations |
| API8 | Security Misconfiguration | 14.x | API-specific: CORS, error responses, HTTP methods |
| API9 | Improper Inventory Management | Minimal | Undocumented endpoints, API versioning, shadow APIs |
| API10 | Unsafe Consumption of APIs | 13.x (partial) | Third-party API integration risks |

## Why It's Low Effort

Most of the API Top 10 maps to existing ASVS sections. The primary value is:

1. **Reframing**: API3 (Broken Object Property Level Authorization) is more specific than ASVS 4.x for API responses — it explicitly asks "does the API return more fields than the client needs?"
2. **Gap filling**: API6 (Unrestricted Access to Sensitive Business Flows) and API9 (Improper Inventory Management) have minimal ASVS coverage
3. **API-specific detection**: API4 asks about query complexity limits and pagination — things ASVS doesn't cover directly

## Data Store Schema

```
Namespace: api-top-10
Key: api-top-10:requirements:API1

{
  "id": "API1",
  "title": "Broken Object Level Authorization",
  "description": "APIs tend to expose endpoints that handle object identifiers, creating a wide attack surface of Object Level Access Control issues. Object level authorization checks should be considered in every function that accesses a data source using an ID from the user.",
  "level": 1,
  "category": "authorization",
  "spec": "api-top-10",
  "spec_version": "2023",
  "detection_focus": [
    "API endpoints that accept object IDs as parameters",
    "Missing authorization checks before returning objects",
    "Predictable/sequential object IDs",
    "Horizontal privilege escalation through ID manipulation"
  ],
  "cross_references": {
    "asvs": ["4.1.1", "4.1.2", "4.2.1", "10.3.1"],
    "cwe-top-25": ["CWE-862", "CWE-639"]
  }
}
```

### Level Mapping

All 10 entries are high-priority by design (it's a "Top 10" list). Map to levels by typical severity:

| Level | Entries | Rationale |
|---|---|---|
| L1 | API1, API2, API3, API5 | Authorization and authentication — critical |
| L2 | API4, API6, API7, API8 | Resource, business logic, SSRF, config |
| L3 | API9, API10 | Inventory and third-party consumption |

## Discovery Agent Changes

The discovery agent already detects HTTP endpoints and frameworks. The enhancement is to specifically identify API patterns:

```python
# API detection signals:
# - REST framework (FastAPI, Flask-RESTful, Django REST, Spring Boot, Express)
# - JSON/XML serialization in response handlers
# - Route patterns with object IDs: /api/v1/users/{id}
# - OpenAPI/Swagger spec files
# - GraphQL schema files
# - API versioning in URLs or headers

api_indicators = {
    "has_rest_framework": bool,
    "has_graphql": bool,
    "has_openapi_spec": bool,
    "api_endpoint_count": int,
    "id_parameter_endpoints": list,  # endpoints with {id} patterns
}
```

When API indicators are present, discovery recommends `api-top-10` alongside ASVS.

## Audit Prompt

```
You are an API security auditor analyzing code against {api_id}: {api_title}.

{api_description}

Detection focus:
{detection_focus}

Analyze the provided API source code. For each API endpoint:
1. Identify if this risk applies
2. Show the specific vulnerable pattern with file and line references
3. Assess severity based on data sensitivity and exposure
4. Provide remediation specific to the framework in use

Pay special attention to:
- How object IDs are handled in route parameters
- What data is included in API responses vs what the client actually needs
- Whether authorization checks happen before or after data retrieval
- Rate limiting and pagination on list endpoints
```

## Cross-Reference Deduplication

Heavy overlap with ASVS. The consolidator maps:

| API Top 10 | ASVS Sections | Dedup Rule |
|---|---|---|
| API1 | 4.1.1, 4.2.1 | Merge if same endpoint + same authz gap |
| API2 | 2.x, 7.x | Merge if same auth mechanism |
| API3 | 4.x, 8.x | API3 often produces MORE SPECIFIC findings — prefer API3 wording |
| API4 | 2.4.1 | Merge, combine rate limit + pagination findings |
| API5 | 4.x, 10.x | Merge if same function-level check |
| API8 | 14.x | Merge if same config issue |

When API Top 10 and ASVS produce overlapping findings, the consolidated report notes both:

```markdown
#### FINDING-042: Missing authorization check on GET /api/elections/{id}/votes

**Specs violated:** ASVS 4.1.1, API1
**Severity:** High
```

## Estimated Effort

| Task | Effort | Dependencies |
|---|---|---|
| Write ingest script (10 entries, manually curated) | Half day | None |
| Build cross-reference mapping (API ↔ ASVS ↔ CWE) | Half day | CWE ingest |
| Audit prompt template | Half day | None |
| Add API detection to discovery agent | Half day | Phase 0 rename |
| Test with ATR (has REST API) | Half day | Ingest script |
| **Total** | **~2.5 days** | |

This is the lowest-effort spec to add because of the heavy ASVS overlap and the small number of requirements (10 vs 345).