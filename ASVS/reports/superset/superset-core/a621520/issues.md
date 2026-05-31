# Security Issues

*1 actionable finding(s). 3 informational finding(s) from the consolidated report are not opened as issues — see consolidated.md for those.*

---

## Issue: FINDING-001 - TaskProperties Schema Exposes Stack Traces and Exception Types to Task Consumers

**Labels:** security, priority:low

### Summary

The `TaskProperties` TypedDict in `superset-core/src/superset_core/tasks/types.py` defines `stack_trace` and `exception_type` as first-class fields in the task's stored state. If API endpoints return task properties without filtering these fields, internal file paths, library versions, and application architecture details could be disclosed to task consumers.

### Details

- **CWE:** CWE-209 (Generation of Error Message Containing Sensitive Information)
- **ASVS:** 16.5.1 (Level L2)
- **Severity:** Low
- **Affected File:** `superset-core/src/superset_core/tasks/types.py`

The schema currently includes sensitive debugging information that may be appropriate for internal logging but should not be exposed to end users or API consumers. While no proof-of-concept against a running system has been demonstrated, the type definition analysis indicates potential for information disclosure if these fields are serialized and returned through task status endpoints without proper filtering.

Exposed information could include:
- Internal file system paths
- Library versions and dependencies
- Application architecture details
- Implementation-specific error handling patterns

**Note:** This finding is based on static type definition analysis. Actual exposure through the API layer has not been confirmed.

### Remediation

1. **Verify current API behavior:** Audit all task status API endpoints to determine if `stack_trace` and `exception_type` fields are currently returned to consumers.

2. **Implement field filtering:** If no filtering exists, add schema-based field projection to ensure only consumer-safe properties are returned in API responses.

3. **Separate internal/external schemas:** Consider creating separate TypedDicts:
   - `InternalTaskProperties` (includes all debug fields)
   - `PublicTaskProperties` (excludes sensitive fields)

4. **Add access controls:** If stack traces are needed for administrative purposes, restrict access to authenticated admin users only.

### Acceptance Criteria

- [ ] Task status API endpoints audited for field exposure
- [ ] Stack trace and exception type fields confirmed filtered from public responses
- [ ] Schema-based field projection implemented (if needed)
- [ ] Test added to verify sensitive fields are not exposed through API
- [ ] Documentation updated to clarify internal vs. public task properties

### References

- Source Report: 16.5.1.md
- Related CWE: https://cwe.mitre.org/data/definitions/209.html
- ASVS 16.5.1: Error handling should not disclose sensitive information

### Priority

**Low** - No confirmed exploitation path; requires verification of actual API serialization behavior.