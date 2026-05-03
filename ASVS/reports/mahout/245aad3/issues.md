# Security Issues

## Issue: FINDING-001 - Remote S3/GCS URL paths may contain sensitive bucket names or object keys in logs
**Labels:** bug, security, priority:low

**Description:**

### Summary
User-supplied S3/GCS URL paths containing potentially sensitive bucket names and object keys may be exposed in application logs and error messages. While query strings are properly rejected, bucket names and object key paths can leak sensitive identifiers such as customer IDs, dataset names, or internal project names through error handling and logging mechanisms.

### Details
The `encode_from_parquet` function accepts remote URL strings that flow through the platform module and may be included in error messages via the `MahoutError::Io(String)` variant. Object keys in S3/GCS paths often contain sensitive business identifiers that should not appear in logs accessible to operators or monitoring systems.

**Affected Files:**
- `qdp/qdp-core/src/lib.rs` - `encode_from_parquet` function, lines referencing `path: &str`
- `docs/qdp/getting-started.md` - remote URL examples

**CWE:** N/A  
**ASVS:** 14.2.1 (L1)  
**Severity:** Low

### Remediation
Implement path sanitization in error messages to redact sensitive bucket names and object keys before logging:

1. Create a `sanitize_remote_path` function that:
   - Detects S3/GCS URL patterns
   - Redacts bucket and key portions (e.g., `s3://bucket/<redacted>` or `s3://<redacted>/<redacted>`)
   - Preserves enough context for debugging (protocol, general error location)

2. Apply sanitization to all error paths that include user-supplied URLs

3. Consider structured logging that separates path components, allowing selective redaction of sensitive fields while preserving protocol/region information for operational debugging

**Example Implementation:**
```rust
fn sanitize_remote_path(path: &str) -> String {
    // Redact bucket and key while preserving protocol
    if path.starts_with("s3://") || path.starts_with("gs://") {
        let protocol = path.split("://").next().unwrap();
        format!("{}://<redacted>", protocol)
    } else {
        path.to_string()
    }
}
```

### Acceptance Criteria
- [ ] Fixed: Implement path sanitization function for S3/GCS URLs
- [ ] Fixed: Apply sanitization to all error messages containing remote paths
- [ ] Fixed: Update logging to use sanitized paths
- [ ] Test added: Unit tests for sanitization function with various URL formats
- [ ] Test added: Integration tests verifying no sensitive paths appear in logs
- [ ] Documentation updated to reflect security logging practices

### References
- Source Report: `14.2.1.md`
- ASVS 14.2.1: Documentation Components
- Related Finding IDs: ASVS-1421-LOW-001

### Priority
**Low** - Information disclosure risk through logs. While sensitive data may be exposed, exploitation requires log access and the impact is limited to metadata leakage rather than direct data compromise. Should be addressed in regular security maintenance cycle.